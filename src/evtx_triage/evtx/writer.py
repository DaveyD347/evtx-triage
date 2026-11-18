"""Minimal EVTX writer used to build synthetic sample logs and test fixtures.

It emits the same structures Windows does: a file header, 64 KiB chunks with valid
CRC32 checksums, and records encoded as BinXML *template instances*. One template
is defined per distinct event shape (same EventData field names) per chunk; the
first record using a shape carries the template inline and later records refer to
it by offset, exactly like real logs. Element and attribute names are likewise
written once per chunk and then referenced.

This lets the repository ship realistic ``.evtx`` samples without redistributing
real logs, and gives the reader a round-trip test.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

from . import binxml as bx
from .reader import CHUNK_HEADER_SIZE, CHUNK_MAGIC, CHUNK_SIZE, FILE_HEADER_SIZE, FILE_MAGIC, RECORD_MAGIC

_EPOCH_DELTA_100NS = 116_444_736_000_000_000
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


@dataclass
class WriterEvent:
    event_id: int
    timestamp: datetime
    computer: str
    channel: str
    provider: str
    data: Dict[str, str] = field(default_factory=dict)
    user_data: Optional[str] = None  # wrap fields in <UserData><name> instead of <EventData>


def to_filetime(ts: datetime) -> int:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = ts - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return _EPOCH_DELTA_100NS + (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


# Template body node types --------------------------------------------------------
@dataclass
class _El:
    name: str
    attrs: List[Tuple[str, Union[str, Tuple[int, int]]]] = field(default_factory=list)
    children: List[Union[_El, str, Tuple[int, int]]] = field(default_factory=list)


class _Chunk:
    def __init__(self) -> None:
        self.buf = bytearray(CHUNK_HEADER_SIZE)
        self.names: Dict[str, int] = {}
        self.templates: Dict[Tuple, Tuple[int, int]] = {}  # shape -> (offset, template id)
        self.first_id: Optional[int] = None
        self.last_id = 0
        self.last_offset = 0

    # Primitive emitters -----------------------------------------------------
    def name_ref(self, out: bytearray, base: int, name: str) -> None:
        """Append a name offset; inline the NameString on first use in this chunk."""
        here = base + len(out) + 4
        if name in self.names:
            out += struct.pack("<I", self.names[name])
            return
        self.names[name] = here
        out += struct.pack("<I", here)
        out += struct.pack("<IHH", 0, 0, len(name)) + _utf16(name) + b"\x00\x00"

    def element(self, out: bytearray, base: int, el: _El) -> None:
        out += bytes([bx.TOK_OPEN_START | (bx.FLAG_MORE if el.attrs else 0)])
        out += struct.pack("<H", 0xFFFF)
        size_pos = len(out)
        out += b"\x00\x00\x00\x00"
        self.name_ref(out, base, el.name)
        if el.attrs:
            attr_size_pos = len(out)
            out += b"\x00\x00\x00\x00"
            attr_start = len(out)
            for i, (key, value) in enumerate(el.attrs):
                more = bx.FLAG_MORE if i < len(el.attrs) - 1 else 0
                out += bytes([bx.TOK_ATTRIBUTE | more])
                self.name_ref(out, base, key)
                self.content(out, value)
            struct.pack_into("<I", out, attr_size_pos, len(out) - attr_start)
        if not el.children:
            out += bytes([bx.TOK_CLOSE_EMPTY])
        else:
            out += bytes([bx.TOK_CLOSE_START])
            for child in el.children:
                if isinstance(child, _El):
                    self.element(out, base, child)
                else:
                    self.content(out, child)
            out += bytes([bx.TOK_END_ELEMENT])
        struct.pack_into("<I", out, size_pos, len(out) - size_pos - 4)

    @staticmethod
    def content(out: bytearray, value: Union[str, Tuple[int, int]]) -> None:
        if isinstance(value, tuple):  # (substitution index, value type)
            out += struct.pack("<BHB", bx.TOK_NORMAL_SUBST, value[0], value[1])
        else:
            out += struct.pack("<BBH", bx.TOK_VALUE, bx.VT_STRING, len(value)) + _utf16(value)


def _template_for(event: WriterEvent) -> _El:
    system = _El("System", children=[
        _El("Provider", attrs=[("Name", (0, bx.VT_STRING))]),
        _El("EventID", children=[(1, bx.VT_UINT16)]),
        _El("TimeCreated", attrs=[("SystemTime", (2, bx.VT_FILETIME))]),
        _El("EventRecordID", children=[(3, bx.VT_UINT64)]),
        _El("Channel", children=[(4, bx.VT_STRING)]),
        _El("Computer", children=[(5, bx.VT_STRING)]),
    ])
    fields = [
        _El("Data", attrs=[("Name", key)], children=[(6 + i, bx.VT_STRING)])
        for i, key in enumerate(event.data)
    ]
    if event.user_data:
        fields = [_El(key, children=[(6 + i, bx.VT_STRING)]) for i, key in enumerate(event.data)]
        payload = _El("UserData", children=[_El(event.user_data, children=list(fields))])
    else:
        payload = _El("EventData", children=list(fields))
    return _El("Event", attrs=[("xmlns", EVENT_NS)], children=[system, payload])


class EvtxWriter:
    def __init__(self) -> None:
        self.chunks: List[_Chunk] = []
        self.next_record_id = 1

    def add(self, event: WriterEvent) -> int:
        record_id = self.next_record_id
        if not self.chunks:
            self.chunks.append(_Chunk())
        record = self._encode(self.chunks[-1], event, record_id)
        if len(self.chunks[-1].buf) + len(record) > CHUNK_SIZE:
            self.chunks.append(_Chunk())
            record = self._encode(self.chunks[-1], event, record_id)
            if len(record) + CHUNK_HEADER_SIZE > CHUNK_SIZE:
                raise ValueError("event too large for a single chunk")
        chunk = self.chunks[-1]
        chunk.last_offset = len(chunk.buf)
        chunk.buf += record
        chunk.first_id = record_id if chunk.first_id is None else chunk.first_id
        chunk.last_id = record_id
        self.next_record_id += 1
        return record_id

    def extend(self, events: Sequence[WriterEvent]) -> None:
        for event in events:
            self.add(event)

    def _encode(self, chunk: _Chunk, event: WriterEvent, record_id: int) -> bytes:
        # Encode against snapshots so a record that overflows the chunk leaves no trace.
        names_before = dict(chunk.names)
        templates_before = dict(chunk.templates)
        base = len(chunk.buf) + 24  # BinXML starts after the 24-byte record header
        body = bytearray(b"\x0f\x01\x01\x00")
        shape = (tuple(event.data), event.user_data)
        body += struct.pack("<BB", bx.TOK_TEMPLATE_INSTANCE, 0x01)
        if shape in chunk.templates:
            offset, template_id = chunk.templates[shape]
            body += struct.pack("<II", template_id, offset)
        else:
            template_id = zlib.crc32(repr(shape).encode())
            offset = base + len(body) + 8
            body += struct.pack("<II", template_id, offset)
            header_pos = len(body)
            body += struct.pack("<I", 0) + struct.pack("<I", template_id) + bytes(12) + b"\x00\x00\x00\x00"
            data_start = len(body)
            body += b"\x0f\x01\x01\x00"
            chunk.element(body, base, _template_for(event))
            body += bytes([bx.TOK_EOF])
            struct.pack_into("<I", body, header_pos + 20, len(body) - data_start)
            chunk.templates[shape] = (offset, template_id)

        values: List[Tuple[int, bytes]] = [
            (bx.VT_STRING, _utf16(event.provider)),
            (bx.VT_UINT16, struct.pack("<H", event.event_id)),
            (bx.VT_FILETIME, struct.pack("<Q", to_filetime(event.timestamp))),
            (bx.VT_UINT64, struct.pack("<Q", record_id)),
            (bx.VT_STRING, _utf16(event.channel)),
            (bx.VT_STRING, _utf16(event.computer)),
        ] + [(bx.VT_STRING, _utf16(str(v))) for v in event.data.values()]
        body += struct.pack("<I", len(values))
        for vtype, raw in values:
            body += struct.pack("<HBB", len(raw), vtype if raw else bx.VT_NULL, 0)
        for _, raw in values:
            body += raw
        body += bytes([bx.TOK_EOF])

        size = 24 + len(body) + 4
        pad = (-size) % 8
        size += pad
        record = bytearray(RECORD_MAGIC)
        record += struct.pack("<IQQ", size, record_id, to_filetime(event.timestamp))
        record += body + bytes(pad) + struct.pack("<I", size)
        if len(chunk.buf) + len(record) > CHUNK_SIZE:
            chunk.names, chunk.templates = names_before, templates_before
        return bytes(record)

    # Serialisation ------------------------------------------------------------
    def to_bytes(self) -> bytes:
        chunks = [self._finish_chunk(c) for c in self.chunks]
        header = bytearray(FILE_MAGIC)
        header += struct.pack(
            "<QQQIHHHH", 0, max(len(chunks) - 1, 0), self.next_record_id, 128, 2, 3,
            FILE_HEADER_SIZE, len(chunks),
        )
        header += bytes(120 - len(header))
        header += struct.pack("<I", 0)  # flags: clean
        header += struct.pack("<I", zlib.crc32(bytes(header[:120])))
        header += bytes(FILE_HEADER_SIZE - len(header))
        return bytes(header) + b"".join(chunks)

    def save(self, path: Union[str, Path]) -> None:
        Path(path).write_bytes(self.to_bytes())

    @staticmethod
    def _finish_chunk(chunk: _Chunk) -> bytes:
        buf = bytearray(chunk.buf)
        free = len(buf)
        first = chunk.first_id or 0
        buf[0:8] = CHUNK_MAGIC
        struct.pack_into("<QQQQ", buf, 8, first, chunk.last_id, first, chunk.last_id)
        struct.pack_into("<IIII", buf, 40, 128, chunk.last_offset, free,
                         zlib.crc32(bytes(buf[CHUNK_HEADER_SIZE:free])))
        struct.pack_into("<I", buf, 120, 0)
        struct.pack_into("<I", buf, 124, zlib.crc32(bytes(buf[:120] + buf[128:CHUNK_HEADER_SIZE])))
        return bytes(buf) + bytes(CHUNK_SIZE - len(buf))
