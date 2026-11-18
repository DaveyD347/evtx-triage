"""Pure-Python reader for the Windows EVTX binary log format.

Layout (all integers little endian)::

    File header  (4096 bytes)   "ElfFile\\0", chunk count, CRC32 of the first 120 bytes
    Chunk        (65536 bytes)  "ElfChnk\\0", record id range, CRC32s, string/template tables
      Record     (variable)     0x00002a2a, size, record id, FILETIME, BinXML ..., size copy

The reader walks chunks by file size rather than trusting the header's chunk count,
so "dirty" logs copied off a live system (where the header lags behind the data)
still yield every record. Checksums are verified and reported, not enforced, which
is what you want when triaging partially corrupted evidence.
"""

from __future__ import annotations

import logging
import struct
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from .binxml import BinXmlError, ChunkContext, Element, filetime_to_datetime

log = logging.getLogger(__name__)

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512  # header (128) + string table (256) + template table (128)


class EvtxError(ValueError):
    """Raised when a file is not a parseable EVTX log."""


@dataclass
class FileHeader:
    first_chunk: int
    last_chunk: int
    next_record_id: int
    major_version: int
    minor_version: int
    chunk_count: int
    flags: int
    checksum: int
    checksum_ok: bool

    @property
    def is_dirty(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def is_full(self) -> bool:
        return bool(self.flags & 0x2)


@dataclass
class ChunkHeader:
    index: int
    first_record_id: int
    last_record_id: int
    last_record_offset: int
    free_space_offset: int
    records_checksum: int
    header_checksum: int
    header_checksum_ok: bool
    records_checksum_ok: bool


@dataclass
class Record:
    record_id: int
    timestamp: datetime
    root: Element
    chunk: int


@dataclass
class ParseStats:
    chunks: int = 0
    records: int = 0
    bad_chunk_checksums: int = 0
    bad_records: int = 0
    warnings: List[str] = field(default_factory=list)


def parse_file_header(buf: bytes) -> FileHeader:
    if len(buf) < 128 or buf[:8] != FILE_MAGIC:
        raise EvtxError("missing ElfFile signature: not an EVTX file")
    first, last, next_id, hdr_size, minor, major, block_size, count = struct.unpack_from(
        "<QQQIHHHH", buf, 8
    )
    if hdr_size != 128 or block_size != FILE_HEADER_SIZE:
        raise EvtxError(f"unexpected header sizes ({hdr_size}, {block_size})")
    flags, checksum = struct.unpack_from("<II", buf, 120)
    return FileHeader(
        first_chunk=first, last_chunk=last, next_record_id=next_id,
        major_version=major, minor_version=minor, chunk_count=count, flags=flags,
        checksum=checksum, checksum_ok=zlib.crc32(buf[:120]) == checksum,
    )


def parse_chunk_header(chunk: bytes, index: int) -> ChunkHeader:
    if chunk[:8] != CHUNK_MAGIC:
        raise EvtxError(f"chunk {index}: missing ElfChnk signature")
    (_first_num, _last_num, first_id, last_id, _hdr_size, last_off, free_off,
     rec_crc) = struct.unpack_from("<QQQQIIII", chunk, 8)
    header_crc = struct.unpack_from("<I", chunk, 124)[0]
    calc_header = zlib.crc32(chunk[:120] + chunk[128:CHUNK_HEADER_SIZE])
    free_off = min(free_off, CHUNK_SIZE)
    calc_records = zlib.crc32(chunk[CHUNK_HEADER_SIZE:free_off]) if free_off > CHUNK_HEADER_SIZE else 0
    return ChunkHeader(
        index=index, first_record_id=first_id, last_record_id=last_id,
        last_record_offset=last_off, free_space_offset=free_off,
        records_checksum=rec_crc, header_checksum=header_crc,
        header_checksum_ok=calc_header == header_crc,
        records_checksum_ok=calc_records == rec_crc,
    )


class EvtxReader:
    """Iterate the records of an EVTX file.

    >>> with open("Security.evtx", "rb") as fh:            # doctest: +SKIP
    ...     for record in EvtxReader(fh.read()).records():
    ...         print(record.record_id, record.root.name)
    """

    def __init__(self, data: bytes):
        self.data = data
        self.header = parse_file_header(data)
        self.stats = ParseStats()
        if not self.header.checksum_ok:
            self._warn("file header checksum mismatch")

    @classmethod
    def open(cls, path: Union[str, Path]) -> EvtxReader:
        return cls(Path(path).read_bytes())

    def _warn(self, message: str) -> None:
        self.stats.warnings.append(message)
        log.warning(message)

    def chunks(self) -> Iterator[ChunkHeader]:
        total = max(0, (len(self.data) - FILE_HEADER_SIZE) // CHUNK_SIZE)
        if total < self.header.chunk_count:
            self._warn(f"header claims {self.header.chunk_count} chunks but file holds {total} (truncated?)")
        for index in range(total):
            start = FILE_HEADER_SIZE + index * CHUNK_SIZE
            chunk = self.data[start:start + CHUNK_SIZE]
            if chunk[:8] != CHUNK_MAGIC:
                if chunk.strip(b"\x00"):
                    self._warn(f"chunk {index}: bad signature, skipped")
                continue  # all-zero chunks are unused pre-allocated space
            yield parse_chunk_header(chunk, index)

    def records(self) -> Iterator[Record]:
        for header in self.chunks():
            self.stats.chunks += 1
            if not (header.header_checksum_ok and header.records_checksum_ok):
                self.stats.bad_chunk_checksums += 1
                self._warn(f"chunk {header.index}: checksum mismatch (parsing anyway)")
            yield from self._chunk_records(header)

    def _chunk_records(self, header: ChunkHeader) -> Iterator[Record]:
        start = FILE_HEADER_SIZE + header.index * CHUNK_SIZE
        chunk = self.data[start:start + CHUNK_SIZE]
        ctx = ChunkContext(chunk)
        pos = CHUNK_HEADER_SIZE
        end = header.free_space_offset
        while pos + 24 <= end and chunk[pos:pos + 4] == RECORD_MAGIC:
            size, record_id, filetime = struct.unpack_from("<IQQ", chunk, pos + 4)
            if size < 28 or pos + size > CHUNK_SIZE:
                self._warn(f"chunk {header.index}: implausible record size {size} at {pos}")
                break
            try:
                root = ctx.parse_record(pos + 24, pos + size - 4)
            except (BinXmlError, struct.error, IndexError) as exc:
                self.stats.bad_records += 1
                self._warn(f"record {record_id}: {exc}")
            else:
                self.stats.records += 1
                yield Record(record_id, filetime_to_datetime(filetime), root, header.index)
            pos += size


# --- Normalisation -----------------------------------------------------------------
def record_to_dict(record: Record) -> Dict[str, Any]:
    """Flatten an event element into System fields plus an EventData dict."""
    root = record.root
    system = root.find("System") or Element("System")
    provider = system.find("Provider")
    time_created = system.find("TimeCreated")
    event_id_el = system.find("EventID")
    out: Dict[str, Any] = {
        "EventID": int(event_id_el.text()) if event_id_el and event_id_el.text().strip() else 0,
        "TimeCreated": (time_created.attr("SystemTime") if time_created else None),
        "Computer": _text(system.find("Computer")),
        "Channel": _text(system.find("Channel")),
        "Provider": provider.attr("Name") if provider else "",
        "EventRecordID": record.record_id,
        "EventData": event_data(root),
    }
    if not out["TimeCreated"]:
        out["TimeCreated"] = record.timestamp
    return out


def event_data(root: Element) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    section = root.find("EventData")
    if section is not None:
        unnamed = 0
        for item in section.elements():
            name = item.attr("Name")
            if not name:
                name = f"Data{unnamed}" if item.name == "Data" else item.name
                unnamed += 1
            data[name] = _text(item)
        return data
    user = root.find("UserData")
    if user is not None and user.elements():
        for item in user.elements()[0].elements():
            data[item.name] = _text(item)
    return data


def _text(el: Optional[Element]) -> str:
    if el is None:
        return ""
    parts = []
    for child in el.children:
        parts.append(child if isinstance(child, str) else _text(child))
    return "".join(parts)
