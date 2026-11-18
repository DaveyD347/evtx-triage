"""Decoder for Microsoft Binary XML (BinXML) as embedded in EVTX chunks.

Every event record in an EVTX file is a BinXML fragment. In practice a record is a
*template instance*: a reference to a template (an XML skeleton with numbered
substitution slots) plus an array of typed values that fill those slots. Templates
and element/attribute name strings live once per 64 KiB chunk and are referenced by
chunk-relative offset, so the decoder works on the whole chunk buffer and keeps a
per-chunk cache of templates it has already parsed.

The decoder builds a tiny element tree (``Element``) rather than XML text, which is
all the triage engine needs and avoids an XML round trip.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

# --- BinXML tokens -----------------------------------------------------------------
TOK_EOF = 0x00
TOK_OPEN_START = 0x01
TOK_CLOSE_START = 0x02
TOK_CLOSE_EMPTY = 0x03
TOK_END_ELEMENT = 0x04
TOK_VALUE = 0x05
TOK_ATTRIBUTE = 0x06
TOK_CDATA = 0x07
TOK_CHARREF = 0x08
TOK_ENTITYREF = 0x09
TOK_PI_TARGET = 0x0A
TOK_PI_DATA = 0x0B
TOK_TEMPLATE_INSTANCE = 0x0C
TOK_NORMAL_SUBST = 0x0D
TOK_OPTIONAL_SUBST = 0x0E
TOK_FRAGMENT_HEADER = 0x0F
FLAG_MORE = 0x40  # high bit flag: "has attributes" / "more attributes follow"

# --- Value types ---------------------------------------------------------------------
VT_NULL = 0x00
VT_STRING = 0x01
VT_ANSI = 0x02
VT_INT8 = 0x03
VT_UINT8 = 0x04
VT_INT16 = 0x05
VT_UINT16 = 0x06
VT_INT32 = 0x07
VT_UINT32 = 0x08
VT_INT64 = 0x09
VT_UINT64 = 0x0A
VT_FLOAT = 0x0B
VT_DOUBLE = 0x0C
VT_BOOL = 0x0D
VT_BINARY = 0x0E
VT_GUID = 0x0F
VT_SIZET = 0x10
VT_FILETIME = 0x11
VT_SYSTIME = 0x12
VT_SID = 0x13
VT_HEX32 = 0x14
VT_HEX64 = 0x15
VT_BINXML = 0x21
VT_ARRAY = 0x80

_FIXED = {
    VT_INT8: "<b", VT_UINT8: "<B", VT_INT16: "<h", VT_UINT16: "<H",
    VT_INT32: "<i", VT_UINT32: "<I", VT_INT64: "<q", VT_UINT64: "<Q",
    VT_FLOAT: "<f", VT_DOUBLE: "<d",
}
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class BinXmlError(ValueError):
    """Raised when a BinXML stream is malformed."""


# --- Tree model ----------------------------------------------------------------------
@dataclass
class Subst:
    """Placeholder for substitution value ``index`` inside a template."""

    index: int
    vtype: int
    optional: bool


Content = Union[str, "Element", Subst]


@dataclass
class Element:
    name: str
    attrs: List[Tuple[str, List[Content]]] = field(default_factory=list)
    children: List[Content] = field(default_factory=list)

    # Convenience accessors used by the normaliser ---------------------------------
    def find(self, name: str) -> Optional[Element]:
        for child in self.children:
            if isinstance(child, Element) and child.name == name:
                return child
        return None

    def elements(self) -> List[Element]:
        return [c for c in self.children if isinstance(c, Element)]

    def attr(self, name: str) -> Optional[str]:
        for key, value in self.attrs:
            if key == name:
                return "".join(str(v) for v in value)
        return None

    def text(self) -> str:
        return "".join(c for c in self.children if isinstance(c, str))


# --- Value decoding -------------------------------------------------------------------
def filetime_to_datetime(value: int) -> datetime:
    return _FILETIME_EPOCH + timedelta(microseconds=value // 10)


def format_filetime(value: int) -> str:
    dt = filetime_to_datetime(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value % 10_000_000:07d}Z"


def format_guid(raw: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", raw)
    tail = raw[8:16].hex().upper()
    return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{tail[:4]}-{tail[4:]}}}"


def format_sid(raw: bytes) -> str:
    if len(raw) < 8:
        raise BinXmlError("SID too short")
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", raw, 8)
    return "S-" + "-".join([str(revision), str(authority)] + [str(s) for s in subs])


def decode_value(vtype: int, raw: bytes, chunk: Optional[ChunkContext] = None,
                 offset: int = 0) -> Any:
    """Decode one substitution value of ``vtype`` from ``raw`` (its exact bytes)."""
    if vtype & VT_ARRAY:
        return _decode_array(vtype & ~VT_ARRAY, raw)
    if vtype == VT_NULL:
        return None
    if vtype == VT_STRING:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if vtype == VT_ANSI:
        return raw.decode("latin-1").rstrip("\x00")
    if vtype in _FIXED:
        return struct.unpack(_FIXED[vtype], raw[: struct.calcsize(_FIXED[vtype])])[0]
    if vtype == VT_BOOL:
        return bool(int.from_bytes(raw[:4], "little"))
    if vtype == VT_BINARY:
        return raw.hex().upper()
    if vtype == VT_GUID:
        return format_guid(raw)
    if vtype == VT_SIZET or vtype in (VT_HEX32, VT_HEX64):
        return hex(int.from_bytes(raw, "little"))  # Windows renders these unpadded
    if vtype == VT_FILETIME:
        return format_filetime(int.from_bytes(raw[:8], "little"))
    if vtype == VT_SYSTIME:
        y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", raw[:16])
        return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"
    if vtype == VT_SID:
        return format_sid(raw)
    if vtype == VT_BINXML:
        if chunk is None:
            raise BinXmlError("nested BinXML needs chunk context")
        return chunk.parse_fragment(offset, offset + len(raw))
    return raw.hex().upper()  # unknown type: keep the bytes visible


def _decode_array(vtype: int, raw: bytes) -> List[Any]:
    if vtype == VT_STRING:
        text = raw.decode("utf-16-le", errors="replace")
        parts = text.split("\x00")
        if parts and parts[-1] == "":
            parts.pop()
        return parts
    sizes = {VT_GUID: 16, VT_FILETIME: 8, VT_SYSTIME: 16, VT_HEX32: 4, VT_HEX64: 8, VT_BOOL: 4}
    size = struct.calcsize(_FIXED[vtype]) if vtype in _FIXED else sizes.get(vtype)
    if not size:
        return [raw.hex().upper()]
    return [decode_value(vtype, raw[i:i + size]) for i in range(0, len(raw) - size + 1, size)]


# --- Chunk-level parser ------------------------------------------------------------------
class ChunkContext:
    """Parses BinXML within one EVTX chunk, caching names and templates by offset."""

    def __init__(self, buf: bytes):
        self.buf = buf
        self._names: Dict[int, str] = {}
        self._templates: Dict[int, Element] = {}

    # Low level readers ------------------------------------------------------------
    def _u8(self, pos: int) -> int:
        return self.buf[pos]

    def _u16(self, pos: int) -> int:
        return struct.unpack_from("<H", self.buf, pos)[0]

    def _u32(self, pos: int) -> int:
        return struct.unpack_from("<I", self.buf, pos)[0]

    def _name_at(self, offset: int) -> Tuple[str, int]:
        """Read a NameString at ``offset``; return (name, byte length)."""
        length = self._u16(offset + 6)
        size = 8 + length * 2 + 2
        if offset not in self._names:
            raw = self.buf[offset + 8: offset + 8 + length * 2]
            self._names[offset] = raw.decode("utf-16-le", errors="replace")
        return self._names[offset], size

    def _read_name_ref(self, pos: int) -> Tuple[str, int]:
        """Read a u32 name offset at ``pos``; the string may be inline right after it."""
        offset = self._u32(pos)
        pos += 4
        name, size = self._name_at(offset)
        if offset == pos:  # defined inline: skip over it
            pos += size
        return name, pos

    # Public API ---------------------------------------------------------------------
    def parse_record(self, start: int, end: int) -> Element:
        """Parse the BinXML of one event record and return the resolved root element."""
        return self.parse_fragment(start, end)

    def parse_fragment(self, start: int, end: int) -> Element:
        pos = start
        root: Optional[Element] = None
        while pos < end:
            tok = self._u8(pos)
            base = tok & 0x0F if tok != TOK_TEMPLATE_INSTANCE else tok
            if tok == TOK_EOF:
                break
            if base == TOK_FRAGMENT_HEADER:
                pos += 4
            elif tok == TOK_TEMPLATE_INSTANCE:
                root, pos = self._template_instance(pos)
            elif base == TOK_OPEN_START:
                root, pos = self._element(pos, in_template=False)
            else:
                raise BinXmlError(f"unexpected token 0x{tok:02x} at chunk offset {pos}")
        if root is None:
            raise BinXmlError("fragment contained no element")
        return root

    # Template instances ------------------------------------------------------------
    def _template_instance(self, pos: int) -> Tuple[Element, int]:
        # token(1) unknown(1) template_id(4) template_offset(4)
        template_offset = self._u32(pos + 6)
        pos += 10
        template = self._templates.get(template_offset)
        if template_offset == pos:  # template definition is inline
            data_size = self._u32(pos + 20)
            if template is None:
                template = self._parse_template(pos + 24, pos + 24 + data_size)
                self._templates[template_offset] = template
            pos += 24 + data_size
        elif template is None:
            data_size = self._u32(template_offset + 20)
            body = template_offset + 24
            template = self._parse_template(body, body + data_size)
            self._templates[template_offset] = template

        count = self._u32(pos)
        pos += 4
        descriptors = []
        for _ in range(count):
            size, vtype = self._u16(pos), self._u8(pos + 2)
            descriptors.append((size, vtype))
            pos += 4
        values: List[Any] = []
        for size, vtype in descriptors:
            raw = self.buf[pos: pos + size]
            values.append(decode_value(vtype, raw, self, pos) if size else None)
            pos += size
        return _resolve(template, values), pos

    def _parse_template(self, start: int, end: int) -> Element:
        pos = start
        if self._u8(pos) == TOK_FRAGMENT_HEADER:
            pos += 4
        tok = self._u8(pos)
        if tok & 0x0F != TOK_OPEN_START:
            raise BinXmlError(f"template does not start with an element (0x{tok:02x})")
        element, _ = self._element(pos, in_template=True)
        return element

    # Elements -------------------------------------------------------------------
    def _element(self, pos: int, in_template: bool) -> Tuple[Element, int]:
        tok = self._u8(pos)
        # token(1) dependency_id(2) data_size(4) name_offset(4)
        name, pos = self._read_name_ref(pos + 7)
        if tok & FLAG_MORE:
            pos += 4  # attribute list size
        element = Element(name)

        while True:
            tok = self._u8(pos)
            base = tok & 0x0F
            if base == TOK_ATTRIBUTE:
                attr_name, pos = self._read_name_ref(pos + 1)
                value, pos = self._content(pos)
                element.attrs.append((attr_name, [value]))
            elif tok == TOK_CLOSE_EMPTY:
                return element, pos + 1
            elif tok == TOK_CLOSE_START:
                pos += 1
                break
            else:
                raise BinXmlError(f"bad token 0x{tok:02x} in start tag <{name}> at {pos}")

        while True:
            tok = self._u8(pos)
            base = tok & 0x0F
            if tok == TOK_END_ELEMENT:
                return element, pos + 1
            if base == TOK_OPEN_START:
                child, pos = self._element(pos, in_template)
                element.children.append(child)
            elif tok == TOK_TEMPLATE_INSTANCE:
                child, pos = self._template_instance(pos)
                element.children.append(child)
            else:
                value, pos = self._content(pos)
                element.children.append(value)

    def _content(self, pos: int) -> Tuple[Content, int]:
        tok = self._u8(pos)
        base = tok & 0x0F
        if base == TOK_VALUE:
            vtype = self._u8(pos + 1)
            if vtype != VT_STRING:
                raise BinXmlError(f"unsupported inline value type 0x{vtype:02x}")
            length = self._u16(pos + 2)
            raw = self.buf[pos + 4: pos + 4 + length * 2]
            return raw.decode("utf-16-le", errors="replace"), pos + 4 + length * 2
        if tok in (TOK_NORMAL_SUBST, TOK_OPTIONAL_SUBST):
            index, vtype = self._u16(pos + 1), self._u8(pos + 3)
            return Subst(index, vtype, tok == TOK_OPTIONAL_SUBST), pos + 4
        if base == TOK_CDATA:
            length = self._u16(pos + 1)
            raw = self.buf[pos + 3: pos + 3 + length * 2]
            return raw.decode("utf-16-le", errors="replace"), pos + 3 + length * 2
        if base == TOK_CHARREF:
            return chr(self._u16(pos + 1)), pos + 3
        if base == TOK_ENTITYREF:
            name, pos = self._read_name_ref(pos + 1)
            return {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}.get(name, f"&{name};"), pos
        if base == TOK_PI_TARGET:
            _, pos = self._read_name_ref(pos + 1)
            return "", pos
        if base == TOK_PI_DATA:
            length = self._u16(pos + 1)
            return "", pos + 3 + length * 2
        raise BinXmlError(f"unexpected content token 0x{tok:02x} at chunk offset {pos}")


def _resolve(template: Element, values: List[Any]) -> Element:
    """Return a copy of ``template`` with substitution slots replaced by ``values``."""

    def value_of(sub: Subst) -> Any:
        return values[sub.index] if sub.index < len(values) else None

    def render(parts: List[Content]) -> Optional[str]:
        out = []
        for part in parts:
            if isinstance(part, Subst):
                v = value_of(part)
                if v is None:
                    if part.optional:
                        return None
                    continue
                out.append(", ".join(map(str, v)) if isinstance(v, list) else str(v))
            else:
                out.append(str(part))
        return "".join(out)

    def walk(node: Element) -> Element:
        new = Element(node.name)
        for key, parts in node.attrs:
            rendered = render(parts)
            if rendered is not None:
                new.attrs.append((key, [rendered]))
        for child in node.children:
            if isinstance(child, Element):
                new.children.append(walk(child))
            elif isinstance(child, Subst):
                v = value_of(child)
                if isinstance(v, Element):
                    new.children.append(v)
                elif isinstance(v, list):
                    new.children.append(", ".join(map(str, v)))
                elif v is not None:
                    new.children.append(str(v))
            else:
                new.children.append(child)
        return new

    return walk(template)
