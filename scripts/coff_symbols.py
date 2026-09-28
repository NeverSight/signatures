"""The names COFF objects and archives define in their code sections.

neverd-sigmaker writes a line only for the functions its rules accept, so its
output cannot say which routines a library holds; the symbol tables can.  This
reads them directly: regular and /bigobj objects, alone or in an archive.
Import objects and link-time-code-generation objects hold no machine code and
are passed over.
"""

from __future__ import annotations

import struct
from pathlib import Path

ARCHIVE_MAGIC = b"!<arch>\n"
# The ClassID of an ANON_OBJECT_HEADER_BIGOBJ.
BIGOBJ_CLASS_ID = bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_CLASS_LABEL = 6


def archive_members(data: bytes):
    """The bytes of each member of an archive, linker and name members skipped."""

    offset = len(ARCHIVE_MAGIC)
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise ValueError(f"archive member header at {offset:#x} is malformed")
        name = header[:16].rstrip()
        size = int(header[48:58].decode("ascii").strip())
        body = data[offset + 60 : offset + 60 + size]
        # "/" and "//" are the linker and long-name members, "/<ECSYMBOLS>/"
        # the ARM64EC symbol map; "/123" is a member with a long name.
        if name not in (b"/", b"//") and not name.startswith(b"/<"):
            yield body
        offset += 60 + size + (size & 1)


def object_symbols(data: bytes) -> set[str]:
    """The names one object defines in its code sections."""

    if len(data) < 20:
        return set()
    if data[:4] == b"\x00\x00\xff\xff":
        # An import object, a link-time-code-generation object, or /bigobj.
        if len(data) < 56 or data[12:28] != BIGOBJ_CLASS_ID:
            return set()
        (sections, symbol_table, symbols) = struct.unpack_from("<III", data, 44)
        section_headers, record, section_field = 56, 20, "<i"
    else:
        (sections, _, symbol_table, symbols, optional) = struct.unpack_from("<HIIIH", data, 2)
        section_headers, record, section_field = 20 + optional, 18, "<h"

    code = set()
    for index in range(sections):
        header = section_headers + 40 * index
        if header + 40 > len(data):
            raise ValueError("section table runs past the object")
        (characteristics,) = struct.unpack_from("<I", data, header + 36)
        if characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE):
            code.add(index + 1)

    strings = symbol_table + record * symbols
    names = set()
    index = 0
    while index < symbols:
        entry = symbol_table + record * index
        if entry + record > len(data):
            raise ValueError("symbol table runs past the object")
        raw = data[entry : entry + 8]
        (section,) = struct.unpack_from(section_field, data, entry + 12)
        storage, auxiliary = data[entry + record - 2], data[entry + record - 1]
        index += 1 + auxiliary
        if section not in code or storage not in (
            IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_LABEL
        ):
            continue
        if raw[:4] == b"\x00\x00\x00\x00":
            (offset,) = struct.unpack_from("<I", raw, 4)
            end = data.find(b"\x00", strings + offset)
            name = data[strings + offset : end if end >= 0 else len(data)]
        else:
            name = raw.rstrip(b"\x00")
        text = name.decode("utf-8", errors="replace")
        # A section's own symbol names the section, not code in it.
        if text and not text.startswith("."):
            names.add(text)
    return names


def code_symbols(path: Path) -> set[str]:
    """The names a .lib or .obj file defines in its code sections."""

    data = path.read_bytes()
    if data.startswith(ARCHIVE_MAGIC):
        names: set[str] = set()
        for member in archive_members(data):
            names |= object_symbols(member)
        return names
    return object_symbols(data)
