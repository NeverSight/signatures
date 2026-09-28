"""The names COFF and ELF objects and archives define in their code sections.

neverd-sigmaker writes a line only for the functions its rules accept, so its
output cannot say which routines a library holds; the symbol tables can.  This
reads them directly: regular and /bigobj COFF objects, and ELF relocatable
objects of either class and byte order, alone or in an archive.  Import
objects and link-time-code-generation objects hold no machine code and are
passed over.
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

ELF_MAGIC = b"\x7fELF"
SHT_SYMTAB = 2
SHF_EXECINSTR = 0x4
STT_FUNC = 2
STT_GNU_IFUNC = 10


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
        # the ARM64EC symbol map, "/SYM64/" GNU ar's 64-bit symbol table;
        # "/123" is a member with a long name.
        if name not in (b"/", b"//", b"/SYM64/") and not name.startswith(b"/<"):
            yield body
        offset += 60 + size + (size & 1)


def elf_object_symbols(data: bytes) -> set[str]:
    """The function names one ELF object defines in its executable sections."""

    if len(data) < 52:
        return set()
    wide, order = data[4] == 2, "<" if data[5] == 1 else ">"
    if wide:
        (shoff,) = struct.unpack_from(order + "Q", data, 40)
        shentsize, shnum = struct.unpack_from(order + "HH", data, 58)
    else:
        (shoff,) = struct.unpack_from(order + "I", data, 32)
        shentsize, shnum = struct.unpack_from(order + "HH", data, 46)
    sections = []
    for index in range(shnum):
        header = shoff + index * shentsize
        if header + shentsize > len(data):
            raise ValueError("section table runs past the object")
        if wide:
            _, kind, flags, _, offset, size, link, _, _, entsize = struct.unpack_from(
                order + "IIQQQQIIQQ", data, header)
        else:
            _, kind, flags, _, offset, size, link, _, _, entsize = struct.unpack_from(
                order + "IIIIIIIIII", data, header)
        sections.append((kind, flags, offset, size, link, entsize))

    names = set()
    for kind, _, offset, size, link, entsize in sections:
        if kind != SHT_SYMTAB or not entsize:
            continue
        strings = sections[link][2]
        for entry in range(offset, offset + size - entsize + 1, entsize):
            if wide:
                name, info, _, shndx = struct.unpack_from(order + "IBBH", data, entry)
            else:
                name, _, _, info, _, shndx = struct.unpack_from(order + "IIIBBH", data, entry)
            if info & 0xF not in (STT_FUNC, STT_GNU_IFUNC) or not 0 < shndx < len(sections):
                continue
            if not sections[shndx][1] & SHF_EXECINSTR:
                continue
            end = data.find(b"\x00", strings + name)
            text = data[strings + name : end if end >= 0 else len(data)].decode(
                "utf-8", errors="replace")
            if text:
                names.add(text)
    return names


def object_symbols(data: bytes) -> set[str]:
    """The names one object defines in its code sections."""

    if data[:4] == ELF_MAGIC:
        return elf_object_symbols(data)
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
    """The names a library or object file defines in its code sections."""

    data = path.read_bytes()
    if data.startswith(ARCHIVE_MAGIC):
        names: set[str] = set()
        for member in archive_members(data):
            names |= object_symbols(member)
        return names
    return object_symbols(data)
