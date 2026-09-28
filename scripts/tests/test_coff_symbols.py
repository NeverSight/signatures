"""Tests for coff_symbols.py."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import coff_symbols  # noqa: E402

CODE = 0x60000020  # IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ
DATA = 0xC0000040  # IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE


def symbol(name: bytes, section: int, storage: int, strings: bytearray,
           auxiliary: int = 0, bigobj: bool = False) -> bytes:
    if len(name) <= 8:
        field = name.ljust(8, b"\x00")
    else:
        field = struct.pack("<II", 0, 4 + len(strings))
        strings += name + b"\x00"
    number = struct.pack("<i" if bigobj else "<h", section)
    record = field + struct.pack("<I", 0) + number + struct.pack("<HBB", 0x20, storage, auxiliary)
    return record + b"\x00" * ((20 if bigobj else 18) * auxiliary)


def coff_object(bigobj: bool = False) -> bytes:
    strings = bytearray()
    records = [
        symbol(b".text$mn", 1, 3, strings, auxiliary=1, bigobj=bigobj),
        symbol(b"?Run@@YAXXZ", 1, 2, strings, bigobj=bigobj),
        symbol(b"_static", 1, 3, strings, bigobj=bigobj),
        symbol(b"?value@@3HA", 2, 2, strings, bigobj=bigobj),
        symbol(b"_extern", 0, 2, strings, bigobj=bigobj),
    ]
    count = 1 + 1 + 1 + 1 + 1 + 1  # five records, one auxiliary
    sections = [(b".text$mn", CODE), (b".data", DATA)]
    header_size = 56 if bigobj else 20
    table = header_size + 40 * len(sections)
    if bigobj:
        header = struct.pack("<HHHHI", 0, 0xFFFF, 2, 0x14C, 0) + coff_symbols.BIGOBJ_CLASS_ID
        header += struct.pack("<IIIIIII", 0, 0, 0, 0, len(sections), table, count)
    else:
        header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, table, count, 0, 0)
    body = b"".join(
        name.ljust(8, b"\x00") + b"\x00" * 28 + struct.pack("<I", flags)
        for name, flags in sections
    )
    return header + body + b"".join(records) + struct.pack("<I", 4 + len(strings)) + bytes(strings)


def archive(*members: bytes) -> bytes:
    data = bytearray(coff_symbols.ARCHIVE_MAGIC)
    for name, body in ((b"/", b"\x00" * 4), *((b"a.obj/", member) for member in members)):
        data += name.ljust(16) + b"0".ljust(12) + b"".ljust(6) * 2 + b"644".ljust(8)
        data += str(len(body)).encode().ljust(10) + b"`\n" + body
        if len(body) & 1:
            data += b"\n"
    return bytes(data)


class CodeSymbolTests(unittest.TestCase):
    def test_names_defined_in_code_sections(self) -> None:
        for bigobj in (False, True):
            with self.subTest(bigobj=bigobj):
                self.assertEqual(coff_symbols.object_symbols(coff_object(bigobj)),
                                 {"?Run@@YAXXZ", "_static"})

    def test_archives_and_import_objects(self) -> None:
        import_object = struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x14C, 0, 8, 0, 0) + b"_f\x00x.dll\x00"
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "x.lib"
            path.write_bytes(archive(coff_object(), import_object, coff_object(True)))
            self.assertEqual(coff_symbols.code_symbols(path), {"?Run@@YAXXZ", "_static"})


if __name__ == "__main__":
    unittest.main()
