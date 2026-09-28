"""Tests for pdb_truth.py's CodeView reading; nothing is downloaded."""

from __future__ import annotations

import struct
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pdb_truth  # noqa: E402


def program_with_codeview(guid: uuid.UUID, age: int, pdb: bytes) -> bytes:
    """A PE32 image with one section holding a debug directory and its RSDS record."""

    pe = 0x80
    optional_size = 96 + 16 * 8
    section_table = pe + 24 + optional_size
    raw = 0x200
    virtual = 0x1000
    debug = virtual + 0x10
    record = debug + 28
    image = bytearray(raw + 0x200)
    struct.pack_into("<I", image, 0x3C, pe)
    image[pe : pe + 4] = b"PE\0\0"
    struct.pack_into("<HH", image, pe + 4, 0x14C, 1)
    struct.pack_into("<H", image, pe + 20, optional_size)
    struct.pack_into("<H", image, pe + 24, 0x10B)
    struct.pack_into("<II", image, pe + 24 + 96 + 6 * 8, debug, 28)
    image[section_table : section_table + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section_table + 8, 0x200, virtual, 0x200, raw)
    rsds = b"RSDS" + guid.bytes_le + struct.pack("<I", age) + pdb + b"\0"
    struct.pack_into("<IIIIIIII", image, raw + 0x10, 0, 0, 0, 2, len(rsds), record,
                     raw + 0x10 + 28, 0)
    image[raw + 0x10 + 28 : raw + 0x10 + 28 + len(rsds)] = rsds
    return bytes(image)


class CodeViewTests(unittest.TestCase):
    def test_the_symbol_server_key_is_the_guid_and_age(self) -> None:
        guid = uuid.UUID("2d8b307b-e70b-4d4c-b4af-20f1904b862d")
        image = program_with_codeview(guid, 1, b"d:\\build\\setup.pdb")
        self.assertEqual(pdb_truth.codeview(image),
                         ("setup.pdb", "2D8B307BE70B4D4CB4AF20F1904B862D1"))

    def test_a_program_without_a_debug_directory_names_no_pdb(self) -> None:
        image = bytearray(program_with_codeview(uuid.uuid4(), 1, b"x.pdb"))
        struct.pack_into("<II", image, 0x80 + 24 + 96 + 6 * 8, 0, 0)
        self.assertIsNone(pdb_truth.codeview(bytes(image)))


if __name__ == "__main__":
    unittest.main()
