"""Tests for collect_masm32.py; the Wine build itself needs Wine."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_masm32 as masm32  # noqa: E402


def member(name: bytes, body: bytes, date: bytes = b"1759000000") -> bytes:
    header = name.ljust(16) + date.ljust(12) + b"".ljust(6) * 2 + b"644".ljust(8)
    header += str(len(body)).encode().ljust(10) + b"`\n"
    return header + body + (b"\n" if len(body) & 1 else b"")


def coff(stamp: int) -> bytes:
    return struct.pack("<HHIIIHH", 0x14C, 0, stamp, 0, 0, 0, 0)


class PayloadTests(unittest.TestCase):
    def test_the_archive_is_carved_from_its_signature(self) -> None:
        installer = b"MZ" + bytes(100) + masm32.SEVEN_ZIP_SIGNATURE + b"payload"
        self.assertEqual(masm32.carve_payload(installer),
                         masm32.SEVEN_ZIP_SIGNATURE + b"payload")

    def test_an_installer_without_an_archive_is_an_error(self) -> None:
        with self.assertRaises(masm32.BuildError):
            masm32.carve_payload(b"MZ" + bytes(100))


class TimestampTests(unittest.TestCase):
    def test_two_builds_differ_only_in_what_is_cleared(self) -> None:
        def library(date: bytes, stamp: int) -> bytes:
            return (masm32.ARCHIVE_MAGIC + member(b"/", bytes(4), date)
                    + member(b"a.obj/", coff(stamp) + b"code", date))

        first = masm32.clear_timestamps(library(b"1759000000", 0x11111111))
        second = masm32.clear_timestamps(library(b"1759999999", 0x22222222))
        self.assertEqual(first, second)
        self.assertIn(b"code", first)

    def test_import_objects_keep_their_bytes(self) -> None:
        import_object = struct.pack("<HHHHI", 0, 0xFFFF, 0, 0x14C, 0x33333333) + bytes(12)
        cleared = masm32.clear_timestamps(masm32.ARCHIVE_MAGIC + member(b"b.obj/", import_object))
        self.assertIn(struct.pack("<I", 0x33333333), cleared)

    def test_a_file_that_is_no_archive_is_an_error(self) -> None:
        with self.assertRaises(masm32.BuildError):
            masm32.clear_timestamps(b"MZ")


class FindPathTests(unittest.TestCase):
    def test_each_part_matches_whatever_its_case(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "vkdebug" / "DBPROC").mkdir(parents=True)
            (root / "vkdebug" / "DBPROC" / "DEBUG.LIB").write_bytes(b"")
            found = masm32.find_path(root, "vkdebug", "dbproc", "debug.lib")
            self.assertEqual(found.name, "DEBUG.LIB")
            with self.assertRaises(masm32.BuildError):
                masm32.find_path(root, "vkdebug", "missing.lib")


class MatrixTests(unittest.TestCase):
    def test_every_row_builds_known_sources(self) -> None:
        import json
        rows = json.loads(masm32.DEFAULT_MATRIX.read_text(encoding="utf-8"))
        self.assertTrue(rows)
        for row in rows:
            self.assertLessEqual(set(row["build"]), set(masm32.LIBRARY_OUTPUTS), row["name"])
            self.assertEqual(len(row["sha256"]), 64, row["name"])


if __name__ == "__main__":
    unittest.main()
