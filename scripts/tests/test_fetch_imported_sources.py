"""Tests for fetch_imported_sources.py."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fetch_imported_sources as fetch  # noqa: E402


def elf_header(machine: int, wide: bool | None = None) -> bytes:
    """An ELF header of a machine, of its usual class unless `wide` says."""

    if wide is None:
        wide = machine in (62, 183)
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1, 1]) + bytes(9)
    return ident + struct.pack("<HH", 1, machine) + bytes(44)


def member(name: bytes, data: bytes) -> bytes:
    header = name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    header += b"644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n"
    return header + data + (b"\n" if len(data) & 1 else b"")


class ArchiveMachineTests(unittest.TestCase):
    def archive(self, *members: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(suffix=".a", delete=False)
        handle.write(b"!<arch>\n" + b"".join(members))
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_symbol_index_is_skipped_and_the_first_object_decides(self) -> None:
        path = self.archive(member(b"/", b"\0\0\0\0"), member(b"a.o/", elf_header(183)))
        self.assertEqual(fetch.archive_machine(path), "elf/arm/64")

    def test_bsd_long_names_are_read_past(self) -> None:
        name = b"a_long_object_name.o"
        path = self.archive(member(b"#1/" + str(len(name)).encode(), name + elf_header(40)))
        self.assertEqual(fetch.archive_machine(path), "elf/arm/32")

    def test_an_object_file_is_filed_by_its_own_header(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".o") as handle:
            handle.write(elf_header(3))
            handle.flush()
            self.assertEqual(fetch.archive_machine(Path(handle.name)), "elf/x86/32")

    def test_x32_code_has_no_directory(self) -> None:
        # x86-64 instructions in a 32-bit class object: neither x86 nor x64.
        path = self.archive(member(b"a.o/", elf_header(62, wide=False)))
        self.assertIsNone(fetch.archive_machine(path))

    def test_unknown_machine_and_non_archives_are_not_filed(self) -> None:
        self.assertIsNone(fetch.archive_machine(self.archive(member(b"a.o/", elf_header(8)))))
        with tempfile.NamedTemporaryFile(suffix=".a") as handle:
            handle.write(b"not an archive")
            handle.flush()
            self.assertIsNone(fetch.archive_machine(Path(handle.name)))


class SourceURLTests(unittest.TestCase):
    def test_known_locations(self) -> None:
        self.assertEqual(
            fetch.source_url("ubuntu/kinetic/amd64/libc++-15-dev/1:15.0.1-1~exp2/"
                             "libc++-15-dev_15.0.1-1~exp2_amd64.deb"),
            "https://launchpad.net/ubuntu/+archive/primary/+files/"
            "libc%2B%2B-15-dev_15.0.1-1~exp2_amd64.deb",
        )
        self.assertEqual(fetch.source_url("android-ndk-r25b-linux.zip"),
                         "https://dl.google.com/android/repository/android-ndk-r25b-linux.zip")
        self.assertEqual(fetch.source_url("android-ndk-r9d-linux-x86_64.tar.bz2"),
                         "https://dl.google.com/android/ndk/android-ndk-r9d-linux-x86_64.tar.bz2")
        self.assertIsNone(fetch.source_url("zlib-1.3.tar.gz"))


if __name__ == "__main__":
    unittest.main()
