"""Tests for collect_homebrew_bottles.py; nothing is downloaded."""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_homebrew_bottles as collect  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402
import msvc_matrix  # noqa: E402


def ar_member(name: bytes, data: bytes) -> bytes:
    """One member of a BSD ar archive; a long name follows the header."""

    if len(name) > 16 or b" " in name:
        data = name + data
        name = b"#1/%d" % len(name)
    header = name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) * 2 + b"644".ljust(8)
    header += str(len(data)).encode().ljust(10) + b"`\n"
    return header + data + (b"\n" if len(data) & 1 else b"")


def mach_o(cpu_type: int, payload: bytes = b"") -> bytes:
    """The start of a 64-bit Mach-O object of a CPU type."""

    return struct.pack("<IIII", collect.MH_MAGIC_64, cpu_type, 0, 1) + payload


def macho_archive(*objects: bytes) -> bytes:
    """An archive as ranlib leaves it: the symbol table, then the objects,
    one of them under a long name."""

    members = ar_member(b"__.SYMDEF SORTED", bytes(8))
    for index, data in enumerate(objects):
        name = b"a_rather_long_object_name.o" if index == 0 else b"o%d.o" % index
        members += ar_member(name, data)
    return collect.AR_MAGIC + members


def bottle(path: Path, members: dict[str, bytes], links: dict[str, str] = {}) -> Path:
    with tarfile.open(path, "w:gz") as out:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            out.addfile(info, io.BytesIO(data))
        for name, target in links.items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            out.addfile(info)
    return path


class ArchiveTests(unittest.TestCase):
    def cpu_type(self, data: bytes) -> int:
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "lib.a"
            path.write_bytes(data)
            return collect.archive_cpu_type(path)

    def test_the_objects_name_the_cpu_type(self) -> None:
        archive = macho_archive(mach_o(collect.CPU_TYPE_ARM64, b"x"),
                                mach_o(collect.CPU_TYPE_ARM64))
        self.assertEqual(self.cpu_type(archive), collect.CPU_TYPE_ARM64)

    def test_objects_of_two_cpu_types_are_an_error(self) -> None:
        archive = macho_archive(mach_o(collect.CPU_TYPE_ARM64),
                                mach_o(collect.CPU_TYPE_X86_64))
        with self.assertRaises(collect.CollectionError):
            self.cpu_type(archive)

    def test_a_member_that_is_no_mach_o_object_is_an_error(self) -> None:
        with self.assertRaises(collect.CollectionError):
            self.cpu_type(macho_archive(b"\x7fELF\x02\x01\x01" + bytes(9)))

    def test_a_universal_archive_is_an_error(self) -> None:
        with self.assertRaises(collect.CollectionError):
            self.cpu_type(struct.pack(">II", 0xCAFEBABE, 2) + bytes(40))

    def test_a_truncated_member_is_an_error(self) -> None:
        with self.assertRaises(collect.CollectionError):
            self.cpu_type(macho_archive(mach_o(collect.CPU_TYPE_ARM64))[:-4])


class RegistryTests(unittest.TestCase):
    def test_a_bottle_is_named_by_its_digest_in_the_formulas_repository(self) -> None:
        self.assertEqual(collect.bottle_url("zlib", "ab"),
                         "https://ghcr.io/v2/homebrew/core/zlib/blobs/sha256:ab")
        self.assertEqual(collect.repository("openssl@3"), "openssl/3")
        self.assertEqual(collect.repository("libxml++"), "libxmlxx")


class ObtainTests(unittest.TestCase):
    def obtain(self, transfers: list[bytes]) -> tuple[Path | None, str | None, list[str]]:
        """What obtain() makes of these transfers, and the files it leaves."""

        good = hashlib.sha256(b"bottle").hexdigest()
        original_fetch, original_location = fetcher.fetch, collect.blob_location
        remaining = iter(transfers)

        def fetch(url: str, destination: Path) -> None:
            destination.write_bytes(next(remaining))

        fetcher.fetch = fetch
        collect.blob_location = lambda formula, digest: "https://example.invalid/b"
        try:
            with tempfile.TemporaryDirectory() as scratch:
                try:
                    package = collect.obtain("zlib", {"tag": "arm64_sequoia", "sha256": good},
                                             Path(scratch))
                    problem = None
                except collect.CollectionError as error:
                    package, problem = None, str(error)
                left = sorted(path.name for path in Path(scratch).iterdir())
        finally:
            fetcher.fetch, collect.blob_location = original_fetch, original_location
        return package, problem, left

    def test_a_damaged_transfer_is_fetched_again(self) -> None:
        package, problem, left = self.obtain([b"damaged", b"bottle"])
        self.assertIsNone(problem)
        self.assertEqual(left, [package.name])
        self.assertTrue(package.name.startswith("zlib--arm64_sequoia--"))

    def test_a_bottle_that_never_matches_is_an_error_and_leaves_nothing(self) -> None:
        package, problem, left = self.obtain([b"damaged"] * 6)
        self.assertIsNone(package)
        self.assertIn("SHA-256", problem)
        self.assertEqual(left, [])


class CollectTests(unittest.TestCase):
    def run_collector(self, root: Path, bottles: dict[str, Path],
                      archives: list[str]) -> int:
        matrix = root / "homebrew-matrix.json"
        matrix.write_text(json.dumps([{
            "name": "homebrew-zlib", "library": "homebrew-zlib", "formula": "zlib",
            "version": "1.3.2", "archives": archives,
            "bottles": [{"tag": tag, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                        for tag, path in bottles.items()]}]))
        original = collect.obtain
        collect.obtain = lambda formula, entry, downloads: bottles[entry["tag"]]
        try:
            return collect.main(["--matrix", str(matrix), "--name", "homebrew-zlib",
                                 "--work", str(root / "work"),
                                 "--output", str(root / "assets"), "--zstd-level", "3"])
        finally:
            collect.obtain = original

    def test_archives_are_filed_by_cpu_type_and_content(self) -> None:
        arm64 = macho_archive(mach_o(collect.CPU_TYPE_ARM64))
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            bottles = {
                "arm64_sonoma": bottle(root / "a.tar.gz", {
                    "zlib/1.3.2/lib/libz.a": arm64,
                    "zlib/1.3.2/include/zlib.h": b"",
                }, {"zlib/1.3.2/lib/libz.dylib": "libz.1.dylib"}),
                # The same archive, byte for byte, is stored once.
                "arm64_sequoia": bottle(root / "b.tar.gz", {"zlib/1.3.2/lib/libz.a": arm64}),
                "arm64_tahoe": bottle(root / "c.tar.gz", {
                    "zlib/1.3.2/lib/libz.a": macho_archive(mach_o(collect.CPU_TYPE_ARM64, b"t")),
                }),
            }
            self.assertEqual(self.run_collector(root, bottles, ["lib/libz.a"]), 0)
            manifest = json.loads((root / "assets/homebrew-zlib-arm64.json").read_text())
            self.assertEqual(sorted(p.name for p in (root / "assets").iterdir()),
                             ["homebrew-zlib-arm64.json", "homebrew-zlib-arm64.tar.zst"])
        self.assertEqual(manifest["format"], "macho")
        self.assertEqual(manifest["library"], "homebrew-zlib")
        self.assertEqual(manifest["library_version"], "1.3.2")
        self.assertEqual(manifest["arch"], "arm64")
        self.assertEqual([entry["path"] for entry in manifest["files"]],
                         ["homebrew-zlib/zlib-1.3.2-arm64_sonoma/lib/libz.a",
                          "homebrew-zlib/zlib-1.3.2-arm64_tahoe/lib/libz.a"])
        self.assertEqual([(entry["tag"], entry["libraries"], entry["stored"])
                          for entry in manifest["bottles"]],
                         [("arm64_sonoma", 1, 1), ("arm64_sequoia", 1, 0),
                          ("arm64_tahoe", 1, 1)])
        self.assertTrue(manifest["bottles"][0]["url"].startswith(
            "https://ghcr.io/v2/homebrew/core/zlib/blobs/sha256:"))

    def test_a_bottle_without_an_archive_the_row_names_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            bottles = {"arm64_sonoma": bottle(root / "a.tar.gz", {
                "zlib/1.3.2/lib/libz.a": macho_archive(mach_o(collect.CPU_TYPE_ARM64)),
            })}
            with self.assertRaises(SystemExit) as raised:
                self.run_collector(root, bottles, ["lib/libz.a", "lib/libminizip.a"])
            self.assertIn("lib/libminizip.a", str(raised.exception))
            self.assertFalse((root / "assets").exists())

    def test_an_archive_the_bottle_links_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            bottles = {"arm64_sonoma": bottle(root / "a.tar.gz", {},
                                              {"zlib/1.3.2/lib/libz.a": "libz.1.a"})}
            with self.assertRaises(SystemExit):
                self.run_collector(root, bottles, ["lib/libz.a"])

    def test_an_archive_of_an_unknown_cpu_type_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            bottles = {"arm64_sonoma": bottle(root / "a.tar.gz", {
                "zlib/1.3.2/lib/libz.a": macho_archive(mach_o(0x0100000D)),
            })}
            with self.assertRaises(SystemExit):
                self.run_collector(root, bottles, ["lib/libz.a"])


class MatrixTests(unittest.TestCase):
    def test_every_row_pins_its_bottles(self) -> None:
        rows = msvc_matrix.load(collect.DEFAULT_MATRIX, msvc_matrix.HOMEBREW_FIELDS)
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(row=row["name"]):
                # The builder files a library under its name.
                self.assertRegex(row["library"], r"^homebrew-[a-z0-9][a-z0-9._+-]*$")
                self.assertTrue(row["archives"])
                self.assertTrue(all(a.startswith("lib/") and a.endswith(".a")
                                    for a in row["archives"]))
                tags = [entry["tag"] for entry in row["bottles"]]
                self.assertTrue(tags)
                self.assertEqual(len(tags), len(set(tags)))
                # macOS bottles: `<release>` on Intel, `arm64_<release>` on
                # Apple silicon; a `*_linux` bottle holds ELF libraries.
                for tag in tags:
                    self.assertRegex(tag, r"^(arm64_)?[a-z]+(_[a-z]+)*$")
                    self.assertFalse(tag.endswith("_linux"), tag)
                for entry in row["bottles"]:
                    self.assertEqual(set(entry), {"tag", "sha256"})
                    self.assertRegex(entry["sha256"], re.compile(r"^[0-9a-f]{64}$"))


if __name__ == "__main__":
    unittest.main()
