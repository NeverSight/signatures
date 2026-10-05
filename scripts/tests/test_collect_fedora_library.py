"""Tests for collect_fedora_library.py; nothing is downloaded or compiled."""

from __future__ import annotations

import gzip
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_fedora_library as collect  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402
import msvc_matrix  # noqa: E402


def header(data: bytes = b"") -> bytes:
    """An RPM header structure with no index entries and `data` as its store."""

    return b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", 0, len(data)) + data


def rpm(payload: bytes, signature_store: bytes = b"") -> bytes:
    signature = header(signature_store)
    padding = bytes(-(96 + len(signature)) % 8)
    return bytes(96) + signature + padding + header(b"main") + payload


class CpioOptionsTests(unittest.TestCase):
    def test_each_supported_tool_keeps_its_path_checks(self) -> None:
        for version, options in (("cpio (GNU cpio) 2.15", ["--no-absolute-filenames"]),
                                 ("bsdcpio 3.5.3", [])):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                package = root / "test.rpm"
                package.write_bytes(rpm(gzip.compress(b"cpio payload")))
                with mock.patch.object(collect.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 0, stdout=b"cpio payload"),
                    subprocess.CompletedProcess([], 0, stdout=version),
                    subprocess.CompletedProcess([], 0),
                ]) as run:
                    collect.unpack_rpm(package, root)
                self.assertEqual(run.call_args_list[-1].args[0],
                                 ["cpio", "-idm", "--quiet", *options])
                self.assertEqual(run.call_args_list[-1].kwargs["input"], b"cpio payload")

    def test_unknown_tool_fails_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            package = root / "test.rpm"
            package.write_bytes(rpm(gzip.compress(b"cpio payload")))
            with mock.patch.object(collect.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], 0, stdout=b"cpio payload"),
                subprocess.CompletedProcess([], 0, stdout="unknown cpio"),
            ]) as run:
                with self.assertRaisesRegex(collect.BuildError, "unsupported cpio"):
                    collect.unpack_rpm(package, root)
            self.assertEqual(run.call_count, 2)


@unittest.skipUnless(shutil.which("cpio"), "needs cpio")
class RpmTests(unittest.TestCase):
    def test_the_payload_is_unpacked_past_a_padded_signature(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            tree = root / "tree"
            (tree / "usr/bin").mkdir(parents=True)
            (tree / "usr/bin/cc").write_text("compiler")
            listing = subprocess.run(["cpio", "-o", "-H", "newc", "--quiet"], cwd=tree,
                                     input=b"./usr/bin/cc\n", capture_output=True,
                                     check=True).stdout
            # A signature store of five bytes leaves the main header three
            # bytes of padding away from it.
            package = root / "cc.rpm"
            package.write_bytes(rpm(gzip.compress(listing), signature_store=b"12345"))
            unpacked = root / "root"
            unpacked.mkdir()
            collect.unpack_rpm(package, unpacked)
            self.assertEqual((unpacked / "usr/bin/cc").read_text(), "compiler")

    def test_a_file_that_is_no_rpm_is_refused(self) -> None:
        with self.assertRaises(collect.BuildError):
            collect.rpm_payload(bytes(200))


class BuildTests(unittest.TestCase):
    def test_a_toolchain_file_reads_like_signature_builds_zlib(self) -> None:
        text = collect.toolchain_file(Path("/r"), {"arch": "x86", "compiler": "clang",
                                                   "cflags": ["--target=i686-linux-elf"]})
        self.assertEqual(text, "set(CMAKE_SYSTEM_NAME Linux)\n\n"
                               "set(CMAKE_C_COMPILER /r/usr/bin/clang)\n"
                               "set(CMAKE_C_FLAGS --target=i686-linux-elf)\n")
        text = collect.toolchain_file(Path("/r"), {"arch": "x64", "compiler": "gcc",
                                                   "cflags": []})
        self.assertNotIn("CMAKE_C_FLAGS", text)

    def test_a_package_that_does_not_match_its_digest_is_refused(self) -> None:
        original = fetcher.fetch
        fetcher.fetch = lambda url, destination: destination.write_bytes(b"other")
        try:
            with tempfile.TemporaryDirectory() as scratch:
                with self.assertRaises(collect.BuildError):
                    collect.obtain({"url": "https://example.org/gcc.rpm", "sha256": "0" * 64},
                                   Path(scratch))
                self.assertEqual(list(Path(scratch).iterdir()), [])
        finally:
            fetcher.fetch = original


class MatrixTests(unittest.TestCase):
    def test_every_row_pins_its_source_and_packages(self) -> None:
        rows = msvc_matrix.load(collect.DEFAULT_MATRIX, msvc_matrix.FEDORA_FIELDS)
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(row=row["name"]):
                self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
                for package in row["packages"]:
                    self.assertTrue(package["url"].startswith(
                        "https://kojipkgs.fedoraproject.org/packages/"), package["url"])
                    self.assertRegex(package["sha256"], r"^[0-9a-f]{64}$")
                names = {PurePosixPath(package["url"]).name for package in row["packages"]}
                for build in row["builds"]:
                    self.assertIn(build["arch"], ("x86", "x64"))
                    # Each build's compiler comes from the row's packages.
                    self.assertTrue(any(re.match(rf"{re.escape(build['compiler'])}-\d", name)
                                        for name in names), build)

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_each_row_builds_an_imported_elf_file(self) -> None:
        root = Path(__file__).resolve().parents[2]
        listing = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "--name-only",
                                  "0a3da7a", "elf"], capture_output=True, text=True)
        if listing.returncode != 0:
            self.skipTest("the import commit is not in this checkout")
        imported = {path.rsplit("/", 1)[1][:-4] for path in listing.stdout.split()
                    if path.endswith(".pat")}
        for row in json.loads(collect.DEFAULT_MATRIX.read_text()):
            self.assertIn(row["library"], imported)


if __name__ == "__main__":
    unittest.main()
