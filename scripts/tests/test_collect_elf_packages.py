"""Tests for collect_elf_packages.py; nothing is downloaded."""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_elf_packages as collect  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402
import msvc_matrix  # noqa: E402


def elf_archive(machine: int, wide: bool, payload: bytes = b"") -> bytes:
    """An ar archive whose one member starts like an ELF object of a machine."""

    header = b"\x7fELF" + bytes([2 if wide else 1, 1, 1]) + bytes(9)
    header += struct.pack("<HH", 1, machine) + payload
    member = b"obj.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) * 2 + b"644".ljust(8)
    member += str(len(header)).encode().ljust(10) + b"`\n" + header
    return b"!<arch>\n" + member + (b"\n" if len(header) & 1 else b"")


class SourceTests(unittest.TestCase):
    def test_a_package_two_series_carried_is_fetched_once(self) -> None:
        lists = {
            "elf/x86/64/android-ndk": [("aa", "android-ndk-r25b-linux.zip"),
                                       ("bb", "android-ndk-r24-linux.zip")],
            "elf/arm/64/android-ndk": [("aa", "android-ndk-r25b-linux.zip")],
        }
        original = fetcher.source_list
        fetcher.source_list = lambda library, commit, cache: lists[library]
        try:
            with tempfile.TemporaryDirectory() as scratch:
                row = {"library": "android-ndk",
                       "directories": ["elf/x86/64", "elf/arm/64"]}
                sources = collect.package_sources(row, Path(scratch))
        finally:
            fetcher.source_list = original
        self.assertEqual(sources, [("aa", "android-ndk-r25b-linux.zip"),
                                   ("bb", "android-ndk-r24-linux.zip")])


class ObtainTests(unittest.TestCase):
    def obtain(self, transfers: list[bytes]) -> tuple[Path | None, str | None, list[str]]:
        """What obtain() makes of these transfers, and the files it leaves."""

        good = hashlib.sha1(b"package").hexdigest()
        original = fetcher.fetch
        remaining = iter(transfers)

        def fetch(url: str, destination: Path) -> None:
            destination.write_bytes(next(remaining))

        fetcher.fetch = fetch
        try:
            with tempfile.TemporaryDirectory() as scratch:
                package, problem = collect.obtain(good, "ubuntu/jammy/amd64/zlib1g-dev/1/z.deb",
                                                  Path(scratch))
                left = sorted(path.name for path in Path(scratch).iterdir())
        finally:
            fetcher.fetch = original
        return package, problem, left

    def test_a_damaged_transfer_is_fetched_again(self) -> None:
        package, problem, left = self.obtain([b"damaged", b"package"])
        self.assertIsNone(problem)
        self.assertEqual(package.name, "z.deb")
        self.assertEqual(left, ["z.deb"])

    def test_a_package_that_never_matches_is_unavailable_and_leaves_nothing(self) -> None:
        package, problem, left = self.obtain([b"other"] * 3)
        self.assertIsNone(package)
        self.assertEqual(problem, "SHA-1 does not match rizin's record")
        self.assertEqual(left, [])


@unittest.skipUnless(shutil.which("zstd") and shutil.which("tar"), "needs zstd and tar")
class CollectTests(unittest.TestCase):
    def test_archives_are_filed_by_machine_scope_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            package = root / "downloads" / "android-ndk-r1-linux.tar.bz2"
            package.parent.mkdir()
            x64 = elf_archive(62, True)
            members = {
                "ndk/platforms/android-21/arch-x86_64/usr/lib/libc.a": x64,
                # The same file at another API level is stored once.
                "ndk/platforms/android-22/arch-x86_64/usr/lib/libc.a": x64,
                "ndk/platforms/android-21/arch-x86/usr/lib/libc.a": elf_archive(3, False),
                "ndk/platforms/android-21/arch-arm64/usr/lib/libc.a": elf_archive(183, True),
                "ndk/sources/libfoo.txt.a": b"not an archive",
                # A library the toolchain runs on the host, not an Android one.
                "ndk/toolchains/x86_64-4.9/prebuilt/linux-x86_64/lib64/libiberty.a":
                    elf_archive(62, True, b"host"),
            }
            with tarfile.open(package, "w:bz2") as bundle:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
            matrix = root / "elf-matrix.json"
            matrix.write_text(json.dumps([{
                "name": "android-ndk", "library": "android-ndk",
                "directories": ["elf/x86/64", "elf/x86/32"], "archives": ["*.a"],
                "paths": ["*/platforms/*"]}]))

            original_sources, original_obtain = collect.package_sources, collect.obtain
            collect.package_sources = lambda row, cache: [("ab", "android-ndk-r1-linux.tar.bz2"),
                                                          ("cd", "android-ndk-r2-linux.zip")]
            collect.obtain = lambda digest, path, downloads: (
                (package, None) if path.endswith("r1-linux.tar.bz2")
                else (None, "HTTP Error 404: Not Found"))
            try:
                status = collect.main(["--matrix", str(matrix), "--name", "android-ndk",
                                       "--work", str(root / "work"),
                                       "--output", str(root / "assets"),
                                       "--zstd-level", "3", "--jobs", "1"])
            finally:
                collect.package_sources, collect.obtain = original_sources, original_obtain
            self.assertEqual(status, 0)
            x64_manifest = json.loads((root / "assets/android-ndk-x64.json").read_text())
            x86_manifest = json.loads((root / "assets/android-ndk-x86.json").read_text())
            self.assertFalse((root / "assets/android-ndk-arm64.json").exists())
        self.assertEqual(x64_manifest["format"], "elf")
        self.assertEqual(x64_manifest["library"], "android-ndk")
        self.assertEqual(
            [entry["path"] for entry in x64_manifest["files"]],
            ["android-ndk/android-ndk-r1-linux/ndk/platforms/android-21/arch-x86_64/usr/lib/libc.a"])
        self.assertEqual(len(x86_manifest["files"]), 1)
        # The package held two x64 archives of the same bytes; one is stored.
        self.assertEqual([(entry["package"], entry["libraries"], entry["stored"])
                          for entry in x64_manifest["sources"]],
                         [("android-ndk-r1-linux.tar.bz2", 2, 1)])
        self.assertEqual([entry["package"] for entry in x64_manifest["unavailable"]],
                         ["android-ndk-r2-linux.zip"])
        self.assertFalse(x64_manifest["reproduces_import"])


class MatrixTests(unittest.TestCase):
    def test_every_row_names_directories_rizin_had_files_in(self) -> None:
        rows = msvc_matrix.load(collect.DEFAULT_MATRIX, msvc_matrix.ELF_FIELDS,
                                msvc_matrix.ELF_OPTIONAL)
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(row=row["name"]):
                self.assertTrue(row["archives"])
                self.assertTrue(set(row["directories"]) <= set(collect.DIRECTORIES))

    def test_an_ndk_row_takes_its_android_libraries_and_no_host_library(self) -> None:
        row = collect.row_named(collect.DEFAULT_MATRIX, "android-ndk")
        root = "android-ndk-r25b/toolchains/llvm/prebuilt/linux-x86_64/"
        android = [
            "android-ndk-r10e/platforms/android-21/arch-x86_64/usr/lib64/libc.a",
            "android-ndk-r17c/sources/cxx-stl/llvm-libc++/libs/x86_64/libc++_static.a",
            "android-ndk-r10e/sources/android/compiler-rt/libs/x86_64/libcompiler_rt_static.a",
            root + "sysroot/usr/lib/x86_64-linux-android/21/libc.a",
            root + "lib64/clang/14.0.6/lib/linux/libclang_rt.builtins-x86_64-android.a",
            root + "lib64/clang/14.0.6/lib/linux/x86_64/libunwind.a",
            root + "lib/gcc/x86_64-linux-android/4.9.x/libgcc_real.a",
            root + "x86_64-linux-android/lib64/libatomic.a",
            "android-ndk-r17c/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/"
            "lib/gcc/arm-linux-androideabi/4.9.x/armv7-a/thumb/libgcc.a",
            "android-ndk-r17c/toolchains/x86_64-4.9/prebuilt/linux-x86_64/"
            "x86_64-linux-android/libx32/libgomp.a",
            "android-ndk-r17c/toolchains/renderscript/prebuilt/linux-x86_64/platform/"
            "x86_64/libcompiler_rt.a",
        ]
        host = [
            "android-ndk-r10e/prebuilt/linux-x86_64/lib/libpython2.7.a",
            "android-ndk-r10e/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/"
            "lib/libarm-linux-android-sim.a",
            "android-ndk-r10e/toolchains/x86-4.9/prebuilt/linux-x86_64/lib64/libiberty.a",
            "android-ndk-r10e/toolchains/x86-4.9/prebuilt/linux-x86_64/lib32/libbfd.a",
            root + "lib64/clang/14.0.6/lib/linux/libclang_rt.asan-x86_64.a",
            "android-ndk-r12b/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/3.8/"
            "lib/linux/libclang_rt.asan-i686.a",
            root + "lib64/clang/14.0.6/lib/linux/host/libFuzzer.a",
            root + "lib/libbolt_rt_instr.a",
            root + "lib64/clang/14.0.6/lib/baremetal/libclang_rt.builtins-aarch64.a",
        ]

        def taken(path: str) -> bool:
            return any(fnmatch.fnmatchcase(path, pattern) for pattern in row["paths"])

        self.assertEqual([path for path in android if not taken(path)], [])
        self.assertEqual([path for path in host if taken(path)], [])

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_the_rows_cover_the_imported_elf_files_built_from_packages(self) -> None:
        root = Path(__file__).resolve().parents[2]
        listing = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "--name-only",
                                  "0a3da7a", "elf"], capture_output=True, text=True)
        if listing.returncode != 0:
            self.skipTest("the import commit is not in this checkout")
        imported = {path.rsplit("/", 1)[1][:-4] for path in listing.stdout.split()
                    if path.endswith(".pat")}
        rows = {row["library"] for row in json.loads(collect.DEFAULT_MATRIX.read_text())}
        # fedora-zlib was built from the zlib release archive, not a package.
        self.assertEqual(imported - rows, {"fedora-zlib"})


if __name__ == "__main__":
    unittest.main()
