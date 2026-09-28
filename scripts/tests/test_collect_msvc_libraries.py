"""Tests for collect_msvc_libraries.py against synthetic installation trees."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_msvc_libraries as collector  # noqa: E402


def _write(path: Path, data: bytes = b"!<arch>\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class TreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def make_installation(self, versions: dict[str, tuple[str, ...]], default: str | None) -> Path:
        installation = self.root / "vs"
        for version, arches in versions.items():
            for arch in arches:
                _write(installation / "VC/Tools/MSVC" / version / "lib" / arch / "libcmt.lib")
                _write(installation / "VC/Tools/MSVC" / version / "lib" / arch / "chkstk.obj")
                _write(installation / "VC/Tools/MSVC" / version / "lib" / arch / "notes.txt")
                _write(
                    installation / "VC/Tools/MSVC" / version / "lib" / arch / "store" / "libcmt.lib"
                )
                _write(
                    installation / "VC/Tools/MSVC" / version / "atlmfc/lib" / arch / "nafxcw.lib"
                )
        if default is not None:
            marker = installation / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("﻿" + default + "\n", encoding="utf-8")
        return installation


class ResolveToolsetTests(TreeTest):
    def test_default_reads_the_installation_marker(self) -> None:
        installation = self.make_installation(
            {"14.44.35207": ("x64",), "14.29.30133": ("x64",)}, default="14.44.35207"
        )
        directory = collector.resolve_toolset_directory(installation, "default")
        self.assertEqual(directory.name, "14.44.35207")

    def test_prefix_selects_the_newest_matching_servicing_build(self) -> None:
        installation = self.make_installation(
            {"14.29.30133": ("x64",), "14.29.30037": ("x64",), "14.290.1": ("x64",)},
            default=None,
        )
        directory = collector.resolve_toolset_directory(installation, "14.29")
        self.assertEqual(directory.name, "14.29.30133")

    def test_missing_prefix_names_what_is_installed(self) -> None:
        installation = self.make_installation({"14.44.35207": ("x64",)}, default=None)
        with self.assertRaisesRegex(collector.CollectionError, "installed: 14.44.35207"):
            collector.resolve_toolset_directory(installation, "14.16")

    def test_default_without_marker_is_an_error(self) -> None:
        installation = self.make_installation({"14.44.35207": ("x64",)}, default=None)
        with self.assertRaisesRegex(collector.CollectionError, "default.txt"):
            collector.resolve_toolset_directory(installation, "default")

    def test_marker_naming_an_absent_toolset_is_an_error(self) -> None:
        installation = self.make_installation({"14.44.35207": ("x64",)}, default="14.50.1")
        with self.assertRaisesRegex(collector.CollectionError, "not installed"):
            collector.resolve_toolset_directory(installation, "default")


class CollectToolsetTests(TreeTest):
    def test_collects_top_level_libraries_and_objects_only(self) -> None:
        installation = self.make_installation({"14.44.35207": ("arm64",)}, default="14.44.35207")
        toolset = installation / "VC/Tools/MSVC/14.44.35207"
        files = collector.collect_toolset_files(toolset, "arm64", include_atlmfc=True)
        members = sorted(str(item.member) for item in files)
        self.assertEqual(
            members,
            [
                "vc/atlmfc/lib/arm64/nafxcw.lib",
                "vc/lib/arm64/chkstk.obj",
                "vc/lib/arm64/libcmt.lib",
            ],
        )

    def test_missing_architecture_is_an_error(self) -> None:
        installation = self.make_installation({"14.50.1": ("x64",)}, default="14.50.1")
        toolset = installation / "VC/Tools/MSVC/14.50.1"
        with self.assertRaisesRegex(collector.CollectionError, "arm build tools"):
            collector.collect_toolset_files(toolset, "arm", include_atlmfc=False)

    def test_requested_atlmfc_must_exist(self) -> None:
        installation = self.make_installation({"14.29.1": ("arm",)}, default=None)
        toolset = installation / "VC/Tools/MSVC/14.29.1"
        shutil.rmtree(toolset / "atlmfc")
        with self.assertRaisesRegex(collector.CollectionError, "ATL/MFC"):
            collector.collect_toolset_files(toolset, "arm", include_atlmfc=True)
        files = collector.collect_toolset_files(toolset, "arm", include_atlmfc=False)
        self.assertEqual(len(files), 2)

    def test_directory_without_archives_is_an_error(self) -> None:
        toolset = self.root / "VC/Tools/MSVC/14.44.1"
        _write(toolset / "lib/x86/chkstk.obj")
        with self.assertRaisesRegex(collector.CollectionError, "no .lib files"):
            collector.collect_toolset_files(toolset, "x86", include_atlmfc=False)


class LibraryFileTests(TreeTest):
    def test_only_coff_archives_and_objects_are_collected(self) -> None:
        directory = self.root / "Lib"
        _write(directory / "libcmt.lib")
        _write(directory / "chkstk.obj", b"\x4c\x01\x03\x00" + bytes(16))
        # A 16-bit OMF import library and object, as old Windows SDKs ship.
        _write(directory / "MAPI.Lib", b"\xf0\x0d\x00\x00\x2c\x00\x00\x0b")
        _write(directory / "old.obj", b"\x80\x08\x00\x06old.c")
        self.assertEqual(
            [path.name for path in collector.library_files(directory)],
            ["chkstk.obj", "libcmt.lib"],
        )


class LegacyV140Tests(TreeTest):
    def test_maps_legacy_architecture_directories(self) -> None:
        vc = self.root / "Microsoft Visual Studio 14.0/VC"
        _write(vc / "lib/libcmt.lib")
        _write(vc / "lib/amd64/libcmt.lib")
        _write(vc / "lib/amd64/libcpmt.lib")
        x86 = collector.collect_legacy_files(vc, "x86", include_atlmfc=False)
        x64 = collector.collect_legacy_files(vc, "x64", include_atlmfc=False)
        self.assertEqual([str(item.member) for item in x86], ["vc/lib/x86/libcmt.lib"])
        self.assertEqual(
            sorted(str(item.member) for item in x64),
            ["vc/lib/x64/libcmt.lib", "vc/lib/x64/libcpmt.lib"],
        )

    def test_v140_has_no_arm64(self) -> None:
        with self.assertRaisesRegex(collector.CollectionError, "no 'arm64'"):
            collector.collect_legacy_files(self.root, "arm64", include_atlmfc=False)


class WinSdkTests(TreeTest):
    def test_collects_ucrt_and_um(self) -> None:
        kits = self.root / "Windows Kits/10"
        _write(kits / "Lib/10.0.22621.0/ucrt/arm/libucrt.lib")
        _write(kits / "Lib/10.0.22621.0/ucrt/arm/ucrt.lib")
        _write(kits / "Lib/10.0.22621.0/um/arm/kernel32.lib")
        files = collector.collect_winsdk_files(kits, "10.0.22621.0", "arm")
        self.assertEqual(
            sorted(str(item.member) for item in files),
            [
                "winsdk/10.0.22621.0/ucrt/arm/libucrt.lib",
                "winsdk/10.0.22621.0/ucrt/arm/ucrt.lib",
                "winsdk/10.0.22621.0/um/arm/kernel32.lib",
            ],
        )

    def test_sdk_without_the_architecture_is_an_error(self) -> None:
        kits = self.root / "Windows Kits/10"
        _write(kits / "Lib/10.0.26100.0/ucrt/x64/libucrt.lib")
        _write(kits / "Lib/10.0.26100.0/um/x64/kernel32.lib")
        with self.assertRaisesRegex(collector.CollectionError, "arm UCRT"):
            collector.collect_winsdk_files(kits, "10.0.26100.0", "arm")

    def test_ucrt_without_libucrt_is_an_error(self) -> None:
        kits = self.root / "Windows Kits/10"
        _write(kits / "Lib/10.0.26100.0/ucrt/x64/ucrt.lib")
        _write(kits / "Lib/10.0.26100.0/um/x64/kernel32.lib")
        with self.assertRaisesRegex(collector.CollectionError, "libucrt.lib"):
            collector.collect_winsdk_files(kits, "10.0.26100.0", "x64")


@unittest.skipIf(shutil.which("zstd") is None, "zstd is not installed")
class ArchiveTests(TreeTest):
    def _archive(self, name: str) -> tuple[Path, list[collector.CollectedFile]]:
        installation = self.make_installation({"14.44.1": ("x64",)}, default="14.44.1")
        toolset = installation / "VC/Tools/MSVC/14.44.1"
        files = collector.collect_toolset_files(toolset, "x64", include_atlmfc=True)
        output = self.root / name
        output.mkdir()
        archive = output / "asset.tar.zst"
        collector.write_archive(files, archive, level=3)
        return archive, files

    def test_archive_is_reproducible_and_complete(self) -> None:
        first, files = self._archive("one")
        second, _ = self._archive("two")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertFalse(first.with_name("asset.tar").exists())

        tar_path = self.root / "check.tar"
        import subprocess

        subprocess.run(["zstd", "-q", "-d", str(first), "-o", str(tar_path)], check=True)
        with tarfile.open(tar_path) as archive:
            names = archive.getnames()
            for info in archive.getmembers():
                self.assertEqual(info.mtime, 0)
                self.assertEqual(info.uid, 0)
        self.assertEqual(names, sorted(str(item.member) for item in files))

    def test_main_writes_manifest_for_every_architecture(self) -> None:
        installation = self.make_installation(
            {"14.44.35207": ("x64", "arm64")}, default="14.44.35207"
        )
        output = self.root / "out"
        collector.main(
            [
                "toolset",
                "--vs-year", "2022",
                "--vswhere-version", "[17.0,18.0)",
                "--installation-path", str(installation),
                "--arch", "x64",
                "--arch", "arm64",
                "--zstd-level", "3",
                "--output", str(output),
            ]
        )
        for arch in ("x64", "arm64"):
            manifest = json.loads((output / f"vs2022-14.44.35207-{arch}.json").read_text())
            self.assertEqual(manifest["kind"], "toolset")
            self.assertEqual(manifest["arch"], arch)
            self.assertEqual(manifest["toolset_version"], "14.44.35207")
            archive = output / f"vs2022-14.44.35207-{arch}.tar.zst"
            self.assertEqual(
                manifest["archive"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest()
            )
            self.assertEqual(
                [entry["path"] for entry in manifest["files"]],
                [
                    f"vc/atlmfc/lib/{arch}/nafxcw.lib",
                    f"vc/lib/{arch}/chkstk.obj",
                    f"vc/lib/{arch}/libcmt.lib",
                ],
            )

    def test_legacy_toolsets_record_their_media(self) -> None:
        vc = self.root / "installed/Program Files/Microsoft Visual Studio 12.0/VC"
        _write(vc / "lib/libcmt.lib")
        _write(vc / "lib/arm/libcmt.lib")
        _write(vc / "atlmfc/lib/uafxcw.lib")
        _write(vc / "atlmfc/lib/arm/uafxcw.lib")
        output = self.root / "out"
        collector.main(
            [
                "toolset-legacy",
                "--vc-directory", str(vc),
                "--vs-year", "2013",
                "--toolset-version", "12.0.21005",
                "--media", "https://download.microsoft.com/VS2013_RTM_PRO_ENU.iso",
                "--media-sha256", "3bf357ca",
                "--arch", "x86",
                "--arch", "arm",
                "--zstd-level", "3",
                "--output", str(output),
            ]
        )
        manifest = json.loads((output / "vs2013-12.0.21005-arm.json").read_text())
        self.assertEqual(manifest["visual_studio"], {"year": 2013})
        self.assertEqual(manifest["toolset_version"], "12.0.21005")
        self.assertEqual(manifest["source"]["sha256"], "3bf357ca")
        self.assertEqual(
            [entry["path"] for entry in manifest["files"]],
            ["vc/atlmfc/lib/arm/uafxcw.lib", "vc/lib/arm/libcmt.lib"],
        )
        extra = self.root / "installed/Program Files/Microsoft Visual Studio 12.0/VC/ce/lib/x86"
        _write(extra / "corelibc.lib")
        collector.main(
            [
                "toolset-legacy", "--vc-directory", str(vc), "--vs-year", "2013",
                "--toolset-version", "12.0.21005", "--media", "m", "--media-sha256", "s",
                "--install-root", str(self.root / "installed"),
                "--extra-directory", "x86:Program Files/Microsoft Visual Studio 12.0/VC/ce/lib/x86",
                "--arch", "x86", "--zstd-level", "3", "--output", str(output),
            ]
        )
        manifest = json.loads((output / "vs2013-12.0.21005-x86.json").read_text())
        self.assertIn(
            "extra/program files/microsoft visual studio 12.0/vc/ce/lib/x86/corelibc.lib",
            [entry["path"] for entry in manifest["files"]],
        )
        with self.assertRaisesRegex(collector.CollectionError, "not arch:path"):
            collector.parse_extra_directories(["arm64"])
        with self.assertRaisesRegex(collector.CollectionError, "not a version"):
            collector.main(["toolset-legacy", "--vc-directory", str(vc), "--vs-year", "2013",
                            "--toolset-version", "RTM", "--media", "m", "--media-sha256", "s",
                            "--arch", "x86", "--output", str(output)])


if __name__ == "__main__":
    unittest.main()
