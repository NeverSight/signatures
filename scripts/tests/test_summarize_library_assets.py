"""Tests for summarize_library_assets.py."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_msvc_libraries as collector  # noqa: E402
import summarize_library_assets as summarize  # noqa: E402


@unittest.skipIf(shutil.which("zstd") is None, "zstd is not installed")
class SummarizeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        kits = root / "kits"
        for arch in ("x64", "arm64"):
            for name in ("ucrt/{a}/libucrt.lib", "um/{a}/kernel32.lib"):
                path = kits / "Lib/10.0.26100.0" / name.format(a=arch)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"!<arch>\n" + arch.encode())
        self.assets = root / "assets"
        collector.main(
            [
                "winsdk",
                "--sdk", "10.0.26100.0",
                "--kits-root", str(kits),
                "--arch", "x64",
                "--arch", "arm64",
                "--zstd-level", "3",
                "--output", str(self.assets),
            ]
        )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_writes_sums_index_and_notes(self) -> None:
        summarize.main([str(self.assets), "--tag", "msvc-libs-test", "--commit", "abc123"])
        sums = (self.assets / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 4)
        self.assertTrue(any(line.endswith("  winsdk-10.0.26100.0-x64.tar.zst") for line in sums))
        index = json.loads((self.assets / "assets.json").read_text())
        self.assertEqual(
            [entry["asset"] for entry in index["assets"]],
            ["winsdk-10.0.26100.0-arm64", "winsdk-10.0.26100.0-x64"],
        )
        self.assertNotIn("files", index["assets"][0])
        self.assertEqual(index["assets"][0]["file_count"], 2)
        notes = (self.assets / "RELEASE.md").read_text()
        self.assertIn("`winsdk-10.0.26100.0-arm64`", notes)
        self.assertIn("abc123", notes)

    def test_libraries_name_their_installer_or_source_archive(self) -> None:
        library = self.assets.parent / "libz.a"
        library.write_bytes(b"!<arch>\n")
        for asset, source in (
            ("masm32-11r-x86", {"media": "http://www.oby.ro/masm32/masm32v11r.zip"}),
            ("mingw32-zlib-1.3-x86", {"url": "https://example.org/zlib-1.3.tar.gz"}),
        ):
            collector.emit_asset(
                output=self.assets, asset=asset, kind="library", arch="x86",
                files=[collector.CollectedFile(library, Path("lib/libz.a"))],
                extra={"library": asset.rsplit("-", 2)[0], "library_version": "1",
                       "source": source},
                level=3,
            )
        collector.emit_asset(
            output=self.assets, asset="ubuntu-zlib-x64", kind="library", arch="x64",
            files=[collector.CollectedFile(library, Path("lib/libz.a"))],
            extra={"library": "ubuntu-zlib", "format": "elf",
                   "sources": [{"package": "a.deb"}, {"package": "b.deb"}],
                   "unavailable": [{"package": "c.deb"}]},
            level=3,
        )
        summarize.main([str(self.assets), "--tag", "t", "--commit", "c"])
        notes = (self.assets / "RELEASE.md").read_text()
        self.assertIn("| `masm32-11r-x86` | masm32 | 1 | http://www.oby.ro/masm32/masm32v11r.zip |",
                      notes)
        self.assertIn("| `ubuntu-zlib-x64` | ubuntu-zlib |  "
                      "| 2 packages sigdb-source records, 1 of them unavailable |", notes)
        self.assertIn("| `mingw32-zlib-1.3-x86` | mingw32-zlib | 1 "
                      "| https://example.org/zlib-1.3.tar.gz |", notes)

    def test_notes_name_only_what_the_release_holds(self) -> None:
        summarize.main([str(self.assets), "--tag", "t", "--commit", "c"])
        notes = (self.assets / "RELEASE.md").read_text()
        self.assertIn("unmodified Microsoft", notes)
        self.assertNotIn("## Toolsets", notes)
        self.assertNotIn("sigdb-source", notes)

        elf = self.assets.parent / "elf"
        elf.mkdir()
        library = self.assets.parent / "libc.a"
        library.write_bytes(b"!<arch>\n")
        collector.emit_asset(
            output=elf, asset="ubuntu-libc6-x64", kind="library", arch="x64",
            files=[collector.CollectedFile(library, Path("lib/libc.a"))],
            extra={"library": "ubuntu-libc6", "format": "elf",
                   "sources": [{"package": "a.deb"}], "unavailable": []},
            level=3,
        )
        summarize.main([str(elf), "--tag", "t", "--commit", "c"])
        notes = (elf / "RELEASE.md").read_text()
        self.assertIn("rizin's sigdb-source records", notes)
        self.assertNotIn("Microsoft", notes)
        self.assertNotIn("## Toolsets", notes)
        self.assertNotIn("## Windows SDKs", notes)
        self.assertIn("| `ubuntu-libc6-x64` | ubuntu-libc6 |", notes)

    def test_archive_that_disagrees_with_its_manifest_fails(self) -> None:
        archive = self.assets / "winsdk-10.0.26100.0-x64.tar.zst"
        archive.write_bytes(archive.read_bytes() + b"tampered")
        with self.assertRaises(SystemExit) as raised:
            summarize.main([str(self.assets), "--tag", "t", "--commit", "c"])
        self.assertIn("does not match", str(raised.exception))

    def test_missing_archive_fails(self) -> None:
        (self.assets / "winsdk-10.0.26100.0-arm64.tar.zst").unlink()
        with self.assertRaises(SystemExit) as raised:
            summarize.main([str(self.assets), "--tag", "t", "--commit", "c"])
        self.assertIn("missing", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
