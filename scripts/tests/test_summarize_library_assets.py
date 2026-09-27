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
