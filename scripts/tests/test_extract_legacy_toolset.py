"""Tests for extract_legacy_toolset.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import extract_legacy_toolset as extract  # noqa: E402


class TargetNameTests(unittest.TestCase):
    def test_the_long_target_name_is_kept(self) -> None:
        self.assertEqual(
            extract.target_name("Microsoft Visual Studio 8:VS80.NET|Microsoft Visual Studio 8"),
            "Microsoft Visual Studio 8",
        )
        self.assertEqual(extract.target_name("VS80|Microsoft Visual Studio 8"),
                         "Microsoft Visual Studio 8")
        self.assertEqual(extract.target_name("VC:Vc7|Vc7"), "VC")
        self.assertEqual(extract.target_name("lib"), "lib")


class NormalizeTests(unittest.TestCase):
    def test_nested_directories_take_their_target_names_and_merge(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            old = root / "Program Files" / "Microsoft Visual Studio 8:VS80|VS8" / "VC:Vc7|Vc7" / "lib:lib|lib"
            old.mkdir(parents=True)
            (old / "libcmt.lib").write_bytes(b"!<arch>\n")
            other = root / "Program Files" / "Microsoft Visual Studio 8" / "VC" / "atlmfc"
            other.mkdir(parents=True)
            extract.normalize(root)
            vc = root / "Program Files" / "Microsoft Visual Studio 8" / "VC"
            self.assertTrue((vc / "lib" / "libcmt.lib").is_file())
            self.assertTrue((vc / "atlmfc").is_dir())
            self.assertEqual(sorted(p.name for p in (root / "Program Files").iterdir()),
                             ["Microsoft Visual Studio 8"])


if __name__ == "__main__":
    unittest.main()
