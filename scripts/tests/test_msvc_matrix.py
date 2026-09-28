"""Tests for msvc_matrix.py and the checked-in matrix."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import msvc_matrix  # noqa: E402


class CheckedInMatrixTests(unittest.TestCase):
    def test_every_row_is_well_formed(self) -> None:
        rows = msvc_matrix.load(msvc_matrix.DEFAULT_MATRIX)
        self.assertGreaterEqual(len(rows), 13)
        for row in rows:
            for invocation in row["collect"].split(";"):
                self.assertTrue(invocation.strip().startswith(
                    ("toolset ", "toolset-v140 ", "winsdk ")), row["name"])
            # A row installs through one mechanism at most.
            mechanisms = [bool(row["components"]), bool(row["choco"]), bool(row["sdk_installer"])]
            self.assertLessEqual(sum(mechanisms), 1, row["name"])

    def test_vs2026_has_no_arm32(self) -> None:
        rows = {row["name"]: row for row in msvc_matrix.load(msvc_matrix.DEFAULT_MATRIX)}
        for name in ("vs2026", "vs2026-14.50"):
            self.assertNotIn("--arch arm ", rows[name]["collect"] + " ")
            self.assertNotIn("arm", rows[name]["probe_arches"])


class SelectTests(unittest.TestCase):
    ROWS = [{"name": "a"}, {"name": "b"}, {"name": "c"}]

    def test_empty_selection_keeps_every_row(self) -> None:
        self.assertEqual(msvc_matrix.select(self.ROWS, ""), self.ROWS)

    def test_selection_keeps_matrix_order(self) -> None:
        self.assertEqual(msvc_matrix.select(self.ROWS, "c, a"), [{"name": "a"}, {"name": "c"}])

    def test_unknown_row_is_an_error(self) -> None:
        with self.assertRaises(SystemExit):
            msvc_matrix.select(self.ROWS, "a d")


class OutputTests(unittest.TestCase):
    def test_github_output_holds_one_matrix_line(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "out"
            msvc_matrix.main(["--rows", "vs2015,winsdk-10.0.20348.0", "--github-output", str(output)])
            line = output.read_text().strip()
        self.assertTrue(line.startswith("matrix="))
        matrix = json.loads(line[len("matrix="):])
        rows = {row["name"]: row for row in matrix["include"]}
        self.assertEqual(rows["vs2015"]["probe_flags"], "")
        self.assertEqual(rows["vs2015"]["probe_winsdk"], "10.0.17763.0")
        self.assertEqual(rows["winsdk-10.0.20348.0"]["choco"], "windows-sdk-10-version-2104-all")
        self.assertEqual(rows["winsdk-10.0.20348.0"]["components"], "")


if __name__ == "__main__":
    unittest.main()
