"""Tests for evaluate_probes.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import evaluate_probes  # noqa: E402


def match(address: int, name: str, confirmed: bool | None = None) -> dict:
    entry = {"addr": hex(address), "name": name}
    if confirmed is not None:
        entry["confirmed"] = confirmed
    return entry


class SettledNameTests(unittest.TestCase):
    def test_one_name_settles_and_two_dispute(self) -> None:
        names, disputed = evaluate_probes.settled_names(
            [match(0x10, "a"), match(0x10, "a"), match(0x20, "b"), match(0x20, "c")]
        )
        self.assertEqual(names, {0x10: "a"})
        self.assertEqual(disputed, {0x20})

    def test_the_one_confirmed_name_settles_a_dispute(self) -> None:
        names, disputed = evaluate_probes.settled_names(
            [match(0x20, "b", True), match(0x20, "c", False)]
        )
        self.assertEqual(names, {0x20: "b"})
        self.assertEqual(disputed, set())

    def test_two_confirmed_names_still_dispute(self) -> None:
        names, disputed = evaluate_probes.settled_names(
            [match(0x20, "b", True), match(0x20, "c", True)]
        )
        self.assertEqual(names, {})
        self.assertEqual(disputed, {0x20})


if __name__ == "__main__":
    unittest.main()
