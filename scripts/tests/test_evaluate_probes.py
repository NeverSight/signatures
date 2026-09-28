"""Tests for evaluate_probes.py."""

from __future__ import annotations

import json
import sys
import tempfile
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

    def test_matches_that_share_an_alias_agree_on_the_preferred_one(self) -> None:
        names, disputed = evaluate_probes.settled_names(
            [{"addr": "0x30", "name": "malloc", "aliases": ["__libc_malloc"]},
             {"addr": "0x30", "name": "__libc_malloc", "aliases": ["__malloc"]},
             {"addr": "0x40", "name": "puts", "aliases": ["_IO_puts"]},
             {"addr": "0x40", "name": "fputs"}]
        )
        self.assertEqual(names, {0x30: "__libc_malloc"})
        self.assertEqual(disputed, {0x40})

    def test_two_confirmed_names_still_dispute(self) -> None:
        names, disputed = evaluate_probes.settled_names(
            [match(0x20, "b", True), match(0x20, "c", True)]
        )
        self.assertEqual(names, {})
        self.assertEqual(disputed, {0x20})


class FailureTests(unittest.TestCase):
    def test_a_program_neverd_cannot_read_is_reported_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            neverd = root / "neverd"
            neverd.write_text("#!/bin/sh\necho 'error: failed to load: elf: overlapping' >&2\n"
                              "exit 1\n")
            neverd.chmod(0o755)
            probe = root / "elf-test-arm-o2.elf"
            probe.write_bytes(b"\x7fELF")
            probe.with_suffix(".truth.json").write_text(json.dumps(
                [{"address": "0x10", "names": ["memcpy"], "from_library": True}]))
            result = evaluate_probes.evaluate(neverd, f"--sig-dir={root}", probe)
        self.assertEqual(result.failure, "error: failed to load: elf: overlapping")
        self.assertEqual(result.library_functions, 1)
        self.assertEqual(result.correct, 0)


if __name__ == "__main__":
    unittest.main()
