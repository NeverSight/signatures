"""Producer boundary tests. No mock library is used as a recognition fixture."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_library_feature_probes as probes


class EvidenceTests(unittest.TestCase):
    def test_dependencies_preserve_escaped_paths_and_reject_unknown_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "header with spaces.h"
            header.write_text("// fixture\n", encoding="utf-8")
            deps = root / "probe.d"
            deps.write_text("probe.o: " + str(header).replace(" ", "\\ ") + " \\\n\n", encoding="utf-8")
            paths = probes.dependency_paths(deps, False)
            self.assertEqual(paths, [header])
            entries = probes.header_evidence(paths + paths, {"headers": root})
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], "headers/header with spaces.h")
            self.assertEqual(len(entries[0]["sha256"]), 64)
            with self.assertRaises(probes.ProbeError):
                probes.header_evidence(paths, {"headers": root / "unrelated"})

    def test_windows_dependencies_use_the_declared_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dependencies.json"
            data = {"Version": "1.2", "Data": {"Includes": ["C:/SDK/include/vector"]}}
            path.write_text(json.dumps(data), encoding="utf-8-sig")
            self.assertEqual(probes.dependency_paths(path, True), [Path("C:/SDK/include/vector")])
            data["Version"] = "9.0"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(probes.ProbeError):
                probes.dependency_paths(path, True)

    def test_cross_target_output_cannot_be_reported_as_the_requested_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.o"
            path.write_bytes(bytes.fromhex("cffaedfe0c000001") + bytes(24))
            probes.verify_object(path, "aarch64-macho")
            with self.assertRaises(probes.ProbeError):
                probes.verify_object(path, "x86_64-coff")
            path.write_bytes(bytes.fromhex("cffaedfe07000001") + bytes(24))
            with self.assertRaises(probes.ProbeError):
                probes.verify_object(path, "aarch64-macho")

    def test_failed_command_keeps_diagnostics_and_never_reports_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            argv = [sys.executable, "-c", "import sys; print('partial'); sys.stderr.write('failed'); sys.exit(3)"]
            with self.assertRaises(probes.ProbeError):
                probes.command(argv, output, "failed")
            self.assertEqual((output / "failed.stdout.txt").read_text(), "partial\n")
            self.assertEqual((output / "failed.stderr.txt").read_text(), "failed")

    def test_preprocessed_headers_are_not_retained_even_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            failure = subprocess.TimeoutExpired(["compiler"], 180, output=b"private header", stderr=b"timeout")
            with patch.object(probes.subprocess, "run", side_effect=failure):
                with self.assertRaises(probes.ProbeError):
                    probes.command(["compiler"], output, "macros", keep_stdout=False)
            self.assertFalse((output / "macros.stdout.txt").exists())
            self.assertEqual((output / "macros.stderr.txt").read_bytes(), b"timeout")

    def test_configuration_values_are_expanded_not_guessed(self):
        text = 'some preprocessed header\nND_CONFIG "_LIBCPP_VERSION" "230000"\nND_CONFIG "_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT" ""\n'
        self.assertEqual(probes.read_macros(text), {
            "_LIBCPP_VERSION": "230000", "_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT": ""})


if __name__ == "__main__":
    unittest.main()
