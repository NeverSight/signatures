"""Offline tests: no network, collectors, installed SDKs, or sigmaker execution."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("updates", Path(__file__).resolve().parents[1] / "collect_signature_updates.py")
u = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(u)


class UpdatesTests(unittest.TestCase):
    def test_names_and_members(self):
        for value in ("../escape", "/tmp/file", "a\\b", "C:escape", "", "./lib/a.a", "lib//a.a"):
            with self.assertRaises(ValueError):
                u.safe_member(value)
        self.assertEqual(u.safe_member("lib/a.a"), "lib/a.a")
        with self.assertRaises(ValueError):
            u.safe_name("../file")

    def test_explicit_bounded_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(u, "targets", return_value={}):
                for names in ([], ["x"] * 4, ["x", "x"]):
                    with self.assertRaises(ValueError):
                        u.collect(root, root, names, False, 1, 1024)

    def test_no_shell_or_installers(self):
        row = {"collect": 'toolset --vs-year 2026 --vswhere-version "[18.0,19.0)" --arch x64', "components": ["ignored"]}
        cmd = u.commands(Path("repo"), "msvc", row, Path("work"), Path("out"))[0]
        self.assertIn("[18.0,19.0)", cmd)
        self.assertNotIn("eval", cmd)
        for invocation in ("install something", "toolset --output=/tmp/x"):
            with self.assertRaises(ValueError):
                u.commands(Path("repo"), "msvc", {"collect": invocation}, Path("w"), Path("o"))

    def test_expected_architectures(self):
        self.assertEqual(u.expected_arches("homebrew", {"bottles": [{"tag": "arm64_sonoma"}, {"tag": "sonoma"}]}), {"x64", "arm64"})
        self.assertEqual(u.expected_arches("elf", {"directories": ["elf/arm/32"]}), {"arm"})

    def fixture(self, root):
        content = b"private test bytes, not a real library"
        (root / "test.tar.zst").write_bytes(content)
        m = {"asset": "test", "arch": "x64", "format": "elf", "files": [{"path": "lib/a.a", "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}],
             "archive": {"name": "test.tar.zst", "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}}
        (root / "test.json").write_text(json.dumps(m))
        return m

    def test_manifest_digest_and_partial_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            m = self.fixture(root)
            self.assertEqual(set(u.validate_assets(root)), {"test"})
            (root / "test.tar.zst").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                u.validate_assets(root)
            m = self.fixture(root)
            m["unavailable"] = [{"package": "missing"}]
            (root / "test.json").write_text(json.dumps(m))
            with self.assertRaises(ValueError):
                u.validate_assets(root)

    def test_tar_members_hashes_links_and_budget(self):
        for kind in ("valid", "hash", "link", "traversal", "duplicate", "missing", "budget"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                if kind != "missing":
                    item = tarfile.TarInfo("../escape" if kind == "traversal" else "lib/a.a")
                    item.size = 3
                    if kind == "link":
                        item.type, item.linkname = tarfile.SYMTYPE, "/tmp/escape"
                    tar.addfile(item, io.BytesIO(b"abc"))
                    if kind == "duplicate":
                        tar.addfile(item, io.BytesIO(b"abc"))
            stream.seek(0)
            m = {"files": [{"path": "lib/a.a", "size": 3, "sha256": hashlib.sha256(b"xyz" if kind == "hash" else b"abc").hexdigest()}]}
            if kind == "valid":
                u.validate_tar(stream, m, 20000)
            else:
                with self.assertRaises(ValueError, msg=kind):
                    u.validate_tar(stream, m, 2 if kind == "budget" else 20000)

    def test_oversized_pax_header_is_rejected_before_payload(self):
        item = tarfile.TarInfo("pax")
        item.type = tarfile.XHDTYPE
        item.size = 1024 * 1024 * 1024
        with self.assertRaisesRegex(ValueError, "oversized tar metadata"):
            u.validate_tar(io.BytesIO(item.tobuf()), {"files": []}, 2 << 30)

    def test_pinned_cache_rehash_and_corrupt_receipt_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "scripts").mkdir(parents=True)
            state = Path(tmp) / "state"
            row = {"name": "fixture", "library": "fixture", "bottles": [{"tag": "sonoma"}]}
            calls = []
            def fake_run(argv, work, log, seconds, max_bytes):
                calls.append(argv)
                assets = work / "assets"
                m = self.fixture(assets)
                m.update(format="macho", library="fixture")
                (assets / "test.json").write_text(json.dumps(m))
            with patch.object(u, "targets", return_value={"homebrew:fixture": ("homebrew", row)}), \
                 patch.object(u, "capabilities", return_value=[]), \
                 patch.object(u, "run_bounded", side_effect=fake_run):
                first = u.collect(root, state, ["homebrew:fixture"], True, 2, 1024)[0]
                self.assertEqual(first["status"], "collected_candidate")
                second = u.collect(root, state, ["homebrew:fixture"], True, 2, 1024)[0]
                self.assertEqual(second["status"], "unchanged")
                self.assertEqual(len(calls), 1)
                Path(second["receipt"]).write_text("broken JSON")
                third = u.collect(root, state, ["homebrew:fixture"], True, 2, 1024)[0]
                self.assertEqual(third["status"], "collected_candidate")
                self.assertEqual(len(calls), 2)

    def test_baseline_collects_all_old_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "elf/x86/64"
            d.mkdir(parents=True)
            (d / "one.sources.json").write_text(json.dumps({"sources": [{"asset": "old-a", "archive_sha256": "a" * 64}, {"asset": "old-b", "archive_sha256": "b" * 64}]}))
            self.assertEqual(set(u.baseline_requirements(root, {"elf/x86/64"})), {"old-a", "old-b"})

    def test_mutable_msvc_not_marked_available_on_linux(self):
        with patch.object(u.os, "name", "posix"), patch.object(u.shutil, "which", return_value="/bin/tool"):
            self.assertTrue(u.capabilities("msvc"))
            self.assertFalse(u.capabilities("homebrew"))


if __name__ == "__main__":
    unittest.main()
