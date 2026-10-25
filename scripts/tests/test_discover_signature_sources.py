"""Offline upstream discovery and candidate handoff tests."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import discover_signature_sources as d
import collect_signature_updates as c


class DiscoveryTests(unittest.TestCase):
    def source(self):
        return {"id": "fixture", "adapter": "fixture", "profile": {"platform": "fixture"}, "notes": "fixture"}

    def test_https_allowlist(self):
        for url in ("http://api.nuget.org/a", "https://evil.test/a", "https://user@api.nuget.org/a", "https://api.nuget.org:444/a"):
            with self.assertRaises(ValueError):
                d.checked_url(url)
        self.assertEqual(d.checked_url("https://api.nuget.org/a"), "https://api.nuget.org/a")

    def test_snapshots_dedup_new_versions_recovery_and_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            source = self.source()
            config = {"sources": [source]}
            entries = [{"version": "1.0", "evidence": [{"timestamp": "old"}]}]
            with patch.dict(d.ADAPTERS, {"fixture": lambda s: copy.deepcopy(entries)}):
                first = d.discover(config, ["fixture"], state)[0]
                self.assertEqual(first["changes"][0]["event"], "initial_observation")
                entries[0]["evidence"] = [{"timestamp": "new"}]
                self.assertFalse(d.discover(config, ["fixture"], state)[0]["changes"])
                candidate = Path(first["changes"][0]["candidate"])
                candidate.write_text("truncated")
                repaired = d.discover(config, ["fixture"], state)[0]
                self.assertEqual(repaired["changes"][0]["event"], "candidate_recovered")
                json.loads(candidate.read_text())
                entries.append({"version": "1.1", "evidence": []})
                self.assertEqual(d.discover(config, ["fixture"], state)[0]["changes"][0]["event"], "new_version")
                source["profile"]["platform"] = "corrected"
                changed = d.discover(config, ["fixture"], state)[0]
                self.assertTrue(all(x["event"] == "profile_changed" for x in changed["changes"]))

    def test_failed_fetch_preserves_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            config = {"sources": [self.source()]}
            with patch.dict(d.ADAPTERS, {"fixture": lambda s: [{"version": "1"}]}):
                d.discover(config, ["fixture"], state)
            old = (state / "fixture/latest.json").read_bytes()
            def fail(source):
                raise OSError("network unavailable")
            with patch.dict(d.ADAPTERS, {"fixture": fail}):
                self.assertEqual(d.discover(config, ["fixture"], state)[0]["status"], "unavailable")
            self.assertEqual((state / "fixture/latest.json").read_bytes(), old)

    def formula(self):
        return {"name": "zlib", "versions": {"stable": "1.3.3"}, "revision": 0,
                "bottle": {"stable": {"rebuild": 0, "files": {"arm64_sonoma": {"sha256": "a" * 64},
                "sonoma": {"sha256": "b" * 64}, "x86_64_linux": {"sha256": "c" * 64}}}}}

    def test_homebrew_pin_identity_and_collection_bridge(self):
        source = {"id": "homebrew-zlib", "adapter": "homebrew", "url": "https://formulae.brew.sh/api/formula/zlib.json", "formula": "zlib", "archives": ["lib/libz.a"]}
        formula = self.formula()
        with patch.object(d, "json_fetch", return_value=(formula, {})):
            entry = d.homebrew(source)[0]
        row = entry["candidate_matrix_row"]
        self.assertEqual(len(row["bottles"]), 2)
        old_name = row["name"]
        formula["bottle"]["stable"]["files"]["sonoma"]["sha256"] = "d" * 64
        with patch.object(d, "json_fetch", return_value=(formula, {})):
            self.assertNotEqual(d.homebrew(source)[0]["candidate_matrix_row"]["name"], old_name)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts/signature-discovery-sources.json").write_text(json.dumps({"sources": [source]}))
            candidate = root / "candidate.json"
            candidate.write_text(json.dumps(dict(entry, source="homebrew-zlib")))
            key, checked = c.candidate_target(root, candidate)
            self.assertEqual(key, "homebrew:" + old_name)
            self.assertEqual(checked, row)
            row["archives"] = ["../../escape"]
            candidate.write_text(json.dumps(dict(entry, source="homebrew-zlib")))
            with self.assertRaises(ValueError):
                c.candidate_target(root, candidate)

    def test_homebrew_rejects_unknown_target_and_wrong_formula(self):
        source = {"url": "unused", "formula": "zlib", "archives": []}
        for change in ("wrong-name", "unknown-target"):
            formula = self.formula()
            if change == "wrong-name":
                formula["name"] = "other"
            else:
                formula["bottle"]["stable"]["files"]["mystery_os"] = {"sha256": "e" * 64}
            with patch.object(d, "json_fetch", return_value=(formula, {})), self.assertRaises(ValueError):
                d.homebrew(source)

    def test_nuget_numeric_order_all_versions_and_resumable_pins(self):
        source = {"url": "index", "package": "example", "channel": "stable"}
        seen = []
        def fixture(url):
            if url == "index":
                return {"versions": ["1.9.0", "1.10.0", "1.11.0", "2.0.0-preview"]}, {}
            version = url.rsplit("/", 1)[1].removesuffix(".json")
            if "registration" in url:
                seen.append(version)
                return {"catalogEntry": "catalog/" + version}, {}
            return {"id": "example", "version": version, "packageHashAlgorithm": "SHA512", "packageHash": base64.b64encode(bytes(64)).decode()}, {}
        with patch.object(d, "json_fetch", side_effect=fixture):
            first = d.nuget(source)
            self.assertEqual([e["version"] for e in first], ["1.11.0", "1.10.0", "1.9.0"])
            self.assertEqual(first[-1]["collection_status"], "pending_catalog_hash")
            second = d.nuget(dict(source, _previous_entries=first))
            self.assertTrue(all("package_sha512_base64" in e for e in second))
            self.assertEqual(seen, ["1.11.0", "1.10.0", "1.9.0"])

    def test_visual_studio_catalog_hash_rejected(self):
        channel = {"channelItems": [{"id": "Microsoft.VisualStudio.Manifests.VisualStudio", "payloads": [{"fileName": "VisualStudio.vsman", "url": "unused", "sha256": "a" * 64}]}]}
        with patch.object(d, "json_fetch", return_value=(channel, {})), patch.object(d, "fetch", return_value=(b"{}", {})), self.assertRaisesRegex(ValueError, "hash mismatch"):
            d.visual_studio({"url": "unused", "channel": "stable"})


if __name__ == "__main__":
    unittest.main()
