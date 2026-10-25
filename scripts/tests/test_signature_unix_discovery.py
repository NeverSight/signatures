"""Offline authored fixtures; no network, installation or project execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("unix", Path(__file__).resolve().parents[1] / "signature_unix_discovery.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class DiscoveryTest(unittest.TestCase):
    def run_source(self, id, raw):
        source = next(s for s in m.SOURCES if s["id"] == id)
        if isinstance(raw, dict) or isinstance(raw, list):
            raw = json.dumps(raw).encode()
        return m.discover_source(source, lambda url, limit: (raw, {"url": url, "resolved_url": url}))

    def test_catalogue_unknown_architecture(self):
        self.assertEqual(len(m.SOURCES), 10)
        for source in m.SOURCES:
            self.assertEqual(source["profile"]["architecture"], "unknown")
            self.assertEqual(source["adapter"], "unix")

    def test_kernel_channels_and_unpinned_source(self):
        rows = self.run_source("linux-kernel", {"releases": [
            {"version": "6.12.1", "moniker": "longterm", "source": "https://cdn.kernel.org/source.tar.xz"},
            {"version": "6.13-rc1", "moniker": "mainline"}]})
        self.assertEqual([r["channel"] for r in rows], ["stable", "preview"])
        self.assertIsNone(rows[0]["source_archive_sha256"])
        self.assertFalse(rows[0]["artifact_verified"])

    def test_gitiles_peeled_commit(self):
        data = b")]}'\n" + json.dumps({"android-16.0.0_r1": {"value": "a" * 40, "peeled": "b" * 40}, "aml_other": {"value": "c" * 40}}).encode()
        rows = self.run_source("android-bionic", data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_commit"], "b" * 40)
        self.assertEqual(rows[0]["source_tag_object"], "a" * 40)
        self.assertEqual(rows[0]["evidence"][0]["metadata_sha256"], hashlib.sha256(data).hexdigest())

    def test_gitiles_reject_prefix_and_bad_commit(self):
        for data in (b"{}", b")]}'\n" + b'{"android-16":{"value":"invalid"}}'):
            with self.assertRaises(ValueError):
                self.run_source("android-bionic", data)

    def test_gki_multiple_tracks(self):
        rows = self.run_source("android-common-gki", b")]}'\n" + json.dumps({
            "android14-6.1-2026-01_r1": {"value": "a" * 40},
            "5.10-android12-9": {"value": "b" * 40}}).encode())
        self.assertEqual(len(rows), 2)

    def test_release_links_not_prose_or_path_injection(self):
        rows = self.run_source("gnu-glibc", b'<p>glibc-99.0.tar.xz</p><a href="../glibc-99.1.tar.xz">bad</a><a href="glibc-2.42.tar.xz">ok</a><a href="glibc-2.42.tar.xz.sig">sig</a>')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["version"], "2.42")
        self.assertTrue(rows[0]["source_signature_url"].endswith(".sig"))

    def test_github_tags_not_shipping_artifacts(self):
        rows = self.run_source("apple-xnu", [{"name": "xnu-123.4", "commit": {"sha": "a" * 40}}])
        self.assertEqual(rows[0]["feed_scope"], "first_100_tags_not_exhaustive")
        self.assertFalse(rows[0]["artifact_verified"])
        self.assertNotIn("source_sha256", rows[0])

    def ndk(self, preview="0", checksum="a" * 40, name="android-ndk-test-linux.zip"):
        return f'''<repo xmlns="urn:test"><channel id="channel-0">stable</channel><remotePackage path="ndk;28.0.123"><revision><major>28</major><preview>{preview}</preview></revision><channelRef ref="channel-0"/><archives><archive><host-os>linux</host-os><complete><size>123</size><checksum type="sha1">{checksum}</checksum><url>{name}</url></complete></archive></archives></remotePackage></repo>'''.encode()

    def test_ndk_preview_host_and_weak_hash(self):
        rows = self.run_source("android-ndk", self.ndk(preview="1"))
        self.assertEqual(rows[0]["channel"], "preview")
        item = rows[0]["payloads"][0]
        self.assertEqual(item["host_os"], "linux")
        self.assertEqual(item["target_architecture"], "unknown")
        self.assertEqual(item["checksum_algorithm"], "sha1")

    def test_ndk_reject_unsafe_xml_checksum_and_url(self):
        for data in (b'<broken', b'<!DOCTYPE x [<!ENTITY e "x">]><x/>', self.ndk(checksum="garbage"), self.ndk(name="../evil.zip")):
            with self.assertRaises(ValueError):
                self.run_source("android-ndk", data)

    def test_ndk_reject_non_utf8_xml_and_nul(self):
        xml = self.ndk().decode("utf-8")
        for raw in (xml.encode("utf-16"), xml.encode("utf-16-le"), xml.encode("utf-32"), b"\xef\xbb\xbf" + xml.encode(), xml.encode() + b"\x00"):
            with self.assertRaises(ValueError):
                self.run_source("android-ndk", raw)

    def test_empty_feed_not_success(self):
        with self.assertRaises(ValueError):
            self.run_source("musl-libc", b"<html>503</html>")


if __name__ == "__main__":
    unittest.main()
