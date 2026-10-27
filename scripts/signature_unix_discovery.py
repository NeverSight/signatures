"""Official Unix-family metadata discovery. Never fetches or executes artifacts.

A source revision is not a shipping binary: all entries remain unpublished
candidates until licensing, exact build profile, collection and validation exist.
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

LIMIT = 8 * 1024 * 1024
SHA1 = re.compile(r"[0-9a-fA-F]{40}\Z")


def _source(id, kind, url, platform, domain, notes, **options):
    return dict(id=id, adapter="unix", kind=kind, url=url,
                profile=dict(platform=platform, domain=domain, architecture="unknown",
                             format="source-metadata", build_config="unknown"),
                notes=notes, **options)


SOURCES = [
    _source("linux-kernel", "kernel", "https://www.kernel.org/releases.json", "linux", "kernel",
            "Upstream kernel releases, not distro or vendor kernel configurations."),
    _source("gnu-glibc", "listing", "https://ftp.gnu.org/gnu/glibc/", "linux", "user-runtime",
            "Source versions only; ABI, target architecture and distro patches require a build profile.",
            filename_pattern=r"glibc-(\d+\.\d+(?:\.\d+)?)\.tar\.xz"),
    _source("musl-libc", "listing", "https://musl.libc.org/releases/", "linux", "user-runtime",
            "Source feed may be unavailable; do not infer success or replace glibc signatures.",
            filename_pattern=r"musl-(\d+\.\d+\.\d+)\.tar\.gz"),
    _source("android-common-gki", "gitiles", "https://android.googlesource.com/kernel/common/+refs/tags?format=JSON", "android", "kernel",
            "Common/GKI source tags are not OEM firmware, vendor modules or a device kernel configuration.",
            ref_pattern=r"(?:android\d+.*|\d+\.\d+-android\d+.*)"),
    _source("android-bionic", "gitiles", "https://android.googlesource.com/platform/bionic/+refs/tags?format=JSON", "android", "user-runtime",
            "Android bionic source, distinct from glibc and NDK prebuilts; source tags do not imply device ABI coverage.",
            ref_pattern=r"android-.*"),
    _source("android-ndk", "ndk", "https://dl.google.com/android/repository/repository2-3.xml", "android", "user-sdk",
            "Archive host OS is not target architecture. Inspect sysroot triples after reviewed collection; never install automatically."),
]
for _id, _repo, _domain in (("apple-xnu", "xnu", "kernel"), ("apple-libc", "Libc", "user-runtime"),
                            ("apple-libsystem", "Libsystem", "user-runtime")):
    SOURCES.append(_source(_id, "github", f"https://api.github.com/repos/apple-oss-distributions/{_repo}/tags?per_page=100",
                          "apple", _domain,
                          "Bounded first 100 source tags, not exhaustive history. Open-source release does not identify shipping iOS/macOS kernelcache or libSystem binaries.",
                          ref_pattern=re.escape(_repo) + r"-.*"))
SOURCES.append(_source("llvm-runtimes", "github", "https://api.github.com/repos/llvm/llvm-project/tags?per_page=100",
                       "cross-platform", "compiler-runtime", "Source tags cover compiler-rt/libc++/libunwind inputs, not ABI-specific built archives. Bounded first 100 tags, not exhaustive history.",
                       ref_pattern=r"llvmorg-\d+\.\d+\.\d+(?:-rc\d+)?"))


def _base(version, evidence, channel="unknown"):
    return dict(version=version, channel=channel,
                collection_status="needs_exact_build_profile_and_collection_adapter",
                evidence=[evidence], artifact_verified=False)


def _commit(value):
    if not isinstance(value, str) or not SHA1.fullmatch(value):
        raise ValueError("invalid source commit or tag object")
    return value.lower()


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(v for k, v in attrs if k == "href" and v)


def discover_source(source, fetch):
    raw, supplied = fetch(source["url"], LIMIT)
    if len(raw) > LIMIT:
        raise ValueError("metadata limit exceeded")
    evidence = dict(supplied, metadata_sha256=hashlib.sha256(raw).hexdigest())
    kind = source["kind"]
    result = []
    if kind == "kernel":
        for release in json.loads(raw)["releases"]:
            version = release["version"]
            if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:-rc\d+)?", version):
                continue
            row = _base(version, evidence, "preview" if "-rc" in version else "stable")
            row.update(upstream_track=release["moniker"], source_archive_url=release.get("source"),
                       source_signature_url=release.get("pgp"), source_archive_sha256=None,
                       end_of_life=release.get("iseol"), collection_status="needs_source_digest_build_profile_and_adapter")
            result.append(row)
    elif kind == "listing":
        parser = _Links()
        parser.feed(raw.decode("utf-8"))
        links = set(parser.links)
        for name in sorted(links):
            match = re.fullmatch(source["filename_pattern"], name)
            if not match:
                continue
            row = _base(match[1], evidence, "stable")
            row.update(source_archive_url=urljoin(source["url"], name), source_archive_sha256=None,
                       source_signature_url=urljoin(source["url"], name + ".sig") if name + ".sig" in links else None,
                       collection_status="needs_source_digest_build_profile_and_adapter")
            result.append(row)
    elif kind == "gitiles":
        if not raw.startswith(b")]}'\n"):
            raise ValueError("missing Gitiles anti-XSSI prefix")
        for name, item in sorted(json.loads(raw[5:]).items()):
            if not re.fullmatch(source["ref_pattern"], name):
                continue
            row = _base(name, evidence, "preview" if re.search(r"(?:preview|beta|(?:^|[-_])rc\d*)", name, re.I) else "upstream-source-tag")
            row.update(source_commit=_commit(item.get("peeled", item["value"])),
                       source_tag_object=_commit(item["value"]))
            result.append(row)
    elif kind == "github":
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("expected GitHub tag list")
        for tag in data:
            if not re.fullmatch(source["ref_pattern"], tag["name"]):
                continue
            row = _base(tag["name"], evidence, "preview" if re.search(r"-rc\d+$", tag["name"]) else "upstream-source-tag")
            row.update(source_commit=_commit(tag["commit"]["sha"]), feed_scope="first_100_tags_not_exhaustive")
            result.append(row)
    elif kind == "ndk":
        # Reject DTD/entity input rather than accepting expansion in external XML.
        xml_text = raw.decode("utf-8", errors="strict")
        if "\x00" in xml_text or xml_text.startswith("\ufeff"):
            raise ValueError("only plain UTF-8 repository XML is supported")
        if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
            raise ValueError("DTD/entity declarations are unsupported")
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as error:
            raise ValueError("invalid repository XML") from error
        # Repository XML mixes namespace-qualified roots with plain descendants.
        for node in root.iter():
            node.tag = node.tag.rsplit("}", 1)[-1]
        channels = {n.attrib["id"]: n.text for n in root.findall("channel")}
        for package in root.findall("remotePackage"):
            path = package.attrib.get("path", "")
            if not re.fullmatch(r"ndk;\d+(?:\.\d+){2,3}", path):
                continue
            revision = package.find("revision")
            if revision is None:
                raise ValueError("NDK revision missing")
            preview = int(revision.findtext("preview", "0"))
            channel_ref = package.find("channelRef")
            channel = channels.get(channel_ref.attrib.get("ref"), "unknown") if channel_ref is not None else "unknown"
            if preview:
                channel = "preview"
            row = _base(path.split(";", 1)[1], evidence, channel)
            archives = []
            for archive in package.findall("archives/archive"):
                complete = archive.find("complete")
                if complete is None:
                    continue
                name = complete.findtext("url", "")
                if not re.fullmatch(r"[A-Za-z0-9._-]+\.zip", name):
                    raise ValueError("unexpected NDK archive URL")
                checksum = complete.find("checksum")
                if checksum is None:
                    raise ValueError("NDK archive checksum absent")
                algorithm = checksum.attrib.get("type", "sha1").lower()
                value = (checksum.text or "").strip().lower()
                lengths = {"sha1": 40, "sha256": 64}
                if algorithm not in lengths or not re.fullmatch(r"[0-9a-f]{%d}" % lengths[algorithm], value):
                    raise ValueError("invalid NDK checksum")
                size_text = (complete.findtext("size") or "").strip()
                if not re.fullmatch(r"[0-9]+", size_text) or int(size_text) <= 0:
                    raise ValueError("invalid NDK archive size")
                archives.append(dict(host_os=archive.findtext("host-os", "unknown"), target_architecture="unknown",
                                     url="https://dl.google.com/android/repository/" + name,
                                     checksum_algorithm=algorithm, checksum=value, size=int(size_text)))
            if not archives:
                raise ValueError("NDK package has no complete archives")
            row.update(package=path, revision_preview=preview, payloads=archives,
                       collection_status="needs_license_review_archive_adapter_and_target_triple_inspection")
            result.append(row)
    else:
        raise ValueError("unknown Unix metadata adapter")
    if not result:
        raise ValueError("no recognized upstream version records")
    return result


def adapters(fetch):
    """Bind the scheduler's reviewed, bounded HTTPS transport."""
    return {"unix": lambda source: discover_source(source, fetch)}
