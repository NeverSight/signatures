#!/usr/bin/env python3
"""Discover new official source versions; emit immutable candidates, never install."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 32 * 1024 * 1024
ALLOWED_HOSTS = {"aka.ms", "download.visualstudio.microsoft.com", "download.microsoft.com",
                 "api.nuget.org", "formulae.brew.sh", "api.github.com",
                 "android.googlesource.com", "dl.google.com", "ftp.gnu.org", "musl.libc.org", "www.kernel.org"}


def checked_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("source URL is outside the reviewed HTTPS allowlist")
    return url


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, url):
        checked_url(url)
        return super().redirect_request(request, fp, code, msg, headers, url)


def fetch(url, limit=MAX_BYTES):
    checked_url(url)
    opener = urllib.request.build_opener(CheckedRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "NeverD-signature-source-discovery", "Accept": "application/json, text/plain, text/html"})
    with opener.open(request, timeout=30) as response:
        checked_url(response.url)
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("source metadata exceeds byte limit")
        return raw, {"url": url, "resolved_url": response.url,
                     "metadata_sha256": hashlib.sha256(raw).hexdigest()}


def json_fetch(url):
    raw, evidence = fetch(url)
    return json.loads(raw), evidence


def version_key(version):
    return tuple(int(n) for n in re.findall(r"\d+", version))


def nuget(source):
    data, evidence = json_fetch(source["url"])
    channel = source.get("channel", "stable")
    versions = [v for v in data["versions"] if re.fullmatch(r"\d+(?:\.\d+){1,4}(?:-[A-Za-z0-9.-]+)?", v)
                and (("-" in v) == (channel == "preview"))]
    if not versions or len(versions) > 10000:
        raise ValueError("empty or excessive NuGet version inventory")
    package = source["package"].lower()
    prior = {e["version"]: e for e in source.get("_previous_entries", [])}
    result, budget = [], 2
    for version in sorted(set(versions), key=lambda v: (version_key(v), v), reverse=True):
        stem = f"https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.{version}.nupkg"
        if version in prior and prior[version].get("package_sha512_base64"):
            result.append(prior[version])
            continue
        entry = {"version": version, "package": package, "package_url": stem,
                 "channel": channel, "collection_status": "pending_catalog_hash",
                 "evidence": [evidence]}
        if budget:
            budget -= 1
            registration, registration_evidence = json_fetch(f"https://api.nuget.org/v3/registration5-semver1/{package}/{version}.json")
            catalog, catalog_evidence = json_fetch(registration["catalogEntry"])
            if catalog["id"].lower() != package or catalog["version"].lower() != version.lower():
                raise ValueError("NuGet catalog identity mismatch")
            value = catalog.get("packageHash")
            if catalog.get("packageHashAlgorithm", "").upper() != "SHA512" or not value or len(base64.b64decode(value, validate=True)) != 64:
                raise ValueError("NuGet catalog lacks a valid package SHA-512")
            entry.update(package_sha512_base64=value,
                         collection_status="needs_package_adapter_and_license_review",
                         evidence=[evidence, registration_evidence, catalog_evidence])
        result.append(entry)
    return result


def visual_studio(source):
    channel, channel_evidence = json_fetch(source["url"])
    items = [item for item in channel["channelItems"] if item.get("id") == "Microsoft.VisualStudio.Manifests.VisualStudio"]
    if len(items) != 1:
        raise ValueError("ambiguous Visual Studio catalog entry")
    payloads = [p for p in items[0]["payloads"] if p.get("fileName", "").endswith(".vsman")]
    if len(payloads) != 1:
        raise ValueError("ambiguous Visual Studio catalog payload")
    payload = payloads[0]
    raw, catalog_evidence = fetch(payload["url"])
    observed = hashlib.sha256(raw).hexdigest()
    if observed != payload["sha256"].lower() or ("size" in payload and len(raw) != payload["size"]):
        raise ValueError(f"Visual Studio catalog hash mismatch: expected {payload['sha256']}, observed {observed}; expected bytes {payload.get('size')}, observed {len(raw)}")
    catalog = json.loads(raw)
    groups = {}
    # Track actual VC CRT package versions/target identifiers, not VS productDisplayVersion.
    for package in catalog["packages"]:
        match = re.fullmatch(r"Microsoft\.(?:VC\..*|VisualCpp)\.CRT\.(x86|x64|ARM|ARM64|ARM64EC)\.Desktop", package["id"], re.I)
        if not match:
            continue
        version = package["version"]
        if not re.fullmatch(r"\d+(?:\.\d+){2,4}", version):
            raise ValueError("unexpected VC package version")
        entry = groups.setdefault(version, {"version": version, "channel": source["channel"],
                 "target_architectures": [], "packages": [],
                 "collection_status": "needs_matching_installed_msvc_toolset",
                 "evidence": [channel_evidence, catalog_evidence]})
        arch = match[1].lower()
        if arch not in entry["target_architectures"]:
            entry["target_architectures"].append(arch)
        entry["packages"].append({"id": package["id"], "version": version,
                                  "payloads": [{k: p[k] for k in ("fileName", "sha256", "size", "url") if k in p}
                                               for p in package.get("payloads", [])]})
    for entry in groups.values():
        entry["target_architectures"].sort()
        entry["packages"].sort(key=lambda p: p["id"])
        for package in entry["packages"]:
            package["payloads"].sort(key=lambda p: p.get("fileName", ""))
    if not groups:
        raise ValueError("catalog has no recognized VC CRT packages")
    return sorted(groups.values(), key=lambda x: version_key(x["version"]))


def homebrew(source):
    formula, evidence = json_fetch(source["url"])
    if formula["name"] != source["formula"]:
        raise ValueError("Homebrew formula identity mismatch")
    version = formula["versions"]["stable"]
    revision = formula.get("revision", 0)
    keg = version + (f"_{revision}" if revision else "")
    bottles = []
    for tag, item in sorted(formula["bottle"]["stable"]["files"].items()):
        # Linux bottles hold ELF, not Mach-O. Keep them out of this collector row.
        if "linux" in tag:
            continue
        if not re.fullmatch(r"(?:arm64_)?(?:high_sierra|mojave|catalina|big_sur|monterey|ventura|sonoma|sequoia|tahoe|golden_gate)", tag) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError("invalid bottle pin")
        bottles.append({"tag": tag, "sha256": item["sha256"]})
    if not bottles:
        raise ValueError("no macOS bottle pins")
    bottle_id = hashlib.sha256(json.dumps(bottles, sort_keys=True).encode()).hexdigest()[:12]
    row = {"name": f"homebrew-{source['formula']}-{keg}-{bottle_id}",
           "library": f"homebrew-{source['formula']}-{keg}-{bottle_id}", "formula": source["formula"],
           "version": keg, "archives": source["archives"], "bottles": bottles}
    matrix = ROOT / ".github/homebrew-matrix.json"
    existing = json.loads(matrix.read_text()) if matrix.exists() else []
    already_pinned = any(r.get("formula") == source["formula"] and r.get("version") == keg
                         and sorted(r.get("bottles", []), key=lambda b: b["tag"]) == bottles
                         for r in existing)
    return [{"version": keg, "channel": "stable", "already_pinned": already_pinned, "bottle_rebuild": formula["bottle"]["stable"].get("rebuild", 0),
             "candidate_matrix_row": row, "collection_status": "already_pinned" if already_pinned else "eligible_versioned_collection_candidate",
             "evidence": [evidence]}]


import signature_unix_discovery

ADAPTERS = {"nuget": nuget, "visual-studio": visual_studio, "homebrew": homebrew}
ADAPTERS.update(signature_unix_discovery.adapters(fetch))


def canonical_hash(value):
    # A regenerated index or catalog timestamp alone is not a new feature source.
    semantic = {k: v for k, v in value.items() if k != "evidence"}
    return hashlib.sha256(json.dumps(semantic, sort_keys=True).encode()).hexdigest()


def candidate_key(entry, source):
    return canonical_hash({"entry_hash": canonical_hash(entry), "profile": source["profile"],
                           "adapter": source["adapter"], "source": source["id"]})


def discover(config, selected, state):
    if not selected or len(selected) > 5 or len(set(selected)) != len(selected):
        raise ValueError("select one to five distinct sources")
    by_id = {s["id"]: s for s in config["sources"]}
    results = []
    for source_id in selected:
        if source_id not in by_id or not re.fullmatch(r"[a-z0-9-]+", source_id):
            raise ValueError(f"unknown source {source_id}")
        source = by_id[source_id]
        report = {"source": source_id, "profile": source["profile"], "notes": source["notes"],
                  "sampled_at": datetime.now(timezone.utc).isoformat(), "publishable": False}
        root = state / source_id
        root.mkdir(parents=True, exist_ok=True)
        try:
            previous_file = root / "latest.json"
            previous = json.loads(previous_file.read_text()) if previous_file.exists() else None
            runtime_source = dict(source, _previous_entries=previous["entries"] if previous else [])
            entries = ADAPTERS[source["adapter"]](runtime_source)
            old_source = dict(source, profile=previous["profile"]) if previous else source
            old = {candidate_key(x, old_source): x for x in previous["entries"]} if previous else {}
            old_versions = set(previous.get("observed_versions", [])) if previous else set()
            old_versions.update(x["version"] for x in old.values())
            changes = []
            for entry in entries:
                key = candidate_key(entry, source)
                event = "initial_observation" if previous is None else ("changed_source_metadata_or_pins" if entry["version"] in old_versions else "new_version")
                if previous and previous["profile"] != source["profile"]:
                    event = "profile_changed"
                candidate = dict(entry, event=event, source=source_id, profile=source["profile"], publishable=False)
                # Content addressing preserves earlier versions; it never overwrites their rows.
                target = root / (key + ".candidate.json")
                if target.exists():
                    try:
                        saved = json.loads(target.read_text())
                        saved_entry = {k: v for k, v in saved.items() if k not in ("event", "source", "profile", "publishable")}
                        if candidate_key(saved_entry, source) == key and saved.get("profile") == source["profile"] and not target.is_symlink():
                            continue
                    except (OSError, ValueError):
                        pass
                if key in old:
                    candidate["event"] = event = "candidate_recovered"
                temporary_candidate = target.with_suffix(".tmp")
                temporary_candidate.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n")
                temporary_candidate.replace(target)
                changes.append({"version": entry["version"], "event": event, "candidate": str(target)})
            report.update(status="observed", entries=entries, changes=changes,
                          observed_versions=sorted(old_versions | {x["version"] for x in entries}),
                          pending_catalog_hashes=sum(e.get("collection_status") == "pending_catalog_hash" for e in entries),
                          coverage="bounded metadata feed, not binary or signature coverage")
            temporary = root / "latest.tmp"
            temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            temporary.replace(root / "latest.json")
        except (OSError, ValueError, KeyError, TypeError) as error:
            report.update(status="unavailable", error=str(error))
            # A failed fetch does not replace the last successful comparison baseline.
        results.append(report)
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", required=True, type=Path)
    p.add_argument("--source", action="append", required=True)
    args = p.parse_args(argv)
    state = args.state.resolve()
    if state == ROOT or ROOT in state.parents:
        p.error("state must be private and outside the checkout")
    state.mkdir(parents=True, exist_ok=True)
    lock = state / ".discovery-lock"
    try:
        lock.mkdir()
    except FileExistsError:
        p.error("another run or stale discovery lock exists")
    try:
        config = json.loads((ROOT / "scripts/signature-discovery-sources.json").read_text())
        config["sources"].extend(signature_unix_discovery.SOURCES)
        results = discover(config, args.source, state)
        print(json.dumps(results, indent=2, sort_keys=True))
        return 2 if any(x["status"] == "unavailable" for x in results) else 0
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}))
        return 2
    finally:
        lock.rmdir()


if __name__ == "__main__":
    sys.exit(main())
