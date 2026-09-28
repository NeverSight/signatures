#!/usr/bin/env python3
"""Index a directory of collected library assets for a release.

Reads every ``<asset>.json`` manifest written by collect_msvc_libraries.py,
checks that the archive beside it is the one the manifest describes, and
writes:

    SHA256SUMS      one line per archive and manifest, sha256sum format
    assets.json     the manifests, minus their per-file lists, in one index
    RELEASE.md      release notes naming every toolset and SDK collected

A manifest whose archive is missing or does not hash to the recorded value
fails the run: a release must never carry an index that disagrees with the
bytes it indexes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

LICENSE_NOTE = """\
These archives hold unmodified static libraries from Microsoft Visual Studio
and the Windows SDK, collected from GitHub-hosted runner images so that the
NeverD signature files in this repository can be traced to, and regenerated
from, the exact bytes they were made from. They remain subject to the license
terms of the products they come from; they are kept here as signature-build
inputs, not as a redistribution of those products.
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifests(directory: Path) -> list[dict]:
    manifests = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "assets.json":
            continue
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("asset") != path.stem:
            raise SystemExit(f"{path.name}: manifest names asset {manifest.get('asset')!r}")
        archive = directory / manifest["archive"]["name"]
        if not archive.is_file():
            raise SystemExit(f"{path.name}: archive {archive.name} is missing")
        if _sha256(archive) != manifest["archive"]["sha256"]:
            raise SystemExit(f"{path.name}: {archive.name} does not match its manifest")
        manifests.append(manifest)
    if not manifests:
        raise SystemExit(f"no asset manifests in {directory}")
    return manifests


def index_entry(manifest: dict) -> dict:
    entry = {key: value for key, value in manifest.items() if key != "files"}
    entry["file_count"] = len(manifest["files"])
    entry["raw_size"] = sum(item["size"] for item in manifest["files"])
    return entry


def release_notes(manifests: list[dict], tag: str, commit: str) -> str:
    lines = [f"# {tag}", "", LICENSE_NOTE, "## Toolsets", ""]
    lines.append("| Asset | Visual Studio | Toolset | Compiler | ATL/MFC | Files |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for manifest in manifests:
        if manifest["kind"] != "toolset":
            continue
        studio = manifest.get("visual_studio") or {}
        product = studio.get("product_display_version") or studio.get("installation_version") or ""
        lines.append(
            f"| `{manifest['asset']}` | {studio.get('year', '')} {product} "
            f"| {manifest.get('toolset_version', '')} "
            f"| {manifest.get('compiler_version') or ''} "
            f"| {'yes' if manifest.get('atlmfc') else 'no'} "
            f"| {len(manifest['files'])} |"
        )
    lines += ["", "## Windows SDKs", ""]
    lines.append("| Asset | SDK | Files |")
    lines.append("| --- | --- | --- |")
    for manifest in manifests:
        if manifest["kind"] != "winsdk":
            continue
        lines.append(
            f"| `{manifest['asset']}` | {manifest.get('windows_sdk_version', '')} "
            f"| {len(manifest['files'])} |"
        )
    libraries = [manifest for manifest in manifests if manifest["kind"] == "library"]
    if libraries:
        lines += ["", "## Other libraries", ""]
        lines.append("| Asset | Library | Version | Source | Files |")
        lines.append("| --- | --- | --- | --- | --- |")
        for manifest in libraries:
            # An installer or disc (MASM32), or a source archive (MinGW builds).
            origin = manifest.get("source") or {}
            source = origin.get("media") or origin.get("url", "")
            lines.append(
                f"| `{manifest['asset']}` | {manifest.get('library', '')} "
                f"| {manifest.get('library_version', '')} | {source} "
                f"| {len(manifest['files'])} |"
            )
    lines += [
        "",
        "Every archive is a zstd-compressed tar; its `.json` manifest lists each",
        "member's size and SHA-256 and records the runner image it came from.",
        "",
        f"Collected by `.github/workflows/msvc-libraries.yml` at `{commit}`.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)

    manifests = load_manifests(args.directory)
    sums = []
    for manifest in manifests:
        for name in (manifest["archive"]["name"], f"{manifest['asset']}.json"):
            sums.append(f"{_sha256(args.directory / name)}  {name}")
    (args.directory / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    (args.directory / "assets.json").write_text(
        json.dumps(
            {"tag": args.tag, "commit": args.commit, "assets": [index_entry(m) for m in manifests]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (args.directory / "RELEASE.md").write_text(
        release_notes(manifests, args.tag, args.commit), encoding="utf-8"
    )
    print(f"indexed {len(manifests)} assets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
