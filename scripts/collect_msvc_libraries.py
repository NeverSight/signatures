#!/usr/bin/env python3
"""Collect the static libraries that Windows toolchains link into programs.

This runs on a GitHub-hosted Windows image and packs one architecture's
libraries per asset, as a zstd-compressed tar with a JSON manifest beside it:

    <asset>.tar.zst   the libraries
    <asset>.json      what was collected: versions, runner image, and the
                      size and SHA-256 of every file in the archive

Two kinds of asset exist:

``toolset``
    One MSVC toolset of one Visual Studio installation:
    ``vc/lib/<arch>/`` and, unless disabled, ``vc/atlmfc/lib/<arch>/``.
    Assets are named ``vs<year>-<toolset version>-<arch>``.

``winsdk``
    One Windows SDK: its Universal CRT (``ucrt/<arch>/``) and its user-mode
    libraries (``um/<arch>/``).  Most of ``um`` is import libraries, which
    carry no code; they are kept because the static members that live among
    them are exactly the SDK code a program links.  Assets are named
    ``winsdk-<sdk version>-<arch>``.

The archives are the raw inputs that signatures are generated from.  They are
kept in a release so that a signature file can always be traced back to, and
regenerated from, the exact bytes it was made from.

Only the top level of each library directory is taken.  The ``store``,
``onecore``, ``spectre``, and ``enclave`` variants are link-time alternatives
that a default build does not use, and would multiply the size of every asset.

Every missing input is an error.  A leg that silently collected nothing would
publish an empty signature file that looks like coverage.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

SCHEMA_VERSION = 1

# The directory names MSVC and the Windows SDK use for each target.
ARCHITECTURES = ("x86", "x64", "arm", "arm64")

# Toolsets up to v140 predate VC/Tools/MSVC/<version>.  Their VC directory
# names architectures after the old cross-compiler directories.
LEGACY_ARCH_DIRECTORIES = {
    "x86": PurePosixPath("."),
    "x64": PurePosixPath("amd64"),
    "arm": PurePosixPath("arm"),
}

# The file types a library directory holds that a linker consumes.  Loose
# objects (chkstk.obj, setargv.obj, ...) are linked by name, so they are
# library code as much as the archives are.
LIBRARY_SUFFIXES = (".lib", ".obj")
ARCHIVE_MAGIC = b"!<arch>\n"

_VERSION = re.compile(r"^\d+(\.\d+)+$")


class CollectionError(RuntimeError):
    """An input the leg was asked to collect is missing or malformed."""


@dataclass(frozen=True)
class CollectedFile:
    """One file placed in an archive."""

    source: Path
    member: PurePosixPath

    def describe(self) -> dict:
        size, digest = hash_file(self.source)
        return {"path": str(self.member), "size": size, "sha256": digest}


def hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _version_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in name.split("."))


def resolve_toolset_directory(installation: Path, toolset: str) -> Path:
    """Return VC/Tools/MSVC/<version> for a toolset request.

    ``default`` reads the version the installation builds with when nothing
    is pinned.  Anything else is a version prefix such as ``14.29`` or
    ``14.16``; the newest installed directory that starts with it wins, so a
    request names a toolset family rather than one servicing build.
    """

    tools_root = installation / "VC" / "Tools" / "MSVC"
    if not tools_root.is_dir():
        raise CollectionError(f"{tools_root} does not exist")

    if toolset == "default":
        marker = (
            installation
            / "VC"
            / "Auxiliary"
            / "Build"
            / "Microsoft.VCToolsVersion.default.txt"
        )
        if not marker.is_file():
            raise CollectionError(f"{marker} does not exist")
        version = marker.read_text(encoding="utf-8-sig").strip()
        if not _VERSION.match(version):
            raise CollectionError(f"{marker} names no toolset version: {version!r}")
        directory = tools_root / version
        if not directory.is_dir():
            raise CollectionError(
                f"the default toolset {version} is not installed under {tools_root}"
            )
        return directory

    if not _VERSION.match(toolset):
        raise CollectionError(f"unrecognized toolset request {toolset!r}")
    candidates = [
        entry
        for entry in tools_root.iterdir()
        if entry.is_dir()
        and _VERSION.match(entry.name)
        and (entry.name == toolset or entry.name.startswith(toolset + "."))
    ]
    if not candidates:
        installed = sorted(entry.name for entry in tools_root.iterdir() if entry.is_dir())
        raise CollectionError(
            f"no MSVC toolset matching {toolset} under {tools_root}; "
            f"installed: {', '.join(installed) or 'none'}"
        )
    return max(candidates, key=lambda entry: _version_key(entry.name))


def is_coff_input(path: Path) -> bool:
    """Whether a .lib or .obj file is a COFF archive or object.

    Old Windows SDKs still ship 16-bit OMF libraries (MAPI.Lib), which hold no
    code a PE image can link and which neverd-sigmaker rightly rejects.
    """

    with path.open("rb") as stream:
        head = stream.read(len(ARCHIVE_MAGIC))
    if head.startswith(ARCHIVE_MAGIC):
        return True
    # An OMF object begins with a THEADR or LHEADR record.
    return path.suffix.lower() == ".obj" and head[:1] not in (b"\x80", b"\x82")


def library_files(directory: Path) -> list[Path]:
    files = []
    for entry in directory.iterdir():
        if not entry.is_file() or entry.suffix.lower() not in LIBRARY_SUFFIXES:
            continue
        if not is_coff_input(entry):
            print(f"skipping {entry}: not a COFF archive or object", file=sys.stderr)
            continue
        files.append(entry)
    return sorted(files, key=lambda entry: entry.name.lower())


def _require_libraries(directory: Path, what: str) -> list[Path]:
    if not directory.is_dir():
        raise CollectionError(f"{directory} does not exist; {what} is not installed")
    files = library_files(directory)
    if not any(path.suffix.lower() == ".lib" for path in files):
        raise CollectionError(f"{directory} holds no .lib files")
    return files


def collect_toolset_files(
    toolset_directory: Path, arch: str, include_atlmfc: bool
) -> list[CollectedFile]:
    """List one architecture's libraries from a VC/Tools/MSVC/<version> toolset."""

    if arch not in ARCHITECTURES:
        raise CollectionError(f"unsupported architecture {arch!r}")
    collected = [
        CollectedFile(path, PurePosixPath("vc", "lib", arch, path.name))
        for path in _require_libraries(
            toolset_directory / "lib" / arch,
            f"the {arch} build tools for {toolset_directory.name}",
        )
    ]
    if include_atlmfc:
        collected.extend(
            CollectedFile(path, PurePosixPath("vc", "atlmfc", "lib", arch, path.name))
            for path in _require_libraries(
                toolset_directory / "atlmfc" / "lib" / arch,
                f"ATL/MFC for {arch} ({toolset_directory.name})",
            )
        )
    return collected


def collect_legacy_files(
    vc_directory: Path, arch: str, include_atlmfc: bool, label: str = "v140"
) -> list[CollectedFile]:
    """List one architecture's libraries from a pre-2017 ``VC`` directory."""

    if arch not in LEGACY_ARCH_DIRECTORIES:
        raise CollectionError(f"the {label} layout has no {arch!r} libraries")
    relative = LEGACY_ARCH_DIRECTORIES[arch]
    collected = [
        CollectedFile(path, PurePosixPath("vc", "lib", arch, path.name))
        for path in _require_libraries(
            vc_directory / "lib" / relative, f"the {label} {arch} build tools"
        )
    ]
    if include_atlmfc:
        collected.extend(
            CollectedFile(path, PurePosixPath("vc", "atlmfc", "lib", arch, path.name))
            for path in _require_libraries(
                vc_directory / "atlmfc" / "lib" / relative, f"{label} ATL/MFC for {arch}"
            )
        )
    return collected


def collect_winsdk_files(kits_root: Path, sdk_version: str, arch: str) -> list[CollectedFile]:
    """List one architecture's UCRT and user-mode libraries from one Windows SDK."""

    if arch not in ARCHITECTURES:
        raise CollectionError(f"unsupported architecture {arch!r}")
    sdk = kits_root / "Lib" / sdk_version
    ucrt = _require_libraries(sdk / "ucrt" / arch, f"the {arch} UCRT of Windows SDK {sdk_version}")
    if not any(path.name.lower() == "libucrt.lib" for path in ucrt):
        raise CollectionError(f"{sdk / 'ucrt' / arch} holds no libucrt.lib")
    um = _require_libraries(sdk / "um" / arch, f"the {arch} libraries of Windows SDK {sdk_version}")
    return [
        CollectedFile(path, PurePosixPath("winsdk", sdk_version, "ucrt", arch, path.name))
        for path in ucrt
    ] + [
        CollectedFile(path, PurePosixPath("winsdk", sdk_version, "um", arch, path.name))
        for path in um
    ]


def write_archive(files: Sequence[CollectedFile], output: Path, level: int) -> None:
    """Write a reproducible tar of ``files`` and compress it with zstd.

    Members are sorted and carry no owner, permission, or time information
    from the runner, so the tar stream depends only on the library bytes.
    """

    if not output.name.endswith(".tar.zst"):
        raise CollectionError(f"archive name must end in .tar.zst: {output}")
    tar_path = output.with_name(output.name[: -len(".zst")])
    seen: set[str] = set()
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
        for item in sorted(files, key=lambda entry: str(entry.member)):
            name = str(item.member)
            if name.lower() in seen:
                raise CollectionError(f"two inputs map to archive member {name}")
            seen.add(name.lower())
            info = tarfile.TarInfo(name)
            info.size = item.source.stat().st_size
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with item.source.open("rb") as stream:
                archive.addfile(info, stream)
    zstd = shutil.which("zstd")
    if zstd is None:
        raise CollectionError("zstd is not on PATH")
    subprocess.run(
        [zstd, "--quiet", "--force", f"-{level}", "-T0", "--rm", str(tar_path), "-o", str(output)],
        check=True,
    )


def find_installation(vswhere: Path, version_range: str) -> dict:
    """Ask vswhere for the newest installation within ``version_range``."""

    if not vswhere.is_file():
        raise CollectionError(f"{vswhere} does not exist")
    completed = subprocess.run(
        [
            str(vswhere),
            "-products",
            "*",
            "-version",
            version_range,
            "-latest",
            "-format",
            "json",
            "-utf8",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    installations = json.loads(completed.stdout or "[]")
    if not installations:
        raise CollectionError(f"no Visual Studio installation in {version_range}")
    return installations[0]


def describe_installation(record: dict) -> dict:
    catalog = record.get("catalog") or {}
    return {
        "display_name": record.get("displayName"),
        "product_id": record.get("productId"),
        "installation_version": record.get("installationVersion"),
        "product_display_version": catalog.get("productDisplayVersion"),
        "installation_path": record.get("installationPath"),
    }


def file_version(path: Path) -> str | None:
    """Return a Windows executable's file version, or None off Windows."""

    if os.name != "nt" or not path.is_file():
        return None
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-Item -LiteralPath '{path}').VersionInfo.FileVersion",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or None


def build_manifest(
    *,
    asset: str,
    kind: str,
    arch: str,
    files: Sequence[CollectedFile],
    archive: Path,
    extra: dict,
) -> dict:
    archive_size, archive_digest = hash_file(archive)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "asset": asset,
        "kind": kind,
        "arch": arch,
        "archive": {"name": archive.name, "size": archive_size, "sha256": archive_digest},
        "runner": {
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
            "runner_os": os.environ.get("RUNNER_OS"),
        },
        "collected_at": _datetime.datetime.now(_datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "files": [item.describe() for item in sorted(files, key=lambda f: str(f.member))],
    }
    manifest.update(extra)
    return manifest


def emit_asset(
    *,
    output: Path,
    asset: str,
    kind: str,
    arch: str,
    files: Sequence[CollectedFile],
    extra: dict,
    level: int,
) -> dict:
    archive = output / f"{asset}.tar.zst"
    write_archive(files, archive, level)
    manifest = build_manifest(
        asset=asset, kind=kind, arch=arch, files=files, archive=archive, extra=extra
    )
    (output / f"{asset}.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    total = sum(entry["size"] for entry in manifest["files"])
    print(
        f"{archive.name}: {len(manifest['files'])} files, "
        f"{total / (1 << 20):.1f} MiB raw, "
        f"{manifest['archive']['size'] / (1 << 20):.1f} MiB compressed",
        flush=True,
    )
    return manifest


def _program_files_x86() -> Path:
    return Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))


def run_toolset(args: argparse.Namespace) -> None:
    if args.installation_path is not None:
        installation = {"installationPath": str(args.installation_path)}
    else:
        installation = find_installation(args.vswhere, args.vswhere_version)
    installation_path = Path(installation["installationPath"])
    toolset_directory = resolve_toolset_directory(installation_path, args.toolset)
    version = toolset_directory.name
    for arch in args.arch:
        files = collect_toolset_files(toolset_directory, arch, args.atlmfc)
        compiler = file_version(toolset_directory / "bin" / "Hostx64" / "x64" / "cl.exe")
        emit_asset(
            output=args.output,
            asset=f"vs{args.vs_year}-{version}-{arch}",
            kind="toolset",
            arch=arch,
            files=files,
            extra={
                "visual_studio": {"year": args.vs_year, **describe_installation(installation)},
                "toolset_request": args.toolset,
                "toolset_version": version,
                "compiler_version": compiler,
                "atlmfc": args.atlmfc,
            },
            level=args.zstd_level,
        )


def run_toolset_v140(args: argparse.Namespace) -> None:
    vc_directory = args.vc_directory
    if not (vc_directory / "lib").is_dir():
        raise CollectionError(f"{vc_directory / 'lib'} does not exist; v140 is not installed")
    compiler = file_version(vc_directory / "bin" / "cl.exe")
    for arch in args.arch:
        files = collect_legacy_files(vc_directory, arch, args.atlmfc)
        emit_asset(
            output=args.output,
            asset=f"vs2015-14.0-{arch}",
            kind="toolset",
            arch=arch,
            files=files,
            extra={
                "visual_studio": {"year": 2015, "installation_path": str(vc_directory)},
                "toolset_request": "v140",
                "toolset_version": "14.0",
                "compiler_version": compiler,
                "atlmfc": args.atlmfc,
            },
            level=args.zstd_level,
        )


def parse_extra_directories(values: Sequence[str]) -> dict[str, list[str]]:
    """Map "arch:relative/path" arguments to the directories of each architecture."""

    extras: dict[str, list[str]] = {}
    for value in values:
        arch, separator, relative = value.partition(":")
        if not separator or arch not in ARCHITECTURES or not relative.strip("/"):
            raise CollectionError(f"--extra-directory {value!r} is not arch:path")
        extras.setdefault(arch, []).append(relative.strip("/"))
    return extras


def run_toolset_legacy(args: argparse.Namespace) -> None:
    """Collect a toolset that extract_legacy_toolset.py unpacked from its media."""

    if not _VERSION.match(args.toolset_version):
        raise CollectionError(f"{args.toolset_version!r} is not a version")
    extras = parse_extra_directories(args.extra_directory)
    if extras and args.install_root is None:
        raise CollectionError("--extra-directory needs --install-root")
    for arch in args.arch:
        files = collect_legacy_files(
            args.vc_directory, arch, args.atlmfc, label=f"VS {args.vs_year}"
        )
        for relative in extras.get(arch, []):
            member = PurePosixPath("extra", *relative.lower().split("/"))
            files.extend(
                CollectedFile(path, member / path.name)
                for path in _require_libraries(
                    args.install_root / relative, f"{relative} for {arch}"
                )
            )
        emit_asset(
            output=args.output,
            asset=f"vs{args.vs_year}-{args.toolset_version}-{arch}",
            kind="toolset",
            arch=arch,
            files=files,
            extra={
                "visual_studio": {"year": args.vs_year},
                "toolset_request": "legacy",
                "toolset_version": args.toolset_version,
                "source": {"media": args.media, "sha256": args.media_sha256},
                "atlmfc": args.atlmfc,
            },
            level=args.zstd_level,
        )


def run_winsdk(args: argparse.Namespace) -> None:
    for sdk_version in args.sdk:
        for arch in args.arch:
            files = collect_winsdk_files(args.kits_root, sdk_version, arch)
            emit_asset(
                output=args.output,
                asset=f"winsdk-{sdk_version}-{arch}",
                kind="winsdk",
                arch=arch,
                files=files,
                extra={"windows_sdk_version": sdk_version},
                level=args.zstd_level,
            )


def parse_arguments(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output", type=Path, required=True)
    common.add_argument("--zstd-level", type=int, default=15)
    common.add_argument(
        "--arch", action="append", required=True, choices=ARCHITECTURES,
        help="architecture to collect (repeatable)",
    )
    atlmfc = argparse.ArgumentParser(add_help=False)
    atlmfc.add_argument(
        "--atlmfc",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="also collect the ATL/MFC libraries (required to exist when set)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    toolset = commands.add_parser(
        "toolset", parents=[common, atlmfc], help="collect a VC/Tools/MSVC toolset"
    )
    toolset.add_argument("--vs-year", required=True, type=int)
    toolset.add_argument(
        "--vswhere-version", required=True,
        help="vswhere -version range selecting the installation, e.g. [18.0,19.0)",
    )
    toolset.add_argument(
        "--toolset", default="default",
        help="'default' or an MSVC version prefix such as 14.29 or 14.16",
    )
    toolset.add_argument(
        "--vswhere", type=Path,
        default=_program_files_x86() / "Microsoft Visual Studio" / "Installer" / "vswhere.exe",
    )
    toolset.add_argument(
        "--installation-path", type=Path,
        help="use this installation instead of asking vswhere (testing aid)",
    )
    toolset.set_defaults(handler=run_toolset)

    v140 = commands.add_parser(
        "toolset-v140", parents=[common, atlmfc], help="collect the v140 (VS 2015) toolset"
    )
    v140.add_argument(
        "--vc-directory", type=Path,
        default=_program_files_x86() / "Microsoft Visual Studio 14.0" / "VC",
    )
    v140.set_defaults(handler=run_toolset_v140)

    legacy = commands.add_parser(
        "toolset-legacy", parents=[common, atlmfc],
        help="collect a VS 2005-2013 toolset unpacked from its installation media",
    )
    legacy.add_argument("--vc-directory", type=Path, required=True)
    legacy.add_argument("--vs-year", type=int, required=True)
    legacy.add_argument("--toolset-version", required=True,
                        help="the library package's ProductVersion, e.g. 12.0.21005")
    legacy.add_argument("--media", required=True, help="URL of the installation media")
    legacy.add_argument("--media-sha256", required=True)
    legacy.add_argument("--install-root", type=Path,
                        help="the directory the media's packages install under")
    legacy.add_argument("--extra-directory", action="append", default=[],
                        help="arch:path of another library directory under --install-root, "
                             "such as the CRT source-build libraries (repeatable)")
    legacy.set_defaults(handler=run_toolset_legacy)

    winsdk = commands.add_parser("winsdk", parents=[common], help="collect Windows SDK libraries")
    winsdk.add_argument("--sdk", action="append", required=True, help="SDK version (repeatable)")
    winsdk.add_argument(
        "--kits-root", type=Path, default=_program_files_x86() / "Windows Kits" / "10"
    )
    winsdk.set_defaults(handler=run_winsdk)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_arguments(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    args.handler(args)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CollectionError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
