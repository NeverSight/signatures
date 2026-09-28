#!/usr/bin/env python3
"""Build and collect the MASM32 SDK's libraries.

The MASM32 SDK does not ship its libraries. Its installer unpacks their
assembler sources and builds them on the user's machine with the SDK's own
ML.EXE and LINK.EXE (makelibs.bat). Each row of .github/masm32-matrix.json
names an SDK release, where one of the mirrors masm32.com lists serves it
(masm32.com itself answers scripts with a browser challenge), the SHA-256 its
archive must have, and the library sources it builds.

The installer holds the SDK as a 7-Zip archive, which this carves out and
unpacks. Each library's make.bat then runs under Wine as makelibs.bat runs
it: from M:\\masm32, which the scripts address as \\masm32. debug.lib, which
the SDK ships prebuilt, joins the built libraries. LINK stamps every member
and object with the time of the build, so those stamps are cleared: two
builds of one release then give the same archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_msvc_libraries as collector  # noqa: E402

DEFAULT_MATRIX = HERE.parent / ".github" / "masm32-matrix.json"
SEVEN_ZIP_SIGNATURE = bytes.fromhex("377abcaf271c")
ARCHIVE_MAGIC = b"!<arch>\n"

# What each library source directory's make.bat builds into \masm32\lib.
LIBRARY_OUTPUTS = {"m32lib": "masm32.lib", "fpulib": "fpu.lib", "datetime": "datetime.lib"}


class BuildError(RuntimeError):
    """The SDK archive or its build is not what the matrix row says."""


def row_named(matrix: Path, name: str) -> dict:
    rows = [row for row in json.loads(matrix.read_text(encoding="utf-8")) if row["name"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{matrix.name} has no row {name!r}")
    return rows[0]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def carve_payload(installer: bytes) -> bytes:
    """The 7-Zip archive an installer carries, from its signature on."""

    start = installer.find(SEVEN_ZIP_SIGNATURE)
    if start < 0:
        raise BuildError("the installer holds no 7-Zip archive")
    return installer[start:]


def unpack(archive: Path, work: Path) -> Path:
    """Unpack the SDK into work/drive/masm32 and return that directory."""

    with zipfile.ZipFile(archive) as bundle:
        installers = [name for name in bundle.namelist() if name.lower().endswith(".exe")]
        if len(installers) != 1:
            raise BuildError(f"{archive.name} holds {len(installers)} programs, not one installer")
        payload = carve_payload(bundle.read(installers[0]))
    packed = work / "sdk.7z"
    packed.write_bytes(payload)
    root = work / "drive" / "masm32"
    shutil.rmtree(root, ignore_errors=True)
    subprocess.run(["7z", "x", "-y", f"-o{root}", str(packed)], check=True,
                   stdout=subprocess.DEVNULL)
    return root


def clear_timestamps(data: bytes) -> bytes:
    """A library archive with its member dates and object time stamps zeroed."""

    if not data.startswith(ARCHIVE_MAGIC):
        raise BuildError("a built library is not an archive")
    out = bytearray(data)
    offset = len(ARCHIVE_MAGIC)
    while offset + 60 <= len(data):
        name = data[offset:offset + 16].rstrip()
        size = int(data[offset + 48:offset + 58].decode("ascii").strip())
        out[offset + 16:offset + 28] = b"0".ljust(12)
        body = offset + 60
        # A COFF object's TimeDateStamp follows its Machine and section count;
        # linker members and import objects (which begin 00 00) have none.
        if name not in (b"/", b"//") and size >= 20 and data[body:body + 2] != b"\x00\x00":
            out[body + 4:body + 8] = bytes(4)
        offset = body + size + (size & 1)
    return bytes(out)


def find_path(root: Path, *parts: str) -> Path:
    """A path under root, whatever the case of each part.

    Releases spell the same names differently: DateTime.lib, or
    vkdebug/DBPROC/DEBUG.LIB in 8.2.
    """

    path = root
    for part in parts:
        matches = [entry for entry in path.iterdir() if entry.name.lower() == part.lower()] \
            if path.is_dir() else []
        if len(matches) != 1:
            raise BuildError(f"{path} holds no {part}")
        path = matches[0]
    return path


def wine_environment(work: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update({
        "WINEPREFIX": str(work / "prefix"),
        "WINEDEBUG": "-all",
        # Neither .NET nor a browser engine is needed to run a make file.
        "WINEDLLOVERRIDES": "mscoree,mshtml=",
    })
    environment.pop("DISPLAY", None)
    return environment


def build(root: Path, directories: list[str], wine: str, work: Path) -> None:
    """Run each library's make.bat as makelibs.bat does, from M:\\masm32."""

    environment = wine_environment(work)
    subprocess.run([wine, "wineboot", "-i"], env=environment, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    drive = work / "prefix" / "dosdevices" / "m:"
    drive.unlink(missing_ok=True)
    drive.symlink_to(root.parent)
    for directory in directories:
        log = work / f"build-{directory}.log"
        with log.open("w", encoding="utf-8", errors="replace") as output:
            # A make.bat pauses on failure; with no input it goes on and the
            # missing library is reported below.
            subprocess.run([wine, "cmd", "/c", f"cd /d M:\\masm32\\{directory} && make.bat"],
                           env=environment, stdin=subprocess.DEVNULL, stdout=output,
                           stderr=subprocess.STDOUT, check=False)
    subprocess.run([wine, "wineboot", "-e"], env=environment, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def collect(root: Path, directories: list[str], work: Path) -> list[collector.CollectedFile]:
    """The built libraries, stamps cleared, and the prebuilt debug.lib."""

    staged = work / "libraries"
    shutil.rmtree(staged, ignore_errors=True)
    staged.mkdir(parents=True)
    files = []
    for directory in directories:
        name = LIBRARY_OUTPUTS[directory]
        built = find_path(root, "lib", name)
        target = staged / name
        target.write_bytes(clear_timestamps(built.read_bytes()))
        files.append(collector.CollectedFile(target, PurePosixPath("masm32", "lib", name)))
    debug = find_path(root, "vkdebug", "dbproc", "debug.lib")
    files.append(collector.CollectedFile(debug, PurePosixPath("masm32", "lib", "debug.lib")))
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--name", required=True, help="the matrix row to build")
    parser.add_argument("--zip", type=Path, required=True, help="the row's downloaded SDK archive")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wine", default="wine64", help="the Wine program to build with")
    parser.add_argument("--zstd-level", type=int, default=15)
    args = parser.parse_args(argv)

    row = row_named(args.matrix, args.name)
    if sha256(args.zip) != row["sha256"]:
        print(f"error: {args.zip.name} does not have the expected SHA-256", file=sys.stderr)
        return 1
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    try:
        root = unpack(args.zip, work)
        build(root, row["build"], args.wine, work)
        files = collect(root, row["build"], work)
    except (BuildError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    wine_version = subprocess.run([args.wine, "--version"], capture_output=True,
                                  text=True).stdout.strip()
    args.output.mkdir(parents=True, exist_ok=True)
    collector.emit_asset(
        output=args.output,
        asset=f"masm32-{row['version']}-x86",
        kind="library",
        arch="x86",
        files=files,
        extra={
            "library": "masm32",
            "library_version": row["version"],
            "source": {"media": row["media"], "sha256": row["sha256"]},
            # The same sources and assembler as the release rizin imported,
            # so its imported lines are superseded by name.
            "reproduces_import": True,
            "built_with": wine_version,
        },
        level=args.zstd_level,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
