#!/usr/bin/env python3
"""Unpack an old Visual C++ toolset's libraries from its installation media.

Microsoft still publishes the installation media of Visual Studio 2005, 2008,
2012 and 2013; the Visual Studio 2010 disc survives as MSDN published it, on
the Internet Archive. No current Windows image can install them.  Their
libraries sit in Windows Installer packages on those discs, and nothing needs
installing to read them:

  * 7-Zip pulls the packages a matrix row names out of the disc image;
  * cabextract opens a self-extracting bundle when the packages sit in one
    (Visual Studio 2005 Express);
  * msitools' msiextract unpacks every package with the directory layout it
    would install.

Old packages name their directories the way the Directory table spells them,
"target|long:source|long", which msiextract keeps; each part is reduced to its
long target name.  The script prints, as JSON, the VC directory the packages
install and the product version the named package states, for
collect_msvc_libraries.py's toolset-legacy command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


# What a linker reads; two packages must never install different copies.
LIBRARY_SUFFIXES = (".lib", ".obj")


class ExtractionError(RuntimeError):
    """The media does not hold what the matrix row says it does."""


def target_name(component: str) -> str:
    """The long target name of a Directory table entry.

    "VS80|Microsoft Visual Studio 8:source" names the target directory
    "Microsoft Visual Studio 8".
    """

    target = component.split(":", 1)[0]
    return target.split("|", 1)[1] if "|" in target else target


def _merge(source: Path, destination: Path) -> None:
    """Move what source holds into destination, merging directories."""

    for child in list(source.iterdir()):
        target = destination / child.name
        if not target.exists():
            child.rename(target)
        elif child.is_dir() and target.is_dir():
            _merge(child, target)
        elif child.is_file() and target.is_file() and (
            child.read_bytes() == target.read_bytes()
            or child.suffix.lower() not in LIBRARY_SUFFIXES
        ):
            # Packages also install runtime files, such as the ANSI and the
            # Unicode ATL80.dll, into one place; only libraries must agree.
            child.unlink()
        else:
            raise ExtractionError(f"{child} and {target} are both installed, differently")
    source.rmdir()


def normalize(root: Path) -> None:
    """Rename every directory under root to its long target name, merging clashes."""

    for directory in sorted((p for p in root.rglob("*") if p.is_dir()),
                            key=lambda p: len(p.parts), reverse=True):
        wanted = target_name(directory.name)
        if directory.parent == root and wanted.lower() == "sourcedir":
            # Some packages name the Directory table's root, TARGETDIR, too.
            wanted = "."
        if wanted == directory.name:
            continue
        # "." names the parent directory itself.
        destination = directory.parent if wanted in ("", ".") else directory.with_name(wanted)
        if destination.exists():
            _merge(directory, destination)
        else:
            directory.rename(destination)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def product_version(msi: Path) -> str:
    """The ProductVersion property of a Windows Installer package."""

    table = subprocess.run(["msiinfo", "export", str(msi), "Property"],
                           check=True, capture_output=True, text=True).stdout
    for row in table.splitlines():
        name, _, value = row.partition("\t")
        if name == "ProductVersion":
            return value.strip()
    raise ExtractionError(f"{msi.name} states no ProductVersion")


def extract(iso: Path, members: list[str], bundle: str | None, work: Path) -> Path:
    """Unpack the named packages and return the directory they install into."""

    # msiextract runs from each package's directory, so every path is absolute.
    work = work.resolve()
    media = work / "media"
    root = work / "installed"
    for directory in (media, root):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
    wanted = members + ([bundle] if bundle else [])
    subprocess.run(["7z", "x", "-y", f"-o{media}", str(iso), *wanted],
                   check=True, stdout=subprocess.DEVNULL)
    if bundle:
        if not (media / bundle).is_file():
            raise ExtractionError(f"{iso.name} holds no {bundle}")
        subprocess.run(["cabextract", "-q", "-d", str(media / "bundle"), str(media / bundle)],
                       check=True, stdout=subprocess.DEVNULL)
    packages = sorted(p for p in media.rglob("*") if p.suffix.lower() == ".msi")
    if not packages:
        raise ExtractionError(f"{iso.name}: {wanted} name no Windows Installer package")
    for package in packages:
        # External cabinets sit beside the package and are found from there.
        subprocess.run(["msiextract", "-C", str(root), package.name],
                       check=True, cwd=package.parent, stdout=subprocess.DEVNULL)
    normalize(root)
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="the image's expected SHA-256")
    parser.add_argument("--member", action="append", default=[],
                        help="image path or glob of a package to unpack (repeatable)")
    parser.add_argument("--bundle", help="image path of a self-extracting package bundle")
    parser.add_argument("--vc-directory", required=True,
                        help="where the packages install VC, relative to the install root")
    parser.add_argument("--version-package", required=True,
                        help="file name of the package whose ProductVersion names the toolset")
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args(argv)

    if sha256(args.iso) != args.sha256.lower():
        print(f"error: {args.iso.name} does not have the expected SHA-256", file=sys.stderr)
        return 1
    try:
        root = extract(args.iso.resolve(), args.member, args.bundle, args.work)
        vc = root / args.vc_directory
        if not (vc / "lib").is_dir():
            raise ExtractionError(f"the packages install no {args.vc_directory}/lib")
        media = args.work.resolve() / "media"
        named = [p for p in media.rglob("*")
                 if p.name.lower() == args.version_package.lower()]
        if len(named) != 1:
            raise ExtractionError(f"{args.version_package} is not one package of the media")
        version = product_version(named[0])
        # The packages are installed now; a runner has no room to keep both.
        shutil.rmtree(media)
        print(json.dumps({"root": str(root), "vc_directory": str(vc),
                          "product_version": version}))
    except (ExtractionError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
