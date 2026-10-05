#!/usr/bin/env python3
"""Compile the library-feature probes and retain reproducible source evidence.

This producer does not recognize code. It records the actual compiler, headers,
configuration, objects, assembly, symbols and layouts used to author a feature
pack. The consumer's positive/negative recognition tests are a separate gate.
MSVC runs in an x64 VsDevCmd environment; libc++ uses explicitly configured
headers from the requested LLVM source revision, never default SDK C++ headers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from collect_msvc_libraries import hash_file

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "validation/library-features"
MACROS = (
    "_LIBCPP_VERSION", "_LIBCPP_ABI_VERSION", "_LIBCPP_ABI_NAMESPACE",
    "_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT", "_LIBCPP_HARDENING_MODE",
    "_LIBCPP_HAS_WIDE_CHARACTERS", "_MSC_VER", "_MSC_FULL_VER",
    "_MSVC_STL_VERSION", "_MSVC_STL_UPDATE", "_ITERATOR_DEBUG_LEVEL",
    "_DEBUG", "_DLL", "_MT", "__SIZEOF_POINTER__", "__SIZEOF_WCHAR_T__",
    "__BYTE_ORDER__", "__ORDER_LITTLE_ENDIAN__", "_M_X64", "__aarch64__",
)


class ProbeError(RuntimeError):
    pass


def describe(path: Path, name: str | None = None) -> dict:
    size, digest = hash_file(path)
    return {"path": name or path.name, "size": size, "sha256": digest}


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command(argv: list[str], output: Path, stem: str, *, keep_stdout: bool = True,
            allowed_codes: tuple[int, ...] = (0,)) -> str:
    """Retain diagnostics before failing, including timeout and partial output."""
    try:
        result = subprocess.run(argv, cwd=output, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        (output / f"{stem}.stderr.txt").write_bytes(error.stderr or b"")
        if keep_stdout:
            (output / f"{stem}.stdout.txt").write_bytes(error.stdout or b"")
        raise ProbeError(f"{stem}: compiler timed out") from error
    (output / f"{stem}.stderr.txt").write_bytes(result.stderr)
    if keep_stdout:
        (output / f"{stem}.stdout.txt").write_bytes(result.stdout)
    if result.returncode not in allowed_codes:
        raise ProbeError(f"{stem}: command exited {result.returncode}; see retained diagnostics")
    return result.stdout.decode("utf-8-sig", errors="replace")


def dependency_paths(path: Path, msvc: bool) -> list[Path]:
    if msvc:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if data.get("Version") not in ("1.1", "1.2"):
            raise ProbeError("unsupported MSVC sourceDependencies version")
        values = data["Data"]["Includes"]
        if not isinstance(values, list) or not all(isinstance(p, str) for p in values):
            raise ProbeError("malformed MSVC header dependencies")
        return [Path(p) for p in values]
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    _, separator, values = text.partition(":")
    if not separator:
        raise ProbeError("missing target in compiler dependency file")
    return [(Path(p) if Path(p).is_absolute() else path.parent / p)
            for p in shlex.split(values)]


def header_evidence(paths: list[Path], roots: dict[str, Path]) -> list[dict]:
    entries: dict[str, dict] = {}
    for path in paths:
        resolved = path.resolve(strict=True)
        for owner, root in roots.items():
            try:
                relative = resolved.relative_to(root.resolve())
            except ValueError:
                continue
            name = f"{owner}/{relative.as_posix()}"
            entries[name] = describe(resolved, name)
            break
        else:
            raise ProbeError(f"dependency has no declared source root: {path}")
    return [entries[name] for name in sorted(entries)]


def verify_object(path: Path, target: str) -> None:
    head = path.read_bytes()[:12]
    if target == "aarch64-macho":
        valid = head[:8] == bytes.fromhex("cffaedfe0c000001")
    elif target == "x86_64-coff":
        valid = head[:2] == bytes.fromhex("6486")
    else:
        raise ProbeError(f"unsupported probe target {target}")
    if not valid:
        raise ProbeError(f"{path.name}: compiler emitted the wrong architecture or format")


def config_source() -> str:
    lines = ["#include <string>", "#include <vector>",
             "#define ND_TEXT_I(x) #x", "#define ND_TEXT(x) ND_TEXT_I(x)"]
    for macro in MACROS:
        lines += [f"#ifdef {macro}", f'ND_CONFIG "{macro}" ND_TEXT({macro})', "#endif"]
    return "\n".join(lines) + "\n"


def read_macros(text: str) -> dict[str, str]:
    return dict(re.findall(r'^ND_CONFIG\s+"([A-Za-z0-9_]+)"\s+"([^"]*)"\s*$',
                           text, flags=re.MULTILINE))


def normalized_args(argv: list[str], roots: dict[str, Path]) -> list[str]:
    result = []
    # Replace nested roots before parents, and handle Windows separators too.
    ordered = sorted(roots.items(), key=lambda pair: len(str(pair[1])), reverse=True)
    for arg in argv:
        for name, root in ordered:
            arg = arg.replace(str(root), "${" + name + "}")
        result.append(arg.replace("\\", "/"))
    return result


def produce(args: argparse.Namespace) -> dict:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "manifest.json").exists():
        raise ProbeError("output already has a manifest; use a fresh directory")
    compiler = Path(shutil.which(args.compiler) or args.compiler).resolve(strict=True)
    msvc = args.kind == "msvc"
    roots = {"probe": SOURCES, "output": output}
    if msvc:
        if os.environ.get("VSCMD_ARG_TGT_ARCH") != "x64":
            raise ProbeError("an x64 VsDevCmd environment is required")
        vc = Path(os.environ["VCToolsInstallDir"]).resolve(strict=True)
        sdk = Path(os.environ["WindowsSdkDir"]).resolve(strict=True)
        roots.update({"msvc": vc, "winsdk": sdk})
        origin = {"implementation": "msvc-stl-and-atl", "kind": "installed-toolset",
                  "origin": "https://visualstudio.microsoft.com/downloads/",
                  "revision": vc.name, "sdk_version": os.environ["WindowsSDKVersion"].rstrip("\\/"),
                  "license": "Visual Studio and Windows SDK license terms"}
        version = command([str(compiler), "/Bv"], output, "compiler", allowed_codes=(0, 2))
        version += (output / "compiler.stderr.txt").read_text(encoding="utf-8", errors="replace")
        target = "x86_64-coff"
        base = [str(compiler), "/nologo", "/std:c++17", "/EHsc", "/W3",
                "/Brepro", "/Z7", f"/pathmap:{SOURCES}=/src/neverd-probes",
                f"/pathmap:{output}=/build/neverd-probes"]
        families = ("accessors", "atl_string", "atl_com")
    else:
        if args.llvm_source is None or args.libcxx_config is None or args.sysroot is None:
            raise ProbeError("libc++ requires --llvm-source, --libcxx-config and --sysroot")
        source = args.llvm_source.resolve(strict=True)
        config = args.libcxx_config.resolve(strict=True)
        sdk = args.sysroot.resolve(strict=True)
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if revision != args.source_revision:
            raise ProbeError("LLVM source revision does not match --source-revision")
        if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain",
                                    "--", "libcxx"], text=True).strip():
            raise ProbeError("libc++ source has local changes")
        resource = subprocess.check_output([str(compiler), "--no-default-config",
                                            "-print-resource-dir"], text=True).strip()
        roots.update({"libcxx": source / "libcxx", "configuration": config,
                      "sdk": sdk, "compiler-resource": Path(resource)})
        origin = {"implementation": "libc++", "kind": "git",
                  "origin": args.source_origin, "revision": revision,
                  "license": "Apache-2.0 WITH LLVM-exception"}
        version = command([str(compiler), "--no-default-config", "--version"], output, "compiler")
        target = "aarch64-macho"
        base = [str(compiler), "--no-default-config", "--target=arm64-apple-macos14.0",
                "-isysroot", str(sdk), "-std=c++17", "-nostdinc++",
                "-isystem", str(config / "include/c++/v1"),
                "-isystem", str(source / "libcxx/include"), "-g",
                "-fdebug-compilation-dir=/src/neverd-probes"]
        for name, root in roots.items():
            base.append(f"-ffile-prefix-map={root}=/src/{name}")
        families = ("accessors",)
    roots["compiler"] = compiler
    config_file = output / "config.cpp"
    config_file.write_text(config_source(), encoding="utf-8")
    manifest = {"schema_version": 1, "kind": "library-feature-evidence", "status": "incomplete",
                "target": target, "source": origin, "compiler": describe(compiler),
                "compiler_version": version.strip(), "builds": [],
                "generator": describe(Path(__file__)), "recognition_verified": False}
    write_json(output / "manifest.json", manifest)
    for mode in ("standalone", "inline", "negative-configuration"):
        flags = (["/Od", "/Ob0"] if mode == "standalone" else ["/O2", "/Ob2"]) if msvc else (
            ["-O0", "-fno-inline"] if mode == "standalone" else ["-O2"])
        if msvc:
            flags += ["/MTd", "/D_ITERATOR_DEBUG_LEVEL=2"] if mode == "negative-configuration" else [
                "/MT", "/D_ITERATOR_DEBUG_LEVEL=0"]
            macro_args = base + flags + ["/EP", str(config_file)]
        else:
            if mode == "negative-configuration":
                flags += ["-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG"]
            macro_args = base + flags + ["-E", str(config_file)]
        # Preprocessed library headers are not published. Only selected macro
        # values survive; diagnostics remain available on failure.
        macros = read_macros(command(macro_args, output, mode + "-config", keep_stdout=False))
        if not macros or (msvc and macros.get("_M_X64") != "100"):
            raise ProbeError("preprocessor did not confirm the requested configuration")
        if not msvc and macros.get("__SIZEOF_POINTER__") != "8":
            raise ProbeError("preprocessor did not confirm a 64-bit target")
        for family in families:
            if mode == "negative-configuration" and family != "accessors":
                continue
            stem = f"{family}-{mode}"
            probe = SOURCES / f"{family}.cpp"
            # A relative source operand also makes LLVM's source_filename
            # independent of the checkout directory. Record the original hash.
            shutil.copyfile(probe, output / probe.name)
            obj = output / (stem + (".obj" if msvc else ".o"))
            deps = output / (stem + (".deps.json" if msvc else ".d"))
            assembly = output / (stem + (".asm" if msvc else ".s"))
            if msvc:
                argv = base + flags + ["/c", probe.name, f"/Fo{obj}", "/FA", f"/Fa{assembly}",
                                      "/d1reportAllClassLayout", "/sourceDependencies", str(deps)]
            else:
                argv = base + flags + ["-c", probe.name, "-o", str(obj), "-MD", "-MF", str(deps),
                                      "-Xclang", "-fdump-record-layouts"]
            command(argv, output, stem)
            verify_object(obj, target)
            headers = header_evidence(dependency_paths(deps, msvc), roots)
            # Keep the normalized hashes, not absolute dependency paths or
            # a redistributed copy of the toolset's headers.
            deps.unlink()
            if not msvc:
                command(base + flags + ["-S", probe.name, "-o", str(assembly)], output, stem + "-assembly")
                command(base + flags + ["-S", "-emit-llvm", probe.name, "-o", str(output / (stem + ".ll"))],
                        output, stem + "-llvm")
            bin_dir = args.llvm_bin.resolve(strict=True)
            exe = ".exe" if os.name == "nt" else ""
            command([str(bin_dir / ("llvm-nm" + exe)), "--defined-only", "--print-size", obj.name],
                    output, stem + "-symbols")
            command([str(bin_dir / ("llvm-objdump" + exe)), "--disassemble", "--reloc", obj.name],
                    output, stem + "-disassembly")
            build = {"id": stem, "mode": mode, "source": describe(probe, probe.relative_to(ROOT).as_posix()),
                     "arguments": normalized_args(argv, roots), "configuration": macros,
                     "headers": headers, "object": describe(obj), "assembly": describe(assembly)}
            manifest["builds"].append(build)
            write_json(output / "manifest.json", manifest)
    manifest["status"] = "produced"
    manifest["artifacts"] = [describe(p) for p in sorted(output.iterdir())
                              if p.is_file() and p.name != "manifest.json"]
    write_json(output / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("libcxx", "msvc"), required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--llvm-source", type=Path)
    parser.add_argument("--libcxx-config", type=Path)
    parser.add_argument("--sysroot", type=Path)
    parser.add_argument("--source-revision", default="cc7be19969b7dc6c309e67619630ccc90ef46d9f")
    parser.add_argument("--source-origin", default="https://github.com/NeverSight/llvm-project")
    args = parser.parse_args()
    try:
        result = produce(args)
    except (ProbeError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"library feature probes: {error}", file=sys.stderr)
        return 1
    print(f"produced {len(result['builds'])} builds; recognition remains unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
