#!/usr/bin/env python3
"""Build five genuine musl routines and validate byte matches on stripped ELF."""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

from build_elf_probes import write_truth
from build_library_feature_probes import command, dependency_paths, describe, header_evidence, normalized_args, verify_object, write_json
from build_libcxx_features import archive_evidence
from evaluate_probes import evaluate
from validate_library_features import FeatureError, require, validate_pack

SOURCE_URL = "https://musl.libc.org/releases/musl-1.2.5.tar.gz"
SOURCE_SHA256 = "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"
ROUTINES = {"memcpy": "src/string/x86_64/memcpy.s", "memmove": "src/string/x86_64/memmove.s",
            "memset": "src/string/x86_64/memset.s", "memcmp": "src/string/memcmp.c", "strlen": "src/string/strlen.c"}


def produce(archive: Path, output: Path, compiler: Path, llvm_bin: Path, linker: Path, sigmaker: Path, neverd: Path, neverd_source: Path) -> dict:
    require(not output.exists(), "use a fresh musl evidence directory")
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == SOURCE_SHA256, "wrong musl source archive")
    output.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as source_tar:
        members = source_tar.getmembers()
        require(len(members) < 5000 and all(m.name.startswith("musl-1.2.5/") or
                                          (m.name == "musl-1.2.5" and m.isdir()) for m in members),
                "unexpected musl archive layout")
        source_tar.extractall(output, filter="data")
    source = output / "musl-1.2.5"
    roots = {"musl": source, "output": output, "compiler": compiler, "llvm-bin": llvm_bin}
    version = command([str(compiler), "--no-default-config", "--version"], output, "compiler")
    require("clang version 22.1.6" in version, "unsupported compiler; author a distinct profile")
    flags = ["-O2", "-g", f"-ffile-prefix-map={source}=/src/musl", "-fdebug-compilation-dir=/src/musl"]
    configure = ["sh", "./configure", "--target=x86_64-linux-musl", "--disable-shared",
                 "CC=" + shlex.join([str(compiler), "--no-default-config", "--target=x86_64-linux-musl"]),
                 "AR=" + str(llvm_bin / "llvm-ar"), "RANLIB=" + str(llvm_bin / "llvm-ranlib"),
                 "CFLAGS=" + shlex.join(flags)]
    command(configure, output, "configure", cwd=source)
    object_names = ["obj/" + str(Path(path).with_suffix(".o")) for path in ROUTINES.values()]
    build_log = command(["make", "-j1", *object_names], output, "make", cwd=source)
    compile_lines = [line for line in build_log.splitlines() if str(compiler) + " " in line]
    invocations = [shlex.split(line.split(" | ")[-1]) for line in compile_lines]
    require(len(invocations) == 5, "could not retain all compiler invocations")
    dependencies = [source / path for path in [*ROUTINES.values(), "Makefile", "configure", "COPYRIGHT",
                    "tools/add-cfi.common.awk", "tools/add-cfi.x86_64.awk"]]
    shutil.copyfile(source / "config.mak", output / "musl-config.mak")
    for index, argv in enumerate(invocations):
        if not argv[-1].endswith(".c"):
            continue
        # Ask that exact compile command for its dependencies without replacing
        # the already-built object. Paths in the depfile are relative to musl.
        depfile = source / f"feature-{index}.d"
        cleaned = []
        i = 0
        while i < len(argv):
            if argv[i] == "-o":
                i += 2
            elif argv[i] == "-c":
                i += 1
            else:
                cleaned.append(argv[i]); i += 1
        command(cleaned + ["-M", "-MF", str(depfile)], output, f"dependencies-{index}", cwd=source)
        dependencies += dependency_paths(depfile, False)
        depfile.unlink()
    headers = header_evidence(dependencies, roots)
    objects = []
    for name, relative in zip(ROUTINES, object_names):
        path = output / (name + ".o")
        shutil.copyfile(source / relative, path)
        verify_object(path, "x86_64-elf")
        objects.append(path)
        command([str(llvm_bin / "llvm-objdump"), "--disassemble", "--reloc", path.name], output, name + "-disassembly")
    probe = Path(__file__).resolve().parents[1] / "validation/library-features/libc.c"
    shutil.copyfile(probe, output / "libc.c")
    include = ["-nostdinc", "-I" + str(source / "arch/x86_64"), "-I" + str(source / "arch/generic"),
               "-I" + str(source / "obj/include"), "-I" + str(source / "include")]
    compile_probe = [str(compiler), "--no-default-config", "--target=x86_64-linux-musl", "-std=c99", "-O2", "-g",
                     "-fno-builtin", "-fno-stack-protector", "-fno-optimize-sibling-calls", "-fdebug-compilation-dir=/src/probe",
                     f"-ffile-prefix-map={output}=/src/probe", *include, "-c", "libc.c", "-o", "libc-probe.o"]
    command(compile_probe, output, "libc-probe")
    program, stripped = output / "library-memory.debug", output / "library-memory.elf"
    link = [str(linker), "-static", "--build-id=sha1", "-e", "nd_libc_probe", "-o", program.name,
            "libc-probe.o", *[p.name for p in objects]]
    command(link, output, "link")
    command([str(llvm_bin / "llvm-strip"), "--strip-all", "-o", stripped.name, program.name], output, "strip")
    command([str(llvm_bin / "llvm-nm"), "--defined-only", "--print-size", program.name], output, "library-memory-symbols")
    library_names = set(ROUTINES) | {"__memcpy_fwd"}
    write_truth(program, stripped, library_names, readelf=str(llvm_bin / "llvm-readelf"))
    pat = output / "musl-1.2.5-memory.pat"
    command([str(sigmaker), "--machine=x64", "--tail=65536", "--name=musl-1.2.5-memory", "-o", pat.name,
             *[p.name for p in objects]], output, "sigmaker")
    command([str(sigmaker), "--verify", pat.name], output, "verify-patterns")
    result = evaluate(neverd, "--sig-file=" + str(pat), stripped)
    named_result = evaluate(neverd, "--sig-file=" + str(pat), program)
    require(not named_result.failure and not named_result.wrong and named_result.correct == 5,
            f"musl signatures fail even with symbol-provided boundaries: {named_result}")
    require(not result.failure and not result.wrong and result.correct >= 4,
            f"musl stripped byte matcher verification failed: {result}")
    write_json(output / "byte-matcher-report.json", {
        "library_functions": result.library_functions, "correct": result.correct,
        "wrong": result.wrong, "disputed": result.disputed, "unmapped": result.unmapped, "failure": result.failure,
        "with_symbol_boundaries": {"correct": named_result.correct, "library_functions": named_result.library_functions},
        "limitation": "The stripped fixture exposes a function discovery miss at memcpy, directly adjacent to an FDE end; retain it as a NeverD regression fixture.",
        "neverd": describe(neverd)})
    compiler_record = describe(compiler)
    source_record = {"origin": SOURCE_URL, "revision": "1.2.5", "license": "MIT (see musl COPYRIGHT)",
                     "archive": describe(archive, "musl-1.2.5.tar.gz"), "implementation": "musl"}
    build = {"id": "library-memory", "mode": "standalone-and-callers", "source": describe(probe),
             "configuration": {"target": "x86_64-linux-musl", "builtin_calls": "disabled"}, "headers": headers,
             "arguments": {"configure": normalized_args(configure, roots),
                           "library": [normalized_args(argv, roots) for argv in invocations],
                           "make_commands": normalized_args(compile_lines, roots),
                           "probe": normalized_args(compile_probe, roots), "link": normalized_args(link, roots)}}
    manifest = {"schema_version": 1, "kind": "library-feature-evidence", "status": "produced", "target": "x86_64-elf",
                "source": source_record, "compiler": compiler_record, "compiler_version": version.strip(),
                "generator": describe(Path(__file__)), "builds": [build], "recognition_verified": False,
                "byte_generator": {"tool": describe(sigmaker), "neverd_revision": subprocess.check_output(
                    ["git", "-C", str(neverd_source), "rev-parse", "HEAD"], text=True).strip()},
                "artifacts": [describe(p) for p in sorted(output.iterdir()) if p.is_file()]}
    write_json(output / "manifest.json", manifest)
    return manifest


def publish(root: Path, output: Path, manifest: dict) -> Path:
    identity = "musl-1.2.5-x64-clang22-memory"
    for name in ("profiles", "rules", "evidence", "patterns", "notices"):
        (root / "features" / name).mkdir(parents=True, exist_ok=True)
    def ref(path):
        return describe(path, path.relative_to(root).as_posix())
    manifest_path = root / "features/evidence" / (identity + ".json")
    shutil.copyfile(output / "manifest.json", manifest_path)
    archive_path = manifest_path.with_suffix(".tar.gz")
    archive_evidence(output, manifest, archive_path)
    shutil.copyfile(output / "musl-1.2.5/COPYRIGHT", root / "features/notices/musl-COPYRIGHT.txt")
    build = manifest["builds"][0]
    profile = {"schema_version": 1, "kind": "library-feature-profile", "id": identity, "implementation": "musl",
               "target": {"architecture": "x86_64", "format": "elf", "abi": "sysv-amd64", "pointer_bits": 64, "endianness": "little"},
               "configuration": {"build": "library-memory", "language": "c99", "optimization": "O2 with recorded musl per-file overrides",
                                 "lto": False, "macros": build["configuration"], "arguments": build["arguments"], "sdk": None},
               "source": {**{k: manifest["source"][k] for k in ("origin", "revision", "license")}, "files": build["headers"]},
               "compiler": {**manifest["compiler"], "version": manifest["compiler_version"]},
               "layouts": {"c-function": {"receiver_type": None}},
               "evidence": ref(manifest_path), "artifact_archive": ref(archive_path)}
    profile_path = root / "features/profiles" / (identity + ".json")
    write_json(profile_path, profile)
    rules = []
    rows = [line for line in (output / "musl-1.2.5-memory.pat").read_text().splitlines() if line and not line.startswith((";", "---"))]
    require(len(rows) == 5, "unexpected musl signature count")
    for row in rows:
        name = row.split()[5]
        require(name in ROUTINES, "unexpected generated routine")
        path = root / "features/patterns" / ("musl." + name + ".pat.txt")
        path.write_text(row + "\n---\n")
        rules.append({"id": "musl." + name, "revision": 1, "family": "libc", "operation": name,
                      "receiver_type": None, "layout": "c-function", "identity_evidence": "byte-signature", "scope": ["whole-function"],
                      "pattern": {"kind": "byte-pattern", "file": ref(path), "symbol": name, "generator": "neverd-sigmaker", "fixed_bytes_min": 16},
                      "positive": [{"build": "library-memory", "symbol": name, "expectation": "whole-function"}],
                      "negative": [{"build": "library-memory", "symbol": "nd_builtin_copy16", "expectation": "extra-effects"},
                                   {"build": "library-memory", "symbol": "nd_user_copy", "expectation": "unproven-receiver"}]})
    pack_path = root / "features/rules" / (identity + ".json")
    write_json(pack_path, {"schema_version": 1, "kind": "library-feature-pack", "id": identity, "profile": ref(profile_path),
                           "rules": rules, "verification": {"data_verified": True, "consumer_verified": False}})
    validate_pack(root, pack_path)
    directory = root / "elf/x86/64"
    directory.mkdir(parents=True, exist_ok=True)
    pat_path = directory / "musl-1.2.5-memory.pat"
    shutil.copyfile(output / "musl-1.2.5-memory.pat", pat_path)
    write_json(pat_path.with_suffix(".sources.json"), {
        "file": pat_path.relative_to(root).as_posix(), "lines": len(rows),
        "generator": {"neverd_ref": manifest["byte_generator"]["neverd_revision"],
                      "release": "musl-1.2.5-source", "tail": 65536,
                      "tool": manifest["byte_generator"]["tool"]},
        "sources": [{"arch": "x64", "kind": "library", "asset": identity,
                     "archive_sha256": manifest["source"]["archive"]["sha256"],
                     "origin": SOURCE_URL, "revision": "1.2.5"}],
        "family": "libc", "feature_pack": ref(pack_path), "evidence": ref(manifest_path), "pattern": ref(pat_path)})
    return pack_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "output", "compiler", "llvm-bin", "linker", "sigmaker", "neverd", "neverd-source"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        paths = [getattr(args, name.replace("-", "_")).absolute() for name in (
            "archive", "output", "compiler", "llvm-bin", "linker", "sigmaker", "neverd", "neverd-source")]
        manifest = produce(*paths)
        print(publish(args.root.resolve(), args.output.resolve(), manifest))
    except (FeatureError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"musl features: {error}\n")
