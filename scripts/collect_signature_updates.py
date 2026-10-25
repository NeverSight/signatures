#!/usr/bin/env python3
"""Bounded, resumable collection for an external scheduler (never publishes)."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {"elf": "collect_elf_packages.py", "homebrew": "collect_homebrew_bottles.py",
            "msvc": "collect_msvc_libraries.py"}
ARCHES = {"x86": "x86/32", "x64": "x86/64", "arm": "arm/32", "arm64": "arm/64"}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_revision(root):
    if not (root / ".git").exists():
        return None
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True, timeout=10)
    return result.stdout.strip()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]*", value):
        raise ValueError(f"unsafe name: {value!r}")
    return value


def safe_member(value):
    p = PurePosixPath(value)
    if not value or value != p.as_posix() or p.is_absolute() or ".." in p.parts or "\\" in value or ":" in value:
        raise ValueError(f"unsafe member: {value!r}")
    return value


def targets(root):
    result = {}
    for family in FAMILIES:
        path = root / ".github" / f"{family}-matrix.json"
        for row in json.loads(path.read_text(encoding="utf-8")):
            key = f"{family}:{safe_name(row['name'])}"
            if key in result:
                raise ValueError(f"duplicate target {key}")
            result[key] = (family, row)
    return result


def capabilities(family):
    missing = [name for name in ("zstd",) if not shutil.which(name)]
    if family == "elf":
        missing += [name for name in ("dpkg-deb", "unzip") if not shutil.which(name)]
    if family == "msvc" and os.name != "nt":
        missing.append("Windows with the selected Visual Studio / SDK already installed")
    return missing


def commands(root, family, row, work, assets):
    script = str(root / "scripts" / FAMILIES[family])
    if family != "msvc":
        argv = [sys.executable, script, "--name", row["name"], "--work", str(work),
                "--output", str(assets), "--zstd-level", "3"]
        if family == "elf":
            argv += ["--jobs", "1"]
        return [argv]
    result = []
    # No eval, shell, installers, Chocolatey, or components installation.
    for invocation in row["collect"].split(";"):
        args = shlex.split(invocation)
        if not args or args[0] not in ("toolset", "toolset-v140", "winsdk"):
            raise ValueError("unsupported MSVC collector invocation")
        if any(a == "--output" or a.startswith("--output=") for a in args):
            raise ValueError("matrix must not override output")
        result.append([sys.executable, script, *args, "--output", str(assets), "--zstd-level", "3"])
    return result


def inventory(directory):
    return {p.relative_to(directory).as_posix(): digest(p)
            for p in sorted(directory.rglob("*")) if p.is_file()}


def validate_assets(directory):
    result = {}
    for path in sorted(directory.glob("*.json")):
        if path.name == "assets.json":
            continue
        m = json.loads(path.read_text(encoding="utf-8"))
        name = safe_name(m["asset"])
        if path.is_symlink() or name != path.stem or name in result:
            raise ValueError(f"manifest identity conflict: {path.name}")
        if m.get("arch") not in ARCHES or m.get("format", "pe") not in ("pe", "elf", "macho"):
            raise ValueError(f"unsupported format/architecture: {name}")
        if m.get("unavailable"):
            raise ValueError(f"incomplete source collection: {name}")
        a = m["archive"]
        if a["name"] != name + ".tar.zst" or not HEX.fullmatch(a["sha256"]):
            raise ValueError(f"invalid archive identity: {name}")
        archive = directory / a["name"]
        if archive.is_symlink() or archive.stat().st_size != a["size"] or digest(archive) != a["sha256"]:
            raise ValueError(f"archive bytes do not match: {name}")
        files = m["files"]
        if not files:
            raise ValueError(f"empty collection: {name}")
        seen = set()
        for item in files:
            member = safe_member(item["path"])
            if member.casefold() in seen or not HEX.fullmatch(item["sha256"]) or item["size"] < 0:
                raise ValueError(f"invalid/duplicate member: {name}: {member}")
            seen.add(member.casefold())
        result[name] = m
    if not result:
        raise ValueError("no collected assets")
    return result


class LimitedReader:
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit

    def read(self, size=-1):
        if size < 0:
            size = self.remaining + 1
        data = self.stream.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("decompressed byte budget exceeded")
        return data


class LimitedTarInfo(tarfile.TarInfo):
    def _proc_pax(self, tarfile):
        if self.size > 65536:
            raise ValueError("oversized tar metadata")
        return super()._proc_pax(tarfile)

    def _proc_gnulong(self, tarfile):
        if self.size > 65536:
            raise ValueError("oversized tar long-name metadata")
        return super()._proc_gnulong(tarfile)


def validate_tar(stream, manifest, max_bytes):
    expected = {item["path"]: item for item in manifest["files"]}
    seen = set()
    total = 0
    with tarfile.open(fileobj=LimitedReader(stream, max_bytes), mode="r|", tarinfo=LimitedTarInfo) as bundle:
        for member in bundle:
            name = safe_member(member.name)
            if not member.isfile() or name not in expected or name in seen:
                raise ValueError(f"unexpected/non-regular/duplicate tar member: {name}")
            total += member.size
            if total > max_bytes or member.size != expected[name]["size"]:
                raise ValueError("expanded archive size exceeds manifest/budget")
            h = hashlib.sha256()
            source = bundle.extractfile(member)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                h.update(chunk)
            if h.hexdigest() != expected[name]["sha256"]:
                raise ValueError(f"archive member digest mismatch: {name}")
            seen.add(name)
    if seen != set(expected):
        raise ValueError("archive is missing recorded members")


def check_archives(assets, max_bytes, seconds):
    manifests = validate_assets(assets)
    deadline = time.monotonic() + seconds
    for m in manifests.values():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("archive validation time budget exceeded")
        with subprocess.Popen(["zstd", "-q", "-d", "-c", str(assets / m["archive"]["name"])],
                              stdout=subprocess.PIPE) as proc:
            timer = threading.Timer(remaining, proc.kill)
            timer.start()
            try:
                validate_tar(proc.stdout, m, max_bytes)
                trailing = 0
                for chunk in iter(lambda: proc.stdout.read(1024 * 1024), b""):
                    trailing += len(chunk)
                    if trailing > max_bytes:
                        raise ValueError("excessive trailing archive data")
                if proc.wait() != 0:
                    raise ValueError("zstd integrity check failed")
            finally:
                timer.cancel()
                proc.stdout.close()
                if proc.poll() is None:
                    proc.terminate()
                proc.wait()


def expected_arches(family, row):
    if family == "elf":
        return {a for a, directory in ARCHES.items() if "elf/" + directory in row["directories"]}
    if family == "homebrew":
        return {"arm64" if b["tag"].startswith("arm64_") else "x64" for b in row["bottles"]}
    return set(re.findall(r"--arch\s+(\w+)", row["collect"]))


def run_bounded(argv, work, log, seconds, max_bytes):
    """Bound wall time and sampled disk use; caller must supply OS isolation/quota."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    with log.open("ab") as output:
        proc = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=env,
                                start_new_session=os.name != "nt")
        start = time.monotonic()
        try:
            while proc.poll() is None:
                if time.monotonic() - start > seconds:
                    raise RuntimeError("wall-time budget exceeded")
                size = sum(p.stat().st_size for p in work.rglob("*") if p.is_file())
                if size > max_bytes:
                    raise RuntimeError("sampled disk budget exceeded")
                time.sleep(1)
            if proc.returncode:
                raise RuntimeError(f"command failed ({proc.returncode}); see {log.name}")
        finally:
            if proc.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                   stdout=output, stderr=output, check=False)
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def collect(root, state, selected, execute, seconds, max_bytes):
    all_targets = targets(root)
    if not selected or len(selected) > 3 or len(set(selected)) != len(selected):
        raise ValueError("select one to three distinct targets; no implicit all-target run")
    scripts = {p.name: digest(p) for p in sorted((root / "scripts").glob("*.py"))}
    results = []
    for key in selected:
        if key not in all_targets:
            raise ValueError(f"unknown/unsupported target {key}")
        family, row = all_targets[key]
        fingerprint = hashlib.sha256(json.dumps([family, row, scripts], sort_keys=True).encode()).hexdigest()
        missing = capabilities(family)
        result = {"target": key, "input_sha256": fingerprint, "row": row,
                  "collector_sha256": scripts, "missing": missing,
                  "status": "unavailable" if missing else "planned", "publishable": False,
                  "repository_ref": source_revision(root),
                  "sampled_at": datetime.now(timezone.utc).isoformat()}
        results.append(result)
        if not execute or missing:
            continue
        location = state / key.replace(":", "-") / fingerprint
        location.mkdir(parents=True, exist_ok=True)
        # A successful pinned download can be reused only after rehashing all outputs.
        # Installed MSVC input is mutable even when the matrix row has not changed.
        receipt = location / "latest.json"
        if family != "msvc" and receipt.exists():
            try:
                prior = json.loads(receipt.read_text(encoding="utf-8"))
                cached = location / safe_name(prior["run"]) / "assets"
                validate_assets(cached)
                if inventory(cached) == prior["inventory"]:
                    result.update(status="unchanged", receipt=str(receipt), assets=str(cached))
                    continue
            except (OSError, ValueError, KeyError):
                pass
        run = location / uuid.uuid4().hex
        run.mkdir()
        assets = run / "assets"
        assets.mkdir()
        result.update(run=run.name, assets=str(assets))
        try:
            started = time.monotonic()
            for argv in commands(root, family, row, run / "work", assets):
                remaining = seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise RuntimeError("target time budget exhausted")
                run_bounded(argv, run, run / "collector.log", remaining, max_bytes)
            manifests = validate_assets(assets)
            fmt = {"msvc": "pe", "elf": "elf", "homebrew": "macho"}[family]
            if any(m.get("format", "pe") != fmt or (family != "msvc" and m.get("library") != row["library"])
                   for m in manifests.values()):
                raise ValueError("collected format/library does not match selected row")
            if {m["arch"] for m in manifests.values()} != expected_arches(family, row):
                raise ValueError("collected architecture set is incomplete or unexpected")
            result.update(status="collected_candidate", inventory=inventory(assets))
            write_json(receipt, result)
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            result.update(status="failed", error=str(error))
        write_json(run / "receipt.json", result)
    return results


def baseline_requirements(root, directories):
    required = {}
    for directory in directories:
        for path in (root / directory).glob("*.sources.json"):
            for source in json.loads(path.read_text(encoding="utf-8")).get("sources", []):
                if "asset" in source:
                    required.setdefault(source["asset"], set()).add(source["archive_sha256"])
    return required


def generate(root, state, assets, builder, sigmaker, builder_hash, sigmaker_hash, ref, seconds, max_bytes):
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValueError("a full reviewed NeverD commit is required")
    for path, expected in ((builder, builder_hash), (sigmaker, sigmaker_hash)):
        if not HEX.fullmatch(expected) or digest(path) != expected:
            raise ValueError(f"trusted tool hash mismatch: {path.name}")
    manifests = validate_assets(assets)
    directories = {m.get("format", "pe") + "/" + ARCHES[m["arch"]] for m in manifests.values()}
    required = baseline_requirements(root, directories)
    missing = set(required) - set(manifests)
    if missing:
        raise ValueError("incomplete directory asset baseline: " + ", ".join(sorted(missing)))
    # Do not silently replace an old same-name archive: keep historical assets until
    # an explicit migration can preserve their coverage and provenance.
    changed = [name for name, hashes in required.items() if hashes != {manifests[name]["archive"]["sha256"]}]
    if changed:
        raise ValueError("same-name source replacement needs migration review: " + ", ".join(sorted(changed)))
    run = state / ("generation-" + uuid.uuid4().hex)
    run.mkdir()
    report = {"status": "failed", "publishable": False, "neverd_ref": ref,
              "builder_sha256": builder_hash, "sigmaker_sha256": sigmaker_hash,
              "assets": inventory(assets), "platform": platform.platform()}
    try:
        run_bounded([sys.executable, str(Path(__file__).resolve()), "--state", str(run / "check"),
                     "--max-gib", str(max_bytes >> 30), "--timeout", str(seconds), "check-archives", "--assets", str(assets)],
                    run, run / "archive-check.log", seconds, max_bytes)
        for index in (1, 2):
            out = run / f"pass-{index}"
            out.mkdir()
            for fmt in ("pe", "elf", "macho"):
                if (root / fmt).exists():
                    shutil.copytree(root / fmt, out / fmt)
            run_bounded([sys.executable, str(builder), "--sigmaker", str(sigmaker), "--assets", str(assets),
                         "--output", str(out), "--neverd-ref", ref, "--work", str(run)],
                        run, run / f"pass-{index}.log", seconds, max_bytes)
        first, second = inventory(run / "pass-1"), inventory(run / "pass-2")
        if first != second:
            raise ValueError("repeat generation differs")
        report.update(status="generated_candidate", output=str(run / "pass-1"), output_sha256=first,
                      pending=["consumer recognition regressions", "license and provenance review",
                               "manual/imported signature preservation and cross-file collision review"],
                      repeated_output_equal=True)
    except (OSError, RuntimeError, ValueError) as error:
        report["error"] = str(error)
    write_json(run / "receipt.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path, help="private persistent workspace outside checkout")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--max-gib", type=int, default=8)
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--target", action="append", required=True, help="family:matrix-row, at most three")
    c.add_argument("--execute", action="store_true", help="otherwise only report plan/capabilities")
    check = sub.add_parser("check-archives", help="validate every tar member without extracting")
    check.add_argument("--assets", type=Path, required=True)
    g = sub.add_parser("generate")
    for name in ("assets", "builder", "sigmaker"):
        g.add_argument("--" + name, type=Path, required=True)
    for name in ("builder-sha256", "sigmaker-sha256", "neverd-ref"):
        g.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 7200 or not 1 <= args.max_gib <= 32:
        parser.error("timeout must be 1..7200 seconds and max-gib 1..32")
    state = args.state.resolve()
    if state == ROOT or ROOT in state.parents:
        parser.error("state must be outside the repository (private artifacts must not be committed)")
    state.mkdir(parents=True, exist_ok=True)
    # A lock directory is portable; stale locks require inspection, never auto stealing.
    lock = state / ".collection-lock"
    try:
        lock.mkdir()
    except FileExistsError:
        parser.error("another run or stale lock exists; inspect before removing .collection-lock")
    try:
        if args.command == "collect":
            result = collect(ROOT, state, args.target, args.execute, args.timeout, args.max_gib << 30)
            failed = any(r["status"] in ("failed", "unavailable") for r in result)
        elif args.command == "check-archives":
            check_archives(args.assets.resolve(), args.max_gib << 30, args.timeout)
            result, failed = {"status": "archive_members_checked", "publishable": False}, False
        else:
            result = generate(ROOT, state, args.assets.resolve(), args.builder.resolve(), args.sigmaker.resolve(),
                              args.builder_sha256, args.sigmaker_sha256, args.neverd_ref,
                              args.timeout, args.max_gib << 30)
            failed = result["status"] == "failed"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2 if failed else 0
    except (ValueError, OSError, KeyError, RuntimeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "publishable": False, "error": str(error)}))
        return 2
    finally:
        lock.rmdir()


if __name__ == "__main__":
    sys.exit(main())
