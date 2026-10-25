# Signature collection outside GitHub Actions

`scripts/collect_signature_updates.py` is the local entry point for an external
scheduler. It calls the existing collectors; it does not dispatch Actions,
install dependencies, execute collected libraries, publish archives, push Git
refs, or create releases. Existing Actions entry points and PR checks remain
unchanged until replacement coverage is demonstrated.

## Scope and environment

Use an isolated, trusted checkout at a recorded commit and a private persistent
state directory outside that checkout. Review collector/matrix changes before
execution. Python 3.12+, existing unpacking tools, and an OS-enforced CPU/memory/
disk quota are required. The wrapper limits each target's wall time and samples
disk use once per second; this is **not** a sandbox or a hard disk quota. It
terminates the process tree on timeout. One to three explicitly selected rows
run serially, never the entire historical matrix by default. Run with a
least-privilege account and only the network access already authorized for the
selected official sources. Network denials are blockers, not invitations to
change proxies or credentials.

Supported adapters reuse these reviewed repository matrices:

- `homebrew:<name>`: existing SHA-256-pinned Homebrew bottle rows. The collector
  reads Mach-O archives without executing them. Linux can collect these bytes;
  native macOS is still needed for applicable consumer/probe validation.
- `elf:<name>`: existing Ubuntu/Android package rows and their pinned sigdb
  source lists. Requires `dpkg-deb`, `unzip`, and `zstd`. Missing packages or
  missing expected architectures fail the run, even if the underlying collector
  emitted a partial archive. Historical source-list SHA-1 checks are inherited,
  not upgraded to an invented vendor SHA-256 attestation; emitted assets receive
  SHA-256 inventories. These are historical pins, not discovery of latest NDKs.
- `msvc:<name>`: collect an **already installed** Visual Studio toolset/Windows
  SDK on Windows, with `zstd` available. No component installers, SDK installers,
  Chocolatey, or downloaded executables are invoked. Missing toolsets fail.

MinGW/Fedora source builds, MASM32/Wine, legacy installation media, and unsupported
architectures/formats are not automatically run by this adapter. They require
separately reviewed execution environments/adapters. A matrix or directory name
is not proof of populated or verified architecture coverage. Existing license
and attribution notices continue to apply. In particular, never upload the
private state directory or unmodified Microsoft SDK/library archives to a public
PR, artifact store, or release.

## External scheduler contract

A scheduler should first record the signatures checkout commit, inspect the
selected official source metadata, and compare versions/content hashes with the
reviewed matrix pins. A new upstream version is a **matrix-pin review candidate**,
not authority to rewrite pins or run upstream build/install scripts. No change
to pinned inputs means a successfully collected download row can be reused;
its cached manifests and archives are rehashed before reuse. Installed MSVC
inputs are always recollected because installed servicing versions can change
without a matrix edit.

Plan without network or collector execution:

```sh
python3 scripts/collect_signature_updates.py --state /private/signature-state \
  collect --target homebrew:homebrew-zlib --target elf:ubuntu-zlib
```

Actually collect the selected, reviewed pins:

```sh
python3 scripts/collect_signature_updates.py --state /private/signature-state \
  --timeout 900 --max-gib 8 collect --target homebrew:homebrew-zlib --execute
```

JSON output distinguishes `planned`, `unavailable`, `unchanged`,
`collected_candidate`, and `failed`. Exit code 2 means blocked/failed/unavailable;
0 never means recognition quality passed. Receipts contain the complete row,
collector hashes, input fingerprint, per-file hashes, and the private asset path.
Failed runs remain isolated for diagnosis, are not cached as success, and retry
into a fresh run directory. A lock prevents concurrent writers; inspect a stale
lock rather than automatically removing it. Retention/cleanup of private state
is the scheduler/operator's responsibility. Do not put private paths or raw
archives into public progress reports.

An external weekly task may run this command on the first suitable already
available environment. It must report unavailable profiles and resume when their
required tools become available, not claim all architectures passed. This PR does
not itself configure or activate a scheduler.

## Candidate generation and preservation

Use a complete private asset inventory for every affected format/architecture
**directory**, not just a newly downloaded library: collision resolution needs
all of that directory's libraries. The wrapper compares its inventory with the
existing `*.sources.json` files and refuses missing historical assets or changed
same-name archive hashes. Renaming/removing historical inputs requires a separate
migration review, not a force option. Preserve concurrent/manual changes, imported
patterns, attribution, and original provenance during that review.

Supply an already trusted `neverd-sigmaker` and the reviewed NeverD
`scripts/signatures/build_msvc_signatures.py`, with recorded SHA-256 values and
full source commit. Do not download/run an arbitrary binary merely because a
hash was supplied. The current workflow's builder pin is
`6228f29bb61f0b684687b1935d4f89a6dc254e40`; any different revision must be reviewed
against the current integration before use.

```sh
python3 scripts/collect_signature_updates.py --state /private/signature-state \
  --timeout 3600 --max-gib 16 generate --assets /private/complete-assets \
  --builder /trusted/build_msvc_signatures.py --builder-sha256 <reviewed-sha256> \
  --sigmaker /trusted/neverd-sigmaker --sigmaker-sha256 <reviewed-sha256> \
  --neverd-ref <reviewed-full-commit>
```

Before generation, archive identities, sizes, hashes, member paths/types,
member hashes, and member inventories are checked without extracting them.
Generation runs twice into fresh copies, never into the source checkout. The
reviewed builder invokes `neverd-sigmaker --verify` and resolves collisions among
its asset-derived outputs; byte-identical repeat outputs are required.

Even `generated_candidate` is **not publishable automatically**. The receipt
explicitly leaves consumer recognition regressions, license/provenance review,
and manual/imported-pattern preservation/cross-file collision review pending.
Parser acceptance and reproducibility do not establish recognition correctness.
The scheduler must run the applicable trusted CLI/shared-consumer regressions,
record exact tool and input heads and actual results, then prepare a minimal data
update draft PR. Missing native platform validation must be stated. Never claim
GUI checks from CLI-only results. Re-read the target head before a write and
read back the entire remote diff afterward. Do not merge or update NeverD's
signature submodule automatically as a side effect.

Only after the scheduled path has demonstrated equivalent collection, provenance,
validation and recovery for a legacy Actions row should its old collection entry
point be retired. Keep unrelated CI and unit tests.

## Offline tests

```sh
python3 -m unittest discover -s scripts/tests -p test_collect_signature_updates.py -v
python3 -m py_compile scripts/collect_signature_updates.py
```

These fixtures exercise orchestration/manifest/archive guards only. They do not
download packages, run collectors, build SDKs, run sigmaker, or validate NeverD
recognition accuracy.
