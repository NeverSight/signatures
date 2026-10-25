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

A scheduler should first record the signatures checkout commit and run
`discover_signature_sources.py` against the selected official feeds (see below).
It compares persistent semantic source records, not just commit timestamps.
New versions produce immutable versioned candidates rather than overwriting
historical matrix rows or running upstream build/install scripts. No change
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

## Discover new versions, then collect their inputs

The update path starts with `scripts/discover_signature_sources.py`, not with a
weekly rebuild of old pins. It fetches official HTTPS metadata, checks redirects
against a narrow host allowlist, bounds response sizes, and preserves the last
successful source baseline if a request fails. Each candidate records platform,
domain, architecture knowledge, format, build-configuration requirements,
version/channel and provenance. Unknown architecture/configuration stays unknown.

```sh
python3 scripts/discover_signature_sources.py --state /private/source-discovery \
  --source msvc-stable --source windows-sdk --source windows-wdk-x64 \
  --source windows-wdk-arm64 --source homebrew-zlib
```

Select at most five sources per invocation and rotate groups. The registered
source IDs and actual coverage are:

| Sources | Metadata discovery | Acquisition / signature status |
| --- | --- | --- |
| `msvc-stable`, `msvc-2022-release` | Actual VC CRT package versions from hash-checked official VS catalogs | Matching installed toolset collector exists; installation is not automated |
| `msvc-insiders`, `msvc-2022-preview` | Explicit preview channels, separate from stable | Opt-in only; never mixed into a stable profile |
| `windows-sdk`, `windows-wdk-x64`, `windows-wdk-arm64` | NuGet stable version inventory, registration/catalog package SHA-512 | New NuGet package acquisition/extraction profiles still need an adapter; package host architecture is not assumed to be every target ABI |
| `homebrew-zlib`, `homebrew-xz`, `homebrew-pcre2` | Stable formula/revision and macOS bottle SHA-256 pins | Executable candidate handoff to the existing bottle collector; Linux bottles excluded |
| `linux-kernel` | Upstream stable/mainline/longterm/RC releases | Exact kernel configuration, compiler, architecture and acquisition/build adapter required |
| `gnu-glibc`, `musl-libc` | Official source-release filenames | Source archive digest, ABI, compiler/distro patches and build adapter required |
| `android-common-gki` | Android common/GKI source tags and peeled commit IDs | Not OEM device kernels or vendor modules; exact configuration/toolchain adapter required |
| `android-bionic` | Android bionic source tags and commits | Not glibc; exact Android ABI/build profile required |
| `android-ndk` | Official stable/preview package inventory and advertised checksum algorithm | New archive adapter/license review and target-triple inspection required; host OS is not target ABI |
| `apple-xnu` | Apple's XNU source tags | Not shipping iOS/macOS kernelcache; source tag is insufficient to claim firmware coverage |
| `apple-libc`, `apple-libsystem` | Apple source tags | Not an extracted shipping dyld cache or every iOS/macOS libSystem ABI |
| `llvm-runtimes` | LLVM release source tags | compiler-rt/libc++/libunwind exact target/build profiles required |

Listing a source here means its metadata parser exists, not that its binaries
were collected or that NeverD recognition was verified. There is no universal
"all architectures" success flag. Current GitHub tag feeds explicitly report
bounded first-page coverage; source histories outside that window remain
uncovered. Gitiles and release-listing responses are bounded and fail if too
large. Kernel/NDK entries retain preview labels; an external scheduler should
select stable entries by default. Preview VS sources require explicit selection.

The first successful fetch is `initial_observation`, not a claim that every old
version was just released. Subsequent entries distinguish `new_version`,
`changed_source_metadata_or_pins`, classification changes and repaired candidate
files. Metadata-only differences do not claim binary bytes changed. NuGet keeps
all advertised stable versions in its inventory, resolving at most two missing
catalog pins per source/run, with the rest explicitly `pending_catalog_hash`;
subsequent runs resume this backlog rather than dropping intermediate versions.
The discovery command does not download SDKs, package archives or installers.

For a genuinely changed eligible Homebrew input, the immutable candidate carries
a new library identity containing version plus bottle-content fingerprint. It
can be passed directly to the collection CLI after source/license review:

```sh
python3 scripts/collect_signature_updates.py --state /private/signature-state \
  --timeout 900 --max-gib 8 collect \
  --candidate /private/source-discovery/homebrew-zlib/<hash>.candidate.json --execute
```

The handoff accepts only registered formula/archive profiles, known macOS tag
shapes and SHA-256 pins. It creates a private temporary matrix and invokes the
existing collector, rather than editing old rows. Candidates matching existing
pins are rejected as redundant. New versions and same-version rebuilt bottles
have distinct identities, preserving earlier coverage. Other newly discovered
families currently remain metadata candidates with their precise adapter or
environment requirements; do not report them as collected.

Generation still needs the complete historical same-directory asset baseline,
trusted sigmaker, two identical passes and the consumer/preservation gates above.
Discovery, collection, generation and recognition validation are separate states.
No legacy Actions capability is retired merely because a metadata feed works.
