# Library feature evidence

These original probes expose small operations from actual library headers.
They produce evidence for the structural feature packs described by
[NeverD #495](https://github.com/NeverSight/NeverD/issues/495). The existing
`.pat` generator, minimum fixed-byte requirement and linkage-name convention
are unchanged.

`accessors.cpp` exercises `basic_string<char>`, `basic_string<wchar_t>` and
`vector<uint32_t/uint64_t>` size, empty, data and capacity. The Windows probes
also exercise shared ATL/MFC `CStringT` and ATL COM `CComPtr<IUnknown>`.
`locale.cpp` explicitly instantiates `use_facet` and `has_facet` for the
standard narrow and wide locale facets. Its O0 and O2 objects retain actual
template symbols and relocation targets for separate signature authoring.
This capture adds no byte rules or recognition claims by itself.
`template-collisions.cpp` instantiates containers, ownership operations,
tuples, atomics and strings for distinct scalar, string and user-defined
types. The two user-defined types have the same layout but different names.
Its release/debug O0 and O2 builds retain nominal alternatives that ordinary
library archives may not instantiate. These bodies are collision evidence;
matching one of them does not recover an erased source type. Reference-only
refinements and incoming-context records need separate source and image checks.
`runtime-collisions.cpp` adds independently named string updates, streams,
allocation/ownership, synchronization and exception operations under the same
four configurations. None of these probes reads evaluation programs or their
symbol maps. These families are collected only for MSVC.

`regex-collisions.cpp` exercises regular expressions and packed-bit containers.
`operation-collisions.cpp` covers free atomic operations and an ABI-aligned
stack-storage size sweep. `frame-collisions.cpp` varies the number and type of
individually destroyed objects, including a stack buffer that exercises compiler
stack protection. `boundary-collisions.cpp` covers const and mutable container
boundaries, piecewise node construction, empty deleter types, ordering predicates,
default atomic loads and calendar wrappers. These are independent source
counterexamples: a matching body supplies evidence against a unique byte claim,
not a replacement name for an evaluated function.

The checked-in [capture receipt](collision-capture-receipt.json) records eight
compiler/target configurations and 128 reproduced objects/assembly files,
including package and included-header hashes. The separate
[collision refinement receipt](collision-refinement.json) records the selected
patterns, input hashes and held-out accuracy/performance checks. It constrains
whole byte cohorts together and retains at most one global required clause per
old record. Earlier generation receipts remain historical evidence; their
`collision_refinement` links identify the current outputs and qualification.
The 60-probe check reduces wrong preferred candidates from 541 to 333 with no
new wrong candidate, while correct library candidates change from 171817 to
171702. All signature-only names remain unadmitted. This is a precision tradeoff,
not complete recognition or proof of original source identity.

`libc.c` keeps C memory/string operations separate from C++ containers.
User classes, `vector<bool>`, a wrong stride, an ordered load, extra effects
and a different library configuration provide near misses. A user wrapper
around an operation is not the library function itself.

Each compilation retains its object, assembly, symbol table, disassembly,
record layouts, compiler identity, selected preprocessor values and hashes
of every included header. Clang builds also retain LLVM IR. An O0 build
keeps out-of-line callees; O2 exercises operations inside callers. Whether
each operation actually inlined is established from the retained output,
not from the optimization flag alone.

Address-taken member pointers also retain genuine, optimized library methods
in the O2 object. This gives an optimized standalone body and an inline caller
under the same supported profile. O0 remains separate evidence; it is not
automatically claimed by a pack derived from O2.

The evidence manifest reports `recognition_verified: false`: producing the
data does not establish NeverD matcher accuracy. Rule packs and their
consumer tests must separately prove accepted regions, rejected lookalikes,
identity precedence and reversible presentation. In particular, an offset,
pointer triple or virtual Release call alone does not establish a library.

## libc++ on arm64 macOS

Use the fixed LLVM source revision
`cc7be19969b7dc6c309e67619630ccc90ef46d9f` from
[NeverSight/llvm-project](https://github.com/NeverSight/llvm-project/tree/cc7be19969b7dc6c309e67619630ccc90ef46d9f/libcxx).
This is libc++ `23.0.0git`. LLVM source and notices remain under
Apache-2.0 with LLVM exceptions. The producer records the source commit and
actual header hashes. It rejects modified libc++ sources. Apple SDK headers
are used only for the target's C/system declarations.

Configure headers with a compatible fixed Clang installation (initial
evidence uses Homebrew Clang 22.1.6). Here `LLVM_SOURCE`, `LLVM_BIN`,
`LIBCXX_CONFIG`, `PROBE_OUTPUT` and `SDK_PATH` denote explicit task paths:

```sh
cmake -S "$LLVM_SOURCE/runtimes" -B "$LIBCXX_CONFIG" -G Ninja \
  -DLLVM_ENABLE_RUNTIMES=libcxx \
  -DCMAKE_C_COMPILER="$LLVM_BIN/clang" \
  -DCMAKE_CXX_COMPILER="$LLVM_BIN/clang++" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC=OFF \
  -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
  -DLIBCXX_CXX_ABI=none -DLIBCXX_ENABLE_ABI_LINKER_SCRIPT=OFF \
  -DLIBCXX_HARDENING_MODE=none
python3 scripts/build_library_feature_probes.py \
  --kind libcxx --compiler "$LLVM_BIN/clang++" --llvm-bin "$LLVM_BIN" \
  --llvm-source "$LLVM_SOURCE" --libcxx-config "$LIBCXX_CONFIG" \
  --sysroot "$SDK_PATH" --output "$PROBE_OUTPUT"
```

The producer selects the configured and source libc++ headers explicitly.
The actual alternate-string-layout macro is recorded; ABI version 1 does
not by itself describe the string layout. The negative configuration uses
libc++ debug hardening. Use a fresh output directory for each run, compare
object and assembly hashes between runs, and retain diagnostics on failure.

## MSVC STL and ATL on Windows

Use a Visual Studio 2022 installation with the x64 v143 14.44 toolset and
its matching ATL headers. LLVM's inspection tools must be installed under
`Program Files/LLVM/bin`. Run:

```powershell
./scripts/Build-LibraryFeatureProbes.ps1 -OutputDirectory C:/evidence/library-features
```

The wrapper selects the real toolset via VsDevCmd and records the installation
metadata. The producer records the actual full toolset/compiler version and
Windows SDK, rather than assigning a guessed version to the result. Positive
builds use `/MT`, C++17 and iterator debug level 0. The near-miss configuration
uses `/MTd` and iterator debug level 2. Missing ATL headers fail collection.

MSVC/ATL/SDK headers remain under their original terms; the evidence records
their hashes and source identity, not copies of the headers or complete
preprocessed translation units. Source versions identify the derivation of
a rule, not the exact library version in a binary subsequently matched.

The `Library feature evidence` workflow uploads Windows build artifacts,
including partial diagnostics when a compilation fails. This workflow does
not overwrite `.pat` files or claim that structural recognition has passed.

Author the retained Windows capture into rules with the fixed NeverD source
and its built signature generator:

```sh
python3 scripts/build_msvc_features.py --evidence "$PROBE_OUTPUT" \
  --neverd-source "$NEVERD_SOURCE" --sigmaker "$NEVERD_SIGMAKER"
```

`build_libcxx_features.py --evidence "$PROBE_OUTPUT" --repeat "$REPEAT_OUTPUT"`
authors the libc++ pack. `verify_library_feature_repeat.py FIRST SECOND`
compares the actual objects/assembly/IR in two fresh runs against both
manifests. A failed comparison is not a successful reproduction.

## musl memory/string on x64 ELF

Download the official musl 1.2.5 archive from the URL in
`scripts/build_musl_features.py`; the producer enforces its SHA-256 before
extracting. It uses Clang 22.1.6, musl's own configure/Makefile and headers,
LLVM inspection tools and an explicit ELF lld linker. No system libc headers
or target execution are required. The linked ELF is an analysis fixture,
not an executable startup environment.

```sh
python3 scripts/build_musl_features.py \
  --archive "$MUSL_ARCHIVE" --output "$PROBE_OUTPUT" \
  --compiler "$LLVM_BIN/clang" --llvm-bin "$LLVM_BIN" \
  --linker "$LLD_BIN/ld.lld" --neverd-source "$NEVERD_SOURCE" \
  --sigmaker "$NEVERD_SIGMAKER" --neverd "$NEVERD_CLI"
```

The script retains source hashes, actual compile flags, library/probe
objects, linked and stripped images, symbol truth, generated patterns, and
byte matching results. See `features/COVERAGE.md` for the retained stripped
function-discovery miss. Do not drop that fixture or call it a matcher pass.

## Producer checks

```sh
python3 -m unittest scripts.tests.test_library_feature_probes -v
python3 -m unittest discover -s scripts/tests -v
```

The full collector suite expects the GNU archive tools provided by its Linux
CI environment. Run those checks there when the host only provides BSD tools.
