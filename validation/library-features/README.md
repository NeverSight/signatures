# Library feature evidence

These original probes expose small operations from actual library headers.
They produce evidence for the structural feature packs described by
[NeverD #495](https://github.com/NeverSight/NeverD/issues/495). The existing
`.pat` generator, minimum fixed-byte requirement and linkage-name convention
are unchanged.

`accessors.cpp` exercises `basic_string<char>`, `basic_string<wchar_t>` and
`vector<uint32_t/uint64_t>` size, empty, data and capacity. The Windows probes
also exercise shared ATL/MFC `CStringT` and ATL COM `CComPtr<IUnknown>`.
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

## Producer checks

```sh
python3 -m unittest scripts.tests.test_library_feature_probes -v
python3 -m unittest discover -s scripts/tests -v
```

The full collector suite expects the GNU archive tools provided by its Linux
CI environment. Run those checks there when the host only provides BSD tools.
