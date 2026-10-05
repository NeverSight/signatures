# NeverD consumer test receipt

The five feature packs contain 59 rules and retain their original compiler evidence.
[NeverD PR #537](https://github.com/NeverSight/NeverD/pull/537) integrated the consumer for
[issue #495](https://github.com/NeverSight/NeverD/issues/495).
[NeverD PR #547](https://github.com/NeverSight/NeverD/pull/547) fixes the validation gaps
found during the integration. This receipt records the subsequent macOS arm64 Release
validation through NeverD revision `e917305086dd3eb4c3b3f9999d383ed286a14ccd`
and feature/tooling revision `3477edde46545ba8396f77d04110f617f09baae5`.

The [machine-readable receipt](consumer-results.json) keeps the earlier aggregate and
baseline measurements as history. Pack-level `consumer_verified: false` remains the
producer's data-only declaration; independent consumer results belong in this receipt.
No matching rule, profile or compiler-evidence digest changes with this update.

## Coverage exercised

| Profile | Consumer evidence |
| --- | --- |
| libc++ arm64 macOS ABI 1 alternate layout | All 16 standalone and inline accessor rules. HighC, optimized LLVMC and NoOpt LLVMC source mappings; 16 distinct template identities; ordinary C compiles through both default source routes. |
| MSVC STL x64 release | All 16 standalone and inline accessor rules using original MSVC objects linked to a matching PE/PDB pair. Source mappings include authenticated PDB member spellings on all three routes. CLI checks preserve 16 distinct display identities and existing, collision-free C identifiers. |
| Shared ATL/MFC string support | All 6 accessor expression rules and 10 gated whole-function byte rules, including narrow/wide construction, copy, assignment and buffer methods. Accessor inline regions map through both C backends, including NoOpt LLVMC. |
| ATL CComPtr<IUnknown> | All 6 ownership rules; standalone bodies and the 5 applicable inline lifetime patterns. Tests cover virtual slots, guards, store/call order, re-entry reloads and authenticated exception metadata. |
| musl x64 ELF | All 5 byte rules in the retained stripped image; wrong bodies and conflicting packs abstain. Four independent direct caller sites map on all three routes. The shared-tail memmove body retains its identity but is deliberately not foldable. |

The 59-rule matrix uses the archived compiler outputs, not replacement library
implementations. Negative tests reject custom lookalikes, missing identities,
wrong layouts or compiler configuration, ambiguous candidates, modified call
slots, unsupported ownership ordering and incomplete exception metadata.
Joint byte/structural conflicts and work-budget exhaustion also abstain.

## Presentation contract

Tests compare ordinary and annotated C byte for byte, retain original LLVM/Med
bodies and call targets, preserve authoritative user/debug/symbol names, and
check shared identities in function lists, call sites, source pages and worker
responses. Source spans must cover the recognized occurrences without hiding
independent caller expressions. GUI tests cover reversible fold/unfold,
disjoint spans, incomplete pages, UTF-8 positions, copying the original text
and invalidation after identity or profile changes.

PDB-informed C views continue to depend on external record type declarations.
The MSVC checks demonstrate unchanged source, naming and mapping; they do not
claim that these views are self-contained compilable STL replacements.
The ATL fixtures are analysis-only. Unresolved platform calls are never run,
and recognition does not authorize native exception rewriting or execution.

The earlier `cf8cfa408` producer measurement in the musl archive remains intact:
it found 4/5 stripped entries and 5/5 symbol-bounded entries. The current
consumer matrix separately exercises all five stripped entries and direct
caller sites; it does not rewrite the historical measurement.

## Results and limits

The stable-build Release aggregate at `de953b4a9` ran 15,651 registered CTest
entries: 15,566 passed, 77 were skipped and eight failed. The failure list contained
seven distinct test names because the pointer-relocation case is registered in two
binaries. This initial run is retained unchanged in the machine-readable receipt.

The aggregate repairs at `46a564bae` passed all nine entries in the targeted replay,
including both registered control-flow and pointer-relocation variants. Four actual
Objective-C runtime fixtures now preserve floating/record setters, nested enumeration
selectors, CoreData properties and constant-object graphs. The constant-object fixture
uses Apple Clang's constant-literal extension; the Darwin LLVM link uses the selected
macOS SDK. Swift compilation and a control-flow runtime timeout passed unchanged at
lower concurrency. No failure from the aggregate remains unresolved.

The complete affected source-recovery suite passed all 1,782 tests at `46a564bae`,
including the new integer-forwarding and private-selector-spill regressions and the
existing contradictory declaration, alias, overlap, unknown-call and outgoing-storage
refusals.

Integration with `dev` revision `71059f7f3` then passed 1,786 source-recovery cases,
34 library-recognition cases, 65 session cases and all four affected Objective-C runtime
fixtures. It exposed two global-address failures and one memory-copy spelling assertion
in the pointer/exception suite. The address regression reproduced a crash in all four
O0/O2 and memory-mode program variants before the fix.

The global-address repair at `8d3cee425` passes all four memory execution tests, 63 LLVMC
execution/value tests, three CLI/worker integrations and the three initial failed cases.
The final pointer/exception/ABI suite passes 876 cases, with 20 documented corpus skips
and no failures. Its last assertion update distinguishes an observable global store
from a redundant local copy. The code repair and subsequent test-only revision are
recorded separately in the receipt; no initial failures remain unresolved.

These results combine the complete aggregate with its repaired failure replay and
affected-suite verification. They are not a claim of a single all-green aggregate at
the final revision. The 77 platform, corpus and optional solver/oracle skips remain
unexecuted coverage.

The signature tooling suite passes all 181 tests after the portability fixes in
[signatures PR #18](https://github.com/NeverSight/signatures/pull/18). The pack validator
accepts all five packs and 59 rules. Previously reported collector compatibility errors
and benchmark-path provenance failures have been corrected; the historical measurements
remain available in the receipt.

Focused checks also exercise 358 jump-table cases, 85 LowIR instruction-boundary cases,
81 Block source-proof cases, and 63 LLVMC execution/value cases. The Block runtime oracle
compiles and executes all eight ownership, fixup and profiling combinations. The i386
wide-argument and frame-address fixes pass both C routes against independent arithmetic
oracles. The full test run uses a stable build; compilation and runtime checks are not
counted as complete when skipped or interrupted.

CPU/driver emulation, Unicorn semantic tests and external binary corpus coverage remain
disabled in this local configuration. PDB/ATL analysis coverage does not authorize
execution of unresolved platform calls or expand native exception support. Earlier GUI,
localization and documentation checks are recorded separately from the final engine run.

## Reproduction

Use the recorded NeverD revision and its signatures gitlink. Configure a Release test
build with the NeverD LLVM toolchain, Clang and `lld-link`; the latter links the archived
MSVC objects to matching PE/PDB fixtures. Follow NeverD's `docs/testing.md` for toolchain
and build requirements.

```sh
python3 scripts/validate_library_features.py
python3 -m unittest discover -s scripts/tests -v
```

From the NeverD checkout, finish the build before running tests:

```sh
cmake --build build-release --parallel 4
ctest --test-dir build-release --output-on-failure --parallel 8
```

The GUI tests require a separate Qt/KDDockWidgets build. Missing tools omit coverage;
they do not count as successful profile validation. This receipt does not expand the
supported profiles to other architectures, allocators, traits, LTO or hardening modes.
