# NeverD consumer test receipt

The feature data in `21d88205a978b6bb71b3ee1b55eab5c38db0dcaa`
(merged by signatures PR #16) was exercised by
[NeverD PR #537](https://github.com/NeverSight/NeverD/pull/537), implementing
[issue #495](https://github.com/NeverSight/NeverD/issues/495).
The tested consumer revision is
[`7f148368679dcb7bd765f537318165770c96ecd2`](https://github.com/NeverSight/NeverD/commit/7f148368679dcb7bd765f537318165770c96ecd2).
The [machine-readable receipt](consumer-results.json) records counts, toolchain
and baseline failures for the macOS arm64 Release run on 2026-10-05. This receipt does not change any rule, profile or evidence
digest. The rule files retain `consumer_verified: false` pending separate
review of this receipt and the engine implementation.

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

The consumer checks passed: 34 library-recognition cases cover all 59 rules;
65 session, 132 signature, 99 debug-info and 56 PDB-identity cases passed.
Both C routes passed 1,764 source regressions and 59 LLVMC value-semantic cases.
Three real CLI/worker integrations and all 23 desktop/worker tests passed.
The 230 documentation/capability checks, 28 feature Python tests, profile
validation, pinned formatting and GUI localization validation also passed.

The full aggregate is **not green**: the initial integrated run executed
15,572 CTest entries with 113 failures. Lower-concurrency replay and a separate
build of dev `c32e0a31c` reproduced 88 distinct failures on both revisions.
Two regressions in tests that parsed JSON using a fixed-field-order regex were
corrected and passed. A Swift compiler timeout also passed on retry. The
receipt lists the baseline failures; it does not claim a final all-green
aggregate. Existing dev benchmark reports also fail the repository-wide
private-path check; the changed files pass the same checker separately.

CPU/driver emulation, Unicorn semantic tests and the external binary corpus
were disabled. The full signatures Python suite previously had 7 macOS
host/tool compatibility errors among 173 tests in existing collector/migration
code; all 28 focused feature tests passed. These limits are distinct from
successful feature matching and presentation checks.

## Reproduction

Use the fixed NeverD revision and its signatures gitlink. Configure a Release
test build with the NeverD LLVM toolchain, Clang and `lld-link`; the latter links
the original `/Z7` objects to local PE/PDB fixtures. Follow NeverD's
`docs/testing.md` for dependency and build-profile requirements.

```sh
python3 scripts/validate_library_features.py
python3 -m unittest discover -s scripts/tests -p 'test_library*.py' -q
```

From the NeverD checkout:

```sh
cmake --build build-release --target NeverDLibraryRecognitionTests \
  NeverDSessionCAPITests NeverDSignatureTests NeverDDebugInfoTests \
  NeverDPDBIdentityTests NeverDObjCSourceCallTests NeverDLLVMCValueTests \
  neverd neverd-worker --parallel 4
ctest --test-dir build-release -R 'LibraryRecognition|LibraryFeature|WorkerLibrary' \
  --output-on-failure
```

The GUI tests require a separate Qt/KDDockWidgets build. Missing tools omit
coverage; they do not count as successful profile validation. This receipt
does not expand the supported profile matrix to other architectures,
allocators, traits, LTO or debug/hardening configurations.
