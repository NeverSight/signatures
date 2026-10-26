# Runtime context follow-up

This update adds five complete required-reference clauses for two unresolved
runtime routines and one complete caller record with conditional references.
It keeps the existing ordinary patterns and uses the existing toolset profile.
The caller record stays out of the global byte index.

The producer is NeverD `d0df4ce1b1b6e6500437e36da92728c560fc4789`.
The single-reference clauses use the earlier address-reference producer
recorded in their provenance and the updated selector. Both audits include all
18 archived x64 source collections, including short, discarded and conflicting
functions. Each retained single-site clause must distinguish every overlapping
raw claim; alternatives at one site are inseparable.

## Recognition checks

The stripped-input evaluation uses linker-map truth for 23 executable probes,
including optimized/debug x64, x86, ARM32 and ARM64 controls. The original
161-entry investigation reached 139 settled candidates, up from 134 before
this engine/data follow-up. Twenty-two entries remained unresolved then.

Against the original `fe9a373c020fd48f68802353497bf8e315f7e178` data/engine
baseline, the complete accumulated changes recover 1,382 correct addresses
(1,359 marked as library routines by the maps), lose zero previously correct
addresses and introduce zero new wrong names. Existing wrong candidates fall
from 236 to 222. These are corpus measurements, not a zero-error guarantee.
Automatic source names remain disabled for all stripped signature-only hits.

## Performance checks

The selected x64 profile grows from 161,333 to 161,339 modules. Five new
required-context records participate in byte lookup; the one new caller record
is queried only by name. Function-address discovery reuses the existing call
sweep and its canonical parallel joins, with no second full scan or detailed
LEA re-decode.

Local Release measurements use one worker. Matching alternates the old and new
data in one process, discards a warmup and records 51 repetitions. Discovery
compares the same source snapshot with and without the address feature, over
five alternating process pairs and 21 measured repetitions per process.
Times below are process-CPU medians in milliseconds.

| Probe | Matching before / after | Discovery before / after |
| --- | --- | --- |
| vs2022-x64-mt-o2 | 5.933 / 6.091 | 14.363 / 14.301 |
| vs2022-x64-mfc-mt-o2 | 42.727 / 43.468 | 81.600 / 80.241 |
| vs2022-x64-mtd-od | 14.127 / 15.377 | 28.920 / 28.763 |

The host was shared with other CPU-heavy work; these values do not establish
an uncontended latency bound or a speed ranking against other analyzers.
Matching increases in this run while discovery stays close to baseline.

## Focused verification

- 222 native signature tests, 134 image-analysis boundary tests and 5 SDK tests.
- 78 core Python generation/selection tests and 241 signature-repository tests
  (one optional vendor round-trip test skipped).
- ASan/UBSan on the changed signature components: 116 tests; on the changed
  discovery components: 32 tests. Linked dependencies were not all instrumented.
- The changed current-tree C++ translation units also compile against their
  current headers. Runtime checks use the frozen local validation build, not
  a claim that every unrelated current-tree component was rebuilt.

Full held-out platform coverage and reliable cross-tool speed comparisons
remain outside this report. Byte-identical functions with unresolved context
remain candidates or unknowns; they do not acquire an invented identity.

## Self-reference audit follow-up

Producer `c275e77111dc2182cfb40e9e322a09cce97f6653` preserves self-address
and self-branch references, including aliases, in raw collision evidence for
COFF, ELF and Mach-O. Omitting those fields hid a useful constraint in rival
initializer bodies. Ordinary and caller patterns still omit self references.
Eight full-library caller/context outputs remain byte-identical to their
previous outputs (libcmt, libcpmt, libvcruntime and libucrt).

All 18 x64 evidence collections were regenerated and audited. Only one useful
new initializer record is retained; both of its independent references are
required. The exact final tree reaches **140/161**, leaving **21** unresolved.
All 23 stripped probes retain zero new wrong names, zero lost correct addresses
and zero automatic signature-only identities. The increment over the preceding
update is one correct address; the other proposed records added no recognition
and were not published.

The selected profile now contains 161,340 modules. The same alternating
one-worker, 51-repetition local matching check gives these process-CPU medians:

| Probe | Before / after (ms) |
| --- | --- |
| vs2022-x64-mt-o2 | 7.558 / 7.426 |
| vs2022-x64-mfc-mt-o2 | 49.043 / 48.793 |
| vs2022-x64-mtd-od | 17.327 / 17.443 |

These small changes vary in both directions on the shared host; they do not
establish a reliable speedup. All 225 native signature tests pass, including
new self-reference and alias cases for the three formats. The raw evidence
marker remains rejected by the runtime parser.

## External-data context follow-up

Producer `7723cee5279d6ca5feb888b0eb6c838104d1b212` adds typed external-data references and
one frozen candidate-validation pass. The five records in `winsdk.part5.npat`
contain two required clauses and three complete source anchors. They retain
source-library, output and all 18 raw collision-input hashes in
`runtime-data-context.sources.json`; no byte-only claim is replaced.

The exact final tree reaches **142/161**, leaving **19** unresolved. Across all
23 stripped probes it adds 15 correct candidate addresses over the preceding
140-entry result, with zero lost correct addresses and zero new wrong names.
Automatic signature-only source identities remain zero. Byte-identical heap
getters, argv accessors and compiler-generated wrappers remain ambiguous;
return padding and a changed test driver cannot erase their counterclaims.

The selected x64 profile grows from 161,340 to 161,345 modules. Three complete
anchor bodies are queried by name, and two required clauses participate in
byte lookup. The data pass groups only requested addresses and source anchors;
frozen reference checking groups only referenced targets and retains its old
prefix in place. There is no additional full-image scan or iterative data chain.

Local Release checks alternate the preceding and new data in one process,
discard a warmup and measure 51 repetitions at one and four workers. These are
process-CPU medians in milliseconds; the paired delta is the median difference
within each repetition, so it need not equal the difference of the medians.

| Workers | Probe | Before / after (ms) | Paired delta (ms) |
| --- | --- | --- | --- |
| 1 | vs2022-x64-mt-o2 | 5.520 / 5.084 | +0.046 |
| 1 | vs2022-x64-mfc-mt-o2 | 41.240 / 42.751 | +1.054 |
| 1 | vs2022-x64-mtd-od | 12.054 / 11.880 | -0.094 |
| 4 | vs2022-x64-mt-o2 | 4.287 / 4.403 | +0.125 |
| 4 | vs2022-x64-mfc-mt-o2 | 30.887 / 31.210 | +0.398 |
| 4 | vs2022-x64-mtd-od | 12.148 / 12.015 | +0.038 |

The shared host has substantial timing variation. The added validation has a
measurable cost on the larger MFC image; these checks do not establish zero
cost, an uncontended bound or a cross-tool performance ranking. Separate
alternating runs also compare the preceding/current engines with unchanged
data. The current engine introduces no additional scanning for old packs.

Verification passes 242 native signature tests, 91 core Python tests and
241 signature-repository tests (one optional vendor round-trip test skipped).
ASan/UBSan passes 134 focused tests with changed components instrumented;
linked dependencies are not all instrumented and leak detection is disabled.
Changed current-tree translation units compile separately. Runtime checks use
the frozen validation build, with the same current signature implementation;
they do not claim a complete unrelated current-tree or native-platform rebuild.


## Primary table context follow-up

Producer `550bca08852a47c6d57b71aab16085621c498e3e` and consumer
`7f90ff52d4f0f4a116d355fa9512fee7165c272e` add explicit primary-table metadata.
The three records in `vs2022.part8.npat` reuse existing complete queried bodies;
no ordinary signature or function body is replaced or copied. All 1,052
relevant readable source declarations in 18 collected x64 inputs agree on
slot names and layout. Raw evidence and archive/file hashes are retained in
`runtime-table-context.sources.json`, including unreadable member counts.
This does not claim coverage of unparsed compiler IR or every possible source.

The exact selected tree reaches **144/161**, leaving **17** unresolved. Across
23 stripped probes it adds two correct candidate addresses, loses no correct
addresses and adds no wrong candidate names. Automatic signature-only source
identities remain zero. The earlier exploratory cross-profile experiment is
not this result: the published metadata is selected only with VS2022 packs.

The selected profile grows from 161,345 to 161,348 records, with no new global
byte-index entries. Runtime verification requires the strict primary RTTI
reader, complete immutable table ownership, relocation-backed pointer slots
and a complete strong existing body. Known contradictory siblings and multiple
matching weak alternatives remain unresolved. A matching weak fallback is a
candidate, not proof that no unknown override was linked. Table candidates do
not restart incoming inference or establish data bindings, and their outgoing
checks cannot bootstrap each other even with an empty original match set.

The pass intersects the smaller loader-owned relocation index. On the local
MFC probe this examines 2,521 data-pointer entries instead of 26,137 code-pointer
entries; the other two probes retain their smaller code-pointer index. It
never scans data sections for byte patterns.

Verification passes 257 native signature tests, 100 core Python tests and
241 signature-repository tests (one optional vendor round-trip test skipped).
ASan/UBSan passes 149 focused tests with changed components instrumented;
linked dependencies are not all instrumented and leak detection is disabled.
Changed current-tree translation units compile separately. Runtime validation
uses the frozen Release fixture with the current signature implementation;
it is not a complete unrelated current-tree or native-platform rebuild.

Alternating in-process Release measurements discard a warmup and retain 51
repetitions at one and four workers. Separate runs compare old/new engines
with unchanged packs and the three-record data increment. CPU medians and
median paired differences (milliseconds) for the increment are:

| Workers | Probe | Before / after (ms) | Paired delta (ms) |
| --- | --- | --- | --- |
| 1 | vs2022-x64-mt-o2 | 7.292 / 7.439 | +0.072 |
| 1 | vs2022-x64-mfc-mt-o2 | 48.260 / 49.829 | +0.611 |
| 1 | vs2022-x64-mtd-od | 16.993 / 17.218 | +0.190 |
| 4 | vs2022-x64-mt-o2 | 6.747 / 6.772 | +0.062 |
| 4 | vs2022-x64-mfc-mt-o2 | 47.331 / 48.504 | +0.760 |
| 4 | vs2022-x64-mtd-od | 17.233 / 17.451 | +0.078 |

The shared host remains busy and the timing variation is substantial. These
results quantify additional validation cost; they do not establish zero cost,
a stable speedup from the smaller-index change, an uncontended latency bound
or a ranking against another tool. The reduced traversal count is independently
observed and both index directions retain the same candidate results.
