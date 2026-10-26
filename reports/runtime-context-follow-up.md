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


## Runtime pointer context follow-up

Producer and consumer `a8622eb7ae995b3a0749b2befad87426d25fec4a` add source-owned load-configuration pointer
metadata. One 911-byte record in `vs2022.part9.npat` names three source fields;
`vs2022.part4.npat` gains one typed outgoing reference on its existing XFG body.
No function body or WDK pack is copied. The 897 readable relevant source records
from 18 collected x64 inputs agree on the selected field/default relationships.
`runtime-pointer-context.sources.json` retains archive/file and raw-evidence
hashes, source counts and unreadable-member diagnostics. This is not coverage
of unparsed compiler IR or every possible source. Source extraction checks
callable fields and overlapping relocations; disjoint scalar fixups are counted
separately and confer no pointer evidence.

The selected tree reaches **146/161**, leaving **15** unresolved. Across 23
stripped probes it adds six correct candidate addresses (two each in the ordinary,
MFC and debug VS2022 images), loses no correct addresses and adds no wrong
candidate names. Automatic signature-only identities remain zero. Existing
incorrect candidates are not reclassified as successes. The selected profile
grows from 161,348 to 161,349 records, with no new global byte-index entries.

The loader owns callable role/field mapping. Matching queries only recorded
immutable relocated slots and requested executable entries, then verifies the
complete existing body. Every wildcard must be a canonical operand referencing
independently established storage; every reference must agree. The ordinary
16-byte caller floor is unchanged. Known contradictory defaults and source or
slot conflicts veto this context. New candidates cannot start incoming inference
or supply data bindings to another candidate. All their outgoing references are
already checked against immutable storage, so the pass avoids rebuilding the
general reference graph. The optimized and preceding outputs are byte-for-byte
equal on all 23 probes.

Verification passes 269 native signature tests, 110 core Python tests and 241
signature-repository tests (one optional vendor round-trip skipped). ASan/UBSan
passes 161 focused tests with changed components instrumented; dependencies are
not all instrumented and leak detection is disabled. Changed current-tree
translation units compile separately. Runtime validation uses the frozen Release
fixture with the current signature implementation; it is not a complete unrelated
current-tree or native-platform rebuild.

Thirty alternating in-process Release runs retain 51 repetitions after a warmup
at one and four workers. Separate runs compare old/new engines with unchanged
packs and the data increment. CPU medians and median paired differences in
milliseconds for the increment are:

| Workers | Probe | Before / after (ms) | Paired delta (ms) |
| --- | --- | --- | --- |
| 1 | vs2022-x64-mt-o2 | 6.682 / 6.705 | -0.003 |
| 1 | vs2022-x64-mfc-mt-o2 | 48.351 / 48.309 | -0.083 |
| 1 | vs2022-x64-mtd-od | 17.082 / 16.943 | -0.150 |
| 4 | vs2022-x64-mt-o2 | 6.853 / 6.839 | -0.032 |
| 4 | vs2022-x64-mfc-mt-o2 | 48.593 / 48.595 | +0.063 |
| 4 | vs2022-x64-mtd-od | 18.218 / 18.161 | +0.071 |

The shared host remains busy and variation is substantial. These measurements
show no clear regression for this increment; negative paired deltas do not prove
a speedup, zero overhead, an uncontended bound or a cross-tool ranking.


## Source-local data follow-up

Producer and consumer `b8ddce7bd49962bfecf99012ee00d6e5441a1f61` add exact same-object data operand relations.
`winsdk.part6.npat` adds 1,766 bytes: two complete required clauses and four
name-indexed source-anchor bodies. Two existing incoming bodies in
`winsdk.part4.npat` gain their local relation in place, preserving all bytes,
names and previous fields. The new required clauses have different admission
conditions from those existing incoming-only records. No WDK pack changes.

The unpruned collision audit covers 4,180,555 emitted source records from 18
collected x64 inputs, including 545 records carrying local relations. It retains
missing fields and conflicting alternatives. The final producer reproduces all
18 raw output hashes, including after the cross-function relocation-overlap
check. `runtime-local-data-context.sources.json` records source and output
hashes, command anchors and unsupported/unreadable-input diagnostics; this is
not coverage of unparsed compiler IR or arbitrary libraries.

The selected tree reaches **147/161**, leaving **14** unresolved. Across 23
stripped probes it adds 18 correct candidate addresses, loses no correct
addresses and adds no wrong candidate names. The 222 pre-existing wrong
candidates are unchanged; automatic signature-only names remain zero. The
short global-locale getter still fails the complete counterclaim audit and is
not added. The selected profile grows from 161,349 to 161,355 records: only
two new entries participate in global byte matching; four are name queries.

The external anchor must already be a complete, strong ordinary candidate.
The exact source operand, canonical decode and mapped data extent must agree,
and every matching source variant must support the relation. A consumer cannot
create its own binding, restart incoming inference or authorize a source name.
External and local data keep separate kinds through generation, folding,
parsing, cache version 7 and frozen reference settlement.

Verification passes 277 native signature tests, 114 core Python tests and 241
signature-repository tests (one optional vendor round-trip skipped). ASan/UBSan
passes 169 focused tests; changed components are instrumented, dependencies are
not all instrumented and leak detection is disabled. Changed current-tree
translation units compile separately and clang-format 22.1.2 passes. Runtime
qualification uses the frozen Release fixture, not a full unrelated current
mainline or native-platform rebuild.

Thirty alternating in-process Release runs use 51 measured repetitions after
a warmup at one and four workers. Separate unchanged-pack engine comparisons
preserve identical candidate digests. The increment's CPU medians and median
paired differences in milliseconds are:

| Workers | Probe | Before / after (ms) | Paired delta (ms) |
| --- | --- | --- | --- |
| 1 | vs2022-x64-mt-o2 | 7.821 / 7.753 | +0.005 |
| 1 | vs2022-x64-mfc-mt-o2 | 51.147 / 51.049 | +0.015 |
| 1 | vs2022-x64-mtd-od | 22.841 / 21.903 | +0.065 |
| 4 | vs2022-x64-mt-o2 | 7.581 / 7.704 | +0.010 |
| 4 | vs2022-x64-mfc-mt-o2 | 56.607 / 57.664 | -0.049 |
| 4 | vs2022-x64-mtd-od | 18.858 / 18.791 | -0.180 |

The shared host remains busy; wall times vary substantially. These paired
measurements show no clear regression for this increment. They establish
neither zero overhead, a stable speedup nor a ranking against other tools.


## Scoped stream-initializer follow-up

Producer and metadata refiner `ab939f0eba2e831ed5e3b29a00f6487599683143` admit uniquely defined typed static
functions as source-local anchors and preserve every cross-version operand
alternative. Runtime qualification uses `5a969d6acdfa3b1d1881d896cbbfed02aaa5d518`. Existing cache version 7
consumers remain format-compatible.

`vs2022.part10.npat` adds **one** complete required clause, **178 bytes**, for the
release stream-initializer body missing from the original comparison set. It
adds one byte-index entry and no additional name-query body. Eight existing
consumer bodies and one existing anchor body gain local fields in place; their
bytes, names and previous references remain unchanged. Different admission
clauses are retained only where the existing full-reference clause leaves the
function unresolved. No ordinary record or WDK pack changes.

The raw audit includes 4,180,555 source records across 18 collected x64 inputs,
including 2,837 records with local relations. All source and output hashes are
verified. Wide-character counterclaims retain every alternative anchor operand.
Missing fields and duplicate definitions remain unknown; consumer alternatives
cannot establish anchor bindings. Unparsed compiler IR and unreadable members
remain outside the evidence coverage.

Across 23 stripped probes, this selected increment adds **one** correct
candidate address with no lost correct or new wrong candidates. The original
gap set reaches **148/161**, leaving **13** unresolved. The 222 pre-existing
wrong candidates are unchanged and automatic signature-only names remain zero.
Running the new engine on the old packs reproduces every prior JSON output
byte-for-byte.

The initial broader proposal also matched a debug body, but newly activating
data validation there retained a measurable cost. That extra body is not part
of this publication. Frozen validation now avoids repeated prefix work and
entry copies, and anchor lookup compares name lengths before text. No reference
constraint is removed.

Thirty Release benchmark runs alternate the previous and current implementations
inside one process, with 51 measured repetitions after warmup. Old-pack controls
retain identical candidate digests. The selected profile grows from 161,355 to
161,356 records. The table includes the new engine and the selected increment:

| Workers | Probe | Previous CPU median (ms) | Current CPU median (ms) | Median paired CPU delta (ms) |
| --- | --- | ---: | ---: | ---: |
| 1 | vs2022-x64-mt-o2 | 6.844 | 6.731 | -0.114 |
| 1 | vs2022-x64-mfc-mt-o2 | 48.835 | 47.347 | -1.495 |
| 1 | vs2022-x64-mtd-od | 17.154 | 16.999 | -0.100 |
| 4 | vs2022-x64-mt-o2 | 7.076 | 6.932 | -0.115 |
| 4 | vs2022-x64-mfc-mt-o2 | 48.927 | 48.012 | -1.182 |
| 4 | vs2022-x64-mtd-od | 17.127 | 17.117 | -0.057 |

These samples show no clear regression for the published selection. Shared-host
variation and the limited corpus do not support a zero-cost guarantee, a
universal speedup, or a comparison with other products.

Verification passes 279 native signature tests, 115 core Python tests and 171
focused ASan/UBSan tests. Changed current-tree translation units compile and
clang-format 22.1.2 passes. Sanitized components do not cover every dependency;
leak detection is disabled. Runtime qualification uses the isolated Release
fixture, not a full unrelated mainline or native-platform rebuild. Signature
repository checks pass 241 tests with one optional vendor round-trip skipped.


## Checked data-layout follow-up

Producer, refiner and required consumer `174c8015902ce9ad6e14e497008499a12aaf711e` support canonical signed
address deltas within one non-COMDAT source data section. Cache format 8
rebuilds older entries. A uniquely defined typed function still needs an
independently matched complete ordinary body and an exact zero-addend static
data operand. Defined consumer coordinates, signed addends, operand extents
and mapped-region bounds are checked. A relative consumer cannot establish
a binding or feed a second inference round. Auxiliary symbol indices, split
sections, weak/undefined targets and conflicting source variants remain refused.

`vs2022.part11.npat` contains one complete required clause, **224 bytes**, for
stream initialization. Two existing wide/unsigned-short initializer records
gain source-owned alternatives in place. Their bytes, names and prior fields
remain unchanged. The selected profile grows from 161,356 to 161,357 records,
with one new byte-index entry and no new name-query body. Ordinary and WDK
packs are unchanged.

The audit retains 4,180,555 records across 18 collected x64 inputs, including
6,487 records with local relations. The final producer reproduces every audited
raw output hash. The proposed stream destructor remains excluded: actual
14.51 counterclaims put the stream and its static buffer in separate source
sections. Cross-kind or absent fields are not treated as a distinction.

Across 23 stripped probes the increment adds one correct candidate address,
loses none and introduces no wrong candidates. The original gap set reaches
**149/161**, leaving **12** unresolved. The 222 pre-existing wrong candidates
are unchanged; automatic signature-only names remain zero. All 23 old-pack
controls reproduce their prior JSON output byte-for-byte.

Thirty Release runs alternate the previous and current implementations in
one process, using 51 measured repetitions after warmup, at one/four workers.
The baseline is checked against the previous immutable binary. Private parser
symbols are isolated between the two implementations; no invalid comparison
is included. Exact keys avoid coordinate decoding. The table records the
increment and separate old-pack controls (milliseconds):

| Workers | Probe | Previous CPU median | Current CPU median | Paired CPU delta | Control paired delta |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | vs2022-x64-mt-o2 | 4.876 | 4.862 | +0.019 | +0.006 |
| 1 | vs2022-x64-mfc-mt-o2 | 34.844 | 34.297 | -0.707 | -0.666 |
| 1 | vs2022-x64-mtd-od | 16.096 | 16.079 | +0.095 | -0.118 |
| 4 | vs2022-x64-mt-o2 | 6.288 | 6.248 | +0.032 | +0.043 |
| 4 | vs2022-x64-mfc-mt-o2 | 36.234 | 36.312 | -0.193 | +0.101 |
| 4 | vs2022-x64-mtd-od | 15.926 | 16.302 | +0.020 | +0.227 |

There is no clear material regression for this small selection on these
samples. Shared-host variation is visible in both controls and increments;
these results do not establish zero overhead or a stable speedup.

Verification passes 286 native signature tests, 116 core Python tests, 178
focused ASan/UBSan tests and 241 repository tests (one optional vendor
round-trip skipped). Changed current-tree translation units and the parser/cache
owners compile; clang-format 22.1.2 passes. Runtime qualification uses the
isolated Release fixture, not a full unrelated current-mainline rebuild.
Sanitizer coverage does not include every dependency and disables leak detection.


## Caller queries from confirmed data consumers

Consumer and selector `1b2bbf2bc8393694035c68b725843c0c35bcf378` allow complete,
strong, independently data-confirmed parents to request existing caller bodies.
Every generation reads the same frozen post-data candidates and exact data
bindings; no descendant can create another binding or alter an ancestor's proof.
The continuation reuses the existing name index and round budget. A preliminary
query gate skips irrelevant data consumers. When useful, only visited addresses
are settled from a sorted index of all frozen claims, preserving ambiguity.

`vs2022.part12.npat` adds one **377-byte** complete source refinement. Existing
records are unchanged; the selected profile has 161,358 records, with **zero**
new byte-index entries and one new name-query body. The selected clause uses
previously qualified raw output from producer `174c8015902ce9ad6e14e497008499a12aaf711e`;
the provenance sidecar records all 18 evidence-file hashes. No producer change
or weakening of cross-kind/missing-source counterclaims is involved. In
particular, the destructor's rejected direct data-layout proof stays rejected;
its registration by an independently confirmed initializer supplies the new
incoming evidence.

All 23 stripped probes reproduce their old-pack control JSON byte-for-byte.
The increment adds one correct candidate, loses none, adds no wrong candidates,
and advances the original gap set to **150/161**, leaving **11** unresolved.
The 222 pre-existing wrong candidates remain; automatic signature-only names
remain zero. Identical nominal bodies and insufficient roots remain unknown.

Thirty paired Release runs use 51 measured calls per variant after warmup,
one/four workers and separate old-pack controls. The previous implementation's
private caller symbols are isolated, and its name digests match the immutable
previous binary on all three probes. Final measurements (milliseconds):

| Workers | Probe | Previous CPU median | Current CPU median | Paired CPU delta | Control paired delta |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | vs2022-x64-mt-o2 | 4.740 | 4.824 | +0.036 | +0.016 |
| 1 | vs2022-x64-mfc-mt-o2 | 35.451 | 34.800 | -0.207 | +0.130 |
| 1 | vs2022-x64-mtd-od | 13.761 | 13.891 | -0.176 | -0.101 |
| 4 | vs2022-x64-mt-o2 | 4.794 | 4.778 | +0.056 | -0.014 |
| 4 | vs2022-x64-mfc-mt-o2 | 34.506 | 34.627 | -0.207 | +0.055 |
| 4 | vs2022-x64-mtd-od | 15.225 | 15.165 | -0.150 | +0.021 |

An initial eager-settlement implementation cost about 0.127 ms per target-probe
call; the qualified implementation settles only visited addresses. Shared-host
variation remains visible in controls and increments. These samples do not
establish zero overhead or a universal speedup.

Verification passes 291 native signature tests, 117 core Python tests, 183
focused ASan/UBSan tests and 241 repository tests (one optional vendor
round-trip skipped). New cases cover frozen competing target claims, rooted
chains with back edges, missing source/root evidence and refusal to establish
new data bindings. Runtime checks use the isolated Release fixture; current-tree
changed translation units compile separately. Dependencies are not all
instrumented and leak detection is disabled. No full unrelated mainline rebuild
or cross-product performance ranking is claimed.
