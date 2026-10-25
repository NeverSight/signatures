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
161-entry investigation now has 139 settled candidates, up from 134 before
this engine/data follow-up. Twenty-two entries remain unresolved.

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
