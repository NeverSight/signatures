# Legacy PE library coverage

The `supplemental-*.pat` packs add **490,677 converted pattern records** in
42 files. They cover Borland/Delphi VCL, OWL, DBE and CodeGuard; Intel math
and runtime code; Digital Mars D; Windows CE; WDK/DDK; Watcom common runtime;
VIREO; Objective Grid/Toolkit; and other historical PE libraries.

| Target | Pattern records | Previously missing symbols |
| --- | ---: | ---: |
| PE x86 | 410,938 | 187,622 |
| PE x64 | 77,249 | 21,868 |
| PE ARM32 | 2,490 | 970 |

Symbol counts are distinct within each target and compare against the
existing `.pat` libraries. Independent semantic recognizers are outside
that symbol comparison. Existing baseline pattern files remain unchanged.

The WDK32, WDK64 and DDK64 supplements contain 8,410, 3,511 and 341 records.
Modern rebuilt MSVC, UCRT, MFC, ATL, SDK, glibc and Android NDK families retain
their existing ownership. These supplements add missing names to the
corresponding format, architecture and width.

## Admission and validation

- Skip every module naming an existing baseline symbol, including another
  machine-code version of the same symbol.
- Preserve leading bytes, CRC spans, sparse tail bytes and expressible direct
  branch references. Unsupported constraints refuse the complete record.
- Use NeverD's existing pattern builder for alias folding and byte-claim
  admission. Reject new claims that conflict with an existing claim and
  remove duplicate records across the supplements.
- Apply the fingerprint exclusions in
  [`legacy-library-counterexamples.json`](../validation/legacy-library-counterexamples.json).
  The 65 rejected byte claims caused 5,518 wrong proposals in the first
  regression pass; excluding their 107 records left no wrong proposals.
- Validation includes differential admission, format/tool roundtrips, cache
  invalidation and exclusion-policy checks. All proposals were checked
  against linker truth in 45 applicable PE probes, with no wrong proposals.
  Another 15 ARM64 probes have no supplement and were outside this check.
  Accuracy for other historical compiler builds remains unmeasured.

Adjacent `.sources.json` files identify the library family, target pack,
baseline revision, artifact hashes and validation policy. The
[`coverage audit`](legacy-library-audit.json) accounts for retained and
excluded profiles. These are converted third-party records; applicable
copyright and license notices remain unchanged.

## Reproduce

Supply a local input signature tree, a compatible binary-signature dump
tool and a NeverD source checkout. Use an empty staging directory separate
from the baseline. Input records are retained in the work directory;
published metadata describes coverage and artifact identities.

```sh
python3 scripts/import_binary_signatures.py \
  --sig-root "$SIGNATURE_INPUT_DIR" \
  --dumpsig "$FLAIR_TOOL_DIR/dumpsig" \
  --neverd-source "$NEVERD_SOURCE_DIR" \
  --baseline "$SIGNATURE_BASELINE_DIR" \
  --baseline-ref 254a63f839f27348badbabdd14f9d15f7d65ee37 \
  --work "$IMPORT_WORK_DIR" --output "$IMPORT_STAGE_DIR"

NEVERD_SOURCE_DIR="$NEVERD_SOURCE_DIR" \
FLAIR_TOOL_DIR="$FLAIR_TOOL_DIR" NEVERD_BIN="$NEVERD_BIN" \
  python3 -m unittest discover -s scripts/tests -v

python3 scripts/check_library_signature_import.py \
  --neverd "$NEVERD_BIN" --signatures "$IMPORT_STAGE_DIR" \
  --probes "$MSVC_PROBE_DIR" --report "$IMPORT_WORK_DIR/probes.json"
```

The native roundtrip builds synthetic patterns and tests both positive
variants and CRC/prefix near misses. The probe checker loads the supplements
alone and checks every proposal, including disputed ones, against independent
linker maps. Existing signatures cannot hide an incorrect imported name.

## Remaining gaps

Go ABI variants and some older runtime profiles have mixed or unspecified
target metadata. One DDK32 profile has contradictory width metadata.
DOS/16-bit, OS/2, special startup recognition and architectures outside the
current signature tree need separate admission support. Ctype checks,
fixup tables, non-printable name encodings and other constraints outside
the current matcher contract remain excluded.
