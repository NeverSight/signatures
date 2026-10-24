# Selected IDA 9.5 signature imports

The `ida95-*.pat` supplements contain missing symbols selected from a local
Hex-Rays IDA 9.5 BETA1 installation. Each adjacent `.sources.json` identifies
the source `.sig`, its SHA-256, the installed FLAIR dumper's SHA-256 and the
baseline signature revision. These are converted third-party records, with
their original source terms; conversion does not relicense the source data.

`ida95-audit.json` accounts for every source file, including files that
contribute nothing. The full dumps remain in the local work directory.

The retained supplement has **490,677 records**. The final native check
examined all proposals in **45 applicable PE probes**, with no wrong names;
15 ARM64 probes have no supplement and were outside this check. The first
pass exposed 65 unsafe byte claims in generic wrappers, causing 5,518 wrong
proposals. The exact claims and independent probe/map hashes are retained in
[`validation/ida95-counterexamples.json`](../validation/ida95-counterexamples.json).
Rejecting them removed 107 records, including their alternate names and
reference variants. Original baseline pattern files are unchanged.

| Target | Pattern records | Previously missing symbols |
| --- | ---: | ---: |
| PE x86 | 410,938 | 187,622 |
| PE x64 | 77,249 | 21,868 |
| PE ARM32 | 2,490 | 970 |

The 42 pattern files cover Borland/Delphi VCL, OWL, DBE and CodeGuard;
Intel-specific math/runtime code; Digital Mars D; Windows CE; WDK/DDK;
Watcom common runtime; VIREO; Objective Grid/Toolkit; and other old PE
libraries. The WDK32, WDK64 and DDK64 files retain 8,410, 3,511 and 341
records respectively. Symbol counts above are distinct within each target.
The local Python suite passed all 207 tests, including the vendor-tool
roundtrip, cache invalidation and counterexample-policy checks.

## Selection

- Preserve the rebuilt MSVC, UCRT, MFC, ATL, Windows SDK, glibc and Android
  NDK families. An omission from those files can be an intentional rejection
  of an ambiguous function, rather than a missing feature.
- Reject a module if any of its public names already occurs in the same
  format/architecture/width's baseline. Keep linkage spellings unchanged.
- Import only PE records with an evidenced architecture and width. A title
  that contradicts the application flags is refused. In particular,
  `msddk32.sig` says “32bit” but its flags say “64BIT”.
- Preserve the complete leading pattern, CRC and sparse rule bytes. A short
  tree path is padded with wildcards to the header's pattern width; rule
  byte offsets start after that width and the CRC span.
- Emit rule-function references only where the stated bytes prove the x86
  `E8`/`E9` direct branch that NeverD's `^offset` means. Data references,
  hidden opcodes and ARM mode-dependent references are refused.
- Refuse startup rules, ctype-table checks, v11 fixup/alternative tables,
  non-printable symbol encodings, local/collision flags and multi-function
  or negative public offsets. Never discard these constraints and keep a
  weaker record. Read the leading-width and minimum-stated-byte policy from
  NeverD's `SignatureLimits.def`.
- Use NeverD's existing `build_msvc_signatures.py` folding and cross-library
  admission rules. Preserve collision exclusions, reject byte claims
  contradicted by other libraries, and remove duplicates across imported
  sources. Also reject a new claim if admitting it would require removing
  an existing claim. Baseline files are never rewritten.
- Reject every byte-claim fingerprint in the counterexample policy. A
  generic wrapper that needs a confirmed reference must not become a name
  merely because that reference is unknown. This policy is applied after
  selection on every normal CLI run, including cached runs.

## Reproduce

Use a matching local installation that provides `dumpsig -F` and a NeverD
source checkout. The output directory must be empty and separate from the
baseline. No IDA download or license credentials are used by these tools.

```sh
python3 scripts/import_ida_signatures.py \
  --sig-root "$IDA_DIR/sig" \
  --dumpsig "$IDA_DIR/tools/flair/dumpsig" \
  --neverd-source "$NEVERD_SOURCE_DIR" \
  --baseline "$SIGNATURE_BASELINE_DIR" \
  --baseline-ref 254a63f839f27348badbabdd14f9d15f7d65ee37 \
  --work "$IMPORT_WORK_DIR" \
  --output "$IMPORT_STAGE_DIR"

NEVERD_SOURCE_DIR="$NEVERD_SOURCE_DIR" \
IDA_FLAIR_DIR="$IDA_DIR/tools/flair" NEVERD_BIN="$NEVERD_BIN" \
  python3 -m unittest discover -s scripts/tests -v

python3 scripts/check_ida_signature_import.py \
  --neverd "$NEVERD_BIN" --signatures "$IMPORT_STAGE_DIR" \
  --probes "$MSVC_PROBE_DIR" --report "$IMPORT_WORK_DIR/probes.json"
```

The optional native test creates its own synthetic patterns, compiles them
with `sigmake`, decodes them with `dumpsig -F`, and applies the converted
patterns through NeverD. It checks both tail variants, wildcard changes and
CRC/prefix near misses. It bundles no vendor signature fixtures.

The probe checker loads only the supplements and checks every proposal
against the independent linker maps, including proposals that the matcher
would leave disputed. Existing patterns cannot hide a wrong imported name.
This checks interference with the covered MSVC probes; it does not establish
complete recognition accuracy for every historical compiler represented by
the source files.

To extend the exclusions after another probe run, add `--neverd-source
"$NEVERD_SOURCE_DIR" --counterexamples validation/ida95-counterexamples.json`
to the checker command. It verifies the exact matching record bytes in the
PE before recording a fingerprint. Reapply the policy or regenerate the
stage, then rerun the probes until none contradict their linker truth.

## Remaining gaps

The Go ABI0/ABIInternal packs have unrestricted format/bitness headers, so
they remain unclassified instead of being copied into both width trees.
`bds40.sig`, Linux libc5 and several older libraries have the same metadata
problem. The contradictory DDK32 pack also remains out. DOS/16-bit, OS/2,
special startup recognition and architectures absent from NeverD's signature
tree need separate admission support. Ctype and v11 fixup records need an
expressive matcher contract before they can be imported without losing
evidence. Their exact dispositions and source identities are in the audit.
