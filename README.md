# signatures

FLIRT-style signature libraries for [NeverD](https://github.com/NeverSight/NeverD).

## Layout

```
<format>/<arch>/<bitness>/*.pat
```

Supported formats: `elf`, `pe`, `macho`. Architectures: `x86` and `arm`, each
at `32` or `64` bits, so Windows ARM64 images use `pe/arm/64` and Windows
ARM32 (Thumb-2) images use `pe/arm/32`.

NeverD copies this tree to `build/bin/signatures/` at build time. Use
`neverd sigs --auto` to apply the set that matches the loaded binary. It
reads every `.pat` file in the matching directory and ignores other files,
such as the `<name>.sources.json` provenance records that sit next to
generated files.

## What a line says

```
<leading bytes> <crc length> <crc16> <function length> :0000 <name> [<tail bytes>]
```

Each line states the bytes of one library function and gives it one name at
offset 0:

- The leading bytes are the first 32 bytes of the function, or all of it
  when it is shorter.
- The CRC16 covers the bytes after them, up to the first byte a relocation
  rewrites.
- The tail states the bytes after the CRC span, starting where the CRC span
  ends.
- Bytes that a relocation rewrites are `..` wildcards.
- A line states at least 16 bytes exactly. A shorter claim matches far more
  code than the function it came from.

These rules are NeverD's own:
[`neverd-sigmaker`](https://github.com/NeverSight/NeverD/tree/f6ac98c003e7e2c1c85c3d6c582ef77722eb64dd/tools/neverd-sigmaker)
produces the lines, and `neverd::sigs::PatternGenerator` defines how many
bytes each relocation rewrites.

A name is the linkage name the library's symbol table spells, byte for byte:
`?Close@CFile@@UEAAXXZ`, `_ZNSt6thread4joinEv`, x86 `_memcpy`. Names are never
demangled, sanitized, prefixed or truncated.

A line is kept only if its bytes identify one routine. When lines state the
same bytes under different names, all of them are dropped, because any one
name would be a guess. NeverD applies every file of a directory together, so
this holds across the directory. A line is also dropped when its bytes open a
longer routine of another name: NeverD compares a line only as far as the
line's own length, so the line would name that routine too.

## Windows (pe/) signatures

| File | Built from |
| --- | --- |
| `vs2015.pat` | MSVC v140 (14.0): x86 and x64 with ATL/MFC, ARM32 without |
| `vs2017.pat` | MSVC v141 14.16 with ATL/MFC (x86, x64, ARM32, ARM64) |
| `vs2019.pat` | MSVC v142 14.29 with ATL/MFC (x86, x64, ARM32, ARM64) |
| `vs2022.pat` | MSVC v143 14.44 with ATL/MFC (x86, x64, ARM32, ARM64) |
| `vs2026.pat` | MSVC 14.50 and 14.51 with ATL/MFC (x86, x64, ARM64; VS 2026 has no ARM32 toolchain) |
| `winsdk.pat` | Windows SDK 10.0.17763, 18362, 19041, 20348, 22000, 22621 and 26100: the Universal CRT and the user-mode libraries (ARM32 through 10.0.22621) |

The x86 and x64 directories also hold files imported from rizin's
sigdb-source for toolsets whose libraries are not collected: `vs2005` to
`vs2013`, `masm32` and `mingw32-zlib`. They were moved to the rules above
wherever a collected library could tell how; see
[Lines imported from rizin](#lines-imported-from-rizin).

Two workflows produce the generated files:

1. [`msvc-libraries.yml`](.github/workflows/msvc-libraries.yml) runs on
   GitHub-hosted Windows images, one job per row of
   [`.github/msvc-matrix.json`](.github/msvc-matrix.json):
   - It installs each toolset or SDK the image lacks. Most come from the
     image's own Visual Studio installer. An SDK that installer no longer
     offers comes from Chocolatey or from Microsoft's standalone SDK installer.
   - It packs each architecture's static libraries into a reproducible
     `tar.zst`, with a manifest that gives the size and SHA-256 of every file,
     and keeps the archives as assets of an `msvc-libs-*` release.
   - It builds the programs in `validation/` with the same toolset:
     statically linked, with linker maps.
2. [`msvc-signatures.yml`](.github/workflows/msvc-signatures.yml) builds
   `neverd-sigmaker` at a pinned NeverD revision and runs NeverD's
   [`build_msvc_signatures.py`](https://github.com/NeverSight/NeverD/blob/f6ac98c003e7e2c1c85c3d6c582ef77722eb64dd/scripts/signatures/build_msvc_signatures.py)
   over every `msvc-libs-*` release, one architecture at a time:
   - A file with library archives behind it is rebuilt from them alone.
   - Each architecture keeps only objects built for it (`--machine`), and
     lines cover every byte of every function.
   - Ambiguous lines are dropped across the directory, as described above.
   - Each file is read back with the loader's parser.
   - A manual run with `publish` set commits the result. With
     `migrate_imported` set, it first runs the migration of the imported
     files again.

Both workflows run from **Actions → Run workflow**. The library releases are
drafts unless `publish_release` is set. The archives hold unmodified Microsoft
libraries, which stay under the license terms of Visual Studio and the Windows
SDK. They are kept so that every line traces back to the exact bytes it came
from, not to redistribute the libraries.

## Accuracy

[`scripts/evaluate_probes.py`](scripts/evaluate_probes.py) runs
`neverd sigs --json --no-debug` over the validation programs and compares
every name NeverD would apply with the linker map of the same image:

- **named**: library functions that NeverD names as the map does.
- **wrong**: addresses NeverD would give a name the map does not give them.
  This includes the program's own functions: STL templates the program
  instantiates compile to the same bytes as library code.
- **disputed**: addresses where the loaded lines disagree, so NeverD names
  nothing.

`validation/` holds three programs, each linked statically with a map: an
MFC program and a CRT program built with `/O2 /MT`, and the CRT program built
with `/Od /MTd`. They were built with Visual Studio 2015 (x86, x64), 2017, 2019
and 2022 (x86, x64, ARM32, ARM64), and 2026 with both its default toolset and
14.50 (x86, x64, ARM64): 60 programs. Each directory is loaded whole, as
`neverd sigs --auto` loads it. Named is the share of the map's library
functions; wrong is the share of the names NeverD applies.

| Architecture | Programs | Named, optimized | Named, `/Od` | Wrong, optimized | Wrong, `/Od` | Disputed |
| --- | --- | --- | --- | --- | --- | --- |
| x86 | 18 | 24% | 50% | <0.1% | 4.7% | 52 |
| x64 | 18 | 57% | 54% | 0.3% | 9.4% | 306 |
| ARM32 | 9 | 57% | 57% | 0.7% | 2.1% | 9 |
| ARM64 | 15 | 56% | 58% | 1.4% | 10.1% | 578 |

Across all 60 programs NeverD names 133,078 of 284,642 library functions
(47%), 2,678 names are wrong (2.0%), and 945 addresses are disputed. With the
first generated files, which still had the imported lines merged into them,
it named 117,063 (41%), 7.6% of the names were wrong, and 18,733 addresses
were disputed.

- Optimized builds (`/O2`, `/MT`, with or without MFC) are the common case.
  On x86 and x64 fewer than 0.3% of the names NeverD applies to them are
  wrong, and three quarters of those come from the imported `vs2005`–`vs2013`
  files (see the last item). On ARM, what remains is mostly short routines
  that share their code with other routines except for what a relocation
  rewrites, such as MFC initializers that differ only in the message they
  register.
- `/Od` builds compile many template instantiations to the same bytes, so
  more of their names are wrong. Telling them apart needs the names a
  routine references, which the line format supports and NeverD does not
  read yet.
- x86 coverage is bounded by NeverD's function discovery. On the VS 2026
  x86 `/MT` program, `--no-debug` finds 344 of its 1,021 library functions;
  462 of the others follow a `ret` directly, with no padding between them.
- ARM64 needs a NeverD that takes every primary `.pdata` entry as a
  function (`fix(loader): make every primary ARM and ARM64 pdata entry a
  function`). Before it, VS 2017 and 2019 ARM64 programs had almost no
  functions to name.
- On programs built with Visual Studio 2015 and later, the imported
  `vs2005`–`vs2013` files add no correct names: with them loaded, 387 more
  names are wrong (82 of them in optimized builds) and 118 fewer are right.
  They are kept for programs built with those older toolsets, which the
  validation programs do not cover.

## Lines imported from rizin

The first commit of this repository imported pattern files from rizin's
[sigdb-source](https://github.com/rizinorg/sigdb-source) (LGPL-3.0): the PE
`vs2005`–`vs2022`, `winsdk`, `masm32` and `mingw32-zlib` files, and every ELF
file. Those lines followed rizin's conventions, not the rules above:

- Names were rewritten. Characters outside `[A-Za-z0-9_.]` became `_`, and PE
  names were cut at 125 characters. ELF C++ names were demangled, and some
  were turned into `method.<class>.<member>`.
- Some lines were named after sections, labels or data objects
  (`.text_tii_131`, `_LN116`, `obj.once.9977`).
- Many tails were stated from the end of the leading bytes, with the CRC span
  written as wildcards. NeverD compares a tail from the end of the CRC span,
  so such a line was checked `crclen` bytes out of place and hardly ever
  matched.
- Many lines stated bytes that other routines share under other names. In the
  ELF files, which the same packages explain, 18,780 lines did.

The PE files for Visual Studio 2015 to 2022 and the Windows SDK are now
rebuilt from collected libraries, so they hold no imported line. The imported
lines had been merged into them at first, and caused 3,100 of the 3,900 wrong
names on the x86 and x64 validation programs of Visual Studio 2017, 2022 and
2026.

[`scripts/migrate_imported_signatures.py`](scripts/migrate_imported_signatures.py)
moves the remaining imported files to the rules above. It starts from the
text of the import commit every time, and compares each line with every
function of the libraries it can read: the collected MSVC and SDK libraries
for `pe/`, and for `elf/` the packages rizin recorded in sigdb-source, which
[`scripts/fetch_imported_sources.py`](scripts/fetch_imported_sources.py)
downloads and checks against rizin's SHA-1s. For each line:

1. A tail stated from the end of the leading bytes is moved to start after
   the CRC span. A line that then states fewer than 16 bytes is removed.
2. A line whose bytes do not identify one routine is removed: they agree in
   full with library functions of several names, they open a longer
   function of another name, or they are a function's other than the one
   the imported name spells.
3. A line whose bytes agree with a library function of exactly one name
   takes that name, when the imported name is its rizin spelling or names
   nothing (a section or a label).
4. Failing that, a line takes the one library name that rizin's conversion
   spells the same way.
5. A line named after a section, label or data object, which no library
   function explained, is removed.
6. An ELF line of the other pointer width's code moves to that directory.
7. Any other line is left unchanged, with its imported name.

[`reports/`](reports) lists, per file, every removed and unresolved name.
