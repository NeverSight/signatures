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
`neverd sigs --auto` to apply the set that matches the loaded binary. It reads
the `.pat` files of the matching directory and ignores other files, such as the
`<name>.sources.json` provenance records and `<name>.imported` inputs that sit
next to generated files. For a PE image whose Rich header names the Visual
Studio release of its linker, it reads only that release's `vs<year>.pat` and
the files that belong to no release (`winsdk.pat`, `masm32.pat`,
`mingw32-zlib.pat`). A static runtime library comes from the linker's own
release, and older releases state some of the same bytes under other names.
Without a usable Rich header it reads every file of the directory.

A file larger than 50 MB, GitHub's recommended limit, is written in parts of
even size: `<name>.pat`, `<name>.part2.pat` and so on. NeverD reads the parts
as one library, and the Rich header chooses a release's parts together.

## What a line says

```
<leading bytes> <crc length> <crc16> <function length> :0000 <name> [^<offset> <name>]... [<tail bytes>]
```

Each line states the bytes of one library function and gives it its names at
offset 0: one, or every symbol an ELF library gives the routine (glibc's
`puts` is also `_IO_puts`), of which NeverD shows the one with the fewest
leading underscores, then the shortest:

- The leading bytes are the first 32 bytes of the function, or all of it
  when it is shorter.
- The CRC16 covers the bytes after them, up to the first byte a relocation
  rewrites.
- The tail states the bytes after the CRC span, starting where the CRC span
  ends.
- Bytes that a relocation rewrites are `..` wildcards, and so are the bytes an
  ELF linker may rewrite around one: the opcode of a GOT load it relaxes to a
  `lea` or a direct call, or a whole TLS access sequence in a static link.
- A line states at least 16 bytes exactly. A shorter claim matches far more
  code than the function it came from.
- Each `^<offset> <name>` names a routine the function branches to directly:
  at `<offset>` starts the rel32 field of an x86 or x64 `call` or `jmp`, or
  the ARM64 `B`/`BL` or Thumb-2 `B.W`/`BL`/`BLX` instruction. NeverD follows
  the branch in the image. A match whose branch reaches a routine NeverD
  names otherwise is dropped; one whose branches all reach the routines they
  name is confirmed. NeverD releases older than these references reject such
  lines.

These rules are NeverD's own:
[`neverd-sigmaker`](https://github.com/NeverSight/NeverD/tree/278e2f2e98af90ed358e25fcffbc84d82d787cd4/tools/neverd-sigmaker)
produces the lines, and `neverd::sigs::PatternGenerator` defines how many
bytes each relocation rewrites.

A name is the linkage name the library's symbol table spells, byte for byte:
`?Close@CFile@@UEAAXXZ`, `_ZNSt6thread4joinEv`, x86 `_memcpy`. Names are never
demangled, sanitized, prefixed or truncated.

A line is kept only if its bytes identify one routine. Lines that state the
same bytes under names they share are one routine's, under the symbols each
build of the library defines, and become one line with all of their names.
When lines state the same bytes under names with nothing in common, all of
them are dropped, because any one name would be a guess, unless the file's lines name different routines at a
branch they all make: then the one whose branch NeverD confirms is taken. NeverD may apply every file of a directory together, so
this holds across the directory. A line is also dropped when a routine of
another name, at least as long, states every byte the line states: NeverD
compares a line only as far as the line's own length and accepts any byte
where the line has a wildcard, so the line would name that routine too.

## Windows (pe/) signatures

| File | Built from |
| --- | --- |
| `vs2015.pat` | MSVC v140 (14.0): x86 and x64 with ATL/MFC, ARM32 without |
| `vs2017.pat` | MSVC v141 14.16 with ATL/MFC (x86, x64, ARM32, ARM64) |
| `vs2019.pat` | MSVC v142 14.29 with ATL/MFC (x86, x64, ARM32, ARM64) |
| `vs2022.pat` | MSVC v143 14.44 with ATL/MFC (x86, x64, ARM32, ARM64) |
| `vs2026.pat` | MSVC 14.50 and 14.51 with ATL/MFC (x86, x64, ARM64; VS 2026 has no ARM32 toolchain) |
| `winsdk.pat` | Windows SDK 10.0.17763, 18362, 19041, 20348, 22000, 22621 and 26100: the Universal CRT and the user-mode libraries (ARM32 through 10.0.22621) |
| `vs2005.pat` | Visual Studio 2005 Team Suite (8.0.50727.42) with ATL/MFC, the Platform SDK, the Windows CE x86 libraries and the DIA SDK (x86, x64) |
| `vs2008.pat` | Visual Studio 2008 Professional (9.0.21022) with ATL/MFC, the Windows SDK 6.0A, the Windows CE x86 libraries, the CRT libraries built from source and the DIA SDK (x86, x64) |
| `vs2010.pat` | Visual Studio 2010 Professional (10.0.30319) with ATL/MFC, the Windows SDK 7.0A and the DIA SDK (x86, x64) |
| `vs2012.pat` | Visual Studio 2012 Professional (11.0.50727) with ATL/MFC (x86, x64, ARM32) |
| `vs2013.pat` | Visual Studio 2013 Professional (12.0.21005) with ATL/MFC and the Windows SDK 7.1A (x86, x64, ARM32) |
| `masm32.pat` | The MASM32 SDK 8.2, 9, 10 and 11: `masm32.lib`, `fpu.lib` and `datetime.lib` built from their sources with the SDK's own assembler, and the prebuilt `debug.lib` (x86) |
| `mingw32-zlib.pat` | zlib 1.3 compiled without optimization, as the code of rizin's `mingw32-zlib` lines reads, by Ubuntu's MinGW-w64 GCC (x86, x64) |

The Visual Studio 2005 to 2013 libraries come from Microsoft's installation
media, which no current Windows image can install; they are unpacked on
Ubuntu instead (see below). They are the release-to-manufacturing builds of
the same media rizin's files were made from. Microsoft no longer publishes a
Visual Studio 2010 disc; its libraries come from the Internet Archive's copy
of the MSDN Professional disc, `en_visual_studio_2010_professional_x86_dvd_509727.iso`,
whose SHA-1 `f0ed50712d83bf0eda7d284da76df49e4c88cef7` is the one MSDN listed
for it and the one rizin's sigdb-source records. (The Windows SDK 7.1, which
Microsoft does publish, carries the same Visual C++ 2010 CRT libraries byte
for byte, but no ATL/MFC.) A file whose libraries do not reproduce every
line rizin had for it keeps the rest, renamed to their linkage names, in
`<name>.imported`, which joins the file when it is built. See
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
   - One Ubuntu job per row of
     [`.github/msvc-legacy-matrix.json`](.github/msvc-legacy-matrix.json)
     downloads an older release's installation medium from Microsoft (for
     Visual Studio 2010, the Internet Archive's copy of the MSDN disc), checks
     its SHA-256, unpacks the Windows Installer packages that hold the
     libraries with 7-Zip, cabextract and msitools, and packs the same kind
     of archive ([`scripts/collect_legacy_media.py`](scripts/collect_legacy_media.py)).
   - One Ubuntu job per row of
     [`.github/masm32-matrix.json`](.github/masm32-matrix.json) builds a
     MASM32 SDK release's libraries. The SDK ships them as sources, which
     its installer assembles with the SDK's own `ML.EXE` and `LINK.EXE`;
     the job runs the same make files under Wine and clears the time
     stamps `LINK` writes, so two builds give the same archive
     ([`scripts/collect_masm32.py`](scripts/collect_masm32.py)).
   - One Ubuntu job per row of
     [`.github/mingw-matrix.json`](.github/mingw-matrix.json) compiles a C
     library rizin built with MinGW itself, from its release archive, with
     Ubuntu's MinGW-w64 cross compilers, and archives it in ar's
     deterministic mode, recording the compiler and header packages
     ([`scripts/collect_mingw_library.py`](scripts/collect_mingw_library.py)).
2. [`msvc-signatures.yml`](.github/workflows/msvc-signatures.yml) builds
   `neverd-sigmaker` at a pinned NeverD revision and runs NeverD's
   [`build_msvc_signatures.py`](https://github.com/NeverSight/NeverD/blob/278e2f2e98af90ed358e25fcffbc84d82d787cd4/scripts/signatures/build_msvc_signatures.py)
   over every `msvc-libs-*` release, one architecture at a time:
   - A file with library archives behind it is rebuilt from them alone, and
     from its `<name>.imported` when it has one.
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
- **disputed**: addresses where the loaded lines disagree and no branch
  reference settles which is right, so NeverD names nothing. An address
  where exactly one of the names comes from a match whose references NeverD
  confirmed gets that name, and counts as named or wrong like any other.

`validation/` holds three programs, each linked statically with a map: an
MFC program and a CRT program built with `/O2 /MT`, and the CRT program built
with `/Od /MTd`. They were built with Visual Studio 2015 (x86, x64), 2017, 2019
and 2022 (x86, x64, ARM32, ARM64), and 2026 with both its default toolset and
14.50 (x86, x64, ARM64): 60 programs. NeverD chooses the files as
`neverd sigs --auto` does, by the program's Rich header. Named is the share of
the map's library functions; wrong is the share of the names NeverD applies.

| Architecture | Programs | Named, optimized | Named, `/Od` | Wrong, optimized | Wrong, `/Od` | Disputed |
| --- | --- | --- | --- | --- | --- | --- |
| x86 | 18 | 28% | 53% | <0.1% | 1.8% | 2,862 |
| x64 | 18 | 59% | 56% | <0.1% | 2.1% | 3,211 |
| ARM32 | 9 | 59% | 59% | 0.1% | 1.3% | 1,626 |
| ARM64 | 15 | 58% | 63% | 0.1% | 1.5% | 2,585 |

Across all 60 programs NeverD names 141,605 of 284,642 library functions
(50%), 535 names are wrong (0.4%), and 10,284 addresses are disputed. A
disputed address is one where lines that differ only in their branches all
match and none of the branches settles which: NeverD leaves it unnamed. At
289 other such addresses a confirmed branch settles it, and 284 of those
names are right. Counting these needs a NeverD that reports each match's
`confirmed` flag (NeverSight/NeverD#164); with an older one the script
counts them as disputed.
Before the Rich header chose the files, before the covering rule and the
branch references, and before the Visual Studio 2005 to 2013 files were
rebuilt from their libraries, it named 133,078 (47%) and 2,678 names were
wrong (2.0%).

- Optimized builds (`/O2`, `/MT`, with or without MFC) are the common case,
  and 52 of their names are wrong. On ARM these are mostly short routines
  that share their code with other routines except for what a relocation
  rewrites, such as MFC initializers that differ only in the message they
  register.
- `/Od` builds compile many template instantiations to the same bytes, so
  more of their names are wrong: the program's own instantiations take the
  names of the library's. The branch references drop such a name when the
  instantiation calls a routine NeverD names otherwise, which it cannot do
  when the routines it calls are the program's own and unnamed.
- Rebuilding `vs2010.pat` from the Visual Studio 2010 disc, with ATL/MFC,
  cost these programs 30 names and made 5 wrong. Releases give some short
  routines' bytes different names -- ATL's `T2BSTR` and the Universal CRT's
  `_wcslen` are the same code up to the routine they call -- so every file
  of the directory drops them, as described above. With the debug CRT's
  `_wcslen` unnamed, the `/Od` programs' `tcslen` wrappers match
  `_aligned_free`'s line, and its reference has no name to contradict.
- x86 coverage is bounded by NeverD's function discovery, which since
  `Find packed MSVC hotpatch entries and start them at the no-op` also finds
  the functions MSVC packs directly after a `ret`. Most of the x86 library
  functions still unnamed are ones it does not find.
- The Visual Studio 2005 to 2013 files have no validation programs with
  maps. On the setup programs of their media, the Rich header chooses the
  file of the linker's release (VS 2005, VS 2008, and VS 2010 SP1 for the VS
  2012 and 2013 installers), and none of their names is disputed.

## Lines imported from rizin

The first commit of this repository imported pattern files from rizin's
[sigdb-source](https://github.com/rizinorg/sigdb-source) (LGPL-3.0): the PE
`vs2005`–`vs2022`, `winsdk`, `masm32` and `mingw32-zlib` files, and every ELF
file. Those lines followed rizin's conventions, not the rules above:

- Names were rewritten. Characters outside `[A-Za-z0-9_.]` became `_`, and PE
  names were cut at 125 characters: `?AfxRegisterClass@@YAHPAUtagWNDCLASSW@@@Z`
  became `_AfxRegisterClass__YAHPAUtagWNDCLASSW___Z`, and the stdcall
  `_TimeSpan@24` became `_TimeSpan_24`. ELF C++ names were demangled, and some
  were turned into `method.<class>.<member>`. None of this can be undone from
  the text alone: `_` stands for any of `_`, `?`, `@` and `$`.
- Some lines were named after sections, labels or data objects
  (`.text_tii_131`, `_LN116`, `obj.once.9977`).
- Many tails were stated from the end of the leading bytes, with the CRC span
  written as wildcards. NeverD compares a tail from the end of the CRC span,
  so such a line was checked `crclen` bytes out of place and hardly ever
  matched.
- Many lines stated bytes that other routines share under other names. In the
  ELF files, which the same packages explain, 18,780 lines did.

sigdb-source records where each line came from: the SHA-1 of the medium or
package, and a pattern file per library object. For Visual Studio 2005 to
2013 those were the MSDN Professional discs. Their libraries are the
release-to-manufacturing builds on the media Microsoft still publishes, and
for Visual Studio 2010 the very disc sigdb-source names, so the PE files for
Visual Studio 2005 to 2022 and the Windows SDK are now built from collected
libraries, as are `masm32.pat` and `mingw32-zlib.pat`.

[`scripts/migrate_imported_signatures.py`](scripts/migrate_imported_signatures.py)
moves what remains to the rules above. It starts from the text of the import
commit every time, and compares each line with every function of the
libraries it can read: the collected MSVC and SDK libraries for `pe/`, and for
`elf/` the packages rizin recorded in sigdb-source, which
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
   spells the same way. The names include every routine a library's symbol
   table defines, also those `neverd-sigmaker` writes no line for.
5. A PE C name is kept as it is: every decorated C++ name holds `@@`, which
   rizin spelled `__`, so a name with no `__` past its leading underscores
   was never rewritten. On 32-bit x86, `_name_N` is also how rizin spelled
   the stdcall `_name@N`; it becomes that only when the routine ends in
   `ret N`.
6. A line named after a section, label or data object, which no library
   function explained, is removed.
7. An ELF line of the other pointer width's code moves to that directory.
8. In a file whose libraries were collected, a line those libraries
   reproduce is left out, and the rest go to `<name>.imported`. A line is
   reproduced when a collected function of its name states every byte the
   line states, also when the function runs on past the line's end only into
   the NOPs or INT3s that pad its section: rizin measured a function to its
   last instruction, `neverd-sigmaker` to the next symbol. When the
   collected libraries are the very build the import was made from (a Visual
   Studio release's RTM libraries, the MASM32 SDK's libraries built from its
   sources with its own assembler), a line whose routine they define at all is
   left out too: the line `neverd-sigmaker` made for that routine, or its
   decision to make none, stands. A library asset states which it is
   (`reproduces_import`): zlib compiled here is not rizin's build, so only
   the `mingw32-zlib` lines it reproduces are left out.
9. A line with no linkage name is kept as a `; unresolved:` comment, which
   NeverD does not read.

Of the 265,631 imported PE lines, 64 are left unresolved: C++/CLI catch
funclets and labels whose rizin names are not linkage names, and VS 2005
lines from test-harness objects on no collected library. The MASM32 SDK's
libraries, built from its sources, reproduce or supersede every imported
`masm32` line, and the Visual Studio 2010 disc's libraries every x64 `vs2010`
line, so those files keep none. In `elf/`, 374 lines are left unresolved,
where the packages rizin recorded are gone or two routines spell the same.
[`reports/`](reports) lists, per file, every removed and unresolved name.
