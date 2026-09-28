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
  the ARM64 `B`/`BL` or Thumb-2 `B.W`/`BL`/`BLX` instruction. An ARM-state
  `B`/`BL`/`BLX` is stated one byte past its instruction, at an odd offset
  that no Thumb-2 instruction has, so the offset says which instruction set
  the branch is in. The name is the symbol the object's relocation names: an
  undefined symbol, or a function the object defines; a call a linker may
  rewrite, such as `__tls_get_addr` in a TLS sequence it relaxes, is not
  stated.
- Several `^<offset>` with one offset name the routines that one branch may
  reach, any of which confirms it: a symbol and the alternate name an
  `/alternatename` directive of the library gives it, which a COFF link
  resolves the symbol to where no object defines it (the x86 CRT's
  `__except_handler4` calls `__filter_x86_sse2_floating_point_exception`, and
  a program without the SSE2 filter reaches
  `__filter_x86_sse2_floating_point_exception_default`), or the routines that
  builds of the same bytes call there (the release CRT's `free` where the
  debug CRT calls `_free_dbg`).
- NeverD follows each branch in the image. A match whose branch reaches a
  routine NeverD names as none of the routines the branch may reach, or in
  an ELF image the PLT stub of another import, is dropped; one whose
  branches all reach routines they name is confirmed. What the matches then
  name is what their callers' branches are checked against in turn, until
  nothing new is named. A branch to a routine that only jumps on -- a
  linker's thunk, or a routine that tail-calls another, such as the release
  CRT's `free`, which jumps to `_free_base` -- is followed on, and what it
  reaches confirms the reference but contradicts nothing.
- NeverD releases older than these references reject such lines. One before
  NeverSight/NeverD#208 reads an odd offset as a Thumb-2 branch, and one
  before NeverSight/NeverD#214 reads the references at one offset as
  separate branches, each of which the others contradict.

These rules are NeverD's own:
[`neverd-sigmaker`](https://github.com/NeverSight/NeverD/tree/4428327d9344f12f84123206a05b87c328fccb6a/tools/neverd-sigmaker)
produces the lines, and `neverd::sigs::PatternGenerator` defines how many
bytes each relocation rewrites.

A name is the linkage name the library's symbol table spells, byte for byte:
`?Close@CFile@@UEAAXXZ`, `_ZNSt6thread4joinEv`, x86 `_memcpy`. Names are never
demangled, sanitized, prefixed or truncated.

A line is kept only if its bytes identify one routine. Lines that state the
same bytes under names they share are one routine's, under the symbols each
build of the library defines, and become one line with all of their names.
When lines state the same bytes under names with nothing in common, all of
them are dropped, because any one name would be a guess, unless the file's
lines name different routines at a branch they all make: then the one whose
branch NeverD confirms is taken. NeverD may apply every file of a directory
together, so this holds across the directory. A line is also dropped when a
routine of another name, at least as long, states every byte the line
states: NeverD compares a line only as far as the line's own length and
accepts any byte where the line has a wildcard, so the line would name that
routine too.

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
   - One Ubuntu job per row of
     [`.github/elf-matrix.json`](.github/elf-matrix.json) collects the static
     libraries of an ELF file's packages; see
     [Linux and Android (elf/) signatures](#linux-and-android-elf-signatures).
2. [`msvc-signatures.yml`](.github/workflows/msvc-signatures.yml) builds
   `neverd-sigmaker` at a pinned NeverD revision and runs NeverD's
   [`build_msvc_signatures.py`](https://github.com/NeverSight/NeverD/blob/4428327d9344f12f84123206a05b87c328fccb6a/scripts/signatures/build_msvc_signatures.py)
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

## Linux and Android (elf/) signatures

| File | Built from |
| --- | --- |
| `ubuntu-libc6.pat` | glibc 2.3.2 to 2.36: `libc.a`, `libpthread.a`, `librt.a`, `libanl.a`, `libutil.a` and `libresolv.a` of 338 `libc6-dev` packages (x64) |
| `ubuntu-libgcc-7.pat` to `ubuntu-libgcc-12.pat` | GCC 7 to 12's `libgcc.a` and `libgcc_eh.a` (x64) |
| `ubuntu-libstdc++-5.pat` to `ubuntu-libstdc++-12.pat` | GCC 5 to 12's `libstdc++.a`, `libsupc++.a` and `libstdc++fs.a` (x64) |
| `ubuntu-libc++-7.pat` to `ubuntu-libc++-15.pat` | LLVM 7 to 15's `libc++.a` and `libc++fs.a` (x64) |
| `ubuntu-musl.pat` | musl 0.9.14 to 1.2.3's `libc.a` (x64) |
| `ubuntu-openssl.pat` | OpenSSL 0.9.7 to 3.0.5's `libcrypto.a` and `libssl.a` (x64) |
| `ubuntu-zlib.pat` | zlib 1.2.1 to 1.2.13's `libz.a` (x64) |
| `ubuntu-libsodium.pat` | libsodium 1.0.0 to 1.0.18's `libsodium.a` (x64) |
| `ubuntu-libseccomp.pat` | libseccomp up to 2.5.4's `libseccomp.a` (x64) |
| `android-ndk.pat` | The Android NDK r9d to r25b: bionic for every API level, the C++ runtimes (libc++, GNU libstdc++, STLport, gabi++) and the toolchains' Android runtimes (libgcc, compiler-rt, libunwind, libatomic, OpenMP), but none of the libraries its toolchains run on the host (x86, x64, ARM32, ARM64) |
| `fedora-zlib.pat` | zlib 1.3 compiled without optimization by Fedora 38's GCC 13.2.1 and clang 16.0.6 (x86, x64) |

Every file but `fedora-zlib.pat` is built from the packages rizin's
sigdb-source records for it: each `ubuntu-*` file from its library's `-dev`
package in every Ubuntu release from 4.10 to 22.10 that carried one, and
`android-ndk.pat` from the NDK releases. One Ubuntu job per row of
[`.github/elf-matrix.json`](.github/elf-matrix.json)
([`scripts/collect_elf_packages.py`](scripts/collect_elf_packages.py))
downloads them, Ubuntu's packages from Launchpad and the NDK from Google,
checks each against the SHA-1 sigdb-source records, and archives the static
libraries it holds by their objects' ELF class and machine, in
`msvc-libs-*` releases like the Windows libraries. A library whose bytes
another package already supplied is stored once; the manifest still lists
the package.

`fedora-zlib.pat` has no package behind it: rizin's lines came from
[signature-builds-zlib](https://github.com/feliwir/signature-builds-zlib),
which configured zlib 1.3 with CMake and no build type and compiled it with
a Fedora machine's `gcc` and `clang`. One job per row of
[`.github/fedora-matrix.json`](.github/fedora-matrix.json)
([`scripts/collect_fedora_library.py`](scripts/collect_fedora_library.py))
builds it the same way with the compilers Fedora 38 had when the lines were
made, unpacked from the packages Koji keeps and checked against their
SHA-256. Of rizin's 561 lines, that build reproduces 538, and 15 state bytes
that several of its routines share. The other 8 state a relocated field, or
a CRC over one, as rizin read it with the object's relocations applied at its
own load address (`0x08000000`), which no program's bytes match.

An ELF image has no Rich header to name the release of its libraries, so
`neverd sigs --auto` reads every file of its `elf/` directory, and ambiguous
lines are dropped across the whole directory, as described above. The ELF
lines state their branches as the Windows ones do since NeverSight/NeverD#208,
so lines that differ only in the routines they call are kept and told apart:
r25b's ARM32 `ctype_byname<wchar_t>::do_toupper` and `do_tolower` are the same
bytes calling `towupper` and `towlower`, and NeverD takes the one whose call
reaches the routine it names: the routine NeverD names there, or in a
dynamically linked program the import whose PLT stub it is.

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
Measured with NeverD at
[4428327d](https://github.com/NeverSight/NeverD/commit/4428327d9344f12f84123206a05b87c328fccb6a).

| Architecture | Programs | Named, optimized | Named, `/Od` | Wrong, optimized | Wrong, `/Od` | Disputed |
| --- | --- | --- | --- | --- | --- | --- |
| x86 | 18 | 54% | 57% | <0.1% | 1.8% | 3,322 |
| x64 | 18 | 62% | 59% | <0.1% | 2.0% | 2,709 |
| ARM32 | 9 | 60% | 61% | <0.1% | 1.3% | 1,453 |
| ARM64 | 15 | 65% | 66% | <0.1% | 1.5% | 2,330 |

Across all 60 programs NeverD names 170,024 of 284,642 library functions
(60%), 550 names are wrong (0.3%), and 9,814 addresses are disputed. A
disputed address is one where lines that differ only in their branches all
match and none of the branches settles which: NeverD leaves it unnamed. At
71 other such addresses a confirmed branch settles it, and 70 of those
names are right. Counting these needs a NeverD that reports each match's
`confirmed` flag (NeverSight/NeverD#164); with an older one the script
counts them as disputed. Since NeverSight/NeverD#208 what the branches settle
is what the branches of the routines' callers are checked against in turn,
which names 1,431 more of these programs' library functions. Since
NeverSight/NeverD#212 a routine that only jumps on no longer contradicts
the matches that call it: 2,605 more, which the references had dropped
because `operator delete` jumps to `free` and `malloc` to `_malloc_base`.
The alternatives of NeverSight/NeverD#214 name 489 more. None of the three
names more wrongly.
Before the Rich header chose the files, before the covering rule and the
branch references, and before the Visual Studio 2005 to 2013 files were
rebuilt from their libraries, it named 133,078 (47%) and 2,678 names were
wrong (2.0%).

- Optimized builds (`/O2`, `/MT`, with or without MFC) are the common case,
  and 53 of their names are wrong. On ARM these are mostly short routines
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
  the functions MSVC packs directly after a `ret`. Since NeverSight/NeverD#204
  signatures are also tried at every function NeverD's detector finds, not
  only at those the image's tables state; the optimized x86 programs went
  from 28% named to 54%.
- The Visual Studio 2005 to 2013 files have no validation programs with
  maps, but the setup programs on their media are linked statically with
  their release's runtime, and the Rich header chooses the file of the
  linker's release (VS 2005, VS 2008, and VS 2010 SP1 for the VS 2012 and
  2013 installers). Microsoft's symbol server keeps the public PDBs of some
  of them, which [`scripts/pdb_truth.py`](scripts/pdb_truth.py) turns into
  what `evaluate_probes.py` compares with. A public PDB names only public
  symbols, so a name at a static function cannot be checked either way.
  - VS 2008's setup program: NeverD names 300 of the 492 functions the PDB
    names that the release's libraries define. Of its other names, 43 are at
    static functions, 2 differ from the PDB only in decoration (an ATL
    header function the program compiled itself with `/Gz` or
    `/Zc:wchar_t-`), and 1 is wrong: MFC's `COccManager::OnEvent` at the
    program's own callback of the same bytes.
  - VS 2010's: 277 of 429. 37 are at static functions, 15 differ only in
    decoration, 5 name the MFC instantiation of an ATL `CStringT` member
    whose code is the same, and 2 are wrong.
  - VS 2005's: 298 of 480. 42 are at static functions, 2 differ only in
    decoration, and none is wrong. Its linker placed read-only data in the
    code section, where NeverD's function discovery alone finds 85 of the
    program's 747 functions; since NeverSight/NeverD#204 signatures are also
    tried at the functions NeverD's detector finds there.
  - The symbol server has no PDB for the VS 2012 and 2013 setup programs.

### ELF programs

`validation/elf/` holds C and C++ programs linked statically against the
very packages the ELF files were made from, as
[`scripts/build_elf_probes.py`](scripts/build_elf_probes.py) builds them, and
Android programs built with NDK r25b's own clang. Each is compared with the
symbol table of the same program before it was stripped: a function is a
library's when one of the archives the program was linked with defines one of
its names. For an ELF image NeverD reads every file of the directory. Before
is what the lines imported from rizin, moved to the rules above, named in the
same programs, as measured with NeverD at
[b08a55bb](https://github.com/NeverSight/NeverD/commit/b08a55bbc8b804f5308721451b6b31d25fe32444)
(ARM) and
[278e2f2e](https://github.com/NeverSight/NeverD/commit/278e2f2e98af90ed358e25fcffbc84d82d787cd4)
(the others). The files as they are now were measured with NeverD at
[4428327d](https://github.com/NeverSight/NeverD/commit/4428327d9344f12f84123206a05b87c328fccb6a).

| Programs | Count | Library functions | Named before | Named | Wrong before | Wrong | Disputed before | Disputed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| glibc 2.27, 2.31, 2.35, `-O2` and `-O0` | 6 | 6,265 | 3,206 (51%) | 4,974 (79%) | 117 | 14 | 79 | 0 |
| GNU libstdc++ 11, 12 | 2 | 9,509 | 2,915 (31%) | 4,454 (47%) | 176 | 5 | 54 | 618 |
| zlib 1.2.11 | 1 | 1,182 | 653 (55%) | 968 (82%) | 25 | 0 | 14 | 0 |
| OpenSSL 3.0 | 1 | 10,726 | 5,278 (49%) | 6,862 (64%) | 1,510 | 2 | 287 | 479 |
| musl 1.2.2 | 1 | 160 | 0 | 94 (59%) | 0 | 0 | 0 | 0 |
| NDK r25b x64 | 1 | 1,850 | 767 (41%) | 1,291 (70%) | 16 | 2 | 14 | 13 |
| NDK r25b x86 | 1 | 1,942 | 177 (9%) | 1,482 (76%) | 10 | 0 | 0 | 17 |
| NDK r25b ARM64, C and C++ | 2 | 5,794 | 465 (8%) | 3,854 (67%) | 4 | 0 | 0 | 90 |
| NDK r25b ARM32, C | 1 | 1,907 | 116 (6%) | 1,255 (66%) | 4 | 0 | 0 | 13 |
| NDK r25b ARM32, C++ | 1 | 4,117 | -- | 2,233 (54%) | -- | 1 | -- | 104 |

- Most of the names wrong before were OpenSSL's: its `d2i_*`, `i2d_*`,
  `*_free` and per-cipher routines are the same code up to the object a
  relocation names, and rizin's lines named one of them. The rebuilt file
  drops such lines, as described above; of the 1,510 addresses named wrong
  before, 2 still are.
- bionic's AArch64 assembly syscall stubs begin with a `bti c` landing pad
  and open their unwind entry after it. NeverD before NeverSight/NeverD#191
  started each such function at its second instruction, where the stub of
  an older NDK without the landing pad matches: 365 of its 373 wrong names on
  these programs were the right names 4 bytes late.
- musl builds its library without unwind tables, and NeverD's function
  discovery does not follow the calls from the entry point: it finds 2 of the
  program's 167 functions. Since NeverSight/NeverD#204 signatures are also
  tried at every function NeverD's detector finds, which names 94.
- NeverD decodes the bytes after every call of a stripped ARM32 program as
  code. After a call that does not return, such as `bl abort`, they are the
  caller's literal pool, which NeverD recognizes by the load that reads it.
  The ARM32 C++ program also needs to know which calls do not return: an ARM
  `__memcpy_chk` ends in one and Thumb `wcslen` follows at once. NeverD infers
  that since NeverSight/NeverD#203, and loads it; the rizin lines were never
  measured on it.
- The disputed addresses are routines whose lines the files keep because
  their branches tell them apart, where this program's branches cannot: C++
  `char` and `wchar_t` instantiations whose whole call chains are the same
  bytes (`basic_istream<char>` and `<wchar_t>`'s constructors call
  `basic_ios<char>::init` and `<wchar_t>::init`, which call the same
  routine), and OpenSSL's `d2i_*`, `i2d_*` and `*_free` wrappers, which call
  `*_it` routines that differ only in the data they point to. Before, the
  files dropped these lines, and NeverD named nothing there either.

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
libraries, as are `masm32.pat` and `mingw32-zlib.pat`, and every ELF file:
from the packages sigdb-source records, and `fedora-zlib.pat` from the
compilers its lines were made with.

[`scripts/migrate_imported_signatures.py`](scripts/migrate_imported_signatures.py)
moves what remains to the rules above. It starts from the text of the import
commit every time, and compares each line with every function of the
libraries it can read: the collected MSVC and SDK libraries for `pe/`, and
the collected ELF libraries for `elf/`. For each line:

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
7. rizin filed some ELF lines under the other pointer width: 32-bit code
   among the 64-bit NDK lines, and some 64-bit code among the ARM32 ones. A
   line whose bytes this width's libraries do not state, but a function of
   the other width's libraries does, is that width's. So is one whose name
   only the other width's libraries define, when both widths' files are
   built from the very build the import was made from: rizin read some
   objects with their relocations applied, so their bytes match no
   function. When that width's file is built anew from that build, the line
   is left out, as that file holds the routine; otherwise it moves to that
   directory.
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
   (`reproduces_import`): the ELF packages rizin recorded are, and so is
   `fedora-zlib` built with the Fedora compilers rizin's lines were made
   with, but `mingw32-zlib` compiled with Ubuntu's MinGW-w64 GCC is not
   rizin's build, so only the `mingw32-zlib` lines it reproduces are left
   out.
9. A line with no linkage name is kept as a `; unresolved:` comment, which
   NeverD does not read.

The migration reads a file's imported lines for as long as its libraries
leave any of them. In `pe/` those are 233,561 lines of the Visual Studio 2005
to 2013 files and `mingw32-zlib.pat`: the libraries of every other PE file
reproduce or supersede all of its imported lines -- the MASM32 SDK's
libraries, built from its sources, every `masm32` line, and the Visual Studio
2010 disc's libraries every x64 `vs2010` line. Of those 233,561 lines, 64 are
left unresolved: C++/CLI catch funclets and labels whose rizin names are not
linkage names, and VS 2005 lines from test-harness objects on no collected
library. Of the 215,550 lines imported into `elf/`, 143,942 are reproduced
and 38,557 superseded by the collected packages, 1,893 are the other pointer
width's code, and 31,136 are removed (ambiguous, opening a longer routine, or
naming no function). 16 are left unresolved, rizin's spellings of ARM32
libc++ templates that no linkage name spells the same way, and 6 are kept:
two libc++abi routines in each of `ubuntu-libc++-12.pat` to
`ubuntu-libc++-14.pat`, which rizin named but no package it recorded defines.
[`reports/`](reports) lists, per file the migration reads, every removed and
unresolved name.
