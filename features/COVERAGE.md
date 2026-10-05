# Library feature coverage

Data production and recognition in NeverD are separate gates. A rule appearing
here does not establish that the runtime consumer or display tests have passed.

| Implementation/profile | Operations | Source and probe evidence | NeverD consumer |
| --- | --- | --- | --- |
| libc++ source `cc7be19969b7dc6c309e67619630ccc90ef46d9f`, Clang 22.1.6, arm64 macOS, ABI 1 alternate string layout, no hardening, C++17, O2 | `basic_string<char/wchar_t>` and `vector<uint32_t/uint64_t>`: size, empty, data, capacity (16 rules) | Produced; optimized standalone methods and inline callers; a second build has identical object, assembly and LLVM IR hashes | Pending |
| MSVC STL 14.44.35207 / compiler 19.44.35229.0, x64, `/MT`, iterator debug 0, C++17, O2 | Same string/vector accessors (16 rules) | Actual installed headers, optimized standalone methods and inline callers; independent object/assembly rebuilds are identical | Pending |
| Shared ATL/MFC CStringT, same MSVC profile, `StrTraitATL<ChTraitsCRT>` | Narrow/wide construction, copy, assignment (6 gated whole-function byte rules); inherited `CSimpleStringT` length/empty/data (6 expression rules); GetBuffer/ReleaseBuffer (4 gated whole-function byte rules) | Real ATL headers, base layouts and methods, compiler output and NeverD-generated patterns; only accessors claim inline support | Pending |
| ATL CComPtr<IUnknown>, same MSVC profile | Construction, copy, assignment, release, destruction (5 ownership rules); inherited CComPtrBase::Release (1 whole-function ownership rule) | Real ATL compiler bodies and inline callers, explicit call/store order; independent object/assembly rebuilds are identical | Pending |
| musl 1.2.5, x64 ELF, Clang 22.1.6 | memcpy, memmove, memset, memcmp, strlen (5 whole-function byte rules) | Official source archive; existing byte matcher names 5/5 with symbol-provided boundaries and 4/5 in stripped fixture, zero wrong names | Feature consumer pending; stripped memcpy discovery regression retained |

The libc++ pack requires independent, authoritative receiver identity. The
source profile is not proof of the target binary's exact implementation
version. A user-defined pointer triple or string-shaped object receives no
forced library name. O0 and debug-hardening objects are retained as additional
evidence; the O2 profile does not automatically claim them. `vector<bool>`,
custom allocators, different traits/layouts, other targets and LTO are not
supported by this pack.

The musl stripped fixture puts `memcpy` directly after a caller's FDE end.
The measured NeverD build at `cf8cfa408` omits that entry from its signature
candidates, so it is never passed to the byte matcher; the same bytes match
when the ELF symbol provides its boundary. The archive keeps both images,
truth and the measured report. The integration must rerun this case on its
current base; this record is not a five-of-five stripped success claim.

Run `python3 scripts/validate_library_features.py` to verify profile digests,
archived compiler artifacts, witness symbols, graph types and mandatory
identity evidence. Runtime matching, overlap/region boundaries, authoritative
names, HighC/LLVMC consistency and reversible folding require the separate
NeverD tests before changing the consumer column.
