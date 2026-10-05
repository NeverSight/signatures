# Library feature coverage

Data production and recognition in NeverD are separate gates. A rule appearing
here does not establish that the runtime consumer or display tests have passed.

| Implementation/profile | Operations | Source and probe evidence | NeverD consumer |
| --- | --- | --- | --- |
| libc++ source `cc7be19969b7dc6c309e67619630ccc90ef46d9f`, Clang 22.1.6, arm64 macOS, ABI 1 alternate string layout, no hardening, C++17, O2 | `basic_string<char/wchar_t>` and `vector<uint32_t/uint64_t>`: size, empty, data, capacity (16 rules) | Produced; optimized standalone methods and inline callers; a second build has identical object, assembly and LLVM IR hashes | Pending |
| MSVC STL x64 | Same string/vector accessors | Producer submitted; actual toolset evidence pending | Pending |
| Shared ATL/MFC CStringT | Construction, assignment, length, empty, data, GetBuffer, ReleaseBuffer | Producer submitted; actual ATL evidence pending | Pending |
| ATL CComPtr<IUnknown> | Construction, copy, assignment, release, destruction | Producer submitted; actual ATL evidence pending | Pending |
| libc memory/string | memcpy, memmove, memset, memcmp, strlen | Source collection in progress; separate from STL/ATL | Pending |

The libc++ pack requires independent, authoritative receiver identity. The
source profile is not proof of the target binary's exact implementation
version. A user-defined pointer triple or string-shaped object receives no
forced library name. O0 and debug-hardening objects are retained as additional
evidence; the O2 profile does not automatically claim them. `vector<bool>`,
custom allocators, different traits/layouts, other targets and LTO are not
supported by this pack.

Run `python3 scripts/validate_library_features.py` to verify profile digests,
archived compiler artifacts, witness symbols, graph types and mandatory
identity evidence. Runtime matching, overlap/region boundaries, authoritative
names, HighC/LLVMC consistency and reversible folding require the separate
NeverD tests before changing the consumer column.
