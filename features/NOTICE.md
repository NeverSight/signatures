# Feature data sources

The probe programs and feature production/validation code are authored for
NeverD. Structural rules describe operations observed in the stated library
sources and compiler evidence; they do not supply a replacement library.

The libc++ profile uses LLVM Project sources from
[NeverSight/llvm-project at cc7be19969b7dc6c309e67619630ccc90ef46d9f](https://github.com/NeverSight/llvm-project/tree/cc7be19969b7dc6c309e67619630ccc90ef46d9f/libcxx).
Copyright belongs to the LLVM Project contributors. Sources and their
applicable notices remain under Apache-2.0 with LLVM exceptions; the complete
notice is retained in [libcxx-LICENSE.txt](notices/libcxx-LICENSE.txt).
Compiler objects and assembly in the evidence archive contain instantiations
from that implementation, as well as the original probes.

Apple SDK C/system declarations are inputs to the arm64 macOS build. Their
identities and hashes appear in the evidence manifest; SDK source headers are
not copied into this repository. Clang's version and executable hash and the
SDK settings hash identify the compilation environment independently of the
libc++ source revision.

The MSVC STL and ATL profiles use toolset 14.44.35207, compiler 19.44.35229.0,
and Windows SDK 10.0.26100.0 from a licensed Visual Studio 2022 installation
on the GitHub `windows-2022` runner. These Microsoft components retain their
own copyright and Visual Studio / Windows SDK license terms. The evidence
contains compiler-generated objects, disassembly and layout observations,
original probes, and input-header hashes. It does not redistribute installed
headers, SDK archives or preprocessed translation units. The recorded ATL
string infrastructure is shared with MFC; it does not establish that a target
application uses either framework.

The libc memory/string profile uses the official
[musl 1.2.5 source release](https://musl.libc.org/releases/musl-1.2.5.tar.gz).
The release archive SHA-256 is recorded in its manifest. Its complete
copyright/permission notices are retained in
[musl-COPYRIGHT.txt](notices/musl-COPYRIGHT.txt), including notices for the
individual implementations. Objects and signatures are derived from those
unmodified sources. musl data remains a separate family from C++ libraries.
