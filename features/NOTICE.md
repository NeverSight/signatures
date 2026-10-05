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
