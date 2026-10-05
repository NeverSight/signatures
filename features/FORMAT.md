# Library feature format version 1

A feature is a bounded, typed description of a library operation and the
evidence needed to attribute that operation to a library. It grants no call
ABI, library replacement or permission to change lifted code. Pack source
versions describe where a rule came from, not an exact version found in a
target program. Existing `.pat` files remain a separate compatible input.

Profiles under `profiles/` name a library implementation, target ABI, concrete
template instantiations, observed layouts, compiler settings and immutable
source/evidence hashes. Packs under `rules/` refer to a profile by ID and hash.
The producer manifests live in `evidence/`; binary/compiler evidence assets
are retained in deterministic compressed archives and referenced by digest.
The validator checks every archive member against the manifest and requires
each witness symbol to exist in the compiler's retained symbol table.
A consumer rejects unsupported schema versions,
operators, target widths or inconsistent evidence without publishing a match.

The current operator and operation names are finite. Profiles with inherited
methods name the actual declaring type (`CSimpleStringT` or `CComPtrBase`). A
listed derived receiver may prove that base only at its recorded base offset;
it cannot turn the base method into a distinct `CStringT`/`CComPtr` callee.

## Expression rules

Nodes form a topologically ordered DAG. Every node has a unique `id`, an `op`
and a result `bits` in {8, 16, 32, 64}. Comparisons produce an 8-bit value 0 or
1. A constant's unsigned bit pattern must fit its width; it is not an address.
Inputs identify the original receiver or explicit argument. `load` reads
exactly `bits / 8` bytes from its pointer input plus a signed byte `offset`,
with ordinary memory ordering. Ordered/volatile/atomic accesses cannot match
ordinary loads. A `select` is conditional and does not authorize speculative
memory reads or collapsing effects.

Unary operators are `zext` and `sext`. Binary operators are `add`, `sub`,
`mul`, `udiv`, `and`, `or`, `xor`, `shl`, `lshr`, `ashr`, `eq`, `ne`, `ult`,
`ule` and `slt`. `select` has condition, true-value and false-value inputs.
The `result` names the root. Integer operations use the declared bit widths.
Shifts/division require the same definedness as the original operations;
a consumer cannot manufacture a proof from the spelling of a rule.

Rules state `receiver_type`, `layout` and `identity_evidence`. In version 1,
an authoritative receiver type or independently authenticated library call
relationship is required, in addition to the structural match. An operation
with only a similar layout remains a candidate and retains its original name.
An unknown template argument cannot be filled from the profile's defaults.

`scope` permits whole-function and/or inline-expression recognition. A wrapper
is not a standalone library callee; inline matches stay inside their original
function and carry original occurrence sets. Pattern nodes describe the
matched expression, not an assertion that the entire enclosing body is pure.
Unrelated effects, external entries, escaping intermediate values and overlap
are checked separately before a region can be folded.

## COM ownership regions

`com-lifetime` describes five fixed effect policies for the recorded
`CComPtr<IUnknown>` specialization. It is not an executable instruction DSL.
The pointer is at offset zero. Interface calls require independently proven
`IUnknown` identity, a vtable load from the same interface pointer, and the
Win64 AddRef/Release slots 1/2. Extra calls/stores, ordered pointer accesses,
unproven aliases or a missing guard reject a region.

| Policy | Required effects, in program order |
| --- | --- |
| `zero-initialize` | Store the null pointer to the receiver; no call |
| `store-before-addref` | Load source pointer, store it to receiver, call its AddRef only if non-null |
| `addref-publish-release` | Compare source and receiver pointers; equal pointers bypass all effects. Otherwise AddRef the non-null source, reload the old receiver after AddRef, publish source, Release the old pointer if non-null |
| `clear-before-release` | Load receiver pointer; if non-null, clear receiver then call Release on the saved pointer |
| `release-without-clear` | Load receiver pointer; if non-null, call Release; do not insert or assume a clear |

Calls may reenter the object. A load after a call cannot be replaced by a
cached value from before that call. The assignment result, when observed,
is the final receiver pointer; constructors return the receiver; other
policies have no result. A caller may discard a result without changing the
required effects. `self_assignment` explicitly records the equal-pointer
guard for assignment. Entry/exit and exact original occurrences remain
consumer obligations, as for expression regions.

## Gated byte patterns

`byte-pattern` references an intact single-entry pattern emitted and parsed
by NeverD's existing `neverd-sigmaker`. It supports whole functions only.
Its `.pat.txt` suffix prevents old directory loaders from silently bypassing
the rule's receiver/identity requirements. The consumer uses the existing
matcher, including CRC, tail and reference verification, then applies those
requirements. C++ methods require receiver evidence even if their bytes match
a user wrapper; the wrapper never inherits the method's whole-function name.
The authoring gate requires 16 fixed leading bytes, which is at least as
strict as the existing matcher's 16 stated-byte floor.

C library functions have no receiver (`receiver_type: null`). Their identity
gate is `byte-signature`, with the existing signature conflict policy. The
musl pack also publishes a compatible `.pat` in `elf/x86/64`; builtin copies
and arbitrary user loops do not gain a libc identity from a structural shape.

## Evidence and coverage

Each witness identifies a producer build and a raw probe/library symbol.
Positive witnesses state whether they demonstrate an operation in a library
function or in a caller. Negative witnesses state the missing/contradictory
evidence. Every supported rule has both. The consumer rechecks the evidence
on the target binary; fixture metadata cannot serve as target authority.

`data_verified` records producer/schema checks. `consumer_verified` is a
separate gate for actual NeverD matching, boundaries, rejection, identity
precedence and presentation tests. Schema validation or successful compilation
must never set the latter. Unknown/ambiguous/unsupported matches do not receive
forced library names. Reference confirmation is not source-version proof.
