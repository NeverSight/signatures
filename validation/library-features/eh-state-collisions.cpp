// Original source counterexamples for exception-state frame helpers.
// Pointer arrays vary frame sizes without introducing a character buffer.
#include <cstddef>

extern void consume_eh_storage(void *, std::size_t);
extern void release_eh_a(void *);
extern void release_eh_b(void *);

struct GuardA {
  void *value;
  __declspec(noinline) ~GuardA() { release_eh_a(value); }
};

struct GuardB {
  void *value;
  __declspec(noinline) ~GuardB() { release_eh_b(value); }
};

template <class Guard, std::size_t Count>
__declspec(noinline) void exception_state_frame() {
  void *storage[Count] = {};
  Guard first = {storage};
  Guard second = {&first};
  consume_eh_storage(storage, sizeof(storage));
  consume_eh_storage(&first, sizeof(first));
  consume_eh_storage(&second, sizeof(second));
}

#define ND_FRAME(Count) \
  template void exception_state_frame<GuardA, Count>(); \
  template void exception_state_frame<GuardB, Count>();
#define ND_BLOCK(Base) \
  ND_FRAME(Base + 1) ND_FRAME(Base + 2) ND_FRAME(Base + 3) ND_FRAME(Base + 4) \
  ND_FRAME(Base + 5) ND_FRAME(Base + 6) ND_FRAME(Base + 7) ND_FRAME(Base + 8) \
  ND_FRAME(Base + 9) ND_FRAME(Base + 10) ND_FRAME(Base + 11) ND_FRAME(Base + 12) \
  ND_FRAME(Base + 13) ND_FRAME(Base + 14) ND_FRAME(Base + 15) ND_FRAME(Base + 16)

ND_BLOCK(0)
ND_BLOCK(16)
ND_BLOCK(32)
ND_BLOCK(48)
ND_BLOCK(64)
ND_BLOCK(80)
ND_BLOCK(96)
ND_BLOCK(112)
ND_BLOCK(128)
ND_BLOCK(144)
ND_BLOCK(160)
ND_BLOCK(176)
ND_BLOCK(192)
ND_BLOCK(208)
ND_BLOCK(224)
ND_BLOCK(240)
