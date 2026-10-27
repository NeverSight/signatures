// Original source counterexamples for cleanup helpers at distinct frame slots.
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

extern void consume_frame_object(void *, std::size_t);

#define ND_OBJECT(Label) \
  T object##Label; \
  consume_frame_object(&object##Label, sizeof(object##Label));
#define ND_EIGHT(Prefix) \
  ND_OBJECT(Prefix##0) ND_OBJECT(Prefix##1) ND_OBJECT(Prefix##2) ND_OBJECT(Prefix##3) \
  ND_OBJECT(Prefix##4) ND_OBJECT(Prefix##5) ND_OBJECT(Prefix##6) ND_OBJECT(Prefix##7)

template <class T, std::size_t Groups>
__declspec(noinline) void many_frame_objects() {
  unsigned char storage[64] = {};
  ND_EIGHT(0)
  ND_EIGHT(1)
  if constexpr (Groups >= 4) {
    ND_EIGHT(2)
    ND_EIGHT(3)
    if constexpr (Groups >= 8) {
      ND_EIGHT(4)
      ND_EIGHT(5)
      ND_EIGHT(6)
      ND_EIGHT(7)
      if constexpr (Groups >= 16) {
        ND_EIGHT(8)
        ND_EIGHT(9)
        ND_EIGHT(a)
        ND_EIGHT(b)
        ND_EIGHT(c)
        ND_EIGHT(d)
        ND_EIGHT(e)
        ND_EIGHT(f)
        consume_frame_object(storage, sizeof(storage));
      }
      consume_frame_object(storage, sizeof(storage));
    }
    consume_frame_object(storage, sizeof(storage));
  }
  consume_frame_object(storage, sizeof(storage));
}

#define ND_INSTANTIATE(Groups) \
  template void many_frame_objects<std::string, Groups>(); \
  template void many_frame_objects<std::wstring, Groups>(); \
  template void many_frame_objects<std::vector<int>, Groups>(); \
  template void many_frame_objects<std::unique_ptr<unsigned long long>, Groups>();

ND_INSTANTIATE(2)
ND_INSTANTIATE(4)
ND_INSTANTIATE(8)
ND_INSTANTIATE(16)
