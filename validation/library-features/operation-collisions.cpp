// Original source counterexamples for free atomic operations and EH frames.
// Frame sizes form a fixed ABI-aligned sweep, independent of evaluated images.
#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

extern void consume_storage(void *, std::size_t);

template <class T>
__declspec(noinline) T free_atomic_operations(std::atomic<T> &value, T desired) {
  std::atomic_init(&value, desired);
  auto old = std::atomic_load(&value);
  std::atomic_store(&value, desired);
  old += std::atomic_exchange(&value, desired);
  old += std::atomic_fetch_add(&value, desired);
  old += std::atomic_fetch_sub(&value, desired);
  old += std::atomic_fetch_and(&value, desired);
  old += std::atomic_fetch_or(&value, desired);
  old += std::atomic_fetch_xor(&value, desired);
  old += std::atomic_fetch_add_explicit(&value, desired, std::memory_order_relaxed);
  old += std::atomic_fetch_sub_explicit(&value, desired, std::memory_order_acquire);
  old += std::atomic_exchange_explicit(&value, desired, std::memory_order_acq_rel);
  std::atomic_compare_exchange_weak(&value, &old, desired);
  std::atomic_compare_exchange_strong_explicit(
      &value, &old, desired, std::memory_order_acq_rel, std::memory_order_acquire);
  return old;
}

template int free_atomic_operations<int>(std::atomic<int> &, int);
template unsigned free_atomic_operations<unsigned>(std::atomic<unsigned> &, unsigned);
template long free_atomic_operations<long>(std::atomic<long> &, long);
template unsigned long free_atomic_operations<unsigned long>(std::atomic<unsigned long> &, unsigned long);
template long long free_atomic_operations<long long>(std::atomic<long long> &, long long);
template unsigned long long free_atomic_operations<unsigned long long>(std::atomic<unsigned long long> &, unsigned long long);

template <class T, std::size_t Size>
__declspec(noinline) void cleanup_frame() {
  unsigned char storage[Size] = {};
  T first;
  T second;
  consume_storage(storage, sizeof(storage));
  consume_storage(&first, sizeof(first));
  consume_storage(&second, sizeof(second));
}

#define ND_FRAME(Size) \
  template void cleanup_frame<std::string, Size>(); \
  template void cleanup_frame<std::wstring, Size>(); \
  template void cleanup_frame<std::vector<int>, Size>(); \
  template void cleanup_frame<std::unique_ptr<unsigned long long>, Size>();

#define ND_FRAME_BLOCK(Base) \
  ND_FRAME(Base + 8) ND_FRAME(Base + 16) ND_FRAME(Base + 24) ND_FRAME(Base + 32) \
  ND_FRAME(Base + 40) ND_FRAME(Base + 48) ND_FRAME(Base + 56) ND_FRAME(Base + 64)

ND_FRAME_BLOCK(0)
ND_FRAME_BLOCK(64)
ND_FRAME_BLOCK(128)
ND_FRAME_BLOCK(192)
ND_FRAME_BLOCK(256)
ND_FRAME_BLOCK(320)
ND_FRAME_BLOCK(384)
ND_FRAME_BLOCK(448)
ND_FRAME_BLOCK(512)
ND_FRAME_BLOCK(576)
ND_FRAME_BLOCK(640)
ND_FRAME_BLOCK(704)
ND_FRAME_BLOCK(768)
ND_FRAME_BLOCK(832)
ND_FRAME_BLOCK(896)
ND_FRAME_BLOCK(960)
