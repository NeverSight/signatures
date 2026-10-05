// Original NeverD probes. Compile against the profile's actual C++ headers.
// The two builds deliberately share this source: O0 keeps library callees,
// while O2 puts their operations inside callers with observable extra work.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#if defined(_MSC_VER)
#define ND_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#else
#define ND_EXPORT extern "C" __attribute__((visibility("default"), noinline))
#endif

#define ND_ACCESSORS(Prefix, Type)                                            \
  ND_EXPORT std::size_t Prefix##_size(const Type *p) { return p->size(); }     \
  ND_EXPORT bool Prefix##_empty(const Type *p) { return p->empty(); }          \
  ND_EXPORT const void *Prefix##_data(const Type *p) { return p->data(); }     \
  ND_EXPORT std::size_t Prefix##_capacity(const Type *p) {                     \
    return p->capacity();                                                    \
  }                                                                         \
  ND_EXPORT std::size_t Prefix##_size_inline(const Type *p, std::size_t n) {   \
    return p->size() + n;                                                    \
  }                                                                         \
  ND_EXPORT unsigned Prefix##_empty_inline(const Type *p, unsigned n) {       \
    return p->empty() ? n + 1 : n + 2;                                       \
  }                                                                         \
  ND_EXPORT std::uintptr_t Prefix##_data_inline(const Type *p,                 \
                                               std::uintptr_t salt) {        \
    return reinterpret_cast<std::uintptr_t>(p->data()) ^ salt;                \
  }                                                                         \
  ND_EXPORT std::size_t Prefix##_capacity_inline(const Type *p,                \
                                               std::size_t n) {              \
    return p->capacity() + n;                                                \
  }                                                                         \
  ND_EXPORT std::size_t Prefix##_object_size() { return sizeof(Type); }

using StringChar = std::basic_string<char>;
using StringWide = std::basic_string<wchar_t>;
using Vector32 = std::vector<std::uint32_t>;
using Vector64 = std::vector<std::uint64_t>;
ND_ACCESSORS(nd_string_char, StringChar)
ND_ACCESSORS(nd_string_wide, StringWide)
ND_ACCESSORS(nd_vector_u32, Vector32)
ND_ACCESSORS(nd_vector_u64, Vector64)

// Instantiate an unsupported specialization in the same binary. Its size()
// must not inherit the ordinary vector pointer-difference rule.
ND_EXPORT std::size_t nd_vector_bool_size(const std::vector<bool> *p) {
  return p->size();
}

struct UserRange {
  const std::uint32_t *begin;
  const std::uint32_t *end;
  const std::uint32_t *limit;
};
ND_EXPORT std::size_t nd_user_range_size(const UserRange *p) {
  return static_cast<std::size_t>(p->end - p->begin);
}
ND_EXPORT bool nd_user_range_empty(const UserRange *p) {
  return p->begin == p->end;
}
ND_EXPORT const void *nd_user_range_data(const UserRange *p) {
  return p->begin;
}
ND_EXPORT std::size_t nd_user_range_wrong_stride(const UserRange *p) {
  return (reinterpret_cast<std::uintptr_t>(p->end) -
          reinterpret_cast<std::uintptr_t>(p->begin)) >> 3;
}
ND_EXPORT std::size_t nd_vector_size_with_effect(const Vector32 *p,
                                                 volatile unsigned *effect) {
  *effect = 17;
  return p->size();
}
ND_EXPORT const void *nd_user_ordered_data(const volatile UserRange *p) {
  return p->begin;
}
