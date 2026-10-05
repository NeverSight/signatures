/* Original memory/string probes; actual libc code is supplied by the profile. */
#include <stddef.h>
#include <string.h>

#if defined(_MSC_VER)
#define ND_EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define ND_EXPORT __attribute__((visibility("default"), noinline))
#endif

ND_EXPORT void *nd_memcpy(void *out, const void *in, size_t n) {
  return memcpy(out, in, n);
}
ND_EXPORT void *nd_memmove(void *out, const void *in, size_t n) {
  return memmove(out, in, n);
}
ND_EXPORT void *nd_memset(void *out, int c, size_t n) {
  return memset(out, c, n);
}
ND_EXPORT int nd_memcmp(const void *a, const void *b, size_t n) {
  return memcmp(a, b, n);
}
ND_EXPORT size_t nd_strlen(const char *s) { return strlen(s); }
ND_EXPORT void nd_builtin_copy16(void *out, const void *in) {
#if defined(__GNUC__) || defined(__clang__)
  __builtin_memcpy(out, in, 16);
#else
  memcpy(out, in, 16);
#endif
}
ND_EXPORT void nd_user_copy(unsigned char *out, const unsigned char *in,
                            size_t n) {
  for (size_t i = 0; i != n; ++i)
    out[i] = in[i];
}

// An analysis fixture entry, supplied buffers by a caller, not an OS startup
// routine. The producer links a freestanding ELF solely for signature checks.
ND_EXPORT int nd_libc_probe(char *out, char *in, size_t n) {
  nd_memcpy(out, in, n);
  nd_memmove(out + 1, out, n);
  nd_memset(out, 0, 1);
  return nd_memcmp(out, in, n) + (int)nd_strlen(in);
}
