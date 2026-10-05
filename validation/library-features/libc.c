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
  memcpy(out, in, 16);
}
ND_EXPORT void nd_user_copy(unsigned char *out, const unsigned char *in,
                            size_t n) {
  for (size_t i = 0; i != n; ++i)
    out[i] = in[i];
}
