// Original probes, compiled only with the selected Visual Studio ATL headers.
#include <atlstr.h>
#include <new>

#define ND_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#define ND_STRING(Prefix, Type, Char)                                        \
  ND_EXPORT Type *Prefix##_construct(void *storage) {                        \
    return new (storage) Type();                                            \
  }                                                                        \
  ND_EXPORT Type *Prefix##_copy(void *storage, const Type *source) {          \
    return new (storage) Type(*source);                                     \
  }                                                                        \
  ND_EXPORT void Prefix##_assign(Type *target, const Type *source) {         \
    *target = *source;                                                      \
  }                                                                        \
  ND_EXPORT int Prefix##_length(const Type *p) { return p->GetLength(); }     \
  ND_EXPORT bool Prefix##_empty(const Type *p) { return p->IsEmpty(); }       \
  ND_EXPORT const Char *Prefix##_data(const Type *p) {                        \
    return p->GetString();                                                  \
  }                                                                        \
  ND_EXPORT Char *Prefix##_get_buffer(Type *p, int length) {                  \
    return p->GetBuffer(length);                                            \
  }                                                                        \
  ND_EXPORT void Prefix##_release_buffer(Type *p, int length) {              \
    p->ReleaseBuffer(length);                                               \
  }                                                                        \
  ND_EXPORT int Prefix##_length_inline(const Type *p, int extra) {            \
    return p->GetLength() + extra;                                          \
  }                                                                        \
  ND_EXPORT unsigned Prefix##_empty_inline(const Type *p, unsigned extra) {  \
    return p->IsEmpty() ? extra + 1 : extra + 2;                             \
  }                                                                        \
  ND_EXPORT const Char *Prefix##_data_inline(const Type *p, unsigned n) {     \
    return p->GetString() + n;                                              \
  }

ND_STRING(nd_cstring_char, ATL::CAtlStringA, char)
ND_STRING(nd_cstring_wide, ATL::CAtlStringW, wchar_t)

// A user type with similar method names supplies no ATL/MFC identity.
struct UserText {
  const wchar_t *buffer;
  int length;
  bool IsEmpty() const { return length == 0; }
  int GetLength() const { return length; }
};
ND_EXPORT bool nd_user_IsEmpty(const UserText *p) { return p->IsEmpty(); }
ND_EXPORT int nd_user_GetLength(const UserText *p) { return p->GetLength(); }
