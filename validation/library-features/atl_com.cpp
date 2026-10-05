// Original probes using real ATL and Windows SDK declarations.
#include <atlbase.h>
#include <atlcomcli.h>
#include <new>

#define ND_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
using ComPointer = ATL::CComPtr<IUnknown>;

ND_EXPORT ComPointer *nd_com_construct(void *storage) {
  return new (storage) ComPointer();
}
ND_EXPORT ComPointer *nd_com_copy(void *storage, const ComPointer *source) {
  return new (storage) ComPointer(*source);
}
ND_EXPORT void nd_com_assign(ComPointer *target, const ComPointer *source) {
  *target = *source;
}
ND_EXPORT void nd_com_release(ComPointer *p) { p->Release(); }
ND_EXPORT void nd_com_destroy(ComPointer *p) { p->~ComPointer(); }
ND_EXPORT unsigned nd_com_release_inline(ComPointer *p, unsigned n) {
  p->Release();
  return n + 1;
}
ND_EXPORT unsigned nd_com_assign_inline(ComPointer *target,
                                        const ComPointer *source, unsigned n) {
  *target = *source;
  return n + 1;
}
ND_EXPORT void nd_unknown_release(IUnknown *p) { p->Release(); }

// Even genuine IUnknown operations do not imply a CComPtr implementation.
struct UserComOwner { IUnknown *pointer; };
ND_EXPORT void nd_user_com_release(UserComOwner *p) {
  if (p->pointer) {
    IUnknown *old = p->pointer;
    p->pointer = nullptr;
    old->Release();
  }
}
ND_EXPORT void nd_user_assign(UserComOwner *target, const UserComOwner *source) {
  target->pointer = source->pointer;
}
