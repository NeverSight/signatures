// Original source counterexamples for member-construction cleanup frames.
#include <cstddef>
#include <ios>
#include <iterator>
#include <locale>
#include <ostream>
#include <string>

extern void consume_member_frame(const void *, std::size_t);
extern void release_member_a(void *);
extern void release_member_b(void *);

struct MemberA {
  void *value;
  __declspec(noinline) ~MemberA() { release_member_a(value); }
};

struct MemberB {
  void *value;
  __declspec(noinline) ~MemberB() { release_member_b(value); }
};

template <std::size_t Count> struct MemberPrefix {
  void *value;
  MemberPrefix<Count - 1> rest;
};

template <> struct MemberPrefix<1> { void *value; };

template <class Member, std::size_t Count> struct MemberFrame {
  MemberPrefix<Count> prefix;
  Member first;
  Member second;
  Member third;

  __declspec(noinline) MemberFrame()
      : prefix{}, first{}, second{}, third{} {
    consume_member_frame(this, sizeof(*this));
  }
  __declspec(noinline) MemberFrame(void *a)
      : prefix{}, first{a}, second{}, third{} {
    consume_member_frame(this, sizeof(*this));
    consume_member_frame(a, sizeof(a));
  }
  __declspec(noinline) MemberFrame(void *a, void *b)
      : prefix{}, first{a}, second{b}, third{} {
    consume_member_frame(a, sizeof(a));
    consume_member_frame(this, sizeof(*this));
    consume_member_frame(b, sizeof(b));
  }
  __declspec(noinline) MemberFrame(void *a, void *b, void *c)
      : prefix{}, first{a}, second{b}, third{c} {
    consume_member_frame(a, sizeof(a));
    consume_member_frame(b, sizeof(b));
    consume_member_frame(this, sizeof(*this));
    consume_member_frame(c, sizeof(c));
  }
};

#define ND_MEMBER_FRAME(Count) \
  template struct MemberFrame<MemberA, Count>; \
  template struct MemberFrame<MemberB, Count>;
#define ND_MEMBER_BLOCK(Base) \
  ND_MEMBER_FRAME(Base + 1) ND_MEMBER_FRAME(Base + 2) \
  ND_MEMBER_FRAME(Base + 3) ND_MEMBER_FRAME(Base + 4) \
  ND_MEMBER_FRAME(Base + 5) ND_MEMBER_FRAME(Base + 6) \
  ND_MEMBER_FRAME(Base + 7) ND_MEMBER_FRAME(Base + 8)

ND_MEMBER_BLOCK(0)
ND_MEMBER_BLOCK(8)
ND_MEMBER_BLOCK(16)
ND_MEMBER_BLOCK(24)

template <class Character>
__declspec(noinline) std::locale locale_boundaries(
    std::basic_ios<Character> &stream, const std::locale &locale,
    const Character *first, const Character *last) {
  auto old = stream.imbue(locale);
  const auto &collation = std::use_facet<std::collate<Character>>(locale);
  auto transformed = collation.transform(first, last);
  consume_member_frame(&transformed, sizeof(transformed));
  return old;
}

template std::locale locale_boundaries<char>(
    std::basic_ios<char> &, const std::locale &, const char *, const char *);
template std::locale locale_boundaries<wchar_t>(
    std::basic_ios<wchar_t> &, const std::locale &, const wchar_t *, const wchar_t *);
