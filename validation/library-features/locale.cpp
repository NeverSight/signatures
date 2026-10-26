//===- locale.cpp - Standard locale template source evidence --------------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Instantiate standard locale facets using the installed library headers.
/// Only compiler-emitted library symbols may become signature candidates.
///
//===----------------------------------------------------------------------===//

#include <codecvt>
#include <iterator>
#include <locale>

// Explicit instantiations retain complete out-of-line library bodies even
// when an application's callers inline some of these operations. No observed
// binary bytes, addresses, names from debug data, or copied implementation
// bodies are used to construct this source.
#define ND_INSTANTIATE_FACET(...)                                              \
  template const __VA_ARGS__ &std::use_facet<__VA_ARGS__>(                     \
      const std::locale &);                                                    \
  template bool std::has_facet<__VA_ARGS__>(const std::locale &) noexcept

ND_INSTANTIATE_FACET(std::ctype<char>);
ND_INSTANTIATE_FACET(std::ctype<wchar_t>);
ND_INSTANTIATE_FACET(std::codecvt<char, char, std::mbstate_t>);
ND_INSTANTIATE_FACET(std::codecvt<wchar_t, char, std::mbstate_t>);
ND_INSTANTIATE_FACET(std::collate<char>);
ND_INSTANTIATE_FACET(std::collate<wchar_t>);
ND_INSTANTIATE_FACET(std::numpunct<char>);
ND_INSTANTIATE_FACET(std::numpunct<wchar_t>);
ND_INSTANTIATE_FACET(std::num_get<char>);
ND_INSTANTIATE_FACET(std::num_get<wchar_t>);
ND_INSTANTIATE_FACET(std::num_put<char>);
ND_INSTANTIATE_FACET(std::num_put<wchar_t>);
ND_INSTANTIATE_FACET(std::moneypunct<char, false>);
ND_INSTANTIATE_FACET(std::moneypunct<char, true>);
ND_INSTANTIATE_FACET(std::moneypunct<wchar_t, false>);
ND_INSTANTIATE_FACET(std::moneypunct<wchar_t, true>);
ND_INSTANTIATE_FACET(std::money_get<char>);
ND_INSTANTIATE_FACET(std::money_get<wchar_t>);
ND_INSTANTIATE_FACET(std::money_put<char>);
ND_INSTANTIATE_FACET(std::money_put<wchar_t>);
ND_INSTANTIATE_FACET(std::time_get<char>);
ND_INSTANTIATE_FACET(std::time_get<wchar_t>);
ND_INSTANTIATE_FACET(std::time_put<char>);
ND_INSTANTIATE_FACET(std::time_put<wchar_t>);
ND_INSTANTIATE_FACET(std::messages<char>);
ND_INSTANTIATE_FACET(std::messages<wchar_t>);

#undef ND_INSTANTIATE_FACET
