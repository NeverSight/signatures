// Original NeverD source counterexamples for regular expressions and packed bits.
// Instantiate public operations without importing evaluation names or addresses.
#include <algorithm>
#include <iterator>
#include <locale>
#include <regex>
#include <string>
#include <vector>

template <class Character>
__declspec(noinline) std::basic_string<Character> regex_operations(
    const std::basic_string<Character> &text,
    const std::basic_string<Character> &expression,
    const std::basic_string<Character> &replacement) {
  using Iterator = typename std::basic_string<Character>::const_iterator;
  std::basic_regex<Character> pattern(expression);
  pattern.imbue(std::locale::classic());
  pattern.assign(expression, std::regex_constants::ECMAScript);
  std::match_results<Iterator> result;
  auto copy = result;
  if (std::regex_search(text.begin(), text.end(), result, pattern)) {
    copy = result;
    if (!copy.empty())
      copy.str();
  }
  std::regex_match(text.begin(), text.end(), result, pattern);
  std::basic_string<Character> output;
  std::regex_replace(std::back_inserter(output), text.begin(), text.end(),
                     pattern, replacement);
  for (std::regex_iterator<Iterator> it(text.begin(), text.end(), pattern), end;
       it != end; ++it)
    output.append(it->str());
  for (std::regex_token_iterator<Iterator> it(text.begin(), text.end(), pattern),
       end; it != end; ++it)
    output.append(it->str());
  return output;
}

template std::string regex_operations<char>(const std::string &,
                                            const std::string &,
                                            const std::string &);
template std::wstring regex_operations<wchar_t>(const std::wstring &,
                                               const std::wstring &,
                                               const std::wstring &);

__declspec(noinline) std::vector<bool> packed_bit_operations(
    std::vector<bool> bits, std::size_t count, bool value) {
  bits.reserve(count);
  bits.resize(count, value);
  bits.push_back(value);
  bits.insert(bits.begin(), count, value);
  std::reverse(bits.begin(), bits.end());
  std::sort(bits.begin(), bits.end());
  bits.flip();
  auto copy = bits;
  if (copy != bits)
    copy.clear();
  if (!bits.empty()) {
    bits.front() = !bits.back();
    bits.erase(bits.begin());
  }
  bits.shrink_to_fit();
  return bits;
}
