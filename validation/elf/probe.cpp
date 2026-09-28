// A C++ program that pulls a broad slice of libstdc++ into a static link:
// streams, strings, containers, algorithms, exceptions and locale facets.
#include <algorithm>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char **argv) {
  std::vector<std::string> words(argv, argv + argc);
  std::sort(words.begin(), words.end());
  std::map<std::string, std::size_t> lengths;
  for (const std::string &word : words)
    lengths[word] = word.size();
  std::ostringstream out;
  for (const auto &[word, length] : lengths)
    out << word << '=' << length << ' ';
  try {
    if (argc > 3)
      throw std::runtime_error(out.str());
    std::cout << out.str() << std::stoi("12") << std::endl;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
  }
  std::string line;
  std::istringstream in("3.5 text");
  double number = 0;
  in >> number >> line;
  std::cout << std::fixed << number << ' ' << line << '\n';
  return static_cast<int>(words.size() % 2);
}
