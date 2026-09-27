// A program that statically links a broad slice of the C runtime and the C++
// standard library, so that a signature set can be checked against the
// linker's own map of the same image. Nothing here is interesting to run;
// what matters is what the linker pulls in.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

std::mutex Lock;
std::atomic<int> Counter{0};

int work(int Seed) {
  std::lock_guard<std::mutex> Guard(Lock);
  std::mt19937 Engine(static_cast<unsigned>(Seed));
  std::uniform_int_distribution<int> Dist(1, 100);
  Counter += Dist(Engine);
  return Counter.load();
}

std::string describe(double Value) {
  std::ostringstream OS;
  OS.imbue(std::locale::classic());
  OS << std::fixed << std::setprecision(3) << Value << " " << std::hex << 255;
  return OS.str();
}

} // namespace

int main(int Argc, char **Argv) {
  std::vector<std::string> Words;
  for (int I = 0; I < Argc; ++I)
    Words.emplace_back(Argv[I]);
  std::sort(Words.begin(), Words.end());

  std::map<std::string, int> Counts;
  std::unordered_map<int, std::wstring> Wide;
  std::set<double> Values;
  for (const std::string &Word : Words) {
    ++Counts[Word];
    Wide[static_cast<int>(Word.size())] = std::wstring(Word.begin(), Word.end());
    Values.insert(std::sqrt(static_cast<double>(Word.size())) + std::sin(1.0));
  }

  std::regex Pattern("([a-z]+)([0-9]*)");
  std::smatch Match;
  std::string Text = "probe42";
  if (std::regex_match(Text, Match, Pattern))
    std::cout << Match[1] << " " << Match[2] << "\n";

  std::vector<std::thread> Threads;
  for (int I = 0; I < 4; ++I)
    Threads.emplace_back([I] { work(I); });
  for (std::thread &Thread : Threads)
    Thread.join();

  try {
    if (Counter.load() < 0)
      throw std::runtime_error("negative");
    std::vector<int> Small(2);
    (void)Small.at(static_cast<size_t>(Argc) + 5);
  } catch (const std::out_of_range &Error) {
    std::cerr << "out_of_range: " << Error.what() << "\n";
  } catch (const std::exception &Error) {
    std::cerr << Error.what() << "\n";
  }

  auto Shared = std::make_shared<std::string>(describe(3.14159));
  std::function<size_t()> Size = [Shared] { return Shared->size(); };

  char Buffer[128];
  std::snprintf(Buffer, sizeof(Buffer), "%s %zu %d %.2f", Shared->c_str(), Size(),
                Counter.load(), std::strtod("2.5", nullptr));
  std::puts(Buffer);

  std::time_t Now = std::time(nullptr);
  std::tm Local{};
#ifdef _WIN32
  localtime_s(&Local, &Now);
#endif
  std::strftime(Buffer, sizeof(Buffer), "%Y-%m-%d", &Local);

  std::ofstream Out("probe.txt");
  Out << Buffer << " " << Counts.size() << " " << Values.size() << "\n";
  Out.close();
  std::ifstream In("probe.txt");
  std::string Line;
  std::getline(In, Line);
  std::remove("probe.txt");

  void *Block = std::malloc(64);
  std::memset(Block, 0, 64);
  std::qsort(Block, 16, 4, [](const void *A, const void *B) {
    return std::memcmp(A, B, 4);
  });
  std::free(Block);

  auto Start = std::chrono::steady_clock::now();
  (void)Start;
  return static_cast<int>(Line.size() + Wide.size()) & 1;
}
