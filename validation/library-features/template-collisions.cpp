// Original NeverD collision probes. Distinct source types can have identical
// machine code; those names must remain separate claims in the source audit.
#include <algorithm>
#include <atomic>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

struct ValueA {
  unsigned long long value;
  bool operator<(const ValueA &other) const { return value < other.value; }
  bool operator==(const ValueA &other) const { return value == other.value; }
};

struct ValueB {
  unsigned long long value;
  bool operator<(const ValueB &other) const { return value < other.value; }
  bool operator==(const ValueB &other) const { return value == other.value; }
};

template <class T>
__declspec(noinline) std::size_t sequence_operations(T *first, T *last,
                                                    const T &value) {
  std::vector<T> vector(first, last);
  std::list<T> list(first, last);
  std::deque<T> deque(first, last);
  vector.push_back(value);
  list.push_front(value);
  deque.push_back(value);
  vector.erase(std::find(vector.begin(), vector.end(), value));
  list.remove(value);
  deque.pop_front();
  std::sort(vector.begin(), vector.end());
  auto copy = vector;
  copy.swap(vector);
  return vector.size() + list.size() + deque.size();
}

template <class T>
__declspec(noinline) std::size_t associative_operations(const T &value) {
  std::map<T, unsigned> map;
  std::map<unsigned, T> reverse;
  std::set<T> set;
  map.emplace(value, 7);
  reverse.emplace(7, value);
  set.insert(value);
  auto copy = map;
  map.erase(value);
  return copy.size() + map.size() + reverse.size() + set.size();
}

template <class T>
__declspec(noinline) T *ownership_operations(std::shared_ptr<T> &output,
                                            const std::shared_ptr<T> &input,
                                            std::weak_ptr<T> &weak) {
  auto copy = input;
  output = std::move(copy);
  weak = output;
  auto locked = weak.lock();
  return locked.get();
}

template <class T>
__declspec(noinline) std::tuple<T, T> value_operations(const T &value) {
  std::pair<T, T> pair(std::piecewise_construct, std::forward_as_tuple(value),
                       std::tuple<>());
  auto tuple = std::make_tuple(pair.first, pair.second);
  std::get<1>(tuple) = value;
  return tuple;
}

#define ND_INSTANTIATE(Type)                                                 \
  template std::size_t sequence_operations<Type>(Type *, Type *, const Type &); \
  template std::size_t associative_operations<Type>(const Type &);            \
  template Type *ownership_operations<Type>(                                \
      std::shared_ptr<Type> &, const std::shared_ptr<Type> &,                  \
      std::weak_ptr<Type> &);                                                 \
  template std::tuple<Type, Type> value_operations<Type>(const Type &);

ND_INSTANTIATE(int)
ND_INSTANTIATE(unsigned)
ND_INSTANTIATE(long)
ND_INSTANTIATE(unsigned long)
ND_INSTANTIATE(float)
ND_INSTANTIATE(double)
ND_INSTANTIATE(std::string)
ND_INSTANTIATE(std::wstring)
ND_INSTANTIATE(ValueA)
ND_INSTANTIATE(ValueB)

template <class T>
__declspec(noinline) T atomic_operations(std::atomic<T> &value, T desired) {
  auto old = std::atomic_load_explicit(&value, std::memory_order_relaxed);
  std::atomic_store_explicit(&value, desired, std::memory_order_relaxed);
  return old;
}

template int atomic_operations<int>(std::atomic<int> &, int);
template unsigned atomic_operations<unsigned>(std::atomic<unsigned> &, unsigned);
template long atomic_operations<long>(std::atomic<long> &, long);
template unsigned long atomic_operations<unsigned long>(
    std::atomic<unsigned long> &, unsigned long);

template <class Character>
__declspec(noinline) bool string_operations(
    std::basic_string<Character> &output, const Character *text,
    std::size_t count) {
  output.assign(text, count);
  auto copy = output;
  output.append(copy);
  return output.compare(copy) != 0;
}

template bool string_operations<char>(std::string &, const char *, std::size_t);
template bool string_operations<wchar_t>(std::wstring &, const wchar_t *, std::size_t);
template bool string_operations<char16_t>(std::u16string &, const char16_t *, std::size_t);
