// Original source counterexamples for container boundaries, forwarding and
// ownership. Every family spans distinct source types and public library APIs.
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <ctime>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

extern void consume_boundary(const void *, std::size_t);

template <class Container>
__declspec(noinline) void
container_boundaries(Container &mutable_value,
                     const Container &constant_value) {
  consume_boundary(&mutable_value.front(), sizeof(mutable_value.front()));
  consume_boundary(&mutable_value.back(), sizeof(mutable_value.back()));
  consume_boundary(&constant_value.front(), sizeof(constant_value.front()));
  consume_boundary(&constant_value.back(), sizeof(constant_value.back()));
  auto first = mutable_value.begin();
  auto last = mutable_value.end();
  auto const_first = constant_value.begin();
  auto const_last = constant_value.end();
  consume_boundary(&first, sizeof(first));
  consume_boundary(&last, sizeof(last));
  consume_boundary(&const_first, sizeof(const_first));
  consume_boundary(&const_last, sizeof(const_last));
}

template <class Key, class Value>
__declspec(noinline) void node_forwarding(const Key &key, const Value &value) {
  std::map<Key, Value> mapping;
  mapping[key] = value;
  mapping.emplace(std::piecewise_construct, std::forward_as_tuple(key),
                  std::forward_as_tuple(value));
  std::list<std::pair<const Key, Value>> sequence;
  sequence.emplace_back(std::piecewise_construct, std::forward_as_tuple(key),
                        std::tuple<>());
  sequence.emplace_back(std::piecewise_construct, std::forward_as_tuple(key),
                        std::forward_as_tuple(value));
  consume_boundary(&mapping, sizeof(mapping));
  consume_boundary(&sequence, sizeof(sequence));
}

struct DeleteA {
  template <class T> void operator()(T *value) const { delete value; }
};

struct DeleteB {
  template <class T> void operator()(T *value) const { delete value; }
};

template <class T, class Deleter>
__declspec(noinline) void move_deleter(T *value, Deleter deleter) {
  std::unique_ptr<T, Deleter> owner(value, std::move(deleter));
  consume_boundary(&owner, sizeof(owner));
}

template <class T>
__declspec(noinline) void ordered_boundaries(T *first, T *last) {
  std::sort(first, last, std::less<T>());
  std::sort(first, last, std::less<void>());
}

template <class T>
__declspec(noinline) T default_atomic_load(const std::atomic<T> &value) {
  T first = value.load();
  T second = std::atomic_load(&value);
  consume_boundary(&first, sizeof(first));
  return second;
}

#define ND_BOUNDARY(Container)                                                 \
  template void container_boundaries<Container>(Container &, const Container &);
#define ND_VALUE(Type)                                                         \
  ND_BOUNDARY(std::vector<Type>)                                               \
  ND_BOUNDARY(std::deque<Type>)                                                \
  ND_BOUNDARY(std::list<Type>)                                                 \
  template void node_forwarding<Type, unsigned>(const Type &,                  \
                                                const unsigned &);             \
  template void node_forwarding<unsigned, Type>(const unsigned &,              \
                                                const Type &);                 \
  template void move_deleter<Type, DeleteA>(Type *, DeleteA);                  \
  template void move_deleter<Type, DeleteB>(Type *, DeleteB);                  \
  template void ordered_boundaries<Type>(Type *, Type *);

ND_VALUE(int)
ND_VALUE(long)
ND_VALUE(double)
ND_VALUE(std::string)
ND_VALUE(std::wstring)
ND_BOUNDARY(std::string)
ND_BOUNDARY(std::wstring)

template int default_atomic_load<int>(const std::atomic<int> &);
template unsigned default_atomic_load<unsigned>(const std::atomic<unsigned> &);
template long default_atomic_load<long>(const std::atomic<long> &);
template unsigned long
default_atomic_load<unsigned long>(const std::atomic<unsigned long> &);
template long long
default_atomic_load<long long>(const std::atomic<long long> &);

__declspec(noinline) int calendar_boundaries(std::tm *value,
                                             const std::time_t *time) {
  return localtime_s(value, time) + gmtime_s(value, time);
}
