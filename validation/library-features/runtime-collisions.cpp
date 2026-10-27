// Original NeverD probes for independently named standard-library operations.
// These are source counterexamples, never aliases for a matching byte body.
#include <algorithm>
#include <condition_variable>
#include <exception>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

template <class Character>
__declspec(noinline) std::basic_string<Character> text_operations(
    std::basic_string<Character> text, Character value, std::size_t count) {
  text.assign(count, value);
  text.append(count, value);
  text.insert(0, count, value);
  text.replace(0, count, count, value);
  text.push_back(value);
  auto found = std::find(text.begin(), text.end(), value);
  if (found != text.end())
    text.erase(found);
  return text;
}

template <class Character>
__declspec(noinline) std::basic_string<Character> stream_operations(
    const std::basic_string<Character> &text, long value) {
  std::basic_stringstream<Character> stream(text);
  stream << value;
  auto copy = stream.str();
  stream.str(copy);
  if (stream.good() || stream.eof() || stream.bad() || stream.fail())
    stream.clear();
  stream >> value;
  return stream.str();
}

template <class T>
__declspec(noinline) std::shared_ptr<T> allocation_operations(const T &value) {
  auto owner = std::make_shared<T>(value);
  std::unique_ptr<T> unique(new T(value));
  auto copy = owner;
  auto moved = std::move(copy);
  unique.reset(new T(*moved));
  owner.reset(unique.release());
  return owner;
}

#define ND_TEXT(Character)                                                    \
  template std::basic_string<Character> text_operations<Character>(          \
      std::basic_string<Character>, Character, std::size_t);                 \
  template std::basic_string<Character> stream_operations<Character>(        \
      const std::basic_string<Character> &, long);

ND_TEXT(char)
ND_TEXT(wchar_t)

#define ND_ALLOCATION(Type)                                                   \
  template std::shared_ptr<Type> allocation_operations<Type>(const Type &);

ND_ALLOCATION(int)
ND_ALLOCATION(long)
ND_ALLOCATION(unsigned long long)
ND_ALLOCATION(std::string)
ND_ALLOCATION(std::wstring)

__declspec(noinline) void synchronization_operations(
    std::mutex &mutex, std::condition_variable &condition) {
  std::unique_lock<std::mutex> lock(mutex);
  condition.notify_one();
  condition.notify_all();
  lock.unlock();
  if (lock.try_lock())
    lock.unlock();
}

__declspec(noinline) std::exception_ptr exception_operations(
    std::exception_ptr error) {
  try {
    if (error)
      std::rethrow_exception(error);
  } catch (...) {
    return std::current_exception();
  }
  return std::exception_ptr();
}
