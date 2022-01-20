#ifndef MAAT_UTIL_H
#define MAAT_UTIL_H

namespace maat
{
namespace util
{
// Overloaded pattern
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
} // util
} // namespace maat
#endif
