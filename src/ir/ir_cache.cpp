#include "maat/ir.hpp"

namespace maat{
namespace ir{

namespace cache{

std::unordered_map<int, IRMap> ir_cache;

} // namespace cache


IRMap& get_ir_map(int mem_engine_uid)
{
    auto it = cache::ir_cache.find(mem_engine_uid);
    if (it == cache::ir_cache.end())
    {
        cache::ir_cache[mem_engine_uid] = IRMap();
        return cache::ir_cache[mem_engine_uid];
    }
    else
    {
        return it->second;
    }
}

} // namespace ir
} // namespace maat