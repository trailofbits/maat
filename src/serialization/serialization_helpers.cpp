#include "maat/serialization_helpers.hpp"
#include <cstdio>
#include <iostream>
#include <string>
#include <fstream>

namespace maat{
namespace serial{

SimpleStateManager::SimpleStateManager(
    std::filesystem::path dir,
    std::string f,
    bool d
): states_dir(dir), base_filename(f), delete_on_load(d), state_cnt(0)
{}

void SimpleStateManager::enqueue_state(MaatEngine& engine)
{
    std::string filename = get_next_state_filename();
    std::ofstream out(filename, std::ios_base::binary);
    Serializer s(out);
    s.serialize(engine);
    out.close();
    pending_states.push(filename);
}

bool SimpleStateManager::dequeue_state(MaatEngine& engine)
{
    if (pending_states.empty())
        return false;

    std::string filename = pending_states.front();
    pending_states.pop();

    std::ifstream in(filename, std::ios_base::binary);
    Deserializer d(in);
    d.deserialize(engine);
    in.close();

    if (delete_on_load)
        remove(filename.c_str());

    return true;
}

std::string SimpleStateManager::get_next_state_filename()
{
    std::string filename = base_filename + "_" + std::to_string(state_cnt++);
    return (states_dir / filename).string();
}

} // namespace serial
} // namespace maat