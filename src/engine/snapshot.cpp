#include "maat/snapshot.hpp"

namespace maat
{

using serial::bits;

SavedMemState::SavedMemState(): size(0), addr(0), concrete_content(0){}

SavedMemState::SavedMemState(size_t size, addr_t addr, cst_t concrete, abstract_mem_chunk_t abstract)
: size(size), addr(addr), concrete_content(concrete), abstract_content(abstract)
{}

uid_t SavedMemState::class_uid() const
{
    return serial::ClassId::SAVED_MEM_STATE;
}

void SavedMemState::dump(serial::Serializer& s) const
{
    s << bits(size) << bits(addr) << bits(concrete_content);
    // Serialize abstract_content --> std::vector<std::pair<Expr, uint8_t>>
    s << bits(abstract_content.size());
    for (const auto& p : abstract_content)
        s << p.first << bits(p.second);
}

void SavedMemState::load(serial::Deserializer& d)
{
    size_t tmp_size;
    Expr tmp_e;
    uint8_t tmp_o;

    d >> bits(size) >> bits(addr) >> bits(concrete_content);
    d >> bits(tmp_size);
    for (size_t i = 0; i < tmp_size; i++)
    {
        d >> tmp_e >> bits(tmp_o);
        abstract_content.push_back(std::make_pair(tmp_e, tmp_o));
    }
}


void Snapshot::add_saved_mem(SavedMemState&& content)
{
    saved_mem.push_back(content);
}

void Snapshot::add_created_segment(ucst_t segment_start)
{
    created_segments.push_back(segment_start);
}

} // namespace maat
