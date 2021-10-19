#include "snapshot.hpp"

namespace maat
{

void Snapshot::add_saved_mem(SavedMemState&& content)
{
    saved_mem.push_back(content);
}

void Snapshot::add_created_segment(ucst_t segment_start)
{
    created_segments.push_back(segment_start);
}

} // namespace maat
