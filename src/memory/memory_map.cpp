#include "maat/memory_page.hpp"
#include "maat/exception.hpp"
#include <iostream>
#include <iomanip>

namespace maat
{

using serial::bits;

MemMap::MemMap(): start(0), end(0), flags(maat::mem_flag_none)
{}

MemMap::MemMap(
addr_t s, addr_t e, mem_flag_t f, std::string n): 
    start(s), end(e), flags(f), name(n)
{}

bool MemMap::intersects_with_range(addr_t min, addr_t max) const
{
    return start <= max && end >= min;
}

bool MemMap::contained_in_range(addr_t min, addr_t max) const 
{
    return start >= min && end <= max;
}

bool MemMap::contains(addr_t addr) const
{
    return start <= addr && end >= addr;
}

void MemMap::truncate(std::list<MemMap>& res, addr_t min, addr_t max)
{
    if (min > end || max < start)
    {
        res.push_back(*this);
        return;
    }

    if (min <= start)
    {
        if (max >= end)
        {
            return;
        }
        else
            res.push_back(MemMap(max+1, end, flags, name));
    }
    else
    {
        res.push_back(MemMap(start, min-1, flags, name));
        if (max < end)
            res.push_back(MemMap(max+1, end, flags, name));
    }
}

bool operator<(const MemMap& m1, const MemMap& m2)
{
    return m1.start < m2.start;
}

uid_t MemMap::class_uid() const
{
    return serial::ClassId::MEM_MAP;
}

void MemMap::dump(serial::Serializer& s) const
{
    s << bits(start) << bits(end)  << bits(flags) << name;
}

void MemMap::load(serial::Deserializer& d)
{
    d >> bits(start) >> bits(end) >> bits(flags) >> name;
}



void MemMapManager::map(MemMap new_map)
{
    std::list<MemMap> new_maps;
    for (MemMap& old_map : _maps)
    {
        if (old_map.contained_in_range(new_map.start, new_map.end))
        {
            if (new_map.name.empty())
                new_map.name = old_map.name;
            continue; // This old map is replace by the new one
        }
        else
        {
            if (
                new_map.name.empty() and
                old_map.intersects_with_range(new_map.start, new_map.end)
            )
            {
                new_map.name = old_map.name;
            }
            old_map.truncate(new_maps, new_map.start, new_map.end);
        }
    }
    if (new_map.name.empty())
        new_map.name = "map_anon";
    new_maps.push_back(new_map);
    _maps = new_maps;
    _maps.sort();
}

void MemMapManager::unmap(addr_t start, addr_t end)
{
    std::list<MemMap> new_maps;
    for (MemMap& old_map : _maps)
    {
        if (old_map.contained_in_range(start, end))
            continue; // This old map is replace by the new one
        else
        {
            old_map.truncate(new_maps, start, end);
        }
    }
    _maps = new_maps;
    _maps.sort();
}

const std::list<MemMap>& MemMapManager::get_maps() const
{
    return _maps;
}

void MemMapManager::set_maps(std::list<MemMap>&& m)
{
    _maps = m;
}

const MemMap& MemMapManager::get_map_by_name(const std::string& name) const
{
    for (const auto& m : _maps)
    {
        if (m.name == name)
            return m;
    }
    throw mem_exception(
        Fmt() << "MemMapManager::get_map_by_name(): no map named " << name
        >> Fmt::to_str
    );
}

bool MemMapManager::is_free(addr_t start, addr_t end) const
{
    for (const MemMap& map : _maps)
        if (map.intersects_with_range(start, end))
            return false;
    return true;
}

std::ostream& operator<<(std::ostream& os, const MemMapManager& mem)
{
    static unsigned int addr_w = 20;
    os << std::endl << "Mappings: " << std::endl;
    os << std::endl << std::left << std::setw(addr_w) << "Start" << std::left << std::setw(addr_w) << "End" 
       << std::left << std::setw(8) << "Name" << std::endl;
    os << std::left << std::setw(addr_w) << "-----" << std::left << std::setw(addr_w) << "---" 
       << std::left << std::setw(8) << "----" << std::endl;
    for (const auto& map : mem.get_maps())
    {
        os << std::hex << "0x" << std::left << std::setw(addr_w-2) << map.start << "0x" << std::left << std::setw(addr_w-2) << map.end;
        if (not map.name.empty())
            os << map.name;
        os << "\n";
    }
    return os;
}

uid_t MemMapManager::class_uid() const
{
    return serial::ClassId::MEM_MAP_MANAGER;
}

void MemMapManager::dump(serial::Serializer& s) const
{
    s << _maps;
}

void MemMapManager::load(serial::Deserializer& d)
{
    d >> _maps;
}

} // namespace maat