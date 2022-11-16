#include "maat/ir.hpp"
#include <vector>
#include <cstring>

namespace maat{
namespace ir{

AsmInst::AsmInst(): _addr(0), _tmp_cnt(0), _raw_size(0) {}

AsmInst::AsmInst(uint64_t address, unsigned int size)
:   _addr(address),
    _tmp_cnt(0),
    _raw_size(size)
{}

AsmInst& AsmInst::operator=(const AsmInst& other)
{
    _addr = other._addr;
    _tmp_cnt = other._tmp_cnt;
    _raw_size = other._raw_size;
    _instructions = other._instructions;
    return *this;
}

AsmInst& AsmInst::operator=(AsmInst&& other)
{
    _addr = other._addr;
    _tmp_cnt = other._tmp_cnt;
    _raw_size = other._raw_size;
    _instructions = std::move(other._instructions);
    return *this;
}

uint64_t AsmInst::addr() const
{
    return _addr;
}

unsigned int AsmInst::raw_size() const
{
    return _raw_size;
}

size_t AsmInst::nb_ir_inst() const
{
    return _instructions.size();
}

AsmInst::inst_id AsmInst::add_inst(const Inst& inst)
{
    _instructions.push_back(inst);
    return _instructions.size()-1;
}

AsmInst::inst_id AsmInst::add_inst(Inst&& inst)
{
    _instructions.push_back(inst);
    return _instructions.size()-1;
}

AsmInst::inst_id AsmInst::add_insts(const AsmInst::inst_list_t& insts)
{
    _instructions.insert(_instructions.end(), insts.begin(), insts.end());
    return _instructions.size()-1;
}

AsmInst::inst_id AsmInst::add_insts(AsmInst::inst_list_t&& insts)
{
    _instructions.insert(_instructions.end(), insts.begin(), insts.end());
    return _instructions.size()-1;
}

AsmInst::inst_list_t& AsmInst::instructions()
{
    return _instructions;
}

const AsmInst::inst_list_t& AsmInst::instructions() const
{
    return _instructions;
}

tmp_t AsmInst::new_tmp()
{
    return _tmp_cnt++;
}

struct Bounds
{
    int high;
    int low;
    Bounds()
    {
        high = 0;
        low = 0xffffff;
    }
    Bounds(int h, int l)
    {
        high = h;
        low = l;
    };
    void update(int h, int l)
    {
        high = std::max(h, high);
        low = std::min(l, low);
    };
    void update_min(int h, int l)
    {
        high = std::min(h, high);
        low = std::max(l, low);
    };
    bool contains(int h, int l)
    {
        return  high >= h && low <= l;
    };
};

bool AsmInst::contains(addr_t start, addr_t end)
{
    return  (_addr <= end and (_addr+_raw_size-1) >= start);
}

std::ostream& operator<<(std::ostream& os, const AsmInst& inst)
{
    os << std::hex << "0x" << inst.addr() << "\n";
    for (auto& inst : inst._instructions)
        os << "\t" << inst << "\n";
    os << std::endl;
    return os;
}


uint64_t IRMap::add(AsmInst&& inst)
{
    uint64_t addr = inst.addr();
    asm_insts[addr] = inst;
    return addr;
}

uint64_t IRMap::add(const AsmInst& inst)
{
    uint64_t addr = inst.addr();
    asm_insts[addr] = inst;
    return addr;
}

AsmInst& IRMap::get_inst_at(uint64_t addr)
{
    IRMap::inst_map_t::iterator it;
    if( (it = asm_insts.find(addr)) != asm_insts.end())
        return it->second;
    else
        throw ir_exception("IRMap::get_inst_at(): missing AsmInst");
}

bool IRMap::contains_inst_at(uint64_t addr)
{
    return asm_insts.find(addr) != asm_insts.end();
}

void IRMap::remove_insts_containing(uint64_t start, uint64_t end)
{
    // Note: if [start,end] is a wide intervall, this code will
    // be very inefficient. We could make it way faster by using 
    // a std::map and erasing using an iterator.
    // However, we don't want to use an ordered map because the 
    // lookup cost for each executed instruction is log(N) while
    // it's O(1) *on average* with unordered_map. Since we can lookup 
    // millions of asm insts in a run and since self-modifying code
    // is very rare we prefer using unordered_map.

    for (uint64_t addr = start; addr <= end; addr++)
    {
        asm_insts.erase(addr);
    }
}

void IRMap::remove_inst_at(uint64_t addr)
{
    asm_insts.erase(addr);
}

} // namespace ir
} // namespace maat
