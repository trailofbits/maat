#include "ir.hpp"
#include <vector>
#include <algorithm>
#include <cstring>
#include <map>

namespace maat
{
    
namespace ir
{

Block::Block(const std::string& _name, uint64_t start, uint64_t end)
:   name(_name),
    _tmp_cnt(0),
    _raw_size(0),
    _start_addr(start),
    _end_addr(end)
{}

Block::Block(std::string&& _name, uint64_t start, uint64_t end)
:   name(_name),
    _tmp_cnt(0),
    _raw_size(0),
    _start_addr(start),
    _end_addr(end)
{}


Block& Block::operator=(const Block& other)
{
    name = other.name;
    _tmp_cnt = other._tmp_cnt;
    _raw_size = other._raw_size;
    _instructions = other._instructions;
    _start_addr = other._start_addr;
    _end_addr = other._end_addr;
    return *this;
}

Block& Block::operator=(Block&& other)
{
    name = other.name;
    _tmp_cnt = other._tmp_cnt;
    _raw_size = other._raw_size;
    _instructions = std::move(other._instructions);
    _start_addr = other._start_addr;
    _end_addr = other._end_addr;
    return *this;
}

uint64_t Block::start_addr() const
{
    return _start_addr;
}

uint64_t Block::end_addr() const
{
    return _end_addr;
}

bool Block::is_multibranch() const
{
    if (_instructions.empty())
        return false;
    else
    {
        const ir::Inst& inst = _instructions.back();
        return  inst.op == ir::Op::CBRANCH;
    }
}

size_t Block::nb_ir_inst() const
{
    return _instructions.size();
}

Block::inst_id Block::add_inst(const Inst& inst)
{
    _instructions.push_back(inst);
    return _instructions.size()-1;
}

Block::inst_id Block::add_inst(Inst&& inst)
{
    _instructions.push_back(inst);
    return _instructions.size()-1;
}

Block::inst_id Block::add_insts(const Block::inst_list_t& insts)
{
    _instructions.insert(_instructions.end(), insts.begin(), insts.end());
}

Block::inst_id Block::add_insts(Block::inst_list_t&& insts)
{
    _instructions.insert(_instructions.end(), insts.begin(), insts.end());
}

const Block::inst_list_t& Block::instructions() const
{
    return _instructions;
}

tmp_t Block::new_tmp()
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


/* Removing dead variables in Blocks
 * 
 *      Eliminate dead variables in each IRBasicBlock. To do so,
 *      simply iterate it from end to beginning and record when variables/
 *      tmps are read and set. If a variable is set and then set a second time
 *      without being read we can remove the first one. Of course we also check
 *      the high/low bits of sets because if we so set var1[31:0] and then set
 *      var1[10:0] we can not remove the first set.
 * 
 * */
void Block::optimise(int nb_regs)
{
    std::vector<ir::reg_t> vec{};
    optimise(vec, nb_regs);
}

void Block::optimise(const std::vector<ir::reg_t>& ignore_regs, int nb_regs)
{
    uint8_t READ=0, SET=1, UNKNOWN=2;
    bool removed = false;
    ir::Inst::param_list_t regs{};
    ir::Inst::param_list_t tmps{};

    // Create use tables for this block
    uint8_t* reg_use_table = new uint8_t[nb_regs];
    uint8_t* tmp_use_table = new uint8_t[_tmp_cnt];
    Bounds* reg_bounds_table = new Bounds[nb_regs];
    Bounds* tmp_bounds_table = new Bounds[_tmp_cnt];
    // Init use tables
    memset(reg_use_table, UNKNOWN, nb_regs);
    memset(tmp_use_table, SET, _tmp_cnt);
    for (int i = 0; i < _tmp_cnt; i++)
    {
        tmp_bounds_table[i] = Bounds(63, 0);
    }
    for (auto inst = _instructions.rbegin(); inst != _instructions.rend(); inst++)
    {
        removed = false;
        // Get written variables and tmps
        regs.clear();
        inst->get_written_regs(regs);
        // Check if the instruction can be removed
        for (auto reg_ref = regs.begin(); reg_ref != regs.end(); reg_ref++)
        {
            auto reg = reg_ref->get(); // Get reference to Param
            if( std::find(ignore_regs.begin(), ignore_regs.end(), reg.reg()) == ignore_regs.end() and
                reg_use_table[reg.reg()] == SET and
                reg_bounds_table[reg.reg()].contains(reg.hb, reg.lb))
            {
                // Remove instruction
                _instructions.erase(inst.base()-1);
                removed = true;
                break;
            }
            reg_use_table[reg.reg()] = SET;
            reg_bounds_table[reg.reg()].update(reg.hb, reg.lb);
        }
        if (removed)
            continue;
        else
        {
            tmps.clear();
            inst->get_written_tmps(tmps);
            for (auto tmp_ref = tmps.begin(); tmp_ref != tmps.end(); tmp_ref++)
            {
                auto tmp = tmp_ref->get(); // Get reference to Param
                if( tmp_use_table[tmp.tmp()] == SET &&
                    tmp_bounds_table[tmp.tmp()].contains(tmp.hb, tmp.lb)){
                    // Remove instruction
                    _instructions.erase(inst.base()-1);
                    removed = true;
                    break;
                }
                tmp_use_table[tmp.tmp()] = SET;
                tmp_bounds_table[tmp.tmp()].update(tmp.hb, tmp.lb);
            }
        }
        // Get read variables (AFTER written because if it is both read and write we want
        // to keep the information that it's read)
        regs.clear();
        inst->get_read_regs(regs);
        tmps.clear();
        inst->get_read_tmps(tmps);
        for (auto& reg_ref : regs)
        {
            reg_use_table[reg_ref.get().reg()] = READ;
            reg_bounds_table[reg_ref.get().reg()] = Bounds();
        }
        for (auto& tmp_ref : tmps)
        {
            tmp_use_table[tmp_ref.get().tmp()] = READ;
            tmp_bounds_table[tmp_ref.get().tmp()] = Bounds();
        }
    }

    /* Free all use tables */
    delete [] reg_use_table;
    delete [] tmp_use_table;
    delete [] reg_bounds_table;
    delete [] tmp_bounds_table;
}

bool Block::contains(addr_t start, addr_t end)
{
    return  (_start_addr <= end and _end_addr >= start);
}

std::ostream& operator<<(std::ostream& os, Block& block)
{
    os << block.name;
    for (auto inst : block._instructions)
        os << "\t" << inst << "\n";
    os << std::endl;
    return os;
}


uint64_t BlockMap::add(std::shared_ptr<Block> block)
{
    blocks[block->start_addr()] = block;
    return block->start_addr();
}

std::shared_ptr<Block> BlockMap::get_block_at(uint64_t addr)
{
    BlockMap::block_map_t::iterator block;
    if( (block = blocks.find(addr)) != blocks.end() ){
        return block->second;
    }else{
        return nullptr;
    }
}

std::vector<std::shared_ptr<Block>> BlockMap::get_blocks_containing(uint64_t addr)
{
    std::vector<std::shared_ptr<Block>> res;
    // Efficiently find first block that overlaps with addr
    auto it = std::lower_bound(
                blocks.begin(),
                blocks.end(),
                addr,
                [](std::pair<uint64_t, std::shared_ptr<Block>> elem, uint64_t addr) -> bool
                    {
                        return elem.second->end_addr() < addr;
                    }
                );
    for (; it != blocks.end() and it->second->start_addr() <= addr; it++)
    {
        if (it->second->end_addr() >= addr)
            res.push_back(it->second);
    }
    return std::move(res);
}

std::vector<std::shared_ptr<Block>> BlockMap::get_blocks_containing(uint64_t start_addr, uint64_t end_addr)
{
    std::vector<std::shared_ptr<Block>> res;
    auto it = std::lower_bound(
                blocks.begin(),
                blocks.end(),
                start_addr,
                [](std::pair<uint64_t, std::shared_ptr<Block>> elem, uint64_t addr) -> bool
                    {
                        return elem.second->end_addr() < addr;
                    }
                );
    for (; it != blocks.end() and it->second->start_addr() <= end_addr; it++)
    {
        if (it->second->end_addr() >= start_addr)
            res.push_back(it->second);
    }
    return std::move(res);
}

std::optional<BlockMap::InstLocation> BlockMap::get_inst_at(uint64_t addr)
{
    auto blocks = get_blocks_containing(addr);
    for (auto& block : blocks)
    {
        Block::inst_id i = 0;
        for (auto& inst : block->instructions())
        {
            if (inst.addr == addr)
                return std::make_optional(BlockMap::InstLocation{block, i});
            i++;
        }
    }
    return std::nullopt;
}

void BlockMap::remove_blocks_containing(uint64_t start, uint64_t end)
{
    
    // TODO: use std::erase_if(std::map) when C++20 support is good in compilers
    // Basically duplicate of get_blocks_containing() but with erase() operation...
    auto it = std::lower_bound(
                blocks.begin(),
                blocks.end(),
                start,
                [](std::pair<uint64_t, std::shared_ptr<Block>> elem, uint64_t addr) -> bool
                    {
                        return elem.second->end_addr() < addr;
                    }
                );
    for (; it != blocks.end() and it->second->start_addr() <= end; )
    {
        if (it->second->end_addr() >= start)
            it = blocks.erase(it);
        else
            it++;
    }
}

void BlockMap::remove_block_at(uint64_t addr)
{
    blocks.erase(addr);
}

} // namespace ir
} // namespace maat
