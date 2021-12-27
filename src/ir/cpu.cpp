#include "cpu.hpp"
#include "pinst.hpp"
#include "engine.hpp"

namespace maat
{
namespace ir
{

void TmpContext::set(ir::tmp_t tmp, const Value& value)
{
    int idx(tmp);
    if (tmps.size() <= idx)
    {
        fill_until(idx);
    }
    try
    {
        tmps.at(idx) = value;
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
            << "TmpContext: Trying to set temporary " << std::dec << idx
            << " which doesn't exist in current context"
        );
    }
}

// Include idx !
void TmpContext::fill_until(int idx)
{
    while (tmps.size() <= idx)
    {
        tmps.push_back(Value());
    }
}

const Value& TmpContext::get(ir::tmp_t tmp)
{
    int idx(tmp);
    try
    {
        return tmps.at(idx);
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext::get() Trying to get temporary " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}


bool TmpContext::exists(ir::tmp_t tmp)
{
    if (tmp < tmps.size() and tmp >= 0)
        return not tmps.at(tmp).is_none();
    else
        return false;
}

void TmpContext::reset()
{
    tmps.clear();
}

std::ostream& operator<<(std::ostream& os, TmpContext& ctx)
{
    for (int i = 0; i < ctx.tmps.size(); i++)
    {
        if (not ctx.tmps[i].is_none())
        {
            os << "T_" << std::dec << i << ": ";
            os << ctx.tmps[i] << "\n";
        }
    }
    return os;
}


ProcessedInst::Param::Param()
:   type(ProcessedInst::Param::Type::NONE),
    val_ptr(nullptr)
{}

ProcessedInst::Param::Param(const Param& other):
    type(other.type),
    val(other.val),
    val_ptr(other.val_ptr),
    auxilliary(other.auxilliary) 
{}

ProcessedInst::Param& ProcessedInst::Param::operator=(const ProcessedInst::Param& other)
{
    type = other.type;
    val = other.val;
    val_ptr = other.val_ptr;
    auxilliary = other.auxilliary;
    return *this;
}

ProcessedInst::Param& ProcessedInst::Param::operator=(const Value& v)
{
    val_ptr = &v;
    type = ProcessedInst::Param::Type::PTR;
    return *this;
}

ProcessedInst::Param& ProcessedInst::Param::operator=(Value&& v)
{
    val = v;
    type = ProcessedInst::Param::Type::INPLACE;
    return *this;
}

void ProcessedInst::Param::set_cst(size_t size, cst_t c)
{
    val.set_cst(size, c);
    type = ProcessedInst::Param::Type::INPLACE;
}

void ProcessedInst::Param::set_none()
{
    type = ProcessedInst::Param::Type::NONE;
}

const Value& ProcessedInst::Param::value() const
{
    if (type == ProcessedInst::Param::Type::PTR)
        return *val_ptr;
    else
        return val;
}

bool ProcessedInst::Param::is_none() const
{
    return type == ProcessedInst::Param::Type::NONE;
}

bool ProcessedInst::Param::is_abstract() const
{
    return not is_none() and value().is_abstract();
}

void ProcessedInst::reset()
{
    out.set_none();
    in0.set_none();
    in1.set_none();
    in2.set_none();
}

event::EventManager& get_engine_events(MaatEngine& engine)
{
    return engine.hooks;
}

} // namespace ir
} // namespace maat
