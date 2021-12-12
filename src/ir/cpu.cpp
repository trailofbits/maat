#include "cpu.hpp"
#include "pinst.hpp"
#include "engine.hpp"

namespace maat
{
namespace ir
{

void TmpContext::set(ir::tmp_t tmp, const ProcessedInst::param_t& value)
{
    if (value.is_abstract())
        return set(tmp, value.expr);
    else if (value.is_concrete())
        return set(tmp, value.number);
    else
        throw runtime_exception("TmpContext::set() got empty parameter!");
}

// Include idx !
void TmpContext::fill_until(int idx)
{
    while (tmps_e.size() <= idx)
    {
        tmps_e.push_back(nullptr); // Fill with null expressions...
        tmps_n.push_back(Number());
    }
}

void TmpContext::set(ir::tmp_t tmp, Expr value)
{
    if (value->is_type(ExprType::CST))
        return set(tmp, value->as_number());
    else
    {
        int idx(tmp);
        if (tmps_e.size() <= idx)
        {
            fill_until(idx);
        }
        tmps_e[idx] = value;
    }
}

void TmpContext::set(ir::tmp_t tmp, const Number& value)
{
    int idx(tmp);
        
    if (tmps_e.size() <= idx)
    {
        fill_until(idx);
    }
    try
    {
        tmps_n[idx] = value;
        tmps_e[idx] = nullptr;
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
            << "TmpContext: Trying to set temporary " << std::dec << idx
            << " which doesn't exist in current context"
        );
    }
}

Expr TmpContext::get(ir::tmp_t tmp)
{
    int idx(tmp);
    try
    {
        if (tmps_e.at(idx) != nullptr)
        {
            return tmps_e.at(idx);
        }
        else if (tmps_n.at(idx).size != 0)
            return exprcst(tmps_n[idx]);
        else
            throw ir_exception(Fmt()
                << "CPUContext::get() Trying to get temporary " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext::get() Trying to get temporary " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

const Number& TmpContext::get_concrete(ir::tmp_t tmp)
{
    int idx(tmp);
    if (idx >= tmps_e.size() or idx < 0)
    {
        throw ir_exception(Fmt()
                << "CPUContext::get_concrete() Trying to get temporary " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
    if (!is_concrete(tmp))
    {
        throw ir_exception(Fmt()
                << "TmpContext::get_concrete() Trying to get temporary " << std::dec << idx
                << " as concrete value but its expression is abstract"
            );
    }
    return tmps_n[idx];
}

bool TmpContext::exists(ir::tmp_t tmp)
{
    if (tmp < tmps_e.size() and tmp >= 0)
        return tmps_e.at(tmp) != nullptr or tmps_n.at(tmp).size != 0;
    else
        return false;
}

bool TmpContext::is_concrete(ir::tmp_t tmp)
{
    int idx(tmp);
    if (idx >= tmps_e.size() or idx < 0)
        return false;
    else
        return tmps_e.at(idx) == nullptr && (tmps_n.at(idx).size != 0);
}

bool TmpContext::is_abstract(ir::tmp_t tmp)
{
    int idx(tmp);
    if (idx >= tmps_e.size() or idx < 0)
        return false;
    else
    {
        return tmps_e.at(idx) != nullptr;
    }
}

void TmpContext::reset()
{
    tmps_e.clear();
    tmps_n.clear();
}

std::ostream& operator<<(std::ostream& os, TmpContext& ctx)
{
    for (int i = 0; i < ctx.tmps_e.size(); i++)
    {
        os << "T_" << std::dec << i << ": ";
        if (ctx.tmps_e[i] != nullptr)
            os << ctx.tmps_e[i] << "\n";
        else if (ctx.tmps_n[i].size != 0)
            os << ctx.tmps_n[i] << "\n";
    }
    return os;
}

const ProcessedInst::Param& ProcessedInst::in(int i) const
{
    switch (i)
    {
        case 0: return in0;
        case 1: return in1;
        case 2: return in2;
        default: throw runtime_exception("ProcessedInst::in() got invalid parameter number!");
    }
}

void ProcessedInst::reset()
{
    out.set_none();
    res.set_none();
    in0.set_none();
    in1.set_none();
    in2.set_none();
}

ProcessedInst::Param::Param():type(Param::Type::NONE), expr(nullptr), number(0) {}

ProcessedInst::Param::Param(const Param& other): type(other.type), expr(other.expr), number(other.number) {}

ProcessedInst::Param& ProcessedInst::Param::operator=(const ProcessedInst::Param& other)
{
    type = other.type;
    expr = other.expr;
    number = other.number;
    return *this;
}

bool ProcessedInst::Param::is_abstract() const { return type == Param::Type::ABSTRACT; }

bool ProcessedInst::Param::is_concrete() const { return type == Param::Type::CONCRETE; }

bool ProcessedInst::Param::is_none() const { return type == Param::Type::NONE; }

Expr ProcessedInst::Param::as_expr() const 
{
    if (is_abstract())
        return expr;
    else if (is_concrete())
        return exprcst(number);
    else
        throw ir_exception("ProcessedInst::Param::as_expr(): should never be called for NONE parameter");
}

ProcessedInst::Param& ProcessedInst::Param::operator=(const Expr& e)
{
    type = Param::Type::ABSTRACT;
    expr = e;
    return *this;
}

ProcessedInst::Param& ProcessedInst::Param::operator=(Expr&& e)
{
    type = Param::Type::ABSTRACT;
    expr = e;
    return *this;
}

ProcessedInst::Param& ProcessedInst::Param::operator=(const Number& n)
{
    type = Param::Type::CONCRETE;
    number = n;
    return *this;
}

void ProcessedInst::Param::set_none()
{
    type = Param::Type::NONE;
}

event::EventManager& get_engine_events(MaatEngine& engine)
{
    return engine.hooks;
}

} // namespace ir
} // namespace maat
