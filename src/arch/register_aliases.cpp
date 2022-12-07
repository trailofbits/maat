#include "maat/cpu.hpp"
#include "maat/arch.hpp"

namespace maat{
namespace ir{

inline void __attribute__((always_inline)) _set_flag_from_bit(
    CPUContext& ctx,
    ir::reg_t reg,
    const Value& val,
    int bit,
    int nb_bits=1
){
    ctx.set(reg, concat(Value(8-nb_bits, 0), extract(val, nb_bits-1+bit, bit)));
}

void x86_alias_setter(CPUContext& ctx, ir::reg_t reg, const Value& val)
{
    if (reg == X86::EFLAGS)
    {
        _set_flag_from_bit(ctx, X86::CF, val, 0);
        _set_flag_from_bit(ctx, X86::PF, val, 2);
        _set_flag_from_bit(ctx, X86::AF, val, 4);
        _set_flag_from_bit(ctx, X86::ZF, val, 6);
        _set_flag_from_bit(ctx, X86::SF, val, 7);
        _set_flag_from_bit(ctx, X86::TF, val, 8);
        _set_flag_from_bit(ctx, X86::IF, val, 9);
        _set_flag_from_bit(ctx, X86::DF, val, 10);
        _set_flag_from_bit(ctx, X86::OF, val, 11);
        _set_flag_from_bit(ctx, X86::IOPL, val, 12, 2);
        _set_flag_from_bit(ctx, X86::NT, val, 14);
        _set_flag_from_bit(ctx, X86::RF, val, 16);
        _set_flag_from_bit(ctx, X86::VM, val, 17);
        _set_flag_from_bit(ctx, X86::AC, val, 18);
        _set_flag_from_bit(ctx, X86::VIF, val, 19);
        _set_flag_from_bit(ctx, X86::VIP, val, 20);
        _set_flag_from_bit(ctx, X86::ID, val, 21);
    }
    else
        throw runtime_exception("x86_alias_setter: got unsupported register");
}

Value x86_alias_getter(CPUContext& ctx, ir::reg_t reg)
{
    Value res;
    if (reg == X86::EFLAGS)
    {
        res = extract(ctx.get(X86::CF),0,0);
        res.set_concat(Value(1,1), res);
        res.set_concat(extract(ctx.get(X86::PF),0,0), res);
        res.set_concat(Value(1,0), res);
        res.set_concat(extract(ctx.get(X86::AF),0,0), res);
        res.set_concat(Value(1,0), res);
        res.set_concat(extract(ctx.get(X86::ZF),0,0), res);
        res.set_concat(extract(ctx.get(X86::SF),0,0), res);
        res.set_concat(extract(ctx.get(X86::TF),0,0), res);
        res.set_concat(extract(ctx.get(X86::IF),0,0), res);
        res.set_concat(extract(ctx.get(X86::DF),0,0), res);
        res.set_concat(extract(ctx.get(X86::OF),0,0), res);
        res.set_concat(extract(ctx.get(X86::IOPL),1,0), res);
        res.set_concat(extract(ctx.get(X86::NT),0,0), res);
        res.set_concat(Value(1,0), res);
        res.set_concat(extract(ctx.get(X86::RF),0,0), res);
        res.set_concat(extract(ctx.get(X86::VM),0,0), res);
        res.set_concat(extract(ctx.get(X86::AC),0,0), res);
        res.set_concat(extract(ctx.get(X86::VIF),0,0), res);
        res.set_concat(extract(ctx.get(X86::VIP),0,0), res);
        res.set_concat(extract(ctx.get(X86::ID),0,0), res);
        res.set_concat(Value(10,0), res);
    }
    else
        throw runtime_exception("x86_alias_getter: got unsupported register");
    return res;
}

std::set x86_aliases{X86::EFLAGS};

void x64_alias_setter(CPUContext& ctx, ir::reg_t reg, const Value& val)
{
    if (reg == X64::RFLAGS)
    {
        _set_flag_from_bit(ctx, X64::CF, val, 0);
        _set_flag_from_bit(ctx, X64::PF, val, 2);
        _set_flag_from_bit(ctx, X64::AF, val, 4);
        _set_flag_from_bit(ctx, X64::ZF, val, 6);
        _set_flag_from_bit(ctx, X64::SF, val, 7);
        _set_flag_from_bit(ctx, X64::TF, val, 8);
        _set_flag_from_bit(ctx, X64::IF, val, 9);
        _set_flag_from_bit(ctx, X64::DF, val, 10);
        _set_flag_from_bit(ctx, X64::OF, val, 11);
        _set_flag_from_bit(ctx, X64::IOPL, val, 12, 2);
        _set_flag_from_bit(ctx, X64::NT, val, 14);
        _set_flag_from_bit(ctx, X64::RF, val, 16);
        _set_flag_from_bit(ctx, X64::VM, val, 17);
        _set_flag_from_bit(ctx, X64::AC, val, 18);
        _set_flag_from_bit(ctx, X64::VIF, val, 19);
        _set_flag_from_bit(ctx, X64::VIP, val, 20);
        _set_flag_from_bit(ctx, X64::ID, val, 21);
    }
    else
        throw runtime_exception("x64_alias_setter: got unsupported register");
}

Value x64_alias_getter(CPUContext& ctx, ir::reg_t reg)
{
    Value res;
    if (reg == X64::RFLAGS)
    {
        res = extract(ctx.get(X64::CF),0,0);
        res.set_concat(Value(1,1), res);
        res.set_concat(extract(ctx.get(X64::PF),0,0), res);
        res.set_concat(Value(1,0), res);
        res.set_concat(extract(ctx.get(X64::AF),0,0), res);
        res.set_concat(Value(1,0), res);
        res.set_concat(extract(ctx.get(X64::ZF),0,0), res);
        res.set_concat(extract(ctx.get(X64::SF),0,0), res);
        res.set_concat(extract(ctx.get(X64::TF),0,0), res);
        res.set_concat(extract(ctx.get(X64::IF),0,0), res);
        res.set_concat(extract(ctx.get(X64::DF),0,0), res);
        res.set_concat(extract(ctx.get(X64::OF),0,0), res);
        res.set_concat(extract(ctx.get(X64::IOPL),1,0), res);
        res.set_concat(extract(ctx.get(X64::NT),0,0), res);
        res.set_concat(Value(1,0), res);
        res.set_concat(extract(ctx.get(X64::RF),0,0), res);
        res.set_concat(extract(ctx.get(X64::VM),0,0), res);
        res.set_concat(extract(ctx.get(X64::AC),0,0), res);
        res.set_concat(extract(ctx.get(X64::VIF),0,0), res);
        res.set_concat(extract(ctx.get(X64::VIP),0,0), res);
        res.set_concat(extract(ctx.get(X64::ID),0,0), res);
        res.set_concat(Value(42,0), res);
    }
    else
        throw runtime_exception("x64_alias_getter: got unsupported register");
    return res;
}

std::set x64_aliases{X64::RFLAGS};

void arm32_alias_setter(CPUContext& ctx, ir::reg_t reg, const Value& val)
{
    if (reg == ARM32::CPSR)
    {
        _set_flag_from_bit(ctx, ARM32::TF, val, 5);
        _set_flag_from_bit(ctx, ARM32::GE1, val, 16);
        _set_flag_from_bit(ctx, ARM32::GE2, val, 17);
        _set_flag_from_bit(ctx, ARM32::GE3, val, 18);
        _set_flag_from_bit(ctx, ARM32::GE4, val, 19);
        _set_flag_from_bit(ctx, ARM32::JF, val, 24);
        _set_flag_from_bit(ctx, ARM32::QF, val, 27);
        _set_flag_from_bit(ctx, ARM32::VF, val, 28);
        _set_flag_from_bit(ctx, ARM32::CF, val, 29);
        _set_flag_from_bit(ctx, ARM32::ZF, val, 30);
        _set_flag_from_bit(ctx, ARM32::NF, val, 31);
    }
    else
        throw runtime_exception("arm32_alias_setter: got unsupported register");
}

Value arm32_alias_getter(CPUContext& ctx, ir::reg_t reg)
{
    Value res;
    if (reg == ARM32::CPSR)
    {
        //res = extract(ctx.get(ARM32::QF),0,0) << 27;
        res.set_concat(extract(ctx.get(ARM32::TF),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::GE1),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::GE2),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::GE3),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::GE4),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::JF),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::VF),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::CF),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::ZF),0,0), res);
        res.set_concat(extract(ctx.get(ARM32::NF),0,0), res);
    }
    else
        throw runtime_exception("arm32_alias_getter: got unsupported register");
    return res;
}

std::set arm32_aliases{ARM32::CPSR};

void CPUContext::init_alias_getset(Arch::Type arch)
{
    if (arch == Arch::Type::X86)
    {
        alias_setter = x86_alias_setter;
        alias_getter = x86_alias_getter;
        aliased_regs = x86_aliases;
    }
    else if (arch == Arch::Type::X64)
    {
        alias_setter = x64_alias_setter;
        alias_getter = x64_alias_getter;
        aliased_regs = x64_aliases;
    }
    else if (arch == Arch::Type::ARM32)
    {
        alias_setter = arm32_alias_setter;
        alias_getter = arm32_alias_getter;
        aliased_regs = arm32_aliases;
    }
}

} // namespace ir
} // namespace maat
