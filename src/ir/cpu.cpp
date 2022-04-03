#include "maat/cpu.hpp"
#include "maat/pinst.hpp"
#include "maat/engine.hpp"

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


serial::uid_t TmpContext::class_uid() const
{
    return serial::ClassId::TMP_CONTEXT;
}

void TmpContext::dump(serial::Serializer& s) const
{
    s << tmps;
}

void TmpContext::load(serial::Deserializer& d)
{
    d >> tmps;
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
    val = v;
    type = ProcessedInst::Param::Type::INPLACE;
    return *this;
}

void ProcessedInst::Param::set_value_by_ref(const Value& v)
{
    val_ptr = &v;
    type = ProcessedInst::Param::Type::PTR;
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


CPUContext::CPUContext(int nb_regs)
{
    regs = std::vector<Value>(nb_regs);
}

void CPUContext::set(ir::reg_t reg, const Value& value)
{
    int idx(reg);
    try
    {
        regs.at(idx) = value;
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext: Trying to set register " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

void CPUContext::set(ir::reg_t reg, Expr value)
{
    int idx(reg);
    try
    {
        regs.at(idx) = value;
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext: Trying to set register " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

void CPUContext::set(ir::reg_t reg, cst_t value)
{
    int idx(reg);
    try
    {
        regs.at(idx).set_cst(regs.at(idx).size(), value);
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext: Trying to set register " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

void CPUContext::set(ir::reg_t reg, Number&& value)
{
    int idx(reg);
    try
    {
        regs.at(idx) = value;
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext: Trying to set register " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

void CPUContext::set(ir::reg_t reg, const Number& value)
{
    int idx(reg);
    try
    {
        regs.at(idx) = value;
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext: Trying to set register " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

const Value& CPUContext::get(ir::reg_t reg) const
{
    int idx(reg);
    try
    {
        return regs.at(idx);
    }
    catch(const std::out_of_range&)
    {
        throw ir_exception(Fmt()
                << "CPUContext: Trying to get register " << std::dec << idx
                << " which doesn't exist in current context"
            );
    }
}

serial::uid_t CPUContext::class_uid() const
{
    return serial::ClassId::CPU_CONTEXT;
}

void CPUContext::dump(serial::Serializer& s) const
{
    s << regs;
}

void CPUContext::load(serial::Deserializer& d)
{
    d >> regs;
}

std::ostream& operator<<(std::ostream& os, const CPUContext& ctx)
{
    for (int i = 0; i < ctx.regs.size(); i++)
        os << "REG_" << std::dec << i << ": " << ctx.regs[i] << "\n";
    return os;
}

// Print the CPU context to a stream with proper register names
void CPUContext::print(std::ostream& os, const Arch& arch)
{
    for (int i = 0; i < arch.nb_regs; i++)
        os << arch.reg_name(i) << ": " << regs[i] << "\n";
}


CPU::CPU(int nb_regs): _cpu_ctx(CPUContext(nb_regs))
{}

Expr CPU::_extract_abstract_if_needed(Expr expr, size_t high_bit, size_t low_bit)
{
    if (low_bit == 0 and high_bit >= expr->size-1)
        return expr;
    else
        return extract(expr, high_bit, low_bit);
}



Value CPU::_extract_value_bits(const Value& val, size_t high_bit, size_t low_bit)
{
    Value res;
    res.set_extract(val, high_bit, low_bit);
    return res;
}

event::Action CPU::_get_param_value(
    ProcessedInst::Param& dest,
    const ir::Param& param,
    MaatEngine& engine,
    bool get_full_register,
    bool trigger_events
)
{
    event::Action action = event::Action::CONTINUE;

    if (param.is_none())
    {
        // skip
    }
    else if (param.is_cst())
    {
        // TODO: what about constants on more than 64 bits?????
        if (param.size() == sizeof(cst_t)*8)
            dest.set_cst(param.size(), param.cst());
        else
            dest.set_cst(param.size(), cst_extract((ucst_t)param.cst(), param.hb, param.lb));
    }
    else if (param.is_addr())
    {
        // Make number size 64, because the size of the param can also
        // refer to the number of bits accessed, not the size of the address!
        // So address is size 64, and the engine will handle how many bits
        // to read or write later...
        dest.set_cst(64, param.addr());
    }
    else if (param.is_tmp())
    {
        if (tmp_ctx.exists(param.tmp()))
        {
            const Value& res = tmp_ctx.get(param.tmp());
            if (res.size() != param.size())
            {
                // TODO this should return Value&& !!!!
                dest = _extract_value_bits(res, param.hb, param.lb);
            }
            else
            {
                dest.set_value_by_ref(res);
            }
        }
        else
        {
            dest.set_none();
        }
    }
    else if (param.is_reg())
    {
        if (trigger_events)
        {
            if (get_engine_events(engine).has_hooks(
                {event::Event::REG_R, event::Event::REG_RW},
                event::When::BEFORE
            ))
            {
                CPU_HANDLE_EVENT_ACTION(
                    get_engine_events(engine).before_reg_read(engine, param.reg()),
                    action
                )
            }
        }
        // Get register
        const Value& res = _cpu_ctx.get(param.reg());
        if (
            (not get_full_register)
            and res.size() != param.size()
        )
        {
            dest = _extract_value_bits(res, param.hb, param.lb);
        }
        else
        {
            dest.set_value_by_ref(res);
        }

        if (trigger_events)
        {
            if (get_engine_events(engine).has_hooks(
                {event::Event::REG_R, event::Event::REG_RW},
                event::When::AFTER
            ))
            {
                CPU_HANDLE_EVENT_ACTION(
                    get_engine_events(engine).after_reg_read(engine, param.reg(), dest),
                    action
                )
            }
        }
    }
    else
    {
        throw runtime_exception("CPU::_get_param_value(): got unsupported parameter type");
    }
    return action;
}

void CPU::_compute_res_value(
    Value& dest,
    const ir::Inst& inst,
    ProcessedInst& pinst
)
{
    const Value& in0 = pinst.in0.value();
    const Value& in1 = pinst.in1.value();

    switch (inst.op)
    {
        case ir::Op::INT_ADD: 
            dest.set_add(in0, in1);
            break;
        case ir::Op::INT_SUB:
            dest.set_sub(in0, in1);
            break;
        case ir::Op::INT_MULT: 
            dest.set_mul(in0, in1);
            break;
        case ir::Op::INT_DIV:
            dest.set_div(in0, in1);
            break;
        case ir::Op::INT_SDIV: 
            dest.set_sdiv(in0, in1);
            break;
        case ir::Op::INT_REM: 
            dest.set_rem(in0, in1);
            break;
        case ir::Op::INT_SREM: 
            dest.set_srem(in0, in1);
            break;
        case ir::Op::INT_LEFT: 
            dest.set_shl(in0, in1);
            break;
        case ir::Op::INT_RIGHT: 
            dest.set_shr(in0, in1);
            break;
        case ir::Op::INT_SRIGHT:
            dest.set_sar(in0, in1);
            break;
        case ir::Op::INT_AND:
            dest.set_and(in0, in1);
            break;
        case ir::Op::INT_OR:
            dest.set_or(in0, in1);
            break;
        case ir::Op::INT_XOR:
            dest.set_xor(in0, in1);
            break;
        case ir::Op::INT_2COMP:
            dest.set_neg(in0);
            break;
        case ir::Op::INT_NEGATE:
            dest.set_not(in0);
            break;
        case ir::Op::INT_CARRY:
            dest.set_carry(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_SCARRY:
            dest.set_scarry(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_SBORROW:
            dest.set_sborrow(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_SLESS:
            dest.set_sless_than(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_EQUAL:
            dest.set_equal_to(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_NOTEQUAL:
            dest.set_notequal_to(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_LESS:
            dest.set_less_than(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_LESSEQUAL:
            dest.set_lessequal_than(in0, in1, inst.out.size());
            break;
        case ir::Op::INT_SLESSEQUAL:
            dest.set_slessequal_than(in0, in1, inst.out.size());
            break;
        case ir::Op::COPY:
            dest = in0;
            break;
        case ir::Op::PIECE:
            dest.set_concat(in0, in1);
            break;
        case ir::Op::POPCOUNT:
            dest.set_popcount(inst.out.size(), in0);
            break;
        case ir::Op::INT_ZEXT:
            dest.set_zext(inst.out.size(), in0);
            break;
        case ir::Op::INT_SEXT:
            dest.set_sext(inst.out.size(), in0);
            break;
        case ir::Op::BOOL_NEGATE:
            dest.set_bool_negate(in0, inst.out.size());
            break;
        case ir::Op::BOOL_AND:
            dest.set_bool_and(in0, in1, inst.out.size());
            break;
        case ir::Op::BOOL_OR:
            dest.set_bool_or(in0, in1, inst.out.size());
            break;
        case ir::Op::BOOL_XOR:
            dest.set_bool_xor(in0, in1, inst.out.size());
            break;
        case ir::Op::SUBPIECE:
            dest.set_subpiece(in0, in1, inst.out.size());
            break;
        case ir::Op::STORE:
        case ir::Op::LOAD:
        case ir::Op::BRANCH:
        case ir::Op::BRANCHIND:
        case ir::Op::CBRANCH:
        case ir::Op::RETURN:
        case ir::Op::CALL:
        case ir::Op::CALLIND:
        case ir::Op::CALLOTHER:
            return;
        default:
            throw runtime_exception( Fmt() <<
                "CPU::_compute_res_value(): got unsupported IR operation: "
                << inst.op
                >> Fmt::to_str
            );
    }

    if (
        (not pinst.out.is_none())
        and (not inst.out.is_addr())
        and (not dest.is_none())
    )
    {
        dest.set_overwrite(pinst.out.value(), dest, inst.out.lb);
    }
}


ProcessedInst& CPU::pre_process_inst(
    const ir::Inst& inst,
    event::Action& action,
    MaatEngine& engine
)
{

    processed_inst.reset();

    // TODO: use Value& at least for input values....
    _get_param_value(processed_inst.out, inst.out, engine, true, false);
    event::merge_actions(action, _get_param_value(processed_inst.in0, inst.in[0], engine));
    event::merge_actions(action, _get_param_value(processed_inst.in1, inst.in[1], engine));
    event::merge_actions(action, _get_param_value(processed_inst.in2, inst.in[2], engine));
    return processed_inst;
}

ProcessedInst& CPU::post_process_inst(const ir::Inst& inst, ProcessedInst& pinst)
{
    _compute_res_value(pinst.res, inst, pinst);
    return pinst;
}

event::Action CPU::apply_semantics(
    const ir::Inst& inst,
    const ProcessedInst& pinst,
    MaatEngine& engine
)
{
    event::Action action = event::Action::CONTINUE;
    // Apply semantics only if destination is a register or a temporary
    if (
        (
            ir::is_assignment_op(inst.op)
            or inst.op == ir::Op::LOAD
            or (
                inst.op == ir::Op::CALLOTHER
                and not inst.out.is_none()
            )
        )
        and (not inst.out.is_addr())
    )
    {
        if (inst.out.is_reg())
        {
            // TODO: handle errors ??? How ??
            if (get_engine_events(engine).has_hooks(
                {event::Event::REG_W, event::Event::REG_RW},
                event::When::BEFORE
            ))
            {
                CPU_HANDLE_EVENT_ACTION(
                    get_engine_events(engine).before_reg_write(
                        engine,
                        inst.out.reg(),
                        pinst.res
                    ),
                    action
                )
            }
            _cpu_ctx.set(inst.out.reg(), pinst.res);
            if (get_engine_events(engine).has_hooks(
                {event::Event::REG_W, event::Event::REG_RW},
                event::When::AFTER
            ))
            {
                CPU_HANDLE_EVENT_ACTION(
                    get_engine_events(engine).after_reg_write(
                        engine,
                        inst.out.reg()
                    ),
                    action
                )
            }
        }
        else if (inst.out.is_tmp())
        {
            tmp_ctx.set(inst.out.tmp(), pinst.res);
        }
        else
        {
            throw ir_exception("CPU::apply_semantics(): got unexpected destination parameter in instruction");
        }
    }
    return action;
}

CPUContext& CPU::ctx()
{
    return _cpu_ctx;
}

void CPU::reset_temporaries()
{
    tmp_ctx.reset();
}

serial::uid_t CPU::class_uid() const
{
    return serial::ClassId::CPU;
}

void CPU::dump(serial::Serializer& s) const
{
    // Note: we don't serialize processed_inst since it is used internally only
    // during the IR execution loop and reset for every new IR instruction
    s << _cpu_ctx << tmp_ctx;
}

void CPU::load(serial::Deserializer& d)
{
    d >> _cpu_ctx >> tmp_ctx;
}



event::EventManager& get_engine_events(MaatEngine& engine)
{
    return engine.hooks;
}

} // namespace ir
} // namespace maat
