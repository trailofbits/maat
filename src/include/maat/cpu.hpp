#ifndef MAAT_CPU_H
#define MAAT_CPU_H

#include <array>
#include <vector>
#include <optional>
#include "maat/expression.hpp"
#include "maat/ir.hpp"
#include "maat/constraint.hpp"
#include "maat/arch.hpp"
#include "maat/event.hpp"
#include "maat/pinst.hpp"

namespace maat
{
namespace ir
{
/** \addtogroup ir
 * \{ */

#define CPU_HANDLE_EVENT_ACTION(statement, res) \
{\
    event::Action tmp = statement;\
    if (tmp == event::Action::ERROR)\
    {\
        return tmp; \
    }\
    else\
    {\
        res = event::merge_actions(res, tmp);\
    }\
}

/** The CPU context in Maat's IR. It is basically
 * a mapping between abstract expressions and CPU registers */
class CPUContext
{
private:
    std::vector<Value> regs;

public:
    CPUContext(int nb_regs)
    {
        regs = std::vector<Value>(nb_regs);
    }
    CPUContext(const CPUContext& other) = default;
    CPUContext& operator=(const CPUContext& other) = default;
    ~CPUContext() = default;

public:
    /// Assign abstract or concrete expression to register *reg*
    void set(ir::reg_t reg, const Value& value)
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

    /// Assign abstract expression to register *reg*
    void set(ir::reg_t reg, Expr value)
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

    /// Assign concrete value to register *reg*
    void set(ir::reg_t reg, cst_t value)
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
    
    /// Assign concrete value to register *reg*
    void set(ir::reg_t reg, Number&& value)
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
    
    /// Assign concrete value to register *reg*
    void set(ir::reg_t reg, const Number& value)
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

    /// Get current value of register *reg* as an abstract expression
    const Value& get(ir::reg_t reg) const
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

public:
    /// Print the CPU context to a stream
    friend std::ostream& operator<<(std::ostream& os, const CPUContext& ctx)
    {
        for (int i = 0; i < ctx.regs.size(); i++)
            os << "REG_" << std::dec << i << ": " << ctx.regs[i] << "\n";
        return os;
    }
    /// Print the CPU context to a stream with proper register names
    void print(std::ostream& os, const Arch& arch)
    {
        for (int i = 0; i < arch.nb_regs; i++)
            os << arch.reg_name(i) << ": " << regs[i] << "\n";
    }
};

/** This class represents a context for temporary registers used in Maat's IR. It is basically
 * a mapping between abstract expressions and temporary registers. It is used internally
 * for executing IR code */
class TmpContext
{
private:
    std::vector<Value> tmps;

public:
    TmpContext() = default;
    TmpContext(const TmpContext& other) = default;
    TmpContext& operator=(const TmpContext& other) = default;
    ~TmpContext() = default;
private:
    void fill_until(int idx);
public:
    bool exists(ir::tmp_t tmp); ///< Return 'true' if the temporary exists in the current context
public:
    void set(ir::tmp_t tmp, const Value& value); ///< Assign abstract or concrete value to temporary 'tmp'
    const Value& get(ir::tmp_t tmp); ///< Get current value of temporary 'tmp'
public:
    void reset(); ///< Remove all temporaries previously created
public:
    friend std::ostream& operator<<(std::ostream& os, TmpContext& ctx);
};

// Hacky method to get engine.events and avoid the compiler to
// complain that engine is an incomplete type (because cpu.hpp is
// included in engine.hpp)
event::EventManager& get_engine_events(MaatEngine& engine);

/** The CPU is responsible for processing most IR instructions when executing code */
class CPU
{
private:
    CPUContext _cpu_ctx; ///< CPU registers context
    TmpContext tmp_ctx; ///< Temporary values context
private:
    ProcessedInst processed_inst; ///< Processed instruction

public:
    CPU(int nb_regs=0): _cpu_ctx(CPUContext(nb_regs)){}
    CPU(const CPU& other) = default;
    CPU& operator=(const CPU& other) = default;
private:

    /** \brief Extracts bit field (high_bit and low_bit included) from 'expr'. If
     * the extract extracts the whole expression, then simply returns 'expr'
     * without performing the extract */
    inline Expr _extract_abstract_if_needed(Expr expr, size_t high_bit, size_t low_bit)
    __attribute__((always_inline))
    {
        if (low_bit == 0 and high_bit >= expr->size-1)
            return expr;
        else
            return extract(expr, high_bit, low_bit);
    };


    /** \brief Extracts bit field (high_bit and low_bit included) from 'val'. 'val' is modified
     * **in place**. 
     * Returns a reference to 'val' */
    inline Value _extract_value_bits(const Value& val, size_t high_bit, size_t low_bit)
    __attribute__((always_inline))
    {
        Value res;
        res.set_extract(val, high_bit, low_bit);
        return res;
    };

    /** \brief Get value of parameter 'param' (extract bits if needed).
     * get_full_register is set to true, the function doesn't truncate the
     * expression if the parameter is a register */
    inline event::Action _get_param_value(
        ProcessedInst::Param& dest,
        const ir::Param& param,
        MaatEngine& engine,
        bool get_full_register = false,
        bool trigger_events = true
    )
    __attribute__((always_inline))
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
    };

    /** \brief Compute value to be assigned to the output parameter
     * for instruction 'inst' (with bit extract/concat if overwriting 
     * only a subset of the output current value). Set value to 'dest'. */
    inline void _compute_res_value(
        Value& dest,
        const ir::Inst& inst,
        ProcessedInst& pinst
    )
    __attribute__((always_inline))
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

public:
    /** \brief Compute the values of the various parameters of the
     *  IR instruction *inst* and return them as a ProcessedInst. ir::Param::Type::ADDR parameters are
     * not resolved by this function but will be by the engine itself, since
     * it requires interacting with the memory engine. \n
     * For more information about the exact values contained in the returned
     * ProcessedInst depending on the input IR instruction type, refer to
     * the ::ProcessedInst class documentation. \n
     * **WARNING:** for performance
     * reasons, the reference returned points to a member of the CPU class. If
     * pre_process_inst() is called again, any previously returned reference will then
     * point to invalid data and can no longer be used (more precisely, it will point to the
     * parameter values of the lastest processed instruction) */
    ProcessedInst& pre_process_inst(const ir::Inst& inst, event::Action& action, MaatEngine& engine)
    {

        processed_inst.reset();

        // TODO: use Value& at least for input values....
        _get_param_value(processed_inst.out, inst.out, engine, true, false);
        event::merge_actions(action, _get_param_value(processed_inst.in0, inst.in[0], engine));
        event::merge_actions(action, _get_param_value(processed_inst.in1, inst.in[1], engine));
        event::merge_actions(action, _get_param_value(processed_inst.in2, inst.in[2], engine));
        return processed_inst;
    }

    /** \brief Compute the value to be assigned to the *output* register of an instruction. This method
     * expects that **pinst** holds the correct values for current input and
     * output parameters (especially, Param::Type::ADDR parameters are expected
     * to have been resolved already by the engine, with the original addresses expressions
     * now residing in the *auxilliary* field of the ::ProcessedInst::Param parameters) \n
     * The method returns a reference to **pinst** */
    ProcessedInst& post_process_inst(const ir::Inst& inst, ProcessedInst& pinst)
    {
        _compute_res_value(pinst.res, inst, pinst);
        return pinst;
    }

    /// Apply the semantics specified by **pinst** for instruction **inst** to the current CPU context
    event::Action apply_semantics(
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
public:
    /// Get the current CPU context
    CPUContext& ctx()
    {
        return _cpu_ctx;
    }

    /// Reset the temporary registers
    void reset_temporaries()
    {
        tmp_ctx.reset();
    }
};

constexpr int max_cpu_regs = 200;

/** \} */ // IR doxygen group
} // namespace ir
} // namespace maat


#endif
