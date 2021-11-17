#ifndef MAAT_CPU_H
#define MAAT_CPU_H

#include <array>
#include <vector>
#include <optional>
#include "expression.hpp"
#include "ir.hpp"
#include "constraint.hpp"
#include "arch.hpp"
#include "event.hpp"
#include "pinst.hpp"

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
template <std::size_t NB_REGS>
class CPUContext
{
private:
    std::array<Expr,NB_REGS> regs_e;
    std::array<Number,NB_REGS> regs_n;

public:
    CPUContext()
    {
        regs_e.fill(nullptr);
    }
    CPUContext(const CPUContext& other) = default;
    CPUContext& operator=(const CPUContext& other) = default;
    ~CPUContext() = default;

public:
    /// Assign abstract or concrete expression to register *reg*
    void set(ir::reg_t reg, const ProcessedInst::param_t& value)
    {
        if (value.is_abstract())
            return set(reg, value.expr);
        else if (value.is_concrete())
            return set(reg, value.number);
        else
            throw runtime_exception("CPUContext::set() got empty parameter!");
    }

    /// Assign abstract expression to register *reg*
    void set(ir::reg_t reg, Expr value)
    {
        int idx(reg);
        try
        {
            if (!value->is_type(ExprType::CST))
                regs_e.at(idx) = value;
            else
            {
                set(reg, value->as_number());
            }
        }
        catch(std::out_of_range)
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
            regs_e.at(idx) = nullptr;
            regs_n.at(idx).set_cst(value);
        }
        catch(std::out_of_range)
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
            regs_e.at(idx) = nullptr;
            regs_n.at(idx) = value;
        }
        catch(std::out_of_range)
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
            regs_e.at(idx) = nullptr;
            regs_n.at(idx) = value;
        }
        catch(std::out_of_range)
        {
            throw ir_exception(Fmt()
                    << "CPUContext: Trying to set register " << std::dec << idx
                    << " which doesn't exist in current context"
                );
        }
    }

    /// Get current value of register *reg* as an abstract expression
    Expr get(ir::reg_t reg) const
    {
        int idx(reg);
        if (is_concrete(reg))
        {
            const Number& val = get_concrete(reg);
            if (val.is_mpz())
                return exprcst(val);
            else
                return exprcst(val.size, val.cst_);
        }

        try
        {
            return regs_e.at(idx);
        }
        catch(std::out_of_range)
        {
            throw ir_exception(Fmt()
                    << "CPUContext: Trying to get register " << std::dec << idx
                    << " which doesn't exist in current context"
                );
        }
    }
    
    /// Get current concrete value of register *reg* (raises an exception if *reg* is not concrete)
    const Number& get_concrete(ir::reg_t reg) const
    {
        int idx(reg);
        if (!is_concrete(reg))
            throw ir_exception(Fmt()
                    << "CPUContext: Trying to get register " << std::dec << idx
                    << " as concrete value but its expression is abstract"
                );
        return regs_n[idx];
    }

    /// Check whether the register's current value is a concrete value
    bool is_concrete(ir::reg_t reg) const
    {
        int idx(reg);
        try
        {
            return regs_e.at(idx) == nullptr;
        }
        catch(std::out_of_range)
        {
            throw ir_exception(Fmt()
                    << "CPUContext: Trying to check register " << std::dec << idx
                    << " which doesn't exist in current context"
                );
        }
    }

    /// Check whether the register's current value is an abstract expression
    bool is_abstract(ir::reg_t reg) const
    {
        return !is_concrete(reg);
    }

public:
    /// Print the CPU context to a stream
    template<size_t T>
    friend std::ostream& operator<<(std::ostream& os, const CPUContext<T>& ctx)
    {
        for (int i = 0; i < ctx.regs_e.size(); i++)
            if (ctx.is_abstract(i))
                os << "REG_" << std::dec << i << ": " << ctx.regs_e[i] << "\n";
            else
                os << "REG_" << std::dec << i << ": " << ctx.regs_n[i] << "\n";
        return os;
    }
    /// Print the CPU context to a stream with proper register names
    void print(std::ostream& os, const Arch& arch)
    {
        for (int i = 0; i < arch.nb_regs; i++)
            if (is_abstract(i))
                os << arch.reg_name(i) << ": " << regs_e[i] << "\n";
            else
                os << arch.reg_name(i) << ": " << regs_n[i] << "\n";
    }
};

/** This class represents a context for temporary registers used in Maat's IR. It is basically
 * a mapping between abstract expressions and temporary registers. It is used internally
 * for executing IR code */
class TmpContext
{
private:
    std::vector<Expr> tmps_e;
    std::vector<Number> tmps_n;

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
    void set(ir::tmp_t tmp, const ProcessedInst::param_t& value); ///< Assign abstract or concrete value to temporary 'tmp'
    void set(ir::tmp_t tmp, Expr value); ///< Assign abstract expression 'value' to temporary 'tmp'
    void set(ir::tmp_t tmp, const Number& value); ///< Assign concrete value 'value' to temporary 'tmp'
    Expr get(ir::tmp_t tmp); ///< Get current value of temporary 'tmp'
    const Number& get_concrete(ir::tmp_t tmp); ///< Get current concrete value of temporary 'tmp'
public:
    bool is_concrete(ir::tmp_t tmp); ///< Return true if 'tmp' currently holds a concrete value
    bool is_abstract(ir::tmp_t tmp); ///< Return true if 'tmp' currently holds an abstract value
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
template <size_t NB_REGS>
class CPU
{
private:
    CPUContext<NB_REGS> _cpu_ctx; ///< CPU registers context
    TmpContext tmp_ctx; ///< Temporary values context
private:
    ProcessedInst processed_inst; ///< Processed instruction

public:
    CPU() = default;
    CPU(const CPU& other) = default;
    CPU& operator=(const CPU& other) = default;
private:
    /** \brief Return 'true' if this instruction assigns a value to
     * the output parameter that entirely replaces its old value (i.e
     * all bits are overwritten */ 
    inline bool _is_param_abstract(const ir::Param& param)
    __attribute__((always_inline))
    {
        return ((param.is_reg() and _cpu_ctx.is_abstract(param.reg()))
                or (param.is_tmp() and tmp_ctx.exists(param.tmp()) and tmp_ctx.is_abstract(param.tmp())));
    }

    /** \brief Return true if at least one of the parameters of the instruction
     * currently holds an abstract value (Expr instance) */
    inline bool uses_abstract_values(const Inst& inst)
    __attribute__((always_inline))
    {
        // Output param counts as a used-abstract value if it's abstract
        // AND not overwritten entirely
        if(
            (inst.out.is_reg() and _cpu_ctx.is_abstract(inst.out.reg())
             and inst.out.size() < _cpu_ctx.get(inst.out.reg())->size)
            or 
            (inst.out.is_tmp() and tmp_ctx.is_abstract(inst.out.tmp())
             and inst.out.size() < tmp_ctx.get(inst.out.tmp())->size)
        )
        {
            return true;
        }
        // Input params count as a used-abstract value if they're abstract
        for (int i = 0; i < 3; i++)
        {
            // We also consider address params to be abstract for non-branch
            // instructions. That's because we'll have to resolve their values
            // in the engine, which will produce 'Expr' values anyway, so the
            // processing is easier if we make everything abstract from here
            if (
                _is_param_abstract(inst.in[i])
                or (inst.in[i].is_addr() and not ir::is_branch_op(inst.op))
            )
                return true;
        }
        return false;
    }

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

    /** \brief Get value of parameter 'param' (extract bits if needed).
     * get_full_register is set to true, the function doesn't truncate the
     * expression if the parameter is a register */
    inline event::Action _get_abstract_param_value(
        ProcessedInst::param_t& dest,
        const ir::Param& param,
        MaatEngine& engine,
        const ir::Inst& inst,
        bool get_full_register = false
    )
    __attribute__((always_inline))
    {
        event::Action action = event::Action::CONTINUE;
        if (param.is_none())
        {
            dest.set_none();
        }
        else if (param.is_cst())
        {
            if (param.size() == sizeof(cst_t)*8)
                dest = exprcst(param.size(), param.cst()); 
            else
                dest = exprcst(param.size(), cst_extract((ucst_t)param.cst(), param.hb, param.lb));
        }
        else if (param.is_addr())
        {
            // Always put addresses as 64 bit expressions because the parameter
            // size deosn't refer to the address size but to the number of bits
            // accessed in memory !
            // FIXME: 64 should be 32 for 32-bit architectures
            dest = exprcst(64, param.addr());
        }
        else if (param.is_tmp())
        {
            if (tmp_ctx.exists(param.tmp()))
            {
                Expr tmp = tmp_ctx.get(param.tmp());
                dest = _extract_abstract_if_needed(tmp, param.hb, param.lb);
            }
            else
            {
                // This tmp variable wasn't created yet
                dest.set_none();
            }
        }
        else if (param.is_reg())
        {
            CPU_HANDLE_EVENT_ACTION(
                get_engine_events(engine).before_reg_read(engine, inst, param.reg()),
                action
            )
            Expr res = _cpu_ctx.get(param.reg());
            if (get_full_register)
            {
                dest = res; // Don't do bit-extract here if because we need the full
                            // current value in order to later compute the full result
                            // to be asigned to the dest register
            }
            else
            {
                dest = _extract_abstract_if_needed(res, param.hb, param.lb);
            }
            CPU_HANDLE_EVENT_ACTION(
                get_engine_events(engine).after_reg_read(engine, inst, param.reg(), dest),
                action
            )
        }
        else
        {
            throw runtime_exception("CPU::_get_abstract_param_value(): got unsupported parameter type");
        }
        return action;
    };

    /** \brief Compute value to be assigned to the output parameter
     * for instruction 'inst' (with bit extract/concat if overwriting 
     * only a subset of the output register) */
    inline void _compute_abstract_res_value(
        ProcessedInst::param_t& res,
        const ir::Inst& inst,
        ProcessedInst& pinst
    )
    __attribute__((always_inline))
    {
        Expr    tmp_res = nullptr,
                in0 = pinst.in0.is_abstract() ? pinst.in0.expr : nullptr,
                in1 = pinst.in1.is_abstract() ? pinst.in1.expr : nullptr;
        Expr tmp, zero;
        int trunc, ext_size;
        Number number;

        switch (inst.op)
        {
            case ir::Op::INT_ADD: 
                tmp_res = in0 + in1;
                break;
            case ir::Op::INT_SUB:
                tmp_res = in0 - in1; 
                break;
            case ir::Op::INT_MULT: 
                tmp_res = in0 * in1;
                break;
            case ir::Op::INT_DIV:
                tmp_res = in0 / in1;
                break;
            case ir::Op::INT_SDIV: 
                tmp_res = sdiv(in0, in1);
                break;
            case ir::Op::INT_REM: 
                tmp_res = in0 % in1; // Unsigned modulo
                break;
            case ir::Op::INT_SREM:
                tmp_res = smod(in0, in1);
            case ir::Op::INT_LEFT:
                tmp_res = shl(in0, in1);
                break;
            case ir::Op::INT_RIGHT: 
                tmp_res = shr(in0, in1);
                break;
            case ir::Op::INT_SRIGHT:
                tmp_res = sar(in0, in1);
                break;
            case ir::Op::INT_AND:
                tmp_res = in0 & in1;
                break;
            case ir::Op::INT_OR:
                tmp_res = in0 | in1;
                break;
            case ir::Op::INT_XOR:
                tmp_res = in0 ^ in1;
                break;
            case ir::Op::INT_2COMP:
                tmp_res = -in0;
                break;
            case ir::Op::INT_NEGATE:
                tmp_res = ~in0;
                break;
            case ir::Op::INT_CARRY:
                // carry is set if result is smaller than one of the operand
                tmp = in0 + in1;
                tmp_res =   ITE(
                    tmp, 
                    ITECond::LT,
                    in0,
                    exprcst(inst.out.size(), 1),
                    ITE(
                        tmp,
                        ITECond::LT,
                        in1,
                        exprcst(inst.out.size(),1),
                        exprcst(inst.out.size(), 0)
                    )
                );
                break;
            case ir::Op::INT_SCARRY:
                // signed carry (i.e overflow) is set if:
                // - (1) both operands are positive and result negative
                // - (2) both operands are negative and result postive
                tmp = in0 + in1;
                zero = exprcst(in0->size, 0);
                tmp_res =   ITE(in0, ITECond::SLT, zero,
                                ITE(in1, ITECond::SLT, zero,
                                    ITE(zero, ITECond::SLE, tmp,
                                        exprcst(inst.out.size(),1), // case (2)
                                        exprcst(inst.out.size(),0)
                                    ),
                                    exprcst(inst.out.size(), 0)
                                ),
                                ITE(zero, ITECond::SLE, in1,
                                    ITE(tmp, ITECond::SLT, zero,
                                        exprcst(inst.out.size(),1), // case (1)
                                        exprcst(inst.out.size(),0)
                                    ),
                                    exprcst(inst.out.size(), 0)
                                )
                            );
                break;
            case ir::Op::INT_SBORROW:
                // signed borrow (i.e overflow) is set when the MSB of
                // both operands is different and result's MSB is the 
                // same as the one of the second operand
                tmp = in0 - in1;
                zero = exprcst(in0->size, 0);
                tmp_res =   ITE(
                    in0, 
                    ITECond::SLT, 
                    zero,
                    ITE(
                        in1, 
                        ITECond::SLT,
                        zero,
                        exprcst(inst.out.size(), 0),
                        ITE(tmp, ITECond::SLT, zero,
                            exprcst(inst.out.size(),0),
                            exprcst(inst.out.size(),1) // in0 < 0, in1 >= 0, tmp >= 0
                        )
                    ),
                    ITE(
                        in1,
                        ITECond::SLT,
                        zero,
                        ITE(tmp, ITECond::SLT, zero,
                            exprcst(inst.out.size(),1), // in0 >= 0, in1 < 0, tmp < 0
                            exprcst(inst.out.size(),0)
                        ),
                        exprcst(inst.out.size(), 0)
                    )
                );
                break;
            case ir::Op::INT_SLESS:
                tmp_res =   ITE(in0, ITECond::SLT, in1,
                                exprcst(inst.out.size(),1),
                                exprcst(inst.out.size(),0)
                            );
                break;
            case ir::Op::INT_EQUAL:
                tmp_res =   ITE(in0, ITECond::EQ, in1,
                                exprcst(inst.out.size(),1),
                                exprcst(inst.out.size(),0)
                            );
                break;
            case ir::Op::INT_NOTEQUAL:
                tmp_res =   ITE(in0, ITECond::EQ, in1,
                                exprcst(inst.out.size(),0),
                                exprcst(inst.out.size(),1)
                            );
                break;
            case ir::Op::INT_LESS:
                tmp_res =   ITE(in0, ITECond::LT, in1,
                                exprcst(inst.out.size(),1),
                                exprcst(inst.out.size(),0)
                            );
                break;
            case ir::Op::INT_LESSEQUAL:
                tmp_res =   ITE(in0, ITECond::LE, in1,
                                exprcst(inst.out.size(),1),
                                exprcst(inst.out.size(),0)
                            );
                break;
            case ir::Op::INT_SLESSEQUAL:
                tmp_res =   ITE(in0, ITECond::SLE, in1,
                                exprcst(inst.out.size(),1),
                                exprcst(inst.out.size(),0)
                            );
                break;
            case ir::Op::COPY:
                tmp_res = in0;
                break;
            case ir::Op::PIECE:
                tmp_res = concat(in0, in1);
                break;
            case ir::Op::POPCOUNT:
                // tmp_res is input lsb
                tmp_res = maat::concat(exprcst(inst.out.size()-1,0), maat::extract(in0, 0, 0));
                // Add other bits
                for (int i = 1; i < in0->size; i++)
                {
                    tmp_res = tmp_res + maat::concat(exprcst(tmp_res->size-1, 0), maat::extract(in0, i, i));
                }
                break;
            case ir::Op::INT_ZEXT:
                tmp_res = maat::concat(
                    exprcst(inst.out.size()-inst.in[0].size(), 0),
                    in0
                );
                break;
            case ir::Op::INT_SEXT:
                ext_size = inst.out.size() - in0->size;
                // Create mask
                if (ext_size > 64)
                {
                    // Need number
                    number.size = ext_size;
                    number.set_mask(ext_size);
                    tmp = exprcst(number);
                }
                else
                {
                    tmp = exprcst(ext_size, cst_mask(ext_size));
                }

                tmp_res = ITE(
                    extract(in0, in0->size-1, in0->size-1),
                    ITECond::EQ,
                    exprcst(1,0),
                    concat(
                        exprcst(ext_size, 0),
                        in0
                    ),
                    concat(
                        tmp,
                        in0
                    )
                );
                break;
            case ir::Op::BOOL_NEGATE:
                // res == (in0 == 0)
                tmp_res = ITE(
                    in0, 
                    ITECond::EQ,
                    exprcst(in0->size, 0),
                    exprcst(inst.out.size(), 1),
                    exprcst(inst.out.size(), 0)
                );
                break;
            case ir::Op::BOOL_AND:
                // res == (in0 != 0 && in1 != 0)
                tmp_res = ITE(
                    in0, 
                    ITECond::EQ,
                    exprcst(in0->size, 0),
                    exprcst(inst.out.size(), 0),
                    ITE(
                        in1,
                        ITECond::EQ,
                        exprcst(in1->size, 0),
                        exprcst(inst.out.size(), 0),
                        exprcst(inst.out.size(), 1)
                    )
                );
                break;
            case ir::Op::BOOL_OR:
                // res == (in0 != 0 || in1 != 0)
                tmp_res = ITE(
                    in0, 
                    ITECond::EQ,
                    exprcst(in0->size, 0),
                    ITE(
                        in1,
                        ITECond::EQ,
                        exprcst(in1->size, 0),
                        exprcst(inst.out.size(), 0),
                        exprcst(inst.out.size(), 1)
                    ),
                    exprcst(inst.out.size(), 1)
                );
                break;
            case ir::Op::BOOL_XOR:
                // res == ((in0 & !in1) || (!in0 & in1))
                tmp_res = ITE(
                    in0, 
                    ITECond::EQ,
                    exprcst(in0->size, 0),
                    ITE(
                        in1,
                        ITECond::EQ,
                        exprcst(in1->size, 0),
                        exprcst(inst.out.size(), 0),
                        exprcst(inst.out.size(), 1)
                    ),
                    ITE(
                        in1,
                        ITECond::EQ,
                        exprcst(in1->size, 0),
                        exprcst(inst.out.size(), 1),
                        exprcst(inst.out.size(), 0)
                    )
                );
                break;
            case ir::Op::SUBPIECE:
                trunc = in1->as_uint()*8; // Number of bits to truncate
                if (inst.out.size() < (in0->size - trunc))
                {
                    tmp_res = extract(
                        in0,
                        trunc + inst.out.size()-1,
                        trunc
                    );
                }
                else if (inst.out.size() == (in0->size - trunc))
                {
                    tmp_res = extract(in0, in0->size-1, trunc);
                }
                else
                {
                    tmp_res = concat(
                        exprcst(inst.out.size() - in0->size + trunc, 0),
                        extract(
                            in0,
                            in0->size-1,
                            trunc
                        )
                    );
                }
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
                tmp_res = nullptr;
                break;
            default:
                throw runtime_exception( Fmt() <<
                    "CPU::_compute_abstract_res_value(): got unsupported IR operation: "
                    << inst.op
                    >> Fmt::to_str
                );
        }

        if (tmp_res == nullptr)
        {
            res.set_none();
        }
        else if (pinst.out.is_abstract() and not inst.out.is_addr())
        {
            res = overwrite_expr_bits(
                      pinst.out.expr,
                      tmp_res,
                      inst.out.hb 
                    );
        }
        else
        {
            res = tmp_res;
        }
    }


    /** \brief Extracts bit field (high_bit and low_bit included) from 'val'. 'val' is modified
     * **in place**. 
     * Returns a reference to 'val' */
    inline void _extract_concrete_if_needed(Number& val, size_t high_bit, size_t low_bit)
    __attribute__((always_inline))
    {
        Number tmp = val;
        if (low_bit != 0 or high_bit != val.size-1)
            val.set_extract(tmp, high_bit, low_bit);
    };

    /** \brief Get value of parameter 'param' (extract bits if needed).
     * get_full_register is set to true, the function doesn't truncate the
     * expression if the parameter is a register */
    inline event::Action _get_concrete_param_value(
        ProcessedInst::param_t& dest,
        const ir::Param& param,
        MaatEngine& engine,
        const ir::Inst& inst,
        bool get_full_register = false
    )
    __attribute__((always_inline))
    {
        Number res(param.size());
        event::Action action = event::Action::CONTINUE;

        if (param.is_none())
        {
            dest.set_none();
        }
        else if (param.is_cst())
        {
            // Manually change type to avoid doing dest = res; which would
            // result in calling Number::operator=(Number&) thus being less performant. 
            // Since this code will be executed a lot of times, we can sacrifice some
            // clarity for performance.
            dest.type = ProcessedInst::Param::Type::CONCRETE;
            dest.number.size = param.size();
            if (param.size() == sizeof(cst_t)*8)
                dest.number.set_cst(param.cst());
            else
                dest.number.set_cst(cst_extract((ucst_t)param.cst(), param.hb, param.lb));
        }
        else if (param.is_addr())
        {
            dest.type = ProcessedInst::Param::Type::CONCRETE;
            // Make number size 64, because the size of the param can also
            // refer to the number of bits accessed, not the size of the address!
            // So address is size 64, and the engine will handle how many bits
            // to read or write later...
            dest.number = Number(64, param.addr());
        }
        else if (param.is_tmp())
        {
            if (tmp_ctx.exists(param.tmp()))
            {
                res = tmp_ctx.get_concrete(param.tmp());
                _extract_concrete_if_needed(res, param.hb, param.lb);
                dest = res;
            }
            else
            {
                dest.set_none();
            }
        }
        else if (param.is_reg())
        {
            CPU_HANDLE_EVENT_ACTION(
                get_engine_events(engine).before_reg_read(engine, inst, param.reg()),
                action
            )
            res = _cpu_ctx.get_concrete(param.reg());
            if (!get_full_register)
            {
                _extract_concrete_if_needed(res, param.hb, param.lb);
            }
            dest = res;
            CPU_HANDLE_EVENT_ACTION(
                get_engine_events(engine).after_reg_read(engine, inst, param.reg(), dest),
                action
            )
        }
        else
        {
            throw runtime_exception("CPU::_get_concrete_param_value(): got unsupported parameter type");
        }
        return action;
    };

    /** \brief Compute value to be assigned to the output parameter
     * for instruction 'inst' (with bit extract/concat if overwriting 
     * only a subset of the output current value). Set value to 'dest'. */
    inline void _compute_concrete_res_value(
        ProcessedInst::param_t& dest,
        const ir::Inst& inst,
        ProcessedInst& pinst
    )
    __attribute__((always_inline))
    {
        int trunc = 0;
        Number tmp_res(inst.out.size()), tmp;
        Number dummy;

        Number& in0 = pinst.in0.is_concrete() ? pinst.in0.number : dummy;
        Number& in1 = pinst.in1.is_concrete() ? pinst.in1.number : dummy;
        Number zero(in0.size, 0), zero1;

        switch (inst.op)
        {
            case ir::Op::INT_ADD: 
                tmp_res.set_add(in0, in1);
                break;
            case ir::Op::INT_SUB:
                tmp_res.set_sub(in0, in1);
                break;
            case ir::Op::INT_MULT: 
                tmp_res.set_mul(in0, in1);
                break;
            case ir::Op::INT_DIV:
                tmp_res.set_div(in0, in1);
                break;
            case ir::Op::INT_SDIV: 
                tmp_res.set_sdiv(in0, in1);
                break;
            case ir::Op::INT_REM: 
                tmp_res.set_rem(in0, in1);
                break;
            case ir::Op::INT_SREM: 
                tmp_res.set_srem(in0, in1);
                break;
            case ir::Op::INT_LEFT: 
                tmp_res.set_shl(in0, in1);
                break;
            case ir::Op::INT_RIGHT: 
                tmp_res.set_shr(in0, in1);
                break;
            case ir::Op::INT_SRIGHT:
                tmp_res.set_sar(in0, in1);
                break;
            case ir::Op::INT_AND:
                tmp_res.set_and(in0, in1);
                break;
            case ir::Op::INT_OR:
                tmp_res.set_or(in0, in1);
                break;
            case ir::Op::INT_XOR:
                tmp_res.set_xor(in0, in1);
                break;
            case ir::Op::INT_2COMP:
                tmp_res.set_neg(in0);
                break;
            case ir::Op::INT_NEGATE:
                tmp_res.set_not(in0);
                break;
            case ir::Op::INT_CARRY:
                // carry is set if result is smaller than one of the operand
                tmp.set_add(in0, in1);
                if (tmp.less_than(in0) or tmp.less_than(in1))
                    tmp_res.set_cst(1);
                else
                    tmp_res.set_cst(0);
                break;
            case ir::Op::INT_SCARRY:
                // signed carry (i.e overflow) is set if:
                // - (1) both operands are positive and result negative
                // - (2) both operands are negative and result postive
                tmp.set_add(in0, in1);
                if (
                    zero.slessequal_than(in0) and
                    zero.slessequal_than(in1) and
                    tmp.sless_than(zero)
                )
                {
                    tmp_res.set_cst(1);
                }
                else if (
                    in0.sless_than(zero) and
                    in1.sless_than(zero) and
                    zero.slessequal_than(tmp)
                )
                {
                    tmp_res.set_cst(1);
                }
                else
                {
                    tmp_res.set_cst(0);
                }
                break;
            case ir::Op::INT_SBORROW:
                // signed borrow (i.e overflow) is set if both input have
                // dfferent MSB and result MSB is identical to the second
                // inputs MSB 
                tmp.set_sub(in0, in1);
                if (
                    zero.slessequal_than(in0) and
                    in1.sless_than(zero) and
                    tmp.sless_than(zero)
                )
                {
                    tmp_res.set_cst(1);
                }
                else if (
                    in0.sless_than(zero) and
                    zero.slessequal_than(in1) and
                    zero.slessequal_than(tmp)
                )
                {
                    tmp_res.set_cst(1);
                }
                else
                {
                    tmp_res.set_cst(0);
                }
                break;
            case ir::Op::INT_SLESS:
                tmp_res.set_cst( in0.sless_than(in1) ? 1 : 0 );
                break;
            case ir::Op::INT_EQUAL:
                tmp_res.set_cst( in0.equal_to(in1) ? 1 : 0 );
                break;
            case ir::Op::INT_NOTEQUAL:
                tmp_res.set_cst( in0.equal_to(in1) ? 0 : 1 );
                break;
            case ir::Op::INT_LESS:
                tmp_res.set_cst( in0.less_than(in1) ? 1 : 0 );
                break;
            case ir::Op::INT_LESSEQUAL:
                tmp_res.set_cst( in0.lessequal_than(in1) ? 1 : 0 );
                break;
            case ir::Op::INT_SLESSEQUAL:
                tmp_res.set_cst( in0.slessequal_than(in1) ? 1 : 0 );
                break;
            case ir::Op::COPY:
                tmp_res = in0;
                break;
            case ir::Op::PIECE:
                tmp_res.set_concat(in0, in1);
                break;
            case ir::Op::POPCOUNT:
                tmp_res.set_popcount(inst.out.size(), in0);
                break;
            case ir::Op::INT_ZEXT:
                tmp_res.set_zext(inst.out.size(), in0);
                break;
            case ir::Op::INT_SEXT:
                tmp_res.set_sext(inst.out.size(), in0);
                break;
            case ir::Op::BOOL_NEGATE:
                zero = Number(in0.size, 0);
                if (in0.equal_to(zero))
                    tmp_res.set(1);
                else
                    tmp_res.set(0);
                break;
            case ir::Op::BOOL_AND:
                zero = Number(in0.size, 0);
                zero1 = Number(in1.size, 0);
                if (
                    in0.equal_to(zero)
                    or in1.equal_to(zero1)
                )
                    tmp_res.set(0);
                else
                    tmp_res.set(1);
                break;
            case ir::Op::BOOL_OR:
                zero = Number(in0.size, 0);
                zero1 = Number(in1.size, 0);
                if (
                    !in0.equal_to(zero)
                    or !in1.equal_to(zero1)
                )
                    tmp_res.set(1);
                else
                    tmp_res.set(0);
                break;
            case ir::Op::BOOL_XOR:
                zero = Number(in0.size, 0);
                zero1 = Number(in1.size, 0);
                if (
                    (!in0.equal_to(zero) and in1.equal_to(zero1))
                    or (in0.equal_to(zero) and !in1.equal_to(zero1))
                )
                    tmp_res.set(1);
                else
                    tmp_res.set(0);
                break;
            case ir::Op::SUBPIECE:
                trunc = in1.get_cst()*8; // Number of bits to truncate
                if (inst.out.size() < (in0.size - trunc))
                {
                    tmp_res.set_extract(
                        in0,
                        trunc + inst.out.size()-1,
                        trunc
                    );
                }
                else if (inst.out.size() == (in0.size - trunc))
                {
                    tmp_res.set_extract(
                        in0,
                        in0.size-1,
                        trunc
                    );
                }
                else
                {
                    tmp_res.set_extract(
                        in0,
                        in0.size-1,
                        trunc
                    );
                    zero = Number(inst.out.size() - tmp_res.size, 0);
                    tmp_res.set_concat(
                        zero,
                        tmp_res
                    );
                }
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
                break;
            default:
                throw runtime_exception( Fmt() <<
                    "CPU::_compute_concrete_res_value(): got unsupported IR operation: "
                    << inst.op
                    >> Fmt::to_str
                );
        }

        if (pinst.out.is_concrete() and not inst.out.is_addr())
        {
            tmp_res.set_overwrite(pinst.out.number, tmp_res, inst.out.lb);
        }

        // Assign result
        dest = tmp_res;
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
        if (uses_abstract_values(inst))
        {
            // If at least one parameter is abstract, get all
            // parameter values as Expr instances
            processed_inst.is_concrete = false;
            _get_abstract_param_value(processed_inst.out, inst.out, engine, inst, true);
            event::merge_actions(action, _get_abstract_param_value(processed_inst.in0, inst.in[0], engine, inst));
            event::merge_actions(action, _get_abstract_param_value(processed_inst.in1, inst.in[1], engine, inst));
            event::merge_actions(action, _get_abstract_param_value(processed_inst.in2, inst.in[2], engine, inst));
        }
        else
        {
            // If all parameters are concrete, get them as Number instances
            processed_inst.is_concrete = true;
            // Except for out parameter for which we need the current value
            // if we want to use it in breakpoint callbacks
            if (_is_param_abstract(inst.out))
                _get_abstract_param_value(processed_inst.out, inst.out, engine, inst, true);
            else
                _get_concrete_param_value(processed_inst.out, inst.out, engine, inst, true);
            event::merge_actions(action, _get_concrete_param_value(processed_inst.in0, inst.in[0], engine, inst));
            event::merge_actions(action, _get_concrete_param_value(processed_inst.in1, inst.in[1], engine, inst));
            event::merge_actions(action, _get_concrete_param_value(processed_inst.in2, inst.in[2], engine, inst));
        }

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
        if (pinst.is_concrete)
        {
            _compute_concrete_res_value(pinst.res, inst, pinst);
        }
        else
        {
            _compute_abstract_res_value(pinst.res, inst, pinst);
        }

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
                CPU_HANDLE_EVENT_ACTION(
                    get_engine_events(engine).before_reg_write(
                        engine,
                        inst,
                        inst.out.reg(),
                        pinst.res
                    ),
                    action
                )
                _cpu_ctx.set(inst.out.reg(), pinst.res);
                CPU_HANDLE_EVENT_ACTION(
                    get_engine_events(engine).after_reg_write(
                        engine,
                        inst,
                        inst.out.reg()
                    ),
                    action
                )
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
    CPUContext<NB_REGS>& ctx()
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
