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
#include "maat/serializer.hpp"

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

// Register aliases setter callback
class CPUContext;
using reg_alias_setter_t = std::function<void(CPUContext&, ir::reg_t, const Value&)>;
using reg_alias_getter_t = std::function<Value(const CPUContext&, ir::reg_t)>;

/** The CPU context in Maat's IR. It is basically
 * a mapping between abstract expressions and CPU registers */
class CPUContext: public serial::Serializable
{
private:
    std::vector<Value> regs;
private:
    reg_alias_getter_t alias_getter;
    reg_alias_setter_t alias_setter;
    std::set<ir::reg_t> aliased_regs;
public:
    CPUContext(int nb_regs);
    CPUContext(const CPUContext& other) = default;
    CPUContext& operator=(const CPUContext& other) = default;
    virtual ~CPUContext() = default;
public:
    /// Initialise special handling of alias registers for the given architecture
    void init_alias_getset(Arch::Type arch);
public:
    /// Assign abstract or concrete expression to register *reg*
    void set(ir::reg_t reg, const Value& value);

    /// Assign abstract expression to register *reg*
    void set(ir::reg_t reg, Expr value);

    /// Assign concrete value to register *reg*
    void set(ir::reg_t reg, cst_t value);
    
    /// Assign concrete value to register *reg*
    void set(ir::reg_t reg, Number&& value);

    /// Assign concrete value to register *reg*
    void set(ir::reg_t reg, const Number& value);

    /// Get current value of register *reg* as an abstract expression
    const Value& get(ir::reg_t reg) const;

private:
    // Internal method that handles setting register aliases
    void _set_aliased_reg(ir::reg_t reg, const Value& val);

public:
    /// Print the CPU context to a stream
    friend std::ostream& operator<<(std::ostream& os, const CPUContext& ctx);
    /// Print the CPU context to a stream with proper register names
    void print(std::ostream& os, const Arch& arch);

public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

/** This class represents a context for temporary registers used in Maat's IR. It is basically
 * a mapping between abstract expressions and temporary registers. It is used internally
 * for executing IR code */
class TmpContext: public serial::Serializable
{
private:
    std::vector<Value> tmps;

public:
    TmpContext() = default;
    TmpContext(const TmpContext& other) = default;
    TmpContext& operator=(const TmpContext& other) = default;
    virtual ~TmpContext() = default;
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
    friend std::ostream& operator<<(std::ostream& os, const TmpContext& ctx);

public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

// Hacky method to get engine.events and avoid the compiler to
// complain that engine is an incomplete type (because cpu.hpp is
// included in engine.hpp)
event::EventManager& get_engine_events(MaatEngine& engine);

/** The CPU is responsible for processing most IR instructions when executing code */
class CPU: public serial::Serializable
{
private:
    CPUContext _cpu_ctx; ///< CPU registers context
    TmpContext tmp_ctx; ///< Temporary values context
private:
    ProcessedInst processed_inst; ///< Processed instruction

public:
    CPU(int nb_regs=0); ///< Constructor
    CPU(const CPU& other) = default;
    CPU& operator=(const CPU& other) = default;
    virtual ~CPU() = default;
private:

    /** \brief Extracts bit field (high_bit and low_bit included) from 'expr'. If
     * the extract extracts the whole expression, then simply returns 'expr'
     * without performing the extract */
    inline Expr _extract_abstract_if_needed(Expr expr, size_t high_bit, size_t low_bit)
    __attribute__((always_inline));


    /** \brief Extracts bit field (high_bit and low_bit included) from 'val'. 'val' is modified
     * **in place**. 
     * Returns a reference to 'val' */
    inline Value _extract_value_bits(const Value& val, size_t high_bit, size_t low_bit)
    __attribute__((always_inline));

    /** \brief Get value of parameter 'param' (extract bits if needed).
     * get_full_register is set to true, the function doesn't truncate the
     * expression if the parameter is a register */
    inline event::Action _get_param_value(
        ProcessedInst::Param& dest,
        const ir::Param& param,
        MaatEngine& engine,
        bool get_full_register = false,
        bool trigger_events = true
    ) __attribute__((always_inline));

    /** \brief Compute value to be assigned to the output parameter
     * for instruction 'inst' (with bit extract/concat if overwriting 
     * only a subset of the output current value). Set value to 'dest'. */
    inline void _compute_res_value(
        Value& dest,
        const ir::Inst& inst,
        ProcessedInst& pinst
    ) __attribute__((always_inline));

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
    ProcessedInst& pre_process_inst(
        const ir::Inst& inst,
        event::Action& action,
        MaatEngine& engine
    );

    /** \brief Compute the value to be assigned to the *output* register of an instruction. This method
     * expects that **pinst** holds the correct values for current input and
     * output parameters (especially, Param::Type::ADDR parameters are expected
     * to have been resolved already by the engine, with the original addresses expressions
     * now residing in the *auxilliary* field of the ::ProcessedInst::Param parameters) \n
     * The method returns a reference to **pinst** */
    ProcessedInst& post_process_inst(const ir::Inst& inst, ProcessedInst& pinst);

    /// Apply the semantics specified by **pinst** for instruction **inst** to the current CPU context
    event::Action apply_semantics(
        const ir::Inst& inst,
        const ProcessedInst& pinst,
        MaatEngine& engine
    );
public:
    /// Get the current CPU context
    CPUContext& ctx();

    /// Reset the temporary registers
    void reset_temporaries();

public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

constexpr int max_cpu_regs = 200;

/** \} */ // IR doxygen group
} // namespace ir
} // namespace maat


#endif
