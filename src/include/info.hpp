#ifndef MAAT_INFO_H
#define MAAT_INFO_H

#include "types.hpp"
#include "ir.hpp"
#include "constraint.hpp"
#include "arch.hpp"

namespace maat
{

/// Namespace regrouping classes and types used by the engine to provide various information to the user
namespace info
{

/** \addtogroup engine
* \{ */


/** Reason while the engine stopped running code */
enum class Stop
{
    EVENT, ///< Event callback halted the engine
    BP, ///< Breakpoint was hit // TODO: remove
    SYMBOLIC_PC, ///< Program counter is purely symbolic 
    SYMBOLIC_CODE, ///< Code to execute is purely symbolic
    MISSING_FUNCTION, ///< Calling a function that is neither loaded nor emulated
    MISSING_SYSCALL, ///< Performing a syscall that is not emulated
    EXIT, ///< Program exited
    INST_COUNT, ///< The maximum number of instructions to execute has been reached
    ILLEGAL_INST, ///< The disassembler encountered an illegal instruction
    UNSUPPORTED_INST, ///< The disassembler encountered an instruction that it can not lift
    ARITHMETIC_ERROR, ///< Fatal arithmetic errors in the emulated code (like div by zero)
    ERROR, ///< An error was encountered in the emulated code
    FATAL, ///< A fatal error occured internally within Maat (not the emulated process)
    NONE
};

/// Struct holding information about a register access
typedef struct
{
    ir::reg_t reg; ///< Register that is accessed
    Expr value; ///< Current value of the register
    Expr new_value; ///< Value of the register after access (for reads it is the same as 'value')
    bool written; ///< If the register is written
    bool read; ///< If the register is read
    
    /// Print register access info to a stream
    void print(std::ostream& os, const Arch& arch)
    {
        std::string space("    ");

        if (written and not read)
            os << "Register writen: ";
        else if (read and not written)
            os << "Register read: ";
        else
            os << "Register read & written: ";

        os << "\n" << space << "Reg: " << arch.reg_name(reg) << "\n";
        os << space << "Curr. value: " << value << "\n";
        if (written)
            os << space << "New value " << new_value << "\n";
    }

} RegAccess;


/// Struct holding information about a memory access
typedef struct
{
    Expr addr; ///< Address where memory is accessed
    size_t size; ///< Number of bytes accessed
    Expr value; ///< Value read/written from/to memory
    bool written; ///< If the memory is written
    bool read; ///< If the memory is read
} MemAccess;

/// Print memory access info to a stream
std::ostream& operator<<(std::ostream& os, const MemAccess& mem_access);

// TODO: next could be a simple addr_t
/// Struct holding information about a regular or conditional branch operation
typedef struct
{
    std::optional<bool> taken = std::nullopt; ///< Boolean indicating if the branch is taken or not (it has no value for purely symbolic conditions)
    Constraint cond; ///< Condition for the branch. The branch is taken if the constraint evaluates to True (**warning**: null for unconditional branches)
    Expr target; ///< Target address if the branch is taken (**warning**: null for IR internal branches)
    Expr next; ///< Next instruction if the branch is not taken (**warning**: null for regular branch operation)
} Branch;

/// Print branch info to a stream
std::ostream& operator<<(std::ostream& os, const Branch& branch);

/** \brief This class is used by the engine to make relevant information easily 
 * available to the user when it stops executing emulated code. The accessible
 * information depends on the reason why the engine stopped. For instance if
 * the engine encountered a breakpoint, the class will hold breakpoint related
 * info, e.g register/memory that was read/written, path constraints that was
 * encountered, etc
 * */
class Info
{
public:
    info::Stop stop; ///< Reason why the engine stopped
    std::optional<int> bp_id; ///< ID of the breakpoint hit
    std::optional<std::string> bp_name; ///< Name of the breakpoint hit
    std::optional<addr_t> addr; ///< Address of the instruction where the engine stopped
    // TODO the lifter should give this info std::optional<std::string> inst; ///< ASM of the instruction where the engine stopped (if applicable)
    // TODO bb_start, bb_end: the ir_blocks should give this info...
    std::optional<Branch> branch; ///< Info about branch operation
    std::optional<RegAccess> reg_access; ///< Info about register access
    std::optional<MemAccess> mem_access; ///< Info about memory access
    std::optional<Expr> exit_status; ///< Expression return as the process exit status at program exit
public:
    Info(){this->reset();};
    Info(const Info& other) = default;
    Info& operator=(const Info& other) = default;
    ~Info() = default;
    /// Reset all current information
    void reset()
    {
        // TODO: add other members to reset
        stop = info::Stop::NONE;
        bp_name = std::nullopt;
        addr = std::nullopt;
        branch = std::nullopt;
        exit_status = std::nullopt;
        reg_access = std::nullopt;
        mem_access = std::nullopt;
        bp_id = std::nullopt;
    };
    friend std::ostream& operator<<(std::ostream& os, const Info& info)
    {
        // TODO
        return os;
    };
};

    /** \} */ // doxygen Engine group
} // namespace info

} // namespace maat

#endif
