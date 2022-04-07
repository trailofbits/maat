#ifndef MAAT_INFO_H
#define MAAT_INFO_H

#include "maat/types.hpp"
#include "maat/ir.hpp"
#include "maat/constraint.hpp"
#include "maat/arch.hpp"
#include "maat/value.hpp"
#include "maat/serializer.hpp"

namespace maat
{

/// Namespace regrouping classes and types used by the engine to provide various information to the user
namespace info
{

using serial::bits;
using serial::optional_bits;

/** \addtogroup engine
* \{ */


/** Reason while the engine stopped running code */
enum class Stop
{
    HOOK, ///< Event hook halted the engine
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
struct  RegAccess: public serial::Serializable
{
    ir::reg_t reg; ///< Register that is accessed
    Value value; ///< Current value of the register
    Value new_value; ///< Value of the register after access (for reads it is the same as 'value')
    bool written; ///< If the register is written
    bool read; ///< If the register is read

    RegAccess() = default;
    RegAccess(ir::reg_t reg, const Value& val, const Value& new_val, bool written, bool read)
    :reg(reg), value(val), new_value(new_val), written(written), read(read){}

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
        os << space << "Curr value: " << value << "\n";
        if (written)
            os << space << "New value: " << new_value << "\n";
    }

    virtual uid_t class_uid() const
    {
        return serial::ClassId::REG_ACCESS;
    }

    virtual void dump(serial::Serializer& s) const
    {
        s << bits(reg) << value << new_value << bits(written) << bits(read);
    }

    virtual void load(serial::Deserializer& d)
    {
        d >> bits(reg) >> value >> new_value >> bits(written) >> bits(read);
    }

};


/// Struct holding information about a memory access
struct MemAccess: public serial::Serializable
{
public:
    Value addr; ///< Address where memory is accessed
    size_t size; ///< Number of bytes accessed
    Value value; ///< Value read/written from/to memory
    bool written; ///< If the memory is written
    bool read; ///< If the memory is read

    MemAccess() = default;
    MemAccess(const Value& addr, size_t size, const Value& val, bool written, bool read)
    :addr(addr), size(size), value(val), written(written), read(read){}

    virtual uid_t class_uid() const
    {
        return serial::ClassId::MEM_ACCESS;
    }

    virtual void dump(serial::Serializer& s) const
    {
        s << addr << bits(size) << value << bits(written) << bits(read);
    }

    virtual void load(serial::Deserializer& d)
    {
        d >> addr >> bits(size) >> value >> bits(written) >> bits(read);
    }
};

/// Print memory access info to a stream
std::ostream& operator<<(std::ostream& os, const MemAccess& mem_access);

// TODO: next could be a simple addr_t
/// Struct holding information about a regular or conditional branch operation
struct Branch: public serial::Serializable
{
    std::optional<bool> taken = std::nullopt; ///< Boolean indicating if the branch is taken or not (it has no value for purely symbolic conditions)
    Constraint cond; ///< Condition for the branch. The branch is taken if the constraint evaluates to True (**warning**: null for unconditional branches)
    Value target; ///< Target address if the branch is taken (**warning**: null for IR internal branches)
    Value next; ///< Next instruction if the branch is not taken (**warning**: null for regular branch operation)

    Branch() = default;
    Branch(const std::optional<bool>& taken, const Constraint& cond, const Value& t, const Value& n)
    :taken(taken), cond(cond), target(t), next(n){}

    virtual uid_t class_uid() const
    {
        return serial::ClassId::BRANCH;
    }

    virtual void dump(serial::Serializer& s) const
    {
        s << optional_bits(taken) << cond << target << next;
    }

    virtual void load(serial::Deserializer& d)
    {
        d >> optional_bits(taken) >> cond >> target >> next;
    }
};

/// Print branch info to a stream
std::ostream& operator<<(std::ostream& os, const Branch& branch);

/** \brief This class is used by the engine to make relevant information easily 
 * available to the user when it stops executing emulated code. The accessible
 * information depends on the reason why the engine stopped. For instance if
 * the engine encountered a breakpoint, the class will hold breakpoint related
 * info, e.g register/memory that was read/written, path constraints that was
 * encountered, etc
 * */
class Info: public serial::Serializable
{
public:
    info::Stop stop; ///< Reason why the engine stopped
    // std::optional<int> bp_id; ///< ID of the breakpoint hit
    // std::optional<std::string> bp_name; ///< Name of the breakpoint hit
    std::optional<addr_t> addr; ///< Address of the instruction where the engine stopped
    // TODO the lifter should give this info std::optional<std::string> inst; ///< ASM of the instruction where the engine stopped (if applicable)
    // TODO bb_start, bb_end: the ir_blocks should give this info...
    std::optional<Branch> branch; ///< Info about branch operation
    std::optional<RegAccess> reg_access; ///< Info about register access
    std::optional<MemAccess> mem_access; ///< Info about memory access
    std::optional<Value> exit_status; ///< Expression return as the process exit status at program exit
public:
    Info(){this->reset();};
    Info(const Info& other) = default;
    Info& operator=(const Info& other) = default;
    ~Info() = default;
    /// Reset all current information
    void reset()
    {
        stop = info::Stop::NONE;
        // bp_name = std::nullopt;
        addr = std::nullopt;
        branch = std::nullopt;
        exit_status = std::nullopt;
        reg_access = std::nullopt;
        mem_access = std::nullopt;
        // bp_id = std::nullopt;
    };

    void print(std::ostream& os, const Arch& arch)
    {
        os << "\n";
        if (stop == Stop::NONE)
        {
            // If NONE don't print info
            os << "No info currently set" << std::endl;
            return;
        }

        // Print stop reason
        os << "Stop:       ";
        switch (stop)
        {
            case Stop::HOOK:
                os << "hook halted execution\n";
                break;
            case Stop::MISSING_FUNCTION:
                os << "missing function emulation\n";
                break;
            case Stop::MISSING_SYSCALL:
                os << "missing syscall emulation\n";
                break;
            case Stop::INST_COUNT:
                os << "reached max instruction count\n";
                break;
            case Stop::EXIT:
                os << "program exited\n";
                if (exit_status.has_value())
                    os << "Status:     " << *exit_status << "\n";
                break;
            case Stop::ERROR:
                os << "error in emulated code\n";
                break;
            case Stop::FATAL:
                os << "fatal error in Maat\n";
                break;
            case Stop::SYMBOLIC_PC:
                os << "program counter in symbolic\n";
                break;
            case Stop::SYMBOLIC_CODE:
                os << "code to execute is symbolic\n";
                break;
            default:
                os << "<unknown>";
                break;
        }
       
        if (addr.has_value())
            os << "Addr:       0x" << std::hex << *addr << "\n";
        
        if (branch.has_value())
            os << *branch << "\n";

        if (mem_access.has_value())
            os << *mem_access << "\n";

        if (reg_access.has_value())
            reg_access->print(os, arch);
    };

    virtual uid_t class_uid() const
    {
        return serial::ClassId::INFO;
    }

    virtual void dump(serial::Serializer& s) const
    {
        s << bits(stop) << optional_bits(addr) << branch << reg_access << mem_access << exit_status;
    }

    virtual void load(serial::Deserializer& d)
    {
        d >> bits(stop) >> optional_bits(addr) >> branch >> reg_access >> mem_access >> exit_status;
    }

};

    /** \} */ // doxygen Engine group
} // namespace info

} // namespace maat

#endif
