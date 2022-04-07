#ifndef MAAT_SETTINGS_H
#define MAAT_SETTINGS_H

#include <iostream>
#include "maat/serializer.hpp"

namespace maat
{

/** \addtogroup engine
 * \{ */
 
/** \brief Tweakable settings and options for the engine
 * 
 * Most of the settings can be enabled or disabled by setting it to **true** or **false**.
 * A few others are more fine-grain and can be assigned an arbitrary number (e.g *symptr_max_range*)
 * */
class Settings: public serial::Serializable
{
public:
    // Symbolic execution
    /// Systematically simplify abstract expressions during execution
    bool force_simplify;
    // Environment
    /// Don't stop executing when emulation is missing for an external function
    bool ignore_missing_imports;
    /// Don't stop executing when emulation is missing for a system call
    bool ignore_missing_syscalls;
    // Constraints
    /// Record path constraints in the path manager
    bool record_path_constraints;
    // Symbolic memory
    /// Allow reading memory from fully-symbolic pointers
    bool symptr_read;
    /// Allow writing memory from fully-symbolic pointers
    bool symptr_write;
    /** \brief Assume that symbolic pointers are memory aligned according to the
     * address size. That reduces the number of possible states when reading
     * and writing memory using symbolic pointers */
    bool symptr_assume_aligned;
    /** \brief Arbitrary limit the range of possible values (aka. value set) for
     * symbolic pointers. It results in a memory state that lacks accuracy
     * (states for a pointer value exceeding the range are lost) but makes
     * execution more efficient by drastically reducing the size of memory 
     * expressions. The maximal range size can be specified with the 
     * **symptr_max_range_size** setting */
    bool symptr_limit_range;
    /// Maximal range size for a symbolic pointer value set (see **symptr_limit_range**)
    unsigned int symptr_max_range;
    /** \brief Use the solver to refine the range of possible values (aka. value set)
     * for symbolic pointers. If there are many symbolic memory accesses this can
     * significantly impact runtime performance. The amount of time given to the
     * solver to refine a pointer's range can be tweaked using the
     * **symptr_refine_timeout** setting */
    bool symptr_refine_range;
    /// Timeout in milliseconds for the solver when refining symbolic pointer value sets (see **symptr_refine_range**).
    unsigned int symptr_refine_timeout;
    // I/O
    /// Log every executed instruction
    bool log_insts;
    /// Log every executed syscall/function (whose symbol is known to the engine)
    bool log_calls;
public:
    Settings();
    virtual ~Settings() = default;
    friend std::ostream& operator<<(std::ostream& os, const Settings& settings);
public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

/** \} */ // doxygen Engine group
} // namespace maat
#endif
