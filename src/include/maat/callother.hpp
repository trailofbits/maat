#ifndef MAAT_CALLOTHER_H
#define MAAT_CALLOTHER_H

#include <unordered_map>

namespace maat
{
 // Fwd declarations
class MaatEngine;
namespace ir
{
    class Inst;
    class ProcessedInst;
}

/// Namespace regrouping classes and handlers to deal with the pcode CALLOTHER instruction
namespace callother
{
/** \addtogroup engine
 * \{ */

/// A handler that executes a CALLOTHER occurence properly
typedef std::add_pointer<void(MaatEngine&, const ir::Inst&, ir::ProcessedInst&)>::type handler_t;

/// Unique identifiers for CALLOTHER occurences in the IR
enum class Id
{
    X86_RDTSC, ///< Load the timestamp counter in a register/temporary
    X86_CPUID, ///< CPUID on X86/X64
    X64_SYSCALL, ///< System call on X64
    X86_PMINUB, ///< PMINUB on X86/X64
    X86_INT, ///< INT on X86
    X86_LOCK, ///< LOCK on X86/X64
    UNSUPPORTED
};

/** \brief Return the Id corresponding to the occurence of CALLOTHER in
  * assembly instruction 'mnemonic' */
Id mnemonic_to_id(const std::string& mnemonic, const std::string& arch);

/// A mapping between CALLOTHER occurences and their handler
class HandlerMap
{
public:
    using handler_map_t = std::unordered_map<callother::Id, callother::handler_t>;
private:
    handler_map_t handlers;
public:
    /// Return 'true' if there exist a handler for 'id'
    bool has_handler(Id id);
    /// Return the handler for CALLOTHER occurence 'id'. Return a null pointer if no handler exists
    handler_t get_handler(Id id);
    /// Set the handler for 'id' to 'handler'
    void set_handler(Id id, handler_t handler);
};

/// Return the default handler map for CALLOTHER occurences
HandlerMap default_handler_map();



/** \} */ // End of doxygen group engine
} // namespace callother
} // namespace maat
#endif
