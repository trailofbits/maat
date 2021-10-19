#ifndef MAAT_BP_H
#define MAAT_BP_H

#include <list>
#include "types.hpp"
#include "info.hpp"
#include "ir.hpp"
#include "cpu.hpp"
#include "arch.hpp"

#ifdef PYTHON_BINDINGS
    #include "Python.h"
#endif

namespace maat
{

class MaatEngine; // Forward declaration

/** \defgroup breakpoint Breakpoints
 * \brief Instrumenting the engine with breakpoints
 * 
 * The MaatEngine can instrument emulated code with breakpoints.
 * Each breakpoint is defined by an event (register read, memory written,
 * branch operation, etc), and is triggered when this event occurs. The 
 * complete list of available events is given by the bp::Event enum class.
 * 
 * Breakpoints can have optional callbacks: those are functions that are
 * executed automatically everytime the breakpoint is triggered. Callbacks
 * must return an action for the engine:
 *   - bp::Action::CONTINUE: continue to execute code
 *   - bp::Action::HALT: stop executing code
 *   - bp::Action::ERROR: indicates that a fatal error happended in the callback and
 *      that the engine should abort execution immediately
 * 
 * By default, breakpoints will not halt the execution. The only possibilities for
 * a breakpoint to halt the engine are:
 *   - One of its callbacks returns bp::Action::HALT
 *   - It has no defined callback
 * 
 * When processing a native instruction in the engine, breakpoints can be triggered
 * at different times:
 *   - Trigger::AFTER: the breakpoint is triggered after the native instruction is executed. This
 *     is by far the most common and is used for almost every event type
 *   - Trigger::BEFORE: the breakpoint is triggered before the native instruction is executed. 
 *     Currently this is used only by Event::ADDR
 *   - Trigger::INSTANT: the breakpoint is triggered and processed on-the-fly, in the middle
 *     of the native instruction processing. More precisely, they are processed before the effects of the IR
 *     instruction that triggered it are applied. Currently, this type is only used for 'PATH' events.
 *     Please note that bp::Trigger::INSTANT breakpoints need to be handled with caution: since they can suspend execution in
 *     the middle of a native instruction, execution should only be resumed by calling 
 *     the engine's 'run()' method, never 'run_from()'. Moreover, bp::Trigger::INSTANT breakpoints callbacks
 *     should access the engine state in a **read-only** fashion, without modifying it, because 
 *     that would otherwise create inconsistencies when terminating to execution the native
 *     instruction.
 * */

/// Namespace regrouping breakpoint related classes and types
namespace bp 
{

/** \addtogroup breakpoint
 * \{ */

/// Events on which a breakpoint can be triggered
enum class Event
{
    /// Executing an instruction in a given address range
    ADDR,
    /// Read a given register
    REG_R,
    /// Write a given register
    REG_W,
    /// A combinaison of Event::REG_R and Event::REG_W
    REG_RW,
    /// Reading memory in a given address range
    MEM_R,
    /// Writing memory in a given address range
    MEM_W,
    /// A combinaison of Event::MEM_R and Event::MEM_W
    MEM_RW,
    /// Reading memory at a symbolic address
    SYMPTR_R,
    /// Writing memory at a symbolic address
    SYMPTR_W,
    /// A combinaison of Event::SYMPTR_R and Event::SYMPTR_W
    SYMPTR_RW,
    /// Performing a branch operation (jmp, call, ret, bl, ...)
    BRANCH,
    /// Performing a conditional branch operation
    CBRANCH,
    /// Reading symbolic/concolic data from register
    TAINTED_REG_R,
    /// Writing symbolic/concolic data to register
    TAINTED_REG_W,
    /// Reading or writing symbolic/concolic data from register
    TAINTED_REG_RW,
    /// Reading symbolic/concolic data from memory
    TAINTED_MEM_R,
    /// Writing symbolic/concolic data to memory
    TAINTED_MEM_W,
    /// Reading or writing symbolic/concolic data from memory
    TAINTED_MEM_RW,
    /// Setting the program counter to a symbolic/concolic value
    TAINTED_PC,
    /** \brief A combinaison of all Event::TAINTED_  events. It basically triggers
     * whenever symbolic/concolic data is used */
    TAINTED_OPERATION,
    /// Encountering a path constraint (conditional branch with symbolic/concolic condition)
    PATH,
    NONE
};

/// Return true if event is Event::REG_R, Event::REG_W, Event::REG_RW
bool is_reg_bp(bp::Event event);
/// Return true if event is Event::MEM_R, Event::MEM_W, or Event::MEM_RW
bool is_mem_bp(bp::Event event);
/// Return true if event neither a Event::REG_ nor a Event::MEM_ nor an Event::ADDR event
bool is_simple_bp(bp::Event event);
/// Return true if event is Event::ADDR
bool is_addr_bp(bp::Event event);
/** \brief Return true if the breakpoint should be triggered before ASM instructions by default.
 * So far only Event::ADDR breakpoints are triggered before instructions */
bool is_before_bp(bp::Event event);
/** \brief Return true if the breakpoint should be triggered and processed on the fly during ASM instructions.
 * So far only Event::PATH breakpoints are triggered instantly instructions */
bool is_instant_bp(bp::Event event);

/*! \public
 * An enum indicating when a breakpoint must be triggered during execution of an instruction
*/
enum class Trigger
{
    /** \brief Trigger breakpoint actions before executing the native instruction
     * that triggers the breakpoint. This is currently used only for Event::ADDR
     * breakpoints */
    BEFORE,
    /** \brief Trigger breakpoint actions after executing the native instruction
     * that triggers the breakpoint. This is currently used for almost all breakpoint events */ 
    AFTER,
    /** \brief Trigger breakpoint actions on-the-fly in the middle of the native
     * instruction that triggers the breakpoint. An Trigger::INSTANT breakpoint can halt the
     * execution but it is important to resume execution with a call to *engine.run()* (not *engine.run_from()*)
     * so that the native instruction finishes to execute properly. Otherwise there will
     * be inconsistencies in the instruction processing. \n
     * Also, the callback(s) for Trigger::INSTANT breakpoints shouldn't modify the engine's state, 
     * because it might cause the native instruction to terminate processing inconsistent values. \n
     * This trigger type is currently used only for Event::PATH */
    INSTANT,
    NONE
};

/// Action returned by breakpoint callbacks for the execution engine
enum class Action
{
    CONTINUE, ///< Continue execution
    HALT, ///< Stop execution
    ERROR ///< An error occured within the callback
};

/// A callback to be executed when a breakpoint is triggered
class BPCallback
{
public:
    /** \typedef native_cb_t 
     * \brief A callback function taking a pointer to  the MaatEngine */
    using native_cb_t = Action (*)(maat::MaatEngine&);
    enum class Type
    {
        NATIVE,
        PYTHON,
        NONE
    };
private:
    BPCallback::Type type;
    native_cb_t native_cb;
public:
    /// Default constructor
    BPCallback();
    /// Create a callback calling a native function
    BPCallback(native_cb_t cb);
    /// Destructor
    ~BPCallback();
public:
    /// Execute callback and return the callback's return value
    Action execute(maat::MaatEngine& engine) const;

// Callbacks from python
#ifdef PYTHON_BINDINGS
public:
    using python_cb_t = PyObject*;
    /// Create a callback calling a python function
    BPCallback(python_cb_t cb);
private:
    python_cb_t python_cb;
#endif
};


class BPManager; // Forward declaration
/// Generic breakpoint base
class BPBase
{
friend BPManager;
protected:
    bp::Event event;
    info::Info _info;
    bool enabled;
    bool triggered;
    std::vector<BPCallback> _callbacks;
    std::string name;
    /// Unique breakpoint identifier
    int _id;
public:
    BPBase(int id, bp::Event event, const std::string& name="");
public:
    /// Return the breakpoint id
    int id();
    /** \brief Get the info associated with the breakpoint. This returned
     * info is set only if the breakpoint was previously triggered */
    const info::Info& info();
    /**  \brief Return **true** if the breakpoint is triggered by the 
     * instruction *inst*, **false** otherwise. If the breapoint is
     * triggered, this method also sets the **info** field in *engine*.
     * This method is used for bp::Trigger::BEFORE breakpoints */
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst);
    /** \brief Return **true** if the breakpoint is triggered by the 
     * instruction *inst*, **false** otherwise. If the breapoint is
     * triggered, this method also sets the **info** field in *engine* */
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
public:
    /// Enable the breakpoint
    void enable();
    /// Disable the breakpoint
    void disable();
    /// Return **true** if breakpoint is enabled
    bool is_enabled();
    /// Return **true** if breakpoint is in triggered state
    bool is_triggered();
    /** \brief Set or reset the triggered state */
    void set_triggered(bool triggered);
public:
    /// Get callbacks registered for the breakpoint
    const std::vector<BPCallback>& callbacks();
    /// Register new native callback to the breakpoint
    void add_callback(BPCallback cb);
    // TODO - python callbacks
public:
    /// Pretty print to stream
    virtual void print(std::ostream& os, const maat::Arch& arch);
public:
};

/// A register access breakpoint
class BPReg: public BPBase
{
private:
    /// Register access to monitor
    reg_t reg;
public:
    /** \brief Create a register breakpoint
     * @param id Unique ID of the breakpoint
     * @param event Trigger the breakpoint when this register event occurs
     * @param name Unique name of the breakpoint
     * @param reg Register to monitor */
    BPReg(int id, bp::Event event, const std::string& name, reg_t reg);
public:
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
    virtual void print(std::ostream& os, const maat::Arch& arch);
};

/// A memory access breakpoint
class BPMem: public BPBase
{
private:
    addr_t addr_min;
    addr_t addr_max;
public:
    /** \brief Create a memory breakpoint monitoring a single address
     * @param id Unique ID of the breakpoint
     * @param event Trigger the breakpoint when this memory event occurs
     * @param name Unique name of the breakpoint
     * @param addr Address to monitor */
    BPMem(int id, bp::Event event, const std::string& name, addr_t addr);
    /** \brief Create a memory breakpoint monitoring a range of addresses
     * @param id Unique ID of the breakpoint
     * @param event Trigger the breakpoint when this memory event occurs
     * @param name Unique name of the breakpoint
     * @param addr_min Lower bound of the range of addresses to monitor (included)
     * @param addr_max Lower bound of the range of addresses to monitor (included) */
    BPMem(int id, bp::Event event, const std::string& name, addr_t addr_min, addr_t addr_max);
public:
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
    virtual void print(std::ostream& os, const maat::Arch& arch);
};

/** \brief A simple event breakpoint. It is used for events such as
 * Event::SYMPTR_R, Event::BRANCH, Event::CBRANCH, etc */
class BPSimple: public BPBase
{
public:
    /** \brief Create a simple breakpoint
     * @param id Unique ID of the breakpoint
     * @param event Trigger the breakpoint when this memory event occurs
     * @param name Unique name of the breakpoint */
    BPSimple(int id, bp::Event event, const std::string& name);
public:
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
    virtual void print(std::ostream& os, const maat::Arch& arch);
};

/// Address breakpoint, triggered when executing code at a given address
class BPAddr: public BPBase
{
private:
    addr_t addr;
public:
    /** \brief Create an address breakpoint
     * @param id Unique ID for the breakpoint
     * @param name Unique name of the breakpoint
     * @param addr The breakpoint is triggered when this address is executed
     */
    BPAddr(int id, const std::string& name, addr_t addr);
public:
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst);
    virtual bool check(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
    virtual void print(std::ostream& os, const maat::Arch& arch);
};

/** \brief The breakpoint manager holds all breakpoints that have been set
 * in the engine. It allows to add/remove/enable/disable breakpoints. It
 * also serves as an interface to check whether breakpoints should be triggered
 * or not given the current executed instruction */
class BPManager
{
public:
    /** \typedef bp_t 
     * \brief Shared pointer to a breakpoint object. We use shared pointers
     * to prevent users to delete pending breakpoints in their callbacks, which
     * would result in having pending breakpoints that have been destroyed in memory.
     * By using shared_ptr we ensure that even if a breakpoint is destroyed by
     * the user it will be accessible by callbacks until automatic breakpoint
     * processing is complete */ 
    using bp_t = std::shared_ptr<BPBase>;
private:
    /// Counter for giving unique IDs to new breakpoints
    int _id_cnt;
private:
    /// A list of all breakpoints in 'before_bps', 'after_bps', and 'instant_bps'
    std::list<bp_t> all_bps;
    /// BEFORE breakpoints
    std::list<bp_t> before_bps;
    /// AFTER breakpoints
    std::list<bp_t> after_bps;
    /// INSTANT breakpoints
    std::list<bp_t> instant_bps;
private:
    /// Pending BEFORE/AFTER breakpoints (they have been triggered)
    std::list<bp_t> _pending_bps;
    /// Pending INSTANT breakpoints (they have been triggered)
    std::list<bp_t> _pending_instant_bps;
public:
    BPManager(); ///< Default constructor
    BPManager(const BPManager& other) = delete;
    BPManager& operator=(const BPManager& other) = delete;
    ~BPManager() = default;
private:
    bool _check(
        MaatEngine& engine, 
        const ir::Inst& inst, 
        const ir::ProcessedInst& pinst,
        std::list<BPManager::bp_t>& bp_list,
        std::list<BPManager::bp_t>& pending_bps
    );
    
private:
    void _remove_in_list(std::list<bp_t>& l, const std::string& bp_name);
    void _remove_in_list(std::list<bp_t>& l, int bp_id);

public:
    /** \brief Check if Trigger::BEFORE breakpoints must be triggered. Returns
     * **true** if at least one breakpoint is triggered */ 
    bool check_before(maat::MaatEngine& engine, const ir::Inst& inst);
    /** \brief Check if Trigger::AFTER breakpoints must be triggered. Returns
     * **true** if at least one breakpoint is triggered */ 
    bool check_after(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
    /** \brief Check if Trigger::INSTANT breakpoints must be triggered. Returns
     * **true** if at least one breakpoint is triggered */ 
    bool check_instant(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst);
public:
    /// Return the breakpoint named *bp_name*, or **nullptr** if the breakpoint doesn't exist
    bp_t get_by_name(const std::string& bp_name);
    /// Return the breakpoint with ID *bp_id*, or **nullptr** if the breakpoint doesn't exist
    bp_t get_by_id(int bp_id);
    /// Get all breakpoints
    const std::list<bp_t>& get_all();
public:
    /** \brief Add a register breakpoint without callbacks
     * @param event Register event, can be Event::REG_R, Event::REG_W, Event::REG_RW
     * @param bp_name Unique name for the breakpoint (optional) */ 
    void add_reg_bp(bp::Event event, reg_t reg, const std::string& bp_name = "");
    /** \brief Add a register breakpoint with a single callback
     * @param event Register event, can be Event::REG_R, Event::REG_W, Event::REG_RW
     * @param callback Callback to execute when the breakpoint is triggered
     * @param reg The register to monitor
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_reg_bp(bp::Event event, BPCallback callback, reg_t reg, const std::string& bp_name = "");
    /** \brief Add a register breakpoint with multiple callbacks
     * @param event Register event, can be Event::REG_R, Event::REG_W, Event::REG_RW
     * @param callbacks List of callbacks to execute when the breakpoint is triggered
     * @param reg The register to monitor
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_reg_bp(bp::Event event, const std::vector<BPCallback>& callbacks, reg_t reg, const std::string& bp_name = "");
    /** \brief Add a memory breakpoint without callbacks
     * @param event Memory event, can be Event::MEM_R, Event::MEM_W, Event::MEM_RW
     * @param addr_min The lower bound of the address range to monitor (included)
     * @param addr_max The higher bound of the address range to monitor (included). If addr_max is zero then the breakoint is only triggered on *addr_min*
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_mem_bp(bp::Event event, addr_t addr_min, addr_t addr_max=0, const std::string& bp_name = "");
    /** \brief Add a memory breakpoint without callbacks
     * @param event Memory event, can be Event::MEM_R, Event::MEM_W, Event::MEM_RW
     * @param callback Callback to execute when the breakpoint is triggered
     * @param addr_min The lower bound of the address range to monitor (included)
     * @param addr_max The higher bound of the address range to monitor (included). If addr_max is zero then the breakoint is only triggered on *addr_min*
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_mem_bp(bp::Event event, BPCallback callback, addr_t addr_min, addr_t addr_max=0, const std::string& bp_name = "");
    /** \brief Add a memory breakpoint with multiple callbacks
     * @param event Memory event, can be Event::MEM_R, Event::MEM_W, Event::MEM_RW
     * @param callbacks List of callbacks to execute when the breakpoint is triggered
     * @param addr_min The lower bound of the address range to monitor (included)
     * @param addr_max The higher bound of the address range to monitor (included). If addr_max is zero then the breakoint is only triggered on *addr_min*
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_mem_bp(bp::Event event, const std::vector<BPCallback>& callbacks, addr_t addr_min, addr_t addr_max=0, const std::string& bp_name = "");
    /** \brief Add a simple breakpoint without callbacks
     * @param event An event that is neither register/memory access, nor an address breakpoint. E.g Event::SYMPTR_*, Event::BRANCH, Event::CBRANCH, Event::PATH
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_bp(bp::Event event, const std::string& bp_name="");
    /** \brief Add a simple breakpoint with a single callback
     * @param event An event that is neither register/memory access, nor an address breakpoint. E.g Event::SYMPTR_*, Event::BRANCH, Event::CBRANCH, Event::PATH
     * @param callback Callback to execute when the breakpoint is triggered
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_bp(bp::Event event , BPCallback callback, const std::string& bp_name="");
    /** \brief Add a simple breakpoint with multiple callbacks
     * @param event An event that is neither register/memory access, nor an address breakpoint. E.g Event::SYMPTR_*, Event::BRANCH, Event::CBRANCH, Event::PATH
     * @param callbacks List of callbacks to execute when the breakpoint is triggered
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_bp(bp::Event event, const std::vector<BPCallback>& callbacks, const std::string& bp_name="");
    /** \brief Add an address breakpoint without callbacks
     * @param addr Trigger the breakpoint when executing code at this address
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_addr_bp(addr_t addr, const std::string& bp_name="");
    /** \brief Add an address breakpoint with a single callback
     * @param addr Trigger the breakpoint when executing code at this address
     * @param callback Callback to execute when the breakpoint is triggered
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_addr_bp(BPCallback callback, addr_t addr, const std::string& bp_name="");
    /** \brief Add an address breakpoint with multiple callbacks
     * @param addr Trigger the breakpoint when executing code at this address
     * @param callbacks List of callbacks to execute when the breakpoint is triggered
     * @param bp_name Unique name for the breakpoint (optional) */
    void add_addr_bp(const std::vector<BPCallback>& callbacks, addr_t addr, const std::string& bp_name="");
public:
    /// Disable a breakpoint by name
    void disable(const std::string& bp_name);
    /// Disable a breakpoint by ID
    void disable(int bp_id);
    /// Disable all breakpoints
    void disable_all();
    /// Remove a breakpoint by name
    void remove(const std::string& bp_name);
    /// Remove a breakpoint by ID
    void remove(int bp_id);
    /// Remove all breakpoints
    void remove_all();
    /// Enable breakpoint by name
    void enable(const std::string& bp_name);
    /// Enable breakpoint by ID
    void enable(int bp_id);
    /** \brief Untrigger all breakpoints of type *type*.
     * If *type* is **Trigger::NONE**, reset all breakpoints */
    void reset_triggers(bp::Trigger type = bp::Trigger::NONE);
public:
    /** \brief Return the list of breakpoints that have been triggered during the
     * last call to check_before() or check_after() */
    const std::list<bp_t>& pending_bps();
    /** \brief Pop a pending breakpoint from the pending breakpoints queue and return it.
     * Return **nullptr** if there are no pending breakpoints */
    bp_t next_pending_bp();
    /// Remove all breakpoints from the pending breakpoints list
    void clear_pending_bps();
public:
    /** \brief Return the list of Trigger::INSTANT breakpoints that have been triggered 
     * during the last call to check_instant(). It is a separate list from 
     * Trigger::BEFORE and Trigger::AFTER breakpoints because Trigger::INSTANT triggers need to be processed
     * on the fly by the engine */
    const std::list<bp_t>& pending_instant_bps();
    /** \brief Pop a pending breakpoint from the pending Trigger::INTANT breakpoints 
     * queue and return it. Return **nullptr** if there are no pending breakpoints. It
     * is a separate list from Trigger::BEFORE and Trigger::AFTER breakpoints because Trigger::INSTANT triggers
     * need to be processed on the fly by the engine */
    bp_t next_pending_instant_bp();
    /** \brief Remove all breakpoints from the pending breakpoints list.
     * It is a separate list from Trigger::BEFORE and Trigger::AFTER breakpoints because 
     * Trigger::INSTANT triggers need to be processed on the fly by the engine */ 
    void clear_pending_instant_bps();
public:
    /// Pretty print breakpoints
    void print(std::ostream& os, const maat::Arch& arch);
private:
    /// Raises a bp_exception if a breakpoint with name 'name' already exists
    void _check_unique_name(const std::string& str);  
    
};

/** \} */ // doxygen Breakpoints group

} // namespace bp
} // namespace maat


#endif
