#ifndef MAAT_EVENT_H
#define MAAT_EVENT_H

#include <list>
#include "types.hpp"
#include "info.hpp"
#include "arch.hpp"
#include "pinst.hpp"

#ifdef PYTHON_BINDINGS
    #include "Python.h"
#endif

namespace maat
{

class MaatEngine; // Forward declaration

/** \defgroup event Events
 * \brief Instrumenting the engine with event subscribers
 * 
 * TODO write doc
 * */

/// Namespace regrouping hook related classes and types
namespace event
{

/** \addtogroup event
 * \{ */
/// Events on which a hook can be triggered
enum class Event
{
    /// Executing an instruction in a given address range
    EXEC,
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
    /// Executing a branch operation (conditional or absolute)
    BRANCH,
    // TODO: 
    //TAINT_PROPAGATION,
    /// Encountering a path constraint (conditional branch with symbolic/concolic condition)
    PATH,
    NONE
};

/// Return true if event is Event::REG_R, Event::REG_W, Event::REG_RW
bool is_reg_event(event::Event event);
/// Return true if event is Event::MEM_R, Event::MEM_W, or Event::MEM_RW
bool is_mem_event(event::Event event);
/// Return true if event neither a Event::REG_ nor a Event::MEM_ nor an Event::ADDR event
bool is_simple_event(event::Event event);
/// Return true if event is Event::EXEC
bool is_exec_event(event::Event event);

/*! \public
 * An enum indicating when callbacks must be triggered
*/
enum class When
{
    /** \brief Trigger callbacks before processing the associated event */
    BEFORE,
    /** \brief Trigger callbacks after processing the associated event */
    AFTER
};

/// Action returned by hook callbacks for the execution engine
enum class Action
{
    CONTINUE, ///< Continue execution
    HALT, ///< Stop execution
    ERROR ///< An error occured within the callback
};

Action merge_actions(Action a, Action b);

/// A callback to be executed on an event
class EventCallback
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
    EventCallback::Type type;
    native_cb_t native_cb;
public:
    /// Default constructor
    EventCallback();
    /// Create a callback calling a native function
    EventCallback(native_cb_t cb);
    EventCallback(const EventCallback& other);
    EventCallback& operator=(const EventCallback& other);
    EventCallback(EventCallback&& other);
    EventCallback& operator=(EventCallback&& other);
    /// Destructor
    ~EventCallback();
public:
    /// Execute callback and return the callback's return value
    Action execute(maat::MaatEngine& engine) const;

// Callbacks from python
#ifdef PYTHON_BINDINGS
public:
    using python_cb_t = PyObject*;
    /// Create a callback calling a python function
    EventCallback(python_cb_t cb);
private:
    python_cb_t python_cb;
#endif
};

/// Filter addresses to monitor
class AddrFilter
{
public:
    /// The lower bound of the address range to monitor (included)
    std::optional<addr_t> addr_min;
    /// The higher bound of the address range to monitor (included)
    std::optional<addr_t> addr_max;
    /// Create a filter monitoring an address range
    AddrFilter(
        std::optional<addr_t> addr_min = std::nullopt,
        std::optional<addr_t> addr_max = std::nullopt
    ): addr_min(addr_min), addr_max(addr_max){};
    /// Return true if 'addr' is monitored
    bool monitors(addr_t addr)
    {
        if (not addr_min)
            return false;
        else if (addr_max)
            return addr >= *addr_min and addr <= *addr_max;
        else
            return addr == *addr_min;
    };
    /// Return true if any address between '_min' and '_max' (both included) is monitored
    bool monitors(addr_t _min, addr_t _max)
    {
        if (not addr_min)
            return false;
        else if (addr_max)
            return _max >= *addr_min and _min <= *addr_max;
        else
            return *addr_min >= _min and *addr_min <= _max;
    };
};

class EventManager; // Forward declaration
/// Generic hook base
class EventHook
{
friend EventManager;
public:
    std::string group;
    std::string name;
protected:
    Event event;
    bool enabled;
    std::vector<EventCallback> _callbacks;
    /// Unique hook identifier
    int _id;
    /// Filter
    AddrFilter filter;
public:
    EventHook(
        int id,
        Event event,
        std::string name="",
        AddrFilter filter=AddrFilter(),
        std::string group=""
    );
    ~EventHook() = default;
public:
    /// Return the hook id
    int id();
    /** \brief Execute all callbacks and return an action for the emulation engine */
    Action trigger(MaatEngine& engine);
public:
    /// Enable the hook
    void enable();
    /// Disable the hook
    void disable();
    /// Return 'true' if hook is enabled
    bool is_enabled();
public:
    /// Get callbacks registered for the hook
    const std::vector<EventCallback>& callbacks();
    /// Register new native callback to the hook
    void add_callback(EventCallback cb);
public:
    /// Pretty print to stream
    void print(std::ostream& os, const Arch& arch);
private:
    /// Return true if the filter allows the hook to be triggered
    bool check_filter(MaatEngine& engine);
};

/** \brief The event manager holds all hooks that have been set
 * in the engine. It allows to add/remove/enable/disable hooks. It
 * also serves as an interface to check whether hooks should be triggered
 * or not given the current executed instruction */
class EventManager
{
public:
    /** \typedef hook_t 
     * \brief Shared pointer to a hook object. We use shared pointers
     * to prevent users to delete pending hooks in their callbacks, which
     * would result in having pending hooks that have been destroyed in memory.
     * By using shared_ptr we ensure that even if a hook is destroyed by
     * the user it will be accessible by callbacks until automatic hook
     * processing is complete */ 
    using hook_t = std::shared_ptr<EventHook>;
private:
    /// Counter for giving unique IDs to new hooks
    int _id_cnt;
private:
    /// A list of all hooks
    std::list<hook_t> all_hooks;
    using when_map_t = std::unordered_map<When, std::list<hook_t>>;
    using hook_map_t = std::unordered_map<Event, when_map_t>;
    hook_map_t hook_map;
public:
    EventManager(); ///< Default constructor
    EventManager(const EventManager& other) = delete;
    EventManager& operator=(const EventManager& other) = delete;
    ~EventManager() = default;
public:
    // Reg events
    Action before_reg_read(MaatEngine& engine, const ir::Inst& inst, reg_t reg);
    Action after_reg_read(MaatEngine& engine, const ir::Inst& inst, reg_t reg, const ir::ProcessedInst::Param& value);
    Action before_reg_write(MaatEngine& engine, const ir::Inst& inst, reg_t reg, const ir::ProcessedInst::Param& new_value);
    Action after_reg_write(MaatEngine& engine, const ir::Inst& inst, reg_t reg);
    // Mem events
    Action before_mem_read(MaatEngine& engine, const ir::Inst& inst, Expr addr, size_t nb_bytes);
    Action after_mem_read(MaatEngine& engine, const ir::Inst& inst, Expr addr, Expr value);
    Action before_mem_write(MaatEngine& engine, const ir::Inst& inst, Expr addr, Expr new_value);
    Action after_mem_write(MaatEngine& engine, const ir::Inst& inst, Expr addr, Expr new_value);
    // Branch
    Action before_branch(MaatEngine& engine, const ir::Inst& inst, Expr target, addr_t next, Constraint cond=nullptr);
    Action after_branch(MaatEngine& engine, const ir::Inst& inst, Expr target, addr_t next, Constraint cond=nullptr, bool taken=true);
    // Exec
    Action before_exec(MaatEngine& engine, addr_t addr);
    Action after_exec(MaatEngine& engine, addr_t addr);
private:
    /// Return true if there is a least one enabled hook for the given event
    bool has_enabled_hook(Event event, When when);
public:
    /// Return the hook with name *name*, or **nullptr** if the hook doesn't exist
    hook_t get_by_name(const std::string& name);
    /// Return the hook with ID *id*, or **nullptr** if the hook doesn't exist
    hook_t get_by_id(int id);
    /// Get all hooks
    const std::list<hook_t>& get_all();
public:
    /** \brief Hook an event without callbacks
     * @param event Event to monitor
     * @param when When to trigger the hook
     * @param name hook unique name (optional)
     * @param filter Address filter (optional)
     * @param group hook group (optional) */
    void add(
        event::Event event,
        event::When when,
        std::string name="",
        AddrFilter filter=AddrFilter(),
        std::string group = ""
    );
    /** \brief Add an event hook with a single callback
     * @param event Event to monitor
     * @param when When to trigger the hook
     * @param callback Callback to execute when the hook is triggered
     * @param name hook unique name (optional)
     * @param filter Address filter (optional)
     * @param group hook group (optional) */
    void add(
        event::Event event,
        event::When when,
        EventCallback callback,
        std::string name="",
        AddrFilter filter=AddrFilter(),
        std::string group = ""
    );
    /** \brief Add an event hook with multiple callbacks
     * @param event Event to monitor
     * @param when Indicates whether to trigger the hook before of after the event
     * @param callbacks List of callbacks to execute when the hook is triggered
     * @param name hook unique name (optional)
     * @param filter Address filter (optional)
     * @param group hook group (optional) */
    void add(
        event::Event event,
        event::When when,
        const std::vector<EventCallback>& callbacks,
        std::string name="",
        AddrFilter filter=AddrFilter(),
        std::string group = ""
    );

public:
    /// Disable a hook by name
    void disable(std::string name);
    /// Disable all hooks in 'group'
    void disable_group(std::string group);
    /// Disable a hook by ID
    void disable(int id);
    /// Disable all hooks
    void disable_all();
    /// Enable a hook by name
    void enable(std::string name);
    /// Enable all hooks in 'group'
    void enable_group(std::string group);
    /// Enable hook by ID
    void enable(int id);
public:
    /// Pretty print hooks
    void print(std::ostream& os, const Arch& arch); 
private:
    /// Raises a event_exception if a hook with name 'name' already exists
    void _check_unique_name(const std::string& str);
    inline Action _trigger_hooks(
        const std::vector<Event>& events,
        When when,
        MaatEngine& engine
    ) __attribute__((always_inline));
    inline Action _trigger_hooks(
        Event event,
        When when,
        MaatEngine& engine
    ) __attribute__((always_inline));
};

/** \} */ // doxygen hooks group

} // namespace bp
} // namespace maat


#endif
