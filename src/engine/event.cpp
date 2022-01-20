#include "maat/event.hpp"
#include "maat/engine.hpp"

namespace maat
{
namespace event
{
    
Action merge_actions(Action a, Action b)
{
    if (a == Action::ERROR or b == Action::ERROR)
        return Action::ERROR;
    else if (a == Action::HALT or b == Action::HALT)
        return Action::HALT;
    else
        return Action::CONTINUE;
}

bool is_reg_event(Event event)
{
    switch (event)
    {
        case Event::REG_R:
        case Event::REG_W:
        case Event::REG_RW:
            return true;
        default:
            return false;
    }
}

bool is_mem_event(Event event)
{
    switch (event)
    {
        case Event::MEM_R:
        case Event::MEM_W:
        case Event::MEM_RW:
            return true;
        default:
            return false;
    }
}

bool is_simple_event(Event event)
{
    return !is_reg_event(event) and !is_mem_event(event) and !is_exec_event(event);
}

bool is_exec_event(Event event)
{
    return event == Event::EXEC;
}

EventCallback::EventCallback():
    type(EventCallback::Type::NONE),
    native_cb(nullptr)
{
#ifdef PYTHON_BINDINGS
    python_cb = nullptr;
#endif
}

EventCallback::EventCallback(native_cb_t cb):
    type(EventCallback::Type::NATIVE),
    native_cb(cb)
{
#ifdef PYTHON_BINDINGS
    python_cb = nullptr;
#endif
}

#ifdef PYTHON_BINDINGS
EventCallback::EventCallback(python_cb_t cb):
    type(EventCallback::Type::PYTHON),
    native_cb(nullptr),
    python_cb(cb)
{
    Py_XINCREF(python_cb); // Increment python ref count for callback 
}
#endif

EventCallback::EventCallback(const EventCallback& other)
{
    *this = other;
}

EventCallback::EventCallback(EventCallback&& other)
{
    *this = other;
}

EventCallback& EventCallback::operator=(const EventCallback& other)
{
    type = other.type;
    native_cb = other.native_cb;
#ifdef PYTHON_BINDINGS
    python_cb = other.python_cb;
    Py_XINCREF(python_cb);
#endif
    return *this;
}

EventCallback& EventCallback::operator=(EventCallback&& other)
{
    type = other.type;
    native_cb = other.native_cb;
#ifdef PYTHON_BINDINGS
    python_cb = other.python_cb;
    Py_XINCREF(python_cb);
#endif
    return *this;
}

EventCallback::~EventCallback()
{
#ifdef PYTHON_BINDINGS
    Py_XDECREF(python_cb);
    python_cb = nullptr;
#endif
}

bool is_valid_action(int action)
{
    return  action == (int)Action::CONTINUE
            or action == (int)Action::HALT
            or action == (int)Action::ERROR;
}

Action EventCallback::execute(MaatEngine& engine) const
{
    if (type == EventCallback::Type::NATIVE)
    {
        try
        {
            return native_cb(engine);
        }
        catch (const std::exception& e)
        {
            engine.log.error("Caught exception in event callback: ", e.what());
            return Action::ERROR;
        }
    }
    else if (type == EventCallback::Type::PYTHON)
    {
        Action res = Action::CONTINUE;
#ifdef PYTHON_BINDINGS
            // Build args list
            PyObject* argslist = PyTuple_Pack(1, engine.self_python_wrapper_object);
            if( argslist == NULL )
            {
                throw runtime_exception("EventCallback::execute(): failed to create args tuple for python callback");
            }
            Py_INCREF(argslist);
            PyObject* result = PyObject_CallObject(python_cb, argslist);
            Py_DECREF(argslist);
            if (result != NULL)
            {
                if (result == Py_None)
                {
                    res = Action::CONTINUE;
                }
                else if (PyLong_Check(result))
                {
                    int int_res = PyLong_AsLong(result);
                    if (not is_valid_action(int_res))
                    {
                        engine.log.fatal("Python callback didn't return a valid action");
                        res = Action::ERROR;
                    }
                    else
                        res = (Action)int_res;
                }
                else
                {
                    engine.log.fatal("Python callback didn't return a valid action (wrong object type)");
                    res = Action::ERROR;
                }
            }
            else // Callback failed, returned NULL
            {
                // TODO: log error properly
                std::cout << "Error in python callback: ";
                PyErr_Print(); // No PyErr_ print to string in Python's API ???
                PyErr_Clear();
                res = Action::ERROR;
            }
            Py_XDECREF(result);
#endif
            return res;
    }
    else
    {
        throw runtime_exception("EventCallback::execute(): called for unsupported callback type!");
    }
}

EventHook::EventHook(int id, Event event, std::string name, AddrFilter filter, std::string group):
    _id(id),
    event(event),
    name(name),
    filter(filter),
    group(group),
    enabled(true)
{}

int EventHook::id()
{
    return _id;
}

bool EventHook::check_filter(MaatEngine& engine)
{
    if (not filter.is_active())
        return true; // If filter not set, we monitor all addresses by default!

    if (is_mem_event(event))
    {
        if (engine.info.mem_access->addr.is_symbolic(*engine.vars))
            return false;
        else
        {
            addr_t addr = engine.info.mem_access->addr.as_uint(*engine.vars);
            return filter.monitors(addr, addr+engine.info.mem_access->size-1);
        }
    }
    else if (is_exec_event(event))
    {
        return filter.monitors(engine.info.addr.value());
    }

    return true;
}

Action EventHook::trigger(MaatEngine& engine)
{
    Action res = Action::CONTINUE;
    // First filter the event
    if (not check_filter(engine))
    {
        return Action::CONTINUE;
    }
    // If no callbacks, halt
    if (_callbacks.empty())
    {
        return Action::HALT;
    }
    // Hook has callbacks, execute them
    for (const EventCallback& cb : _callbacks)
    {
        engine.info.stop = info::Stop::HOOK;
        switch (cb.execute(engine))
        {
            case Action::CONTINUE:
                break;
            case Action::HALT:
                res = Action::HALT;
                break;
            case Action::ERROR:
                engine.info.reset();
                engine.info.stop = info::Stop::FATAL;
                engine.log.fatal(
                    "EventHook::trigger(): error in event callback for '",
                    name,
                    "'"
                );
                return Action::ERROR;
            default: // Unknown return value for breakpoint...
                engine.info.reset();
                engine.info.stop = info::Stop::FATAL;
                engine.log.fatal(
                    "EventHook::trigger(): event callback for '",
                    name,
                    "' returned unsupported Action value: "
                );
                return Action::ERROR;
        }
    }
    return res;
}

void EventHook::enable()
{
    enabled = true;
}

void EventHook::disable()
{
    enabled = false;
}

bool EventHook::is_enabled()
{
    return enabled;
}

const std::vector<EventCallback>& EventHook::callbacks()
{
    return _callbacks;
}

void EventHook::add_callback(EventCallback cb)
{
    _callbacks.push_back(cb);
}

std::ostream& operator<<(std::ostream& os, const EventHook& h)
{
    os << std::dec << h._id;
    if (not h.name.empty())
        os << "/'" << h.name << "'";
    os << ": ";

    switch (h.event)
    {
        case Event::REG_R:
            os << "Register read"; break;
        case Event::REG_W:
            os << "Register write"; break;
        case Event::REG_RW:
            os << "Register read/write"; break;
        case Event::MEM_R:
            os << "Memory read"; break;
        case Event::MEM_W:
            os << "Memory write"; break;
        case Event::MEM_RW:
            os << "Memory read/write"; break;
        case Event::BRANCH:
            os << "Branch"; break;
        case Event::PATH:
            os << "Path constraint"; break;
        case Event::EXEC:
            os << "Execute"; break;
        default:
            throw runtime_exception("operator<<: got unexpected Event enum value");
    }

    if (h.filter.is_active())
    {
        if (not h.filter.addr_max.has_value())
            os << std::hex << " [0x" << *h.filter.addr_min << ']';
        else
            os << std::hex << " [0x" << *h.filter.addr_min << "-0x" << *h.filter.addr_max << "]";
    }

    if (!h.enabled)
        os << " (disabled)";

    return os;
}


EventManager::EventManager(): _id_cnt(0)
{
    // Initialise hook map
    hook_map = 
    {
        {Event::EXEC, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::REG_R, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::REG_W, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::REG_RW, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::MEM_R, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::MEM_W, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::MEM_RW, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::BRANCH, {{When::BEFORE, {}}, {When::AFTER, {}} }},
        {Event::PATH, {{When::BEFORE, {}}, {When::AFTER, {}} }}
    };
}

void EventManager::disable_group(std::string group)
{
    for (auto& hook : all_hooks)
    {
        if (hook->group == group)
            hook->disable();
    }
}

void EventManager::disable(std::string name)
{
    get_by_name(name)->disable();
}

void EventManager::disable(int id)
{
    get_by_id(id)->disable();
}

void EventManager::disable_all()
{
    for (auto& hook : all_hooks)
        hook->disable();
}

void EventManager::enable_group(std::string group)
{
    for (auto& hook : all_hooks)
    {
        if (hook->group == group)
            hook->enable();
    }
}

void EventManager::enable(std::string name)
{
    get_by_name(name)->enable();
}

void EventManager::enable(int id)
{
    get_by_id(id)->enable();
}


std::ostream& operator<<(std::ostream& os, const EventManager& m)
{
    for (auto& hook : m.all_hooks)
    {
        os << *hook << "\n";
    }
    return os;
}

EventManager::hook_t EventManager::get_by_name(const std::string& name)
{
    for (auto& hook : all_hooks)
        if (hook->name == name)
            return hook;
    throw event_exception(
        Fmt() << "No Hook named: '" << name << "'"
        >> Fmt::to_str
    );
}

EventManager::hook_t EventManager::get_by_id(int id)
{
    for (auto& hook : all_hooks)
        if (hook->id() == id)
            return hook;
    throw event_exception(
        Fmt() << "No Hook with ID: '" << std::dec << id << "'"
        >> Fmt::to_str
    );
}

const std::list<EventManager::hook_t>& EventManager::get_all()
{
    return all_hooks;
}


void EventManager::add(
    event::Event event,
    event::When when,
    std::string name,
    AddrFilter filter,
    std::string group
)
{
    _check_unique_name(name);
    EventManager::hook_t h = std::make_shared<EventHook>(
        _id_cnt++, event,
        name, filter, group
    );
    all_hooks.push_back(h);
    hook_map.at(event).at(when).push_back(h);
}

void EventManager::add(
    event::Event event,
    event::When when,
    EventCallback callback,
    std::string name,
    AddrFilter filter,
    std::string group
)
{
    _check_unique_name(name);
    EventManager::hook_t h = std::make_shared<EventHook>(
        _id_cnt++, event,
        name, filter, group
    );
    h->add_callback(callback);
    all_hooks.push_back(h);
    hook_map.at(event).at(when).push_back(h);
}

void EventManager::add(
    event::Event event,
    event::When when,
    const std::vector<EventCallback>& callbacks,
    std::string name,
    AddrFilter filter,
    std::string group
)
{
    _check_unique_name(name);
    EventManager::hook_t h = std::make_shared<EventHook>(
        _id_cnt++, event,
        name, filter, group
    );
    for (auto& cb : callbacks)
        h->add_callback(cb);
    all_hooks.push_back(h);
    hook_map.at(event).at(when).push_back(h);
}

void EventManager::_check_unique_name(const std::string& str)
{
    if (str.empty())
        return;
    try
    {
        get_by_name(str);
    }
    catch (const event_exception& e)
    { 
        // Hook doesn't exist, we're good
        return;
    }
    // Hook exists, raise exception
    throw event_exception(
        Fmt() << "An event hook named '" << str << "' already exists"
        >> Fmt::to_str
    );
}



std::vector<Event> reg_read_events = {Event::REG_R, Event::REG_RW};
std::vector<Event> reg_write_events = {Event::REG_W, Event::REG_RW};
std::vector<Event> mem_read_events = {Event::MEM_R, Event::MEM_RW};
std::vector<Event> mem_write_events = {Event::MEM_W, Event::MEM_RW};
std::vector<Event> exec_events = {Event::EXEC};

Action EventManager::before_reg_read(MaatEngine& engine, reg_t reg)
{
    engine.info.reg_access = info::RegAccess{
        reg, // reg
        engine.cpu.ctx().get(reg), // value
        engine.cpu.ctx().get(reg), // new_value
        false, // written
        true // read
    };
    return _trigger_hooks(reg_read_events, When::BEFORE, engine);
}

Action EventManager::after_reg_read(
    MaatEngine& engine,
    reg_t reg,
    const ir::ProcessedInst::Param& value
)
{
    engine.info.reg_access = info::RegAccess{
        reg, // reg
        engine.cpu.ctx().get(reg), // value
        engine.cpu.ctx().get(reg), // new_value
        false, // written
        true // read
    };
    return _trigger_hooks(reg_read_events, When::AFTER, engine);
}

Action EventManager::before_reg_write(
    MaatEngine& engine,
    reg_t reg,
    const Value& new_value
)
{
    engine.info.reg_access = info::RegAccess{
        reg, // reg
        engine.cpu.ctx().get(reg), //value
        new_value, // new_value
        true, // written
        false // read
    };
    return _trigger_hooks(reg_write_events, When::BEFORE, engine);
}

Action EventManager::after_reg_write(
    MaatEngine& engine,
    reg_t reg
)
{
    engine.info.reg_access = info::RegAccess{
        reg, // reg
        engine.cpu.ctx().get(reg), // value
        engine.cpu.ctx().get(reg), // new_value
        true, // written
        false // read
    };
    return _trigger_hooks(reg_write_events, When::AFTER, engine);
}

Action EventManager::before_mem_read(
    MaatEngine& engine,
    const Value& addr,
    size_t nb_bytes
)
{
    engine.info.mem_access = info::MemAccess{
        addr, // addr
        nb_bytes, // size
        Value(), // value
        false, // written
        true // read
    };
    return _trigger_hooks(mem_read_events, When::BEFORE, engine);
}

Action EventManager::after_mem_read(
    MaatEngine& engine,
    const Value& addr,
    const Value& value
)
{
    engine.info.mem_access = info::MemAccess{
        addr, // addr
        value.size()/8, // size
        value, // value
        false, // written
        true // read
    };
    return _trigger_hooks(mem_read_events, When::AFTER, engine);
}

Action EventManager::before_mem_write(
    MaatEngine& engine,
    const Value& addr,
    const Value& new_value
)
{
    engine.info.mem_access = info::MemAccess{
        addr, // addr
        new_value.size()/8, // size
        new_value, // value
        true, // written
        false // read
    };
    return _trigger_hooks(mem_write_events, When::BEFORE, engine);
}

Action EventManager::after_mem_write(
    MaatEngine& engine,
    const Value& addr,
    const Value& new_value
)
{
    engine.info.mem_access = info::MemAccess{
        addr, // addr
        new_value.size()/8, // size
        new_value, // value
        true, // written
        false // read
    };
    return _trigger_hooks(mem_write_events, When::AFTER, engine);
}

Action EventManager::before_branch(
    MaatEngine& engine,
    Value target,
    Value next,
    Constraint cond,
    std::optional<bool> taken
)
{
    Action res = Action::CONTINUE;
    engine.info.branch = info::Branch{
        taken, // taken
        cond, // cond
        target, // target
        next // next
    };
    if (cond != nullptr) // engine passes condition only if it is not concrete
        res = _trigger_hooks(Event::PATH, When::BEFORE, engine);
    if (not target.is_none()) // engine passes target only if real branch (not pcode-relative)
        res = merge_actions(res, _trigger_hooks(Event::BRANCH, When::BEFORE, engine));
    return res;
}

Action EventManager::after_branch(
    MaatEngine& engine,
    Value target,
    Value next,
    Constraint cond,
    bool taken
)
{
    Action res = Action::CONTINUE;
    engine.info.branch = info::Branch{
        taken, // taken
        cond, // cond
        target, // target
        next // next
    };
    if (cond != nullptr) // engine passes condition only if it is not concrete
        res = _trigger_hooks(Event::PATH, When::AFTER, engine);
    if (not target.is_none()) // engine passes target only if real branch (not pcode-relative)
        res = merge_actions(res, _trigger_hooks(Event::BRANCH, When::AFTER, engine));
    return res;
}

Action EventManager::before_exec(MaatEngine& engine, addr_t addr)
{
    engine.info.addr = addr;
    return _trigger_hooks(Event::EXEC, When::BEFORE, engine);
}

Action EventManager::after_exec(MaatEngine& engine, addr_t addr)
{
    engine.info.addr = addr;
    return _trigger_hooks(Event::EXEC, When::AFTER, engine);
}

Action EventManager::_trigger_hooks(
    const std::vector<Event>& events,
    When when,
    MaatEngine& engine
)
{
    Action res = Action::CONTINUE;
    for (auto& e : events)
    {
        Action tmp = _trigger_hooks(e, when, engine);
        if (tmp == Action::ERROR)
            return tmp;
        else
            res = merge_actions(res, tmp);
    }
    return res;
}

Action EventManager::_trigger_hooks(Event event, When when, MaatEngine& engine)
{
    Action res = Action::CONTINUE;
    for (EventManager::hook_t& hook : hook_map[event][when])
    {
        if (not hook->is_enabled())
            continue;
        Action tmp = hook->trigger(engine);
        if (tmp == Action::ERROR)
            return tmp;
        else 
            res = merge_actions(res, tmp);
    }
    return res;
}

bool EventManager::has_hooks(const std::vector<Event>& events, When when)
{
    for (auto& e : events)
        if (not hook_map[e][when].empty())
            return true;
    return false;       
}

bool EventManager::has_hooks(Event event, When when)
{
    return not hook_map[event][when].empty();
}

} // namespace event
} // namespace maat
