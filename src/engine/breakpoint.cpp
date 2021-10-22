#include "breakpoint.hpp"
#include "engine.hpp"

namespace maat
{
namespace bp
{
    
bool is_reg_bp(bp::Event event)
{
    switch (event)
    {
        case bp::Event::REG_R:
        case bp::Event::REG_W:
        case bp::Event::REG_RW:
            return true;
        default:
            return false;
    }
}

bool is_mem_bp(bp::Event event)
{
    switch (event)
    {
        case bp::Event::MEM_R:
        case bp::Event::MEM_W:
        case bp::Event::MEM_RW:
            return true;
        default:
            return false;
    }
}

bool is_simple_bp(bp::Event event)
{
    return !is_reg_bp(event) and !is_mem_bp(event) and !is_addr_bp(event);
}

bool is_addr_bp(bp::Event event)
{
    return event == bp::Event::ADDR;
}

bool is_before_bp(bp::Event event)
{
    switch (event)
    {
        case bp::Event::ADDR:
            return true;
        default:
            return false;
    }
}

bool is_instant_bp(bp::Event event)
{
    switch (event)
    {
        case bp::Event::PATH:
            return true;
        default:
            return false;
    }
}

BPCallback::BPCallback():
    type(BPCallback::Type::NONE),
    native_cb(nullptr)
{
#ifdef PYTHON_BINDINGS
    python_cb = nullptr;
#endif
}

BPCallback::BPCallback(native_cb_t cb):
    type(BPCallback::Type::NATIVE),
    native_cb(cb)
{
#ifdef PYTHON_BINDINGS
    python_cb = nullptr;
#endif
}

#ifdef PYTHON_BINDINGS
BPCallback::BPCallback(python_cb_t cb):
    type(BPCallback::Type::PYTHON),
    native_cb(nullptr),
    python_cb(cb)
{
    Py_XINCREF(python_cb); // Increment python ref count for callback 
}
#endif

BPCallback::BPCallback(const BPCallback& other)
{
    *this = other;
}

BPCallback::BPCallback(BPCallback&& other)
{
    *this = other;
}

BPCallback& BPCallback::operator=(const BPCallback& other)
{
    type = other.type;
    native_cb = other.native_cb;
#ifdef PYTHON_BINDINGS
    python_cb = other.python_cb;
    Py_XINCREF(python_cb);
#endif
    return *this;
}

BPCallback& BPCallback::operator=(BPCallback&& other)
{
    type = other.type;
    native_cb = other.native_cb;
#ifdef PYTHON_BINDINGS
    python_cb = other.python_cb;
    Py_XINCREF(python_cb);
#endif
    return *this;
}

BPCallback::~BPCallback()
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

Action BPCallback::execute(MaatEngine& engine) const
{
    if (type == BPCallback::Type::NATIVE)
    {
        try
        {
            return native_cb(engine);
        }
        catch (const std::exception& e)
        {
            // TODO set error
            return Action::ERROR;
        }
    }
    else if (type == BPCallback::Type::PYTHON)
    {
        Action res = Action::CONTINUE;
#ifdef PYTHON_BINDINGS
            // Build args list
            PyObject* argslist = PyTuple_Pack(1, engine.self_python_wrapper_object);
            if( argslist == NULL )
            {
                throw runtime_exception("BPCallback::execute(): failed to create args tuple for python callback");
            }
            Py_INCREF(argslist);
            PyObject* result = PyObject_CallObject(python_cb, argslist);
            Py_DECREF(argslist);
            if (result != NULL)
            {
                if (PyLong_Check(result))
                {
                    int int_res = PyLong_AsLong(result);
                    if (not is_valid_action(int_res))
                    {
                        // TODO log ERROR
                        res = Action::ERROR;
                    }
                    else
                        res = (Action)int_res;
                }
                else
                {
                    // TODO log error returned wrong value
                    res = Action::ERROR;
                }
            }
            else // Callback failed, returned NULL
            {
                // TODO handle/log error
                std::cout << "Error in python callback: ";
                PyErr_Print(); // PyErr_ print to string ???
                PyErr_Clear();
                res = Action::ERROR;
            }
            Py_XDECREF(result);
#endif
            return res;
    }
    else
    {
        throw runtime_exception("BPCallback::execute(): called for unsupported callback type!");
    }
}

BPBase::BPBase(int id, bp::Event e, const std::string& n):
    _id(id),
    event(e),
    name(n),
    enabled(true)
{}

int BPBase::id()
{
    return _id;
}

const info::Info& BPBase::info()
{
    return _info;
}

bool BPBase::check(MaatEngine& engine, const ir::Inst& inst)
{
    throw runtime_exception("BPBase::check(): shouldn't be called from base class!");
}

bool BPBase::check(MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    throw runtime_exception("BPBase::check(): shouldn't be called from base class!");
}

void BPBase::enable()
{
    enabled = true;
}

void BPBase::disable()
{
    enabled = false;
}

bool BPBase::is_triggered()
{
    return triggered;
}

bool BPBase::is_enabled()
{
    return enabled;
}

const std::vector<BPCallback>& BPBase::callbacks()
{
    return _callbacks;
}

void BPBase::add_callback(BPCallback cb)
{
    _callbacks.push_back(cb);
}

void BPBase::set_triggered(bool _triggered)
{
    triggered = _triggered;
    if (not triggered)
        _info.reset();
}

void BPBase::print(std::ostream& os, const maat::Arch& arch)
{
    throw runtime_exception("BPBase::check(): shouldn't be called from base class!");
}

BPReg::BPReg(int id, bp::Event event, const std::string& name, reg_t r): 
    BPBase(id, event, name),
    reg(r)
{}

bool BPReg::check(MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    if (event == bp::Event::REG_R or event == bp::Event::REG_RW)
    {
        if (inst.reads_reg(reg))
        {
            _info.reg_access = info::RegAccess{
                reg, // reg
                engine.cpu.ctx().get(reg), // old_value
                engine.cpu.ctx().get(reg), // new_value
                false, // written
                true // read
            };
            triggered = true;
        }
    }

    if (event == bp::Event::REG_W or event == bp::Event::REG_RW)
    {
        if (inst.writes_reg(reg))
        {
            // Create reg_access if not already created
            if (!_info.reg_access.has_value())
            {
                _info.reg_access = info::RegAccess{
                    reg,
                    engine.cpu.ctx().get(reg), // old_value
                    pinst.res.as_expr(), // new_value
                    true, // written
                    false // read
                };
            }
            else // else add additional info to current reg_access
            {
                _info.reg_access->written = true;
                _info.reg_access->new_value = pinst.res.as_expr();
            }
            triggered = true;
        }
    }
    if (triggered)
    {
        // Add other info and return
        _info.stop = info::Stop::BP;
        _info.bp_id = _id;
        if (!name.empty())
            _info.bp_name = name;
        _info.addr = inst.addr;
    }
    return triggered;
}

void BPReg::print(std::ostream& os, const maat::Arch& arch)
{
    os << std::dec << _id;
    if (!name.empty())
        os << "/" << name;
    os << ": ";

    switch (event)
    {
        case bp::Event::REG_R:
            os << "Read "; break;
        case bp::Event::REG_W:
            os << "Write "; break;
        case bp::Event::REG_RW:
            os << "Read/Write "; break;
        default:
            throw runtime_exception("BPReg::print(): got unexpected breakpoint event!");
    }
    os << arch.reg_name(reg);
    os << " ";
        
    if (!enabled)
        os << " (disabled)";
}


BPMem::BPMem(int id, bp::Event event, const std::string& name, addr_t addr):
    BPBase(id, event, name),
    addr_min(addr),
    addr_max(addr)
{}

BPMem::BPMem(int id, bp::Event event, const std::string& name, addr_t min, addr_t max):
    BPBase(id, event, name),
    addr_min(min),
    addr_max(max)
{}

bool BPMem::check(MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    Expr old_value, new_value;
    addr_t concrete_addr_min, concrete_addr_max;

    if (event == bp::Event::MEM_R or event == bp::Event::MEM_RW)
    {
        for (int i = 0; i < 3; i++)
        {
            if (inst.in[i].is_addr())
            {
                const Expr& addr_expr = pinst.in(i).auxilliary;
                // get concrete address
                if (addr_expr->is_symbolic(*engine.vars))
                    continue;
                concrete_addr_min = addr_expr->as_uint(*engine.vars);
                concrete_addr_max = concrete_addr_min + (inst.in[i].size()/8) -1;
            }
            else if (inst.op == ir::Op::LOAD and i == 1)
            {
                const Expr& addr_expr = pinst.in1.auxilliary;
                // get concrete address
                if (addr_expr->is_symbolic(*engine.vars))
                    continue;
                concrete_addr_min = addr_expr->as_uint(*engine.vars);
                concrete_addr_max = concrete_addr_min + (inst.out.size()/8) -1;
            }
            else
            {
                continue;
            }
            // Check if address falls in range
            if (concrete_addr_min > addr_max or concrete_addr_max < addr_min)
                continue;

            // Trigger breakpoint
            old_value = pinst.in(i).as_expr();
            new_value = old_value;

            _info.mem_access = info::MemAccess{
                pinst.in(i).auxilliary, // addr
                inst.out.size()/8, // size
                old_value,
                new_value,
                false, // written
                true // read
            };
            triggered = true;
            break;
        }
    }
    
    // If not already triggered, check for memory writes
    if (
        not triggered
        and (event == bp::Event::MEM_W or event == bp::Event::MEM_RW)
    )
    {
        Expr addr_expr;
        // Get concrete address and value to write
        if (inst.op == ir::Op::STORE)
        {
            addr_expr = pinst.in1.as_expr();
            new_value = pinst.in2.as_expr();
            // Get concrete address
            if (addr_expr->is_symbolic(*engine.vars))
                return false;
        }
        else if (ir::is_assignment_op(inst.op) and inst.out.is_addr())
        {
            addr_expr = pinst.out.as_expr();
            new_value = pinst.in0.as_expr();
        }
        else
        {
            return false;
        }
        concrete_addr_min = addr_expr->as_uint(*engine.vars);
        concrete_addr_max = concrete_addr_min + (new_value->size/8) -1;
        // Check if address in monitored range
        if (concrete_addr_min <= addr_max and concrete_addr_max >= addr_min)
        {
            try
            {
                old_value = engine.mem->read(addr_expr, new_value->size/8);
            }
            catch (mem_exception& e)
            {
                throw bp_exception("BPMem::check() memory engine threw exception when getting old_value for STORE operation");
            }
            _info.mem_access = info::MemAccess{
                addr_expr, // addr
                new_value->size/8, // size
                old_value,
                new_value,
                true, // written
                false // read
            };
            triggered = true;
        }
    }

    if (triggered)
    {
        // Add other info and return
        _info.stop = info::Stop::BP;
        _info.bp_id = _id;
        if (!name.empty())
            _info.bp_name = name;
        _info.addr = inst.addr;
    }
    return triggered;
}

void BPMem::print(std::ostream& os, const maat::Arch& arch)
{
    os << std::dec << _id;
    if (!name.empty())
        os << "/" << name;
    os << ": ";
    
    switch (event)
    {
        case bp::Event::MEM_R:
            os << "Read @"; break;
        case bp::Event::MEM_W:
            os << "Write @"; break;
        case bp::Event::MEM_RW:
            os << "Read/Write @"; break;
        default:
            throw runtime_exception("BPReg::print(): got unexpected breakpoint event!");
    }
    if (addr_min == addr_max)
        os << std::hex << "0x" << addr_min;
    else
        os << std::hex << "[0x" << addr_min << "-0x" << addr_max << "]";
    os << " ";
        
    if (!enabled)
        os << " (disabled)";
}

BPSimple::BPSimple(int id, bp::Event event, const std::string& name): BPBase(id, event, name)
{}

bool BPSimple::check(MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    // symbolic pointer read
    if (event == bp::Event::SYMPTR_R or event == bp::Event::SYMPTR_RW)
    {
        Expr addr_expr;
        for (int i = 0; i < 3; i++)
        {
            if (inst.in[i].is_addr())
            {
                addr_expr = pinst.in(i).auxilliary;
            }
            else if (inst.op == ir::Op::LOAD and i == 1)
            {
                addr_expr = pinst.in1.auxilliary;
            }
            else
            {
                continue;
            }
            // Trigger if address is symbolic/concolic
            if (!addr_expr->is_concrete(*engine.vars))
            {
                Expr old_value = pinst.in(i).as_expr();
                Expr new_value = old_value;

                _info.mem_access = info::MemAccess{
                    addr_expr, // addr
                    inst.out.size()/8, // size
                    old_value,
                    new_value,
                    false, // written
                    true // read
                };
                triggered = true;
                break;
            }
        }
    }
    
    // symbolic pointer write
    if (
        not triggered
        and (event == bp::Event::SYMPTR_W or event == bp::Event::SYMPTR_RW)
    )
    {
        if (inst.op == ir::Op::STORE)
        {
            Expr addr_expr = pinst.in1.as_expr();

            // If address is symbolic, 
            if (!addr_expr->is_concrete(*engine.vars))
            {
                Expr new_value = pinst.in2.as_expr();
                _info.mem_access = info::MemAccess{
                    addr_expr, // addr
                    inst.in[2].size()/8, // size
                    nullptr, // old_value, unknown
                    new_value,
                    true, // written
                    false // read
                };
                triggered = true;
            }
        }
    }
    
    // branch and conditional branch
    if (
        (event == bp::Event::BRANCH or event == bp::Event::CBRANCH)
        and ir::is_branch_op(inst.op)
    )
    {
        // Process conditional branches for BRANCH and CBRANCH events
        if (inst.op == ir::Op::CBRANCH)
        {
            // Check that not pcode relative
            if (not inst.in[0].is_cst())
            {
                // Get target
                Expr target = pinst.in0.as_expr();
                // It's a 'real' branch only if not branching to current or next instruction
                if (
                    target->is_symbolic(*engine.vars)
                    or (
                        target->as_uint(*engine.vars) != inst.addr
                        and target->as_uint(*engine.vars) != inst.addr+inst.size
                    )
                )
                {
                    Expr cond_expr = pinst.in1.as_expr();
                    std::optional<bool> taken = cond_expr->is_symbolic(*engine.vars) ?
                        std::nullopt : std::make_optional<bool>(cond_expr->as_uint(*engine.vars) != 0);
                    _info.branch = info::Branch{
                        taken, // taken
                        (Constraint)(cond_expr != 0), // cond
                        target, // target
                        exprcst(target->size, inst.addr+inst.size) // next  
                    };
                    triggered = true;
                }
            }
        }
        // Process unconditional branches only for BRANCH event
        else if (event == bp::Event::BRANCH)
        {
            // Trigger if :
            // - native branch (ignore pcode relative branching)
            // - (AND) we branch to an instruction that is not the current one
            
            // Get target
            Expr target = nullptr;
            switch (inst.op)
            {
                case ir::Op::CALL: // Equivalent to branch
                case ir::Op::BRANCH:
                    if (inst.in[0].is_cst()) // internal pcode branch
                    {
                        target = nullptr;
                    }
                    else // address, native branch
                    {
                        target = pinst.in0.as_expr();
                    }
                    break;
                case ir::Op::RETURN: // Equivalent to branchind
                case ir::Op::CALLIND: // Equivalent to branchind
                case ir::Op::BRANCHIND:
                    target = pinst.in0.as_expr();
                    break;
                default:
                    throw runtime_exception("BPSimple::check(): While checking BRANCH/CBRANCH event, got unexptected branch operation!");
            }
            // Check only if target != NULL (so not a pcode branch)
            if (target)
            {
                // It's a 'real' branch only if not branching to current or next instruction
                if (
                    target->is_symbolic(*engine.vars)
                    or (
                        target->as_uint(*engine.vars) != inst.addr
                        and target->as_uint(*engine.vars) != inst.addr+inst.size
                    )
                )
                {
                    _info.branch = info::Branch{
                        true, // taken
                        nullptr, // cond
                        target, // target
                        nullptr // next  
                    };
                    triggered = true;
                }
            }
        }
    }
    
    // Tainted register read
    if (
        event == bp::Event::TAINTED_REG_R
        or event == bp::Event::TAINTED_REG_RW
        or event == bp::Event::TAINTED_OPERATION
    )
    {
        ir::Inst::param_list_t read_regs;
        inst.get_read_regs(read_regs);
        for (const auto& p : read_regs)
        {
            reg_t reg = p.get().reg();
            if (!engine.cpu.ctx().get(reg)->is_concrete(*engine.vars))
            {
                _info.reg_access = info::RegAccess{
                    reg, // reg
                    engine.cpu.ctx().get(reg), // old_value
                    engine.cpu.ctx().get(reg), // new_value
                    false, // written
                    true // read
                };
                triggered = true;
                break;
            }
        }
    }

    // Tainted register write
    if (
        not triggered 
        and(
            event == bp::Event::TAINTED_REG_W 
            or event == bp::Event::TAINTED_REG_RW
            or event == bp::Event::TAINTED_OPERATION
        )
    )
    {
        if (
            inst.out.is_reg()
            and pinst.res.is_abstract() 
            and !pinst.res.expr->is_concrete(*engine.vars)
        )
        {
            reg_t reg = inst.out.reg();
            // Create reg_access if not already created
            if (!_info.reg_access.has_value())
            {
                _info.reg_access = info::RegAccess{
                    reg,
                    engine.cpu.ctx().get(reg), // old_value
                    pinst.res.as_expr(), // new_value
                    true, // written
                    false // read
                };
            }
            else // else add additional info to current reg_access
            {
                _info.reg_access->written = true;
                _info.reg_access->new_value = pinst.res.as_expr();
            }
            triggered = true;
        }
    }
    
    // Tainted memory read
    if (
        not triggered
        and (
            event == bp::Event::TAINTED_MEM_R 
            or event == bp::Event::TAINTED_MEM_RW
            or event == bp::Event::TAINTED_OPERATION
        )
    )
    {
        Expr loaded = nullptr;
        for (int i = 0; i < 3; i++)
        {
            if (
                inst.in[i].is_addr()
                or (inst.op == ir::Op::LOAD and i == 1)
            )
            {
                loaded = pinst.in(i).as_expr();
                // get loaded value
                if (loaded->is_concrete(*engine.vars))
                    continue;
            }
            else
            {
                continue;
            }

            // Trigger breakoint
            _info.mem_access = info::MemAccess{
                pinst.in(i).auxilliary, // addr
                inst.out.size()/8, // size
                loaded, // old_value
                loaded, // new_value
                false, // written
                true // read
            };
            triggered = true;
            break;
        }
    }
    
    // Tainted memory write
    if (
        not triggered
        and (
            event == bp::Event::TAINTED_MEM_W 
            or event == bp::Event::TAINTED_MEM_RW
            or event == bp::Event::TAINTED_OPERATION
            )
    )
    {
        Expr addr_expr, old_value, new_value;
        // Get concrete address and value to write
        if (inst.op == ir::Op::STORE)
        {
            addr_expr = pinst.in1.as_expr();
            new_value = pinst.in2.as_expr();
        }
        else if (ir::is_assignment_op(inst.op) and inst.out.is_addr())
        {
            addr_expr = pinst.out.as_expr();
            new_value = pinst.in0.as_expr();
        }
        else
        {
            return false;
        }
        // Check if value symbolic/concolic
        if (new_value->is_concrete(*engine.vars))
            return false;

        try
        {
            old_value = engine.mem->read(addr_expr, new_value->size/8);
        }
        catch (mem_exception& e)
        {
            throw bp_exception("BPSimple::check() memory engine threw exception when getting old_value for STORE operation");
        }
        _info.mem_access = info::MemAccess{
            addr_expr, // addr
            new_value->size/8, // size
            old_value,
            new_value,
            true, // written
            false // read
        };
        triggered = true;
    }

    // Tainted program counter
    if (
        not triggered
        and (
            event == bp::Event::TAINTED_PC
            or event == bp::Event::TAINTED_OPERATION
            )
    )
    {
        // Check if PC is tainted
        Expr pc = engine.cpu.ctx().get(engine.arch->pc());
        if (!pc->is_concrete(*engine.vars))
        {
            _info.reg_access = info::RegAccess{
                engine.arch->pc(), // reg
                nullptr, // old_value
                pc, // new_value
                true, // written
                false // read
            };
            triggered = true;
        }
    }

    // Path constraint
    if ((not triggered) and event == bp::Event::PATH)
    {
        if (inst.op == ir::Op::CBRANCH)
        {
            // Get condition
            Expr cond_expr = pinst.in1.as_expr();
            if (!cond_expr->is_concrete(*engine.vars))
            {
                // Get target
                Expr target = pinst.in0.as_expr();
                // Check if taken or not
                std::optional<bool> taken = cond_expr->is_symbolic(*engine.vars) ?
                    std::nullopt : std::make_optional<bool>(cond_expr->as_uint(*engine.vars) != 0);
                // Trigger
                _info.branch = info::Branch{
                    taken, // taken
                    (Constraint)(cond_expr != 0), // cond
                    target, // target
                    exprcst(target->size, inst.addr + inst.size) // next  
                };
                triggered = true;
            }
        }
    }

    // If triggered, set basic info
    if (triggered)
    {
        _info.stop = info::Stop::BP;
        _info.bp_id = _id;
        if (!name.empty())
            _info.bp_name = name;
        _info.addr = inst.addr;
    }

    return triggered;
}


void BPSimple::print(std::ostream& os, const maat::Arch& arch)
{
    os << std::dec << _id;
    if (!name.empty())
        os << "/" << name;
    os << ": ";
    
    switch (event)
    {
        case bp::Event::SYMPTR_R:
            os << "Read memory at symbolic pointer"; break;
        case bp::Event::SYMPTR_W:
            os << "Write memory at symbolic pointer"; break;
        case bp::Event::SYMPTR_RW:
            os << "Read/Write memory at symbolic pointer"; break;
        case bp::Event::BRANCH:
            os << "Branch instruction"; break;
        case bp::Event::CBRANCH:
            os << "Conditional branch instruction"; break;
        case bp::Event::PATH:
            os << "Symbolic path constraint"; break;
        case bp::Event::TAINTED_REG_R:
            os << "Read tainted data from register"; break;
        case bp::Event::TAINTED_REG_W:
            os << "Write tainted data to register"; break;
        case bp::Event::TAINTED_REG_RW:
            os << "Read/write tainted data from/to register"; break;
        case bp::Event::TAINTED_MEM_R:
            os << "Read tainted data from memory"; break;
        case bp::Event::TAINTED_MEM_W:
            os << "Write tainted data to memory"; break;
        case bp::Event::TAINTED_MEM_RW:
            os << "Read/write tainted data from/to memory"; break;
        case bp::Event::TAINTED_OPERATION:
            os << "Use tainted data"; break;
        case bp::Event::TAINTED_PC:
            os << "Tainted program counter"; break;
        default:
            throw runtime_exception("BPSimple::print(): got unexpected breakpoint event!");
    }
    os << " ";

    if (!enabled)
        os << " (disabled)";
}

BPAddr::BPAddr(int id, const std::string& name, addr_t a): 
    BPBase(id, bp::Event::ADDR, name),
    addr(a)
{}

bool BPAddr::check(maat::MaatEngine& engine, const ir::Inst& inst)
{
    if (inst.addr == addr)
    {
        triggered = true;
        // Add basic info
        _info.stop = info::Stop::BP;
        _info.bp_id = _id;
        if (!name.empty())
            _info.bp_name = name;
        _info.addr = inst.addr;
    }
    return triggered;
}

bool BPAddr::check(maat::MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    return check(engine, inst);
}

void BPAddr::print(std::ostream& os, const maat::Arch& arch)
{
    os << std::dec << _id;
    if (!name.empty())
        os << "/" << name;
    os << ": ";

    os << "Execute @" << std::hex << "0x" << addr << " ";

    if (!enabled)
        os << " (disabled)";
}

BPManager::BPManager(): _id_cnt(0)
{}

bool BPManager::check_before(MaatEngine& engine, const ir::Inst& inst)
{
    ir::ProcessedInst dummy;
    return _check(engine, inst, dummy, before_bps, _pending_bps);
}

bool BPManager::check_after(MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    return _check(engine, inst, pinst, after_bps, _pending_bps);
}

bool BPManager::check_instant(MaatEngine& engine, const ir::Inst& inst, const ir::ProcessedInst& pinst)
{
    return _check(engine, inst, pinst, instant_bps, _pending_instant_bps);
}

bool BPManager::_check(
    MaatEngine& engine, 
    const ir::Inst& inst, 
    const ir::ProcessedInst& pinst,
    std::list<BPManager::bp_t>& bp_list,
    std::list<BPManager::bp_t>& pending_bps
)
{
    bool res = false;
    for (auto& bp : bp_list)
    {
        if (bp->is_triggered() or !bp->is_enabled())
        {
            continue; // Already triggered or disabled
        }
        else if (bp->check(engine, inst, pinst))
        {
            // Breakpoint got triggered, add it to the pending breakpoints
            if (bp::is_instant_bp(bp->event))
                _pending_instant_bps.push_back(bp);
            else
                _pending_bps.push_back(bp);
            res = true;
        }
    }
    return res;
}

void BPManager::disable(const std::string& bp_name)
{
    get_by_name(bp_name)->disable();
}

void BPManager::disable(int bp_id)
{
    get_by_id(bp_id)->disable();
}

void BPManager::disable_all()
{
    for (auto& bp : all_bps)
        bp->disable();
}

void BPManager::_remove_in_list(std::list<BPManager::bp_t>& l, const std::string& bp_name)
{
    l.erase(
        std::remove_if(
            l.begin(),
            l.end(),
            [&bp_name](BPManager::bp_t bp){return bp->name == bp_name;}
        ),
        l.end()
    );
}

void BPManager::_remove_in_list(std::list<BPManager::bp_t>& l, int bp_id)
{
    l.erase(
        std::remove_if(
            l.begin(),
            l.end(),
            [&bp_id](BPManager::bp_t bp){return bp->_id == bp_id;}
        ),
        l.end()
    );
}

void BPManager::remove(const std::string& bp_name)
{
    try
    {
        get_by_name(bp_name);
    }
    catch(const bp_exception& e)
    {
        throw bp_exception(
            Fmt() << "BPManager::remove(): not breakpoint named '"
            << bp_name << "'"
            >> Fmt::to_str
        );
    }
    
    _remove_in_list(before_bps, bp_name);
    _remove_in_list(instant_bps, bp_name);
    _remove_in_list(after_bps, bp_name);
    _remove_in_list(all_bps, bp_name);
}

void BPManager::remove(int bp_id)
{
    try
    {
        get_by_id(bp_id);
    }
    catch(const bp_exception& e)
    {
        throw bp_exception(
            Fmt() << "BPManager::remove(): not breakpoint with id '"
            << std::dec << bp_id << "'"
            >> Fmt::to_str
        );
    }
    
    _remove_in_list(before_bps, bp_id);
    _remove_in_list(instant_bps, bp_id);
    _remove_in_list(after_bps, bp_id);
    _remove_in_list(all_bps, bp_id);
}

void BPManager::remove_all()
{
    before_bps.clear();
    instant_bps.clear();
    after_bps.clear();
    all_bps.clear();
}

void BPManager::enable(const std::string& bp_name)
{
    get_by_name(bp_name)->enable();
}

void BPManager::enable(int bp_id)
{
    get_by_id(bp_id)->enable();
}

void BPManager::reset_triggers(bp::Trigger t)
{
    if (t == bp::Trigger::NONE or t == bp::Trigger::BEFORE)
        for (auto& bp : before_bps)
            bp->set_triggered(false);
    if (t == bp::Trigger::NONE or t == bp::Trigger::AFTER)
        for (auto& bp : after_bps)
            bp->set_triggered(false);
    if (t == bp::Trigger::NONE or t == bp::Trigger::INSTANT)
        for (auto& bp : instant_bps)
            bp->set_triggered(false);
}

const std::list<BPManager::bp_t>& BPManager::pending_bps()
{
    return _pending_bps;
}

BPManager::bp_t BPManager::next_pending_bp()
{
    if (_pending_bps.empty())
        return nullptr;
    // Pop front to get breakpoints in the order they were added
    BPManager::bp_t res = _pending_bps.front();
    _pending_bps.pop_front();
    return res;
}

void BPManager::clear_pending_bps()
{
    _pending_bps.clear();
}

const std::list<BPManager::bp_t>& BPManager::pending_instant_bps()
{
    return _pending_instant_bps;
}

BPManager::bp_t BPManager::next_pending_instant_bp()
{
    if (_pending_instant_bps.empty())
        return nullptr;
    // Pop front to get breakpoints in the order they were added
    BPManager::bp_t res = _pending_instant_bps.front();
    _pending_instant_bps.pop_front();
    return res;
}

void BPManager::clear_pending_instant_bps()
{
    _pending_instant_bps.clear();
}

void BPManager::print(std::ostream& os, const maat::Arch& arch)
{
    for (auto& bp : all_bps)
    {
        bp->print(os, arch);
        os << "\n";
    }
}

BPManager::bp_t BPManager::get_by_name(const std::string& bp_name)
{
    for (auto& bp : all_bps)
        if (bp->name == bp_name)
            return bp;
    throw bp_exception(
        Fmt() << "No breakpoint named: '" << bp_name << "'"
        >> Fmt::to_str
    );
}

BPManager::bp_t BPManager::get_by_id(int bp_id)
{
    for (auto& bp : all_bps)
        if (bp->id() == bp_id)
            return bp;
    throw bp_exception(
        Fmt() << "No breakpoint with ID: '" << std::dec << bp_id << "'"
        >> Fmt::to_str
    );
}

const std::list<BPManager::bp_t>& BPManager::get_all()
{
    return all_bps;
}

/// Add a register breakpoint (REG_R, REG_W, REG_RW) without callbacks
void BPManager::add_reg_bp(bp::Event event, reg_t reg, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_reg_bp(event))
    {
        throw bp_exception("BPManager::add_reg_bp(): got unexpected breakpoint event, expected REG_R, REG_W, or REG_RW");
    }
    BPManager::bp_t b = std::make_shared<BPReg>(_id_cnt++, event, bp_name, reg);
    after_bps.push_back(b);
    all_bps.push_back(b);
}

/// Add a register breakpoint (REG_R, REG_W, REG_RW) with a single callback
void BPManager::add_reg_bp(bp::Event event, BPCallback callback, reg_t reg, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_reg_bp(event))
    {
        throw bp_exception("BPManager::add_reg_bp(): got unexpected breakpoint event, expected REG_R, REG_W, or REG_RW");
    }
    BPManager::bp_t b = std::make_shared<BPReg>(_id_cnt++, event, bp_name, reg);
    b->add_callback(callback);
    after_bps.push_back(b);
    all_bps.push_back(b);
}

/// Add a register breakpoint (REG_R, REG_W, REG_RW) with multiple callbacks
void BPManager::add_reg_bp(bp::Event event, const std::vector<BPCallback>& callbacks, reg_t reg, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_reg_bp(event))
    {
        throw bp_exception("BPManager::add_reg_bp(): got unexpected breakpoint event, expected REG_R, REG_W, or REG_RW");
    }
    BPManager::bp_t b = std::make_shared<BPReg>(_id_cnt++, event, bp_name, reg);
    for (auto cb : callbacks)
        b->add_callback(cb);
    after_bps.push_back(b);
    all_bps.push_back(b);
}

/** \brief Add a memory breakpoint (MEM_R, MEM_W, MEM_RW) between 'addr_min' and 'addr_max' (included)
 * without callbacks. If 'addr_max' is null then break on the single address 'addr_min'. */
void BPManager::add_mem_bp(bp::Event event, addr_t addr_min, addr_t addr_max, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_mem_bp(event))
    {
        throw bp_exception("BPManager::add_mem_bp(): got unexpected breakpoint event, expected MEM_R, MEM_W, or MEM_RW");
    }
    if (addr_max == 0)
        addr_max = addr_min;
    BPManager::bp_t b = std::make_shared<BPMem>(_id_cnt++, event, bp_name, addr_min, addr_max);
    after_bps.push_back(b);
    all_bps.push_back(b);
}

/** \brief Add a memory breakpoint (MEM_R, MEM_W, MEM_RW) between 'addr_min' and 'addr_max' (included)
 * with a single callback. If 'addr_max' is null then break on the single address 'addr_min'. */
void BPManager::add_mem_bp(
    bp::Event event,
    BPCallback callback,
    addr_t addr_min,
    addr_t addr_max,
    const std::string& bp_name
)
{
    _check_unique_name(bp_name);
    if (!is_mem_bp(event))
    {
        throw bp_exception("BPManager::add_mem_bp(): got unexpected breakpoint event, expected MEM_R, MEM_W, or MEM_RW");
    }
    if (addr_max == 0)
        addr_max = addr_min;
    BPManager::bp_t b = std::make_shared<BPMem>(_id_cnt++, event, bp_name, addr_min, addr_max);
    b->add_callback(callback);
    after_bps.push_back(b);
    all_bps.push_back(b);
}

/** \brief Add a memory breakpoint (MEM_R, MEM_W, MEM_RW) between 'addr_min' and 'addr_max' (included)
 * with multiple callbacks. If 'addr_max' is null then break on the single address 'addr_min'. */
void BPManager::add_mem_bp(
    bp::Event event,
    const std::vector<BPCallback>& callbacks,
    addr_t addr_min,
    addr_t addr_max,
    const std::string& bp_name
)
{
    _check_unique_name(bp_name);
    if (!is_mem_bp(event))
    {
        throw bp_exception("BPManager::add_mem_bp(): got unexpected breakpoint event, expected MEM_R, MEM_W, or MEM_RW");
    }
    if (addr_max == 0)
        addr_max = addr_min;
    BPManager::bp_t b = std::make_shared<BPMem>(_id_cnt++, event, bp_name, addr_min, addr_max);
    for (auto& cb : callbacks)
        b->add_callback(cb);
    after_bps.push_back(b);
    all_bps.push_back(b);
}

/// Add simple breakpoint (ADDR, TAINTED_*, BRANCH, CBRANCH, ...) without callbacks
void BPManager::add_bp(bp::Event event, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_simple_bp(event))
    {
        throw bp_exception("BPManager::add_bp(): this breakpoint event requires additional arguments");
    }
    BPManager::bp_t b = std::make_shared<BPSimple>(_id_cnt++, event, bp_name);
    if (is_before_bp(event))
        before_bps.push_back(b);
    else if (is_instant_bp(event))
        instant_bps.push_back(b);
    else
        after_bps.push_back(b);
    all_bps.push_back(b);
}

/// Add simple breakpoint (ADDR, TAINTED_*, BRANCH, CBRANCH, ...) with a single callback
void BPManager::add_bp(bp::Event event, BPCallback callback, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_simple_bp(event))
    {
        throw bp_exception("BPManager::add_bp(): this breakpoint event requires additional arguments");
    }
    BPManager::bp_t b = std::make_shared<BPSimple>(_id_cnt++, event, bp_name);
    b->add_callback(callback);
    if (is_before_bp(event))
        before_bps.push_back(b);
    else if (is_instant_bp(event))
        instant_bps.push_back(b);
    else
        after_bps.push_back(b);
    all_bps.push_back(b);
}

/// Add simple breakpoint (ADDR, TAINTED_*, BRANCH, CBRANCH, ...) with multiple callbacks
void BPManager::add_bp(bp::Event event, const std::vector<BPCallback>& callbacks, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    if (!is_simple_bp(event))
    {
        throw bp_exception("BPManager::add_bp(): this breakpoint event requires additional arguments");
    }
    BPManager::bp_t b = std::make_shared<BPSimple>(_id_cnt++, event, bp_name);
    for (auto& cb : callbacks)
        b->add_callback(cb);
    if (is_before_bp(event))
        before_bps.push_back(b);
    else if (is_instant_bp(event))
        instant_bps.push_back(b);
    else
        after_bps.push_back(b);
    all_bps.push_back(b);
}


void BPManager::add_addr_bp(addr_t addr, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    BPManager::bp_t b = std::make_shared<BPAddr>(_id_cnt++, bp_name, addr);
    before_bps.push_back(b);
    all_bps.push_back(b);
}

void BPManager::add_addr_bp(BPCallback callback, addr_t addr, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    BPManager::bp_t b = std::make_shared<BPAddr>(_id_cnt++, bp_name, addr);
    b->add_callback(callback);
    before_bps.push_back(b);
    all_bps.push_back(b);
}

void BPManager::add_addr_bp(const std::vector<BPCallback>& callbacks, addr_t addr, const std::string& bp_name)
{
    _check_unique_name(bp_name);
    BPManager::bp_t b = std::make_shared<BPAddr>(_id_cnt++, bp_name, addr);
    for( auto& cb : callbacks)
        b->add_callback(cb);
    before_bps.push_back(b);
    all_bps.push_back(b);
}

void BPManager::_check_unique_name(const std::string& str)
{
    if (str.empty())
        return;
    try
    {
        get_by_name(str);
    }
    catch (const bp_exception& e)
    { 
        // Breakpoint doesn't exist, we're good
        return;
    }
    // Breakpoint exists, raise exception
    throw bp_exception(
        Fmt() << "A breakpoint named '" << str << "' already exists"
        >> Fmt::to_str
    );
}

} // namespace bp
} // namespace maat
