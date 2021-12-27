#include "engine.hpp"
#include "solver.hpp"
#include <chrono>

namespace maat
{
    
using namespace maat::event;

MaatEngine::MaatEngine(Arch::Type _arch, env::OS os)
{
    switch (_arch)
    {
        case Arch::Type::X86:
            arch = std::make_shared<X86::ArchX86>();
            lifters[CPUMode::X86] = std::make_shared<LifterX86>(32);
            _current_cpu_mode = CPUMode::X86;
            break;
        case Arch::Type::X64:
            arch = std::make_shared<X64::ArchX64>();
            lifters[CPUMode::X64] = std::make_shared<LifterX86>(64);
            _current_cpu_mode = CPUMode::X64;
            break;
        /* TODO 
        case Arch::Type::ARM64:
            arch = std::make_shared<ARM64::ArchARM64>();
            break; */
        case Arch::Type::NONE:
            arch = std::make_shared<ArchNone>();
            _current_cpu_mode = CPUMode::NONE;
            break;
        default:
            throw runtime_exception("MaatEngine(): unsupported architecture");
    }
    switch (os)
    {
        case env::OS::LINUX:
            env = std::make_shared<env::LinuxEmulator>(_arch);
            break;
        default:
            env = std::make_shared<env::EnvEmulator>(_arch, env::OS::NONE);
            break;
    }
    symbols = std::make_shared<SymbolManager>();
    vars = std::make_shared<VarContext>();
    snapshots = std::make_shared<SnapshotManager<Snapshot>>();
    mem = std::make_shared<MemEngine>(vars, arch->bits(), snapshots);
    ir_map = std::make_shared<ir::IRMap>();
    process = std::make_shared<ProcessInfo>();
    simplifier = NewDefaultExprSimplifier();
    callother_handlers = callother::default_handler_map();
    // Initialize all registers to their proper bit-size with value 0
    for (reg_t reg = 0; reg < arch->nb_regs; reg++)
        cpu.ctx().set(reg, Number(arch->reg_size(reg), 0));
    // Initialize some variables for execution statefullness
    _previous_halt_before_exec = -1;
#ifdef PYTHON_BINDINGS
    self_python_wrapper_object = nullptr;
#endif
}

// TODO: such macros are probably not best practice...
#define ASSERT_SUCCESS(statement) \
if (statement != true)\
{               \
    log.error("Unexpected error when processing IR instruction, aborting..."); \
    info.stop = info::Stop::FATAL; \
    return info.stop; \
}

#define HANDLE_EVENT_ACTION(statement) \
{\
    event::Action action = statement;\
    if (action == event::Action::ERROR)\
    {\
        log.error("Error executing event callback, aborting..."); \
        info.reset();\
        info.stop = info::Stop::FATAL; \
        return info.stop; \
    }\
    else if (action == event::Action::HALT)\
    {\
        _halt_after_inst = true;\
    }\
}

// Handle action in subfunction returning boolean
#define SUB_HANDLE_EVENT_ACTION(statement, ret_val) \
{\
    event::Action action = statement;\
    if (action == event::Action::ERROR)\
    {\
        log.error("Error executing event callback, aborting..."); \
        return ret_val;\
    }\
    else if (action == event::Action::HALT)\
    {\
        _halt_after_inst = true;\
    }\
}

info::Stop MaatEngine::run(int max_inst)
{
    bool next_inst = true;
    // True if max_instr argument was specified (!= 0)
    bool check_max_inst = (max_inst != 0); 
    ir::AsmInst::inst_id ir_inst_id = 0;
    addr_t to_execute = -1;
    MaatEngine::branch_type_t branch_type = MaatEngine::branch_none;

    // Reset info field
    info.reset();
    _halt_after_inst = false;

    /* Execute forever while there is an instruction to execute */
    while (next_inst)
    {
        // Handle potential pending X memory overwrites: if a user callback
        // or a user script did mess with the memory, make sure that any lifted
        // instructions that were overwritten gets their cached IR deleted
        handle_pending_x_mem_overwrites();

        // Check if program already exited
        if (process->terminated)
        {
            info.stop = info::Stop::EXIT;
            return info.stop;
        }

        // Get next instruction to execute
        if (pending_ir_state)
        {
            to_execute = pending_ir_state->addr;
            ir_inst_id = pending_ir_state->inst_id;
            pending_ir_state.reset();
        }
        else if (not cpu.ctx().get(arch->pc()).is_symbolic(*vars))
        {
            to_execute = cpu.ctx().get(arch->pc()).as_uint(*vars);
            ir_inst_id = 0;
            // Reset temporaries in CPU for new instruction
            cpu.reset_temporaries();
        }
        else
        {
            this->info.stop = info::Stop::SYMBOLIC_PC;
            return this->info.stop;
        }

        // If the target to execute is a function emulated with a callback,
        // process the callback and branch to next IR block
        if (symbols->is_callback_emulated_function(to_execute))
        {
            
            if (!process_callback_emulated_function(to_execute))
                return info.stop;
            // Jump to next block after executing callback
            continue;
        }
        else if (symbols->is_missing_function(to_execute))
        {
            log.error("Branch to missing function: ", symbols->name(to_execute));
            info.stop = info::Stop::MISSING_FUNCTION;
            info.addr = to_execute;
            return info.stop;
        }

        // Check if max_instr limit has been reached
        if (check_max_inst and max_inst <= 0)
        {
            info.stop = info::Stop::INST_COUNT;
            info.addr = to_execute;
            return info.stop;
        }

        // EXEC event
        if (hooks.has_hooks(Event::EXEC, When::BEFORE))
        {
            HANDLE_EVENT_ACTION(hooks.before_exec(*this, to_execute))
            // If we already halted before executing this instruction, don't halt
            // again, neither before nor after the instruction
            if (_previous_halt_before_exec == to_execute)
                _halt_after_inst = false;
            // For EXEC::BEFORE events, if a hook halts execution then we actually stop
            // right now, not after the instruction
            if (_halt_after_inst)
            {
                info.stop = info::Stop::HOOK;
                _previous_halt_before_exec = to_execute;
                return info.stop;
            }
            // If user callback changed the address to execute, exit the loop
            if (info.addr.has_value() and *info.addr != to_execute)
            {
                cpu.ctx().set(arch->pc(), *info.addr);
                info.reset();
                continue;
            }
            info.reset();
        }
        _previous_halt_before_exec = -1;

        // TODO: periodically increment tsc() ?
        // TODO: increment stats with instr count

        // Get the PCODE IR
        const ir::AsmInst* asm_inst = nullptr;
        try
        {
            asm_inst = &(get_asm_inst(to_execute));
        }
        catch (const lifter_exception& e)
        {
            return info.stop;
        }

        // Print current asm instruction if option is set
        if (settings.log_insts)
        {
            log.info("Run 0x", std::hex, asm_inst->addr(), ": ", get_inst_asm(asm_inst->addr()));
        }

        // Update max_instructions count
        max_inst--;

        // Execute the PCODE instructions for the current Asm instruction
        while (ir_inst_id < asm_inst->nb_ir_inst())
        {
            // Sanity checks
            if (ir_inst_id < 0 or ir_inst_id >= asm_inst->nb_ir_inst())
            {
                info.stop = info::Stop::FATAL;
                log.fatal("MaatEngine::run(): got wrong inst_id. Should not happen!");
                return this->info.stop;
            }

            // Get IR instruction to execute
            const ir::Inst& inst = asm_inst->instructions()[ir_inst_id];            

            // TODO: add settings.log_ir option
            // if settings.log_ir:
            //      log.debug("Run IR: ", inst);
            // std::cout << "DEBUG " << inst << std::endl;

            // Pre-process IR instruction
            event::Action tmp_action = event::Action::CONTINUE;
            info.addr = asm_inst->addr();
            ir::ProcessedInst& pinst = cpu.pre_process_inst(inst, tmp_action, *this);
            // Check event results on register read
            if (tmp_action == event::Action::ERROR)
            {
                log.error("Error in event callback when processing instruction");
                info.addr = asm_inst->addr();
                info.stop = info::Stop::FATAL;
                return info.stop;
            }
            else if (tmp_action == event::Action::HALT)
            {
                _halt_after_inst = true;
            }
            info.reset(); // Reset info here because the CPU can not do it

            // Process Addr parameters and load them from memory
            info.addr = asm_inst->addr();
            ASSERT_SUCCESS(process_addr_params(inst, pinst))

            // Post-process IR instruction once Addr params are resolved
            pinst = cpu.post_process_inst(inst, pinst);

            // Handle CALLOTHER operation
            if (inst.op == ir::Op::CALLOTHER)
            {
                ASSERT_SUCCESS(process_callother(inst, pinst))
            }

            // If LOAD, do the load (!= process_addr_params)
            if (inst.op == ir::Op::LOAD)
            {
                info.addr = asm_inst->addr();
                ASSERT_SUCCESS(process_load(inst, pinst))
            }

            // If branch instruction, update control flow now
            // This will also add potential path constraints to the path manager
            // This will potentially update PC
            if (ir::is_branch_op(inst.op))
            {
                ASSERT_SUCCESS(
                    process_branch(*asm_inst, inst, pinst, branch_type, ir_inst_id)
                )
            }
            else
            {
                branch_type = MaatEngine::branch_none;
            }

            if (
                inst.op == ir::Op::STORE 
                or (inst.out.is_addr() and ir::is_assignment_op(inst.op))
            )
            {
                info.addr = asm_inst->addr();
                ASSERT_SUCCESS(
                    process_store(inst, pinst)
                )
            }

            // If instruction result is concrete expression, make it a concrete value
            if (pinst.res.is_abstract() and pinst.res.expr()->is_concrete(*vars))
            {
                pinst.res = pinst.res.expr()->as_number(*vars);
            }

            // Simplify abstract expressions
            if (settings.force_simplify)
            {
                // Simplify only if not concrete
                if (
                    pinst.res.is_abstract() 
                    and inst.out.is_reg()
                    and not pinst.res.expr()->is_concrete(*vars)
                )
                {
                    pinst.res = simplifier->simplify(pinst.res.expr());
                }
            }

            // Apply semantics to the IR CPU
            info.addr = asm_inst->addr();
            HANDLE_EVENT_ACTION(
                cpu.apply_semantics(inst, pinst, *this)
            )
            info.reset(); // Reset info here because the CPU can not do it

            // Manage branching
            if (branch_type == MaatEngine::branch_native)
            {
                // NOTE: PC was already updated by process_branch() IFF the branch
                // was taken!
                break;
            }
            else if (branch_type == MaatEngine::branch_none)
            {
                // No branch, go to next instruction
                if (ir_inst_id == asm_inst->nb_ir_inst()-1)
                {
                    // That was the last IR inst of this AsmInst,
                    // update PC, exit and go to next AsmInst
                    cpu.ctx().set(arch->pc(), asm_inst->addr() + asm_inst->raw_size());
                    break;
                }
                else // Just go to the next PCODE instruction
                    ir_inst_id += 1;
            }
            // else: pcode relative branching, ir_inst_id has already
            // been updated by process_branch(), so do nothing and 
            // just loop again
        }

        // Update PC for NOPs....
        if (asm_inst->instructions().empty())
        {
            cpu.ctx().set(arch->pc(), asm_inst->addr()+asm_inst->raw_size());
        }

        // Event EXEC
        if (hooks.has_hooks(Event::EXEC, When::AFTER))
        {
            HANDLE_EVENT_ACTION(hooks.after_exec(*this, asm_inst->addr()))
            info.reset();
        }
        if (_halt_after_inst)
        {
            info.stop = info::Stop::HOOK;
            info.addr = asm_inst->addr();
            return info.stop;
        }

    }

    this->info.stop = info::Stop::NONE;
    return this->info.stop;
}

info::Stop MaatEngine::run_from(addr_t addr, unsigned int max_inst)
{
    // Set PC to new location to execute
    cpu.ctx().set(arch->pc(), addr);
    // Reset pending IR state
    pending_ir_state.reset();

    // Run!
    return run(max_inst);
}


bool MaatEngine::process_branch(
    const ir::AsmInst& asm_inst,
    const ir::Inst& inst, 
    ir::ProcessedInst& pinst,
    MaatEngine::branch_type_t& branch_type,
    ir::AsmInst::inst_id& inst_id
)
{
    if (!ir::is_branch_op(inst.op))
        throw runtime_exception("MaatEngine::process_branch(): called with non-branching instruction!");
    
    Expr in0, in1;
    addr_t next = asm_inst.addr() + asm_inst.raw_size();
    bool taken = false;
    std::optional<bool> opt_taken;
    bool pcode_rela = inst.in[0].is_cst();

    if (pinst.in0.is_none())
        throw runtime_exception("MaatEngine::process_branch(): got empty input parameter!");
    else if (pinst.in0.is_abstract())
        in0 = pinst.in0.value().expr();
    else
        in0 = exprcst(arch->bits(), pinst.in0.value().number().get_cst());
        
    if (pinst.in1.is_abstract())
        in1 = pinst.in1.value().expr();
    else if (not pinst.in1.is_none())
        in1 = pinst.in1.value().as_expr();

    switch (inst.op)
    {
        case ir::Op::CALL: // Equivalent to branch
        case ir::Op::BRANCH:
            if (inst.in[0].is_cst()) // internal pcode branch
            {
                inst_id += (int)in0->as_int();
                branch_type = MaatEngine::branch_pcode;
            }
            else // address, branch to it
            {
                if (hooks.has_hooks(Event::BRANCH, When::BEFORE))
                {
                    info.addr = asm_inst.addr();
                    SUB_HANDLE_EVENT_ACTION(hooks.before_branch(*this, in0, next), false)
                }
                // TODO handle branch to same instruction !
                // find to which IR inst id we have to loop back !
                cpu.ctx().set(arch->pc(), in0);
                branch_type = MaatEngine::branch_native;
                if (hooks.has_hooks(Event::BRANCH, When::AFTER))
                {
                    info.addr = asm_inst.addr();
                    SUB_HANDLE_EVENT_ACTION(hooks.after_branch(*this, in0, next), false)
                }
                info.reset();
            }
            break;
        case ir::Op::RETURN: // Equivalent to branchind
        case ir::Op::CALLIND: // Equivalent to branchind
        case ir::Op::BRANCHIND:
            if (hooks.has_hooks(Event::BRANCH, When::BEFORE))
            {
                info.addr = asm_inst.addr();
                SUB_HANDLE_EVENT_ACTION(hooks.before_branch(*this, in0, next), false)
            }
            // Branch to in0
            cpu.ctx().set(arch->pc(), in0);
            branch_type = MaatEngine::branch_native;
            if (hooks.has_hooks(Event::BRANCH, When::AFTER))
            {
                info.addr = asm_inst.addr();
                SUB_HANDLE_EVENT_ACTION(hooks.after_branch(*this, in0, next), false)
            }
            info.reset();
            break;
        case ir::Op::CBRANCH:
            // Try to resolve the branch is not symbolic
            if (not in1->is_symbolic(*vars))
            {
                if (in1->as_uint(*vars) != 0) // branch condition is true, branch to target
                    opt_taken = true;
                else
                    opt_taken = false;
            }
            else
            {
                opt_taken = std::nullopt;
            }

            // TODO: indicate that the branch is pcode relative if it's the case
            // probably add a info.branch.type field
            if (
                hooks.has_hooks(Event::BRANCH, When::BEFORE) or
                (
                 (not in1->is_concrete(*vars)) and
                  hooks.has_hooks(Event::PATH, When::BEFORE)
                )
            )
            {
                info.addr = asm_inst.addr();
                SUB_HANDLE_EVENT_ACTION(
                    hooks.before_branch(
                        *this,
                        pcode_rela? nullptr : in0,
                        next,
                        in1 != 0, // cond,
                        opt_taken
                    ), false
                )
            }

            // Resolve the branch again to account for potential changes made by
            // user callbacks
            if (in1->is_symbolic(*vars))
            {
                if (info.branch->taken.has_value())
                {
                    // User callback specified which branch to take
                    taken = info.branch->taken.value();
                }
                else
                {
                    log.error("Purely symbolic branch condition");
                    // TODO: have Stop::SYMBOLIC_BRANCH ?
                    info.stop = info::Stop::ERROR;
                    info.addr = asm_inst.addr();
                    return false;
                }
            }
            else if (in1->as_uint(*vars) != 0) // branch condition is true, branch to target
            {
                taken = true;
            }
            else
            {
                taken = false;
            }

            // Perform the branch
            if (taken) // branch taken
            {
                if (inst.in[0].is_cst()) // internal pcode branch
                {
                    inst_id += (int)in0->as_int();
                    branch_type = MaatEngine::branch_pcode;
                }
                else // native asm branch
                {
                    // TODO: handle branch on same address?
                    // used for REP/REPE/REPNE prefixes...
                    cpu.ctx().set(arch->pc(), in0);
                    branch_type = MaatEngine::branch_native;
                }
                // Add path constraint
                if (
                    settings.record_path_constraints 
                    and not in1->is_concrete(*vars)
                )
                {
                    path.add(in1 != 0);
                }
            }
            else // branch condition is false, so no branch
            {
                branch_type = MaatEngine::branch_none;
                // Add path constraint
                if (
                    settings.record_path_constraints
                    and not in1->is_concrete(*vars)
                )
                {
                    path.add(in1 == 0);
                }
            }
            if (
                hooks.has_hooks(Event::BRANCH, When::AFTER) or
                (
                 (not in1->is_concrete(*vars)) and
                  hooks.has_hooks(Event::PATH, When::AFTER)
                )
            )
            {
                info.addr = asm_inst.addr();
                SUB_HANDLE_EVENT_ACTION(
                    hooks.after_branch(
                        *this, 
                        pcode_rela? nullptr : in0,
                        next,
                        in1 != 0, // cond
                        taken
                    ), false
                )
            }
            info.reset();
            break;
        default:
            throw runtime_exception(Fmt()
                    << "MaatEngine::process_branch(): got unexpected operation: "
                    << inst.op
                    >> Fmt::to_str
                );
    }
    return true;
}


Expr MaatEngine::resolve_addr_param(const ir::Param& param, ir::ProcessedInst::param_t& addr)
{
    Expr loaded;
    bool do_abstract_load = true;
    int load_size = param.size()%8 == 0 ? param.size()/8 : (param.size()/8) + 1;

    if (not addr.is_abstract())
    {
        do_abstract_load = false;
        addr.auxilliary = exprcst(addr.value().number());
    }
    else if (addr.is_abstract() and addr.value().expr()->is_concrete(*vars))
    {
        do_abstract_load = false;
        addr.auxilliary = addr.value().expr();
    }
    else if (addr.is_abstract() and addr.value().expr()->is_concolic(*vars) and not settings.symptr_read)
    {
        do_abstract_load = false;
        addr.auxilliary = exprcst(addr.value().expr()->as_number(*vars));
    }
    else if (addr.is_abstract() and addr.value().expr()->is_symbolic(*vars) and not settings.symptr_read)
    {
        info.stop = info::Stop::FATAL;
        log.fatal("MaatEngine::resolve_addr_param(): trying to read from symbolic pointer, but symptr_read option is disabled");
        return nullptr;
    }
    else
    {
        addr.auxilliary = addr.value();
    }

    try
    {
        // Memory read event
        if (hooks.has_hooks({Event::MEM_R, Event::MEM_RW}, When::BEFORE))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.before_mem_read(
                    *this,
                    addr.auxilliary, // addr
                    load_size // size in bytes
                ),
                nullptr
            )
        }

        // TODO: shouldn't use as_expr everywhere here....
        if (do_abstract_load)
        {
            simplifier->simplify(addr.auxilliary.as_expr());
            ValueSet range = addr.auxilliary.as_expr()->value_set();
            if (settings.symptr_refine_range)
            {
                range = refine_value_set(addr.auxilliary.as_expr());
            }
            loaded = mem->symbolic_ptr_read(addr.auxilliary.as_expr(), range, load_size, settings);
        }
        else
        {
            loaded = mem->read(addr.auxilliary.as_expr(), load_size);
        }
        // P-code can load a number of bits that's not a multiple of 8.
        // If that's the case, readjust the loaded value size by trimming
        // the extra bits
        if (loaded->size > param.size())
        {
            loaded = extract(loaded, param.size()-1, 0);
        }

        // Mem read event
        if (hooks.has_hooks({Event::MEM_R, Event::MEM_RW}, When::AFTER))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.after_mem_read(
                    *this,
                    addr.auxilliary, // addr
                    loaded // value
                ),
                nullptr
            )
        }
        // Reset info (but save addr)
        auto tmp_addr = info.addr;
        info.reset();
        info.addr = tmp_addr;
    }
    catch (const mem_exception& e)
    {
        info.reset();
        info.stop = info::Stop::FATAL;
        log.error(
            "MaatEngine::resolve_addr_param(): Memory exception when resolving IR address parameter: ",
            e.what()
        );
        return nullptr;
    }

    // Update processed parameter (auxiliary already set at the 
    // beginning of the method). Here we can just re-assign 'addr'
    // to an abstract value because Address parameters are expected 
    // to always trigger abstract processing in the CPU
    // TODO: this is ugly, 'loaded' should become a value too...
    Value tmp;
    tmp = loaded;
    addr = std::move(tmp);
    return loaded;
}

bool MaatEngine::process_addr_params(const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Don't resolve addresses for BRANCH/CBRANCH/CALL operators, they are targets, not
    // real input parameters
    if (inst.op == ir::Op::BRANCH or inst.op == ir::Op::CBRANCH or inst.op == ir::Op::CALL)
        return true;

    if (
        (inst.in[0].is_addr() and !resolve_addr_param(inst.in[0], pinst.in0))
        or (inst.in[1].is_addr() and !resolve_addr_param(inst.in[1], pinst.in1))
    )
    {
        log.error("MaatEngine::process_addr_params(): failed to process IR inst: ", inst);
        return false;
    }

    return true;
}

bool MaatEngine::process_load(const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    Expr loaded;

    if ((loaded = resolve_addr_param(inst.out, pinst.in1)) == nullptr)
    {
        log.error("MaatEngine::process_load(): failed to resolve address parameter");
        return false;
    }

    // TODO: should use Value here instead of Expr/concrete, .....
    // Write load result to processed inst
    if (pinst.out.is_none())
    {
        pinst.res = loaded;
    }
    else if (pinst.out.is_abstract())
    {
        // dest is abstract anyways so keep loaded as a constant
        pinst.res = maat::overwrite_expr_bits(pinst.out.value().expr(), loaded, inst.out.hb);
    }
    else if (not pinst.out.is_none()) // TODO: this test so uglyyy
    {
        if (loaded->is_concrete(*vars))
        {
            // dest and loaded have concrete values:
            // translate loaded to number and assign to dest
            Number tmp;
            tmp.set_overwrite(pinst.out.value().number(), loaded->as_number(), inst.out.lb);
            pinst.res = tmp;
        }
        else
        {
            // dest is concrete but loaded not concrete.
            // translate dest to Expr to assign loaded
            Expr out_expr = exprcst(pinst.out.value().as_number());
            pinst.res = maat::overwrite_expr_bits(out_expr, loaded, inst.out.hb);
        }
    }
    else
    {
        throw runtime_exception("MaatEngine::process_load(): this should never be reached!");
    }

    // Success
    return true;
}

bool MaatEngine::process_store(
    const ir::Inst& inst,
    ir::ProcessedInst& pinst
)
{
    mem_alert_t mem_alert = maat::mem_alert_none;
    ir::ProcessedInst::param_t& addr = pinst.in1;
    bool do_abstract_store = true;
    Expr store_addr = nullptr;
    Expr to_store = nullptr;

    // Get address and value to store
    if (inst.op == ir::Op::STORE)
    {
        if (not addr.is_abstract())
        {
            do_abstract_store = false;
            store_addr = exprcst(arch->bits(), addr.value().number().get_ucst());
        }
        else if (addr.is_abstract() and addr.value().expr()->is_concrete(*vars))
        {
            do_abstract_store = false;
            store_addr = addr.value().expr();
        }
        else if (addr.is_abstract() and addr.value().expr()->is_concolic(*vars) and not settings.symptr_write)
        {
            do_abstract_store = false;
            store_addr = exprcst(addr.value().expr()->as_number(*vars));
        }
        else if (addr.is_abstract() and addr.value().expr()->is_symbolic(*vars) and not settings.symptr_write)
        {
            log.fatal("MaatEngine::process_store(): trying to write at symbolic pointer but symptr_write option is disabled");
            info.stop = info::Stop::FATAL;
            return false;
        }
        else // symbolic address and symbolic writes enabled
        {
            store_addr = addr.value().expr();
        }
        to_store = pinst.in2.is_abstract() ? pinst.in2.value().expr() : exprcst(pinst.in2.value().number());
    }
    else // out parameter is a constant address and operation is an assignment operation
    {
        do_abstract_store = false;
        store_addr = exprcst(arch->bits(), inst.out.addr());
        to_store = pinst.res.is_abstract() ? pinst.res.expr() : exprcst(pinst.res.number());
    }

    // Perform the memory store
    try
    {
        // Mem write event
        if (hooks.has_hooks({Event::MEM_W, Event::MEM_RW}, When::BEFORE))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.before_mem_write(
                    *this,
                    store_addr, // addr
                    to_store // value
                ),
                false
            )
        }

        if (do_abstract_store)
        {
            store_addr = simplifier->simplify(store_addr);
            ValueSet range = store_addr->value_set();
            if (settings.symptr_refine_range)
            {
                range = refine_value_set(store_addr);
            }
            mem->symbolic_ptr_write(store_addr, range, to_store, settings, &mem_alert, true);
        }
        else
        {
            mem->write(store_addr->as_uint(*vars), to_store, &mem_alert, true);
        }
        // Mem write event
        if (hooks.has_hooks({Event::MEM_W, Event::MEM_RW}, When::AFTER))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.after_mem_write(
                    *this,
                    store_addr, // addr
                    to_store // value
                ),
                false
            )
        }
        info.reset(); // Reset info after event callbacks
    }
    catch(mem_exception& e)
    {
        info.stop = info::Stop::ERROR;
        log.error("MaatEngine::process_store(): Caught memory exception: ", e.what());
        return false;
    }

    return true;
}

bool MaatEngine::process_callother(const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    if (inst.op != ir::Op::CALLOTHER)
    {
        log.error("MaatEngine::process_callother(): called with wrong ir operation (not CALLOTHER)");
        return false;
    }
    if (not callother_handlers.has_handler(inst.callother_id))
    {
        log.error("Instruction can not be emulated (missing CALLOTHER handler)");
        return false;
    }
    callother::handler_t handler = callother_handlers.get_handler(inst.callother_id);
    try
    {
        handler(*this, inst, pinst);
    }
    catch(const std::exception& e)
    {
        log.error("Exception in CALLOTHER handler: ", e.what());
        return false;
    }
    return true;
}

bool MaatEngine::process_callback_emulated_function(addr_t addr)
{
    const Symbol& symbol = symbols->get_by_addr(addr);
    if (symbol.func_status != Symbol::FunctionStatus::EMULATED_CALLBACK)
    {
        info.stop = info::Stop::FATAL;
        log.fatal(
            "MaatEngine::process_callback_emulated_function(): ", 
            "No emulation callback for symbol/addr ", symbol
        );
        return false;
    }
    try
    {
        const env::Function& func = env->get_library_by_num(symbol.env_lib_num).get_function_by_num(symbol.env_func_num);
        // Execute function callback
        switch (func.callback().execute(*this, env->default_abi))
        {
            case env::Action::CONTINUE:
                break;
            case env::Action::ERROR:
                log.fatal("MaatEngine::process_callback_emulated_function(): Emulation callback signaled an error");
                info.stop = info::Stop::FATAL;
                return false;
        }
    }
    catch(const std::exception& e)
    {
        log.fatal(
            "MaatEngine::process_callback_emulated_function(): Caught exception during emulation callback ",
            e.what()
        );
        info.stop = info::Stop::FATAL;
        return false;
    }
    // Callback executed properly
    return true;
}


const ir::AsmInst& MaatEngine::get_asm_inst(addr_t addr)
{
    if (ir_map->contains_inst_at(addr))
        return ir_map->get_inst_at(addr);

    // The code hasn't been lifted yet so we disassemble it
    try
    {
        // TODO: check if code region is symbolic
        if (
            not lifters[_current_cpu_mode]->lift_block(
                *ir_map,
                addr,
                mem->raw_mem_at(addr),
                0xfffffff,
                0xffffffff,
                nullptr, // is_symbolic
                nullptr, // is_tainted
                true
            )
        ){
            throw lifter_exception("MaatEngine::run(): failed to lift instructions");
        }
        return ir_map->get_inst_at(addr);
    }
    catch(unsupported_instruction_exception& e)
    {
        this->info.stop = info::Stop::UNSUPPORTED_INST;
        log.error("Lifter error: ", e.what());
        throw lifter_exception("MaatEngine::get_asm_inst(): lifter error");
    }
    catch(lifter_exception& e)
    {
        log.fatal("Lifter error: ", e.what());
        this->info.stop = info::Stop::FATAL;
        throw lifter_exception("MaatEngine::get_asm_inst(): lifter error");
    }
}

void MaatEngine::handle_pending_x_mem_overwrites()
{
    for (auto& mem_access : mem->_get_pending_x_mem_overwrites())
    {
        ir_map->remove_insts_containing(mem_access.first, mem_access.second);
    }
    mem->_clear_pending_x_mem_overwrites();
}

/// Take a snapshot of the current engine state
MaatEngine::snapshot_t MaatEngine::take_snapshot()
{
    Snapshot& snapshot = snapshots->emplace_back();
    snapshot.cpu = cpu; // Copy CPU
    snapshot.symbolic_mem = mem->symbolic_mem_engine.take_snapshot();
    snapshot.pending_ir_state = pending_ir_state;
    snapshot.info = info;
    snapshot.process = process;
    snapshot.page_permissions = mem->page_manager.regions();
    snapshot.path = path.take_snapshot();
    snapshot.env = env->fs.take_snapshot();
    // Snapshot ID is its index in the snapshots list
    return snapshots->size()-1;
}

/** Restore the engine state to 'snapshot'. If remove is true, the 
 * snapshot is removed after being restored */
void MaatEngine::restore_snapshot(snapshot_t snapshot, bool remove)
{
    int idx(snapshot);
    if (idx < 0)
    {
        throw snapshot_exception("MaatEngine::restore_snapshot(): called with invalid snapshot parameter!");
    }

    // idx is the index of the oldest snapshot to restore
    // start by rewinding until 'idx' and delete more recent snapshots 
    while (idx < snapshots->size()-1)
    {
        restore_last_snapshot(true); // remove = true
    }
    // For the last one (the 'idx' snapshot), pass the user provided 'remove' parameter
    if (idx == snapshots->size()-1)
    {
        restore_last_snapshot(remove);
    }
}

/** Restore the engine state to the lastest snapshot. If remove is true, the 
 * snapshot is removed after being restored */
void MaatEngine::restore_last_snapshot(bool remove)
{
    mem_alert_t mem_alert = maat::mem_alert_none;

    Snapshot& snapshot = snapshots->back();
    cpu = std::move(snapshot.cpu); // Restore CPU
    mem->symbolic_mem_engine.restore_snapshot(snapshot.symbolic_mem);
    pending_ir_state.swap(snapshot.pending_ir_state);
    info = snapshot.info;
    process = snapshot.process;
    mem->page_manager.set_regions(std::move(snapshot.page_permissions));
    path.restore_snapshot(snapshot.path);
    env->fs.restore_snapshot(snapshot.env);
    // Restore memory segments
    for (addr_t start : snapshot.created_segments)
    {
        mem->delete_segment(start);
    }
    snapshot.created_segments.clear();
    // Restore memory state in reverse order !
    for (
        auto it = snapshot.saved_mem.rbegin(); 
        it != snapshot.saved_mem.rend();
        it++
    )
    {
        SavedMemState& saved = *it;
        mem->write_from_concrete_snapshot(
            saved.addr,
            saved.concrete_content,
            saved.size,
            mem_alert
        );
        mem->write_from_abstract_snapshot(
            saved.addr,
            saved.abstract_content,
            mem_alert
        );
    }
    snapshot.saved_mem.clear();

    // If remove, destroy the snapshot
    if (remove)
        snapshots->pop_back();
}


void MaatEngine::terminate_process(Expr status)
{
    info.stop = info::Stop::EXIT;
    info.exit_status = status;
    process->terminated = true;
}

// Return the mean of min/max by taking stride into account
ucst_t _mean_with_stride(ucst_t min, ucst_t max, ucst_t stride, bool round_upper=false)
{
    ucst_t tmp = min + ((max-min) / 2);
    ucst_t adjust = ((max-min)/2) % stride;
    if( !round_upper)
        return tmp - adjust;
    else if( adjust != 0 || (min == max - stride))
        return tmp + (stride - adjust);
    else 
        return tmp;
}

// Sets "check" to true if a model was found
// Decrements "timeout" according to the time taken to solve the constraint
// --> if solver times out, "timeout" is set to 0
unsigned int _solver_check_time(solver::Solver& solver, bool& check, unsigned int& timeout){
    std::chrono::steady_clock::time_point time_begin;
    std::chrono::steady_clock::time_point time_end;
    unsigned int prev_timeout;
    /* Measure elasped time */
    time_begin = std::chrono::steady_clock::now();
    prev_timeout = solver.timeout;
    solver.timeout = timeout;
    check = solver.check();
    solver.timeout = prev_timeout; // Restore previous timeout
    time_end = std::chrono::steady_clock::now();

    /* Check timeout */
    unsigned int used_time = std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_begin).count();
    if (used_time > timeout)
    {
        timeout = 0;
    }
    else
    {
        timeout -= used_time;
    }
    return used_time;
}

ValueSet MaatEngine::refine_value_set(Expr e)
{
    ucst_t max, min, tmp, new_min, new_max;
    std::set<std::string> var_list;
    bool check;
    unsigned int tmp_timeout = settings.symptr_refine_timeout/2;
    unsigned int used_time = 0;
    ValueSet res(e->size);

    new_min = e->value_set().min;
    new_max = e->value_set().max;

    std::unique_ptr<solver::Solver> solver = solver::new_solver();

    if (solver == nullptr)
    {
        // No solver backend
        res.set(new_min, new_max, 1);
        return res;
    }

    // Check if value set is a constant, don't try to solve it
    if( e->value_set().is_cst())
    {
        res.set_cst(new_min);
        return res;
    }

    // No overhead if already simplified
    e = simplifier->simplify(e);

    // Get path constraints involving same variables as expression 
    e->get_vars(var_list);
    solver->reset();
    for (auto& constraint : path.constraints())
    {
        if (constraint->contains_vars(var_list))
            solver->add(constraint);
    }

    // Dichotomy search to find the min
    max = e->value_set().max;
    min = e->value_set().min;
    while( max != min && tmp_timeout > 0)
    {
        tmp = _mean_with_stride(min, max, e->value_set().stride);
        solver->add(ULT(e, tmp));
        used_time += _solver_check_time(*solver, check, tmp_timeout);
        // Check result
        solver->pop();
        if (tmp_timeout == 0)
        {
            break; // Timeout
        }
        if (check)
        {
            // Expression can be smaller than mean
            max = tmp;
        }
        else
        {
            if (tmp == min)
            {
                // Only two values left, check which one if the lower bound
                solver->add(e == tmp);
                if (solver->check())
                {
                    max = min;
                }
                else
                {
                    min = max;
                }
                solver->pop();
            }
            else
            {
                // More values left, so increase mean
                min = tmp;
            }
        }
    }
    new_min = min;

    // Dichotomy search to find the max
    // (start from mean or min if already bigger than original mean)
    min = new_min;
    max = e->value_set().max;
    tmp_timeout = settings.symptr_refine_timeout/2;
    while (max != min && tmp_timeout > 0)
    {
        tmp = _mean_with_stride(min, max, e->value_set().stride, true);
        solver->add(ULT(tmp, e));
        used_time += _solver_check_time(*solver, check, tmp_timeout);
        solver->pop();
        if (tmp_timeout == 0)
        {
            break; // Timeout
        }
        if (check)
        {
            // Expression can be greater than mean
            min = tmp;
        }
        else
        {
            if (max == tmp)
            {
                // Only two values left, check which one
                solver->add(e == tmp);
                if (solver->check())
                {
                    min = max;
                }
                else
                {
                    max = min;
                }
                solver->pop();
            }
            else
            {
                // Many values left, decrease max
                max = tmp;
            }
        }
    }
    new_max = max;
    // Record this refinement
    // TODO stats.record_ptr_refinement(used_time);

    // Return refined range
    res.set(new_min, new_max, e->value_set().stride);
    return res;
}

int MaatEngine::nb_snapshots()
{
    return snapshots->size();
}

const std::string& MaatEngine::get_inst_asm(addr_t addr)
{
    return lifters[_current_cpu_mode]->get_inst_asm(addr, mem->raw_mem_at(addr));
}

void MaatEngine::load(
    const std::string& binary,
    loader::Format type,
    addr_t base,
    const std::vector<loader::CmdlineArg>& args,
    const loader::environ_t& envp,
    const std::string& virtual_path,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    bool load_interp
)
{
#ifdef HAS_LOADER_BACKEND
    std::unique_ptr<loader::Loader> l = loader::new_loader();
    l->load(
        this,
        binary,
        type,
        base,
        args,
        envp,
        virtual_path,
        libdirs,
        ignore_libs,
        load_interp
    );
#else
    throw runtime_exception("Maat was compiled without a loader backend");
#endif
}

} // namespace maat
