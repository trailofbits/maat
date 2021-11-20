#include "engine.hpp"
#include "solver.hpp"
#include <chrono>

namespace maat
{
    
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
    ir_blocks = std::make_shared<ir::BlockMap>();
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
    bool next_block = true;
    bool automodifying_block = false;
    // True if max_instr argument was specified (!= 0)
    bool check_max_inst = (max_inst != 0); 
    ir::Block::inst_id ir_inst_id = 0;
    std::shared_ptr<ir::Block> block = nullptr;
    addr_t current_inst_addr = 0;
    MaatEngine::branch_type_t branch_type = MaatEngine::branch_none;

    // Reset info field
    info.reset();
    _halt_after_inst = false;

    // Process pending breakpoints
    // If a breakpoint requested halting the execution, there might be other
    // breakpoints still pending, so process them all before resuming execution.
    // This gets called before handle_pending_x_mem_overwrites() because 
    // breakpoint callbacks might alter memory 
    if (!process_pending_breakpoints())
        return info.stop;

    // Handle potential pending X memory overwrites: if a user callback
    // or a user script did mess with the memory, make sure that any lifted
    // basic block that was overwritten gets its IR deleted since it is
    // no longer valid
    handle_pending_x_mem_overwrites();

    // TODO: check if program already exited

    /* Execute forever while there is a block to execute */
    while (next_block)
    {
        next_block = false; // We don't have a next block to execute yet
        automodifying_block = false;

        
        addr_t to_execute = -1; 
        if (not cpu.ctx().get(arch->pc())->is_symbolic(*vars))
        {
            to_execute = cpu.ctx().get(arch->pc())->as_uint(*vars);
        }

        // TODO: *IMPORTANT* this check is also done later but it is duplicated
        // here to avoid calling get_location() on uninitialised memory when executing
        // event unit-tests... 
        // --> This will disappear once I rework how IR blocks are managed, which will
        // make the logic of this main execution loop significantly cleaner
        if (_halt_after_inst)
        {
            info.stop = info::Stop::HOOK;
            info.addr = current_inst_addr;
            return info.stop;
        }

        // If the target to execute is a function emulated with a callback,
        // process the callback and branch to next IR block
        if (symbols->is_callback_emulated_function(to_execute))
        {
            
            if (!process_callback_emulated_function(to_execute))
                return info.stop;
            // Jump to next block after executing callback
            next_block = true;
            continue;
        }
        else if (symbols->is_missing_function(to_execute))
        {
            log.error("Branch to missing function: ", symbols->name(to_execute));
            info.stop = info::Stop::MISSING_FUNCTION;
            info.addr = to_execute;
            return info.stop;
        }

        // Initialize the IR state to execute IR code
        // Find the IR instruction to execute, it can be either 
        // - a pending state
        // - or more likely the instruction pointer by the instruction pointer
        std::optional<ir::BlockMap::InstLocation> location = std::nullopt;
        if (pending_ir_state)
        {
            location.swap(pending_ir_state);
            // Note: we don't reset temporaries when we have a pending IR state...
        }
        else
        {
            // Reset temporaries in CPU
            cpu.reset_temporaries();
            // Get the program counter
            if (cpu.ctx().get(arch->pc())->is_symbolic(*vars))
            {
                this->info.stop = info::Stop::SYMBOLIC_PC;
                return this->info.stop;
            }
            location = get_location(to_execute);
        }

        if (!location)
        {
            return this->info.stop;
        }

        // Unpack values 
        ir_inst_id = location->inst_id;
        block = location->block;
        // Set the current instruction address to -1. It will be set to the proper
        // address in the while() loop below. Setting it to -1 enables to treat the
        // first instruction executed after a branch as a new instruction, and check
        // for Trigger::BEFORE breakpoints and other stuff
        current_inst_addr = -1;
        // Execute the IR block
        while (ir_inst_id < block->nb_ir_inst())
        {
            // Check if inst_id is valid
            if (ir_inst_id < 0 or ir_inst_id >= block->nb_ir_inst())
            {
                info.stop = info::Stop::FATAL;
                log.fatal("MaatEngine::run(): got wrong inst_id. Should not happen!");
                return this->info.stop;
            }

            // Get IR instruction to execute
            const ir::Inst& inst = block->instructions()[ir_inst_id];

            // Actions to do everytime we change ASM instruction
            if (current_inst_addr != inst.addr)
            {
                // Update instruction pointer:
                cpu.ctx().set(arch->pc(), inst.addr);

                // If halt was triggered on the previous instruction, halt now
                if (_halt_after_inst)
                {
                    info.stop = info::Stop::HOOK;
                    info.addr = current_inst_addr;
                    return info.stop;
                }

                // Update current_inst_addr
                current_inst_addr = inst.addr;
                // TODO: periodically increment tsc() ?
                // TODO: increment stats with instr count
                // Check if max_instr limit has been reached
                if (check_max_inst and max_inst <= 0)
                {
                    info.stop = info::Stop::INST_COUNT;
                    info.addr = current_inst_addr;
                    return info.stop;
                }

                // EXEC event
                HANDLE_EVENT_ACTION(hooks.before_exec(*this, current_inst_addr))
                // If we already halted before executing this instruction, don't halt
                // again, neither before not after the instruction
                if (_previous_halt_before_exec == current_inst_addr)
                    _halt_after_inst = false;
                // For EXEC event, if a hook halts execution then we stop directly
                if (_halt_after_inst)
                {
                    info.stop = info::Stop::HOOK;
                    _previous_halt_before_exec = current_inst_addr;
                    return info.stop;
                }
                _previous_halt_before_exec = -1;
                // If user callback changed the address to execute, exit the loop
                if (info.addr.has_value() and *info.addr != current_inst_addr)
                {
                    next_block = true;
                    cpu.ctx().set(arch->pc(), *info.addr);
                    info.reset();
                    break;
                }
                info.reset();

                // Print current asm instruction if option is set
                if (settings.log_insts)
                {
                    log.info("Run 0x", std::hex, current_inst_addr, ": ", get_inst_asm(current_inst_addr));
                }

                // Check for breakpoints to execute when entering new ASM instruction
                if (bp_manager.check_before(*this, inst))
                {
                    // Process pending breakpoints
                    // We stop if an error occurs or if a breakpoint requests 
                    // to HALT the analysis
                    if (!process_pending_breakpoints())
                        return info.stop;
                }
                // Untrigger all breakpoints
                // Note: We do it after the bp_manager.check() call because
                // if we have a BEFORE breakpoint that halts, then continue
                // the execution and reset breakpoints at the beginning of the
                // function, the breakpoints would be re-triggered
                // Note2: we don't reset INSTANT breakpoints here, otherwise
                // they would keep retriggering when we enter their IR instruction.
                // INSTANT breakpoints need to be reset at the end of IR instructions.
                bp_manager.reset_triggers(bp::Trigger::BEFORE);
                bp_manager.reset_triggers(bp::Trigger::AFTER);
                // Update max_instructions count, we do this AFTER checking for
                // breakpoints because if we halt execution before the instruction
                // we dont want to update the instruction count
                max_inst--;
                // If block modified itself, stop executing the current block
                // to re-lift it
                if (automodifying_block)
                {
                    next_block = true; // Tell that we want to continue executing
                    break;
                }
            }

            // TODO: add settings.log_ir option
            // if settings.log_ir:
            //      log.debug("Run IR: ", inst);
            // std::cout << "DEBUG " << inst << std::endl;

            // Pre-process IR instruction
            event::Action tmp_action = event::Action::CONTINUE;
            ir::ProcessedInst& pinst = cpu.pre_process_inst(inst, tmp_action, *this);
            // Check event results on register read
            if (tmp_action == event::Action::ERROR)
            {
                log.error("Error in event callback when processing instruction");
                info.addr = current_inst_addr;
                info.stop = info::Stop::FATAL;
                return info.stop;
            }
            else if (tmp_action == event::Action::HALT)
            {
                _halt_after_inst = true;
            }
            info.reset(); // Reset info here because the CPU can not do it

            // Process Addr parameters and load them from memory
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
                ASSERT_SUCCESS(process_load(inst, pinst))
            }

            // We test & process INSTANT breakpoints before branch instructions are processed.
            // That's because if we snapshot the state before a branch instruction 
            // we want the current PC, not the updated one...
            if (bp_manager.check_instant(*this, inst, pinst))
            {
                // Set pending IR state in case breakpoints halt execution
                pending_ir_state = ir::BlockMap::InstLocation(block, ir_inst_id);
                if (!process_pending_instant_breakpoints())
                {
                    // Halt requested by instant breakpoint (or error occured)
                    return info.stop;
                }
                // reset pending IR state
                pending_ir_state.reset();
            }
            // Reset instant breakpoints
            bp_manager.reset_triggers(bp::Trigger::INSTANT);

            // If branch instruction, update control flow now
            // This will also add potential path constraints to the path manager
            if (ir::is_branch_op(inst.op))
            {
                // next_block will be set to true if we jump to another instruction
                process_branch(inst, pinst, branch_type, ir_inst_id);
            }
            else
            {
                branch_type = MaatEngine::branch_none;
            }

            // Update program counter/instruction pointer
            update_pc_if_needed(*block, ir_inst_id, branch_type);

            // We test for AFTER breakpoints after processing instruction and branching, but
            // before altering the engine state with STORE/apply_semantics. It's needed
            // so that the breakpoints can use current register/mem values in their info
            // field before they are altered when applying semantics/store.
            bp_manager.check_after(*this, inst, pinst);

            // If STORE, apply the store
            // NOTE: if overwriting code in memory, this will
            // remove the corresponding basic(s) block(s) from the block map
            // *including* the current one. But we can still use it until we 
            // finish the current ASM instruction and then break 
            if (
                inst.op == ir::Op::STORE 
                or (inst.out.is_addr() and ir::is_assignment_op(inst.op))
            )
            {
                ASSERT_SUCCESS(
                    process_store(inst, pinst, block, automodifying_block)
                )
            }

            // Simplify abstract expressions
            if (settings.force_simplify)
            {
                // Simplify only if not concrete
                if (
                    pinst.res.is_abstract() 
                    and inst.out.is_reg()
                    and not pinst.res.expr->is_concrete(*vars)
                )
                {
                    pinst.res = simplifier->simplify(pinst.res.expr);
                }
            }

            // Apply semantics to the IR CPU
            HANDLE_EVENT_ACTION(
                cpu.apply_semantics(inst, pinst, *this)
            )
            info.reset(); // Reset info here because the CPU can not do it

            // Check for breakpoints to execute at the end of an ASM instruction
            // Note: End of instruction if we branch or change instruction within the
            // same block
            if (
                // End of IR instruction conditions
                (branch_type == MaatEngine::branch_none and ir_inst_id == block->nb_ir_inst()-1) // last instruction of block
                or (branch_type == MaatEngine::branch_native) // branch native
                or (
                    ir_inst_id + 1 < block->nb_ir_inst()
                    and block->instructions()[ir_inst_id+1].addr != current_inst_addr
                ) // change ASM instruction
            )
            {
                // Process pending breakpoints
                // We stop if an error occurs or if a breakpoint requests 
                // to HALT the analysis
                if (!process_pending_breakpoints())
                    return info.stop;

                // Untrigger all breakpoints if none of them halted
                bp_manager.reset_triggers();

                // Handle executable memory overwrite
                // TODO:
                // FIXME: this currently will remove the current block
                // from the block map if it has been overwritten but the
                // executing loop won't detect that it's automodifying, thus
                // the current and now 'invalid' ir block will continue to
                // be executed until we branch  out from it
                handle_pending_x_mem_overwrites();
            }

            // Manage branching and IR instruction ID update in the end
            if (branch_type == MaatEngine::branch_native)
            {
                next_block = true;
                break;
            }
            else if (branch_type == MaatEngine::branch_none)
            {
                // No branch, go to next instruction
                if (ir_inst_id == block->nb_ir_inst()-1)
                {
                    // That was the last IR inst of this IR block, exit and go to next IR block
                    // This case occurs when the last instruction of the block has a CBRANCH
                    // in the middle of its IR and CBRANCH is not taken
                    next_block = true;
                    break;
                }
                else
                    ir_inst_id += 1;
            }
            // else: pcode relative branching, ir_inst_id has already
            // been updated by process_branch(), so do nothing and 
            // just loop again

            // Event EXEC
            HANDLE_EVENT_ACTION(hooks.after_exec(*this, current_inst_addr))
            info.reset();
        }
    }

    this->info.stop = info::Stop::NONE;
    return this->info.stop;
}

info::Stop MaatEngine::run_from(addr_t addr, unsigned int max_inst)
{
    // Reset all breakpoints if case there were pending triggered breakpoints
    bp_manager.clear_pending_bps();
    bp_manager.reset_triggers();

    // Set PC to new location to execute
    cpu.ctx().set(arch->pc(), addr);
    // Reset pending IR state
    pending_ir_state.reset();

    // Run! 
    return run(max_inst);
}


bool MaatEngine::update_pc_if_needed(
    const ir::Block& curr_block,
    ir::Block::inst_id curr_inst_id,
    MaatEngine::branch_type_t branch_type
)
{
    // - if branch is pcode-relative, the instruction address doesn't change
    // - if branch is native-branch, pc has already been updated by 'process_branch'

    // If branch is none, update according to next IR instruction in the block
    if (branch_type == MaatEngine::branch_none)
    {
        // Check if next IR inst is at another address and update PC
        if (
            curr_inst_id + 1 < curr_block.nb_ir_inst()
            and curr_block.instructions()[curr_inst_id].addr != curr_block.instructions()[curr_inst_id+1].addr
        )
        {
            cpu.ctx().set(
                arch->pc(),
                curr_block.instructions()[curr_inst_id+1].addr
            );
        }
        // If this IR inst was the last of the block, increment PC by the 
        // instruction size...
        else if (curr_inst_id == curr_block.nb_ir_inst()-1)
        {
            cpu.ctx().set(
                arch->pc(),
                curr_block.instructions()[curr_inst_id].addr +
                curr_block.instructions()[curr_inst_id].size
            );
        }
    }
    return true;
}

bool MaatEngine::process_branch(
    const ir::Inst& inst, 
    ir::ProcessedInst& pinst,
    MaatEngine::branch_type_t& branch_type,
    ir::Block::inst_id& inst_id
)
{
    if (!ir::is_branch_op(inst.op))
        throw runtime_exception("MaatEngine::process_branch(): called with non-branching instruction!");
    
    Expr in0, in1;
    addr_t next = inst.addr + inst.size;
    bool taken = false;
    std::optional<bool> opt_taken;
    bool pcode_rela = inst.in[0].is_cst();

    if (pinst.in0.is_abstract())
        in0 = pinst.in0.expr;
    else if (pinst.in0.is_concrete())
        in0 = exprcst(arch->bits(), pinst.in0.number.get_cst());
    else
        throw runtime_exception("MaatEngine::process_branch(): got empty input parameter!");

    if (pinst.in1.is_abstract())
        in1 = pinst.in1.expr;
    else if (pinst.in1.is_concrete())
        in1 = pinst.in1.as_expr();

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
                SUB_HANDLE_EVENT_ACTION(hooks.before_branch(*this, inst, in0, next), false)
                // TODO handle branch to same instruction !
                // find to which IR inst id we have to loop back !
                cpu.ctx().set(arch->pc(), in0);
                branch_type = MaatEngine::branch_native;
                SUB_HANDLE_EVENT_ACTION(hooks.after_branch(*this, inst, in0, next), false)
                info.reset();
            }
            break;
        case ir::Op::RETURN: // Equivalent to branchind
        case ir::Op::CALLIND: // Equivalent to branchind
        case ir::Op::BRANCHIND:
            SUB_HANDLE_EVENT_ACTION(hooks.before_branch(*this, inst, in0, next), false)
            // Branch to in0
            cpu.ctx().set(arch->pc(), in0);
            branch_type = MaatEngine::branch_native;
            SUB_HANDLE_EVENT_ACTION(hooks.after_branch(*this, inst, in0, next), false)
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
            SUB_HANDLE_EVENT_ACTION(
                hooks.before_branch(
                    *this,
                    inst, 
                    pcode_rela? nullptr : in0,
                    next,
                    in1 != 0, // cond,
                    opt_taken
                ), false
            )

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
                    info.addr = inst.addr;
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

            SUB_HANDLE_EVENT_ACTION(
                hooks.after_branch(
                    *this,
                    inst, 
                    pcode_rela? nullptr : in0,
                    next,
                    in1 != 0, // cond
                    taken
                ), false
            )
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


Expr MaatEngine::resolve_addr_param(const ir::Inst& inst, const ir::Param& param, ir::ProcessedInst::param_t& addr)
{
    Expr loaded;
    bool do_abstract_load = true;
    int load_size = param.size()%8 == 0 ? param.size()/8 : (param.size()/8) + 1;

    if (addr.is_concrete())
    {
        do_abstract_load = false;
        addr.auxilliary = exprcst(addr.number);
    }
    else if (addr.is_abstract() and addr.expr->is_concrete(*vars))
    {
        do_abstract_load = false;
        addr.auxilliary = addr.expr;
    }
    else if (addr.is_abstract() and addr.expr->is_concolic(*vars) and not settings.symptr_read)
    {
        do_abstract_load = false;
        addr.auxilliary = addr.expr;
    }
    else if (addr.is_abstract() and addr.expr->is_symbolic(*vars) and not settings.symptr_read)
    {
        info.stop = info::Stop::FATAL;
        log.fatal("MaatEngine::resolve_addr_param(): trying to read from symbolic pointer, but symptr_read option is disabled");
        return nullptr;
    }
    else
    {
        addr.auxilliary = addr.expr;
    }

    try
    {
        // Memory read event
        SUB_HANDLE_EVENT_ACTION(
            hooks.before_mem_read(
                *this,
                inst,
                addr.auxilliary, // addr
                load_size // size in bytes
            ),
            nullptr
        )

        if (do_abstract_load)
        {
            simplifier->simplify(addr.auxilliary);
            ValueSet range = addr.auxilliary->value_set();
            if (settings.symptr_refine_range)
            {
                range = refine_value_set(addr.auxilliary);
            }
            loaded = mem->symbolic_ptr_read(addr.auxilliary, range, load_size, settings);
        }
        else
        {
            loaded = mem->read(addr.auxilliary, load_size);
        }
        // P-code can load a number of bits that's not a multiple of 8.
        // If that's the case, readjust the loaded value size by trimming
        // the extra bits
        if (loaded->size > param.size())
        {
            loaded = extract(loaded, param.size()-1, 0);
        }

        // Mem read event
        SUB_HANDLE_EVENT_ACTION(
            hooks.after_mem_read(
                *this,
                inst,
                addr.auxilliary, // addr
                loaded // value
            ),
            nullptr
        )
        // If callback changed the loaded value, update it
        loaded = info.mem_access->value;
        // Sanity checks
        if (loaded == nullptr)
        {
            log.error("Memory read event callback changed the read value to a null pointer ");
            return nullptr;
        }
        else if (loaded->size != param.size())
        {
            log.error(
                "Memory read event callback changed the read value expression size, expected ",
                (int)param.size(), " bits but got ", (int)loaded->size
            );
            return nullptr;
        }
        // Reset info
        info.reset();
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
    addr = loaded;
    return loaded;
}

bool MaatEngine::process_addr_params(const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Don't resolve addresses for BRANCH/CBRANCH/CALL operators, they are targets, not
    // real input parameters
    if (inst.op == ir::Op::BRANCH or inst.op == ir::Op::CBRANCH or inst.op == ir::Op::CALL)
        return true;

    if (
        (inst.in[0].is_addr() and !resolve_addr_param(inst, inst.in[0], pinst.in0))
        or (inst.in[1].is_addr() and !resolve_addr_param(inst, inst.in[1], pinst.in1))
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

    if ((loaded = resolve_addr_param(inst, inst.out, pinst.in1)) == nullptr)
    {
        log.error("MaatEngine::process_load(): failed to resolve address parameter");
        return false;
    }

    // Write load result to processed inst
    if (pinst.out.is_none())
    {
        pinst.res = loaded;
    }
    else if (pinst.out.is_concrete())
    {
        if (loaded->is_concrete(*vars))
        {
            // dest and loaded have concrete values:
            // translate loaded to number and assign to dest
            Number tmp;
            tmp.set_overwrite(pinst.out.number, loaded->as_number(), inst.out.lb);
            pinst.res = tmp;
        }
        else
        {
            // dest is concrete but loaded not concrete.
            // translate dest to Expr to assign loaded
            Expr out_expr = exprcst(pinst.out.number);
            pinst.res = maat::overwrite_expr_bits(out_expr, loaded, inst.out.hb);
        }
    }
    else if (pinst.out.is_abstract())
    {
        // dest is abstract anyways so keep loaded as a constant
        pinst.res = maat::overwrite_expr_bits(pinst.out.expr, loaded, inst.out.hb);
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
    ir::ProcessedInst& pinst,
    std::shared_ptr<ir::Block> current_block,
    bool& automodifying_block
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
        if (addr.is_concrete())
        {
            do_abstract_store = false;
            store_addr = exprcst(arch->bits(), addr.number.get_ucst());
        }
        else if (addr.is_abstract() and addr.expr->is_concrete(*vars))
        {
            do_abstract_store = false;
            store_addr = addr.expr;
        }
        else if (addr.is_abstract() and addr.expr->is_concolic(*vars) and not settings.symptr_write)
        {
            do_abstract_store = false;
            store_addr = addr.expr;
        }
        else if (addr.is_abstract() and addr.expr->is_symbolic(*vars) and not settings.symptr_write)
        {
            log.fatal("MaatEngine::process_store(): trying to write at symbolic pointer but symptr_write option is disabled");
            info.stop = info::Stop::FATAL;
            return false;
        }
        else // symbolic address and symbolic writes enabled
        {
            store_addr = addr.expr;
        }
        to_store = pinst.in2.is_abstract() ? pinst.in2.expr : exprcst(pinst.in2.number);
    }
    else // out parameter is a constant address and operation is an assignment operation
    {
        do_abstract_store = false;
        store_addr = exprcst(arch->bits(), inst.out.addr());
        to_store = pinst.res.is_abstract() ? pinst.res.expr : exprcst(pinst.res.number);
    }

    // Perform the memory store
    try
    {
        // Mem read event
        SUB_HANDLE_EVENT_ACTION(
            hooks.before_mem_write(
                *this,
                inst,
                store_addr, // addr
                to_store // value
            ),
            false
        )
        // If callback changed the stored value, update it
        to_store = info.mem_access->value;
        // Sanity checks
        if (to_store == nullptr)
        {
            log.error("Memory write event callback changed the value to store to a null pointer");
            return false;
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
        SUB_HANDLE_EVENT_ACTION(
            hooks.after_mem_write(
                *this,
                inst,
                store_addr, // addr
                to_store // value
            ),
            false
        )
        info.reset(); // Reset info after event callbacks
    }
    catch(mem_exception& e)
    {
        info.stop = info::Stop::ERROR;
        info.addr = inst.addr;
        log.error("MaatEngine::process_store(): Caught memory exception: ", e.what());
        return false;
    }

    // Check if we overwrote memory that was previously lifter to IR
    if(
        (mem_alert & mem_alert_x_overwrite) and
        !do_abstract_store
    )
    {
        addr_t concrete_addr = store_addr->as_uint(*vars);
        addr_t end_addr = concrete_addr-1+(to_store->size/8);
        if (current_block->contains(concrete_addr, end_addr))
            automodifying_block = true;
        ir_blocks->remove_blocks_containing(concrete_addr, end_addr);
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
        log.error("Instruction at 0x", std::hex, inst.addr, 
            " can not be emulated (missing CALLOTHER handler)");
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

bool MaatEngine::_process_breakpoint(bp::BPManager::bp_t& breakpoint, bool& halt)
{
    // Set info field to the breakpoint info
    info = breakpoint->info();

    // If breakpoint has no callbacks, halt execution
    if (breakpoint->callbacks().empty())
        halt = true;

    // If breakpoint has callbacks, execute them
    for (const bp::BPCallback& cb : breakpoint->callbacks())
    {
        switch (cb.execute(*this))
        {
            case bp::Action::CONTINUE:
                break;
            case bp::Action::HALT:
                halt = true;
                break;
            case bp::Action::ERROR:
                info.reset();
                info.stop = info::Stop::FATAL;
                log.fatal("MaatEngine::_process_breakpoint(): error in breakpoint callback");
                return false;
            default: // Unknown return value for breakpoint...
                info.reset();
                info.stop = info::Stop::FATAL;
                std::string _name;
                if (info.bp_name.has_value())
                    _name = info.bp_name.value();
                log.fatal(
                    "MaatEngine::_process_breakpoint(): breakpoint callback for '",
                    _name,
                    "' returned unsupported Action value: "
                );
                return false;
        }
    }
    // No error, return true
    return true;
}

bool MaatEngine::process_pending_instant_breakpoints()
{
    bp::BPManager::bp_t breakpoint = nullptr;
    bool halt = false;
    while ((breakpoint = bp_manager.next_pending_instant_bp()) != nullptr)
    {
        if (!_process_breakpoint(breakpoint, halt))
        {
            // Error while executing breakpoints
            return false;
        }
    }
    return !halt;
}


bool MaatEngine::process_pending_breakpoints()
{
    bp::BPManager::bp_t breakpoint = nullptr;
    bool halt = false;
    while ((breakpoint = bp_manager.next_pending_bp()) != nullptr)
    {
        if (!_process_breakpoint(breakpoint, halt))
        {
            return false;
        }
    }
    return !halt;
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


std::optional<ir::BlockMap::InstLocation> MaatEngine::get_location(addr_t addr)
{
    std::shared_ptr<ir::Block> block;
    ir::Block::inst_id ir_inst_id = 0;
    std::optional<ir::BlockMap::InstLocation> location = ir_blocks->get_inst_at(addr);
    if (location.has_value())
        return location;

    // The code hasn't been lifted yet so we disassemble it
    try
    {
        block = lifters[_current_cpu_mode]->lift_block(
            addr,
            mem->raw_mem_at(addr),
            0xfffffff,
            0xffffffff,
            nullptr, // is_symbolic
            nullptr, // is_tainted
            true
        );
        
        if (block == nullptr)
        {
            throw lifter_exception("MaatEngine::run(): lifter returned NULL IR Block");
        }
        ir_inst_id = 0;
    }
    catch(unsupported_instruction_exception& e)
    {
        this->info.stop = info::Stop::UNSUPPORTED_INST;
        log.error("Lifter error: ", e.what());
        return std::nullopt;
    }
    catch(lifter_exception& e)
    {
        log.fatal("Lifter error: ", e.what());
        this->info.stop = info::Stop::FATAL;
        return std::nullopt;;
    }
        // TODO: check if symbolic
        // TODO: check if optimize IR
        // --> Not check for breakpoints and stuff here, do it later...

    // Add new block to IR block map
    ir_blocks->add(block);

    // return location
    return std::make_optional<ir::BlockMap::InstLocation>(block, ir_inst_id);
}

void MaatEngine::handle_pending_x_mem_overwrites()
{
    for (auto& mem_access : mem->_get_pending_x_mem_overwrites())
    {
        ir_blocks->remove_blocks_containing(mem_access.first, mem_access.second);
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
    snapshot.page_permissions = mem->page_manager.regions();
    snapshot.path = path.take_snapshot();
    // Save current breakpoint triggers
    for (auto& bp : bp_manager.get_all())
    {
        snapshot.bp_triggers.push_back(std::make_pair(bp->id(), bp->is_triggered()));
    }
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
    mem->page_manager.set_regions(std::move(snapshot.page_permissions));
    path.restore_snapshot(snapshot.path);

    // Restore breakpoint triggers
    for (auto p : snapshot.bp_triggers)
    {
        bp_manager.get_by_id(p.first)->set_triggered(p.second);
    }
    snapshot.bp_triggers.clear();
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
