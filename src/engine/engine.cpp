#include "maat/engine.hpp"
#include "maat/solver.hpp"
#include "maat/stats.hpp"
#include "maat/env/env_EVM.hpp"

namespace maat
{
    
using namespace maat::event;

int MaatEngine::_uid_cnt = 0;

MaatEngine::MaatEngine(Arch::Type _arch, env::OS os): env(nullptr), _uid(++_uid_cnt)
{
    Endian endianness = Endian::LITTLE;
    switch (_arch)
    {
        case Arch::Type::X86:
            arch = std::make_shared<X86::ArchX86>();
            lifters[CPUMode::X86] = std::make_shared<Lifter>(CPUMode::X86);
            _current_cpu_mode = CPUMode::X86;
            break;
        case Arch::Type::X64:
            arch = std::make_shared<X64::ArchX64>();
            lifters[CPUMode::X64] = std::make_shared<Lifter>(CPUMode::X64);
            _current_cpu_mode = CPUMode::X64;
            break;
        case Arch::Type::EVM:
            arch = std::make_shared<EVM::ArchEVM>();
            lifters[CPUMode::EVM] = std::make_shared<Lifter>(CPUMode::EVM);
            _current_cpu_mode = CPUMode::EVM;
            env = std::make_shared<env::EVM::EthereumEmulator>();
            endianness = Endian::BIG;
            break;
        case Arch::Type::RISCV:
            arch = std::make_shared<RISCV::ArchRISCV>();
            lifters[CPUMode::RISCV] = std::make_shared<Lifter>(CPUMode::RISCV);
            _current_cpu_mode = CPUMode::RISCV;
            break;
        case Arch::Type::ARM32:
            arch = std::make_shared<ARM32::ArchARM32>();
            lifters[CPUMode::A32] = std::make_shared<Lifter>(CPUMode::A32);
            _current_cpu_mode = CPUMode::A32;
            break;
        case Arch::Type::NONE:
            arch = std::make_shared<ArchNone>();
            _current_cpu_mode = CPUMode::NONE;
            break;
        default:
            throw runtime_exception("MaatEngine(): unsupported architecture");
    }

    // Set environment if not already set automatically by architecture
    if (env == nullptr)
    {
        switch (os)
        {
            case env::OS::LINUX:
                env = std::make_shared<env::LinuxEmulator>(_arch);
                break;
            default:
                env = std::make_shared<env::EnvEmulator>(_arch, env::OS::NONE);
                break;
        }
    }

    symbols = std::make_shared<SymbolManager>();
    path = std::make_shared<PathManager>();
    vars = std::make_shared<VarContext>(0, endianness);
    snapshots = std::make_shared<SnapshotManager<Snapshot>>();
    mem = std::make_shared<MemEngine>(vars, arch->bits(), snapshots, endianness);
    process = std::make_shared<ProcessInfo>();
    simplifier = NewDefaultExprSimplifier();
    callother_handlers = callother::default_handler_map();
    // Initialize all registers to their proper bit-size with value 0
    cpu = ir::CPU(arch->nb_regs);
    cpu.ctx().init_alias_getset(arch->type);
    for (reg_t reg = 0; reg < arch->nb_regs; reg++)
        cpu.ctx().set(reg, Number(arch->reg_size(reg), 0));
    // Initialize some variables for execution statefullness
    _previous_halt_before_exec = -1;
#ifdef MAAT_PYTHON_BINDINGS
    self_python_wrapper_object = nullptr;
#endif
}

MaatEngine::MaatEngine(
    const MaatEngine& other,
    std::set<std::string>& duplicate,
    std::set<std::string>& share
): env(nullptr), _uid(++_uid_cnt)
{
    _current_cpu_mode = other._current_cpu_mode;
    _halt_after_inst = other._halt_after_inst;
    _halt_after_inst_reason = other._halt_after_inst_reason;
    _previous_halt_before_exec = other._previous_halt_before_exec;
    current_ir_state = other.current_ir_state;
    lifters = other.lifters;
    // snapshots
    if (duplicate.count("snapshots"))
        // TODO snapshots = std::make_shared<SnapshotManager<Snapshot>>(*other.snapshots);
        throw runtime_exception("MaatEngine: duplication of snapshots manager not yet implemented");
    else
        snapshots = std::make_shared<SnapshotManager<Snapshot>>();
    simplifier = other.simplifier;
    callother_handlers = other.callother_handlers;
    arch = other.arch;
    symbols = std::make_shared<SymbolManager>();
    // var context
    if (share.count("vars"))
        vars = other.vars;
    else
        vars = std::make_shared<VarContext>();
    // memory
    if (share.count("mem"))
        mem = other.mem;
    else
        mem = std::make_shared<MemEngine>(
            vars, arch->bits(), snapshots, other.mem->endianness()
        );
    cpu = other.cpu;
    // hooks
    if (duplicate.count("hooks"))
        hooks = other.hooks;
    // path manager
    if (share.count("path"))
        path = other.path;
    else
        path = std::make_shared<PathManager>();

    symbols = other.symbols;
    // process
    if (share.count("process"))
        process = other.process;
    else
        process = std::make_shared<ProcessInfo>();
    // Always share environment for now
    env = other.env;
#ifdef MAAT_PYTHON_BINDINGS
    self_python_wrapper_object = nullptr;
#endif
}

int MaatEngine::uid() const {
    return _uid;
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
        _stop_after_inst(info::Stop::HOOK);\
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
        _stop_after_inst(info::Stop::HOOK);\
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
    _halt_after_inst_reason = info::Stop::NONE;

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
            info.exit_status = process->exit_status;
            return info.stop;
        }

        // Get next instruction to execute
        if (not cpu.ctx().get(arch->pc()).is_symbolic(*vars))
        {
            to_execute = cpu.ctx().get(arch->pc()).as_uint(*vars);
            // Reload pending IR state if it matches current PC
            if (
                current_ir_state.has_value() and
                current_ir_state->addr == to_execute
            ){
                ir_inst_id = current_ir_state->inst_id;
            }
            else
            {
                ir_inst_id = 0;
                // Reset temporaries in CPU for new instruction
                cpu.reset_temporaries();
            }
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
            // Update internal IR state
            current_ir_state = ir::IRMap::InstLocation(asm_inst->addr(), ir_inst_id);

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

            // Check for unsupported instruction
            if (inst.op == ir::Op::UNSUPPORTED)
            {
                info.stop = info::Stop::UNSUPPORTED_INST;
                info.addr = asm_inst->addr();
                log.fatal(
                    "Could not lift instruction at 0x", std::hex, asm_inst->addr(),
                    ": ", get_inst_asm(asm_inst->addr())
                );
                return info.stop;
            }

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
                _stop_after_inst(info::Stop::HOOK);
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
                    process_store(inst, pinst, *mem)
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
                // Simplify only we set a register to a non concrete value
                // or if the operation was a callother
                if (
                    pinst.res.is_abstract() 
                    and (inst.out.is_reg() or inst.op == ir::Op::CALLOTHER)
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

            // Record executed IR instruction in statistics
            MaatStats::instance().inc_executed_ir_insts();

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

        // Record executed instruction in statistics
        MaatStats::instance().inc_executed_insts();

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

        // Reset current IR state (we change instruction)
        current_ir_state.reset();

        if (_halt_after_inst)
        {
            info.stop = _halt_after_inst_reason;
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
    current_ir_state.reset();

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

    Value in0 = pinst.in0.value(); 
    Value in1 = pinst.in1.value();
    Value next(arch->bits(), asm_inst.addr()+asm_inst.raw_size());
    bool taken = false;
    std::optional<bool> opt_taken;
    bool pcode_rela = inst.in[0].is_cst();
    size_t pc_size = arch->reg_size(arch->pc());

    if (in0.is_none())
        throw runtime_exception("MaatEngine::process_branch(): got empty input parameter!");

    // Adjust operand size to PC size if needed
    if (in0.size() < pc_size)
        in0.set_concat(
            Value(pc_size-in0.size(), 0),
            in0
        );
    else if (in0.size() > pc_size)
        in0.set_extract(in0, pc_size-1, 0);

    switch (inst.op)
    {
        case ir::Op::CALL: // Equivalent to branch
        case ir::Op::BRANCH:
            if (inst.in[0].is_cst()) // internal pcode branch
            {
                inst_id += (int)in0.as_int();
                branch_type = MaatEngine::branch_pcode;
            }
            else // address, branch to it
            {
                // Trigger hooks
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
            // If we record a symbolic constraints, simplify it...
            if (settings.record_path_constraints and not in1.is_concrete(*vars))
                in1 = simplifier->simplify(in1.as_expr());

            // Try to resolve the branch is not symbolic
            if (not in1.is_symbolic(*vars))
            {
                if (in1.as_uint(*vars) != 0) // branch condition is true, branch to target
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
                 (not in1.is_concrete(*vars)) and
                  hooks.has_hooks(Event::PATH, When::BEFORE)
                )
            )
            {
                info.addr = asm_inst.addr();
                SUB_HANDLE_EVENT_ACTION(
                    hooks.before_branch(
                        *this,
                        pcode_rela? Value() : in0,
                        next,
                        in1 != 0, // cond,
                        opt_taken
                    ), false
                )
            }

            // Resolve the branch again to account for potential changes made by
            // user callbacks
            if (in1.is_symbolic(*vars))
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
            else if (in1.as_uint(*vars) != 0) // branch condition is true, branch to target
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
                    inst_id += (int)in0.as_int();
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
                    and not in1.is_concrete(*vars)
                )
                {
                    path->add(in1 != 0);
                }
            }
            else // branch condition is false, so no branch
            {
                branch_type = MaatEngine::branch_none;
                // Add path constraint
                if (
                    settings.record_path_constraints
                    and not in1.is_concrete(*vars)
                )
                {
                    path->add(in1 == 0);
                }
            }
            if (
                hooks.has_hooks(Event::BRANCH, When::AFTER) or
                (
                 (not in1.is_concrete(*vars)) and
                  hooks.has_hooks(Event::PATH, When::AFTER)
                )
            )
            {
                info.addr = asm_inst.addr();
                SUB_HANDLE_EVENT_ACTION(
                    hooks.after_branch(
                        *this, 
                        pcode_rela? Value() : in0,
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


bool MaatEngine::resolve_addr_param(
    const ir::Param& param,
    ir::ProcessedInst::param_t& addr_param,
    MemEngine& mem_engine
)
{
    const Value& addr = addr_param.value();
    Value loaded;
    bool do_abstract_load = true;
    int load_size = param.size()%8 == 0 ? param.size()/8 : (param.size()/8) + 1;

    if (
        addr.is_concrete(*vars)
        or (
            addr.is_concolic(*vars) and
            not settings.symptr_read
        )
    )
    {
        do_abstract_load = false;
        addr_param.auxilliary = addr.as_number(*vars);
    }
    else if (addr.is_symbolic(*vars) and not settings.symptr_read)
    {
        info.stop = info::Stop::FATAL;
        log.fatal("MaatEngine::resolve_addr_param(): trying to read from symbolic pointer, but symptr_read option is disabled");
        return false;
    }
    else
    {
        addr_param.auxilliary = addr;
    }

    try
    {
        // Memory read event
        if (hooks.has_hooks({Event::MEM_R, Event::MEM_RW}, When::BEFORE))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.before_mem_read(
                    *this,
                    addr_param.auxilliary, // addr
                    load_size // size in bytes
                ),
                false
            )
        }

        if (do_abstract_load)
        {
            Expr load_addr = simplifier->simplify(addr_param.auxilliary.as_expr());
            ValueSet range = load_addr->value_set();
            if (settings.symptr_refine_range)
            {
                MaatStats::instance().start_refine_symptr_read();
                range = refine_value_set(load_addr);
                MaatStats::instance().done_refine_symptr_read();
            }
            mem_engine.symbolic_ptr_read(loaded, load_addr, range, load_size, settings);
        }
        else
        {
            mem_engine.read(loaded, addr_param.auxilliary.as_uint(*vars), load_size);
        }
        // P-code can load a number of bits that's not a multiple of 8.
        // If that's the case, readjust the loaded value size by trimming
        // the extra bits
        if (loaded.size() > param.size())
        {
            loaded.set_extract(loaded, param.size()-1, 0);
        }

        // Mem read event
        if (hooks.has_hooks({Event::MEM_R, Event::MEM_RW}, When::AFTER))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.after_mem_read(
                    *this,
                    addr_param.auxilliary, // addr
                    loaded // value
                ),
                false
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
        return false;
    }

    // Update processed parameter (auxiliary already set at the 
    // beginning of the method). Here we can just re-assign 'addr'
    // to an abstract value because Address parameters are expected 
    // to always trigger abstract processing in the CPU
    addr_param = loaded;
    return not addr_param.value().is_none();
}

bool MaatEngine::process_addr_params(const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Don't resolve addresses for BRANCH/CBRANCH/CALL operators, they are targets, not
    // real input parameters
    if (inst.op == ir::Op::BRANCH or inst.op == ir::Op::CBRANCH or inst.op == ir::Op::CALL)
        return true;

    if (
        (inst.in[0].is_addr() and !resolve_addr_param(inst.in[0], pinst.in0, *mem))
        or (inst.in[1].is_addr() and !resolve_addr_param(inst.in[1], pinst.in1, *mem))
    )
    {
        log.error("MaatEngine::process_addr_params(): failed to process IR inst: ", inst);
        return false;
    }

    return true;
}

bool MaatEngine::process_load(const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    if (not resolve_addr_param(inst.out, pinst.in1, *mem))
    {
        log.error("MaatEngine::process_load(): failed to resolve address parameter");
        return false;
    }

    const Value& loaded = pinst.in1.value();

    // Write load result to processed inst
    if (pinst.out.is_none() or pinst.out.value().size() == loaded.size())
    {
        pinst.res = loaded;
    }
    else
    {
        pinst.res.set_overwrite(pinst.out.value(), loaded, inst.out.lb);
    }

    // Success
    return true;
}

bool MaatEngine::process_store(
    const ir::Inst& inst,
    ir::ProcessedInst& pinst,
    MemEngine& mem_engine,
    bool treat_as_pcode_store
)
{
    mem_alert_t mem_alert = maat::mem_alert_none;
    const Value& addr = pinst.in1.value();
    bool do_abstract_store = true;
    addr_t concrete_store_addr = 0;
    Expr abstract_store_addr = nullptr;
    Value to_store = pinst.in2.value();

    // Get address and value to store
    if (inst.op == ir::Op::STORE or treat_as_pcode_store)
    {
        if (
            addr.is_concrete(*vars)
            or (
                addr.is_concolic(*vars) and
                not settings.symptr_write
            )
        )
        {
            do_abstract_store = false;
            // WARNING: this truncates addresses on more than 64 bits...
            concrete_store_addr = addr.as_number(*vars).get_ucst();
        }
        else if (addr.is_symbolic(*vars) and not settings.symptr_write)
        {
            log.fatal("MaatEngine::process_store(): trying to write at symbolic pointer but symptr_write option is disabled");
            info.stop = info::Stop::FATAL;
            return false;
        }
        else // symbolic address and symbolic writes enabled
        {
            abstract_store_addr = addr.as_expr();
        }
        to_store = pinst.in2.value();
    }
    else // out parameter is a constant address and operation is an assignment operation
    {
        do_abstract_store = false;
        concrete_store_addr = inst.out.addr();
        to_store = pinst.res;
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
                    addr, // addr
                    to_store // value
                ),
                false
            )
        }

        if (do_abstract_store)
        {
            abstract_store_addr = simplifier->simplify(abstract_store_addr);
            ValueSet range = abstract_store_addr->value_set();
            if (settings.symptr_refine_range)
            {
                MaatStats::instance().start_refine_symptr_write();
                range = refine_value_set(abstract_store_addr);
                MaatStats::instance().done_refine_symptr_write();
            }
            mem_engine.symbolic_ptr_write(abstract_store_addr, range, to_store, settings, &mem_alert, true);
        }
        else
        {
            mem_engine.write(concrete_store_addr, to_store, &mem_alert, true);
        }
        // Mem write event
        if (hooks.has_hooks({Event::MEM_W, Event::MEM_RW}, When::AFTER))
        {
            SUB_HANDLE_EVENT_ACTION(
                hooks.after_mem_write(
                    *this,
                    addr, // addr
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
        switch (func.callback().execute(*this, *env->default_abi))
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

// Return the number of bytes from 'addr' to the end of the mapping
// that contains addr
int _get_distance_till_end_of_map(MemEngine& mem, addr_t addr)
{
    int res = 0;
    addr_t tmp_end = 0;
    for (const auto& map : mem.mappings.get_maps())
    {
        if (map.contains(addr))
            res = map.end - addr + 1;
        else if (map.start == tmp_end+1 and res != 0)
            res += map.end - map.start + 1;
        else if (map.start > addr)
            break;
        tmp_end = map.end;
    }
    return res;
}

const ir::AsmInst& MaatEngine::get_asm_inst(addr_t addr, unsigned int max_inst)
{
    ir::IRMap& ir_map = ir::get_ir_map(mem->uid());
    if (ir_map.contains_inst_at(addr))
    {
        return ir_map.get_inst_at(addr);
    }
    // The code hasn't been lifted yet so we disassemble it
    try
    {
        // Number of instructions to lift is the max number of instructions
        // to execute, or 'until end of basic block' (0xffffffff) if
        // max_inst == 0
        unsigned int code_size = (unsigned int)_get_distance_till_end_of_map(*mem, addr);
        unsigned int max_inst_to_lift = max_inst == 0? 0xffffffff : max_inst;

        // TODO: check if code region is symbolic
        if (
            not lifters[_current_cpu_mode]->lift_block(
                log,
                ir_map,
                addr,
                mem->raw_mem_at(addr),
                code_size,
                max_inst_to_lift,
                nullptr, // is_symbolic
                nullptr, // is_tainted
                true
            )
        ){
            throw lifter_exception("MaatEngine::get_asm_inst(): failed to lift instructions");
        }
        return ir_map.get_inst_at(addr);
    }
    catch(const unsupported_instruction_exception& e)
    {
        this->info.stop = info::Stop::UNSUPPORTED_INST;
        log.error("Lifter error: ", e.what());
        throw lifter_exception("MaatEngine::get_asm_inst(): lifter error");
    }
    catch(const lifter_exception& e)
    {
        log.error("Lifter error: ", e.what());
        this->info.stop = info::Stop::FATAL;
        throw lifter_exception("MaatEngine::get_asm_inst(): lifter error");
    }
    catch(const mem_exception& e)
    {
        log.fatal("Memory exception while trying to lift code: ", e.what());
        this->info.stop = info::Stop::FATAL;
        throw lifter_exception("MaatEngine::get_asm_inst(): lifter error");
    }
}

void MaatEngine::handle_pending_x_mem_overwrites()
{
    for (auto& mem_access : mem->_get_pending_x_mem_overwrites())
    {
        ir::IRMap& ir_map = ir::get_ir_map(mem->uid());
        ir_map.remove_insts_containing(mem_access.first, mem_access.second);
    }
    mem->_clear_pending_x_mem_overwrites();
}

/// Take a snapshot of the current engine state
MaatEngine::snapshot_t MaatEngine::take_snapshot()
{
    Snapshot& snapshot = snapshots->emplace_back();
    snapshot.cpu = cpu; // Copy CPU
    snapshot.symbolic_mem = mem->symbolic_mem_engine.take_snapshot();
    snapshot.pending_ir_state = current_ir_state;
    snapshot.info = info;
    snapshot.process = std::make_shared<ProcessInfo>(*process);
    snapshot.page_permissions = mem->page_manager.regions();
    snapshot.mem_mappings = mem->mappings.get_maps();
    snapshot.path = path->take_snapshot();
    snapshot.env = env->take_snapshot();
    // Snapshot ID is its index in the snapshots list
    return snapshots->size()-1;
}

/** Restore the engine state to 'snapshot'. If remove is true, the 
 * snapshot is removed after being restored */
void MaatEngine::restore_snapshot(snapshot_t snapshot, bool remove)
{
    size_t idx(snapshot);
    if (idx < 0)
    {
        throw snapshot_exception("MaatEngine::restore_snapshot(): called with invalid snapshot parameter!");
    }

    if (not snapshots->active())
    {
        throw snapshot_exception("MaatEngine::restore_snapshot(): No more snapshots to restore");
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
    // Check that there are snapshots
    if (not snapshots->active())
    {
        throw snapshot_exception("MaatEngine::restore_last_snapshot(): No more snapshots to restore");
    }

    mem_alert_t mem_alert = maat::mem_alert_none;
    Snapshot& snapshot = snapshots->back();

    if (remove)
    {
        // Use move semantics only when the snpashot gets deleted
        cpu = std::move(snapshot.cpu);
        current_ir_state.swap(snapshot.pending_ir_state);
    }
    else
    {
        cpu = snapshot.cpu;
        current_ir_state = snapshot.pending_ir_state;
    }
    mem->symbolic_mem_engine.restore_snapshot(snapshot.symbolic_mem);
    info = snapshot.info;
    process = snapshot.process;
    mem->page_manager.set_regions(std::move(snapshot.page_permissions));
    mem->mappings.set_maps(std::move(snapshot.mem_mappings));
    path->restore_snapshot(snapshot.path);
    env->restore_snapshot(snapshot.env, remove);
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


void MaatEngine::terminate_process(Value status)
{
    info.stop = info::Stop::EXIT;
    info.exit_status = status;
    process->terminated = true;
    process->exit_status = status;
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
    for (auto& constraint : path->constraints())
    {
        // FIXME(boyan): we should use get_related_vars() once we
        // fix the implementation
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


void MaatEngine::_stop_after_inst(info::Stop reason)
{
    _halt_after_inst = true;
    _halt_after_inst_reason = reason;
}

std::vector<uint8_t> MaatEngine::get_inst_bytes(addr_t addr)
{
    const ir::AsmInst& inst = get_asm_inst(addr);
    std::vector<uint8_t> res((size_t)inst.raw_size());
    uint8_t* raw_bytes = mem->raw_mem_at(addr);
    for (int i = 0; i < inst.raw_size(); i++)
        res[i] = raw_bytes[i];
    return res;
}

void MaatEngine::load(
    const std::string& binary,
    loader::Format type,
    addr_t base,
    const std::vector<loader::CmdlineArg>& args,
    const loader::environ_t& envp,
    const std::unordered_map<std::string, std::string>& virtual_fs,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    bool load_interp
)
{
    if (arch->type == Arch::Type::EVM)
    {
        // Use special loader for EVM
        loader::LoaderEVM().load(this, binary, args, envp);
    }
    else
    {
#ifdef MAAT_HAS_LOADER_BACKEND
        // TODO(boyan): pass binary type to new_loader() so that it returns
        // the appropriate loader. i.e LoaderLIEF, LoaderXXXX...
        std::unique_ptr<loader::Loader> l = loader::new_loader();
        l->load(
            this,
            binary,
            type,
            base,
            args,
            envp,
            virtual_fs,
            libdirs,
            ignore_libs,
            load_interp
        );
#else
        throw runtime_exception("Maat was compiled without a suitable loader backend");
#endif
    }
}

serial::uid_t MaatEngine::class_uid() const
{
    return serial::ClassId::MAAT_ENGINE;
}

void MaatEngine::dump(serial::Serializer& s) const
{
    s << bits(_current_cpu_mode) << bits(_halt_after_inst)
      << bits(_halt_after_inst_reason)
      << bits(_previous_halt_before_exec)
      << current_ir_state << path
      << snapshots << arch << vars << mem
      << cpu << env << symbols << process
      << info << settings;
    // Lifter(s)
    s << bits(lifters.size());
    for (const auto& [key,val] : lifters)
        s << bits(key) << val;
}

void MaatEngine::load(serial::Deserializer& d)
{
    d >> bits(_current_cpu_mode) >> bits(_halt_after_inst)
      >> bits(_halt_after_inst_reason)
      >> bits(_previous_halt_before_exec)
      >> current_ir_state >> path
      >> snapshots >> arch >> vars >> mem
      >> cpu >> env >> symbols >> process
      >> info >> settings;
    cpu.ctx().init_alias_getset(arch->type);
    // Lifter(s)
    size_t tmp_size;
    d >> bits(tmp_size);
    for (int i = 0; i < tmp_size; i++)
    {
        CPUMode mode;
        std::shared_ptr<Lifter> lifter;
        d >> bits(mode) >> lifter;
        lifters[mode] = lifter;
    }
}


} // namespace maat
