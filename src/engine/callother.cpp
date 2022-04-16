#include "maat/callother.hpp"
#include "maat/engine.hpp"
#include "maat/memory.hpp"
#include "maat/env/library.hpp"
#include "maat/env/env_EVM.hpp"

namespace maat{
namespace callother{

Id mnemonic_to_id(const std::string& mnemonic, Arch::Type arch)
{
    switch (arch)
    {
        case Arch::Type::X86:
        case Arch::Type::X64:
            if (mnemonic == "RDTSC") return Id::X86_RDTSC;
            if (mnemonic == "SYSCALL")
                if (arch == Arch::Type::X64) return Id::X64_SYSCALL;
            if (mnemonic == "CPUID") return Id::X86_CPUID;
            if (mnemonic == "PMINUB") return Id::X86_PMINUB;
            if (mnemonic == "INT") return Id::X86_INT;
            if (mnemonic == "LOCK") return Id::X86_LOCK;
            break;
        case Arch::Type::EVM:
            if (mnemonic == "STACK_PUSH") return Id::EVM_STACK_PUSH;
            if (mnemonic == "STACK_POP") return Id::EVM_STACK_POP;
            break;
        default:
            break;
    }
    return Id::UNSUPPORTED;
}

bool HandlerMap::has_handler(Id id)
{
    return handlers.find(id) != handlers.end();
}

handler_t HandlerMap::get_handler(Id id)
{
    if (has_handler(id))
        return handlers[id];
    else
        return nullptr;
}

void HandlerMap::set_handler(Id id, handler_t handler)
{
    handlers[id] = handler;
}

// =============== Handlers ===============
void X86_LOCK_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Just assume LOCK worked
    return;
}

void X86_RDTSC_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // We put the timestamp counter in the output parameter
    const Value& counter = engine.cpu.ctx().get(engine.arch->tsc());
    if (inst.out.size() != counter.size())
    {
        throw callother_exception("RDTSC: inconsistent sizes for output parameter and TSC");
    }
    pinst.res = counter;
}

// Use a handler for PMINUB instead of adding support in sleigh because pcode
// doesn't have an ITE opcode
// Note: PMINUB has been implemented in ghidra upstream, but the implementation
// results in overly complicated expressions w.r.t to the semantics of the instruction,
// so for now we do want to keep our own emulation callback for it.
void X86_PMINUB_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    Expr    src1 = pinst.in1.value().as_expr(),
            src2 = pinst.in2.value().as_expr();

    Expr res = ITE(
        extract(src1, 7, 0), ITECond::LT, extract(src2, 7, 0),
        extract(src1, 7, 0),
        extract(src2, 7, 0)
    );
    for (int i = 8; i < src1->size; i+=8)
    {
        res = ITE(
            extract(src1, i+7, i), ITECond::LT, extract(src2, i+7, i),
            concat(extract(src1, i+7, i), res),
            concat(extract(src2, i+7, i), res)
        );
    }
    pinst.res = res;
}

void X86_CPUID_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // http://www.flounder.com/cpuid_explorer2.htm for reference
    /* Apparently in pcode the instruction puts a pointer in the res parameter.
     * The area pointed contains: eax:ebx:edx:ecx in this order, 4 bytes each */
    ucst_t eax, ebx, ecx, edx;
    reg_t ax = (engine.arch->type == Arch::Type::X86)? X86::EAX : X64::RAX;
    ucst_t leaf = engine.cpu.ctx().get(ax).as_uint(*engine.vars);

    if (leaf == 0)
    {
        /* Leaf 0
        * Return the CPU's manufacturer ID string in ebx, edx and ecx
        * Set EAX to the higher supported leaf */
        // Set registers to "GenuineIntel"
        ebx = 0x756e6547;
        edx = 0x49656e69;
        ecx = 0x6c65746e;
        eax = 1;
    }
    else if (leaf == 1)
    {
        /* Leaf 1
        * This returns the CPU's stepping, model, and family 
        * information in register EAX (also called the signature of 
        * a CPU), feature flags in registers EDX and ECX, and
        * additional feature info in register EBX */

        // Feature information (ecx, edx)
        cst_t f_tsc = 1 << 4;
        cst_t f_sysenter = 1 << 11;
        cst_t f_mmx = 1 << 23;
        cst_t f_sse = 1 << 25;
        cst_t f_sse2 = 1 << 26;
        cst_t edx_feature_info = f_tsc | f_sysenter | f_mmx | f_sse | f_sse2;
        cst_t ecx_feature_info = 0;
        // Additional information (ebx)
        cst_t additional_info = 0;
        // Version information (eax)
        cst_t version_info = 0;

        // Set registers
        eax = version_info;
        ebx = additional_info;
        ecx = ecx_feature_info;
        edx = edx_feature_info;
    }
    else if (leaf == 0x80000000)
    {
        // eax gets highest supported leaf for extended CPUID
        eax = 0x80000004;
        // ebx, ecx, edx: reserved
        ebx = 0;
        ecx = 0;
        edx = 0;
    }
    else if (leaf == 0x80000001)
    {
        eax = 0; // Undefined for Intel CPUs
        ebx = 0; // Reserved
        // ECX
        ucst_t  lahf_available = 1 << 0;
        ecx = lahf_available;
        // EDX
        ucst_t  syscall_available = 1 << 11;
        edx = syscall_available;
    }
    else if (
        leaf == 0x80000002
        or leaf == 0x80000003
        or leaf == 0x80000004
    )
    {
        // Processor brand string continued
        // String is "ocessor 1.10GH"
        eax = 0x7365636f; // 'seco'
        ebx = 0x20726f73; // ' ros'
        ecx = 0x30312e31; // '01.1'
        edx = 0x007a4847; // '\0zHG'
    }
    else
    {
        throw callother_exception(
            Fmt() << "CPUID: unsupported leaf number: " << leaf
            >> Fmt::to_str
        );
    }
    // Write registers to reserved memory
    addr_t reserved = reserved_memory(*engine.mem);
    engine.mem->write(reserved, eax, 4);
    engine.mem->write(reserved+4, ebx, 4);
    engine.mem->write(reserved+8, edx, 4);
    engine.mem->write(reserved+12, ecx, 4);

    // Write pointer to reserved memory in res parameter
    pinst.res = Number(inst.out.size(), reserved);
    return;
}

void X64_SYSCALL_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Get syscall number
    const Value& num = engine.cpu.ctx().get(X64::RAX);
    if (num.is_symbolic(*engine.vars))
    {
        throw callother_exception("SYSCALL: syscall number is symbolic!");
    }

    // Get function to emulate syscall
    try
    {
        const env::Function& func = engine.env->get_syscall_func_by_num(
            num.as_uint(*engine.vars)
        );

        // Set a function name for logging the syscall
        std::optional<std::string> func_name;
        if (engine.settings.log_calls)
            func_name = func.name();

        // Execute function callback
        switch (func.callback().execute(engine, *engine.env->syscall_abi, func_name))
        {
            case env::Action::CONTINUE:
                break;
            case env::Action::ERROR:
                throw callother_exception(
                    "SYSCALL: Emulation callback signaled an error"
                );
            default:
                throw callother_exception(
                    "SYSCALL: Unsupported env::Action value returned by emulation callback"
                );
        }
    }
    catch(const env_exception& e)
    {
        throw callother_exception(
            Fmt() << "SYSCALL: " << e.what() >> Fmt::to_str
        );
    }
}

void X86_INT_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Get interrupt number
    cst_t num = pinst.in1.value().as_uint(*engine.vars);
    if (num != 0x80)
    {
        throw callother_exception("INT: only supported for number 0x80");
    }

    // Get syscall number
    const Value& sys_num = engine.cpu.ctx().get(X86::EAX);
    if (sys_num.is_symbolic(*engine.vars))
    {
        throw callother_exception("INT 0x80: syscall number is symbolic!");
    }

    // Get function to emulate syscall
    try
    {
        const env::Function& func = engine.env->get_syscall_func_by_num(
            sys_num.as_uint(*engine.vars)
        );
        // Execute function callback
        switch (func.callback().execute(engine, env::abi::X86_LINUX_INT80::instance()))
        {
            case env::Action::CONTINUE:
                break;
            case env::Action::ERROR:
                throw callother_exception(
                    "INT 0x80: Emulation callback signaled an error"
                );
        }
    }
    catch(const env_exception& e)
    {
        throw callother_exception(
            Fmt() << "INT 0x80: " << e.what() >> Fmt::to_str
        );
    }
}

void EVM_STOP_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    throw callother_exception("STOP: instruction not implemented");
}

void EVM_STACK_POP_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    pinst.res = contract->stack.get(0);
    contract->stack.pop();
}

void EVM_STACK_PUSH_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    contract->stack.push(pinst.in1.value());
}

// A/B = 0 if (B==0) else A/B
void EVM_DIV_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();

    if (in2.is_concrete(*engine.vars) and in2.as_number().equal_to(Number(in2.size(), 0)))
        pinst.res.set_cst(inst.out.size(), 0);
    else
        pinst.res.set_ITE(
            in2, ITECond::EQ, Value(in2.size(), 0),
            Value(inst.out.size(), 0),
            in1/in2
        );
}

// A/B = 0 if (B==0) else A/B
void EVM_SDIV_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();

    if (in2.is_concrete(*engine.vars) and in2.as_number().equal_to(Number(in2.size(), 0)))
        pinst.res.set_cst(inst.out.size(), 0);
    else
        pinst.res.set_ITE(
            in2, ITECond::EQ, Value(in2.size(), 0),
            Value(inst.out.size(), 0),
            sdiv(in1,in2)
        );
}

// A%B = 0 if (B==0) else A%B
void EVM_MOD_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();

    if (in2.is_concrete(*engine.vars) and in2.as_number().equal_to(Number(in2.size(), 0)))
        pinst.res.set_cst(inst.out.size(), 0);
    else
        pinst.res.set_ITE(
            in2, ITECond::EQ, Value(in2.size(), 0),
            Value(inst.out.size(), 0),
            in1%in2
        );
}

// A%B = 0 if (B==0) else A%B
void EVM_SMOD_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();

    if (in2.is_concrete(*engine.vars) and in2.as_number().equal_to(Number(in2.size(), 0)))
        pinst.res.set_cst(inst.out.size(), 0);
    else
    {
        pinst.res.set_ITE(
            in2, ITECond::EQ, Value(in2.size(), 0),
            Value(inst.out.size(), 0),
            smod(in1,in2)
        );
    }
}

// sext(byte, val) = sext(val[byte*8-1 : 0])
void EVM_SIGNEXTEND_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();
    Value tmp;

    if (not in1.is_concrete(*engine.vars))
        throw callother_exception("SIGNEXTEND: not supported for symbolic bytes count");

    if (in1.as_uint() >= 32)
        pinst.res = in2;
    else
    {
        tmp.set_extract(in2, 8*(in1.as_uint()+1)-1, 0);
        pinst.res.set_sext(256, tmp);
    }
}

// byte(n, val) = val[n*8+7 : n*8]
void EVM_BYTE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();

    if (in1.is_concrete(*engine.vars))
    {
        ucst_t select = in1.as_uint();
        if (select >= 32)
            pinst.res = Value(256, 0);
        else
        {
            pinst.res.set_extract(in2, select*8+7, select*8);
            pinst.res.set_zext(256, pinst.res);
        }
    }
    else
    {
        // NOTE(boyan): we can simulate the symbolic index extract by either
        // a mask+shift or with a big ITE expression. I am not sure what 
        // the SMT solver prefers...
        Value mask(256, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00", 16);
        pinst.res.set_ITE(
            Value(256, 32), ITECond::LE, in1,
            Value(256, 0),
            (in2 >> (in1*8)) & mask
        );
    }

}

void EVM_MLOAD_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    // Note: calling resolve_addr_param() should not be done from outside the MaatEngine
    // but here it's a hacky way to trigger the whole memory processing with handling of
    // symbolic pointers and triggering of event hooks
    bool success = engine.resolve_addr_param(inst.in[1], pinst.in1, contract->memory.mem());
    if (success)
        pinst.res = pinst.in1.value();
    else 
        throw callother_exception("MLOAD: fatal error reading memory");
}

void EVM_MSTORE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    // Note: calling process_store() should not be done from outside the MaatEngine
    // but here it's a hacky way to trigger the whole memory processing with handling of
    // symbolic pointers and triggering of event hooks
    bool success = engine.process_store(inst, pinst, contract->memory.mem(), true);
    if (not success)
        throw callother_exception("MSTORE: fatal error writing memory");
}

void EVM_MSIZE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    pinst.res = Value(256, contract->memory.size());
}

void EVM_DUP_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    const Value& cnt = pinst.in1.value();
    if (not cnt.is_concrete(*engine.vars))
        throw callother_exception("DUP: got symbolic position");
    // We do cnt-1 because DUP<n> gets element <n-1> in the stack
    const Value& val = contract->stack.get(cnt.as_uint(*engine.vars)-1);
    contract->stack.push(val);
}

void EVM_SWAP_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    const Value& cnt = pinst.in1.value();
    if (not cnt.is_concrete(*engine.vars))
        throw callother_exception("SWAP: got symbolic position");
    int pos = cnt.as_uint(*engine.vars);
    Value tmp = contract->stack.get(pos);
    contract->stack.set(contract->stack.get(0), pos);
    contract->stack.set(tmp, 0);
}

void EVM_SLOAD_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    // Set result but don't push, push is done by next PCODE instruction
    pinst.res = contract->storage.read(pinst.in1.value());
}

void EVM_SSTORE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    contract->storage.write(
        pinst.in1.value(),
        pinst.in2.value(),
        engine.settings
    );
}

/// Return the default handler map for CALLOTHER occurences
HandlerMap default_handler_map()
{
    HandlerMap h;
    h.set_handler(Id::X86_RDTSC, X86_RDTSC_handler);
    h.set_handler(Id::X86_CPUID, X86_CPUID_handler);
    h.set_handler(Id::X64_SYSCALL, X64_SYSCALL_handler);
    h.set_handler(Id::X86_PMINUB, X86_PMINUB_handler);
    h.set_handler(Id::X86_INT, X86_INT_handler);
    h.set_handler(Id::X86_LOCK, X86_LOCK_handler);

    h.set_handler(Id::EVM_STOP, EVM_STOP_handler);
    h.set_handler(Id::EVM_STACK_POP, EVM_STACK_POP_handler);
    h.set_handler(Id::EVM_STACK_PUSH, EVM_STACK_PUSH_handler);
    h.set_handler(Id::EVM_DIV, EVM_DIV_handler);
    h.set_handler(Id::EVM_SDIV, EVM_SDIV_handler);
    h.set_handler(Id::EVM_MOD, EVM_MOD_handler);
    h.set_handler(Id::EVM_SMOD, EVM_SMOD_handler);
    h.set_handler(Id::EVM_SIGNEXTEND, EVM_SIGNEXTEND_handler);
    h.set_handler(Id::EVM_BYTE, EVM_BYTE_handler);
    h.set_handler(Id::EVM_MLOAD, EVM_MLOAD_handler);
    h.set_handler(Id::EVM_MSTORE, EVM_MSTORE_handler);
    h.set_handler(Id::EVM_MSTORE8, EVM_MSTORE_handler); // Can use the same handler as MSTORE
    h.set_handler(Id::EVM_MSIZE, EVM_MSIZE_handler);
    h.set_handler(Id::EVM_DUP, EVM_DUP_handler);
    h.set_handler(Id::EVM_SWAP, EVM_SWAP_handler);
    h.set_handler(Id::EVM_SLOAD, EVM_SLOAD_handler);
    h.set_handler(Id::EVM_SSTORE, EVM_SSTORE_handler);

    return h;
}

} // namespace callother
} // namespace maat
