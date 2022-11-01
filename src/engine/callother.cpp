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
        case Arch::Type::RISCV:
            if (mnemonic == "ecall") return Id::RISCV_ECALL;
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
    pinst.res.set_overwrite(pinst.out.value(), res, inst.out.lb);
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

void RISCV_ECALL_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // Get syscall number
    const Value& num = engine.cpu.ctx().get(RISCV::A7);
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

// Helper function that ensures a contract transaction is set
void _check_transaction_exists(env::EVM::contract_t contract)
{
    if (not contract->transaction.has_value())
        throw callother_exception("Trying to access transaction but no transaction is set");
}

// Helper that ensures that EVM static flag is not set
void _check_static_flag(const std::string& inst, MaatEngine& engine)
{
    if (env::EVM::get_ethereum(engine)->static_flag)
        throw callother_exception(
            Fmt() << "Can not execute " << inst << " with static flag set in EVM" >> Fmt::to_str
        );
}

void EVM_STOP_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_transaction_exists(contract);
    engine.terminate_process(Value(32, (int)env::EVM::TransactionResult::Type::STOP));
    contract->transaction->result = env::EVM::TransactionResult(
        env::EVM::TransactionResult::Type::STOP,
        {}
    );
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

// exponentiation
void EVM_EXP_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    const Value& in1 = pinst.in1.value();
    const Value& in2 = pinst.in2.value();

    // X**0 is always 1
    if (in2.is_concrete(*engine.vars) and in2.as_number().equal_to(Number(in2.size(), 0)))
        pinst.res.set_cst(inst.out.size(), 1);
    else if (in1.is_symbolic(*engine.vars) or in2.is_symbolic(*engine.vars))
    {
        throw callother_exception("EXP: exponentiation operation not supported with fully symbolic arguments");
    }
    // TODO(boyan): we could concretize the arguments if they are concolic,
    // but then if we later change the concrete values we loose soundness...
    else if (in1.is_concolic(*engine.vars) or in2.is_concolic(*engine.vars))
    {
        throw callother_exception("EXP: exponentiation operation not yet supported with fully symbolic arguments");
    }
    else
    {
        Number res(256);
        res.set_exp(in1.as_number(), in2.as_number());
        pinst.res = Value(res);
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

// byte(n, val) = nth byte of val, starting from most significant byte
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
            pinst.res.set_extract(
                in2,
                in2.size()-1-(select*8),
                in2.size()-8-(select*8)
            );
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
            (in2 >> (in2.size()-8-(in1*8))) & mask
        );
    }

}

void EVM_MLOAD_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    contract->memory.expand_if_needed(pinst.in1.value(), inst.out.size()/8);
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
    contract->memory.expand_if_needed(pinst.in1.value(), inst.in[2].size()/8);
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
    pinst.res = contract->storage->read(pinst.in1.value());
}

void EVM_SSTORE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    _check_static_flag("SSTORE", engine);
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    contract->storage->write(
        pinst.in1.value(),
        pinst.in2.value(),
        engine.settings
    );
}

void EVM_ENV_INFO_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    unsigned int evm_inst = pinst.in1.value().as_uint();
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    switch(evm_inst)
    {
        // TODO(boyan): most of these instructions could push the value on
        // the stack directly to avoid executing an additional stack_push
        // IR instruction to push the result
        case 0x30: // ADDRESS
            pinst.res = contract->address;
            break;
        case 0x32: // ORIGIN
            _check_transaction_exists(contract);
            pinst.res = zext(256, contract->transaction->origin);
            break;
        case 0x33: // CALLER
            _check_transaction_exists(contract);
            pinst.res = zext(256, contract->transaction->sender);
            break;
        case 0x34: // CALLVALUE
            _check_transaction_exists(contract);
            pinst.res = contract->transaction->value;
            break;
        case 0x35: // CALLDATALOAD
        {
            _check_transaction_exists(contract);
            const Value& offset = pinst.in2.value();
            if (not offset.is_concrete(*engine.vars))
                throw callother_exception("CALLDATALOAD: not supported with symbolic offset");
            pinst.res = contract->transaction->data_load_word(offset.as_uint(*engine.vars));
            break;
        }
        case 0x36: // CALLDATASIZE
            _check_transaction_exists(contract);
            pinst.res = Value(256, contract->transaction->data_size());
            break;
        case 0x37: // CALLDATACOPY
        {
            _check_transaction_exists(contract);
            Value addr = contract->stack.get(0);
            addr_t offset = contract->stack.get(1).as_uint(*engine.vars);
            unsigned int size = contract->stack.get(2).as_uint(*engine.vars);
            contract->stack.pop(3);
            for (const auto& val : contract->transaction->data_load_bytes(offset, size))
            {
                contract->memory.write(addr, val);
                addr = addr + val.size()/8;
            }
            break;
        }
        case 0x38: // CODESIZE
            pinst.res = Value(256, contract->code_size);
            break;
        case 0x39: // CODECOPY
        {
            Value addr = contract->stack.get(0);
            addr_t offset = contract->stack.get(1).as_uint(*engine.vars);
            unsigned int size = contract->stack.get(2).as_uint(*engine.vars);
            contract->stack.pop(3);
            for (const auto& val : engine.mem->read_buffer(offset, size, 1))
            {
                contract->memory.write(addr, val);
                addr = addr + val.size()/8;
            }
            break;
        }
        case 0x3a: // GASPRICE
        {
            pinst.res = env::EVM::get_ethereum(engine)->gas_price;
            break;
        }
        case 0x3b: // EXTCODESIZE
        {
            Value addr = contract->stack.get(0);
            contract->stack.pop();
            if (not addr.is_concrete(*engine.vars))
                throw callother_exception("EXTCODESIZE: not supported for symbolic address");
            env::EVM::contract_t ext_contract = env::EVM::get_ethereum(engine)->get_contract_by_address(
                extract(addr, 159, 0).as_number() // Extract 160 bits for address
            );
            if (ext_contract == nullptr)
                // If no contract at that address return 0
                pinst.res = Value(256, 0);
            else
                pinst.res = Value(256, ext_contract->code_size);
            break;
        }
        case 0x3d: // RETURNDATASIZE
        {
            if (not contract->result_from_last_call.has_value())
                pinst.res = Value(256, 0);
            else
                pinst.res = Value(256, contract->result_from_last_call->return_data_size());
            break;
        }
        case 0x3e: // RETURNDATACOPY
        {
            Value addr = contract->stack.get(0);
            addr_t offset = contract->stack.get(1).as_uint(*engine.vars);
            unsigned int size = contract->stack.get(2).as_uint(*engine.vars);
            contract->stack.pop(3);
            if (not contract->result_from_last_call.has_value())
            {
                // Write zeroes
                std::vector<Value> zeroes (size, Value(8,0));
                contract->memory.write(addr, zeroes);
            }
            else
            {
                for (const auto& val : contract->result_from_last_call->return_data_load_bytes(offset, size))
                {
                    contract->memory.write(addr, val);
                    addr = addr + val.size()/8;
                }
            }
            break;
        }
        case 0x42: // TIMESTAMP
        {
            contract->stack.push(
                env::EVM::get_ethereum(engine)->current_block_timestamp.current_value()
            );
            break;
        }
        case 0x43: // NUMBER
        {
            contract->stack.push(
                env::EVM::get_ethereum(engine)->current_block_number.current_value()
            );
            break;
        }
        case 0x47: // SELFBALANCE
        {
            contract->stack.push(contract->balance);
            break;
        }
        case 0x5a: // GAS
        {
            _check_transaction_exists(contract);
            pinst.res =contract->transaction->gas_limit - contract->consumed_gas;
            break;
        }
        default:
            throw callother_exception(
                Fmt() << "ENV_INFO: instruction not implemented for 0x"
                    << std::hex << evm_inst >> Fmt::to_str
            );
    }
}

void EVM_KECCAK_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    auto eth = env::EVM::get_ethereum(engine);
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);

    Value addr = pinst.in1.value();
    Value len = pinst.in2.value();
    uint8_t* raw_bytes = nullptr;

    if (not len.is_concrete(*engine.vars))
        throw callother_exception("KECCAK: not supported with symbolic length");

    // Handle special case of keccak("")
    if (len.as_uint() == 0){
        pinst.res = Value(256, "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470", 16);
        return;
    }

    contract->memory.expand_if_needed(pinst.in1.value(), pinst.in2.value().as_uint());
    ir::Param fake_param = ir::Param(
        inst.in[1].type,
        inst.in[1].tmp(),
        len.as_uint(*engine.vars)*8-1,
        0
    ); // Ugly hack to craft fake param to read correct number of bytes from memory

    if (not engine.resolve_addr_param(
        fake_param,
        pinst.in1,
        contract->memory.mem())
    )
        throw callother_exception("KECCAK: fatal error reading memory");

    Value to_hash = pinst.in1.value(); // Now contains the read value from memory

    if (not addr.is_symbolic(*engine.vars))
    {
        addr_t a = addr.as_uint(*engine.vars);
        raw_bytes = contract->memory.mem().raw_mem_at(a);
    }

    pinst.res = eth->keccak_helper.apply(*engine.vars, to_hash, raw_bytes);
}

void _set_return_data(MaatEngine& engine, const Value& addr, const Value& len, env::EVM::TransactionResult::Type type)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);

    if (len.is_symbolic(*engine.vars))
        throw callother_exception("Setting transaction return data: not supported with symbolic length");
    else if (len.is_concolic(*engine.vars))
        engine.log.warning("Setting transaction return data: concretizing concolic length");

    if (addr.is_symbolic(*engine.vars))
        throw callother_exception("Setting transaction return data: not supported with symbolic address");
    else if (addr.is_concolic(*engine.vars))
        engine.log.warning("Setting transaction return data: concretizing concolic address");

    std::vector<Value> return_data;
    _check_transaction_exists(contract);
    ucst_t concrete_len = len.as_number(*engine.vars).get_ucst();
    if (concrete_len != 0)
    {
        return_data = contract->memory.mem()._read_optimised_buffer(
            addr.as_number(*engine.vars).get_ucst(),
            concrete_len
        );
    }
    contract->transaction->result = env::EVM::TransactionResult(type, return_data);
}

void EVM_RETURN_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    Value addr = pinst.in1.value();
    Value len = pinst.in2.value();
    auto type = env::EVM::TransactionResult::Type::RETURN;
    _set_return_data(engine, addr, len, type);
    engine.terminate_process(Value(32, (int)type));
}

void EVM_REVERT_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    Value addr = pinst.in1.value();
    Value len = pinst.in2.value();
    auto type = env::EVM::TransactionResult::Type::REVERT;
    _set_return_data(engine, addr, len, type);
    engine.terminate_process(Value(32, (int)type));
}

void EVM_INVALID_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // engine.log.warning("Executing the 'INVALID' EVM instruction");
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_transaction_exists(contract);
    auto type = env::EVM::TransactionResult::Type::INVALID;
    engine.terminate_process(Value(32, (int)type));
    contract->transaction->result = env::EVM::TransactionResult(type,{});
}

// For CALL and CALLCODE
void _evm_generic_call(
    MaatEngine& engine,
    const ir::Inst& inst,
    ir::ProcessedInst& pinst,
    bool is_callcode
){
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_transaction_exists(contract);

    // Get parameters on stack
    Value gas = contract->stack.get(0);
    Value addr = extract(contract->stack.get(1), 159, 0);
    Number concrete_addr;
    // TODO: check that we are attempting to send more than what we have?
    Value value = contract->stack.get(2);
    Value argsOff = contract->stack.get(3);
    Value argsLen = contract->stack.get(4);
    Value retOff = contract->stack.get(5);
    Value retLen = contract->stack.get(6);
    contract->stack.pop(7);

    // We don't support symbolic offsets to args data
    if (not argsOff.is_concrete(*engine.vars))
        throw callother_exception("CALL: argsOff parameter is symbolic. Not yet supported");
    if (not argsLen.is_concrete(*engine.vars))
        throw callother_exception("CALL: argsLen parameter is symbolic. Not yet supported");

    // We allow concolic address
    if (addr.is_symbolic(*engine.vars))
        throw callother_exception("CALL: 'addr' parameter is symbolic");
    else
        concrete_addr = addr.as_number(*engine.vars);

    // Read transaction data
    std::vector<Value> tx_data = contract->memory.mem()._read_optimised_buffer(
        argsOff.as_uint(*engine.vars),
        argsLen.as_uint(*engine.vars)
    );

    env::EVM::Transaction::Type tx_type = 
        is_callcode ?
        env::EVM::Transaction::Type::CALLCODE :
        env::EVM::Transaction::Type::CALL;

    contract->outgoing_transaction = env::EVM::Transaction(
        contract->transaction->origin,
        contract->address,
        concrete_addr,
        value,
        tx_data,
        contract->transaction->gas_price,
        gas, // gas limit is remaining gas
        tx_type,
        retOff,
        retLen
    );
    // Tell the engine to stop because execution must be transfered to
    // another contract
    engine._stop_after_inst(info::Stop::NONE);
}

void EVM_CALL_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    _evm_generic_call(engine, inst, pinst, false);
}

void EVM_CALLCODE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    _evm_generic_call(engine, inst, pinst, true);
}



void EVM_CREATE_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    bool is_create2 = (bool)pinst.in1.value().as_uint();
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_transaction_exists(contract);
    _check_static_flag("CREATE", engine);

    // Get parameters on stack
    Value value = contract->stack.get(0);
    Value offset = contract->stack.get(1);
    Value len = contract->stack.get(2);
    // TODO: for CREATE2, we leave the salt on the stack? Or maybe append it
    // in the tx_data?
    contract->stack.pop(3);

    // We don't support symbolic offsets to code data
    if (not offset.is_concrete(*engine.vars))
        throw callother_exception("CREATE: data 'offset' parameter is symbolic. Not supported");
    if (not len.is_concrete(*engine.vars))
        throw callother_exception("CREATE: data 'length' parameter is symbolic. Not supported");

    // Read transaction data
    std::vector<Value> tx_data = contract->memory.mem()._read_optimised_buffer(
        offset.as_uint(*engine.vars),
        len.as_uint(*engine.vars)
    );

    env::EVM::Transaction::Type tx_type = 
        is_create2 ?
        env::EVM::Transaction::Type::CREATE2 :
        env::EVM::Transaction::Type::CREATE;

    contract->outgoing_transaction = env::EVM::Transaction(
        contract->transaction->origin,
        contract->address,
        Number(160, 0), // no recipient for CREATE
        value,
        tx_data,
        Value(256, 0), // no gas
        Value(256, 0), // null gas limit
        tx_type
    );

    // Tell the engine to stop because we need to deploy the new contract
    engine._stop_after_inst(info::Stop::NONE);
}

void EVM_DELEGATECALL_handler(
    MaatEngine& engine,
    const ir::Inst& inst,
    ir::ProcessedInst& pinst
){
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_transaction_exists(contract);

    // Get parameters on stack
    Value gas = contract->stack.get(0);
    Value addr = extract(contract->stack.get(1), 159, 0);
    Value argsOff = contract->stack.get(2);
    Value argsLen = contract->stack.get(3);
    Value retOff = contract->stack.get(4);
    Value retLen = contract->stack.get(5);
    contract->stack.pop(6);

    // We don't support symbolic offsets to args data
    if (not argsOff.is_concrete(*engine.vars))
        throw callother_exception("DELEGATECALL: argsOff parameter is symbolic. Not yet supported");
    if (not argsLen.is_concrete(*engine.vars))
        throw callother_exception("DELEGATECALL: argsLen parameter is symbolic. Not yet supported");

    // Read transaction data
    std::vector<Value> tx_data = contract->memory.mem()._read_optimised_buffer(
        argsOff.as_uint(*engine.vars),
        argsLen.as_uint(*engine.vars)
    );

    contract->outgoing_transaction = env::EVM::Transaction(
        contract->transaction->origin,
        contract->transaction->sender, // same sender
        addr.as_number(),
        contract->transaction->value, // same value
        tx_data,
        contract->transaction->gas_price,
        gas,
        env::EVM::Transaction::Type::DELEGATECALL,
        retOff,
        retLen
    );
    // Tell the engine to stop because execution must be transfered to
    // another contract
    engine._stop_after_inst(info::Stop::NONE);
}

void EVM_STATICCALL_handler(
    MaatEngine& engine,
    const ir::Inst& inst,
    ir::ProcessedInst& pinst
){
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_transaction_exists(contract);

    // Get parameters on stack
    Value gas = contract->stack.get(0);
    Value addr = extract(contract->stack.get(1), 159, 0);
    Value argsOff = contract->stack.get(2);
    Value argsLen = contract->stack.get(3);
    Value retOff = contract->stack.get(4);
    Value retLen = contract->stack.get(5);
    contract->stack.pop(6);

    // We don't support symbolic offsets to args data
    if (not argsOff.is_concrete(*engine.vars))
        throw callother_exception("STATICCALL: argsOff parameter is symbolic. Not yet supported");
    if (not argsLen.is_concrete(*engine.vars))
        throw callother_exception("STATICCALL: argsLen parameter is symbolic. Not yet supported");

    // Read transaction data
    std::vector<Value> tx_data = contract->memory.mem()._read_optimised_buffer(
        argsOff.as_uint(*engine.vars),
        argsLen.as_uint(*engine.vars)
    );

    contract->outgoing_transaction = env::EVM::Transaction(
        contract->transaction->origin,
        contract->address,
        addr.as_number(),
        Value(256, 0), // null value
        tx_data,
        contract->transaction->gas_price,
        gas,
        env::EVM::Transaction::Type::STATICCALL,
        retOff,
        retLen
    );
    // Tell the engine to stop because execution must be transfered to
    // another contract
    engine._stop_after_inst(info::Stop::NONE);
}

void EVM_SELFDESTRUCT_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    throw callother_exception("SELFDESTRUCT: not implemented");
}

void EVM_LOG_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    env::EVM::contract_t contract = env::EVM::get_contract_for_engine(engine);
    _check_static_flag("LOG", engine);

    int lvl = pinst.in1.value().as_uint();
    Value data_start = contract->stack.get(0);
    Value data_len = contract->stack.get(1);
    contract->stack.pop(2+lvl);

    if (data_start.is_symbolic(*engine.vars))
    {
        engine.log.warning(
            Fmt() << "LOG" << std::dec << lvl 
            << ": data address is symbolic. Memory will not be expanded accordingly"
            >> Fmt::to_str
        );
    }
    else if (data_len.is_symbolic(*engine.vars))
    {
        engine.log.warning(
            Fmt() << "LOG" << std::dec << lvl
            << ": data length is symbolic. Memory will not be expanded accordingly"
            >> Fmt::to_str
        );
    }
    else
    {
        contract->memory.expand_if_needed(
            data_start,
            data_len.as_uint(*engine.vars)
        );
    }
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
    h.set_handler(Id::EVM_ENV_INFO, EVM_ENV_INFO_handler);
    h.set_handler(Id::EVM_KECCAK, EVM_KECCAK_handler);
    h.set_handler(Id::EVM_RETURN, EVM_RETURN_handler);
    h.set_handler(Id::EVM_INVALID, EVM_INVALID_handler);
    h.set_handler(Id::EVM_REVERT, EVM_REVERT_handler);
    h.set_handler(Id::EVM_EXP, EVM_EXP_handler);
    h.set_handler(Id::EVM_CALL, EVM_CALL_handler);
    h.set_handler(Id::EVM_CALLCODE, EVM_CALLCODE_handler);
    h.set_handler(Id::EVM_STATICCALL, EVM_STATICCALL_handler);
    h.set_handler(Id::EVM_DELEGATECALL, EVM_DELEGATECALL_handler);
    h.set_handler(Id::EVM_CREATE, EVM_CREATE_handler);
    h.set_handler(Id::EVM_SELFDESTRUCT, EVM_SELFDESTRUCT_handler);
    h.set_handler(Id::EVM_LOG, EVM_LOG_handler);

    h.set_handler(Id::RISCV_ECALL, RISCV_ECALL_handler);

    return h;
}

} // namespace callother
} // namespace maat
