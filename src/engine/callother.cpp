#include "maat/callother.hpp"
#include "maat/engine.hpp"
#include "maat/memory.hpp"
#include "maat/env/library.hpp"

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
        cst_t f_fpu = 1 << 0;
        cst_t f_tsc = 1 << 4;
        cst_t f_cx8 = 1 << 8;
        cst_t f_sysenter = 1 << 11;
        cst_t f_cmov = 1 << 15;
        cst_t f_mmx = 1 << 23;
        cst_t f_fxsr = 1 << 24;
        cst_t f_sse = 1 << 25;
        cst_t f_sse2 = 1 << 26;
        cst_t edx_feature_info = f_fpu | f_tsc | f_cx8 | f_sysenter | f_cmov | f_mmx | f_fxsr | f_sse | f_sse2;
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
    return h;
}

} // namespace callother
} // namespace maat
