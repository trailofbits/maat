#include "callother.hpp"
#include "engine.hpp"
#include "memory.hpp"

namespace maat{
namespace callother{

Id mnemonic_to_id(const std::string& mnemonic, const std::string& arch)
{
    if (mnemonic == "RDTSC") return Id::X86_RDTSC;
    if (mnemonic == "SYSCALL")
        if (arch == "X64") return Id::X64_SYSCALL;
    if (mnemonic == "CPUID") return Id::X86_CPUID;
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
void X86_RDTSC_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    // We put the timestamp counter in the output parameter
    Expr counter = engine.cpu.ctx().get(engine.arch->tsc());
    if (inst.out.size() != counter->size)
    {
        throw callother_exception("RDTSC: inconsistent sizes for output parameter and TSC");
    }
    pinst.res = counter;
}

void X86_CPUID_handler(MaatEngine& engine, const ir::Inst& inst, ir::ProcessedInst& pinst)
{
    /* TODO pcode expects to return a pointer to the CPUID struct (see terminak)
    so write in the kernel stack! */
    /* Apparently in pcode the instruction puts a pointer in the res parameter.
     * The area pointed contains: eax:ebx:edx:ecx in this order, 4 bytes each */
    ucst_t eax, ebx, ecx, edx;
    reg_t ax = (engine.arch->type == Arch::Type::X86)? X86::EAX : X64::RAX;
    ucst_t leaf = engine.cpu.ctx().get(ax)->as_uint(*engine.vars);

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
    Expr num = engine.cpu.ctx().get(X64::RAX);
    if (num->is_symbolic(*engine.vars))
    {
        throw callother_exception("SYSCALL: syscall number is symbolic!");
    }
    // Get function to emulate syscall
    try
    {
        const env::Function& func = engine.env->get_syscall_func_by_num(
            num->as_uint(*engine.vars)
        );
        // Execute function callback
        switch (func.callback().execute(engine, engine.env->syscall_abi))
        {
            case env::Action::CONTINUE:
                break;
            case env::Action::ERROR:
                throw callother_exception(
                    "SYSCALL: Emulation callback signaled an error"
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

/// Return the default handler map for CALLOTHER occurences
HandlerMap default_handler_map()
{
    HandlerMap h;
    h.set_handler(Id::X86_RDTSC, X86_RDTSC_handler);
    h.set_handler(Id::X86_CPUID, X86_CPUID_handler);
    h.set_handler(Id::X64_SYSCALL, X64_SYSCALL_handler);
    return h;
}

} // namespace callother
} // namespace maat