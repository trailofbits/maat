#include "callother.hpp"
#include "engine.hpp"

namespace maat{
namespace callother{

Id mnemonic_to_id(const std::string& mnemonic, const std::string& arch)
{
    if (mnemonic == "RDTSC") return Id::X86_RDTSC;
    if (mnemonic == "SYSCALL")
        if (arch == "X64") return Id::X64_SYSCALL;
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
    h.set_handler(Id::X64_SYSCALL, X64_SYSCALL_handler);
    return h;
}

} // namespace callother
} // namespace maat