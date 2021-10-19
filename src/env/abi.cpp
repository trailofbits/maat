#include "env/library.hpp"
#include "engine.hpp"
#include "util.hpp"

namespace maat
{
namespace env
{
namespace abi
{

// ========== ABI generic class ============
ABI::ABI(Type t): _type(t) 
{}

Type ABI::type() const
{
    return _type;
}

void ABI::prepare_args(MaatEngine& engine, const std::vector<Expr>& args) const
{
    throw env_exception("ABI::prepare_args(): cannot be called from base class");
}

void ABI::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Expr>& args
) const
{
    throw env_exception("ABI::get_args(): cannot be called from base class");
}

Expr ABI::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    throw env_exception("ABI::get_arg(): cannot be called from base class");
}

void ABI::set_ret_value(MaatEngine& engine, const FunctionCallback::return_t& ret_val) const
{
    throw env_exception("ABI::prepare_ret_value(): cannot be called from base class");
}

void ABI::prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const
{
    throw env_exception("ABI::prepare_ret_address(): cannot be called from base class");
}

void ABI::ret(MaatEngine& engine) const
{
    throw env_exception("ABI::ret(): cannot be called from base class");
}

size_t ABI::real_arg_size(MaatEngine& engine, size_t arg_size)
{
    return (arg_size == 0)? engine.arch->octets() : arg_size;
}

// =========== ABI NONE ============
ABI_NONE::ABI_NONE(): ABI(Type::NONE) {}

const ABI& ABI_NONE::instance()
{
    static ABI_NONE abi;
    return abi;
}


// ========== ABI X86 CDECL ============
X86_CDECL::X86_CDECL(): ABI(Type::X86_CDECL)
{}

const ABI& X86_CDECL::instance()
{
    static X86_CDECL abi;
    return abi;
}

void X86_CDECL::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Expr>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Expr X86_CDECL::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    // Regs on the stack, pushed right to left
    arg_size = ABI::real_arg_size(engine, arg_size);
    Expr res = engine.mem->read(engine.cpu.ctx().get(X86::ESP)->as_uint() + 4 + 4*n, 4);
    return (res->size/8 == arg_size) ? res : extract(res, arg_size*8-1, 0);
}

void X86_CDECL::set_ret_value(
    MaatEngine& engine,
    const FunctionCallback::return_t& ret_val
) const
{
    // Return value in EAX
    std::visit(maat::util::overloaded{
        [](std::monostate arg){return;}, // no return value
        [&engine](auto arg){engine.cpu.ctx().set(X86::EAX, arg);}
    }, ret_val);
}

void X86_CDECL::prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const
{
    // Push the return address, simply
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP) - 4);
    engine.mem->write(engine.cpu.ctx().get(X86::ESP)->as_uint(), ret_addr, 4);
}

void X86_CDECL::ret(MaatEngine& engine) const
{
    // Pop EIP
    engine.cpu.ctx().set(X86::EIP, engine.mem->read((engine.cpu.ctx().get(X86::ESP)->as_uint()), 4));
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP) + 4);
}



// ========== ABI X86 STDCALL ============
X86_STDCALL::X86_STDCALL(): ABI(Type::X86_STDCALL)
{}

const ABI& X86_STDCALL::instance()
{
    static X86_STDCALL abi;
    return abi;
}

void X86_STDCALL::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Expr>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Expr X86_STDCALL::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    // Regs on the stack, pushed right to left
    arg_size = ABI::real_arg_size(engine, arg_size);
    Expr res = engine.mem->read(engine.cpu.ctx().get(X86::ESP)->as_uint() + 4 + 4*n, 4);
    return (res->size/8 == arg_size) ? res : extract(res, arg_size*8-1, 0);
}

void X86_STDCALL::set_ret_value(
    MaatEngine& engine,
    const FunctionCallback::return_t& ret_val
) const
{
    // Return value in EAX
    std::visit(maat::util::overloaded{
        [](std::monostate arg){return;}, // no return value
        [&engine](auto arg){engine.cpu.ctx().set(X86::EAX, arg);}
    }, ret_val);
}

void X86_STDCALL::prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const
{
    // Push the return address, simply
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP) - 4);
    engine.mem->write(engine.cpu.ctx().get(X86::ESP)->as_uint(), ret_addr, 4);
}

void X86_STDCALL::ret(MaatEngine& engine) const
{
    // Pop EIP
    engine.cpu.ctx().set(X86::EIP, engine.mem->read((engine.cpu.ctx().get(X86::ESP)->as_uint()), 4));
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP) + 4);
}

// ========== ABI X86 LINUX INT80 ============
X86_LINUX_INT80::X86_LINUX_INT80(): ABI(Type::X86_LINUX_INT80)
{}

const ABI& X86_LINUX_INT80::instance()
{
    static X86_LINUX_INT80 abi;
    return abi;
}

void X86_LINUX_INT80::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Expr>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Expr X86_LINUX_INT80::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    std::vector<reg_t> arg_regs{X86::EBX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBP};
    if (n > 6)
    {
        throw env_exception("X86 Linux INT80 ABI doesn't support more than 6 arguments");
    }
    arg_size = ABI::real_arg_size(engine, arg_size);
    Expr res = engine.cpu.ctx().get(arg_regs[n]);
    return (res->size/8 == arg_size) ? res : extract(res, arg_size*8-1, 0);
}

// ========== ABI X86 LINUX SYSENTER ============
X86_LINUX_SYSENTER::X86_LINUX_SYSENTER(): ABI(Type::X86_LINUX_SYSENTER)
{}

const ABI& X86_LINUX_SYSENTER::instance()
{
    static X86_LINUX_SYSENTER abi;
    return abi;
}

void X86_LINUX_SYSENTER::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Expr>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Expr X86_LINUX_SYSENTER::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    std::vector<reg_t> arg_regs{X86::EBX, X86::ECX, X86::EDX, X86::ESI, X86::EDI};
    if (n > 6)
    {
        throw env_exception("X86 Linux INT80 ABI doesn't support more than 6 arguments");
    }

    Expr res = nullptr;
    if (n < 6)
        res = engine.cpu.ctx().get(arg_regs[n]);
    else // n == 6
        res = engine.mem->read(engine.cpu.ctx().get(X86::EBP)->as_uint(), 4);

    arg_size = ABI::real_arg_size(engine, arg_size);
    return (res->size/8 == arg_size) ? res : extract(res, arg_size*8-1, 0);
}


} // namespace abi
} // namespace env
} // namespace maat
