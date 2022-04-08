#include "maat/env/library.hpp"
#include "maat/engine.hpp"
#include "maat/util.hpp"

namespace maat
{
namespace env
{
namespace abi
{

// Apply extract on a value to reduce its size if needed
// 'size' is passed in bytes, it must be inferior or equal to the size of 'val'
Value _adjust_value_to_size(Value& val, size_t size, MaatEngine& engine)
{
    if (val.is_concrete(*engine.vars))
        return Value(size*8, maat::cst_extract(val.as_uint(*engine.vars), size*8-1, 0));
    else
        return (val.size()/8 == size) ? val : extract(val, size*8-1, 0);
}

// ========== ABI generic class ============
ABI::ABI(Type t): _type(t) 
{}

Type ABI::type() const
{
    return _type;
}

void ABI::prepare_args(MaatEngine& engine, const std::vector<Value>& args) const
{
    throw env_exception("ABI::prepare_args(): cannot be called from base class");
}

void ABI::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    throw env_exception("ABI::get_args(): cannot be called from base class");
}

Value ABI::get_arg(MaatEngine& engine, int n, size_t arg_size) const
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

ABI& ABI_NONE::instance()
{
    static ABI_NONE abi;
    return abi;
}

// ========== ABI X86 CDECL ============
X86_CDECL::X86_CDECL(): ABI(Type::X86_CDECL)
{}

ABI& X86_CDECL::instance()
{
    static X86_CDECL abi;
    return abi;
}

void X86_CDECL::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Value X86_CDECL::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    // Regs on the stack, pushed right to left
    arg_size = ABI::real_arg_size(engine, arg_size);
    Value res = engine.mem->read(engine.cpu.ctx().get(X86::ESP).as_uint() + 4 + 4*n, 4);
    return _adjust_value_to_size(res, arg_size, engine);
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
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_uint() - 4);
    engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint(), ret_addr, 4);
}

void X86_CDECL::ret(MaatEngine& engine) const
{
    // Pop EIP
    engine.cpu.ctx().set(X86::EIP, engine.mem->read((engine.cpu.ctx().get(X86::ESP).as_uint()), 4));
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_uint() + 4);
}


// ========== ABI X86 STDCALL ============
X86_STDCALL::X86_STDCALL(): ABI(Type::X86_STDCALL)
{}

ABI& X86_STDCALL::instance()
{
    static X86_STDCALL abi;
    return abi;
}

void X86_STDCALL::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Value X86_STDCALL::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    // Regs on the stack, pushed right to left
    arg_size = ABI::real_arg_size(engine, arg_size);
    Value res = engine.mem->read(engine.cpu.ctx().get(X86::ESP).as_uint() + 4 + 4*n, 4);
    return _adjust_value_to_size(res, arg_size, engine);
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
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_uint() - 4);
    engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint(), ret_addr, 4);
}

void X86_STDCALL::ret(MaatEngine& engine) const
{
    // Pop EIP
    engine.cpu.ctx().set(X86::EIP, engine.mem->read((engine.cpu.ctx().get(X86::ESP).as_uint()), 4));
    engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_uint() + 4);
}


// ========== ABI X86 LINUX SYSENTER ============
X86_LINUX_SYSENTER::X86_LINUX_SYSENTER(): ABI(Type::X86_LINUX_SYSENTER)
{}

ABI& X86_LINUX_SYSENTER::instance()
{
    static X86_LINUX_SYSENTER abi;
    return abi;
}

void X86_LINUX_SYSENTER::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Value X86_LINUX_SYSENTER::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    std::vector<reg_t> arg_regs{X86::EBX, X86::ECX, X86::EDX, X86::ESI, X86::EDI};
    if (n > 6)
    {
        throw env_exception("X86 Linux INT80 ABI doesn't support more than 6 arguments");
    }

    Value res;
    if (n < 6)
        res = engine.cpu.ctx().get(arg_regs[n]);
    else // n == 6
        res = engine.mem->read(engine.cpu.ctx().get(X86::EBP).as_uint(), 4);

    arg_size = ABI::real_arg_size(engine, arg_size);
    return _adjust_value_to_size(res, arg_size, engine);
}

// ========== ABI X64 SYSTEM V ============
X64_SYSTEM_V::X64_SYSTEM_V(): ABI(Type::X64_SYSTEM_V)
{}

ABI& X64_SYSTEM_V::instance()
{
    static X64_SYSTEM_V abi;
    return abi;
}

void X64_SYSTEM_V::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Value X64_SYSTEM_V::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    std::vector<reg_t> arg_regs{X64::RDI, X64::RSI, X64::RDX, X64::RCX, X64::R8, X64::R9};
    Value res;
    arg_size = ABI::real_arg_size(engine, arg_size);
    if (n < 6)
    {
        res = engine.cpu.ctx().get(arg_regs[n]);
    }
    else
    {
        addr_t stack = engine.cpu.ctx().get(X64::RSP).as_uint() + 8;
        res = engine.mem->read(stack+(8*(n-arg_regs.size())), arg_size);
    }
    // TODO(boyan): this assumes little endian if we read arguments
    // from the stack
    return _adjust_value_to_size(res, arg_size, engine);
}

void X64_SYSTEM_V::prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const
{
    // Push the return address, simply
    engine.cpu.ctx().set(X64::RSP, engine.cpu.ctx().get(X64::RSP).as_uint() - 8);
    engine.mem->write(engine.cpu.ctx().get(X64::RSP).as_uint(), ret_addr, 8);
}

void X64_SYSTEM_V::set_ret_value(
    MaatEngine& engine,
    const FunctionCallback::return_t& ret_val
) const
{
    // Return value in EAX
    std::visit(maat::util::overloaded{
        [](std::monostate arg){return;}, // no return value
        [&engine](auto arg){engine.cpu.ctx().set(X64::RAX, arg);}
    }, ret_val);
}

void X64_SYSTEM_V::ret(MaatEngine& engine) const
{
    // Caller clean-up, we just simulate a 'ret' instruction
    engine.cpu.ctx().set(X64::RIP, engine.mem->read(engine.cpu.ctx().get(X64::RSP).as_uint(), 8));
    engine.cpu.ctx().set(X64::RSP, engine.cpu.ctx().get(X64::RSP).as_uint() + 8);
}

// ========== ABI X64 SYSCALL LINUX ============
X64_LINUX_SYSCALL::X64_LINUX_SYSCALL(): ABI(Type::X64_LINUX_SYSCALL)
{}

ABI& X64_LINUX_SYSCALL::instance()
{
    static X64_LINUX_SYSCALL abi;
    return abi;
}

void X64_LINUX_SYSCALL::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Value X64_LINUX_SYSCALL::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    std::vector<reg_t> arg_regs{X64::RDI, X64::RSI, X64::RDX, X64::R10, X64::R8, X64::R9};
    Value res;
    arg_size = ABI::real_arg_size(engine, arg_size);
    if (n >= arg_regs.size())
    {
        throw env_exception("get_arg(): Linux X64 syscall ABI supports only up to 6 arguments");
    }
    else
    {
        res = engine.cpu.ctx().get(arg_regs[n]).as_expr();
    }
    return _adjust_value_to_size(res, arg_size, engine);
}

void X64_LINUX_SYSCALL::set_ret_value(
    MaatEngine& engine,
    const FunctionCallback::return_t& ret_val
) const
{
    // Return value in RAX
    std::visit(maat::util::overloaded{
        [](std::monostate arg){return;}, // no return value
        [&engine](auto arg){engine.cpu.ctx().set(X64::RAX, arg);}
    }, ret_val);
}

void X64_LINUX_SYSCALL::ret(MaatEngine& engine) const
{
    // Do nothing
}


// ========== ABI X64 SYSCALL LINUX ============
X86_LINUX_INT80::X86_LINUX_INT80(): ABI(Type::X86_LINUX_INT80)
{}

ABI& X86_LINUX_INT80::instance()
{
    static X86_LINUX_INT80 abi;
    return abi;
}

void X86_LINUX_INT80::get_args(
    MaatEngine& engine,
    const args_spec_t& args_spec,
    std::vector<Value>& args
) const
{
    int i = 0;
    for (auto arg : args_spec)
        args.push_back(get_arg(engine, i++, arg));
}

Value X86_LINUX_INT80::get_arg(MaatEngine& engine, int n, size_t arg_size) const
{
    std::vector<reg_t> arg_regs{X86::EBX, X86::ECX, X86::EDX, X86::ESI, X86::EDI, X86::EBP};
    Value res;
    arg_size = ABI::real_arg_size(engine, arg_size);
    if (n >= arg_regs.size())
    {
        throw env_exception("get_arg(): Linux X86 int 0x80 ABI supports only up to 6 arguments");
    }
    else
    {
        res = engine.cpu.ctx().get(arg_regs[n]);
    }
    return _adjust_value_to_size(res, arg_size, engine);
}

void X86_LINUX_INT80::set_ret_value(
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

void X86_LINUX_INT80::ret(MaatEngine& engine) const
{
    // Do nothing
}

} // namespace abi
} // namespace env
} // namespace maat
