#include "maat/symbol.hpp"
#include "maat/exception.hpp"

namespace maat
{

using serial::bits;
using serial::container_bits;

Symbol::Symbol():
func_status(Symbol::FunctionStatus::NONE),
data_status(Symbol::DataStatus::NONE),
addr(0), name(""), args(std::nullopt),
env_lib_num(-1), env_func_num(-1),
size(-1)
{}

// Create a function symbol
Symbol::Symbol(
    FunctionStatus status,
    addr_t _addr,
    const std::string& _name,
    std::optional<args_spec_t> _args,
    int lib_num,
    int func_num,
    size_t _size
):
func_status(status),
data_status(Symbol::DataStatus::NONE),
addr(_addr), name(_name), args(_args),
env_lib_num(lib_num),
env_func_num(func_num),
size(_size)
{}

// Create a data symbol
Symbol::Symbol(
    DataStatus status,
    addr_t _addr,
    const std::string& _name,
    size_t _size
):
func_status(Symbol::FunctionStatus::NONE),
data_status(status),
addr(_addr), name(_name), args(std::nullopt),
env_lib_num(-1),
env_func_num(-1),
size(_size)
{}

serial::uid_t Symbol::class_uid() const
{
    return serial::ClassId::SYMBOL;
}

void Symbol::dump(serial::Serializer& s) const
{
    s << bits(func_status) << bits(data_status) << bits(addr) << name
      << bits(env_lib_num) << bits(env_func_num) << bits(size);
    // optional args
    s << bits(args.has_value());
    if (args.has_value())
        s << container_bits(args.value());
}

void Symbol::load(serial::Deserializer& d)
{
    d >> bits(func_status) >> bits(data_status) >> bits(addr) >> name
      >> bits(env_lib_num) >> bits(env_func_num) >> bits(size);
    // optional args
    bool has_args;
    d >> bits(has_args);
    if (has_args)
        d >> container_bits(args.emplace());
    else
        args = std::nullopt;
}

std::ostream& operator<<(std::ostream& os, const Symbol& s)
{
    return os << s.name << std::hex << ": @0x" << s.addr;
}

void SymbolManager::add_symbol(Symbol symbol)
{
    symbols_by_addr[symbol.addr] = symbol;
    symbols_by_name[symbol.name] = symbol;
}

bool SymbolManager::has_symbol(addr_t addr)
{
    return symbols_by_addr.find(addr) != symbols_by_addr.end();
}

bool SymbolManager::is_callback_emulated_function(addr_t addr)
{
    const auto& sym = symbols_by_addr.find(addr);
    if (sym == symbols_by_addr.end())
        return false;
    else
        return sym->second.func_status == Symbol::FunctionStatus::EMULATED_CALLBACK;
}

bool SymbolManager::is_missing_function(addr_t addr)
{
    const auto& sym = symbols_by_addr.find(addr);
    if (sym == symbols_by_addr.end())
        return false;
    else
        return sym->second.func_status == Symbol::FunctionStatus::MISSING;
}

const std::string _empty_symbol_str;
const std::string& SymbolManager::name(addr_t addr)
{
    if (has_symbol(addr))
        return get_by_addr(addr).name;
    else
        return _empty_symbol_str;
}

addr_t SymbolManager::addr(const std::string& name)
{
    const auto& sym = symbols_by_name.find(name);
    if (sym == symbols_by_name.end())
        throw symbol_exception(
            Fmt() << "SymbolManager::addr(): symbol '" << name
            << "' doesn't exist"
            >> Fmt::to_str
        );
    else
        return sym->second.addr;
}

const Symbol& SymbolManager::get_by_name(const std::string& name)
{
    const auto& sym = symbols_by_name.find(name);
    if (sym == symbols_by_name.end())
        throw symbol_exception(
            Fmt() << "SymbolManager::get_by_name(): symbol '" << name
            << "' doesn't exist"
            >> Fmt::to_str
        );
    else
        return sym->second;
}

const Symbol& SymbolManager::get_by_addr(addr_t addr)
{
    const auto& sym = symbols_by_addr.find(addr);
    if (sym == symbols_by_addr.end())
        throw symbol_exception(
            Fmt() << "SymbolManager::get_by_addr(): no symbol at address 0x" 
            << std::hex << addr >> Fmt::to_str
        );
    else
        return sym->second;
}

void SymbolManager::add_function(
    addr_t addr,
    const std::string& name,
    std::optional<Symbol::args_spec_t> args
)
{
    add_symbol(Symbol(
        Symbol::FunctionStatus::USER_DEFINED,
        addr,
        name,
        args
    ));
}

serial::uid_t SymbolManager::class_uid() const
{
    return serial::ClassId::SYMBOL_MANAGER;
}

void SymbolManager::dump(serial::Serializer& s) const
{
    s << bits(symbols_by_addr.size());
    for (const auto& [addr,sym] : symbols_by_addr)
        s << bits(addr) << sym;

    s << bits(symbols_by_name.size());
    for (const auto& [name,sym] : symbols_by_name)
        s << name << sym;
}

void SymbolManager::load(serial::Deserializer& d)
{
    size_t tmp_size;
    Symbol sym;
    d >> bits(tmp_size);
    for (int i = 0; i < tmp_size; i++)
    {
        addr_t addr;
        d >> bits(addr) >> sym;
        symbols_by_addr[addr] = sym;
    }

    d >> bits(tmp_size);
    for (int i = 0; i < tmp_size; i++)
    {
        std::string name;
        d >> name >> sym;
        symbols_by_name[name] = sym;
    }
}

std::ostream& operator<<(std::ostream& os, const SymbolManager& s)
{
    os << "Symbols:\n";
    for (const auto& it : s.symbols_by_name)
    {
        os << "\t" << it.second << "\n";
    }
    return os;
}

} // namespace maat
