#include "loader.hpp"
#include "symbol.hpp"
#include "engine.hpp"

namespace maat
{
namespace loader
{
    
/// Create a concrete command-line argument
CmdlineArg::CmdlineArg(const std::string& value):
    _value(value),
    _len(value.size() + 1),
    _is_concolic(false),
    _is_symbolic(false)
{}

/** \brief Create a concolic command-line argument. *value* is the concrete
* value of the argument, *name* is it's symbolic  name */
CmdlineArg::CmdlineArg(const std::string& value, const std::string& name):
    _value(value),
    _name(name),
    _len(value.size() + 1),
    _is_concolic(true),
    _is_symbolic(false)
{}

/** \brief Create a symbolic command-line argument. *len* is the number
* of bytes in the argument string (without potential terminating null bytes).
* *name* is the argument's symbolic name */
CmdlineArg::CmdlineArg(size_t len, const std::string& name):
    _name(name),
    _len(len+1),
    _is_concolic(true),
    _is_symbolic(true)
{}

const std::string& CmdlineArg::value() const
{
    return _value;
}

const std::string& CmdlineArg::name() const
{
    return _name;
}

size_t CmdlineArg::len() const
{
    return _len;
}

bool CmdlineArg::is_symbolic() const
{
    return _is_symbolic;
}

bool CmdlineArg::is_concrete() const
{
    return not (_is_symbolic or _is_concolic); 
}

bool CmdlineArg::is_concolic() const
{
    return _is_concolic;
}


void Loader::load(
    MaatEngine* engine,
    const std::string& binary,
    loader::Format type,
    addr_t base,
    const std::vector<CmdlineArg>& args,
    const environ_t& envp,
    const std::string& virtual_path,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    bool interpreter
)
{
    throw runtime_exception("Loader::load(): shouldn't be called from base class!");
}

void Loader::load_emulated_libs(MaatEngine* engine)
{
    Symbol symbol;
    // Create segment for emulated libs
    addr_t emu = engine->mem->allocate_segment(
        0xaaaa0000, 0x1000, 0x1000,
        maat::mem_flag_r,
        "Emulated functions",
        true // is_special_segment
    );
    addr_t idx = 0;
    int lib_idx = 0;
    for (const auto& lib : engine->env->libraries())
    {
        int func_idx = 0;
        for (const auto& func : lib.functions())
        {
            std::string symbol_name = func.name();
            if (func.type() == env::Function::Type::CALLBACK)
            {
                engine->symbols->add_symbol(Symbol(
                    Symbol::FunctionStatus::EMULATED_CALLBACK,
                    emu + (idx++), // address
                    symbol_name,
                    func.callback().args_spec,
                    lib_idx,
                    func_idx,
                    0
                ));
            }
            // FOR IR block we need the correct address in the block so have a block
            // generator method instead of just passing the shared_ptr around ?
            else
            {
                throw loader_exception(
                    Fmt() << "Loader::load_emulated_functions(): got unsupported function type for: "
                    << symbol_name >> Fmt::to_str
                );
            }
            func_idx++;
        }
        lib_idx++;
    }
}

std::unique_ptr<Loader> new_loader()
{
#if defined(LIEF_BACKEND)
    return std::make_unique<LoaderLIEF>();
#else
    throw loader_exception("new_loader(): No loader backend available!");
#endif
}

} // namespace loader
} // namespace maat
