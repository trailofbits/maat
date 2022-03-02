#include "maat/loader.hpp"
#include "maat/symbol.hpp"
#include "maat/engine.hpp"

namespace maat
{
namespace loader
{
    

CmdlineArg::CmdlineArg(const std::string& value):
    _value(value),
    _len(value.size())
{}


CmdlineArg::CmdlineArg(const std::vector<Value>& buffer):
    _buffer(buffer),
    _len(buffer.size())
{
    // Ensure values are 1-byte values
    for (const auto& val : _buffer)
        if (val.size() != 8)
            throw loader_exception(
                "CmdlineArg::CmdlineArg(): abstract buffer must contain only 8-bit values"
            );
}

const std::string& CmdlineArg::string() const
{
    return _value;
}

const std::vector<Value>& CmdlineArg::buffer() const
{
    return _buffer;
}

size_t CmdlineArg::len() const
{
    return _len;
}

bool CmdlineArg::is_concrete() const
{
    return _buffer.empty();
}

bool CmdlineArg::is_abstract() const
{
    return not is_concrete();
}


void Loader::load(
    MaatEngine* engine,
    const std::string& binary,
    loader::Format type,
    addr_t base,
    const std::vector<CmdlineArg>& args,
    const environ_t& envp,
    const std::unordered_map<std::string, std::string>& virtual_fs,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    bool interpreter
)
{
    throw runtime_exception("Loader::load(): shouldn't be called from base class!");
}

void Loader::load_emulated_libs(MaatEngine* engine)
{
    int lib_idx = 0;
    addr_t offset = 0;
    for (const auto& lib : engine->env->libraries())
    {
        int func_idx = 0;
        // Create segment for emulated lib
        int lib_size = lib.functions().size() + lib.total_data_size();
        // Align on 0x100
        addr_t emu = engine->mem->allocate_segment(
            0xaaaa0000, lib_size, 0x1000,
            maat::mem_flag_rw,
            "Emulated " + lib.name(),
            true // is_special_segment
        );
        // Add functions
        for (const auto& func : lib.functions())
        {
            std::string symbol_name = func.name();
            if (func.type() == env::Function::Type::CALLBACK)
            {
                engine->symbols->add_symbol(Symbol(
                    Symbol::FunctionStatus::EMULATED_CALLBACK,
                    emu + (offset++), // address
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
        // Add exported data
        for (const auto& data : lib.data())
        {
            std::string symbol_name = data.name();
            engine->symbols->add_symbol(Symbol(
                Symbol::DataStatus::EMULATED,
                emu + offset, // address
                symbol_name,
                data.data().size()
            ));
            engine->mem->write_buffer(emu+offset, (uint8_t*)data.data().data(), data.data().size());
            offset += data.data().size();
        }
        lib_idx++;
    }
}

std::unique_ptr<Loader> new_loader()
{
#if defined(MAAT_LIEF_BACKEND)
    return std::make_unique<LoaderLIEF>();
#else
    throw loader_exception("new_loader(): No loader backend available!");
#endif
}

} // namespace loader
} // namespace maat
