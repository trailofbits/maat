#ifdef LIEF_BACKEND

#include "loader.hpp"
#include "engine.hpp"
#include "env/filesystem.hpp"
#include <sstream>
#include <fstream>

namespace maat
{
namespace loader
{

void LoaderLIEF::load(
    MaatEngine* engine,
    const std::string& binary,
    loader::Format type,
    addr_t base,
    const std::vector<CmdlineArg>& args,
    const environ_t& envp,
    const std::string& virtual_path,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs
)
{
    // Load binary
    switch (type)
    {
        case loader::Format::ELF32:
        case loader::Format::ELF64:
            load_elf(engine, binary, base, args, envp, virtual_path, libdirs, ignore_libs);
            break;
        default: 
            throw loader_exception("LoaderLIEF::load(): Unsupported executable format");
    }
    // Init environment
    // Set process info
    env::fspath_t vfspath;
    if (virtual_path.empty())
        vfspath = {binary_name}; // Put it at root
    else
    {
        vfspath = engine->env->fs.fspath_from_path(virtual_path);
        vfspath.push_back(binary_name);
    }
    std::string vpath = engine->env->fs.path_from_fspath(vfspath);
    engine->process->pid = 1234;
    engine->process->binary_path = vpath;
    env::fspath_t pwd = engine->env->fs.fspath_from_path(vpath);
    pwd.pop_back();
    engine->process->pwd = engine->env->fs.path_from_fspath(pwd);
    // Add binary to filesystem
    // Read the actual file on disk
    std::ifstream file(binary, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> content(size);
    if (not (file.read(content.data(), size)))
    {
        engine->log.warning("LoaderLIEF::load(): couldn't read file: ", binary);
    }
    else
    {
        try
        {
            engine->env->add_running_process(*engine->process, (uint8_t*)content.data(), content.size());
        }
        catch(const env_exception& e)
        {
            engine->log.warning(
                "Failed to add the binary in the virtual filesystem due to the following error: ",
                e.what()
            );
        }
    }
}

void LoaderLIEF::parse_binary(const std::string& binary, Format type)
{
    try
    {
        // Check if format is supported
        if (type == Format::ELF32 or type == Format::ELF64)
        {
            _elf = LIEF::ELF::Parser::parse(binary);
            if( _elf == nullptr )
            {
                throw loader_exception(
                    Fmt() << "Couldn't parse file '" << binary
                    << "'" >> Fmt::to_str
                );
            }
            binary_name = _elf->name();
        }
        else
        {
            throw loader_exception("LoaderLIEF::parse_binary(): Unsupported executable format!");
        }
    }
    catch(std::exception& e)
    {
        throw loader_exception(
            Fmt() << "LoaderLIEF::parse_binary(): " << e.what()
            >> Fmt::to_str
        );
    }
}

void LoaderLIEF::get_arch_special_registers(
    const Arch& arch, reg_t& pc, reg_t& sp, reg_t& bp, reg_t& gs, reg_t& fs
)
{
    pc = arch.pc();
    sp = arch.sp();
    switch (arch.type)
    {
        case Arch::Type::X86:
            bp = X86::EBP;
            gs = X86::GS;
            fs = X86::GS;
            break;
        case Arch::Type::X64:
            bp = X64::RBP;
            gs = X64::GS;
            fs = X64::FS;
            break;
        default:
            throw loader_exception(
                Fmt() << "LoaderLIEF::get_arch_special_registers(): Unsupported architecture!"
                >> Fmt::to_str
            );
    }
}

addr_t LoaderLIEF::alloc_segment(
    MaatEngine*engine,
    addr_t prefered_base,
    addr_t size,
    mem_flag_t flags,
    const std::string& name,
    bool is_special_segment
)
{
    try
    {
        return engine->mem->allocate_segment(prefered_base, size, 0x1000, flags, name, is_special_segment);
    }
    catch(mem_exception& e)
    {
        throw loader_exception(e.what());
    }
}

addr_t LoaderLIEF::find_free_space(MaatEngine*engine, addr_t start, addr_t size)
{
    addr_t base = start;
    bool ok = false;
    addr_t max_addr = engine->arch->bits() == 32 ? 0xffffffff : 0xffffffffffffffff;
    addr_t step = 0x1000;

    if (start == 0)
    {
        throw runtime_exception("LoaderLIEF::find_free_space() doesn't work with start == 0");
    }

    do{
        if (base <= max_addr-size and engine->mem->is_free(base, base+size-1))
        {
            ok = true;
            return base;
        }
        base += step;
    }while ((not ok) and base < max_addr - size);

    return 0;
}

mem_flag_t get_segment_flags(LIEF::ELF::Segment& segment)
{
    mem_flag_t flags = 0;
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_R) ){
        flags |= mem_flag_r;
    }
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_W) ){
        flags |= mem_flag_w;
    }
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_X) ){
        flags |= mem_flag_x;
    }
    return flags;
}

void LoaderLIEF::load_cmdline_args(
    MaatEngine*engine,
    const std::vector<CmdlineArg>& cmdline_args,
    int& argc, 
    std::vector<addr_t>& argv_addresses)
{
    addr_t mem_arg_addr;
    int args_total_size = 0;
    std::string arg_name, var_name, var;
    std::stringstream ss;

    argc = 0;
    for (auto arg : cmdline_args)
    {
        args_total_size += arg.len();
        argc++;
    }

    mem_arg_addr = engine->cpu.ctx().get(engine->arch->sp())->as_uint() - args_total_size - 0x100;
    // Adjust SP so it points after the program args and env variables
    engine->cpu.ctx().set(engine->arch->sp(), mem_arg_addr);
    // Write args in memory
    for (int i = 0; i < cmdline_args.size(); i++)
    {
        const CmdlineArg& arg = cmdline_args[i];
        // Get arg name
        ss.str("");
        ss << "argv" << std::dec << i << "_";
        arg_name = arg.name().empty() ? ss.str() : arg.name();
        // Align address
        if( mem_arg_addr % 16 != 0 )
        {
            mem_arg_addr += 16 - (mem_arg_addr%16);
        }
        // Write arg in memory
        for (int j = 0; j < arg.len()-1; j++)
        {
            if (not arg.is_concrete())
            {
                ss.str("");
                ss << std::dec << arg_name << j;
                var_name = ss.str();
                engine->mem->write(mem_arg_addr+j, exprvar(8, var_name));
                
            }
            else
            {
                engine->mem->write(mem_arg_addr+j, (uint8_t)(arg.value()[j]), 1);
            }

            if (arg.is_concolic())
            {
                engine->vars->set(var_name, (uint8_t)(arg.value()[j]));
            }
        }
        engine->mem->write(mem_arg_addr+arg.len()-1, exprcst(8, 0));

        // Record address
        argv_addresses.push_back(mem_arg_addr);
        // Increment address
        mem_arg_addr += arg.len();
    }
}

} // namespace loader
} // namespace maat
#endif
