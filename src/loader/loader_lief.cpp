#ifdef MAAT_LIEF_BACKEND

#include "maat/loader.hpp"
#include "maat/engine.hpp"
#include "maat/env/filesystem.hpp"
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
    const std::unordered_map<std::string, std::string>& virtual_fs,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    bool load_interp
)
{
    binary_path = binary;
    // Load binary
    switch (type)
    {
        case loader::Format::ELF32:
        case loader::Format::ELF64:
            load_elf(engine, binary, base, args, envp, virtual_fs, libdirs, ignore_libs, load_interp);
            break;
        default: 
            throw loader_exception("LoaderLIEF::load(): Unsupported executable format");
    }
    // Init environment
    // Set process info
    std::string vpath = get_path_in_virtual_fs(engine, virtual_fs, binary_name);
    engine->process->pid = 1234;
    engine->process->binary_path = vpath;
    env::fspath_t pwd = engine->env->fs.fspath_from_path(vpath);
    pwd.pop_back();
    engine->process->pwd = engine->env->fs.path_from_fspath(pwd);
    // Add binary to filesystem
    try {
        engine->env->add_running_process(*engine->process, binary);
    } catch (const env_exception &e) {
        engine->log.warning("Failed to add the binary in the virtual "
                            "filesystem due to the following error: ",
                            e.what());
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
    const Arch& arch, std::optional<reg_t>& pc, std::optional<reg_t>& sp, std::optional<reg_t>& bp, std::optional<reg_t>& gs, std::optional<reg_t>& fs
)
{
    pc = arch.pc();
    sp = arch.sp();
    switch (arch.type)
    {
        case Arch::Type::X86:
            bp = X86::EBP;
            gs = X86::GS;
            fs = X86::FS;
            break;
        case Arch::Type::X64:
            bp = X64::RBP;
            gs = X64::GS;
            fs = X64::FS;
            break;
        case Arch::Type::RISCV:
        case Arch::Type::ARM32:
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
    const std::string& name
){
    try
    {
        return engine->mem->allocate(prefered_base, size, 0x1000, flags, name);
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
        flags |= maat::mem_flag_r;
    }
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_W) ){
        flags |= maat::mem_flag_w;
    }
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_X) ){
        flags |= maat::mem_flag_x;
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
        args_total_size += arg.len()+1; // +1 for terminating null byte
        argc++;
    }

    mem_arg_addr = engine->cpu.ctx().get(engine->arch->sp()).as_uint() - args_total_size - 0x100;
    // Adjust SP so it points after the program args and env variables
    engine->cpu.ctx().set(engine->arch->sp(), mem_arg_addr);
    // Write args in memory
    for (int i = 0; i < cmdline_args.size(); i++)
    {
        const CmdlineArg& arg = cmdline_args[i];
        // Align address
        if( mem_arg_addr % 16 != 0 )
        {
            mem_arg_addr += 16 - (mem_arg_addr%16);
        }
        // Write arg in memory
        if (arg.is_concrete())
        {
            engine->mem->write_buffer(mem_arg_addr, (uint8_t*)(arg.string().c_str()), arg.len());
        }
        else
        {
            engine->mem->write_buffer(mem_arg_addr, arg.buffer()); 
        }
        engine->mem->write(mem_arg_addr+arg.len(), 0, 1); // Add terminating null byte
        // Record address
        argv_addresses.push_back(mem_arg_addr);
        // Increment address
        mem_arg_addr += arg.len()+1;
    }
}

} // namespace loader
} // namespace maat
#endif
