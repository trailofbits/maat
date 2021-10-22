#include "env/env.hpp"

namespace maat
{
namespace env
{

const abi::ABI& _get_default_abi(Arch::Type arch, OS os)
{
    if (arch == Arch::Type::X86)
    {
        if (os == OS::LINUX)
            return abi::X86_CDECL::instance();
    }
    else if (arch == Arch::Type::X64)
    {
        if (os == OS::LINUX)
            return abi::X64_SYSTEM_V::instance();
    }
    return abi::ABI_NONE::instance();
}

const abi::ABI& _get_syscall_abi(Arch::Type arch, OS os)
{
    return abi::ABI_NONE::instance();
}

EnvEmulator::EnvEmulator(Arch::Type arch, OS os):
default_abi(_get_default_abi(arch, os)),
syscall_abi(_get_syscall_abi(arch, os)),
fs(FileSystem(os))
{}

bool EnvEmulator::contains_library(const std::string& name) const
{
    const auto& it = std::find_if(
        _libraries.begin(),
        _libraries.end(),
        [&name](const Library& lib){return lib.name() == name;}
    );
    return it != _libraries.end();
}

const std::vector<Library>& EnvEmulator::libraries() const
{
    return _libraries;
}

const Library& EnvEmulator::get_library_by_name(const std::string& name) const
{
    for (auto& lib : _libraries)
        if (lib.name() == name)
            return lib;

    throw env_exception(
        Fmt() << "EnvEmulator::get_library_by_name(): library '" << name
        << "' doesn't exist in emulated environment" 
        >> Fmt::to_str
    );
}

const Library& EnvEmulator::get_library_by_num(int num) const
{
    if (num < 0 or num >= _libraries.size())
        throw env_exception(
            Fmt() << "EnvEmulator::get_library_by_num(): library '" << num
            << "' doesn't exist in emulated environment" 
            >> Fmt::to_str
        );
    return _libraries.at(num);
}

void EnvEmulator::add_running_process(const ProcessInfo& pinfo, uint8_t* binary_content, size_t binary_size)
{
    throw env_exception("add_running_process() not supported for generic EnvEmulator");
}


LinuxEmulator::LinuxEmulator(Arch::Type arch): EnvEmulator(arch, OS::LINUX)
{
    // Load emulated libraries
    switch (arch)
    {
        case Arch::Type::X86:
            _libraries.push_back(env::emulated::linux_x86_libc());
            break;
        case Arch::Type::X64:
            _libraries.push_back(env::emulated::linux_x64_libc());
            break;
        case Arch::Type::NONE:
        default:
            break;
    }
}

void LinuxEmulator::add_running_process(const ProcessInfo& pinfo, uint8_t* binary_content, size_t binary_size)
{
    addr_t offset = 0;
    // Create actual file
    fs.create_file(pinfo.binary_path, true); // create_path = true
    physical_file_t file = fs.get_file(pinfo.binary_path);
    file->write_buffer(binary_content, offset, binary_size);

    // Set symbolic links to loaded binary in /proc/<pid>/exe
    std::stringstream ss;
    ss << "/proc/" << std::dec << pinfo.pid << "/exe";
    fs.create_symlink(ss.str(), pinfo.binary_path, true);
    
    // Create stdin,stdout,stderr, for this process
    std::string stdin = fs.get_stdin_for_pid(pinfo.pid);
    std::string stdout = fs.get_stdout_for_pid(pinfo.pid);
    std::string stderr = fs.get_stderr_for_pid(pinfo.pid);

    fs.create_file(stdin);
    fs.create_file(stdout);
    fs.create_file(stderr);
    fs._new_fa(stdin, 0);
    fs._new_fa(stdout, 1);
    fs._new_fa(stderr, 2);

    std::cout << fs << std::endl; // DEBUG
}

} // namespace env
} // namespace maat
