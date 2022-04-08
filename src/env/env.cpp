#include "maat/env/env.hpp"

namespace maat{
namespace env{

abi::ABI* _get_default_abi(Arch::Type arch, OS os)
{
    if (arch == Arch::Type::X86)
    {
        if (os == OS::LINUX)
            return &abi::X86_CDECL::instance();
    }
    else if (arch == Arch::Type::X64)
    {
        if (os == OS::LINUX)
            return &abi::X64_SYSTEM_V::instance();
    }
    return &abi::ABI_NONE::instance();
}

abi::ABI* _get_syscall_abi(Arch::Type arch, OS os)
{
    if (arch == Arch::Type::X64)
    {
        if (os == OS::LINUX)
            return &abi::X64_LINUX_SYSCALL::instance();
    }
    return &abi::ABI_NONE::instance();
}

EnvEmulator::EnvEmulator(Arch::Type arch, OS os):
default_abi(_get_default_abi(arch, os)),
syscall_abi(_get_syscall_abi(arch, os)),
fs(FileSystem(os))
{}

void EnvEmulator::_init(Arch::Type arch, OS os)
{
    default_abi = _get_default_abi(arch, os);
    syscall_abi = _get_syscall_abi(arch, os);
    fs = FileSystem(os);
}

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

const Function& EnvEmulator::get_syscall_func_by_num(int num) const
{
    auto it = _syscall_func_map.find(num);
    if (it == _syscall_func_map.end())
        throw env_exception(
            Fmt() << "EnvEmulator: syscall '" << num
            << "' not supported for emulation" 
            >> Fmt::to_str
        );
    return it->second;
}

void EnvEmulator::add_running_process(const ProcessInfo& pinfo, const std::string& filepath)
{
    throw env_exception("add_running_process() not supported for generic EnvEmulator");
}


/// Take a snapshot of the current engine state
EnvEmulator::snapshot_t EnvEmulator::take_snapshot()
{
    return fs.take_snapshot();
}

/** Restore the engine state to 'snapshot'. If remove is true, the 
 * snapshot is removed after being restored */
void EnvEmulator::restore_snapshot(snapshot_t snapshot, bool remove)
{
    return fs.restore_snapshot(snapshot, remove);
}

uid_t EnvEmulator::class_uid() const
{
    return serial::ClassId::ENV_EMULATOR;
}

void EnvEmulator::dump(serial::Serializer& s) const
{
    // Note: we don't serialize the ABIs and stuff because
    // the base EnvEmulator class is only used to provide
    // a symbolic filesystem without being a real environment.
    // Every OS properly supported for emulation will have its
    // own derived class
    s << fs;
}

void EnvEmulator::load(serial::Deserializer& d)
{
    d >> fs;
}

} // namespace env
} // namespace maat
