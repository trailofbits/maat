#ifndef MAAT_ENV_H
#define MAAT_ENV_H

#include "maat/env/library.hpp"
#include "maat/env/filesystem.hpp"
#include "maat/env/os.hpp"
#include "maat/env/syscall.hpp"
#include "maat/arch.hpp"
#include "maat/snapshot.hpp"
#include "maat/process.hpp"
#include "maat/serializer.hpp"

namespace maat
{
    
/// Simulation of the external environment in which a process is run
namespace env
{

/** \defgroup env Environment
 * \brief Simulation of the external environment in which a process is run */

/** \addtogroup env
 * \{ */

/** \brief Main class emulating a process environment.
 * 
 * This class provides an interface to other components that can be used
 * to emulate system calls, IPC, a filesystem, external libraries, memory
 * allocation on the heap, etc. */
class EnvEmulator: public serial::Serializable
{
public:
    abi::ABI& default_abi; ///< Default ABI for calling functions
    abi::ABI& syscall_abi; ///< Default ABI for system calls
protected:
    std::vector<Library> _libraries;
    syscall_func_map_t _syscall_func_map; // <sysnum:handler>
public:
    FileSystem fs;
public:
    /// Create an emulator for architecture *arch* and system *system*
    EnvEmulator(Arch::Type arch = Arch::Type::NONE, OS os = OS::NONE);
    virtual ~EnvEmulator() = default;
protected:
    /** In-place initialisation function.
     * This function is redundent with the constructor, however it is necessary
     * to have it so that it can be called from derived classes when they are
     * deserialized and need to be initialized after the object was allocated */
    void _init(Arch::Type arch, OS os);
// Library functions
public:
    /// Return **true** if the environment can emulate the library *name*
    bool contains_library(const std::string& name) const;
    /// Return the emulated library named *name*
    const Library& get_library_by_name(const std::string& name) const;
    const Library& get_library_by_num(int num) const;
    /// Return a list of all emulated libraries
    const std::vector<Library>& libraries() const;
public:
    const Function& get_syscall_func_by_num(int num) const;
public:
    using snapshot_t = int;
    /// Take a snapshot of the environment
    virtual snapshot_t take_snapshot();
    /// Restore a snapshot of the environment
    virtual void restore_snapshot(snapshot_t snapshot, bool remove=false);
// Virtual functions
public:
    /// Add a running process to the environment
    virtual void add_running_process(const ProcessInfo& pinfo, const std::string& filepath);
public:
    virtual maat::serial::uid_t class_uid() const;
    virtual void dump(maat::serial::Serializer& s) const;
    virtual void load(maat::serial::Deserializer& d);
};

/// Specialisation of 'EnvEmulator' for the Linux operating system 
class LinuxEmulator: public EnvEmulator
{
private:
    Arch::Type _arch;
public:
    LinuxEmulator(Arch::Type arch);
    virtual ~LinuxEmulator() = default;
private:
    /// In-place initialization function used by constructor and deserializer
    void _init(Arch::Type arch);
public:
    /// Add a running process to the environment
    virtual void add_running_process(const ProcessInfo& pinfo, const std::string& filepath);
public:
    virtual maat::serial::uid_t class_uid() const;
    virtual void dump(maat::serial::Serializer& s) const;
    virtual void load(maat::serial::Deserializer& d);
};


// Util functions
abi::ABI& _get_default_abi(Arch::Type arch, OS os);
abi::ABI& _get_syscall_abi(Arch::Type arch, OS os);

/** \} */ // doxygen group env

} // namespace env
} // namespace maat


#endif
