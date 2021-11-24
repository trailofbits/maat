#ifndef MAAT_ENV_H
#define MAAT_ENV_H

#include "env/library.hpp"
#include "env/filesystem.hpp"
#include "env/os.hpp"
#include "env/syscall.hpp"
#include "arch.hpp"
#include "snapshot.hpp"
#include "process.hpp"

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
class EnvEmulator
{
public:
    const abi::ABI& default_abi; ///< Default ABI for calling functions
    const abi::ABI& syscall_abi; ///< Default ABI for system calls
protected:
    std::vector<Library> _libraries;
    syscall_func_map_t _syscall_func_map; // <sysnum:handler>
public:
    FileSystem fs;
public:
    /// Create an emulator for architecture *arch* and system *system*
    EnvEmulator(Arch::Type arch, OS os);
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
};

/// Specialisation of 'EnvEmulator' for the Linux operating system 
class LinuxEmulator: public EnvEmulator
{
public:
    LinuxEmulator(Arch::Type arch);
public:
    /// Add a running process to the environment
    virtual void add_running_process(const ProcessInfo& pinfo, const std::string& filepath);
};


/** \} */ // doxygen group env

} // namespace env
} // namespace maat


#endif
