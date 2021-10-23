#ifndef MAAT_ENV_SYSCALL_H
#define MAAT_ENV_SYSCALL_H

#include "env/library.hpp"

namespace maat
{
class MaatEngine; // Forward decl

namespace env
{

/** \addtogroup env
 * \{ */

typedef std::unordered_map<int, env::Function> syscall_func_map_t;

namespace emulated
{
/// Return the emulated syscalls for Linux on X86
syscall_func_map_t linux_x86_syscall_map();
/// Return the emulated syscalls for Linux on X64
syscall_func_map_t linux_x64_syscall_map();
}


/** \} */ // doxygen group env
} // namespace env
} // namespace maat 
#endif