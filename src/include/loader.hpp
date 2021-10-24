#ifndef MAAT_LOADER_H
#define MAAT_LOADER_H

#ifdef LIEF_BACKEND
#include <LIEF/LIEF.hpp>
#endif

#include <vector>
#include <list>
#include "types.hpp"
#include "arch.hpp"
#include "memory_page.hpp"
#include "exception.hpp"

namespace maat
{

    class MaatEngine; // Forward decl
/// Functionalities to load executable files in Maat's engine
namespace loader
{

/** \defgroup loader Loader
 * \brief The main interface to load an executable file in Maat's engine */

/** \addtogroup loader
 * \{ */

/// Executable file formats
enum class Format
{
    ELF32, ///< ELF 32-bits
    ELF64 ///< ELF 64-bits
};


/** \brief A class representing a command line argument supplied when executing a binary
 * 
 * Command line arguments can be of the 3 following types:
 * - **Concrete**: a regular argument with a fixed concrete value
 * - **Concolic**: an argument with a concrete value, whose every single byte is
 *   written in memory as a concolic variable
 * - **Symbolic**: an argument without a concrete value, whose every single byte
 *   is written in memory as a symbolic variable */ 
class CmdlineArg
{
private:
    std::string _value;
    std::string _name;
    size_t _len;
    bool _is_symbolic;
    bool _is_concolic;
public:
    /// Create a concrete command-line argument
    CmdlineArg(const std::string& value);
    /** \brief Create a concolic command-line argument
     * @param value Concrete value of the argument
     * @param name Abstract name of the argument */
    CmdlineArg(const std::string& value, const std::string& name);
    /** \brief Create a symbolic command-line argument
     * @param len Maximal concrete length of the argument
     * @param name Abstract name of the argument */
    CmdlineArg(size_t len, const std::string& name);
public:
    const std::string& value() const; ///< Return the argument value (empty for symbolic arguments)
    const std::string& name() const; ///< Retun the argument symbolic name (empty for concrete arguments)
    size_t len() const; ///< Return the argument length in bytes, including terminating null byte
    bool is_symbolic() const; ///< Return true if the argument is symbolic
    bool is_concrete() const; ///< Return true if the argument is concrete
    bool is_concolic() const; ///< Return true if the argument is concolic
};

/// Environment variables for a given process
typedef std::unordered_map<std::string, std::string> environ_t;

/// Loader interface for loading executables into a *MaatEngine*
class Loader
{
public:
    /** \brief Load a binary in *engine*
     * 
     * @param binary Path of the executable file 
     * @param type Executable format of the executable to load
     * @param base Base address where to load the binary (used if relocatable or position independent code)
     * @param args Command line arguments with whom to invoke the executable
     * @param virtual_path Path of the loaded binary in the emulated file system
     * @param libdirs Directories where to search for shared objects the binary might depend on
     * @param ignore_libs List of libraries to **NOT** load even though the binary lists them as dependencies. This option has no effect when 'interpreter' is 'true'
     * @param interpreter If set to <code>True</code>, load and emulate the interpreter and let it load
     *   the binary and dependencies by itself. The interpreter binary must be found in one of 
     *   the 'libdirs' directories. If the interpreter is missing, Maat loads the binary and 
     *   dependencies manually */

    virtual void load(
        MaatEngine*engine,
        const std::string& binary,
        loader::Format type,
        addr_t base,
        const std::vector<CmdlineArg>& args,
        const environ_t& envp,
        const std::string& virtual_path,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        bool interpreter = true
    );
protected:
    void load_emulated_libs(MaatEngine* engine);
};

#ifdef LIEF_BACKEND
/// Implementation of the Loader interface using LIEF
class LoaderLIEF : public Loader
{
private:
    std::unique_ptr<LIEF::ELF::Binary> _elf;
    std::string binary_name;
    std::optional<addr_t> interpreter_entry;
    std::optional<addr_t> interpreter_base; // For aux vector
public:
    virtual void load(
        MaatEngine*engine,
        const std::string& binary,
        loader::Format type,
        addr_t base,
        const std::vector<CmdlineArg>& args,
        const environ_t& envp,
        const std::string& virtual_path,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        bool interpreter = true
    );

private:
    void parse_binary(const std::string& binary, loader::Format type);
    void get_arch_special_registers(
        const Arch& arch, reg_t& pc, reg_t& sp, reg_t& bp, reg_t& gs, reg_t& fs
    );
    void map_elf_segments(MaatEngine*engine, addr_t base_address);
    void load_elf_dependencies(
        MaatEngine*engine,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        std::list<std::string>& loaded_libs,
        LoaderLIEF& top_loader
    );
    addr_t alloc_segment(
        MaatEngine*engine,
        addr_t prefered_base,
        addr_t size,
        mem_flag_t flags,
        const std::string& name = "",
        bool is_special_segment = false
    );
    void elf_setup_stack(
        MaatEngine* engine,
        addr_t base,
        std::vector<CmdlineArg> args,
        const environ_t& envp
    );
    addr_t find_free_space(MaatEngine*engine, addr_t start, addr_t size);
    void load_elf(
        MaatEngine*engine,
        const std::string& binary,
        addr_t base,
        std::vector<CmdlineArg> args,
        const environ_t& envp,
        const std::string& virtual_path,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        bool load_interp
    );
    void load_elf_binary(
        MaatEngine*engine,
        const std::string& binary,
        addr_t base,
        std::vector<CmdlineArg> args,
        const environ_t& envp,
        const std::string& virtual_path,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs
    );
    void load_elf_using_interpreter(
        MaatEngine*engine,
        const std::string& binary,
        addr_t base,
        std::vector<CmdlineArg> args,
        const environ_t& envp,
        const std::string& virtual_path,
        const std::string& interp_path
    );
    // Return the base address for the loaded lib
    addr_t load_elf_library(
        MaatEngine*engine,
        loader::Format type,
        const std::string& libpath,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        std::list<std::string>& loaded_libs,
        LoaderLIEF& top_loader
    );
    void load_elf_interpreter(
        MaatEngine* engine,
        const std::string& interp_path,
        LoaderLIEF& top_loader
    );
    std::vector<std::pair<uint64_t, uint64_t>> generate_aux_vector(
        MaatEngine*engine,
        addr_t base_segment,
        addr_t argv_0
    );
    void perform_elf_relocations(MaatEngine*engine, addr_t base);
    void load_cmdline_args(
        MaatEngine*engine,
        const std::vector<CmdlineArg>& args,
        int& argc,
        std::vector<addr_t>& argv_addresses
    );
    /// Add internal symbols to the engine symbol manager
    void add_elf_symbols(MaatEngine* engine, uint64_t base);
};

// util function
mem_flag_t get_segment_flags(LIEF::ELF::Segment& segment);
#endif // ifdef LIEF_BACKEND

/** \brief Convenience function returning a loader instance abstracting the
 * underlying backend implementation */
std::unique_ptr<Loader> new_loader();

/** \} */ // end doxygen group Loader

} // namespace loader
} // namespace maat

#endif
