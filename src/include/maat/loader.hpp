#ifndef MAAT_LOADER_H
#define MAAT_LOADER_H

#ifdef MAAT_LIEF_BACKEND
#include <LIEF/LIEF.hpp>
#endif

#include <vector>
#include <list>
#include <unordered_map>
#include "maat/types.hpp"
#include "maat/arch.hpp"
#include "maat/memory_page.hpp"
#include "maat/exception.hpp"
#include "maat/value.hpp"

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
    ELF64, ///< ELF 64-bits
    NONE ///< Unspecified
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
    std::vector<Value> _buffer;
    size_t _len;
public:
    /// Create a concrete command-line argument
    CmdlineArg(const std::string& value);
    /// Create a command line argument from a single abstract value
    CmdlineArg(const Value& value);
    /** \brief Create a command-line argument from a buffer
     * @param arg Argument as a buffer of values that are concatenated
     * to form the argument */
    CmdlineArg(const std::vector<Value>& arg);
public:
    const std::string& string() const; ///< Return the concrete argument string
    const std::vector<Value>& buffer() const; ///< Retun the abstract argument buffer
    size_t len() const; ///< Return the argument length in bytes
    bool is_abstract() const; ///< Return true if the argument is an abstract buffer
    bool is_concrete() const; ///< Return true if the argument is a concrete string
};

/// Environment variables for a given process
typedef std::unordered_map<std::string, std::string> environ_t;

/// Loader interface for loading executables into a *MaatEngine*
class Loader
{
public:
    virtual ~Loader() = default;
public:
    /** \brief Load a binary in *engine*
     * 
     * @param binary Path of the executable file 
     * @param type Executable format of the executable to load
     * @param base Base address where to load the binary (used if relocatable or position independent code)
     * @param args Command line arguments with whom to invoke the executable
     * @param virtual_fs Location of loaded binaries and libraries in the emulated filesystem.
     *   Maps the object(s) filenames to their path(s) in the virtual filesystem, eg:
     *   { "libc.so.6": "/usr/lib" }
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
        const std::unordered_map<std::string, std::string>& virtual_fs,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        bool interpreter = true
    );
protected:
    void load_emulated_libs(MaatEngine* engine);
    const std::string get_path_in_virtual_fs(
        MaatEngine * engine,
        const std::unordered_map<std::string, std::string>& virtual_fs,
        const std::string& filename,
        const std::string& default_dir = "/");
};

#ifdef MAAT_LIEF_BACKEND
/// Implementation of the Loader interface using LIEF
class LoaderLIEF : public Loader
{
private:
    std::unique_ptr<LIEF::ELF::Binary> _elf;
    std::string binary_name;
    std::string binary_path;
    std::optional<addr_t> interpreter_entry;
    std::optional<addr_t> interpreter_base; // For aux vector
public:
    virtual ~LoaderLIEF() = default;
public:
    virtual void load(
        MaatEngine*engine,
        const std::string& binary,
        loader::Format type,
        addr_t base,
        const std::vector<CmdlineArg>& args,
        const environ_t& envp,
        const std::unordered_map<std::string, std::string>& virtual_fs,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        bool interpreter = true
    );

private:
    void parse_binary(const std::string& binary, loader::Format type);
    void get_arch_special_registers(
        const Arch& arch, std::optional<reg_t>& pc, std::optional<reg_t>& sp, std::optional<reg_t>& bp, std::optional<reg_t>& gs, std::optional<reg_t>& fs
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
        const std::string& name = ""
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
        const std::unordered_map<std::string, std::string>& virtual_fs,
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
        const std::unordered_map<std::string, std::string>& virtual_fs,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs
    );
    void load_elf_using_interpreter(
        MaatEngine*engine,
        const std::string& binary,
        addr_t base,
        std::vector<CmdlineArg> args,
        const environ_t& envp,
        const std::unordered_map<std::string, std::string>& virtual_fs,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        const std::string& interp_path
    );
    void add_elf_dependencies_to_emulated_fs(
        MaatEngine* engine,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        const std::unordered_map<std::string, std::string>& virtual_fs
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
    void add_elf_symbols(MaatEngine* engine, uint64_t base);
    void load_cmdline_args(
        MaatEngine*engine,
        const std::vector<CmdlineArg>& args,
        int& argc,
        std::vector<addr_t>& argv_addresses
    );
    void force_relocation(
        MaatEngine* engine,
        addr_t base,
        const std::string& rel_name,
        addr_t value
    );
    void elf_additional_processing(MaatEngine* engine, addr_t base);
};

/// Class for deploying ethereum smart-contracts into a MaatEngine
class LoaderEVM
{
public:
    /** \brief Deploy a contract into 'engine'. 
    
    @param engine The engine where to deploy the contract
    @param contract_file The file containing the contract bytecode
    @param args The arguments to the contract constructor
    @param env Additional information. 'address' contains the address
    where to deploy the contract. 'deployer' contains the address of the
    deployer of the contract. Both must be encoded in hex form without
    the preceeding '0x' */
    void load(
        MaatEngine* engine,
        const std::string& contract_file,
        const std::vector<CmdlineArg>& args,
        const environ_t& env
    );
};

// util function
mem_flag_t get_segment_flags(LIEF::ELF::Segment& segment);
#endif // ifdef MAAT_LIEF_BACKEND

/** \brief Convenience function returning a loader instance abstracting the
 * underlying backend implementation */
std::unique_ptr<Loader> new_loader();

/** \} */ // end doxygen group Loader

} // namespace loader
} // namespace maat

#endif
