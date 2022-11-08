#ifndef MAAT_ENV_LIBRARY_H
#define MAAT_ENV_LIBRARY_H

#include "maat/value.hpp"
#include "maat/types.hpp"
#include <vector>
#include <string>
#include <variant>
#include "maat/ir.hpp"

namespace maat
{
class MaatEngine; // Forward decl

namespace env
{

/** \addtogroup env
 * \{ */

/// Util classes and methods to handle various calling conventions
namespace abi
{
    class ABI; // Forward decl
}

/// Action returned by emulated function callbacks
enum class Action
{
    CONTINUE, ///< Continue execution
    ERROR ///< An error occured within the callback
};

/// List of function arguments sizes. A size of zero means the current architecture address size
typedef std::vector<size_t> args_spec_t;

/// A C/C++ or Python callback emulating an imported function 
class FunctionCallback
{
public:
    using return_t = std::variant<std::monostate, cst_t, Value>; ///< Value returned by the function (if any)
    using native_cb_t = std::add_pointer<return_t(MaatEngine&, const std::vector<Value>&)>::type; ///< Native C/C++ callback
public:
    args_spec_t args_spec; /// Arguments list
private:
    native_cb_t native_callback; ///< Native callback function
    // TODO python callbacks
public:
    FunctionCallback();
    FunctionCallback(const args_spec_t& args, native_cb_t callback); ///< Create a callback with a native function
    // TODO make them not default and add reference count for python callbacks!!!
    FunctionCallback(const FunctionCallback& other) = default; ///< Copy constructor
    FunctionCallback(FunctionCallback&& other) = default; ///< Move semantics
    FunctionCallback& operator=(const FunctionCallback& other) = default; ///< Assignment operator
    FunctionCallback& operator=(FunctionCallback&& other) = default; ///< Move assignment
    ~FunctionCallback();
public:
    /** Run the function callback
    * 
    * @param abi ABI to use to get function arguments and return from the function
    * @param func_wrapper_name Optional function name to use to log the function call. If
    * unspecified the call will not be logged
    */
    env::Action execute(
        MaatEngine& engine,
        const abi::ABI& abi,
        std::optional<std::string> func_wrapper_name = std::nullopt
    ) const;
private:
    /// Execute native callback
    env::Action _execute_native(
        MaatEngine& engine,
        const abi::ABI& abi,
        std::optional<std::string> func_wrapper_name = std::nullopt
    ) const;
    /// Execute python callack
    env::Action _execute_python(MaatEngine& engine, const abi::ABI& abi) const;
};

namespace abi
{

/** \addtogroup env
 * \{ */

/// Value to use in **args_spec_t** for arguments whose size must be equal to the architecture default address size
static constexpr size_t auto_argsize = 0;

/// ABI types
enum class Type
{
    /* X86 */
    X86_CDECL,
    X86_STDCALL,
    X86_FASTCALL,
    X86_THISCALL_GCC,
    X86_THISCALL_MS,
    X86_LINUX_SYSENTER,
    X86_LINUX_INT80,
    /* X64 */
    X64_MS,
    X64_SYSTEM_V,
    X64_LINUX_SYSCALL,
    /* ARM64 */
    ARM64,
    /* RISCV */
    RISCV_LINUX_SYSCALL,
    /* Custom */
    X86_LINUX_CUSTOM_SYSCALL, ///< Used internally
    X64_LINUX_CUSTOM_SYSCALL, ///< Used internally
    /* No specific ABI */
    NONE
};

/// Abstract interface for different ABIs
class ABI
{
private:
    Type _type;
public:
    ABI(Type type);
public:
    /// Return the ABI type
    Type type() const;
public:
    /// Set function arguments
    virtual void prepare_args(MaatEngine& engine, const std::vector<Value>& args) const;
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Set the return address prior to call a function
    virtual void prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const;
    /// Return from a function
    virtual void ret(MaatEngine& engine) const;
protected:
    static size_t real_arg_size(MaatEngine& engine, size_t arg_size);
};


class ABI_NONE: public ABI
{
protected:
    ABI_NONE();
public:
    static ABI& instance();
};

/// X86 CDECL ABI
class X86_CDECL : public ABI
{
protected:
    X86_CDECL();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Set the return address prior to call a function
    virtual void prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const;
    /// Return from a function
    virtual void ret(MaatEngine& engine) const;
};

/// X86 STDCALL ABI
class X86_STDCALL : public ABI
{
protected:
    X86_STDCALL();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Set the return address prior to call a function
    virtual void prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const;
    /// Return from a function
    virtual void ret(MaatEngine& engine) const;
};

/// X86 Linux INT 0x80 ABI
class X86_LINUX_INT80 : public ABI
{
protected:
    X86_LINUX_INT80();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Return from the syscall
    virtual void ret(MaatEngine& engine) const;
};

/// X86 Linux SYSENTER ABI
class X86_LINUX_SYSENTER : public ABI
{
protected:
    X86_LINUX_SYSENTER();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
};

/// X64 SYSTEM V ABI
class X64_SYSTEM_V : public ABI
{
protected:
    X64_SYSTEM_V();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Set the return address prior to call a function
    virtual void prepare_ret_address(MaatEngine& engine, addr_t ret_addr) const;
    /// Return from a function
    virtual void ret(MaatEngine& engine) const;
};

/// X64 Linux SYSCALL ABI
class X64_LINUX_SYSCALL : public ABI
{
protected:
    X64_LINUX_SYSCALL();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Return from the syscall
    virtual void ret(MaatEngine& engine) const;
};

/// X64 Linux SYSCALL ABI
class RISCV_LINUX_SYSCALL : public ABI
{
protected:
    RISCV_LINUX_SYSCALL();
public:
    /// ABI instance (singleton pattern)
    static ABI& instance();
public:
    /// Get function arguments
    virtual void get_args(
        MaatEngine& engine,
        const args_spec_t& args_spec,
        std::vector<Value>& args
    ) const;
    /// Get function argument number 'n' (starting at 0)
    virtual Value get_arg(MaatEngine& engine, int n, size_t arg_size) const;
    /// Set a function's return value before it returns
    virtual void set_ret_value(
        MaatEngine& engine,
        const FunctionCallback::return_t& ret_val
    ) const;
    /// Return from the syscall
    virtual void ret(MaatEngine& engine) const;
};

/** \} */ // doxygen group env
} // namespace ABI

/// Emulated function
class Function
{
public:
    using names_t = std::vector<std::string>; ///< Name of the function (and potential aliases)
public:
    /// Different types of emulated functions
    enum class Type
    {
        CALLBACK, ///< Emulated with a native C/C++ callback, or a Python callback
        IR, ///< Emulated with an IR block
        RAW ///< Defined with raw assembly code
    };

private:
    std::vector<std::string> _names; ///< Name of the function and alternative aliases
    Type _type; ///< Type of emulated function
    std::optional<FunctionCallback> _callback; ///< Emulation callback, for *NATIVE_CB* and *PYTHON_CB* functions
    std::optional<std::shared_ptr<ir::AsmInst>> _ir_block; ///< IR block, for *IR* functions
    std::optional<std::vector<uint8_t>> _raw; ///< Raw assembly, for *RAW* functions
public:
    Function();
    /// Create an emulated function from a callback
    Function(const std::string& name, const FunctionCallback& callback);
    /// Create an emulated function from a callback
    Function(const names_t& names, const FunctionCallback& callback);
    // TODO: python callbacks
    Function(const names_t& names, std::shared_ptr<ir::AsmInst> block); ///< Create an emulated function from an IR block
    Function(const names_t& names, const std::vector<uint8_t>& raw); ///< Create an emulated function from raw assembly
    Function(const Function& other);
    Function& operator=(const Function& other);
    Function& operator=(Function&& other) = delete;
    ~Function() = default;
public:
    Type type() const; ///< Type of emulated function
    const FunctionCallback& callback() const; ///< Return the function callback if it exists, otherwise raise an exception
    const std::shared_ptr<ir::AsmInst>& ir() const; ///< Return the function IR block if it exists, otherwise raise an exception
public:
    const std::vector<std::string>& names() const; ///< Return the name and aliases of the function
    const std::string& name() const; ///< Return the main name of the function
    const bool has_name(const std::string& name) const; ///< Return True if function has name 'name'
};

/// Emulated external data (in a library)
class Data
{
public:
    using names_t = std::vector<std::string>; ///< Name of the data (and potential aliases)
private:
    std::vector<uint8_t> _data;
    names_t _names;
public:
    Data() = default;
    Data(std::string name, const std::vector<uint8_t>& data);
public:
    const std::vector<uint8_t>& data() const; ///< Return the raw data content
    const std::vector<std::string>& names() const; ///< Return the name and aliases of the data
    const std::string& name() const; ///< Return the main name of the data
    const bool has_name(const std::string& name) const; ///< Return True if data has name 'name'
};

/// Emulated external library
class Library
{
private:
    std::vector<Function> _functions;
    std::vector<Data> _data;
    std::string _name;
public:
    Library(const std::string& name);
    Library(const std::string& name, const std::vector<Function>& functions, const std::vector<Data>& exported_data);
    Library(const Library& other) = delete;
    Library(Library&& other);
    Library& operator=(const Library& other) = delete;
    Library& operator=(Library&& other) = delete;
public:
    const std::string& name() const; ///< Get the name of the library
public:
    /// Get all functions
    const std::vector<Function>& functions() const;
    /// Add a function to the library
    void add_function(const Function& function);
    /// Get function by name. Raise an exception if the function doesn't exist in this library
    const Function& get_function_by_name(const std::string& name) const;
    /// Get function by num. Raise an exception if the number doesn't correspond to a function
    const Function& get_function_by_num(int num) const;
public:
    /// Get all exported data
    const std::vector<Data>& data() const;
    /// Add exported data to the library
    void add_data(const Data& data);
    /// Get exported data by name. Raise an exception if the data doesn't exist in this library
    const Data& get_data_by_name(const std::string& name) const;
    /// Return the total size of exported data in bytes
    size_t total_data_size() const;
};


/// Namespace containing all emulated external functions, data, libraries, and syscalls
namespace emulated
{
/// Return the emulated libc.so for Linux on X86
Library linux_x86_libc();
/// Return the emulated libc.so for Linux on X64
Library linux_x64_libc();
/// Return the emulated libc.so for Linux on ARM32 
Library linux_ARM32_libc();
}


/** \} */ // doxygen group env
} // namespace env
} // namespace maat 


#endif
