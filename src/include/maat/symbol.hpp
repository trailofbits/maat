#ifndef MAAT_SYMBOL_H
#define MAAT_SYMBOL_H

#include "maat/types.hpp"
#include <optional>
#include <unordered_map>
#include <vector>
#include <string>

namespace maat
{

/// A class representing a symbol
class Symbol
{
public:
    using args_spec_t = std::vector<size_t>;
public:
    /// Type of symbol
    enum class Type
    {
        FUNCTION, ///< Function
        DATA ///< Data
    };
    
    /// Status of this function in the engine
    enum class FunctionStatus
    {
        EMULATED_RAW, ///< Emulated with raw assembly
        EMULATED_IR, ///< Emulated with IR
        EMULATED_CALLBACK, ///< Emulated with callback
        MISSING, ///< Neither loaded nor emulated 
        LOADED, ///< Included in the loaded binary or a loaded library
        USER_DEFINED, ///< Symbol added manually by the user
        NONE
    };
    
    /// Status of this data in the engine 
    enum class DataStatus
    {
        EMULATED, ///< Data was defined in an emulated library
        MISSING, ///< Neither loaded nor emulated 
        LOADED, ///< Included in the loaded binary or a loaded library 
        USER_DEFINED, ///< Symbol added manually by the user
        NONE
    };

public:
    FunctionStatus func_status;
    DataStatus data_status;
    addr_t addr;
    std::string name;
    std::optional<Symbol::args_spec_t> args; ///< Args for functions
    int env_lib_num;
    int env_func_num;
    size_t size; ///< Size for data
public:
    Symbol();
    Symbol(const Symbol& other) = default;
    Symbol& operator=(const Symbol& other) = default;
    ~Symbol() = default;
    /// Create a function symbol
    Symbol(
        FunctionStatus status,
        addr_t addr,
        const std::string& name,
        std::optional<Symbol::args_spec_t> args = std::nullopt,
        int env_lib_num = -1,
        int env_func_num = -1,
        size_t size = 0
    );
    /// Create a data symbol
    Symbol(
        DataStatus status,
        addr_t addr,
        const std::string& name,
        size_t size = 0
    );
public:
    friend std::ostream& operator<<(std::ostream&, const Symbol&);
};

/// Manager for all symbols in an engine
class SymbolManager
{
protected:
    std::unordered_map<addr_t, Symbol> symbols_by_addr;
    std::unordered_map<std::string, Symbol> symbols_by_name;
public:
    void add_symbol(Symbol symbol); ///< Add a symbol
public:
    bool has_symbol(addr_t addr); ///< Return true if address *addr* has a symbol
    bool is_callback_emulated_function(addr_t addr); ///< Return true if address *addr* is actually a callback-emulated function
    /// Return true if *addr* corresponds to a function that was not loaded and can't be emulated
    bool is_missing_function(addr_t addr);
    const std::string& name(addr_t addr); ///< Get symbol name for address *addr*
    addr_t addr(const std::string& name); ///< Get address for symbol *name*
    const Symbol& get_by_name(const std::string& name); ///< Get symbol *name*
    const Symbol& get_by_addr(addr_t addr); ///< \brief Get symbol for address *addr*

    /// Add a user defined function symbol
    void add_function(
        addr_t addr,
        const std::string& name,
        std::optional<Symbol::args_spec_t> args = std::nullopt
    );
public:
    /// Print all symbols to a stream
    friend std::ostream& operator<<(std::ostream&, const SymbolManager&);
};


} // namespace maat

#endif
