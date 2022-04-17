#ifndef MAAT_ENV_EVM_HPP
#define MAAT_ENV_EVM_HPP

#include "maat/env/library.hpp"
#include "maat/env/filesystem.hpp"
#include "maat/env/os.hpp"
#include "maat/env/env.hpp"
#include "maat/arch.hpp"
#include "maat/snapshot.hpp"
#include "maat/process.hpp"
#include "maat/serializer.hpp"
#include <iostream>

namespace maat{
namespace env{
/// Simulation of the Ethereum blockchain state
namespace EVM{


/** \addtogroup env
 * \{ */

/// EVM Stack
class Stack
{
private:
    std::vector<Value> _stack;
public:
    Stack() = default;
    virtual ~Stack() = default;
public:
    /// Return number of elements present in the stack
    int size() const;
    /// Get value at given position. Position 0 is the top of the stack
    const Value& get(int pos) const;
    /// Remove value from top of the stack
    void pop();
    /// Get value at given position. Position 0 is the top of the stack
    void set(const Value& value, int pos);
    /// Push new value at the top of the stack
    void push(const Value& value);
public:
    friend std::ostream& operator<<(std::ostream&, const Stack&);
private:
    // Convert a position to corresponding index in internal vector
    int _pos_to_idx(int pos) const;
};

/// EVM Volatile Memory
class Memory
{
private:
    MemEngine _mem;
    addr_t _size; // Current memory size in the EVM sense
    addr_t _limit; // Limit of internally allocated memory
    addr_t _alloc_size;
    std::shared_ptr<VarContext> _varctx;
public:
    Memory(std::shared_ptr<VarContext> ctx);
    ~Memory() = default;
public:
    MemEngine& mem(); ///< Get internal memory engine
    addr_t size() const; ///< Get current memory size in bytes
public:
    /// Read 'nb_bytes' at address 'addr'
    Value read(const Value& addr, size_t nb_bytes);
    /// Write value to memory
    void write(const Value& addr, const Value& val);
private:
    // Expand memory if needed to write 'nb_bytes' at 'addr'
    void _expand_if_needed(const Value& addr, size_t nb_bytes);
};


class ValueHash {
  public:
    ::std::size_t operator ()(const Value& value) const
    {
        if (value.is_abstract())
            return value.as_expr()->hash();
        else
            return value.as_uint(); // Not abstract so should be safe to call
    }
};

class ValueEqual {
  public:
    bool operator ()(const Value& v1, const Value& v2) const
    {
        return v1.eq(v2);
    }
};

class NumberEqual {
  public:
    bool operator ()(const Number& n1, const Number& n2) const
    {
        return n1.equal_to(n2);
    }
};

/// Contract permananent storage
class Storage
{
private:
    /// Storage state for concrete addresses
    std::unordered_map<Value, Value, ValueHash, ValueEqual> _storage;
    /// History of storage writes, including symbolic addresses
    std::vector<std::pair<Value, Value>> writes_history;
    std::shared_ptr<VarContext> _varctx;
    /// True if at least one address written to was symbolic
    bool _has_symbolic_addresses; 
public:
    Storage(std::shared_ptr<VarContext> ctx);
    ~Storage() = default;
public:
    /// Get storage word at 'addr'
    Value read(const Value& addr);
    /// Write storage word at 'addr'
    void write(const Value& addr, const Value& val, const Settings& settings);
};

/// Deployed Smart-Contract
class Contract
{
public:
    Value address; ///< Address where the contract is deployed
    Stack stack; ///< Stack of the executing EVM
    Memory memory; ///< Volatile memory of the executing EVM
    Storage storage; ///< Persistent contract storage
public:
    /** Constructor. Create new deployed contract */
    Contract(const MaatEngine& engine, Value address);
};

typedef std::shared_ptr<Contract> contract_t;

/// Specialisation of 'EnvEmulator' for the Ethereum blockchain state
class EthereumEmulator: public EnvEmulator
{
private:
    int _uid_cnt;
    std::unordered_map<int, contract_t> _contracts;
public:
    EthereumEmulator();
    virtual ~EthereumEmulator() = default;
private:
    /// In-place initialization function used by constructor and deserializer
    void _init();
public:
    /// Add a running deployed contract instance and return its unique id
    int add_contract(contract_t contract);
    /// Get running contract by uid
    contract_t get_contract_by_uid(int uid) const;
public:
    virtual maat::serial::uid_t class_uid() const;
    virtual void dump(maat::serial::Serializer& s) const;
    virtual void load(maat::serial::Deserializer& d);
};

/** \brief Helper function that gets the environment linked to an engine and casts it to EthereumEmulator.
 * This function performs dynamic casting without further checks, use at your own risk */ 
std::shared_ptr<EthereumEmulator> get_ethereum(MaatEngine& engine);

/// Helper function that gets the running contract associated to an engine
contract_t get_contract_for_engine(MaatEngine& engine); 

/** \} */ // doxygen group env

} // namespace EVM
} // namespace env
} // namespace maat

#endif 