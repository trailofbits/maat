#include "maat/env/env_EVM.hpp"
#include "maat/engine.hpp"
#include "sha3.hpp"

namespace maat{
namespace env{
namespace EVM{

int Stack::size() const
{
    return _stack.size();
}

int Stack::_pos_to_idx(int pos) const
{
    int idx = size()-1-pos;
    if (idx < 0 or idx >= size())
        throw env_exception("EVM::Stack: requested invalid element posiion");
    return idx;
}

const Value& Stack::get(int pos) const
{
    int idx = _pos_to_idx(pos);
    return _stack[idx];
}

void Stack::pop(int n)
{
    while (n-- > 0)
    {
        if (size() == 0)
            throw env_exception("EVM::Stack::pop(): stack is empty");
        _stack.pop_back();
    }
}

void Stack::set(const Value& value, int pos)
{
    int idx = _pos_to_idx(pos);
    _stack[idx] = value;
}
void Stack::push(const Value& value)
{
    _stack.push_back(value);
}

std::ostream& operator<<(std::ostream& os, const Stack& stack)
{
    os << "EVM Stack:\n";
    for (const auto& val : stack._stack)
        os << val << "\n";
    return os;
}

Memory::Memory(std::shared_ptr<VarContext> ctx)
:_size(0), _limit(0), _alloc_size(0x1000), _mem(ctx, 64, nullptr, Endian::BIG), _varctx(ctx)
{};

MemEngine& Memory::mem()
{
    return _mem;
}

addr_t Memory::size() const
{
    return _size;
}

Value Memory::read(const Value& addr, size_t nb_bytes)
{
    expand_if_needed(addr, nb_bytes);
    return _mem.read(addr, nb_bytes);
}

void Memory::write(const Value& addr, const Value& val)
{
    expand_if_needed(addr, val.size()/8);
    _mem.write(addr, val);
}

void Memory::expand_if_needed(const Value& addr, size_t nb_bytes)
{
    if (not addr.is_symbolic(*_varctx))
    {
        addr_t required_size = addr.as_uint(*_varctx)+nb_bytes;
        while (required_size > _limit)
        {
            // Expand memory and init with zeros
            _mem.map(_limit, _limit+_alloc_size-1);
            std::vector<uint8_t> zeros(_alloc_size, 0);
            _mem.write_buffer(_limit, zeros.data(), _alloc_size, true);
            _limit += _alloc_size;
            _alloc_size *= 4;
        }
        // Update size if needed
        if ( required_size > _size)
        {
            _size = required_size;
            // Memory is expanded by blocks of 32 bytes
            if (_size % 32 != 0)
                _size = _size + 32 - (_size%32);
        }
    }
    // TODO: need to handle else{} case when computing gas to know how much
    // bytes have been allocated
}



Storage::Storage(std::shared_ptr<VarContext> ctx)
: _varctx(ctx), _has_symbolic_addresses(false)
{};



Value Storage::read(const Value& addr)
{
    // First see if we have an address that matches
    auto base = _storage.find(addr);
    Value res;
    if (base == _storage.end())
        res = Value(256, 0);
    else
        res = base->second;
    
    auto cmp = [](const Number& a, const Number& b) { return a.less_than(b);};
    std::set<Number, decltype(cmp)> seen_concrete_addresses(cmp);

    // Then apply potential previous symbolic writes
    for (auto it = writes_history.rbegin(); it != writes_history.rend(); it++)
    {
        const Value& prev_addr = it->first;
        const Value& prev_val = it->second;
        // If write address is same as 'addr', don't need to go further
        if (prev_addr.eq(addr))
            break;

        // If write address is concrete and was already seen, don't 
        // take older writes into account
        if (not prev_addr.is_abstract())
        {
            if (seen_concrete_addresses.count(prev_addr.as_number(*_varctx)) > 0)
                continue;
            else
                seen_concrete_addresses.insert(prev_addr.as_number(*_varctx));
        }

        // If both addresses are concrete and different, skip this one
        if (
            not prev_addr.is_abstract() and
            not addr.is_abstract() and
            not prev_addr.as_number(*_varctx).equal_to(addr.as_number(*_varctx))            
        )
            continue;

        // Else add ITE clause
        res.set_ITE(prev_addr, ITECond::EQ, addr, prev_val, res);
    }

    return res;
}

void Storage::write(const Value& addr, const Value& val, const Settings& settings)
{
    if (addr.is_symbolic(*_varctx) and not settings.symptr_write)
        throw env_exception("Storage::write(): writing at fully symbolic address but symptr_write is disabled");
    else if (addr.is_concrete(*_varctx) or not settings.symptr_write)
    {
        // Concrete or concolic without symptr enabled
        Value concrete_addr(addr.as_number(*_varctx));
        _storage[concrete_addr] = val;
        // We only care recording concrete address writes when there are
        // already symbolic writes that could be overwritten
        if (_has_symbolic_addresses)
            writes_history.push_back(std::make_pair(concrete_addr, val));
    }
    else
    {
        // Concolic or symbolic, with symptr enabled
        _storage[addr] = val;
        writes_history.push_back(std::make_pair(addr, val));
        _has_symbolic_addresses = true;
    }
}

TransactionResult::TransactionResult(
    TransactionResult::Type type,
    std::vector<Value> return_data
): _type(type), _return_data(return_data)
{}

const std::vector<Value>& TransactionResult::return_data() const
{
    return _return_data;
}

TransactionResult::Type TransactionResult::type() const
{
    return _type;
}

size_t TransactionResult::return_data_size() const
{
    size_t res = 0;
    for (const auto& val : _return_data)
        res += val.size()/8;
    return res;
}

Transaction::Transaction()
: origin(256, 0), sender(256, 0), recipient(256, 0), value(256, 0), gas_limit(256, 0)
{}

Transaction::Transaction(
    Value origin,
    Value sender,
    Number recipient,
    Value value,
    std::vector<Value> data,
    Value gas_limit
): origin(origin), sender(sender), recipient(recipient), value(value),
   data(data), gas_limit(gas_limit)
{}

size_t Transaction::data_size() const
{
    size_t res = 0;
    for (const auto& val : data)
        res += val.size()/8;
    return res;
}

Value Transaction::data_load_word(size_t offset) const
{
    Value res;
    size_t tmp_size = 0;
    int i = 0;
    offset *= 8; // convert size in bits

    if (data.empty())
        return Value(256, 0);

    // Skip the first expressions to reach desired offset
    for (i = 0; i < data.size() and offset > 0; i++)
    {
        const Value& val = data[i];
        if (val.size() > offset)
        {
            if (val.size()-offset > 256)
                res = extract(val, val.size()-1-offset, val.size()-256-offset);
            else
                res = extract(val, val.size()-1-offset, 0);
            i++;
            break;
        }
        else
            offset -= val.size();
    } 

    // Read 32 bytes from next expresions in data
    for (; (res.is_none() or res.size() < 256) and i < data.size(); i++)
    {
        const Value& val = data[i];
        if (res.is_none())
        {
            if (val.size() > 256)
                res = extract(val, val.size()-1, val.size()-256);
            else
                res = val;
        }
        else
        {
            if (val.size() + res.size() > 256)
                res.set_concat(res, extract(val, val.size()-1, val.size()-256+res.size()));
            else
                res.set_concat(res, val);
        }

        if (res.size() == 256)
            break;
    }

    // If not enough data, pad with zeros
    if (res.size() < 256)
        res.set_concat(res, Value(256-res.size(), 0));

    return res;
}

std::vector<Value> Transaction::data_load_bytes(size_t offset, size_t len) const
{
    std::vector<Value> res;
    size_t tmp_size = 0;
    int i = 0;
    offset *= 8; // convert size in bits
    len *= 8; // convert len in bits

    // Skip the first expressions to reach desired offset
    for (i = 0; i < data.size() and offset > 0; i++)
    {
        const Value& val = data[i];
        if (val.size() > offset)
        {
            if (val.size()-offset > len)
            {
                res.push_back(extract(val, val.size()-1-offset, val.size()-len-offset));
                len = 0;
            }
            else
            {
                res.push_back(extract(val, val.size()-1-offset, 0));
                len -= val.size()-offset;
            }
            i++;
            break;
        }
        else
            offset -= val.size();
    }

    // Read 32 bytes from next expresions in data
    for (; len > 0 and i < data.size(); i++)
    {
        const Value& val = data[i];
        if (val.size() > len)
            res.push_back(extract(val, val.size()-1, val.size()-len));
        else
            res.push_back(val);
        len -= res.back().size();
    }

    // If not enough data, pad with zeros
    for (; len > 0; len--)
        res.push_back(Value(8, 0));
    return res;
}

Contract::Contract(const MaatEngine& engine, Value addr)
: memory(engine.vars), address(addr), storage(engine.vars), code_size(0)
{}

void _set_EVM_code(MaatEngine& engine, uint8_t* code, size_t code_size)
{
    engine.mem->map(0x0, code_size);
    engine.mem->write_buffer(0x0, code, code_size);
    get_contract_for_engine(engine)->code_size = code_size;
}

void _set_EVM_code(MaatEngine& engine, const std::vector<Value>& code)
{
    addr_t code_size = 0;
    for (const auto& val : code)
        code_size += val.size()/8;
    engine.mem->map(0x0, code_size);
    engine.mem->write_buffer(0x0, code);
    get_contract_for_engine(engine)->code_size = code_size;
}


KeccakHelper::KeccakHelper()
: _symbolic_hash_prefix("keccak_hash")
{}

const std::string& KeccakHelper::symbolic_hash_prefix() const 
{
    return _symbolic_hash_prefix;
}

Value KeccakHelper::apply(VarContext& ctx, const Value& val, uint8_t* raw_bytes)
{
    // Check if the value hash already been hashed
    Value res;
    auto it = known_hashes.find(val);
    if (it != known_hashes.end())
        return it->second;
    
    if (val.is_concrete(ctx))
    {
        res = _do_keccak256(raw_bytes, val.size()/8);
    }
    else if (val.is_concolic(ctx))
    {
        Value concrete_hash = _do_keccak256(raw_bytes, val.size()/8);
        Value concrete_value = Value(val.as_number(ctx));
        res = exprvar(256, ctx.new_name_from(_symbolic_hash_prefix));
        // Also record concrete hash mapping
        known_hashes[concrete_value] = concrete_hash;
        // Set concrete hash result in varctx
        ctx.set(res.as_expr()->name(), concrete_hash.as_number());
    }
    else // purely symbolic value
    {
        res = exprvar(256, ctx.new_name_from(_symbolic_hash_prefix));
    }
    known_hashes[val] = res;
    return res;
}

Value _do_keccak256(uint8_t* in, int size)
{
    uint8_t out[32];
    sha3_return_t success = sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, (void const*)in, (unsigned int)size, (void*)out, 32);
    if (success != SHA3_RETURN_OK)
        throw env_exception("_do_keccak256(): unexpected internal error");
    // Read back hashed buffer into a big endian value
    Value res(256, 0);
    for (int i = 0; i < 32; i++)
        res = (res<<8) | (ucst_t)out[i];
    return res;
}

EthereumEmulator::EthereumEmulator(): EnvEmulator(Arch::Type::EVM, OS::NONE)
{
    _init();
}

void EthereumEmulator::_init()
{
    EnvEmulator::_init(Arch::Type::NONE, OS::NONE);
}

int EthereumEmulator::add_contract(contract_t contract)
{
    int uid = _uid_cnt++;
    const auto& exists = _contracts.find(uid);
    if (exists != _contracts.end())
        throw env_exception("Ethereum: add_contract(): uid already used !");
    _contracts[uid] = contract;
    return uid;
}

contract_t EthereumEmulator::get_contract_by_uid(int uid) const
{
    auto res = _contracts.find(uid);
    if (res == _contracts.end())
        throw env_exception("Ethereum: get_contract_by_uid(): no corresponding contract");
    return res->second;
}


serial::uid_t EthereumEmulator::class_uid() const
{
    return serial::ClassId::ENV_ETHEREUM_EMULATOR;
}

void EthereumEmulator::dump(serial::Serializer& s) const
{
    // TODO 
}

void EthereumEmulator::load(serial::Deserializer& d)
{
   // TODO
}


std::shared_ptr<EthereumEmulator> get_ethereum(MaatEngine& engine)
{
    std::shared_ptr<EthereumEmulator> res = std::dynamic_pointer_cast<EthereumEmulator>(
        engine.env
    );
    return res;
}

contract_t get_contract_for_engine(MaatEngine& engine)
{
    return get_ethereum(engine)->get_contract_by_uid(engine.process->pid);
}

std::vector<uint8_t> hex_string_to_bytes(const std::vector<char>& in)
{
    std::vector<uint8_t> res;
    for(int i = 0; i < in.size(); i+=2)
    {
        uint8_t val = std::stoul(std::string(in.data()+i, 2), nullptr, 16);
        res.push_back(val);
    }
    return res;
}

} // namespace EVM
} // namespace env
} // namespace maat