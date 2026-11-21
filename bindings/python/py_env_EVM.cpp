#include "python_bindings.hpp"
#include <nanobind/stl/pair.h>

namespace maat::py
{
using namespace env::EVM;

// Contract transactions can be replaced while a script holds the view.
struct TransactionView
{
    std::shared_ptr<Transaction> owned;
    contract_t contract;
    std::optional<Transaction> Contract::* member = nullptr;

    Transaction& get() const
    {
        if (owned)
            return *owned;
        auto& tx = contract.get()->*member;
        if (!tx)
            throw nb::attribute_error("Transaction is no longer present");
        return *tx;
    }
};

struct StorageIterator
{
    const Storage& storage;
    // Keep a key across Python calls. Writes or a restore can invalidate a native iterator.
    std::optional<Value> next_key;
};

static std::shared_ptr<EthereumEmulator> ethereum(MaatEngine& engine)
{
    auto eth = get_ethereum(engine);
    if (!eth)
        throw std::runtime_error("No Ethereum environment for this engine");
    return eth;
}

void bind_evm(nb::module_& m)
{
    nb::class_<StorageIterator>(m, "_StorageIterator", nb::is_final(), "EVM Storage iterator")
        .def(
            "__iter__", [](StorageIterator& it) -> StorageIterator& { return it; },
            nb::rv_policy::reference)
        .def("__next__",
             [](StorageIterator& it)
             {
                 if (!it.next_key)
                     throw nb::stop_iteration();
                 auto pos = it.storage.find(*it.next_key);
                 if (pos == it.storage.end())
                     throw std::runtime_error("Storage changed during iteration");
                 std::pair<Value, Value> slot = *pos++;
                 it.next_key =
                     pos == it.storage.end() ? std::nullopt : std::optional<Value>(pos->first);
                 return slot;
             });
    nb::class_<Storage>(m, "_EVMStorage", nb::is_final(), "EVM Storage memory")
        .def(
            "used_slots",
            [](const Storage& storage)
            {
                auto first = storage.begin();
                return StorageIterator{storage, first == storage.end()
                                                    ? std::nullopt
                                                    : std::optional<Value>(first->first)};
            },
            nb::keep_alive<0, 1>(), "Iterate through all used storage slots")
        .def("__repr__", &format<Storage>)
        .def("__str__", &format<Storage>);
    nb::class_<Stack>(m, "_EVMStack", nb::is_final(), "EVM Stack")
        .def("push", &Stack::push, "Push a 256-bits value on the stack")
        .def("__repr__", &format<Stack>)
        .def("__str__", &format<Stack>);
    nb::class_<Memory>(m, "_EVMMemory", nb::is_final(), "EVM Memory")
        .def("write", nb::overload_cast<const Value&, const Value&>(&Memory::write),
             "Write in the EVM memory")
        .def(
            "write_buffer", [](Memory& mem, const Value& addr, nb::typed<nb::list, Value> values)
            { mem.write(addr, list_items(values)); }, "Write a buffer in the EVM memory");
    nb::class_<TransactionResult>(m, "_EVMTransactionResult", nb::is_final(),
                                  "Ethereum transaction result")
        .def_prop_ro(
            "type", [](TransactionResult& r) { return int(r.type()); },
            "Reason why the transaction terminated")
        .def_prop_ro("return_data", &TransactionResult::return_data,
                     "Data returned by the transaction")
        .def_prop_ro("return_data_size", &TransactionResult::return_data_size,
                     "Size of data returned by the transaction");
    nb::class_<TransactionView>(m, "EVMTransaction", nb::is_final(), "Ethereum transaction")
        .def("__init__",
             [](TransactionView* self, Value origin, Value sender, nb::int_ recipient, Value value,
                nb::typed<nb::list, Value> data, Value price, Value limit)
             {
                 new (self) TransactionView{std::make_shared<Transaction>(
                     origin, sender, bigint(160, recipient), value, list_items(data), price, limit),
                     {}};
             })
        .def_prop_ro(
            "result", [](const TransactionView& t) { return t.get().result; },
            "Result of the transaction")
        .def_prop_ro(
            "sender", [](const TransactionView& t) { return t.get().sender; },
            "Sender of the transaction")
        .def_prop_ro(
            "recipient", [](const TransactionView& t) { return integer(t.get().recipient); },
            "Transaction recipient")
        .def_prop_ro(
            "type", [](const TransactionView& t) { return int(t.get().type); }, "Transaction type")
        .def_prop_ro(
            "ret_offset", [](const TransactionView& t) { return t.get().ret_offset; },
            "Return offset")
        .def_prop_ro(
            "ret_len", [](const TransactionView& t) { return t.get().ret_len; }, "Return length")
        .def_prop_ro(
            "value", [](const TransactionView& t) { return t.get().value; }, "Value in WEI")
        .def_prop_ro(
            "gas_price", [](const TransactionView& t) { return t.get().gas_price; }, "Gas price")
        .def_prop_rw(
            "data", [](const TransactionView& t) -> const std::vector<Value>& { return t.get().data; },
            [](TransactionView& t, nb::typed<nb::list, Value> data)
            { t.get().data = list_items(data); }, "Transaction data")
        .def(
            "deepcopy", [](const TransactionView& t)
            { return TransactionView{std::make_shared<Transaction>(t.get()), {}}; },
            "Copy the transaction");
    nb::class_<Contract> contract(m, "EVMContract", nb::is_final(), "Ethereum contract");
    contract.def_ro("storage", &Contract::storage, "Contract storage")
        .def_ro("stack", &Contract::stack, "Contract stack")
        .def_ro("memory", &Contract::memory, "Contract volatile memory")
        .def_prop_ro(
            "address", [](Contract& c) { return c.address; }, "Address of the contract")
        .def_prop_rw(
            "balance", [](Contract& c) { return c.balance; },
            [](Contract& c, std::variant<Value, nb::int_> amount)
            {
                if (auto v = std::get_if<Value>(&amount))
                    c.balance = *v;
                else
                    c.balance = bigint(256, std::get<1>(amount));
            },
            "Balance of the contract/account in WEI")
        .def_prop_rw(
            "result_from_last_call", [](const Contract& c) { return c.result_from_last_call; },
            [](Contract& c, std::optional<TransactionResult> result)
            { c.result_from_last_call = std::move(result); }, "Result from last message call");
    for (auto [name, member, doc] :
         {std::make_tuple("transaction", &Contract::transaction, "Transaction being executed"),
          std::make_tuple("outgoing_transaction", &Contract::outgoing_transaction,
                          "Transaction being sent")})
    {
        contract.def_prop_rw(
            name,
            [member = member](contract_t c) -> std::optional<TransactionView>
            {
                if (!(c.get()->*member))
                    return std::nullopt;
                return TransactionView{{}, std::move(c), member};
            },
            [member = member](Contract& c, std::optional<TransactionView> tx)
            {
                if (tx)
                    c.*member = tx->get();
                else
                    (c.*member).reset();
            },
            doc);
    }
    m.def(
        "contract",
        [](MaatEngine& e)
        {
            auto contract = get_contract_for_engine(e);
            if (!contract)
                throw std::runtime_error("No EVM contract loaded in this engine");
            return contract;
        },
        "Get EVM contract associated with a MaatEngine");
    m.def(
        "new_evm_runtime", [](MaatEngine& target, const MaatEngine& source, nb::object)
        { new_evm_runtime(target, source, std::nullopt); }, nb::arg(), nb::arg(),
        nb::arg().none() = nb::none(),
        "Create new EVM contract runtime for 'new_engine' based on runtime for "
        "'old_engine'. The optional third argument is ignored.");
    m.def(
        "set_evm_bytecode",
        [](MaatEngine& e, nb::typed<nb::list, Value> code) { _set_EVM_code(e, list_items(code)); },
        "Set runtime bytecode for the contract associated to an engine");
    m.def(
        "increment_block_number",
        [](MaatEngine& e, Value v) { ethereum(e)->current_block_number.increment(v); },
        "Increment the current block number by an abstract value");
    m.def(
        "increment_block_timestamp",
        [](MaatEngine& e, Value v) { ethereum(e)->current_block_timestamp.increment(v); },
        "Increment the current block timestamp by an abstract value");
    m.def(
        "allow_symbolic_keccak", [](MaatEngine& e, nb::object allow)
        { ethereum(e)->keccak_helper.allow_symbolic_hashes = truth(allow); }, nb::arg(),
        nb::arg().none(), "Enable/disable symbolic KECCAK hashes");
    m.def(
        "evm_get_static_flag", [](MaatEngine& e) { return ethereum(e)->static_flag; },
        "Get EVM static flag");
    m.def(
        "evm_set_static_flag",
        [](MaatEngine& e, nb::object flag) { ethereum(e)->static_flag = truth(flag); }, nb::arg(),
        nb::arg().none(), "Set EVM static flag");
    m.def(
        "evm_set_gas_price", [](MaatEngine& e, Value price) { ethereum(e)->gas_price = price; },
        "Set EVM gas price");
}
} // namespace maat::py
