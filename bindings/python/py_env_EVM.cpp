#include "python_bindings.hpp"
#include "maat/env/env_EVM.hpp"

namespace maat {
namespace py {

// =============== Storage =================
static void EVMStorage_dealloc(PyObject* self){
    as_storage_object(self).storage = nullptr;
    free_binding_object(self);
};

static PyObject* EVMStorage_str(PyObject* self){
    std::stringstream res;
    res << *as_storage_object(self).storage;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* EVMStorage_repr(PyObject* self) {
    return EVMStorage_str(self);
}

static PyObject* Storage_used_slots(PyObject* self, PyObject* args)
{
    return PyStorageIterator(
        as_storage_object(self).storage->begin(),
        as_storage_object(self).storage->end()
    );
};

static PyMethodDef Storage_methods[] = {
    {"used_slots", (PyCFunction)Storage_used_slots, METH_VARARGS, "Iterate through all used storage slots"},
    {NULL, NULL, 0, NULL}
};

static PyType_Slot EVMStorage_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(EVMStorage_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(EVMStorage_repr)},
    {Py_tp_str, reinterpret_cast<void*>(EVMStorage_str)},
    {Py_tp_doc, const_cast<char*>("EVM Storage memory")},
    {Py_tp_methods, Storage_methods},
    {0, nullptr}
};

PyType_Spec BindingTypes::EVMStorage_spec = {
    "maat.EVMStorage", sizeof(EVMStorage_Object), 0, binding_type_flags, EVMStorage_slots
};

PyObject* PyEVMStorage_FromStorage(env::EVM::Storage* s)
{
    EVMStorage_Object* object;

    // Create object
    object = PyObject_New(EVMStorage_Object, binding_types().EVMStorage);
    if( object != nullptr ){
        object->storage = s;
    }
    return (PyObject*)object;
}


// =============== Stack =================
static void EVMStack_dealloc(PyObject* self){
    as_stack_object(self).stack = nullptr;
    free_binding_object(self);
};

static PyObject* EVMStack_str(PyObject* self){
    std::stringstream res;
    res << *as_stack_object(self).stack;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* EVMStack_repr(PyObject* self) {
    return EVMStack_str(self);
}

static PyObject* Stack_push(PyObject* self, PyObject* args)
{
    Value_Object* value;

    if (not PyArg_ParseTuple(args, "O!", binding_types().Value, &value))
        return NULL;

    as_stack_object(self).stack->push(*(value->value));

    Py_RETURN_NONE;
};

static PyMethodDef Stack_methods[] = {
    {"push", (PyCFunction)Stack_push, METH_VARARGS, "Push a 256-bits value on the stack"},
    {NULL, NULL, 0, NULL}
};

static PyType_Slot EVMStack_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(EVMStack_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(EVMStack_repr)},
    {Py_tp_str, reinterpret_cast<void*>(EVMStack_str)},
    {Py_tp_doc, const_cast<char*>("EVM Stack")},
    {Py_tp_methods, Stack_methods},
    {0, nullptr}
};

PyType_Spec BindingTypes::EVMStack_spec = {
    "maat.EVMStack", sizeof(EVMStack_Object), 0, binding_type_flags, EVMStack_slots
};

PyObject* PyEVMStack_FromStack(env::EVM::Stack* s)
{
    EVMStack_Object* object;

    // Create object
    object = PyObject_New(EVMStack_Object, binding_types().EVMStack);
    if( object != nullptr ){
        object->stack = s;
    }
    return (PyObject*)object;
}

// =============== Memory =================
static void EVMMemory_dealloc(PyObject* self){
    as_evm_memory_object(self).memory = nullptr;
    free_binding_object(self);
};

static PyObject* EVMMemory_write(PyObject* self, PyObject* args)
{
    Value_Object *value, *addr;

    if (not PyArg_ParseTuple(args, "O!O!", binding_types().Value, &addr, binding_types().Value, &value))
        return NULL;

    as_evm_memory_object(self).memory->write(
        *(addr->value),
        *(value->value)
    );

    Py_RETURN_NONE;
};

static PyObject* EVMMemory_write_buffer(PyObject* self, PyObject* args)
{
    PyObject *py_values, *addr;
    std::vector<Value> values;

    if (not PyArg_ParseTuple(args, "O!O!", binding_types().Value, &addr, &PyList_Type, &py_values))
        return NULL;

    // TODO(boyan): factorize this with other code that translates a Value list
    // from python to native
    for (int i = 0; i < PyList_Size(py_values); i++)
    {
        PyObject* val = PyList_GetItem(py_values, i);
        if (!PyObject_TypeCheck(val, binding_types().Value))
        {
            return PyErr_Format(PyExc_TypeError, "Expected a a list of 'Value'");
        }
        values.push_back(*as_value_object(val).value);
    }

    as_evm_memory_object(self).memory->write(
        *(as_value_object(addr).value),
        values
    );

    Py_RETURN_NONE;
};

static PyMethodDef EVMMemory_methods[] = {
    {"write", (PyCFunction)EVMMemory_write, METH_VARARGS, "Write in the EVM memory"},
    {"write_buffer", (PyCFunction)EVMMemory_write_buffer, METH_VARARGS, "Write a buffer in the EVM memory"},
    {NULL, NULL, 0, NULL}
};

static PyType_Slot EVMMemory_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(EVMMemory_dealloc)},
    {Py_tp_doc, const_cast<char*>("EVM Memory")},
    {Py_tp_methods, EVMMemory_methods},
    {0, nullptr}
};

PyType_Spec BindingTypes::EVMMemory_spec = {
    "maat.EVMMemory", sizeof(EVMMemory_Object), 0, binding_type_flags, EVMMemory_slots
};

PyObject* PyEVMMemory_FromMemory(env::EVM::Memory* m)
{
    EVMMemory_Object* object;

    // Create object
    object = PyObject_New(EVMMemory_Object, binding_types().EVMMemory);
    if( object != nullptr ){
        object->memory = m;
    }
    return (PyObject*)object;
}

// =============== Storage slots iterator ===================
static void StorageIterator_dealloc(PyObject* self)
{
    free_binding_object(self);
};

PyObject* StorageIterator_iter(PyObject *self)
{
  Py_INCREF(self);
  return self;
}
 
PyObject* StorageIterator_iternext(PyObject *self)
{
    StorageIterator_Object* p = (StorageIterator_Object*)self;
    if (p->current != p->end)
    {
        PyObject *res = PyTuple_Pack(
            2,
            PyValue_FromValue(p->current->first),
            PyValue_FromValue(p->current->second)
        );
        p->current++;
        return res;
    }
    else
    {
        /* Raising of standard StopIteration exception with empty value. */
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
}

static PyType_Slot StorageIterator_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(StorageIterator_dealloc)},
    {Py_tp_doc, const_cast<char*>("EVM Storage iterator")},
    {Py_tp_iter, reinterpret_cast<void*>(StorageIterator_iter)},
    {Py_tp_iternext, reinterpret_cast<void*>(StorageIterator_iternext)},
    {0, nullptr}
};

PyType_Spec BindingTypes::StorageIterator_spec = {
    "maat.StorageIterator", sizeof(StorageIterator_Object), 0, binding_type_flags, StorageIterator_slots
};

PyObject* PyStorageIterator(
    env::EVM::Storage::const_iterator begin,
    env::EVM::Storage::const_iterator end
){
    StorageIterator_Object* object;

    // Create object
    object = PyObject_New(StorageIterator_Object, binding_types().StorageIterator);
    if (object != nullptr)
    {
        object->current = begin;
        object->end = end;
    }
    return (PyObject*)object;
}


// =============== Contract =================
static void EVMContract_dealloc(PyObject* self){
    as_contract_object(self).contract = nullptr;
    Py_XDECREF(as_contract_object(self).storage); as_contract_object(self).storage = nullptr;
    Py_XDECREF(as_contract_object(self).stack); as_contract_object(self).stack = nullptr;
    Py_XDECREF(as_contract_object(self).memory); as_contract_object(self).memory = nullptr;
    free_binding_object(self);
};


static PyObject* EVMContract_get_transaction(PyObject* self, void* closure)
{
    if (not as_contract_object(self).contract->transaction.has_value())
        Py_RETURN_NONE;
    else
        return PyEVMTx_FromTx(
            &(*as_contract_object(self).contract->transaction),
            true
        );
}

static int EVMContract_set_transaction(PyObject* self, PyObject* tx, void* closure){
    if (tx == Py_None)
        as_contract_object(self).contract->transaction = std::nullopt;
    else if (PyObject_TypeCheck(tx, binding_types().EVMTransaction))
        as_contract_object(self).contract->transaction = *as_tx_object(tx).transaction;
    else{
        PyErr_SetString(PyExc_TypeError, "Expected EVM transaction");
        return 1;
    }
    return 0;
}

static PyObject* EVMContract_get_out_transaction(PyObject* self, void* closure)
{
    if (not as_contract_object(self).contract->outgoing_transaction.has_value())
        Py_RETURN_NONE;
    else
        return PyEVMTx_FromTx(
            &(*as_contract_object(self).contract->outgoing_transaction),
            true
        );
}

static int EVMContract_set_out_transaction(PyObject* self, PyObject* tx, void* closure){
    if (tx == Py_None)
        as_contract_object(self).contract->outgoing_transaction = std::nullopt;
    else if (PyObject_TypeCheck(tx, binding_types().EVMTransaction))
        as_contract_object(self).contract->outgoing_transaction = *as_tx_object(tx).transaction;
    else
    {
        PyErr_SetString(PyExc_TypeError, "Expected EVM transaction or None");
        return 1;
    }
    return 0;
}

static PyObject* EVMContract_get_result_from_last_call(PyObject* self, void* closure)
{
    if (not as_contract_object(self).contract->result_from_last_call.has_value())
        Py_RETURN_NONE;
    else
        return PyEVMTxResult_FromTxResult(
            &(*as_contract_object(self).contract->result_from_last_call)
        );
}

static int EVMContract_set_result_from_last_call(PyObject* self, PyObject* tx, void* closure){
    if (tx == Py_None)
        as_contract_object(self).contract->result_from_last_call = std::nullopt;
    else if (PyObject_TypeCheck(tx, binding_types().EVMTransactionResult))
        as_contract_object(self).contract->result_from_last_call = 
            *as_tx_result_object(tx).result;
    else
    {
        PyErr_SetString(PyExc_TypeError, "Expected EVMTransactionResult");
        return 1;
    }
    return 0;
}

static PyObject* EVMContract_get_address(PyObject* self, void* closure){
    return PyValue_FromValue(as_contract_object(self).contract->address);
}

static PyObject* EVMContract_get_balance(PyObject* self, void* closure){
    return PyValue_FromValue(as_contract_object(self).contract->balance);
}

static int EVMContract_set_balance(PyObject* self, PyObject* balance, void* closure){
    if (PyObject_TypeCheck(balance, binding_types().Value))
        as_contract_object(self).contract->balance = 
            *as_value_object(balance).value;
    else if (PyLong_Check(balance))
        as_contract_object(self).contract->balance = bigint_to_number(256, balance);
    else
    {
        PyErr_SetString(PyExc_TypeError, "Expected Value or int");
        return 1;
    }
    return 0;
}

static PyGetSetDef EVMContract_getset[] = {
    {"transaction", EVMContract_get_transaction, EVMContract_set_transaction, "Transaction being executed", NULL},
    {"outgoing_transaction", EVMContract_get_out_transaction, EVMContract_set_out_transaction, "Transaction being sent", NULL},
    {"result_from_last_call", EVMContract_get_result_from_last_call, EVMContract_set_result_from_last_call, "Result from last message call", NULL},
    {"address", EVMContract_get_address, NULL, "Address of the contract", NULL},
    {"balance", EVMContract_get_balance, EVMContract_set_balance, "Balance of the contract/account in WEI", NULL},
    {NULL}
};

static PyMemberDef EVMContract_members[] = {
    {"storage", T_OBJECT_EX, offsetof(EVMContract_Object, storage), READONLY, "Contract storage"},
    {"stack", T_OBJECT_EX, offsetof(EVMContract_Object, stack), READONLY, "Contract stack"},
    {"memory", T_OBJECT_EX, offsetof(EVMContract_Object, memory), READONLY, "Contract volatile memory"},
    {NULL}
};

static PyType_Slot EVMContract_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(EVMContract_dealloc)},
    {Py_tp_doc, const_cast<char*>("Ethereum contract")},
    {Py_tp_members, EVMContract_members},
    {Py_tp_getset, EVMContract_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::EVMContract_spec = {
    "maat.EVMContract", sizeof(EVMContract_Object), 0, binding_type_flags, EVMContract_slots
};

PyObject* PyEVMContract_FromContract(env::EVM::Contract* contract)
{
    EVMContract_Object* object;

    // Create object
    object = PyObject_New(EVMContract_Object, binding_types().EVMContract);
    if( object != nullptr ){
        object->contract = contract;
        object->storage = PyEVMStorage_FromStorage(contract->storage.get());
        object->stack = PyEVMStack_FromStack(&(contract->stack));
        object->memory = PyEVMMemory_FromMemory(&(contract->memory));
    }
    return (PyObject*)object;
}


// ================== EVM Transaction =================

static void EVMTransaction_dealloc(PyObject* self){
    if (not as_tx_object(self).is_ref)
        delete as_tx_object(self).transaction;
    as_tx_object(self).transaction = nullptr;
    free_binding_object(self);
};


static PyObject* EVMTransaction_get_result(PyObject* self, void* closure)
{
    if (not as_tx_object(self).transaction->result.has_value())
        Py_RETURN_NONE;
    else
        return PyEVMTxResult_FromTxResult(
            &(*as_tx_object(self).transaction->result)
        );
}

static PyObject* EVMTransaction_get_sender(PyObject* self, void* closure)
{
    return PyValue_FromValue(as_tx_object(self).transaction->sender);
}

static PyObject* EVMTransaction_get_recipient(PyObject* self, void* closure)
{
    return number_to_bigint(as_tx_object(self).transaction->recipient);
}

static PyObject* EVMTransaction_get_type(PyObject* self, void* closure)
{
    return PyLong_FromUnsignedLong((int)as_tx_object(self).transaction->type);
}

static PyObject* EVMTransaction_get_ret_offset(PyObject* self, void* closure)
{
    if (not as_tx_object(self).transaction->ret_offset.has_value())
        Py_RETURN_NONE;
    return PyValue_FromValue(*as_tx_object(self).transaction->ret_offset);
}

static PyObject* EVMTransaction_get_ret_len(PyObject* self, void* closure)
{
    if (not as_tx_object(self).transaction->ret_len.has_value())
        Py_RETURN_NONE;
    return PyValue_FromValue(*as_tx_object(self).transaction->ret_len);
}

static PyObject* EVMTransaction_get_value(PyObject* self, void* closure)
{
    return PyValue_FromValue(as_tx_object(self).transaction->value);
}

static PyObject* EVMTransaction_get_gas_price(PyObject* self, void* closure)
{
    return PyValue_FromValue(as_tx_object(self).transaction->gas_price);
}

static PyObject* EVMTransaction_get_data(PyObject* self, void* closure)
{
    return native_to_py(as_tx_object(self).transaction->data);
}

static int EVMTransaction_set_data(PyObject* self, PyObject* py_data, void* closure){
    std::vector<Value> data;
    // TODO(boyan): factorize this with other code that translates a Value list
    // from python to native
    if (!PyList_Check(py_data) )
    {
        PyErr_SetString(PyExc_TypeError, "'data' must be a list of 'Value'");
        return 1;
    }
    for (int i = 0; i < PyList_Size(py_data); i++)
    {
        PyObject* val = PyList_GetItem(py_data, i);
        if (!PyObject_TypeCheck(val, binding_types().Value))
        {
            PyErr_SetString(PyExc_TypeError, "'data' must be a list of 'Value'");
            return 1;
        }
        data.push_back(*as_value_object(val).value);
    }
    as_tx_object(self).transaction->data = data;
    return 0;
}

static PyObject* EVMTransaction_deepcopy(PyObject* self)
{
    auto tx = new env::EVM::Transaction(*as_tx_object(self).transaction);
    return PyEVMTx_FromTx(tx, false); // Not a ref
}

static PyMethodDef EVMTransaction_methods[] = {
    {"deepcopy", (PyCFunction)EVMTransaction_deepcopy, METH_NOARGS, "Copy the transaction"},
    {NULL, NULL, 0, NULL}
};

static PyGetSetDef EVMTransaction_getset[] = {
    {"sender", EVMTransaction_get_sender, NULL, "Sender of the transaction", NULL},
    {"result", EVMTransaction_get_result, NULL, "Result of the transaction", NULL},
    {"data", EVMTransaction_get_data, EVMTransaction_set_data, "Transaction data", NULL},
    {"recipient", EVMTransaction_get_recipient, NULL, "Transaction recipient", NULL},
    {"type", EVMTransaction_get_type, NULL, "Transaction type", NULL},
    {"ret_offset", EVMTransaction_get_ret_offset, NULL, "Return offset", NULL},
    {"ret_len", EVMTransaction_get_ret_len, NULL, "Return length", NULL},
    {"value", EVMTransaction_get_value, NULL, "Value in WEI", NULL},
    {"gas_price", EVMTransaction_get_gas_price, NULL, "Gas price", NULL},
    {NULL}
};

static PyType_Slot EVMTransaction_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(EVMTransaction_dealloc)},
    {Py_tp_doc, const_cast<char*>("Ethereum transaction")},
    {Py_tp_methods, EVMTransaction_methods},
    {Py_tp_getset, EVMTransaction_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::EVMTransaction_spec = {
    "maat.EVMTransaction", sizeof(EVMTransaction_Object), 0, binding_type_flags, EVMTransaction_slots
};

PyObject* PyEVMTx_FromTx(env::EVM::Transaction* tx, bool is_ref)
{
    EVMTransaction_Object* object;

    // Create object
    object = PyObject_New(EVMTransaction_Object, binding_types().EVMTransaction);
    if( object != nullptr ){
        object->transaction = tx;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}


PyObject* maat_Transaction(PyObject* self, PyObject* args){
    PyObject    *py_origin,
                *py_sender,
                *py_value,
                *py_recipient,
                *py_data,
                *py_gas_price,
                *py_gas_limit;
    std::vector<Value> data;

    if( !PyArg_ParseTuple(args, "O!O!O!O!OO!O!",
        binding_types().Value, &py_origin,
        binding_types().Value, &py_sender,
        &PyLong_Type, &py_recipient,
        binding_types().Value, &py_value,
        &py_data,
        binding_types().Value, &py_gas_price,
        binding_types().Value, &py_gas_limit)
    ){
        return NULL;
    }

    // Check if it's a list
    if (!PyList_Check(py_data) )
    {
        return PyErr_Format(PyExc_TypeError, "'data' parameter must be a list of 'Value'");
    }
    for (int i = 0; i < PyList_Size(py_data); i++)
    {
        PyObject* val = PyList_GetItem(py_data, i);
        if (!PyObject_TypeCheck(val, binding_types().Value))
        {
            return PyErr_Format(PyExc_TypeError, "'data' parameter must be a list of 'Value'");
        }
        data.push_back(*as_value_object(val).value);
    }

    return PyEVMTx_FromTx( 
        new env::EVM::Transaction(
            *as_value_object(py_origin).value,
            *as_value_object(py_sender).value,
            bigint_to_number(160, py_recipient),
            *as_value_object(py_value).value,
            data,
            *as_value_object(py_gas_price).value,
            *as_value_object(py_gas_limit).value
        ),
        false // not ref, this object is owned by the python object
    );
}


// ================== EVM Transaction Result =================

static void EVMTransactionResult_dealloc(PyObject* self){
    as_tx_result_object(self).result = nullptr;
    free_binding_object(self);
};


static PyObject* EVMTransactionResult_get_type(PyObject* self, void* closure)
{
    return PyLong_FromUnsignedLong(
        (int)as_tx_result_object(self).result->type()
    );
}

static PyObject* EVMTransactionResult_get_return_data(PyObject* self, void* closure)
{
    const std::vector<Value> res = as_tx_result_object(self).result->return_data();
    return native_to_py(res);
}

static PyObject* EVMTransactionResult_get_return_data_size(PyObject* self, void* closure)
{
    return PyLong_FromUnsignedLong(as_tx_result_object(self).result->return_data_size());
}

static PyGetSetDef EVMTransactionResult_getset[] = {
    {"type", EVMTransactionResult_get_type, NULL, "Reason why the transaction terminated", NULL},
    {"return_data", EVMTransactionResult_get_return_data, NULL, "Data returned by the transaction", NULL},
    {"return_data_size", EVMTransactionResult_get_return_data_size, NULL, "Size of data returned by the transaction", NULL},
    {NULL}
};

static PyType_Slot EVMTransactionResult_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(EVMTransactionResult_dealloc)},
    {Py_tp_doc, const_cast<char*>("Ethereum transaction result")},
    {Py_tp_getset, EVMTransactionResult_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::EVMTransactionResult_spec = {
    "maat.EVMTransactionResult", sizeof(EVMTransactionResult_Object), 0, binding_type_flags, EVMTransactionResult_slots
};

PyObject* PyEVMTxResult_FromTxResult(env::EVM::TransactionResult* result)
{
    EVMTransactionResult_Object* object;

    // Create object
    object = PyObject_New(EVMTransactionResult_Object, binding_types().EVMTransactionResult);
    if( object != nullptr ){
        object->result = result;
    }
    return (PyObject*)object;
}


// Helper functions
PyObject* maat_contract(PyObject* mod, PyObject* args)
{
    PyObject * engine;
    if( !PyArg_ParseTuple(args, "O!", binding_types().MaatEngine, &engine))
    {
        return NULL;
    }
    try
    {
        env::EVM::contract_t contract = env::EVM::get_contract_for_engine(*as_engine_object(engine).engine);
        if (contract == nullptr)
        {
            return PyErr_Format(PyExc_RuntimeError, "No EVM contract loaded in this engine");
        }
        return PyEVMContract_FromContract(contract.get()); // Always ref
    }
    catch(maat::env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

PyObject* maat_new_evm_runtime(PyObject* mod, PyObject* args)
{
    PyObject *new_engine, *old_engine;
    PyObject* py_share_storage_uid = nullptr;
    std::optional<int> share_storage_uid;
    if( !PyArg_ParseTuple(args, "O!O!|O", binding_types().MaatEngine, &new_engine, binding_types().MaatEngine, &old_engine, &share_storage_uid))
    {
        return NULL;
    }
    try
    {
        if (py_share_storage_uid == nullptr or py_share_storage_uid == Py_None)
            share_storage_uid = std::nullopt;
        else if (PyLong_Check(py_share_storage_uid))
            share_storage_uid = PyLong_AsLongLong(py_share_storage_uid);
        else
            return PyErr_Format(PyExc_TypeError, "share_storage_uid should be None or int");

        env::EVM::new_evm_runtime(
            *as_engine_object(new_engine).engine,
            *as_engine_object(old_engine).engine,
            share_storage_uid
        );
    }
    catch(maat::env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
    Py_RETURN_NONE;
}

PyObject* maat_set_evm_bytecode(PyObject* mod, PyObject* args)
{
    PyObject *engine, *bytecode;
    if( !PyArg_ParseTuple(args, "O!O!", binding_types().MaatEngine, &engine, &PyList_Type, &bytecode))
    {
        return NULL;
    }

    std::vector<Value> data;
    // TODO(boyan): factorize this with other code that translates a Value list
    // from python to native
    for (int i = 0; i < PyList_Size(bytecode); i++)
    {
        PyObject* val = PyList_GetItem(bytecode, i);
        if (!PyObject_TypeCheck(val, binding_types().Value))
        {
            return PyErr_Format(PyExc_TypeError, "'bytecode' must be a list of 'Value'");
        }
        data.push_back(*as_value_object(val).value);
    }

    try
    {
        env::EVM::_set_EVM_code(
            *as_engine_object(engine).engine,
            data
        );
    }
    catch(maat::env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
    Py_RETURN_NONE;
}

PyObject* maat_increment_block_number(PyObject* mod, PyObject* args)
{
    PyObject* engine;
    PyObject* inc;
    if( !PyArg_ParseTuple(args, "O!O!", binding_types().MaatEngine, &engine, binding_types().Value, &inc))
    {
        return NULL;
    }
    try
    {
        auto eth = env::EVM::get_ethereum(*as_engine_object(engine).engine);
        if (eth == nullptr)
            return PyErr_Format(PyExc_RuntimeError, "No environment for this engine");
        eth->current_block_number.increment(*as_value_object(inc).value);
        Py_RETURN_NONE;
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

PyObject* maat_increment_block_timestamp(PyObject* mod, PyObject* args)
{
    PyObject* engine;
    PyObject* inc;
    if( !PyArg_ParseTuple(args, "O!O!", binding_types().MaatEngine, &engine, binding_types().Value, &inc))
    {
        return NULL;
    }
    try
    {
        auto eth = env::EVM::get_ethereum(*as_engine_object(engine).engine);
        if (eth == nullptr)
            return PyErr_Format(PyExc_RuntimeError, "No environment for this engine");
        eth->current_block_timestamp.increment(*as_value_object(inc).value);
        Py_RETURN_NONE;
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

PyObject* maat_allow_symbolic_keccak(PyObject* mod, PyObject* args)
{
    PyObject* engine;
    int allow = 0;
    if( !PyArg_ParseTuple(args, "O!p", binding_types().MaatEngine, &engine, &allow))
        return NULL;

    try
    {
        auto eth = env::EVM::get_ethereum(*as_engine_object(engine).engine);
        if (eth == nullptr)
            return PyErr_Format(PyExc_RuntimeError, "No environment for this engine");
        eth->keccak_helper.allow_symbolic_hashes = allow;
        Py_RETURN_NONE;
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

PyObject* maat_evm_get_static_flag(PyObject* mod, PyObject* args)
{
    PyObject* engine;
    if( !PyArg_ParseTuple(args, "O!", binding_types().MaatEngine, &engine))
        return NULL;

    try
    {
        auto eth = env::EVM::get_ethereum(*as_engine_object(engine).engine);
        if (eth == nullptr)
            return PyErr_Format(PyExc_RuntimeError, "No environment for this engine");
        return PyBool_FromLong(eth->static_flag);
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

PyObject* maat_evm_set_static_flag(PyObject* mod, PyObject* args)
{
    PyObject* engine;
    int flag = 0;
    if( !PyArg_ParseTuple(args, "O!p", binding_types().MaatEngine, &engine, &flag))
        return NULL;

    try
    {
        auto eth = env::EVM::get_ethereum(*as_engine_object(engine).engine);
        if (eth == nullptr)
            return PyErr_Format(PyExc_RuntimeError, "No environment for this engine");
        eth->static_flag = flag;
        Py_RETURN_NONE;
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

PyObject* maat_evm_set_gas_price(PyObject* mod, PyObject* args)
{
    PyObject* engine;
    PyObject* price;
    if( !PyArg_ParseTuple(args, "O!O!", binding_types().MaatEngine, &engine, binding_types().Value, &price))
        return NULL;

    try
    {
        auto eth = env::EVM::get_ethereum(*as_engine_object(engine).engine);
        if (eth == nullptr)
            return PyErr_Format(PyExc_RuntimeError, "No environment for this engine");
        eth->gas_price = *as_value_object(price).value;
        Py_RETURN_NONE;
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
}

void init_evm(PyObject* module)
{
    /* TX_END enum */
    PyObject* evm_enum = PyDict_New();
    // Transaction result types
    PyDict_SetItemString(evm_enum, "RETURN", PyLong_FromLong(
        (int)env::EVM::TransactionResult::Type::RETURN)
    );
    PyDict_SetItemString(evm_enum, "REVERT", PyLong_FromLong(
        (int)env::EVM::TransactionResult::Type::REVERT)
    );
    PyDict_SetItemString(evm_enum, "STOP", PyLong_FromLong(
        (int)env::EVM::TransactionResult::Type::STOP)
    );
    PyDict_SetItemString(evm_enum, "INVALID", PyLong_FromLong(
        (int)env::EVM::TransactionResult::Type::INVALID)
    );
    PyDict_SetItemString(evm_enum, "NONE", PyLong_FromLong(
        (int)env::EVM::TransactionResult::Type::NONE)
    );

    PyObject* evm_class = create_class(PyUnicode_FromString("TX_RES"), PyTuple_New(0), evm_enum);
    PyModule_AddObject(module, "TX_RES", evm_class);


    /* TX enum */
    PyObject* tx_enum = PyDict_New();
    // Transaction result types
    PyDict_SetItemString(tx_enum, "CALL", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::CALL)
    );
    PyDict_SetItemString(tx_enum, "CALLCODE", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::CALLCODE)
    );
    PyDict_SetItemString(tx_enum, "DELEGATECALL", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::DELEGATECALL)
    );
    PyDict_SetItemString(tx_enum, "STATICCALL", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::STATICCALL)
    );
    PyDict_SetItemString(tx_enum, "EOA", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::EOA)
    );
    PyDict_SetItemString(tx_enum, "NONE", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::NONE)
    );
    PyDict_SetItemString(tx_enum, "CREATE", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::CREATE)
    );
    PyDict_SetItemString(tx_enum, "CREATE2", PyLong_FromLong(
        (int)env::EVM::Transaction::Type::CREATE2)
    );

    PyObject* tx_class = create_class(PyUnicode_FromString("TX"), PyTuple_New(0), tx_enum);
    PyModule_AddObject(module, "TX", tx_class);

};

}} // namespaces maat::py