#include "python_bindings.hpp"
#include "maat/env/env_EVM.hpp"

namespace maat {
namespace py {

// =============== Contract =================
static void EVMContract_dealloc(PyObject* self){
    as_contract_object(self).contract = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
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
    else if (PyObject_TypeCheck(tx, (PyTypeObject*)get_EVMTransaction_Type()))
        as_contract_object(self).contract->transaction = *as_tx_object(tx).transaction;
    else{
        PyErr_SetString(PyExc_TypeError, "Expected EVM transaction");
        return 1;
    }
    return 0;
}

static PyObject* EVMContract_get_address(PyObject* self, void* closure){
    return PyValue_FromValue(as_contract_object(self).contract->address);
}


static PyGetSetDef EVMContract_getset[] = {
    {"transaction", EVMContract_get_transaction, EVMContract_set_transaction, "Transaction being executed", NULL},
    {"address", EVMContract_get_address, NULL, "Address of the contract", NULL},
    {NULL}
};

PyTypeObject EVMContract_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EVMContract",                                   /* tp_name */
    sizeof(EVMContract_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)EVMContract_dealloc,            /* tp_dealloc */
    0,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Ethereum contract",                     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    EVMContract_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* PyEVMContract_FromContract(env::EVM::Contract* contract)
{
    EVMContract_Object* object;

    // Create object
    PyType_Ready(&EVMContract_Type);
    object = PyObject_New(EVMContract_Object, &EVMContract_Type);
    if( object != nullptr ){
        object->contract = contract;
    }
    return (PyObject*)object;
}

PyObject* get_EVMContract_Type()
{
    return (PyObject*)&EVMContract_Type;
}


// ================== EMV Transaction =================

static void EVMTransaction_dealloc(PyObject* self){
    if (not as_tx_object(self).is_ref)
        delete as_tx_object(self).transaction;
    as_tx_object(self).transaction = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
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

static PyObject* EVMTransaction_get_recipient(PyObject* self, void* closure)
{
    return number_to_bigint(as_tx_object(self).transaction->recipient);
}

static PyObject* EVMTransaction_get_data(PyObject* self, void* closure)
{
    // TODO(boyan): factorize this code with other places where we translate
    // value lists to python
    PyObject* list = PyList_New(0);
    if( list == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const Value& val : as_tx_object(self).transaction->data)
    {
        if( PyList_Append(list, PyValue_FromValue(val)) == -1){
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add expression to python list");
        }
    }
    return list;
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
        if (!PyObject_TypeCheck(val, (PyTypeObject*)get_Value_Type()))
        {
            PyErr_SetString(PyExc_TypeError, "'data' must be a list of 'Value'");
            return 1;
        }
        data.push_back(*as_value_object(val).value);
    }
    as_tx_object(self).transaction->data = data;
    return 0;
}

static PyGetSetDef EVMTransaction_getset[] = {
    {"result", EVMTransaction_get_result, NULL, "Result of the transaction", NULL},
    {"data", EVMTransaction_get_data, EVMTransaction_set_data, "Transaction data", NULL},
    {"recipient", EVMTransaction_get_recipient, NULL, "Transaction recipient", NULL},
    {NULL}
};

PyTypeObject EVMTransaction_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EVMTransaction",                                   /* tp_name */
    sizeof(EVMTransaction_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)EVMTransaction_dealloc,            /* tp_dealloc */
    0,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Ethereum transaction",                     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    EVMTransaction_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* PyEVMTx_FromTx(env::EVM::Transaction* tx, bool is_ref)
{
    EVMTransaction_Object* object;

    // Create object
    PyType_Ready(&EVMTransaction_Type);
    object = PyObject_New(EVMTransaction_Object, &EVMTransaction_Type);
    if( object != nullptr ){
        object->transaction = tx;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

PyObject* get_EVMTransaction_Type()
{
    return (PyObject*)&EVMTransaction_Type;
}


PyObject* maat_Transaction(PyObject* self, PyObject* args){
    PyObject    *py_origin,
                *py_sender,
                *py_value,
                *py_recipient,
                *py_data,
                *py_gas_limit;
    std::vector<Value> data;

    if( !PyArg_ParseTuple(args, "O!O!O!O!OO!",
        get_Value_Type(), &py_origin,
        get_Value_Type(), &py_sender,
        &PyLong_Type, &py_recipient,
        get_Value_Type(), &py_value,
        &py_data,
        get_Value_Type(), &py_gas_limit)
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
        if (!PyObject_TypeCheck(val, (PyTypeObject*)get_Value_Type()))
        {
            return PyErr_Format(PyExc_TypeError, "'data' parameter must be a list of 'Value'");
        }
        data.push_back(*as_value_object(val).value);
    }

    return PyEVMTx_FromTx( 
        new env::EVM::Transaction(
            *as_value_object(py_origin).value,
            *as_value_object(py_sender).value,
            bigint_to_number(256, py_recipient),
            *as_value_object(py_value).value,
            data,
            *as_value_object(py_gas_limit).value
        ),
        false // not ref, this object is owned by the python object
    );
}


// ================== EVM Transaction Result =================

static void EVMTransactionResult_dealloc(PyObject* self){
    as_tx_result_object(self).result = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
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

static PyGetSetDef EVMTransactionResult_getset[] = {
    {"type", EVMTransactionResult_get_type, NULL, "Reason why the transaction terminated", NULL},
    {"return_data", EVMTransactionResult_get_return_data, NULL, "Data returned by the transaction", NULL},
    {NULL}
};

PyTypeObject EVMTransactionResult_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EVMTransactionResult",                                   /* tp_name */
    sizeof(EVMTransactionResult_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)EVMTransactionResult_dealloc,            /* tp_dealloc */
    0,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Ethereum transaction result",                     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    EVMTransactionResult_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* PyEVMTxResult_FromTxResult(env::EVM::TransactionResult* result)
{
    EVMTransactionResult_Object* object;

    // Create object
    PyType_Ready(&EVMTransactionResult_Type);
    object = PyObject_New(EVMTransactionResult_Object, &EVMTransactionResult_Type);
    if( object != nullptr ){
        object->result = result;
    }
    return (PyObject*)object;
}

PyObject* get_EVMTransactionResult_Type()
{
    return (PyObject*)&EVMTransactionResult_Type;
}


// Helper functions
PyObject* maat_contract(PyObject* mod, PyObject* args)
{
    PyObject * engine;
    if( !PyArg_ParseTuple(args, "O!", get_MaatEngine_Type(), &engine))
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
    if( !PyArg_ParseTuple(args, "O!O!", get_MaatEngine_Type(), &new_engine, get_MaatEngine_Type(), &old_engine))
    {
        return NULL;
    }
    try
    {
        env::EVM::new_evm_runtime(
            *as_engine_object(new_engine).engine,
            *as_engine_object(old_engine).engine
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
    if( !PyArg_ParseTuple(args, "O!O!", get_MaatEngine_Type(), &engine, get_Value_Type(), &inc))
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
    if( !PyArg_ParseTuple(args, "O!O!", get_MaatEngine_Type(), &engine, get_Value_Type(), &inc))
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

void init_evm(PyObject* module)
{
    /* EVM enum */
    PyObject* evm_enum = PyDict_New();
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

    PyObject* evm_class = create_class(PyUnicode_FromString("EVM"), PyTuple_New(0), evm_enum);
    PyModule_AddObject(module, "EVM", evm_class);
};

}} // namespaces maat::py