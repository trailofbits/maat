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

PyObject* PyEVMContract_FromEVMContract(env::EVM::Contract* contract)
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


static PyGetSetDef EVMTransaction_getset[] = {
    {"result", EVMTransaction_get_result, NULL, "Result of the transaction", NULL},
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
        &py_origin, get_Value_Type(),
        &py_sender, get_Value_Type(),
        &py_recipient, &PyLong_Type,
        &py_value, get_Value_Type(),
        &py_data,
        &py_gas_limit, get_Value_Type())
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



}} // namespaces maat::py