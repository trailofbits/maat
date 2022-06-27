#include "Python.h"
#include <vector>
#include "maat/value.hpp"
#include "python_bindings.hpp"

namespace maat{
namespace py{

PyObject* create_class(PyObject* name, PyObject* bases, PyObject* dict){
    PyObject* res = PyObject_CallFunctionObjArgs((PyObject*)&PyType_Type, name, bases, dict, NULL);
    Py_CLEAR(name);
    Py_CLEAR(bases);
    Py_CLEAR(dict);
    return res;
}

PyObject* native_to_py(const std::vector<Value>& values)
{
    PyObject* list = PyList_New(0);
    if( list == NULL )
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const Value& e : values)
    {
        if( PyList_Append(list, PyValue_FromValue(e)) == -1)
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add expression to python list");
        }
    }
    return list;
}

PyObject* native_to_py(const std::unordered_set<Constraint>& constraints)
{
    PyObject* list = PyList_New(0);
    if( list == NULL )
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const Constraint& c : constraints)
    {
        if( PyList_Append(list, PyConstraint_FromConstraint(c)) == -1)
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add constraint to python list");
        }
    }
    return list;
}

Number bigint_to_number(size_t bits, PyObject* num)
{
    if (bits <= 64)
    {
        return Number(bits, PyLong_AsLongLong(num));
    }
    else
    {
    PyObject* str = PyObject_Str(num);
    const char* s = PyUnicode_AsUTF8(str);
    return Number(bits, std::string(s), 10); // base 10
    }
}

PyObject* number_to_bigint(const Number& num)
{
    std::stringstream ss;
    ss << std::hex << num;
    return PyLong_FromString(ss.str().c_str(), NULL, 16);
}

void register_type(PyObject* module, PyTypeObject* type_obj)
{
    // TODO(boyan): We could use PyModule_AddType(module, get_Config_Type()); instead
    // of the cumbersome code below but it's not avaialble before Python 3.10 and we
    // don't want to force Python 3.10 yet
    if (PyType_Ready(type_obj) < 0)
        return;
    Py_INCREF(type_obj);
    PyModule_AddObject(module, type_obj->tp_name, (PyObject*)type_obj);
}

bool py_to_c_string_set(PySetObject* set, std::set<std::string>& res)
{
    PyObject *iterator = PyObject_GetIter((PyObject*)set);
    PyObject *item;
    bool error = false;
    while ((item = PyIter_Next(iterator))) {
        // Translate item to string
        const char* s = PyUnicode_AsUTF8(item);
        if (s == nullptr)
            error = true;
        else
            res.insert(std::string(s));
        // Release reference when done
        Py_DECREF(item);
        if (error)
            break;
    }
    Py_DECREF(iterator);
    return !error;
}

} // namespace py
} // namespace maat
