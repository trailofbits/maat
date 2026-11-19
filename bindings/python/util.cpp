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
        cst_t res = PyLong_AsLongLong(num);
        if (PyErr_Occurred() != nullptr)
        {
            PyErr_Clear();
            res = PyLong_AsUnsignedLongLong(num);
        }
        return Number(bits, res);
    }
    else
    {
        PyObject* str = PyObject_Str(num);
        const char* s = PyUnicode_AsUTF8AndSize(str, nullptr);
        return Number(bits, std::string(s), 10); // base 10
    }
}

PyObject* number_to_bigint(const Number& num)
{
    std::stringstream ss;
    ss << std::hex << num;
    return PyLong_FromString(ss.str().c_str(), NULL, 16);
}

int ByteString::convert(PyObject* value, void* destination)
{
    auto& result = *static_cast<ByteString*>(destination);
    if (PyUnicode_Check(value))
        result.bytes.reset(PyUnicode_AsUTF8String(value));
    else if (PyBytes_Check(value))
        result.bytes.reset(Py_NewRef(value));
    else
    {
        // Require the buffer protocol here. PyBytes_FromObject alone also
        // accepts lists, which have their own symbolic-value conversion.
        PyObject* view = PyMemoryView_FromObject(value);
        if (!view)
            return 0;
        result.bytes.reset(PyBytes_FromObject(view));
        Py_DECREF(view);
    }
    return result.bytes != nullptr;
}

void free_binding_object(PyObject* self)
{
    PyTypeObject* type = Py_TYPE(self);
    PyObject_Free(self);
    Py_DECREF(type);
}

bool py_to_c_string_set(PyObject* set, std::set<std::string>& res)
{
    PyObject *iterator = PyObject_GetIter(set);
    PyObject *item;
    bool error = false;
    while ((item = PyIter_Next(iterator))) {
        // Translate item to string
        const char* s = PyUnicode_AsUTF8AndSize(item, nullptr);
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
