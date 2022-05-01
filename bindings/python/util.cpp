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

} // namespace py
} // namespace maat
