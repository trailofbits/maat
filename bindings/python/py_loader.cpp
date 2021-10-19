#include "python_bindings.hpp"

namespace maat{
namespace py{
    

static void CmdlineArg_dealloc(PyObject* self){
    delete ((CmdlineArg_Object*)self)->arg;
    as_arg_object(self).arg = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyMethodDef CmdlineArg_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyMemberDef CmdlineArg_members[] = {
    {NULL}
};

/* Type description for python CmdlineArg objects */
static PyTypeObject CmdlineArg_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "CmdlineArg",                             /* tp_name */
    sizeof(CmdlineArg_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)CmdlineArg_dealloc,           /* tp_dealloc */
    0,                                       /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Command line argument",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    CmdlineArg_methods,                       /* tp_methods */
    CmdlineArg_members,                       /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_CmdlineArg_Type(){
    return (PyObject*) &CmdlineArg_Type;
}

PyObject* PyCmdlineArg(const std::string& value, const std::string name = "")
{
    CmdlineArg_Object* object;

    // Create object
    PyType_Ready(&CmdlineArg_Type);
    object = PyObject_New(CmdlineArg_Object, &CmdlineArg_Type);
    if (object != nullptr)
    {
        if (name.empty())
            object->arg = new loader::CmdlineArg(value);
        else
            object->arg = new loader::CmdlineArg(value, name);
    }
    return (PyObject*)object;
}

PyObject* PyCmdlineSymArg(unsigned int len, const std::string& name)
{
    CmdlineArg_Object* object;

    // Create object
    PyType_Ready(&CmdlineArg_Type);
    object = PyObject_New(CmdlineArg_Object, &CmdlineArg_Type);
    if (object != nullptr)
    {
        object->arg = new loader::CmdlineArg(len, name);
    }
    return (PyObject*)object;
}


PyObject* maat_Arg(PyObject* module, PyObject* args, PyObject* keywords)
{
    char * value = NULL;
    char * name = NULL;
    int value_len;
    unsigned int arg_len;

    if( PyArg_ParseTuple(args, "s#|s", &value, &value_len, &name))
    {
        if (name == NULL)
            return PyCmdlineArg(std::string(value, value_len));
        else
            return PyCmdlineArg(std::string(value, value_len), std::string(name));
    }
    else if( PyArg_ParseTuple(args, "Ks#", &arg_len, &value, &value_len))
    {
        PyErr_Clear();
        return PyCmdlineSymArg(arg_len, std::string(value, value_len));
    }
    else
    {
        return PyErr_Format(PyExc_TypeError, "Arg(): Invalid parameter types");
    }
}

void init_loader(PyObject* module)
{
    // BIN enum
    PyObject* bin_enum = PyDict_New();
    PyDict_SetItemString(bin_enum, "ELF32", PyLong_FromLong((int)loader::Format::ELF32));
    PyDict_SetItemString(bin_enum, "ELF64", PyLong_FromLong((int)loader::Format::ELF64));
    // PyDict_SetItemString(bin_enum, "PE32", PyLong_FromLong((int)loader::Format::PE32));
    // PyDict_SetItemString(bin_enum, "PE64", PyLong_FromLong((int)loader::Format::PE64));
    PyObject* bin_class = create_class(PyUnicode_FromString("BIN"), PyTuple_New(0), bin_enum);
    PyModule_AddObject(module, "BIN", bin_class);
    
};

} // namespace py
} // namespace maat
