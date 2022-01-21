#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void Config_dealloc(PyObject* self){
    Py_TYPE(self)->tp_free((PyObject *)self);
};


static PyObject* Config_add_explicit_sleigh_dir(PyObject* self, PyObject* args)
{
    const char* dir = nullptr;
    if (!PyArg_ParseTuple(args, "s", &dir))
    {
        return NULL;
    }
    maat::MaatConfig::instance().add_explicit_sleigh_dir(std::string(dir));
    Py_RETURN_NONE;
}

static PyObject* Config_add_explicit_sleigh_file(PyObject* self, PyObject* args)
{
    const char* filepath = nullptr;
    if (!PyArg_ParseTuple(args, "s", &filepath))
    {
        return NULL;
    }
    maat::MaatConfig::instance().add_explicit_sleigh_file(std::string(filepath));
    Py_RETURN_NONE;
}

static PyMethodDef Config_methods[] = {
    {"add_explicit_sleigh_file", (PyCFunction)Config_add_explicit_sleigh_file, METH_VARARGS | METH_CLASS, "Add an explicit path to a sleigh specification file"},
    {"add_explicit_sleigh_dir", (PyCFunction)Config_add_explicit_sleigh_dir, METH_VARARGS | METH_CLASS, "Add an explicit directory where to look for sleigh specification files"},
    {NULL, NULL, 0, NULL}
};


/* Type description for python Expr objects */
PyTypeObject Config_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "MaatConfig",                                   /* tp_name */
    sizeof(Config_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Config_dealloc,            /* tp_dealloc */
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
    "Maat global configuration",             /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Config_methods,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_Config_Type()
{
    return (PyObject*)&Config_Type;
}

// Constructor
PyObject* maat_Config()
{
    // Create object
    PyType_Ready(&Config_Type);
    Config_Object* object = PyObject_New(Config_Object, &Config_Type);
    return (PyObject*)object;
}

void init_config(PyObject* module)
{
    // TODO(boyan): We could use PyModule_AddType(module, get_Config_Type()); instead
    // of the cumbersome code below but it's not avaialble before Python 3.10 and we
    // don't want to force Python 3.10 yet
    PyObject* config_type = get_Config_Type();
    if (PyType_Ready((PyTypeObject*)config_type) < 0)
        return;
    Py_INCREF(config_type);
    PyModule_AddObject(module, "MaatConfig", config_type);
}

} // namespace py
} // namespace maat