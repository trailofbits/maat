#include "python_bindings.hpp"

namespace maat{
namespace py{

// ============== EnvEmulator =================
static void Env_dealloc(PyObject* self)
{
    delete ((Env_Object*)self)->env;  ((Env_Object*)self)->env = nullptr;
    Py_DECREF(as_env_object(self).fs);
    Py_TYPE(self)->tp_free((PyObject *)self);
};


static PyMemberDef Env_members[] = {
    {"fs", T_OBJECT_EX, offsetof(Env_Object, fs), READONLY, "Emulated symbolic file-system"},
    {NULL}
};

PyTypeObject Env_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EnvEmulator",                         /* tp_name */
    sizeof(Env_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Env_dealloc,       /* tp_dealloc */
    0,                                        /* tp_print */
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
    "Process environment emulator",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    Env_members,                              /* tp_members */
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

// Constructor
PyObject* PyEnv_FromEnvEmulator(maat::env::EnvEmulator* env, bool is_ref)
{
    Env_Object* object;

    // Create object
    PyType_Ready(&Env_Type);
    object = PyObject_New(Env_Object, &Env_Type);
    if (object != nullptr)
    {
        object->env = env;
        object->is_ref = is_ref;
        // Init member wrappers
        // TODO object->fs = PyFileSystem_FromFileSystem(&(object->env->fs), true);
    }
    return (PyObject*)object;
}

void init_env(PyObject* module)
{
    // OS enum
    PyObject* os_enum = PyDict_New();
    PyDict_SetItemString(os_enum, "LINUX", PyLong_FromLong((int)env::OS::LINUX));
    PyDict_SetItemString(os_enum, "NONE", PyLong_FromLong((int)env::OS::NONE));
    PyObject* os_class = create_class(PyUnicode_FromString("OS"), PyTuple_New(0), os_enum);
    PyModule_AddObject(module, "OS", os_class);
};

}
}
