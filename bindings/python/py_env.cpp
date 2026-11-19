#include "python_bindings.hpp"

namespace maat{
namespace py{

// ============== EnvEmulator =================
static void Env_dealloc(PyObject* self)
{
    if (! as_env_object(self).is_ref)
        delete ((Env_Object*)self)->env;
    ((Env_Object*)self)->env = nullptr;

    Py_DECREF(as_env_object(self).fs);
    free_binding_object(self);
};


static PyMemberDef Env_members[] = {
    {"fs", T_OBJECT_EX, offsetof(Env_Object, fs), READONLY, "Emulated symbolic file-system"},
    {NULL}
};

static PyType_Slot Env_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Env_dealloc)},
    {Py_tp_doc, const_cast<char*>("Process environment emulator")},
    {Py_tp_members, Env_members},
    {0, nullptr}
};

PyType_Spec BindingTypes::Env_spec = {
    "maat.EnvEmulator", sizeof(Env_Object), 0, binding_type_flags, Env_slots
};

// Constructor
PyObject* PyEnv_FromEnvEmulator(maat::env::EnvEmulator* env, bool is_ref)
{
    Env_Object* object;

    // Create object
    object = PyObject_New(Env_Object, binding_types().Env);
    if (object != nullptr)
    {
        object->env = env;
        object->is_ref = is_ref;
        // Init member wrappers
        object->fs = PyFileSystem_FromFileSystem(&(object->env->fs), true);
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
