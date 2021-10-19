#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void Settings_dealloc(PyObject* self){
    if( ! as_settings_object(self).is_ref){
        delete ((Settings_Object*)self)->settings;
    }
    as_settings_object(self).settings = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int Settings_print(PyObject* self, void * io, int s){
    std::cout << *((Settings_Object*)self)->settings << std::flush;
    return 0;
}

static PyObject* Settings_str(PyObject* self) {
    std::stringstream res;
    res << *((Settings_Object*) self)->settings;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Settings_repr(PyObject* self) {
    return Settings_str(self);
}

// Getters/Setters for the members
static PyObject* Settings_get_symptr_refine_timeout(PyObject* self, void* closure){
    return PyLong_FromLong(as_settings_object(self).settings->symptr_refine_timeout);
}

static int Settings_set_symptr_refine_timeout(PyObject* self, PyObject* val, void* closure){

    if( ! PyLong_Check(val)){
        PyErr_SetString(PyExc_RuntimeError, "Expected a number of milliseconds (int)");
        return -1;
    }

    unsigned long timeout = PyLong_AsUnsignedLong(val);
    as_settings_object(self).settings->symptr_refine_timeout = timeout;

    return 0;
}

static PyObject* Settings_get_symptr_max_range(PyObject* self, void* closure){
    return PyLong_FromLong(as_settings_object(self).settings->symptr_max_range);
}

static int Settings_set_symptr_max_range(PyObject* self, PyObject* val, void* closure){

    if( ! PyLong_Check(val)){
        PyErr_SetString(PyExc_RuntimeError, "Expected an integer");
        return -1;
    }

    unsigned long long range  = PyLong_AsUnsignedLongLong(val);
    as_settings_object(self).settings->symptr_max_range = range;

    return 0;
}

static PyObject* Settings_get_force_simplify(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->force_simplify);
}

static int Settings_set_force_simplify(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->force_simplify = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_ignore_missing_imports(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->ignore_missing_imports);
}

static int Settings_set_ignore_missing_imports(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->ignore_missing_imports = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_ignore_missing_syscalls(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->ignore_missing_syscalls);
}

static int Settings_set_ignore_missing_syscalls(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->ignore_missing_syscalls = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_record_path_constraints(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->record_path_constraints);
}

static int Settings_set_record_path_constraints(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->record_path_constraints = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_symptr_read(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->symptr_read);
}

static int Settings_set_symptr_read(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->symptr_read = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_symptr_write(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->symptr_write);
}

static int Settings_set_symptr_write(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->symptr_write = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_symptr_assume_aligned(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->symptr_assume_aligned);
}

static int Settings_set_symptr_assume_aligned(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->symptr_assume_aligned = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_symptr_limit_range(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->symptr_limit_range);
}

static int Settings_set_symptr_limit_range(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->symptr_limit_range = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_symptr_refine_range(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->symptr_refine_range);
}

static int Settings_set_symptr_refine_range(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->symptr_refine_range = (bool)PyObject_IsTrue(val);
    return 0;
}




static PyObject* Settings_get_print_insts(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->log_insts);
}

static int Settings_set_print_insts(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->log_insts = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyObject* Settings_get_print_calls(PyObject* self, void* closure){
    return PyBool_FromLong((long)as_settings_object(self).settings->log_calls);
}

static int Settings_set_print_calls(PyObject* self, PyObject* val, void* closure){
    as_settings_object(self).settings->log_calls = (bool)PyObject_IsTrue(val);
    return 0;
}

static PyGetSetDef Settings_getset[] = {
    {"symptr_refine_timeout", Settings_get_symptr_refine_timeout, Settings_set_symptr_refine_timeout, "Maximum time to spend on symbolic pointer range refinement (in milliseconds, per pointer)", NULL},
    {"symptr_max_range", Settings_get_symptr_max_range, Settings_set_symptr_max_range, "Maximum range of possible values for symbolic pointers"},
    {"force_simplify", Settings_get_force_simplify, Settings_set_force_simplify, "Systematically simplify newly created symbolic expressions"},
    {"symptr_read", Settings_get_symptr_read, Settings_set_symptr_read, "Allow reading from symbolic pointers"},
    {"symptr_write", Settings_get_symptr_write, Settings_set_symptr_write, "Allow writing to symbolic pointers"},
    {"ignore_missing_imports", Settings_get_ignore_missing_imports, Settings_set_ignore_missing_imports, "Ignore calls to functions that are neither loaded nor emulated"},
    {"ignore_missing_syscalls", Settings_get_ignore_missing_syscalls, Settings_set_ignore_missing_syscalls, "Ignore syscalls that can not be emulated"},
    {"record_path_constraints", Settings_get_record_path_constraints, Settings_set_record_path_constraints, "Record symbolic constraints associated with the current execution path"},
    {"symptr_assume_aligned", Settings_get_symptr_assume_aligned, Settings_set_symptr_assume_aligned, "Assume that symbolic pointers are aligned on the default architecture address size"},
    {"symptr_limit_range", Settings_get_symptr_limit_range, Settings_set_symptr_limit_range, "Arbitrary limit the maximal range of symbolic pointers"},
    {"symptr_refine_range", Settings_get_symptr_refine_range, Settings_set_symptr_refine_range, "Refine the range of symbolic pointers using the SMT solver"},
    {"log_insts", Settings_get_print_insts, Settings_set_print_insts, "Log every executed instruction"},
    {"log_calls", Settings_get_print_calls, Settings_set_print_calls, "Log calls to functions and system calls"},
    {NULL}
};

/* Type description for python Expr objects */
PyTypeObject Settings_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Settings",                                   /* tp_name */
    sizeof(Settings_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Settings_dealloc,            /* tp_dealloc */
    (printfunc)Settings_print,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Settings_repr,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Settings_str,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Engine settings and options",             /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    Settings_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

/* Constructors */
PyObject* PySettings_FromSettings(Settings* _settings, bool is_ref){
    Settings_Object* object;
    
    // Create object
    PyType_Ready(&Settings_Type);
    object = PyObject_New(Settings_Object, &Settings_Type);
    if( object != nullptr ){
        object->settings = _settings;
    }
    return (PyObject*)object;
}

    
} // namespace py
} // namespace maat
