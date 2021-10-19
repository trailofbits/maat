#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void ProcessInfo_dealloc(PyObject* self){
    if( ! as_process_object(self).is_ref){
        delete ((ProcessInfo_Object*)self)->process;
    }
    as_process_object(self).process = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};


// Getters/Setters for the members
static PyObject* ProcessInfo_get_pid(PyObject* self, void* closure){
    return PyLong_FromLongLong((long)as_process_object(self).process->pid);
}

static PyGetSetDef ProcessInfo_getset[] = {
    {"pid", ProcessInfo_get_pid, NULL, "Process PID", NULL},
    {NULL}
};

/* Type description for python Expr objects */
PyTypeObject ProcessInfo_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ProcessInfo",                                   /* tp_name */
    sizeof(ProcessInfo_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)ProcessInfo_dealloc,            /* tp_dealloc */
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
    "Process Info",             /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    ProcessInfo_getset,                              /* tp_getset */
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
PyObject* PyProcessInfo_FromProcessInfo(ProcessInfo* pinfo, bool is_ref)
{
    ProcessInfo_Object* object;
    
    // Create object
    PyType_Ready(&ProcessInfo_Type);
    object = PyObject_New(ProcessInfo_Object, &ProcessInfo_Type);
    if( object != nullptr ){
        object->process = pinfo;
    }
    return (PyObject*)object;
}

    
} // namespace py
} // namespace maat
