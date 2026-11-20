#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void ProcessInfo_dealloc(PyObject* self){
    if( ! as_process_object(self).is_ref){
        delete ((ProcessInfo_Object*)self)->process;
    }
    as_process_object(self).process = nullptr;
    free_binding_object(self);
};


// Getters/Setters for the members
static PyObject* ProcessInfo_get_pid(PyObject* self, void* closure){
    return PyLong_FromLongLong((long)as_process_object(self).process->pid);
}

static PyGetSetDef ProcessInfo_getset[] = {
    {"pid", ProcessInfo_get_pid, NULL, "Process PID", NULL},
    {NULL}
};

static PyType_Slot ProcessInfo_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(ProcessInfo_dealloc)},
    {Py_tp_doc, const_cast<char*>("Process Info")},
    {Py_tp_getset, ProcessInfo_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::ProcessInfo_spec = {
    "maat.ProcessInfo", sizeof(ProcessInfo_Object), 0, binding_type_flags, ProcessInfo_slots
};

// Constructor
PyObject* PyProcessInfo_FromProcessInfo(ProcessInfo* pinfo, bool is_ref)
{
    ProcessInfo_Object* object;
    
    // Create object
    object = PyObject_New(ProcessInfo_Object, binding_types().ProcessInfo);
    if( object != nullptr ){
        object->process = pinfo;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

    
} // namespace py
} // namespace maat
