#include "python_bindings.hpp"
#include <iostream>
#include <sstream>
#include <filesystem>

namespace maat{
namespace py{

// Methods
static void SimpleStateManager_dealloc(PyObject* self){
    delete ((SimpleStateManager_Object*)self)->s; 
    ((SimpleStateManager_Object*)self)->s = nullptr;
    free_binding_object(self);
};

static PyObject* SimpleStateManager_enqueue_state(PyObject* self, PyObject* args)
{
    PyObject* engine;

    if( !PyArg_ParseTuple(args, "O!", binding_types().MaatEngine, &engine))
    {
        return NULL;
    }
    
    try
    {
        as_simple_serializer_object(self).s->enqueue_state(*as_engine_object(engine).engine);
    }
    catch(const runtime_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    Py_RETURN_NONE;
}

static PyObject* SimpleStateManager_dequeue_state(PyObject* self, PyObject* args)
{
    PyObject* engine;
    
    if( !PyArg_ParseTuple(args, "O!", binding_types().MaatEngine, &engine))
    {
        return NULL;
    }

    bool res = false;
    try
    {
        res = as_simple_serializer_object(self).s->dequeue_state(
            *as_engine_object(engine).engine
        );
    }
    catch(const runtime_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    // IMPORTANT: we need to reinit the object attributes so that they point to the
    // fields of the new engine, otherwise they will continue pointing to the fields
    // of the previous engine
    _clear_MaatEngine_attributes((MaatEngine_Object*)engine); // To decref previous objects
    _init_MaatEngine_attributes((MaatEngine_Object*)engine); // To create new wrapper objects

    if (res)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyMethodDef SimpleStateManager_methods[] = {
    {"enqueue_state", (PyCFunction)SimpleStateManager_enqueue_state, METH_VARARGS, "Save current state of a MaatEngine in pending states list"},
    {"dequeue_state", (PyCFunction)SimpleStateManager_dequeue_state, METH_VARARGS, "Load next pending state into MaatEngine"},
    {NULL, NULL, 0, NULL}
};

static PyType_Slot SimpleStateManager_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(SimpleStateManager_dealloc)},
    {Py_tp_doc, const_cast<char*>("Simple engine serializer helper")},
    {Py_tp_methods, SimpleStateManager_methods},
    {0, nullptr}
};

PyType_Spec BindingTypes::SimpleStateManager_spec = {
    "maat.SimpleStateManager", sizeof(SimpleStateManager_Object), 0, binding_type_flags, SimpleStateManager_slots
};

PyObject* maat_SimpleStateManager(PyObject* self, PyObject* args)
{
    // Parse args
    SimpleStateManager_Object* object;
    std::filesystem::path dir;
    std::string base_filename;
    const char* py_dir = nullptr;
    const char* py_base_filename = nullptr;
    int delete_on_load = 1;
    
    if( !PyArg_ParseTuple(args, "s|sp", &py_dir, &py_base_filename, &delete_on_load))
    {
        return NULL;
    }

    try{
        dir = std::filesystem::path(py_dir);
    }catch(const std::filesystem::filesystem_error& e){
        return PyErr_Format(PyExc_ValueError, "Invalid 'dir' argument");
    }

    if (py_base_filename != nullptr)
        base_filename = std::string(py_base_filename);
    if (base_filename.empty())
        base_filename = std::string("maat_state");

    // Create object
    object = PyObject_New(SimpleStateManager_Object, binding_types().SimpleStateManager);
    if( object != nullptr ){
        object->s = new serial::SimpleStateManager(dir, base_filename, (bool)delete_on_load);
    }
    return (PyObject*)object;
}


}
}