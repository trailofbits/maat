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
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* SimpleStateManager_enqueue_state(PyObject* self, PyObject* args)
{
    PyObject* engine;

    if( !PyArg_ParseTuple(args, "O!", get_MaatEngine_Type(), &engine))
    {
        return NULL;
    }
    
    as_simple_serializer_object(self).s->enqueue_state(*as_engine_object(engine).engine);

    Py_RETURN_NONE;
}

static PyObject* SimpleStateManager_dequeue_state(PyObject* self, PyObject* args)
{
    PyObject* engine;

    if( !PyArg_ParseTuple(args, "O!", get_MaatEngine_Type(), &engine))
    {
        return NULL;
    }

    bool res = as_simple_serializer_object(self).s->dequeue_state(
        *as_engine_object(engine).engine
    );

    if (res)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyMethodDef SimpleStateManager_methods[] = {
    {"enqueue_state", (PyCFunction)SimpleStateManager_enqueue_state, METH_VARARGS, "Save current state of a MaatEngine in pending states list"},
    {"dequeue_state", (PyCFunction)SimpleStateManager_dequeue_state, METH_NOARGS, "Load next pending state into MaatEngine"},
    {NULL, NULL, 0, NULL}
};

/* Type description for python Expr objects */
PyTypeObject SimpleStateManager_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Constraint",                                   /* tp_name */
    sizeof(SimpleStateManager_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)SimpleStateManager_dealloc,                 /* tp_dealloc */
    0,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                                /* tp_repr */
    0,                          /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Simple engine serializer helper",     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    SimpleStateManager_methods,                       /* tp_methods */
    0,                       /* tp_members */
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

PyObject* get_SimpleStateManager_Type(){
    return (PyObject*)&SimpleStateManager_Type;
};

PyObject* maat_SimpleStateManager(PyObject* self, PyObject* args)
{
    // Parse args
    SimpleStateManager_Object* object;
    std::filesystem::path dir;
    std::string base_filename;
    const char* py_dir;
    const char* py_base_filename;
    int delete_on_load = 1;
    
    if( !PyArg_ParseTuple(args, "s|sp", &dir, &base_filename, &delete_on_load))
    {
        return NULL;
    }

    try{
        dir = std::filesystem::path(py_dir);
    }catch(const std::filesystem::filesystem_error&){
        return PyErr_Format(PyExc_ValueError, "Invalid 'dir' argument");
    }

    base_filename = std::string(py_base_filename);
    if (base_filename.empty())
        base_filename = std::string("maat_state");


    // Create object
    PyType_Ready(&SimpleStateManager_Type);
    object = PyObject_New(SimpleStateManager_Object, &SimpleStateManager_Type);
    if( object != nullptr ){
        object->s = new serial::SimpleStateManager(dir, base_filename, (bool)delete_on_load);
    }
    return (PyObject*)object;
}


}
}