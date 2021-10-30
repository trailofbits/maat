#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void BPManager_dealloc(PyObject* self){
    if( ! as_bp_object(self).is_ref){
        delete as_bp_object(self).bp;
    }
    as_bp_object(self).bp = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int BPManager_print(PyObject* self, void * io, int s)
{
    as_bp_object(self).bp->print(std::cout, *as_bp_object(self).arch);
    return 0;
}

static PyObject* BPManager_str(PyObject* self)
{
    std::stringstream res;
    as_bp_object(self).bp->print(res, *as_bp_object(self).arch);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* BPManager_repr(PyObject* self)
{
    return BPManager_str(self);
}

static PyObject* BPManager_add(PyObject* self, PyObject*args, PyObject* keywords)
{
    int int_event;
    const char* name;
    PyObject* value1 = NULL;
    const char * reg_name = nullptr;
    unsigned long long  value1_int = 0,
                        value2 = 0;
    PyObject* callbacks = NULL;
    std::vector<bp::BPCallback> callbacks_list;

    char* keywd[] = {"", "", "", "", "callbacks", NULL};

    if( !PyArg_ParseTupleAndKeywords(args, keywords, "si|OKO", keywd, &name, &int_event, &value1, &value2, &callbacks))
    {
        return NULL;
    }

    // Check callbacks list
    if (callbacks != NULL)
    {
        // Check if it's a list
        if (not PyList_Check(callbacks))
        {
            return PyErr_Format(PyExc_TypeError, "'callbacks' parameter must be a list of callbacks");
        }
        for (int i = 0; i < PyList_Size(callbacks); i++)
        {
            PyObject* cb = PyList_GetItem(callbacks, i);
            if (not PyCallable_Check(cb))
            {
                return PyErr_Format(PyExc_TypeError, "Callback number %d is not a callable object", i);
            }
            callbacks_list.push_back(bp::BPCallback(cb));
        }
    }

    bp::Event event = (bp::Event)int_event;

    // Get value1
    if (not bp::is_simple_bp(event))
    {
        if (value1 != nullptr and PyLong_Check(value1))
        {
            value1_int = PyLong_AsUnsignedLongLong(value1);
        }
        else if (value1 != nullptr and PyUnicode_Check(value1))
        {
            reg_name = PyUnicode_AsUTF8(value1);
        }
        else
        {
            return PyErr_Format(PyExc_TypeError, "Expected 'int' or 'str' as third argument");
        }
    }

    /* Handle the case where optional parameter was not specified, then it must be equal to the 
     * first value parameter */
    if (PyTuple_Size(args) == 3)
    {
        value2 = value1_int;
    }

    try
    {
        if (is_reg_bp(event))
        {
            if (reg_name)
                as_bp_object(self).bp->add_reg_bp(
                    event,
                    callbacks_list,
                    (ir::reg_t)as_bp_object(self).arch->reg_num(std::string(reg_name)),
                    std::string(name)
                );
            else
                return PyErr_Format(PyExc_TypeError, "Expected a 'str' for register name");
        }
        else if (is_mem_bp(event))
        {
            if (not reg_name)
                as_bp_object(self).bp->add_mem_bp(
                    event,
                    callbacks_list,
                    (addr_t)value1_int,
                    (addr_t)value2,
                    std::string(name)
                );
            else
                return PyErr_Format(PyExc_TypeError, "Expected type 'int' for memory address");
        }
        else if (is_addr_bp(event))
        {
            if (not reg_name)
                as_bp_object(self).bp->add_addr_bp(callbacks_list, (addr_t)value1_int, std::string(name));
            else
                return PyErr_Format(PyExc_TypeError, "Expected type 'int' for memory address");
        }
        else if (is_simple_bp(event))
            as_bp_object(self).bp->add_bp(event, callbacks_list, std::string(name));
        else
            return PyErr_Format(PyExc_ValueError, "Unknown breakpoint event: %d", int_event);
    }
    catch(const bp_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }

    Py_RETURN_NONE;
};

static PyObject* BPManager_disable(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }
    try
    {
        as_bp_object(self).bp->disable(std::string(name));
    }
    catch (const bp_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* BPManager_remove(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }
    try
    {
        as_bp_object(self).bp->remove(std::string(name));
    }
    catch (const bp_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* BPManager_enable(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }

    try
    {
        as_bp_object(self).bp->enable(std::string(name));
    }
    catch (const bp_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* BPManager_disable_all(PyObject* self )
{
    as_bp_object(self).bp->disable_all();
    Py_RETURN_NONE;
};

static PyObject* BPManager_remove_all(PyObject* self )
{
    as_bp_object(self).bp->remove_all();
    Py_RETURN_NONE;
};

static PyMethodDef BPManager_methods[] = {
    {"add", (PyCFunction)BPManager_add, METH_VARARGS | METH_KEYWORDS, "Add a breakpoint"},
    {"disable", (PyCFunction)BPManager_disable, METH_VARARGS, "Disable a given breakpoint"},
    {"disable_all", (PyCFunction)BPManager_disable_all, METH_NOARGS, "Disable all breakpoints"},
    {"enable", (PyCFunction)BPManager_enable, METH_VARARGS, "Enable a given breakpoint"},
    {"remove", (PyCFunction)BPManager_remove, METH_VARARGS, "Remove a given breakpoint"},
    {"remove_all", (PyCFunction)BPManager_remove_all, METH_NOARGS, "Remove all breakpoints"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef BPManager_members[] = {
    {NULL}
};

/* Type description for python BreakopintManager objects */
static PyTypeObject BPManager_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "bp::BPManager",                             /* tp_name */
    sizeof(BPManager_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)BPManager_dealloc,           /* tp_dealloc */
    (printfunc)BPManager_print,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    BPManager_repr,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    BPManager_str,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Breakpoint manager",                  /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    BPManager_methods,                /* tp_methods */
    BPManager_members,                /* tp_members */
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


PyObject* PyBPManager_FromBPManagerAndArch(bp::BPManager* b, bool is_ref, Arch* arch){
    BPManager_Object* object;
    
    // Create object
    PyType_Ready(&BPManager_Type);
    object = PyObject_New(BPManager_Object, &BPManager_Type);
    if (object != nullptr)
    {
        object->bp = b;
        object->is_ref = is_ref;
        object->arch = arch;
    }
    return (PyObject*)object;
}

// Init enums
void init_breakpoint(PyObject* module)
{
    // EVENT enum
    PyObject* event_enum = PyDict_New();
    PyDict_SetItemString(event_enum, "ADDR", PyLong_FromLong((int)bp::Event::ADDR));
    PyDict_SetItemString(event_enum, "BRANCH", PyLong_FromLong((int)bp::Event::BRANCH));
    PyDict_SetItemString(event_enum, "MEM_R", PyLong_FromLong((int)bp::Event::MEM_R));
    PyDict_SetItemString(event_enum, "MEM_W", PyLong_FromLong((int)bp::Event::MEM_W));
    PyDict_SetItemString(event_enum, "MEM_RW", PyLong_FromLong((int)bp::Event::MEM_RW));
    PyDict_SetItemString(event_enum, "CBRANCH", PyLong_FromLong((int)bp::Event::CBRANCH));
    PyDict_SetItemString(event_enum, "PATH", PyLong_FromLong((int)bp::Event::PATH));
    PyDict_SetItemString(event_enum, "REG_R", PyLong_FromLong((int)bp::Event::REG_R));
    PyDict_SetItemString(event_enum, "REG_W", PyLong_FromLong((int)bp::Event::REG_W));
    PyDict_SetItemString(event_enum, "REG_RW", PyLong_FromLong((int)bp::Event::REG_RW));
    PyDict_SetItemString(event_enum, "SYMPTR_R", PyLong_FromLong((int)bp::Event::SYMPTR_R));
    PyDict_SetItemString(event_enum, "SYMPTR_W", PyLong_FromLong((int)bp::Event::SYMPTR_W));
    PyDict_SetItemString(event_enum, "SYMPTR_RW", PyLong_FromLong((int)bp::Event::SYMPTR_RW));
    PyDict_SetItemString(event_enum, "TAINTED_REG_R", PyLong_FromLong((int)bp::Event::TAINTED_REG_R));
    PyDict_SetItemString(event_enum, "TAINTED_REG_W", PyLong_FromLong((int)bp::Event::TAINTED_REG_W));
    PyDict_SetItemString(event_enum, "TAINTED_REG_RW", PyLong_FromLong((int)bp::Event::TAINTED_REG_RW));
    PyDict_SetItemString(event_enum, "TAINTED_PC", PyLong_FromLong((int)bp::Event::TAINTED_PC));
    PyDict_SetItemString(event_enum, "TAINTED_MEM_R", PyLong_FromLong((int)bp::Event::TAINTED_MEM_R));
    PyDict_SetItemString(event_enum, "TAINTED_MEM_W", PyLong_FromLong((int)bp::Event::TAINTED_MEM_W));
    PyDict_SetItemString(event_enum, "TAINTED_MEM_RW", PyLong_FromLong((int)bp::Event::TAINTED_MEM_RW));
    PyDict_SetItemString(event_enum, "TAINTED_OPERATION", PyLong_FromLong((int)bp::Event::TAINTED_OPERATION));

    PyObject* event_class = create_class(PyUnicode_FromString("EVENT"), PyTuple_New(0), event_enum);
    PyModule_AddObject(module, "EVENT", event_class);
    
    // Action enum
    PyObject* action_enum = PyDict_New();
    PyDict_SetItemString(action_enum, "CONTINUE", PyLong_FromLong((int)bp::Action::CONTINUE));
    PyDict_SetItemString(action_enum, "HALT", PyLong_FromLong((int)bp::Action::HALT));
    PyDict_SetItemString(action_enum, "ERROR", PyLong_FromLong((int)bp::Action::ERROR));

    PyObject* action_class = create_class(PyUnicode_FromString("ACTION"), PyTuple_New(0), action_enum);
    PyModule_AddObject(module, "ACTION", action_class);
}

} // namespace py
} // namespace maat
