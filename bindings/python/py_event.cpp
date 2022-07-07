#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void EventManager_dealloc(PyObject* self){
    if( ! as_event_object(self).is_ref){
        delete as_event_object(self).manager;
    }
    as_event_object(self).manager = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int EventManager_print(PyObject* self, void * io, int s)
{
    std::cout << *(as_event_object(self).manager);
    return 0;
}

static PyObject* EventManager_str(PyObject* self)
{
    std::stringstream res;
    res << *(as_event_object(self).manager);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* EventManager_repr(PyObject* self)
{
    return EventManager_str(self);
}

static PyObject* EventManager_add(PyObject* self, PyObject*args, PyObject* keywords)
{
    int int_event, int_when;
    const char* name = "";
    const char* group = "";
    PyObject* filter = NULL;
    const char * reg_name = nullptr;
    unsigned long long  filter_min = 0,
                        filter_max = 0xffffffffffffffff;
    PyObject* callbacks = NULL;
    PyObject* callback_data = NULL;
    std::vector<event::EventCallback> callbacks_list;

    char* keywd[] = {"", "", "name", "filter", "callbacks", "data", "group", NULL};

    if( !PyArg_ParseTupleAndKeywords(
        args, keywords, "ii|s(KK)OOs", keywd, &int_event, &int_when, &name, &filter_min, &filter_max, &callbacks, &callback_data, &group))
    {
        PyErr_Clear();
        if( !PyArg_ParseTupleAndKeywords(
        args, keywords, "ii|sOOOs", keywd, &int_event, &int_when, &name, &filter, &callbacks, &callback_data, &group))
        {
            return NULL;
        }
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
            callbacks_list.push_back(event::EventCallback(cb, callback_data));
        }
    }

    event::Event event = (event::Event)int_event;
    event::When when = (event::When)int_when;
    event::AddrFilter addr_filter;
    // Get filter
    if (filter == NULL)
    {
        // If not default, then set it to specified value
        if (filter_min != 0 or filter_max != 0xffffffffffffffff)
        {
            addr_filter = event::AddrFilter(filter_min, filter_max);
        }
        // Otherwise let the default filter
    }
    else
    {
        if (not PyLong_Check(filter))
            return PyErr_Format(PyExc_TypeError, "Expected integer or integer pair for 'filter' argument");
        addr_filter = event::AddrFilter(PyLong_AsUnsignedLongLong(filter));
    }

    // Add hook
    try
    { 
        as_event_object(self).manager->add(
            event, when, callbacks_list, std::string(name), addr_filter, std::string(group)
        );
    }
    catch(const event_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }

    Py_RETURN_NONE;
};

static PyObject* EventManager_disable(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }
    try
    {
        as_event_object(self).manager->disable(std::string(name));
    }
    catch (const event_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* EventManager_disable_group(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }
    try
    {
        as_event_object(self).manager->disable_group(std::string(name));
    }
    catch (const event_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* EventManager_enable(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }

    try
    {
        as_event_object(self).manager->enable(std::string(name));
    }
    catch (const event_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* EventManager_enable_group(PyObject* self, PyObject *args)
{
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }

    try
    {
        as_event_object(self).manager->enable_group(std::string(name));
    }
    catch (const event_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* EventManager_disable_all(PyObject* self )
{
    as_event_object(self).manager->disable_all();
    Py_RETURN_NONE;
};


static PyMethodDef EventManager_methods[] = {
    {"add", (PyCFunction)EventManager_add, METH_VARARGS | METH_KEYWORDS, "Add a hook"},
    {"disable", (PyCFunction)EventManager_disable, METH_VARARGS, "Disable a given hook"},
    {"disable_group", (PyCFunction)EventManager_disable_group, METH_VARARGS, "Disable a group of hooks"},
    {"disable_all", (PyCFunction)EventManager_disable_all, METH_NOARGS, "Disable all hooks"},
    {"enable", (PyCFunction)EventManager_enable, METH_VARARGS, "Enable a given hook"},
    {"enable_group", (PyCFunction)EventManager_enable_group, METH_VARARGS, "Enable a group of hooks"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef EventManager_members[] = {
    {NULL}
};

/* Type description for python BreakopintManager objects */
static PyTypeObject EventManager_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EventManager",                             /* tp_name */
    sizeof(EventManager_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)EventManager_dealloc,           /* tp_dealloc */
    (printfunc)EventManager_print,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    EventManager_repr,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    EventManager_str,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Event hooks manager",                  /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    EventManager_methods,                /* tp_methods */
    EventManager_members,                /* tp_members */
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


PyObject* PyEventManager_FromEventManager(event::EventManager* m, bool is_ref)
{
    EventManager_Object* object;
    
    // Create object
    PyType_Ready(&EventManager_Type);
    object = PyObject_New(EventManager_Object, &EventManager_Type);
    if (object != nullptr)
    {
        object->manager = m;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

// Init enums
void init_event(PyObject* module)
{
    // EVENT enum
    PyObject* event_enum = PyDict_New();
    PyDict_SetItemString(event_enum, "EXEC", PyLong_FromLong((int)event::Event::EXEC));
    PyDict_SetItemString(event_enum, "BRANCH", PyLong_FromLong((int)event::Event::BRANCH));
    PyDict_SetItemString(event_enum, "MEM_R", PyLong_FromLong((int)event::Event::MEM_R));
    PyDict_SetItemString(event_enum, "MEM_W", PyLong_FromLong((int)event::Event::MEM_W));
    PyDict_SetItemString(event_enum, "MEM_RW", PyLong_FromLong((int)event::Event::MEM_RW));
    PyDict_SetItemString(event_enum, "PATH", PyLong_FromLong((int)event::Event::PATH));
    PyDict_SetItemString(event_enum, "REG_R", PyLong_FromLong((int)event::Event::REG_R));
    PyDict_SetItemString(event_enum, "REG_W", PyLong_FromLong((int)event::Event::REG_W));
    PyDict_SetItemString(event_enum, "REG_RW", PyLong_FromLong((int)event::Event::REG_RW));

    PyObject* event_class = create_class(PyUnicode_FromString("EVENT"), PyTuple_New(0), event_enum);
    PyModule_AddObject(module, "EVENT", event_class);
    
    // Action enum
    PyObject* action_enum = PyDict_New();
    PyDict_SetItemString(action_enum, "CONTINUE", PyLong_FromLong((int)event::Action::CONTINUE));
    PyDict_SetItemString(action_enum, "HALT", PyLong_FromLong((int)event::Action::HALT));
    PyDict_SetItemString(action_enum, "ERROR", PyLong_FromLong((int)event::Action::ERROR));

    PyObject* action_class = create_class(PyUnicode_FromString("ACTION"), PyTuple_New(0), action_enum);
    PyModule_AddObject(module, "ACTION", action_class);

    // WHEN enum
    PyObject* when_enum = PyDict_New();
    PyDict_SetItemString(when_enum, "BEFORE", PyLong_FromLong((int)event::When::BEFORE));
    PyDict_SetItemString(when_enum, "AFTER", PyLong_FromLong((int)event::When::AFTER));

    PyObject* when_class = create_class(PyUnicode_FromString("WHEN"), PyTuple_New(0), when_enum);
    PyModule_AddObject(module, "WHEN", when_class);
}

} // namespace py
} // namespace maat
