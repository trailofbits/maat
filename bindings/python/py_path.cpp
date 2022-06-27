#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void Path_dealloc(PyObject* self)
{
    if (! as_path_object(self).is_ref)
    {
        delete ((Path_Object*)self)->path;
    }
    as_path_object(self).path = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};



static PyObject* Path_get_related_constraints(PyObject* self, PyObject* args)
{
    PyObject* arg;
    std::unordered_set<Constraint> res;
    if (! PyArg_ParseTuple(args, "O", &arg)){
        return NULL;
    }

    if (PyObject_TypeCheck(arg, (PyTypeObject*)get_Value_Type()))
    {
        res = as_path_object(self).path->get_related_constraints(
            as_value_object(arg).value->as_expr()
        );
    }
    else if (PyObject_TypeCheck(arg, (PyTypeObject*)get_Constraint_Type()))
    {
        res = as_path_object(self).path->get_related_constraints(
            *as_constraint_object(arg).constr
        );
    }
    else
    {
        return PyErr_Format(PyExc_TypeError, "Parameter must be 'Value' or 'Constraint' object");
    }
    // Translate result into python objects
    return native_to_py(res);
};

static PyObject* Path_get_constraints_containing(PyObject* self, PyObject* args, PyObject* keywords)
{
    PySetObject* py_vars = nullptr;
    std::set<std::string> vars;

    // Process arguments
    if( ! PyArg_ParseTuple(args, "O!", &PySet_Type, &py_vars)){
        return NULL;
    }

    if (not py_to_c_string_set(py_vars, vars))
        return PyErr_Format(PyExc_RuntimeError, "Failed to translate set of variables to native std::set");

    return PyPathIterator_FromWrapper(
        as_path_object(self).path->get_constraints_containing(vars)
    );
};

static PyObject* Path_constraints(PyObject* self, PyObject* args)
{
    return PyPathIterator_FromWrapper(
        as_path_object(self).path->_constraints_iterator()
    );
};

static PyObject* Path_add(PyObject* self, PyObject* args)
{
    PyObject* constr;
    if (! PyArg_ParseTuple(args, "O!", get_Constraint_Type(), &constr)){
        return NULL;
    }

    as_path_object(self).path->add(*as_constraint_object(constr).constr);
    Py_RETURN_NONE;
};

static PyMethodDef Path_methods[] = {
    {"add", (PyCFunction)Path_add, METH_VARARGS, "Add a path constraint"},
    {"constraints", (PyCFunction)Path_constraints, METH_VARARGS, "Get current path constraints"},
    {"get_related_constraints", (PyCFunction)Path_get_related_constraints, METH_VARARGS, "Get all path constraints related to a constraint or expression"},
    {"get_constraints_containing", (PyCFunction)Path_get_constraints_containing, METH_VARARGS, "Get current path constraints containing at least one variable from a given set"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Path_members[] = {
    {NULL}
};

static PyTypeObject Path_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "PathManager",                            /* tp_name */
    sizeof(Path_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Path_dealloc,           /* tp_dealloc */
    0,                                       /* tp_print */
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
    "Path Manager",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Path_methods,                       /* tp_methods */
    Path_members,                       /* tp_members */
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

/* Constructors */
PyObject* PyPath_FromPath(PathManager* path, bool is_ref)
{
    Path_Object* object;
    
    // Create object
    PyType_Ready(&Path_Type);
    object = PyObject_New(Path_Object, &Path_Type);
    if (object != nullptr){
        object->path = path;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}
    
    
// =============== PathIterator ===================
static void PathIterator_dealloc(PyObject* self)
{
    delete as_pathiterator_object(self).wrapper;
    as_pathiterator_object(self).wrapper = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

PyObject* PathIterator_iter(PyObject *self)
{
  Py_INCREF(self);
  return self;
}
 
PyObject* PathIterator_iternext(PyObject *self)
{
    PathIterator_Object* p = (PathIterator_Object*)self;
    if (p->current != p->end)
    {
        PyObject *res = PyConstraint_FromConstraint(*(p->current));
        p->current++;
        return res;
    }
    else
    {
        /* Raising of standard StopIteration exception with empty value. */
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
}

static PyTypeObject PathIterator_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "PathIterator ",                            /* tp_name */
    sizeof(PathIterator_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)PathIterator_dealloc,           /* tp_dealloc */
    0,                                       /* tp_print */
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
    "Path constraints custom iterator",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    PathIterator_iter,                                        /* tp_iter */
    PathIterator_iternext,                                        /* tp_iternext */
    0,                       /* tp_methods */
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

PyObject* PyPathIterator_FromWrapper(const PathManager::IteratorWrapper& wrapper)
{
    PathIterator_Object* object;

    // Create object
    PyType_Ready(&PathIterator_Type);
    object = PyObject_New(PathIterator_Object, &PathIterator_Type);
    if (object != nullptr)
    {
        object->wrapper = new PathManager::IteratorWrapper(wrapper); // iterators point to wrapper so it needs to live as long as the iterator themselves
        object->current = object->wrapper->begin();
        object->end = object->wrapper->end();
    }
    return (PyObject*)object;
}

} // namespace py
} // namespace maat
