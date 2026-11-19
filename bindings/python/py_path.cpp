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
    free_binding_object(self);
};


static PyObject* Path_get_related_constraints(PyObject* self, PyObject* args)
{
    PyObject* arg;
    std::unordered_set<Constraint> res;
    if (! PyArg_ParseTuple(args, "O", &arg)){
        return NULL;
    }

    if (PyObject_TypeCheck(arg, binding_types().Value))
    {
        res = as_path_object(self).path->get_related_constraints(
            as_value_object(arg).value->as_expr()
        );
    }
    else if (PyObject_TypeCheck(arg, binding_types().Constraint))
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
    PyObject* py_vars = nullptr;
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
    if (! PyArg_ParseTuple(args, "O!", binding_types().Constraint, &constr)){
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

static PyType_Slot Path_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Path_dealloc)},
    {Py_tp_doc, const_cast<char*>("Path Manager")},
    {Py_tp_methods, Path_methods},
    {Py_tp_members, Path_members},
    {0, nullptr}
};

PyType_Spec BindingTypes::Path_spec = {
    "maat.PathManager", sizeof(Path_Object), 0, binding_type_flags, Path_slots
};

/* Constructors */
PyObject* PyPath_FromPath(PathManager* path, bool is_ref)
{
    Path_Object* object;
    
    // Create object
    object = PyObject_New(Path_Object, binding_types().Path);
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
    free_binding_object(self);
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

static PyType_Slot PathIterator_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(PathIterator_dealloc)},
    {Py_tp_doc, const_cast<char*>("Path constraints custom iterator")},
    {Py_tp_iter, reinterpret_cast<void*>(PathIterator_iter)},
    {Py_tp_iternext, reinterpret_cast<void*>(PathIterator_iternext)},
    {0, nullptr}
};

PyType_Spec BindingTypes::PathIterator_spec = {
    "maat.PathIterator", sizeof(PathIterator_Object), 0, binding_type_flags, PathIterator_slots
};

PyObject* PyPathIterator_FromWrapper(const PathManager::IteratorWrapper& wrapper)
{
    PathIterator_Object* object;

    // Create object
    object = PyObject_New(PathIterator_Object, binding_types().PathIterator);
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
