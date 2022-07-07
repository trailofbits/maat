#ifdef MAAT_HAS_SOLVER_BACKEND

#include "python_bindings.hpp"

namespace maat
{
namespace py
{


static void Solver_dealloc(PyObject* self)
{
    // This will destroy the underlying Solver object
    delete as_solver_object(self).solver;
    as_solver_object(self).solver = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* Solver_reset(PyObject* self)
{
    as_solver_object(self).solver->reset();
    Py_RETURN_NONE;
};

static PyObject* Solver_add(PyObject* self, PyObject* args)
{
    PyObject* constr;
    
    if( !PyArg_ParseTuple(args, "O!", get_Constraint_Type(), &constr)){
        return NULL;
    }
    
    as_solver_object(self).solver->add(*(as_constraint_object(constr).constr));
    Py_RETURN_NONE;
};

static PyObject* Solver_check(PyObject* self)
{
    bool res;
    res = as_solver_object(self).solver->check();

    if( res )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
};

static PyObject* Solver_get_model(PyObject* self)
{
    VarContext* res = as_solver_object(self).solver->_get_model_raw();
    if (res == nullptr)
        Py_RETURN_NONE;
    return PyVarContext_FromVarContext(res, false); // not a ref
};

static PyMethodDef Solver_methods[] = {
    {"reset", (PyCFunction)Solver_reset, METH_NOARGS, "Remove all constraints from the solver"},
    {"add", (PyCFunction)Solver_add, METH_VARARGS, "Add a constraint to the solver"},
    {"check", (PyCFunction)Solver_check, METH_NOARGS, "Check if a model exists for the current constraints"},
    {"get_model", (PyCFunction)Solver_get_model, METH_NOARGS, "If a model exists, return the model as a 'VarContext' instance"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Solver_members[] = {
    {NULL}
};

/* Get/Set for the attributes */
static PyObject* Solver_get_timeout(PyObject* self, void* closure)
{
    return PyLong_FromUnsignedLong(as_solver_object(self).solver->timeout);
}

static int Solver_set_timeout(PyObject* self, PyObject* val, void* closure)
{

    if( ! PyLong_Check(val)){
        PyErr_SetString(PyExc_RuntimeError, "Excpected a number of milliseconds (int)");
        return -1;
    }

    unsigned long timeout = PyLong_AsUnsignedLong(val);
    as_solver_object(self).solver->timeout = timeout;

    return 0;
}

static PyObject* Solver_get_did_time_out(PyObject* self, void* closure)
{
    return PyBool_FromLong(as_solver_object(self).solver->did_time_out());
}

static PyGetSetDef Solver_getset[] = 
{
    {"timeout", Solver_get_timeout, Solver_set_timeout, "Maximum time to spend to solve a constraint (in milliseconds)", NULL},
    {"did_time_out", Solver_get_did_time_out, NULL, "True if the last call to check() timed out", NULL},
    {NULL}
};

/* Type description for python Solver objects */
static PyTypeObject Solver_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Solver",                             /* tp_name */
    sizeof(Solver_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Solver_dealloc,           /* tp_dealloc */
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
    "Constraint solver",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Solver_methods,                           /* tp_methods */
    Solver_members,                           /* tp_members */
    Solver_getset,                            /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_Solver_Type(){
    return (PyObject*)&Solver_Type;
}

/* Constructors */
PyObject* PySolver_FromSolver(solver::Solver* s)
{
    Solver_Object* object;
    
    // Create object
    PyType_Ready(&Solver_Type);
    object = PyObject_New(Solver_Object, &Solver_Type);
    if( object != nullptr )
    {
        object->solver = s;
    }
    return (PyObject*)object;
}

PyObject* maat_Solver(PyObject* module)
{
    solver::Solver* res = solver::_new_solver_raw();
    return PySolver_FromSolver(res);
}

} // namespace py
} // namespace maat

#endif