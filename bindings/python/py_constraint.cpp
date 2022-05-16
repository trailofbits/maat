#include "python_bindings.hpp"
#include <iostream>
#include <sstream>


namespace maat
{
namespace py
{

// Methods
static void Constraint_dealloc(PyObject* self){
    delete ((Constraint_Object*)self)->constr;  ((Constraint_Object*)self)->constr = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int Constraint_print(PyObject* self, void * io, int s){
    std::cout << *(as_constraint_object(self).constr) << std::flush;
    return 0;
}

static PyObject* Constraint_str(PyObject* self) {
    std::stringstream res;
    res << *(as_constraint_object(self).constr);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Constraint_repr(PyObject* self) {
    return Constraint_str(self);
}

static PyObject* Constraint_invert(PyObject* self) {
    return PyConstraint_FromConstraint((*(as_constraint_object(self).constr))->invert());
}

static PyObject* Constraint_contained_vars(PyObject* self) {
    std::set<std::string> res;
    res = (*(as_constraint_object(self).constr))->contained_vars();

    PyObject* list = PyList_New(0);
    if( list == NULL )
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const std::string& s : res)
    {
        PyObject* unistr = PyUnicode_FromString(s.c_str());
        if ( unistr == NULL )
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create python string from variable name");
        }
        if( PyList_Append(list, unistr) == -1)
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add string to python list");
        }
    }
    return list;
}

PyObject* maat_ITE(PyObject* self, PyObject* args)
{
    Constraint_Object* cond;
    PyObject* if_true;
    PyObject* if_false;
    if( ! PyArg_ParseTuple(args, "O!OO", get_Constraint_Type(), &cond, &if_true, &if_false)){
        return NULL;
    }

    Value res;
    Value if_true_val;
    Value if_false_val;
    
    // We cannot accept ITE with both if_true and if_false as constants without a size parameter
    
    if( PyLong_Check(if_true) && PyLong_Check(if_false)) {
        return PyErr_Format(PyExc_ValueError, "ITE requires at least one argument be a value inorder to deduce resulting size");
    }else if( PyLong_Check(if_true) && PyObject_IsInstance(if_false, get_Value_Type())) {
        if_false_val = *(as_value_object(if_false).value);
        if_true_val.set_cst(if_false_val.size(), PyLong_AsLongLong(if_true));
    }else if( PyLong_Check(if_false) && PyObject_IsInstance(if_true, get_Value_Type())) {
        if_true_val = *(as_value_object(if_true).value);
        if_false_val.set_cst(if_true_val.size(), PyLong_AsLongLong(if_false));
    }else if( PyObject_IsInstance(if_true, get_Value_Type()) && PyObject_IsInstance(if_false, get_Value_Type())) {
        // ExprITE will make sure sizes match
        if_true_val = *(as_value_object(if_true).value);
        if_false_val = *(as_value_object(if_false).value);
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching type for ITE arguments");
    }

	try{
		res = ITE(*(as_constraint_object(cond).constr), if_true_val.as_expr(), if_false_val.as_expr());
		return PyValue_FromValue(res);
	} catch(expression_exception e) {
		return PyErr_Format(PyExc_ValueError, "%s", e.what());
	}
}

static PyMethodDef Constraint_methods[] = {
    {"invert", (PyCFunction)Constraint_invert, METH_NOARGS, "Returns the invert of the condition"},
    {"contained_vars", (PyCFunction)Constraint_contained_vars, METH_NOARGS, "Returns a list of involved symbolic variables"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Constraint_members[] = {
    {NULL}
};

static PyNumberMethods Constraint_operators; // Empty PyNumberMethods, will be filled in the init_constraint() function

/* Type description for python Expr objects */
PyTypeObject Constraint_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Constraint",                                   /* tp_name */
    sizeof(Constraint_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Constraint_dealloc,                 /* tp_dealloc */
    (printfunc)Constraint_print,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Constraint_repr,                                /* tp_repr */
    &Constraint_operators,                          /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Constraint_str,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Constraint on abstract expressions",     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Constraint_methods,                       /* tp_methods */
    Constraint_members,                       /* tp_members */
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

PyObject* get_Constraint_Type(){
    return (PyObject*)&Constraint_Type;
};

PyObject* PyConstraint_FromConstraint(Constraint c){
    Constraint_Object* object;
    
    // Create object
    PyType_Ready(&Constraint_Type);
    object = PyObject_New(Constraint_Object, &Constraint_Type);
    if( object != nullptr ){
        object->constr = new Constraint();
        *object->constr = c;
    }
    return (PyObject*)object;
}

/* Number methods */
static PyObject* Constraint_nb_and(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Constraint_Type))){
        return PyErr_Format(PyExc_TypeError, "Operator '&' expected a Constraint instance as second argument");
    }
    return PyConstraint_FromConstraint(*(as_constraint_object(self).constr) && *(as_constraint_object(other).constr));
}

static PyObject* Constraint_nb_or(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Constraint_Type))){
        return PyErr_Format(PyExc_TypeError, "Operator '|' expected a Constraint instance as second argument");
    }
    return PyConstraint_FromConstraint(*(as_constraint_object(self).constr) || *(as_constraint_object(other).constr));
}

static PyObject* Constraint_nb_not(PyObject* self){
    return PyConstraint_FromConstraint((*as_constraint_object(self).constr)->invert());
}

// Init 
void init_constraint(PyObject* module)
{
    /* Add number operators to Constraint */
    Constraint_operators.nb_and = Constraint_nb_and;
    Constraint_operators.nb_or = Constraint_nb_or;
    Constraint_operators.nb_invert = Constraint_nb_not;
}

} // namespace py
} // namespace maat
