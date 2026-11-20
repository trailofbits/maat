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
    free_binding_object(self);
};

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
    return native_to_py((*as_constraint_object(self).constr)->contained_vars());
}

PyObject* maat_ITE(PyObject* self, PyObject* args)
{
    Constraint_Object* cond;
    PyObject* if_true;
    PyObject* if_false;
    Value res;
    Value if_true_val;
    Value if_false_val;

    if( ! PyArg_ParseTuple(args, "O!OO", binding_types().Constraint, &cond, &if_true, &if_false)){
        return NULL;
    }
    
    // We cannot accept ITE with both if_true and if_false as constants without a size parameter    
    if( PyLong_Check(if_true) && PyLong_Check(if_false)) {
        return PyErr_Format(PyExc_ValueError, "ITE requires at least one argument be a value inorder to deduce resulting size");
    }else if( PyLong_Check(if_true) && PyObject_TypeCheck(if_false, binding_types().Value)) {
        if_false_val = *(as_value_object(if_false).value);
        if_true_val.set_cst(if_false_val.size(), PyLong_AsLongLong(if_true));
    }else if( PyLong_Check(if_false) && PyObject_TypeCheck(if_true, binding_types().Value)) {
        if_true_val = *(as_value_object(if_true).value);
        if_false_val.set_cst(if_true_val.size(), PyLong_AsLongLong(if_false));
    }else if( PyObject_TypeCheck(if_true, binding_types().Value) && PyObject_TypeCheck(if_false, binding_types().Value)) {
        // ExprITE will make sure sizes match
        if_true_val = *(as_value_object(if_true).value);
        if_false_val = *(as_value_object(if_false).value);
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching type for ITE arguments");
    }

    try
    {
        res = ITE(*(as_constraint_object(cond).constr), if_true_val.as_expr(), if_false_val.as_expr());
	    return PyValue_FromValue(res);
    }
    catch(const expression_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
}

PyObject* _generic_value_comparison(PyObject* self, PyObject* args, bool is_ule)
{
    PyObject* left;
    PyObject* right;
    Constraint res;
    Value left_val;
    Value right_val;
    
    if( ! PyArg_ParseTuple(args, "OO", &left, &right)){
        return NULL;
    }
    
    if (PyLong_Check(left) && PyLong_Check(right))
    {
        return PyErr_Format(PyExc_ValueError, "ULE requires at least one argument to be a Value instance");
    }
    else if (PyLong_Check(left) && PyObject_TypeCheck(right, binding_types().Value))
    {
        right_val = *(as_value_object(right).value);
        left_val.set_cst(right_val.size(), PyLong_AsLongLong(left));
    }
    else if( PyLong_Check(right) && PyObject_TypeCheck(left, binding_types().Value))
    {
        left_val = *(as_value_object(left).value);
        right_val.set_cst(left_val.size(), PyLong_AsLongLong(right));
    }
    else if( PyObject_TypeCheck(left, binding_types().Value) && PyObject_TypeCheck(right, binding_types().Value))
    {
        left_val = *(as_value_object(left).value);
        right_val = *(as_value_object(right).value);
    }
    else
    {
        return PyErr_Format(PyExc_TypeError, "Incorrect types for ULE arguments");
    }

    try
    {
        // Note: this pattern needs to change if we add support for more
        // function-like comparison between values (like UGE, UGT)
        res = is_ule? 
            ULE(left_val.as_expr(), right_val.as_expr()) 
            : ULT(left_val.as_expr(), right_val.as_expr());
	    return PyConstraint_FromConstraint(res);
    }
    catch(const constraint_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    catch(const expression_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
}

PyObject* maat_ULE(PyObject* self, PyObject* args)
{
    return _generic_value_comparison(self, args, true);
}

PyObject* maat_ULT(PyObject* self, PyObject* args)
{
    return _generic_value_comparison(self, args, false);
}

static PyMethodDef Constraint_methods[] = {
    {"invert", (PyCFunction)Constraint_invert, METH_NOARGS, "Returns the invert of the condition"},
    {"contained_vars", (PyCFunction)Constraint_contained_vars, METH_NOARGS, "Returns a list of involved symbolic variables"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Constraint_members[] = {
    {NULL}
};


PyObject* PyConstraint_FromConstraint(Constraint c){
    Constraint_Object* object;
    
    // Create object
    object = PyObject_New(Constraint_Object, binding_types().Constraint);
    if( object != nullptr ){
        object->constr = new Constraint();
        *object->constr = c;
    }
    return (PyObject*)object;
}

/* Number methods */
static PyObject* Constraint_nb_and(PyObject* self, PyObject *other){
    if( ! PyObject_TypeCheck(other, binding_types().Constraint)){
        return PyErr_Format(PyExc_TypeError, "Operator '&' expected a Constraint instance as second argument");
    }
    return PyConstraint_FromConstraint(*(as_constraint_object(self).constr) && *(as_constraint_object(other).constr));
}

static PyObject* Constraint_nb_or(PyObject* self, PyObject *other){
    if( ! PyObject_TypeCheck(other, binding_types().Constraint)){
        return PyErr_Format(PyExc_TypeError, "Operator '|' expected a Constraint instance as second argument");
    }
    return PyConstraint_FromConstraint(*(as_constraint_object(self).constr) || *(as_constraint_object(other).constr));
}

static PyObject* Constraint_nb_not(PyObject* self){
    return PyConstraint_FromConstraint((*as_constraint_object(self).constr)->invert());
}

static PyType_Slot Constraint_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Constraint_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(Constraint_repr)},
    {Py_nb_and, reinterpret_cast<void*>(Constraint_nb_and)},
    {Py_nb_or, reinterpret_cast<void*>(Constraint_nb_or)},
    {Py_nb_invert, reinterpret_cast<void*>(Constraint_nb_not)},
    {Py_tp_str, reinterpret_cast<void*>(Constraint_str)},
    {Py_tp_doc, const_cast<char*>("Constraint on abstract expressions")},
    {Py_tp_methods, Constraint_methods},
    {Py_tp_members, Constraint_members},
    {0, nullptr}
};

PyType_Spec BindingTypes::Constraint_spec = {
    "maat.Constraint", sizeof(Constraint_Object), 0, binding_type_flags, Constraint_slots
};

} // namespace py
} // namespace maat
