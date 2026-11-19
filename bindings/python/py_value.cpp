#include "python_bindings.hpp"
#include <climits>
#include <iostream>
#include <sstream>

namespace maat
{
namespace py
{

// ============ Value =============
// Methods
static void Value_dealloc(PyObject* self)
{
    delete as_value_object(self).value;
    as_value_object(self).value = nullptr;
    
    if (as_value_object(self).varctx)
    {
        delete as_value_object(self).varctx;
        as_value_object(self).varctx = nullptr;
    }

    free_binding_object(self);
};

static PyObject* Value_str(PyObject* self)
{
    std::stringstream res;
    res << *((Value_Object*) self)->value;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Value_repr(PyObject* self)
{
    return Value_str(self);
}

static PyObject* Value_is_concolic(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    if( !PyArg_ParseTuple(args, "|O!", binding_types().VarContext, &varctx)){
        return NULL;
    }
    if (varctx)
        return PyBool_FromLong((*(as_value_object(self).value)).is_concolic(*as_varctx_object(varctx).ctx));
    else if (as_value_object(self).varctx)
        return PyBool_FromLong((*(as_value_object(self).value)).is_concolic(**as_value_object(self).varctx));
    else
        return PyErr_Format(PyExc_RuntimeError, "Value isn't bound to a VarContext");
}

static PyObject* Value_is_concrete(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    if( !PyArg_ParseTuple(args, "|O!", binding_types().VarContext, &varctx)){
        return NULL;
    }

    if (varctx)
        return PyBool_FromLong((*(as_value_object(self).value)).is_concrete(*as_varctx_object(varctx).ctx));
    else if (as_value_object(self).varctx)
        return PyBool_FromLong((*(as_value_object(self).value)).is_concrete(**as_value_object(self).varctx));
    else
        return PyErr_Format(PyExc_RuntimeError, "Value isn't bound to a VarContext");
        
}

static PyObject* Value_is_symbolic(PyObject* self, PyObject* args){
    PyObject* varctx = nullptr;
    if( !PyArg_ParseTuple(args, "|O!", binding_types().VarContext, &varctx)){
        return NULL;
    }

    if (varctx)
        return PyBool_FromLong((*(as_value_object(self).value)).is_symbolic(*as_varctx_object(varctx).ctx));
    else if (as_value_object(self).varctx)
        return PyBool_FromLong((*(as_value_object(self).value)).is_symbolic(**as_value_object(self).varctx));
    else
        return PyErr_Format(PyExc_RuntimeError, "Value isn't bound to a VarContext");
}

static PyObject* Value_as_uint(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", binding_types().VarContext, &varctx))
    {
        return NULL;
    }

    try
    {
        if ((*(as_value_object(self).value)).size() <= 64)
        {
            ucst_t res = 0;
            if (varctx != nullptr)
                res = (*(as_value_object(self).value)).as_uint(*as_varctx_object(varctx).ctx);
            else if (as_value_object(self).varctx != nullptr)
                res = (*(as_value_object(self).value)).as_uint(**(as_value_object(self).varctx));
            else
                res = (*(as_value_object(self).value)).as_uint();
            return PyLong_FromUnsignedLongLong(res);
        }
        else
        {
            Number res;
            if (varctx != nullptr)
                res = (*(as_value_object(self).value)).as_number(*as_varctx_object(varctx).ctx);
            else if (as_value_object(self).varctx != nullptr)
                res = (*(as_value_object(self).value)).as_number(**(as_value_object(self).varctx));
            else
                res = (*(as_value_object(self).value)).as_number();
            std::stringstream ss;
            ss << std::hex << res;
            return PyLong_FromString(ss.str().c_str(), NULL, 16);
        }
    }
    catch(const expression_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Value_as_int(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", binding_types().VarContext, &varctx))
    {
        return NULL;
    }

    try
    {
        if ((*(as_value_object(self).value)).size() <= 64)
        {
            cst_t res = 0;
            if (varctx != nullptr)
                res = (*(as_value_object(self).value)).as_int(*as_varctx_object(varctx).ctx);
            else if (as_value_object(self).varctx != nullptr)
                res = (*(as_value_object(self).value)).as_int(**(as_value_object(self).varctx));
            else
                res = (*(as_value_object(self).value)).as_int();
            return PyLong_FromLongLong(res);
        }
        else
        {
            Number res;
            if (varctx != nullptr)
                res = (*(as_value_object(self).value)).as_number(*as_varctx_object(varctx).ctx);
            else if (as_value_object(self).varctx != nullptr)
                res = (*(as_value_object(self).value)).as_number(**(as_value_object(self).varctx));
            else
                res = (*(as_value_object(self).value)).as_number();
            std::stringstream ss;
            ss << std::hex << res;
            return PyLong_FromString(ss.str().c_str(), NULL, 16);
        }
    }
    catch(const expression_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Value_as_float(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", binding_types().VarContext, &varctx)){
        return NULL;
    }

    try
    {
        if ((*(as_value_object(self).value)).size() <= 64)
        {
            fcst_t res = 0;
            if (varctx != nullptr)
                res = (*(as_value_object(self).value)).as_float(*as_varctx_object(varctx).ctx);
            else if (as_value_object(self).varctx != nullptr)
                res = (*(as_value_object(self).value)).as_float(**(as_value_object(self).varctx));
            else
                res = (*(as_value_object(self).value)).as_float();
            return PyLong_FromUnsignedLongLong(res);
        }
        else
        {
            return PyErr_Format(PyExc_RuntimeError, "as_float() not supported for expressions bigger than 64 bits");
        }
    }
    catch(const expression_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Value_eq(PyObject* self, PyObject* args)
{
    PyObject* other = nullptr;
    if( !PyArg_ParseTuple(args, "O!", binding_types().Value, &other)){
        return NULL;
    }
    return PyBool_FromLong(
        as_value_object(self).value->eq(*as_value_object(other).value)
    );
}

static PyObject* Value_get_size(PyObject* self, void* closure)
{
    return PyLong_FromLong((*as_value_object(self).value).size());
}

static PyObject* Value_get_name(PyObject* self, void* closure)
{
    const Value& val = *as_value_object(self).value;
    if( val.is_abstract() and val.expr()->is_type(ExprType::VAR)) 
    {
        return PyUnicode_FromString(val.expr()->name().c_str());
    }
    else
    {
        return PyErr_Format(
            PyExc_AttributeError,
            "Trying to get 'name' attribute but value is not a symbolic variable"
        );
    }
}

static PyMethodDef Value_methods[] = 
{
    {"is_concolic", (PyCFunction)Value_is_concolic, METH_VARARGS, "Check whether the value is concolic"},
    {"is_concrete", (PyCFunction)Value_is_concrete, METH_VARARGS, "Check whether the value is concrete"},
    {"is_symbolic", (PyCFunction)Value_is_symbolic, METH_VARARGS, "Check whether the value is symbolic"},
    {"as_int", (PyCFunction)Value_as_int, METH_VARARGS, "Concretize the value interpreted as a signed value"},
    {"as_uint", (PyCFunction)Value_as_uint, METH_VARARGS, "Concretize the value interpreted as an unsigned value"},
    {"as_float", (PyCFunction)Value_as_float, METH_VARARGS, "Concretize the value interpreted as a floating point value"},
    {"eq", (PyCFunction)Value_eq, METH_VARARGS, "Return True if two values are identical (same abstract syntax tree)"},
    {NULL, NULL, 0, NULL}
};

static PyGetSetDef Value_getset[] =
{
    {"size", Value_get_size, NULL, "Value size in bits", NULL},
    {"name", Value_get_name, NULL, "Variable name (throws AttributeError if the value is not a symbolic variable)", NULL},
    {NULL}
};

// Compare functions
static PyObject* Value_richcompare(PyObject* self, PyObject* other, int op)
{
    Constraint res;
    Value e1, e2;
    e1 = *as_value_object(self).value;

    if( PyLong_Check(other)){
        e2 = exprcst(e1.size(), PyLong_AsUnsignedLongLong(other));
    }else if( PyObject_TypeCheck(other, binding_types().Value)){
        e2 = *as_value_object(other).value;
    }else{
        return PyErr_Format(PyExc_TypeError, "Expected 'Value' or 'int' as second argument");
    }

    try{
        switch(op){
            case Py_LT: res = e1 < e2; break;
            case Py_LE: res = e1 <= e2; break;
            case Py_EQ: res = e1 == e2; break;
            case Py_NE: res = e1 != e2; break;
            case Py_GT: res = e1 > e2; break;
            case Py_GE: res = e1 >= e2; break;
            default: return Py_NotImplemented;
        }
        return PyConstraint_FromConstraint(res);
    }catch(constraint_exception e){
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
}

// Hash
Py_hash_t Value_hash(PyObject* self)
{
    return as_value_object(self).value->as_expr()->hash();
}


#define CATCH_EXPRESSION_EXCEPTION(x) try{x}catch(expression_exception e){ \
    return PyErr_Format(PyExc_ValueError, "%s", e.what()); \
}

/* Number methods & Various Constructors */
static PyObject* Value_nb_add(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) + *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) + *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(other) + *(as_value_object(self).value)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '+'");
    }
}

static PyObject* Value_nb_sub(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) - *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) - *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) - PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '-'");
    }
}

static PyObject* Value_nb_mul(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) * *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) * (*(as_value_object(other).value))); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) * PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '*'");
    }
}

static PyObject* Value_nb_div(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) / *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) / *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) / PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '/'");
    }
}

static PyObject* Value_nb_and(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) & *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) & *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) & PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '&'");
    }
}

static PyObject* Value_nb_or(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) | *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) | *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) | PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '|'");
    }
}

static PyObject* Value_nb_xor(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) ^ *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) ^ *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) ^ PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '^'");
    }
}

static PyObject* Value_nb_rem(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) % *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) % *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) % PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '%'");
    }
}

static PyObject* Value_nb_lshift(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) << *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) << *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) << PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '<<'");
    }
}

static PyObject* Value_nb_rshift(PyObject* self, PyObject *other){
    if( PyObject_TypeCheck(other, binding_types().Value) &&
            PyObject_TypeCheck(self, binding_types().Value)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) >> *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(other, binding_types().Value) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(PyLong_AsLongLong(self) >> *(as_value_object(other).value)); )
    }else if( PyObject_TypeCheck(self, binding_types().Value) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyValue_FromValue(*(as_value_object(self).value) >> PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '>>'");
    }
}

static PyObject* Value_nb_neg(PyObject* self)
{
    CATCH_EXPRESSION_EXCEPTION ( return PyValue_FromValue(- *(as_value_object(self).value)); )
}

static PyObject* Value_nb_not(PyObject* self)
{
    CATCH_EXPRESSION_EXCEPTION ( return PyValue_FromValue(~ *(as_value_object(self).value)); )
}

PyObject* maat_Cst(PyObject* self, PyObject* args, PyObject* keywords)
{
    PyObject* val = nullptr;
    int base = 16;
    Py_ssize_t size = 0;

    static char* kwlist[] = {"size", "value", "base", NULL};
    // Parse arguments
    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "iO|i", kwlist, &size, &val, &base))
    {
        return NULL;
    }

    if (PyUnicode_Check(val))
    {
        Py_ssize_t len = 0;
        const char* str = PyUnicode_AsUTF8AndSize(val, &len);
        if (str == nullptr)
            return PyErr_Format(PyExc_ValueError, "Constant value string is invalid");
        CATCH_EXPRESSION_EXCEPTION( 
            return (PyObject*)PyValue_FromValue(exprcst(size, std::string(str, (int)len), base)); 
        )
    }
    else if (PyLong_Check(val))
    {
        CATCH_EXPRESSION_EXCEPTION(
            return (PyObject*)PyValue_FromValue(bigint_to_number(size, val));
        )
    }
    else
    {
        return PyErr_Format(PyExc_TypeError, "'value' must be an integer or a string");
    }
}

PyObject* maat_Var(PyObject* self, PyObject* args, PyObject* keywords)
{
    const char * name;
    Py_ssize_t name_length;
    int size = 0;
    static char* kwlist[] = {"size", "name", NULL};
    
    // Parse arguments
    if( !PyArg_ParseTupleAndKeywords(args, keywords, "is#|p", kwlist, &size, &name, &name_length)){
        return NULL;
    }
    
    if (name_length > 255)
    {
        return PyErr_Format(PyExc_TypeError, "Var: name cannot be longer than 255 characters");
    }
    
    CATCH_EXPRESSION_EXCEPTION( return PyValue_FromValue(exprvar(size, name)); )
}

PyObject* maat_Concat(PyObject* self, PyObject* args)
{
    Value_Object* upper, *lower;
    if( ! PyArg_ParseTuple(args, "O!O!", binding_types().Value, &upper, binding_types().Value, &lower)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyValue_FromValue( concat(*(as_value_object(upper).value), *(as_value_object(lower).value))); )
}

PyObject* maat_Extract(PyObject* self, PyObject* args)
{
    Value_Object* val;
    long lower, higher;
    if( ! PyArg_ParseTuple(args, "O!ll", binding_types().Value, &val, &higher, &lower)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyValue_FromValue( extract(*(as_value_object(val).value), higher, lower)); )
}


PyObject* maat_Zext(PyObject* self, PyObject* args)
{
    Value_Object* val;
    long new_size;
    if( ! PyArg_ParseTuple(args, "lO!", &new_size, binding_types().Value, &val)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyValue_FromValue( zext(new_size, *(as_value_object(val).value)));)
}

PyObject* maat_Sext(PyObject* self, PyObject* args)
{
    Value_Object* val;
    long new_size;
    if( ! PyArg_ParseTuple(args, "lO!", &new_size, binding_types().Value, &val)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyValue_FromValue( sext(new_size, *(as_value_object(val).value)));)
}

// TODO SAR, ...

PyObject* PyValue_FromValue(const Value& e)
{
    Value_Object* object;
    
    // Create object
    object = PyObject_New(Value_Object, binding_types().Value);
    if( object != nullptr )
    {
        object->value = new Value();
        *object->value = e;
        object->varctx = nullptr;
    }
    return (PyObject*)object;
}

PyObject* PyValue_FromValueAndVarContext(const Value& e, std::shared_ptr<VarContext> ctx)
{
    Value_Object* object;

    // Create object
    object = PyObject_New(Value_Object, binding_types().Value);
    if( object != nullptr )
    {
        // This code is ugly but smh necessary to avoid random segfaults
        object->value = new Value();
        *object->value = e;
        object->varctx = new std::shared_ptr<VarContext>();
        *object->varctx = ctx;
    }
    return (PyObject*)object;
}

// ============== VarContext ================
static void VarContext_dealloc(PyObject* self)
{
    if( ! as_varctx_object(self).is_ref){
        delete ((VarContext_Object*)self)->ctx;
    }
    as_varctx_object(self).ctx = nullptr;
    free_binding_object(self);
};

static PyObject* VarContext_str(PyObject* self) 
{
    std::stringstream res;
    res << *((VarContext_Object*) self)->ctx;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* VarContext_repr(PyObject* self)
{
    return VarContext_str(self);
}

static PyObject* VarContext_set(PyObject* self, PyObject* args)
{
    const char * name;
    PyObject* value;
    int bits = 64;

    if( !PyArg_ParseTuple(args, "sO!|i", &name, &PyLong_Type, &value, &bits)){
        return NULL;
    }

    Number number = bigint_to_number(bits, value);
    as_varctx_object(self).ctx->set(std::string(name), number);
    Py_RETURN_NONE;
}

static PyObject* VarContext_get(PyObject* self, PyObject* args)
{
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    std::string sname(name);

    if( !as_varctx_object(self).ctx->contains(sname)){
        return PyErr_Format(PyExc_KeyError, "Variable %s unknown in this context", name);
    }
    try
    {
        const Number& res =  as_varctx_object(self).ctx->get_as_number(sname);
        std::stringstream ss;
        ss << std::hex << res;
        return PyLong_FromString(ss.str().c_str(), NULL, 16);
    }
    catch(const var_context_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, e.what());
    }
}

static PyObject* VarContext_get_as_buffer(PyObject* self, PyObject* args)
{
    const char * name;
    std::vector<uint8_t> buffer;
    char str[4096];
    unsigned int elem_size = 1;
    PyObject* res;
    
    if( !PyArg_ParseTuple(args, "s|I", &name, &elem_size)){
        return NULL;
    }
    
    buffer = as_varctx_object(self).ctx->get_as_buffer(std::string(name), elem_size);
    if( buffer.size() > sizeof(str) ){
        return PyErr_Format(PyExc_RuntimeError, "Buffer is too big!");
    }else{
        for( int i = 0; i < buffer.size(); i++ ){
            str[i] = (char)buffer[i];
        }
    }
    
    res = PyBytes_FromStringAndSize(str, buffer.size());
    if( res == nullptr ){
        return PyErr_Format(PyExc_RuntimeError, "Internal error: couldn't build bytes from string!");
    }

    return res;
}

static PyObject* VarContext_get_as_string(PyObject* self, PyObject* args)
{
    const char * name;
    std::string s;
    PyObject* res;

    if( !PyArg_ParseTuple(args, "s", &name))
    {
        return NULL;
    }

    try
    {
        s = as_varctx_object(self).ctx->get_as_string(std::string(name));
    }
    catch(std::exception& e)
    {
        return PyErr_Format(PyExc_ValueError, e.what());
    }

    res = PyBytes_FromString(s.c_str());
    if (res == nullptr)
    {
        return NULL;
    }

    return res;
}

static PyObject* VarContext_new_concolic_buffer(PyObject* self, PyObject* args, PyObject* keywords)
{
    const char * name;
    std::vector<cst_t> concrete_buffer;
    PyObject* py_concrete_buffer;
    const char* bytes;
    Py_ssize_t bytes_len=0;
    int nb_elems = -1, elem_size =1;
    PyObject* trailing_value = NULL;
    std::optional<cst_t> tval = std::nullopt;

    static char* kwlist[] = {"", "", "nb_elems", "elem_size", "trailing_value", NULL};

    if (PyArg_ParseTupleAndKeywords(args, keywords, "ss#|iiO!", kwlist, &name, &bytes,
        &bytes_len, &nb_elems, &elem_size, &PyLong_Type, &trailing_value))
    {
        PyErr_Clear();

        if (elem_size <= 0)
            return PyErr_Format(PyExc_ValueError, "Element size must be positive");
        if (nb_elems == -1)
        {
            if (bytes_len % elem_size != 0)
                return PyErr_Format(PyExc_ValueError, "Buffer size must be a multiple of the element size");
            if (bytes_len / elem_size > INT_MAX)
                return PyErr_Format(PyExc_OverflowError, "Buffer contains too many elements");
            nb_elems = static_cast<int>(bytes_len / elem_size);
        }
        if (nb_elems < 0 || nb_elems > bytes_len / elem_size)
            return PyErr_Format(PyExc_ValueError, "Buffer contains fewer elements than requested");

        // NOTE: this assumes little endian!! (inverting the bytes to build the values)
        for (int i = 0; i < nb_elems; i += 1)
        {
            cst_t val = 0;
            for (int j = elem_size-1; j >= 0; j--)
            {
                if (as_varctx_object(self).ctx->endianness() == Endian::LITTLE)
                    val = (val << 8) | ((cst_t)(bytes[static_cast<Py_ssize_t>(i)*elem_size+j]) & 0xff);
                else
                    val |= ((ucst_t)(bytes[static_cast<Py_ssize_t>(i)*elem_size+j]) << j);
            }
            concrete_buffer.push_back(val);
        }
    }
    else if( PyArg_ParseTupleAndKeywords(args, keywords, "sO!|iiO!", kwlist, &name, &PyList_Type, 
        &py_concrete_buffer , &nb_elems, &elem_size, &PyLong_Type, &trailing_value))
    {
        PyErr_Clear();
        size_t list_len = PyList_Size(py_concrete_buffer);
        // Buffer = list of concrete vals
        if (nb_elems == -1)
        {
            nb_elems = PyList_Size(py_concrete_buffer);
        }
        else if (nb_elems > list_len)
        {
            return PyErr_Format(PyExc_TypeError, "Buffer length (%d) exceeds 'nb_elems' (%d)", list_len, nb_elems);
        }

        for (int i = 0; i < list_len and i < nb_elems; i++)
        {
            PyObject* val = PyList_GetItem(py_concrete_buffer, i);
            if (not PyLong_Check(val))
            {
                return PyErr_Format(PyExc_TypeError, "Buffer element %d is not an integer", i);
            }
            concrete_buffer.push_back(PyLong_AsLongLong(val));
        }
    }
    else
    {
        return PyErr_Format(PyExc_TypeError, "Wrong argument types");
    }

    std::vector<Value> res;
    if (trailing_value != NULL)
        tval = PyLong_AsLongLong(trailing_value);
    try
    {
        res = as_varctx_object(self).ctx->new_concolic_buffer(
            std::string(name),
            concrete_buffer,
            nb_elems,
            elem_size,
            tval
        );
    }
    catch(const var_context_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, e.what());
    }
    
    // Build result back to python
    return native_to_py(res);
}

static PyObject* VarContext_new_symbolic_buffer(PyObject* self, PyObject* args, PyObject* keywords)
{
    const char * name;
    int nb_elems, elem_size =1;
    PyObject* trailing_value=NULL;
    std::optional<cst_t> tval = std::nullopt;

    static char* kwlist[] = {"", "nb_elems", "elem_size", "trailing_value", NULL};

    if( !PyArg_ParseTupleAndKeywords(args, keywords, "si|iO!", kwlist, &name, 
        &nb_elems, &elem_size, &PyLong_Type, &trailing_value))
    {
        return NULL;
    }

    if (trailing_value != NULL)
        tval = PyLong_AsLongLong(trailing_value);

    std::vector<Value> res;
    try
    {
        res = as_varctx_object(self).ctx->new_symbolic_buffer(
            std::string(name),
            nb_elems,
            elem_size,
            tval
        );
    }
    catch(const var_context_exception& e)
    {
        return PyErr_Format(PyExc_ValueError, e.what());
    }

    return native_to_py(res);
}

static PyObject* VarContext_remove(PyObject* self, PyObject* args)
{
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }

    as_varctx_object(self).ctx->remove(std::string(name));
    Py_RETURN_NONE;
}

static PyObject* VarContext_contains(PyObject* self, PyObject* args)
{
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    
    if( as_varctx_object(self).ctx->contains(std::string(name)))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyObject* VarContext_update_from(PyObject* self, PyObject* args)
{
    PyObject* other;
    
    if( !PyArg_ParseTuple(args, "O!", PyObject_Type(self), &other)){
        return NULL;
    }
    as_varctx_object(self).ctx->update_from(*(as_varctx_object(other).ctx));
    Py_RETURN_NONE;
}


static PyObject* VarContext_contained_vars(PyObject* self)
{
    PyObject* list = PyList_New(0);
    if( list == NULL )
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const std::string& var : as_varctx_object(self).ctx->contained_vars())
    {
        if( PyList_Append(list, PyUnicode_FromString(var.c_str())) == -1)
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add expression to python list");
        }
    }
    return list;
}

static PyMethodDef VarContext_methods[] = {
    {"set", (PyCFunction)VarContext_set, METH_VARARGS, "Give a concrete value to a symbolic variable"},
    {"get", (PyCFunction)VarContext_get, METH_VARARGS, "Give the concrete value associated with a symbolic variable"},
    {"get_as_buffer", (PyCFunction)VarContext_get_as_buffer, METH_VARARGS, "Give the buffer associated with a certain symbolic variable prefix"},
    {"get_as_str", (PyCFunction)VarContext_get_as_string, METH_VARARGS, "Give the string associated with a certain symbolic variable prefix"},
    {"remove", (PyCFunction)VarContext_remove, METH_VARARGS, "Remove the concrete value associated with a symbolic variable"},
    {"contains", (PyCFunction)VarContext_contains, METH_VARARGS, "Check if a given symbolic variable has an associated concrete value"},
    {"contained_vars", (PyCFunction)VarContext_contained_vars, METH_NOARGS, "Get the list of contained symbolic variables"},
    {"update_from", (PyCFunction)VarContext_update_from, METH_VARARGS, "Update concrete values associated with symbolic variables according to another VarContext"},
    {"new_concolic_buffer", (PyCFunction)VarContext_new_concolic_buffer, METH_VARARGS|METH_KEYWORDS, "Create a new buffer of concolic variables"},
    {"new_symbolic_buffer", (PyCFunction)VarContext_new_symbolic_buffer, METH_VARARGS|METH_KEYWORDS, "Create a new buffer of symbolic variables"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef VarContext_members[] = {
    {NULL}
};

static PyType_Slot VarContext_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(VarContext_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(VarContext_repr)},
    {Py_tp_str, reinterpret_cast<void*>(VarContext_str)},
    {Py_tp_doc, const_cast<char*>("Concrete context for abstract variables")},
    {Py_tp_methods, VarContext_methods},
    {Py_tp_members, VarContext_members},
    {0, nullptr}
};

PyType_Spec BindingTypes::VarContext_spec = {
    "maat.VarContext", sizeof(VarContext_Object), 0, binding_type_flags, VarContext_slots
};

/* Constructors */
PyObject* PyVarContext_FromVarContext(VarContext* ctx, bool is_ref){
    VarContext_Object* object;
    
    // Create object
    object = PyObject_New(VarContext_Object, binding_types().VarContext);
    if( object != nullptr ){
        object->ctx = ctx;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

PyObject* maat_VarContext(PyObject* self, PyObject* args){
    if( !PyArg_ParseTuple(args, "") ){
        return NULL;
    }
    VarContext * ctx = new VarContext();
    return PyVarContext_FromVarContext(ctx, false);
}

static PyType_Slot Value_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Value_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(Value_repr)},
    {Py_nb_add, reinterpret_cast<void*>(Value_nb_add)},
    {Py_nb_subtract, reinterpret_cast<void*>(Value_nb_sub)},
    {Py_nb_multiply, reinterpret_cast<void*>(Value_nb_mul)},
    {Py_nb_floor_divide, reinterpret_cast<void*>(Value_nb_div)},
    {Py_nb_true_divide, reinterpret_cast<void*>(Value_nb_div)},
    {Py_nb_and, reinterpret_cast<void*>(Value_nb_and)},
    {Py_nb_or, reinterpret_cast<void*>(Value_nb_or)},
    {Py_nb_xor, reinterpret_cast<void*>(Value_nb_xor)},
    {Py_nb_remainder, reinterpret_cast<void*>(Value_nb_rem)},
    {Py_nb_lshift, reinterpret_cast<void*>(Value_nb_lshift)},
    {Py_nb_rshift, reinterpret_cast<void*>(Value_nb_rshift)},
    {Py_nb_negative, reinterpret_cast<void*>(Value_nb_neg)},
    {Py_nb_invert, reinterpret_cast<void*>(Value_nb_not)},
    {Py_tp_hash, reinterpret_cast<void*>(Value_hash)},
    {Py_tp_str, reinterpret_cast<void*>(Value_str)},
    {Py_tp_doc, const_cast<char*>("Abstract expression")},
    {Py_tp_richcompare, reinterpret_cast<void*>(Value_richcompare)},
    {Py_tp_methods, Value_methods},
    {Py_tp_getset, Value_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::Value_spec = {
    "maat.Value", sizeof(Value_Object), 0, binding_type_flags, Value_slots
};

} // namespace py
} // namespace maat
