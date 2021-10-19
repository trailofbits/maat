#include "python_bindings.hpp"
#include <iostream>
#include <sstream>

namespace maat
{
namespace py
{

// ============ Expr =============
// Methods
static void Expr_dealloc(PyObject* self)
{
    delete as_expr_object(self).expr;
    as_expr_object(self).expr = nullptr;
    
    if (as_expr_object(self).varctx)
    {
        delete as_expr_object(self).varctx;
        as_expr_object(self).varctx = nullptr;
    }

    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int Expr_print(PyObject* self, void * io, int s)
{
    std::cout << *as_expr_object(self).expr << std::flush;
    return 0;
}

static PyObject* Expr_str(PyObject* self)
{
    std::stringstream res;
    res << *((Expr_Object*) self)->expr;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Expr_repr(PyObject* self)
{
    return Expr_str(self);
}

static PyObject* Expr_is_concolic(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }
    if (varctx)
        return PyBool_FromLong((*(as_expr_object(self).expr))->is_concolic(*as_varctx_object(varctx).ctx));
    else if (as_expr_object(self).varctx)
        return PyBool_FromLong((*(as_expr_object(self).expr))->is_concolic(**as_expr_object(self).varctx));
    else
        return PyErr_Format(PyExc_RuntimeError, "Expression isn't bound to a VarContext");
}

static PyObject* Expr_is_concrete(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }

    if (varctx)
        return PyBool_FromLong((*(as_expr_object(self).expr))->is_concrete(*as_varctx_object(varctx).ctx));
    else if (as_expr_object(self).varctx)
        return PyBool_FromLong((*(as_expr_object(self).expr))->is_concrete(**as_expr_object(self).varctx));
    else
        return PyErr_Format(PyExc_RuntimeError, "Expression isn't bound to a VarContext");
        
}

static PyObject* Expr_is_symbolic(PyObject* self, PyObject* args){
    PyObject* varctx = nullptr;
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }

    if (varctx)
        return PyBool_FromLong((*(as_expr_object(self).expr))->is_symbolic(*as_varctx_object(varctx).ctx));
    else if (as_expr_object(self).varctx)
        return PyBool_FromLong((*(as_expr_object(self).expr))->is_symbolic(**as_expr_object(self).varctx));
    else
        return PyErr_Format(PyExc_RuntimeError, "Expression isn't bound to a VarContext");
}

static PyObject* Expr_as_uint(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx))
    {
        return NULL;
    }

    try
    {
        if ((*(as_expr_object(self).expr))->size <= 64)
        {
            ucst_t res = 0;
            if (varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_uint(*as_varctx_object(varctx).ctx);
            else if (as_expr_object(self).varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_uint(**(as_expr_object(self).varctx));
            else
                res = (*(as_expr_object(self).expr))->as_uint();
            return PyLong_FromUnsignedLongLong(res);
        }
        else
        {
            Number res;
            if (varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_number(*as_varctx_object(varctx).ctx);
            else if (as_expr_object(self).varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_number(**(as_expr_object(self).varctx));
            else
                res = (*(as_expr_object(self).expr))->as_number();
            std::stringstream ss;
            ss << std::hex << res;
            return PyLong_FromString(ss.str().c_str(), NULL, 16);
        }
    }
    catch(var_context_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Expr_as_int(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx))
    {
        return NULL;
    }

    try
    {
        if ((*(as_expr_object(self).expr))->size <= 64)
        {
            cst_t res = 0;
            if (varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_int(*as_varctx_object(varctx).ctx);
            else if (as_expr_object(self).varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_int(**(as_expr_object(self).varctx));
            else
                res = (*(as_expr_object(self).expr))->as_int();
            return PyLong_FromLongLong(res);
        }
        else
        {
            Number res;
            if (varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_number(*as_varctx_object(varctx).ctx);
            else if (as_expr_object(self).varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_number(**(as_expr_object(self).varctx));
            else
                res = (*(as_expr_object(self).expr))->as_number();
            std::stringstream ss;
            ss << std::hex << res;
            return PyLong_FromString(ss.str().c_str(), NULL, 16);
        }
    }
    catch(var_context_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Expr_as_float(PyObject* self, PyObject* args)
{
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }

    try
    {
        if ((*(as_expr_object(self).expr))->size <= 64)
        {
            fcst_t res = 0;
            if (varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_float(*as_varctx_object(varctx).ctx);
            else if (as_expr_object(self).varctx != nullptr)
                res = (*(as_expr_object(self).expr))->as_float(**(as_expr_object(self).varctx));
            else
                res = (*(as_expr_object(self).expr))->as_float();
            return PyLong_FromUnsignedLongLong(res);
        }
        else
        {
            return PyErr_Format(PyExc_RuntimeError, "as_float() not supported for expressions bigger than 64 bits");
        }
    }
    catch(var_context_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Expr_get_size(PyObject* self, void* closure)
{
    return PyLong_FromLong((*as_expr_object(self).expr)->size);
}

static PyMethodDef Expr_methods[] = 
{
    {"is_concolic", (PyCFunction)Expr_is_concolic, METH_VARARGS, "Check whether the expression is concolic"},
    {"is_concrete", (PyCFunction)Expr_is_concrete, METH_VARARGS, "Check whether the expression is concrete"},
    {"is_symbolic", (PyCFunction)Expr_is_symbolic, METH_VARARGS, "Check whether the expression is symbolic"},
    {"as_int", (PyCFunction)Expr_as_int, METH_VARARGS, "Concretize the expression interpreted as a signed value"},
    {"as_uint", (PyCFunction)Expr_as_uint, METH_VARARGS, "Concretize the expression interpreted as an unsigned value"},
    {"as_float", (PyCFunction)Expr_as_float, METH_VARARGS, "Concretize the expression interpreted as a floating point value"},
    {NULL, NULL, 0, NULL}
};

static PyGetSetDef Expr_getset[] =
{
    {"size", Expr_get_size, NULL, "Expression size in bits", NULL},
    {NULL}
};

// Compare functions
static PyObject* Expr_richcompare(PyObject* self, PyObject* other, int op)
{
    Constraint res;
    Expr e1, e2;
    e1 = *as_expr_object(self).expr;

    if( PyLong_Check(other)){
        e2 = exprcst(e1->size, PyLong_AsUnsignedLongLong(other));
    }else if( PyObject_IsInstance(other, get_Expr_Type())){
        e2 = *as_expr_object(other).expr;
    }else{
        return PyErr_Format(PyExc_TypeError, "Expected 'Expr' or 'int' as second argument");
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

static PyNumberMethods Expr_operators; // Empty PyNumberMethods, will be filled in the init_expression() function

/* Type description for python Expr objects */
PyTypeObject Expr_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Expr",                                   /* tp_name */
    sizeof(Expr_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Expr_dealloc,                 /* tp_dealloc */
    (printfunc)Expr_print,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Expr_repr,                                /* tp_repr */
    &Expr_operators,                          /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Expr_str,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Abstract expression",                    /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    Expr_richcompare,                         /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Expr_methods,                             /* tp_methods */
    0,                                        /* tp_members */
    Expr_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_Expr_Type(){
    return (PyObject*)&Expr_Type;
};

#define CATCH_EXPRESSION_EXCEPTION(x) try{x}catch(expression_exception e){ \
    return PyErr_Format(PyExc_ValueError, "%s", e.what()); \
}

/* Number methods & Various Constructors */
static PyObject* Expr_nb_add(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) + *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) + *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(other) + *(as_expr_object(self).expr)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '+'");
    }
}

static PyObject* Expr_nb_sub(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) - *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) - *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) - PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '-'");
    }
}

static PyObject* Expr_nb_mul(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) * *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) * (*(as_expr_object(other).expr))); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) * PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '*'");
    }
}

static PyObject* Expr_nb_div(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) / *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) / *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) / PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '/'");
    }
}

static PyObject* Expr_nb_and(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) & *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) & *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) & PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '&'");
    }
}

static PyObject* Expr_nb_or(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) | *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) | *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) | PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '|'");
    }
}

static PyObject* Expr_nb_xor(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) ^ *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) ^ *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) ^ PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '^'");
    }
}

static PyObject* Expr_nb_rem(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) % *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) % *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) % PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '%'");
    }
}

static PyObject* Expr_nb_lshift(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) << *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) << *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) << PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '<<'");
    }
}

static PyObject* Expr_nb_rshift(PyObject* self, PyObject *other){
    if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) &&
            PyObject_IsInstance(self, (PyObject*)&(Expr_Type))){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) >> *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(other, (PyObject*)&(Expr_Type)) && PyLong_Check(self)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(PyLong_AsLongLong(self) >> *(as_expr_object(other).expr)); )
    }else if( PyObject_IsInstance(self, (PyObject*)&(Expr_Type)) && PyLong_Check(other)){
        CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) >> PyLong_AsLongLong(other)); )
    }else{
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '>>'");
    }
}

static PyObject* Expr_nb_neg(PyObject* self)
{
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(- *(as_expr_object(self).expr)); )
}

static PyObject* Expr_nb_not(PyObject* self)
{
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(~ *(as_expr_object(self).expr)); )
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
            return (PyObject*)PyExpr_FromExpr(exprcst(size, std::string(str, (int)len), base)); 
        )
    }
    else if (PyLong_Check(val))
    {
        CATCH_EXPRESSION_EXCEPTION(
            return (PyObject*)PyExpr_FromExpr(exprcst(size, PyLong_AsLongLong(val)));
        )
    }
    else
    {
        return PyErr_Format(PyExc_TypeError, "'value' must be an integer or a string");
    }
}

PyObject* maat_Var(PyObject* self, PyObject* args, PyObject* keywords)
{
    Expr_Object* object;
    const char * name;
    int name_length;
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
    
    CATCH_EXPRESSION_EXCEPTION( return PyExpr_FromExpr(exprvar(size, name)); )
}

PyObject* maat_Concat(PyObject* self, PyObject* args)
{
    Expr_Object* upper, *lower;
    if( ! PyArg_ParseTuple(args, "O!O!", (PyObject*)&Expr_Type, &upper, (PyObject*)&Expr_Type, &lower)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr( concat(*(as_expr_object(upper).expr), *(as_expr_object(lower).expr))); )
}

PyObject* maat_Extract(PyObject* self, PyObject* args)
{
    Expr_Object* expr;
    long lower, higher;
    if( ! PyArg_ParseTuple(args, "O!ll", (PyObject*)&Expr_Type, &expr, &higher, &lower)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr( extract(*(as_expr_object(expr).expr), higher, lower)); )
}

// TODO SAR, ITE, ...

PyObject* PyExpr_FromExpr(Expr e)
{
    Expr_Object* object;
    
    // Create object
    PyType_Ready(&Expr_Type);
    object = PyObject_New(Expr_Object, &Expr_Type);
    PyObject_Init((PyObject*)object, &Expr_Type);
    if( object != nullptr )
    {
        object->expr = new Expr();
        *object->expr = e;
        object->varctx = nullptr;
    }
    return (PyObject*)object;
}

PyObject* PyExpr_FromExprAndVarContext(Expr e, std::shared_ptr<VarContext> ctx)
{
    Expr_Object* object;

    // Create object
    PyType_Ready(&Expr_Type);
    object = PyObject_New(Expr_Object, &Expr_Type);
    PyObject_Init((PyObject*)object, &Expr_Type);
    if( object != nullptr )
    {
        // This code is ugly but smh necessary to avoid random segfaults
        object->expr = new Expr();
        *object->expr = e;
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
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int VarContext_print(PyObject* self, void * io, int s)
{
    std::cout << *((VarContext_Object*)self)->ctx << std::flush;
    return 0;
}

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
    cst_t value;

    if( !PyArg_ParseTuple(args, "sl", &name, &value)){
        return NULL;
    }

    as_varctx_object(self).ctx->set(std::string(name), value);
    Py_RETURN_NONE;
}

static PyObject* VarContext_get(PyObject* self, PyObject* args)
{
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    if( !as_varctx_object(self).ctx->contains(std::string(name))){
        return PyErr_Format(PyExc_KeyError, "Variable %s unknown in this context");
    }
    return PyLong_FromUnsignedLongLong(as_varctx_object(self).ctx->get(std::string(name)));
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

    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }

    try{
        s = as_varctx_object(self).ctx->get_as_string(std::string(name));
    }catch(var_context_exception& e){
        return PyErr_Format(PyExc_ValueError, e.what());
    }

    res = PyUnicode_FromFormat("%s", s.c_str());
    if( res == nullptr ){
        return NULL;
    }

    return res;
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

static PyMethodDef VarContext_methods[] = {
    {"set", (PyCFunction)VarContext_set, METH_VARARGS, "Give a concrete value to a symbolic variable"},
    {"get", (PyCFunction)VarContext_get, METH_VARARGS, "Give the concrete value associated with a symbolic variable"},
    {"get_as_buffer", (PyCFunction)VarContext_get_as_buffer, METH_VARARGS, "Give the buffer associated with a certain symbolic variable prefix"},
    {"get_as_str", (PyCFunction)VarContext_get_as_string, METH_VARARGS, "Give the string associated with a certain symbolic variable prefix"},
    {"remove", (PyCFunction)VarContext_remove, METH_VARARGS, "Remove the concrete value associated with a symbolic variable"},
    {"contains", (PyCFunction)VarContext_contains, METH_VARARGS, "Check if a given symbolic variable has an associated concrete value"},
    {"update_from", (PyCFunction)VarContext_update_from, METH_VARARGS, "Update concrete values associated with symbolic variables according to another VarContext"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef VarContext_members[] = {
    {NULL}
};

/* Type description for python VarContext objects */
static PyTypeObject VarContext_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "VarContext",                             /* tp_name */
    sizeof(VarContext_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)VarContext_dealloc,           /* tp_dealloc */
    (printfunc)VarContext_print,              /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    VarContext_repr,                          /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    VarContext_str,                           /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Concrete context for abstract variables", /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    VarContext_methods,                       /* tp_methods */
    VarContext_members,                       /* tp_members */
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

PyObject* get_VarContext_Type(){
    return (PyObject*)&VarContext_Type;
};

/* Constructors */
PyObject* PyVarContext_FromVarContext(VarContext* ctx, bool is_ref){
    VarContext_Object* object;
    
    // Create object
    PyType_Ready(&VarContext_Type);
    object = PyObject_New(VarContext_Object, &VarContext_Type);
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

// ========= Module initialisation ===========
void init_expression(PyObject* module)
{
    // Add number operators to Expr
    Expr_operators.nb_add = Expr_nb_add;
    Expr_operators.nb_subtract = Expr_nb_sub;
    Expr_operators.nb_multiply = Expr_nb_mul;
    Expr_operators.nb_floor_divide = Expr_nb_div;
    Expr_operators.nb_true_divide = Expr_nb_div;
    Expr_operators.nb_and = Expr_nb_and;
    Expr_operators.nb_or = Expr_nb_or;
    Expr_operators.nb_xor = Expr_nb_xor;
    Expr_operators.nb_remainder = Expr_nb_rem;
    Expr_operators.nb_lshift = Expr_nb_lshift;
    Expr_operators.nb_rshift = Expr_nb_rshift;
    Expr_operators.nb_negative = Expr_nb_neg;
    Expr_operators.nb_invert = Expr_nb_not;
}

} // namespace py
} // namespace maat
