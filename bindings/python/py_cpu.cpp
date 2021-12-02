#include "python_bindings.hpp"

namespace maat{
namespace py{
    
// ==================== CPU ====================

static void CPU_dealloc(PyObject* self){
    delete as_cpu_object(self).varctx; as_cpu_object(self).varctx = nullptr;
    if( not as_cpu_object(self).is_ref)
    {
        delete ((CPU_Object*)self)->cpu;
    }
    as_cpu_object(self).cpu = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* CPU_str(PyObject* self){
    std::stringstream res;
    as_cpu_object(self).cpu->ctx().print(res, *as_cpu_object(self).arch);
    return PyUnicode_FromString(res.str().c_str());
}

static int CPU_print(PyObject* self, void * io, int s){
    as_cpu_object(self).cpu->ctx().print(std::cout, *as_cpu_object(self).arch);
    return 0;
}

static PyObject* CPU_repr(PyObject* self) {
    return CPU_str(self);
}


int CPU_set_attro(PyObject *self, PyObject *attr, PyObject *value)
{
    std::string name(PyUnicode_AsUTF8(attr));
    try
    {
        // Get reg number
        ir::reg_t reg = as_cpu_object(self).arch->reg_num(name);
        // Check if value to set is expression or integer
        if (PyObject_TypeCheck(value, (PyTypeObject*)get_Expr_Type()))
        {
            as_cpu_object(self).cpu->ctx().set(reg, *(as_expr_object(value).expr));
        }
        else if (PyLong_Check(value))
        {
            int overflow = 0;
            cst_t int_val = PyLong_AsLongLongAndOverflow(value, &overflow);
            if (overflow == 0)
                as_cpu_object(self).cpu->ctx().set(reg, int_val);
            else // More than 64 bits, set as number
            {
                Number number(as_cpu_object(self).arch->reg_size(reg));
                PyObject* repr = PyObject_Repr(value);
                std::string s = std::string(PyUnicode_AsUTF8(repr));
                number.set_mpz(s, 10); // Base 10 because python repr() uses base 10
                as_cpu_object(self).cpu->ctx().set(reg, number);
            }
        }
        else
        {
            PyErr_SetString(PyExc_RuntimeError, "Invalid value: expected 'int' or 'Expr'");
            return 1;
        }
    }
    catch(const ir_exception& e)
    {
        std::stringstream ss; 
        ss << "No register named " << name;
        PyErr_SetString(PyExc_AttributeError, ss.str().c_str());
        return 1;
    }
    catch(const generic_exception& e)
    {
        std::stringstream ss; 
        ss << "Error setting attribute " << name << ": " << e.what();
        PyErr_SetString(PyExc_AttributeError, ss.str().c_str());
        return 1;
    }
    catch(const std::exception& e)
    {
        PyErr_SetString(PyExc_AttributeError, e.what());
        return 1;
    }

    return 0;
}

PyObject* CPU_get_attro(PyObject *self, PyObject *attr)
{
    std::string name(PyUnicode_AsUTF8(attr));
    try
    {
        ir::reg_t reg = as_cpu_object(self).arch->reg_num(name);
        return PyExpr_FromExprAndVarContext(as_cpu_object(self).cpu->ctx().get(reg), *(as_cpu_object(self).varctx));
    }
    catch(const ir_exception& e)
    {
        return PyErr_Format(PyExc_AttributeError, "No register named %s", attr);
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_AttributeError, "Error getting attribute %s: %s", attr, e.what());
    }
}

static PyMethodDef CPU_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyMemberDef CPU_members[] = {
    {NULL}
};


/* Type description for python CPU objects */
static PyTypeObject CPU_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "CPU",                             /* tp_name */
    sizeof(CPU_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)CPU_dealloc,           /* tp_dealloc */
    (printfunc)CPU_print,              /* tp_print */
    0,                /* tp_getattr */
    0,                /* tp_setattr */
    0,                                        /* tp_reserved */
    CPU_repr,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    CPU_str,                            /* tp_str */
    (getattrofunc)CPU_get_attro,                                        /* tp_getattro */
    (setattrofunc)CPU_set_attro,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Emulated CPU",                           /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    CPU_methods,                       /* tp_methods */
    CPU_members,                       /* tp_members */
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

PyObject* PyCPU_FromCPUAndArchAndVarContext(ir::CPU<ir::max_cpu_regs>* cpu, bool is_ref, Arch* arch, std::shared_ptr<VarContext>& ctx)
{
    CPU_Object* object;

    // Create object
    PyType_Ready(&CPU_Type);
    object = PyObject_New(CPU_Object, &CPU_Type);
    if( object != nullptr ){
        object->cpu = cpu;
        object->is_ref = is_ref;
        object->arch = arch;
        object->varctx = new std::shared_ptr<VarContext>(ctx);
    }
    return (PyObject*)object;
}

} // namespace py
} // namespace maat
