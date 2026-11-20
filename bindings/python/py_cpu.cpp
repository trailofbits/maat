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
    free_binding_object(self);
};

static PyObject* CPU_str(PyObject* self){
    std::stringstream res;
    as_cpu_object(self).cpu->ctx().print(res, *as_cpu_object(self).arch);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* CPU_repr(PyObject* self) {
    return CPU_str(self);
}


int CPU_set_attro(PyObject *self, PyObject *attr, PyObject *value)
{
    std::string name(PyUnicode_AsUTF8AndSize(attr, nullptr));
    try
    {
        // Get reg number
        ir::reg_t reg = as_cpu_object(self).arch->reg_num(name);
        // Check if value to set is expression or integer
        if (PyObject_TypeCheck(value, binding_types().Value))
        {
            as_cpu_object(self).cpu->ctx().set(reg, *(as_value_object(value).value));
        }
        else if (PyLong_Check(value))
        {
            // Try to get as unsigned 64-bit first
            unsigned long long uint_val = PyLong_AsUnsignedLongLong(value);
            if (uint_val != (unsigned long long)-1 || !PyErr_Occurred())
            {
                // Successfully got as unsigned 64-bit
                PyErr_Clear();
                as_cpu_object(self).cpu->ctx().set(reg, (cst_t)uint_val);
            }
            else
            {
                // Value exceeds 64 bits, use Number for multiprecision
                PyErr_Clear();
                Number number(as_cpu_object(self).arch->reg_size(reg));
                PyObject* repr = PyObject_Repr(value);
                std::string s = std::string(PyUnicode_AsUTF8AndSize(repr, nullptr));
                number.set_mpz(s, 10);
                as_cpu_object(self).cpu->ctx().set(reg, number);
                Py_DECREF(repr);
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
    std::string name(PyUnicode_AsUTF8AndSize(attr, nullptr));
    try
    {
        ir::reg_t reg = as_cpu_object(self).arch->reg_num(name);
        return PyValue_FromValueAndVarContext(as_cpu_object(self).cpu->ctx().get(reg), *(as_cpu_object(self).varctx));
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


static PyType_Slot CPU_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(CPU_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(CPU_repr)},
    {Py_tp_str, reinterpret_cast<void*>(CPU_str)},
    {Py_tp_getattro, reinterpret_cast<void*>(CPU_get_attro)},
    {Py_tp_setattro, reinterpret_cast<void*>(CPU_set_attro)},
    {Py_tp_doc, const_cast<char*>("Emulated CPU")},
    {Py_tp_methods, CPU_methods},
    {Py_tp_members, CPU_members},
    {0, nullptr}
};

PyType_Spec BindingTypes::CPU_spec = {
    "maat.CPU", sizeof(CPU_Object), 0, binding_type_flags, CPU_slots
};

PyObject* PyCPU_FromCPUAndArchAndVarContext(ir::CPU* cpu, bool is_ref, Arch* arch, std::shared_ptr<VarContext>& ctx)
{
    CPU_Object* object;

    // Create object
    object = PyObject_New(CPU_Object, binding_types().CPU);
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
