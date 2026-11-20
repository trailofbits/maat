#include "python_bindings.hpp"

namespace maat{
namespace py{
    
// =============== RegAccess =================
static void RegAccess_dealloc(PyObject* self){
    if( ! as_regaccess_object(self).is_ref){
        delete ((RegAccess_Object*)self)->access;
    }
    as_regaccess_object(self).access = nullptr;
    free_binding_object(self);
};

static PyObject* RegAccess_str(PyObject* self){
    std::stringstream res;
    if (as_regaccess_object(self).arch == nullptr)
        return PyErr_Format(PyExc_RuntimeError, "Can not print RegAccess that was created without a reference to Arch");
    as_regaccess_object(self).access->print(res, *as_regaccess_object(self).arch);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* RegAccess_repr(PyObject* self) {
    return RegAccess_str(self);
}


static PyObject* RegAccess_get_reg(PyObject* self, void* closure)
{
    if (as_regaccess_object(self).arch == nullptr)
        return PyErr_Format(PyExc_RuntimeError, "Can not get RegAccess.reg because object was created without a reference to Arch");
    std::string reg_name = as_regaccess_object(self).arch->reg_name(as_regaccess_object(self).access->reg);
    return PyUnicode_FromString(reg_name.c_str());
}

static PyObject* RegAccess_get_value(PyObject* self, void* closure){
    if( as_regaccess_object(self).access->value.is_none() ){
        return PyErr_Format(PyExc_AttributeError, "'value' property is not set currently");
    }
    return PyValue_FromValue(as_regaccess_object(self).access->value);
}

static PyObject* RegAccess_get_new_value(PyObject* self, void* closure){
    if( as_regaccess_object(self).access->new_value.is_none() ){
        return PyErr_Format(PyExc_AttributeError, "'new_value' property is not set currently");
    }
    return PyValue_FromValue(as_regaccess_object(self).access->new_value);
}

static PyObject* RegAccess_get_read(PyObject* self, void* closure){
    return PyBool_FromLong(as_regaccess_object(self).access->read);
}

static PyObject* RegAccess_get_written(PyObject* self, void* closure){
    return PyBool_FromLong(as_regaccess_object(self).access->written);
}

static PyGetSetDef RegAccess_getset[] = {
    {"read", RegAccess_get_read, NULL, "Is the register being read", NULL},
    {"written", RegAccess_get_written, NULL, "Is the register being written", NULL},
    {"reg", RegAccess_get_reg, NULL, "Register being accessed", NULL},
    {"new_value", RegAccess_get_new_value, NULL, "Value that is written to the register", NULL},
    {"value", RegAccess_get_value, NULL, "Current value of the register", NULL},
    {NULL}
};

static PyType_Slot RegAccess_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(RegAccess_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(RegAccess_repr)},
    {Py_tp_str, reinterpret_cast<void*>(RegAccess_str)},
    {Py_tp_doc, const_cast<char*>("Register access info")},
    {Py_tp_getset, RegAccess_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::RegAccess_spec = {
    "maat.RegAccess", sizeof(RegAccess_Object), 0, binding_type_flags, RegAccess_slots
};

PyObject* PyRegAccess_FromRegAccess(info::RegAccess* access, bool is_ref)
{
    RegAccess_Object* object;

    // Create object
    object = PyObject_New(RegAccess_Object, binding_types().RegAccess);
    if( object != nullptr ){
        object->access = access;
        object->is_ref = is_ref;
        object->arch = nullptr;
    }
    return (PyObject*)object;
}

PyObject* PyRegAccess_FromRegAccessAndArch(info::RegAccess* access, bool is_ref, Arch* arch)
{
    RegAccess_Object* object;

    // Create object
    object = PyObject_New(RegAccess_Object, binding_types().RegAccess);
    if( object != nullptr ){
        object->access = access;
        object->is_ref = is_ref;
        object->arch = arch;
    }
    return (PyObject*)object;
}


//================== MemAccess ======================
static void MemAccess_dealloc(PyObject* self){
    if( ! as_memaccess_object(self).is_ref){
        delete ((MemAccess_Object*)self)->access;
    }
    as_memaccess_object(self).access = nullptr;
    free_binding_object(self);
};

static PyObject* MemAccess_str(PyObject* self) {
    std::stringstream res;
    res << *((MemAccess_Object*) self)->access;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* MemAccess_repr(PyObject* self) {
    return MemAccess_str(self);
}


static PyObject* MemAccess_get_addr(PyObject* self, void* closure){
    if( as_memaccess_object(self).access->addr.is_none() ){
        return PyErr_Format(PyExc_AttributeError, "'addr' property is not set currently");
    }
    return PyValue_FromValue(as_memaccess_object(self).access->addr);
}


static PyObject* MemAccess_get_size(PyObject* self, void* closure){
    return PyLong_FromLong(as_memaccess_object(self).access->size);
}

static PyObject* MemAccess_get_value(PyObject* self, void* closure){
    if( as_memaccess_object(self).access->value.is_none() ){
        return PyErr_Format(PyExc_AttributeError, "'value' property is not set currently");
    }
    return PyValue_FromValue(as_memaccess_object(self).access->value);
}

static PyObject* MemAccess_get_read(PyObject* self, void* closure){
    return PyBool_FromLong(as_memaccess_object(self).access->read);
}

static PyObject* MemAccess_get_written(PyObject* self, void* closure){
    return PyBool_FromLong(as_memaccess_object(self).access->written);
}

static PyGetSetDef MemAccess_getset[] = {
    {"addr", MemAccess_get_addr, NULL, "Expression of the address where the memory is accessed", NULL},
    {"read", MemAccess_get_read, NULL, "Is the memory being read", NULL},
    {"written", MemAccess_get_written, NULL, "Is the memory being written", NULL},
    {"size", MemAccess_get_size, NULL, "Number of bytes accessed", NULL},
    {"value", MemAccess_get_value, NULL, "Value read/written from/to memory", NULL},
    {NULL}
};


static PyType_Slot MemAccess_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(MemAccess_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(MemAccess_repr)},
    {Py_tp_str, reinterpret_cast<void*>(MemAccess_str)},
    {Py_tp_doc, const_cast<char*>("Memory Access Info")},
    {Py_tp_getset, MemAccess_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::MemAccess_spec = {
    "maat.MemAccess", sizeof(MemAccess_Object), 0, binding_type_flags, MemAccess_slots
};

PyObject* PyMemAccess_FromMemAccess(info::MemAccess* access, bool is_ref){
    MemAccess_Object* object;
    
    // Create object
    object = PyObject_New(MemAccess_Object, binding_types().MemAccess);
    if( object != nullptr ){
        object->access = access;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

// ======================= Branch =====================
static void Branch_dealloc(PyObject* self){
    if( ! as_branch_object(self).is_ref){
        delete ((Branch_Object*)self)->branch;
    }
    as_branch_object(self).branch = nullptr;
    free_binding_object(self);
};

static PyObject* Branch_str(PyObject* self) {
    std::stringstream res;
    res << *(((Branch_Object*) self)->branch);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Branch_repr(PyObject* self) {
    return Branch_str(self);
}


static PyObject* Branch_get_cond(PyObject* self, void* closure){
    if( as_branch_object(self).branch->cond == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'cond' property is not set currently");
    }
    return PyConstraint_FromConstraint(as_branch_object(self).branch->cond);
}

static PyObject* Branch_get_taken(PyObject* self, void* closure){
    if( not as_branch_object(self).branch->taken.has_value()){
        return PyErr_Format(PyExc_AttributeError, "'taken' property is not set currently");
    }
    return PyBool_FromLong(as_branch_object(self).branch->taken.value());
}

static int Branch_set_taken(PyObject* self, PyObject* val, void* closure){
    std::optional<bool> taken;
    if (val == Py_None)
        taken = std::nullopt;
    else
        taken = (bool)PyObject_IsTrue(val);
    as_branch_object(self).branch->taken = taken;
    return 0;
}

static PyObject* Branch_get_target(PyObject* self, void* closure){
    if( as_branch_object(self).branch->target.is_none() ){
        return PyErr_Format(PyExc_AttributeError, "'target' property is not set currently");
    }
    return PyValue_FromValue(as_branch_object(self).branch->target);
}

static PyObject* Branch_get_next(PyObject* self, void* closure){
    if( as_branch_object(self).branch->next.is_none() ){
        return PyErr_Format(PyExc_AttributeError, "'next' property is not set currently");
    }
    return PyValue_FromValue(as_branch_object(self).branch->next);
}

static PyGetSetDef Branch_getset[] = {
    {"cond", Branch_get_cond, NULL, "Branch condition (if applicable)", NULL},
    {"target", Branch_get_target, NULL, "Target instruction if branch is taken", NULL},
    {"next", Branch_get_next, NULL, "Next instruction if branch is not taken", NULL},
    {"taken", Branch_get_taken, Branch_set_taken, "Is the branch taken or not", NULL},
    {NULL}
};


static PyType_Slot Branch_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Branch_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(Branch_repr)},
    {Py_tp_str, reinterpret_cast<void*>(Branch_str)},
    {Py_tp_doc, const_cast<char*>("Branch operation info")},
    {Py_tp_getset, Branch_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::Branch_spec = {
    "maat.Branch", sizeof(Branch_Object), 0, binding_type_flags, Branch_slots
};

PyObject* PyBranch_FromBranch(info::Branch* branch, bool is_ref){
    Branch_Object* object;
    
    // Create object
    object = PyObject_New(Branch_Object, binding_types().Branch);
    if( object != nullptr ){
        object->branch = branch;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

// ==================== Info ===================
static void Info_dealloc(PyObject* self){
    if( ! as_info_object(self).is_ref){
        delete ((Info_Object*)self)->info;
    }
    as_info_object(self).info = nullptr;
    free_binding_object(self);
};

static PyObject* Info_str(PyObject* self) {
    std::stringstream res;
    as_info_object(self).info->print(res, *as_info_object(self).arch);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Info_repr(PyObject* self) {
    return Info_str(self);
}

static PyObject* Info_get_stop(PyObject* self, void* closure){
    return PyLong_FromLong((int)as_info_object(self).info->stop);
}

static PyObject* Info_get_addr(PyObject* self, void* closure){
    if( not as_info_object(self).info->addr.has_value()){
        return PyErr_Format(PyExc_AttributeError, "'addr' property is not set currently");
    }
    return PyLong_FromUnsignedLongLong(as_info_object(self).info->addr.value());
}

static int Info_set_addr(PyObject* self, PyObject* val, void* closure){
    as_info_object(self).info->addr = PyLong_AsUnsignedLongLong(val);
    return 0;
}

static PyObject* Info_get_exit_status(PyObject* self, void* closure){
    if( not as_info_object(self).info->exit_status.has_value()){
        return PyErr_Format(PyExc_AttributeError, "'exit_status' property is not set currently");
    }
    return PyValue_FromValue(as_info_object(self).info->exit_status.value());
}

static PyObject* Info_get_branch(PyObject* self, void* closure){
    if( not as_info_object(self).info->branch.has_value()){
        return PyErr_Format(PyExc_AttributeError, "'branch' property is not set currently");
    }
    return PyBranch_FromBranch(&(as_info_object(self).info->branch.value()), true);
}

static PyObject* Info_get_mem_access(PyObject* self, void* closure){
    if( not as_info_object(self).info->mem_access.has_value()){
        return PyErr_Format(PyExc_AttributeError, "'mem_access' property is not set currently");
    }
    return PyMemAccess_FromMemAccess(&(as_info_object(self).info->mem_access.value()), true);
}

static PyObject* Info_get_reg_access(PyObject* self, void* closure){
    if( not as_info_object(self).info->reg_access.has_value()){
        return PyErr_Format(PyExc_AttributeError, "'reg_access' property is not set currently");
    }
    return PyRegAccess_FromRegAccessAndArch(
        &(as_info_object(self).info->reg_access.value()),
        true,
        as_info_object(self).arch
    );
}

static PyGetSetDef Info_getset[] = {
    {"stop", Info_get_stop, NULL, "Reason why emulation stopped", NULL},
    {"addr", Info_get_addr, Info_set_addr, "Address of the instruction where the engine stopped", NULL},
    {"exit_status", Info_get_exit_status, NULL, "Exit value of the program", NULL},
    {"branch", Info_get_branch, NULL, "Branch operation info", NULL},
    {"reg_access", Info_get_reg_access, NULL, "Register access info", NULL},
    {"mem_access", Info_get_mem_access, NULL, "Memory access info", NULL},
    {NULL}
};

static PyType_Slot Info_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Info_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(Info_repr)},
    {Py_tp_str, reinterpret_cast<void*>(Info_str)},
    {Py_tp_doc, const_cast<char*>("Symbolic Engine Info")},
    {Py_tp_getset, Info_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::Info_spec = {
    "maat.Info", sizeof(Info_Object), 0, binding_type_flags, Info_slots
};

PyObject* PyInfo_FromInfo(info::Info* info, bool is_ref){
    Info_Object* object;
    
    // Create object
    object = PyObject_New(Info_Object, binding_types().Info);
    if( object != nullptr ){
        object->info = info;
        object->is_ref = is_ref;
        object->arch = nullptr;
    }
    return (PyObject*)object;
}

PyObject* PyInfo_FromInfoAndArch(info::Info* info, bool is_ref, Arch* arch){
    Info_Object* object;

    // Create object
    object = PyObject_New(Info_Object, binding_types().Info);
    if( object != nullptr ){
        object->info = info;
        object->is_ref = is_ref;
        object->arch = arch;
    }
    return (PyObject*)object;
}

} // namespace py
} // namespace maat
