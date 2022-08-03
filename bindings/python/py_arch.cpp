#include "python_bindings.hpp"
#include "maat/arch.hpp"

namespace maat{
namespace py{

static void Arch_dealloc(PyObject* self) {

    if ( ! as_arch_object(self).is_ref) {
        delete ((Arch_Object*)self)->arch;
    }
    as_arch_object(self).arch = nullptr;

    Py_TYPE(self)->tp_free((PyObject*)self);
}

void init_arch(PyObject* module)
{
    // ARCH enum
    PyObject* arch_enum = PyDict_New();
    PyDict_SetItemString(arch_enum, "X86", PyLong_FromLong((int)Arch::Type::X86));
    PyDict_SetItemString(arch_enum, "X64", PyLong_FromLong((int)Arch::Type::X64));
    PyDict_SetItemString(arch_enum, "EVM", PyLong_FromLong((int)Arch::Type::EVM));

    PyObject* arch_class = create_class(PyUnicode_FromString("ARCH"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "ARCH", arch_class);
};

static PyObject* Arch_reg_size(PyObject* self, PyObject* args) {
    const char *reg_name;
    reg_t reg_num;
    size_t reg_size;
    
    // get reg name from params
    if ( !PyArg_ParseTuple(args, "s", &reg_name)) {
        return NULL;
    }

    // get reg number from reg name
    Arch* local_arch = as_arch_object(self).arch;
    try {
        reg_num = local_arch->reg_num(reg_name);
        reg_size = local_arch->reg_size(reg_num);
    } catch (const std::exception& e) {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    return PyLong_FromSize_t(reg_size);
}

static PyObject* Arch_pc(PyObject* self, PyObject* args) {
    reg_t reg_num;
    
    try {
        reg_num = as_arch_object(self).arch->pc();
        const std::string& reg_name = as_arch_object(self).arch->reg_name(reg_num);
        
        return PyUnicode_FromString(reg_name.c_str());
    } catch (const std::exception& e) {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Arch_sp(PyObject* self, PyObject* args) {
    reg_t reg_num;

    try {
        reg_num = as_arch_object(self).arch->sp();
        const std::string& reg_name = as_arch_object(self).arch->reg_name(reg_num);

        return PyUnicode_FromString(reg_name.c_str());
    } catch (const std::exception &e) {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* Arch_tsc(PyObject* self, PyObject* args) {
    reg_t reg_num;

    try {
        reg_num = as_arch_object(self).arch->tsc();
        const std::string& reg_name = as_arch_object(self).arch->reg_name(reg_num);

        return PyUnicode_FromString(reg_name.c_str());
    } catch (const std::exception &e) {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyMethodDef Arch_methods[] = {
    {"reg_size", (PyCFunction)Arch_reg_size, METH_VARARGS, "The size in bits of given register in this architecture" },
    {"pc", (PyCFunction)Arch_pc, METH_NOARGS, "Program counter for this architecture"},
    {"sp", (PyCFunction)Arch_sp, METH_NOARGS, "Stack pointer for this architecture"}, 
    {"tsc", (PyCFunction)Arch_tsc, METH_NOARGS, "Clock counter for this architecture"},
    {NULL},
};


// ================= GETSETTERS =================

static PyObject* Arch_get_nbregs(PyObject* self, void* closure)
{
    return PyLong_FromLong(as_arch_object(self).arch->nb_regs);
}

static PyObject* Arch_get_type(PyObject* self, void* closure)
{
    return PyLong_FromLong((int) as_arch_object(self).arch->type);
}

static PyGetSetDef Arch_getset[] = {
    { "nb_regs", Arch_get_nbregs, NULL, "Number of registers in this architecture", NULL },
    { "type", Arch_get_type, NULL, "Type of this architecture", NULL },
    {NULL}
};

PyTypeObject Arch_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Arch",                                     /* tp_name */
    sizeof(Arch_Object),                        /* tp_basicsize */
    0,                                          /* tp_itemsize */
    (destructor)Arch_dealloc,                   /* tp_dealloc */
    0,                                          /* tp_print */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_reserved */
    0,                                          /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash  */
    0,                                          /* tp_call */
    0,                                          /* tp_str */
    0,                                          /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                         /* tp_flags */
    "Architecture information and functionality",/* tp_doc */
    0,                                          /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    0,                                          /* tp_iter */
    0,                                          /* tp_iternext */
    Arch_methods,                               /* tp_methods */
    0,                                          /* tp_members */
    Arch_getset,                                /* tp_getset */
    0,                                          /* tp_base */
    0,                                          /* tp_dict */
    0,                                          /* tp_descr_get */
    0,                                          /* tp_descr_set */
    0,                                          /* tp_dictoffset */
    0,                                          /* tp_init */
    0,                                          /* tp_alloc */
    0,                                          /* tp_new */
};

PyObject* get_Arch_Type() {
    return (PyObject*)&Arch_Type;
}

PyObject* maat_Arch(PyObject* self, PyObject* args)
{
    int type;

    // Architecture given by enum above, represented as integer
    if ( !PyArg_ParseTuple(args, "i", &type) ) {
        return NULL;
    }

    Arch::Type arch_type = (Arch::Type) type;
    Arch* arch = nullptr;

    switch (arch_type) {
        case Arch::Type::EVM:
            arch = (Arch*) new EVM::ArchEVM();
            break;
        case Arch::Type::X86:
            arch = (Arch*) new X86::ArchX86();
            break;
        case Arch::Type::X64:
            arch = (Arch*) new X64::ArchX64();
            break;
        default:
            return PyErr_Format(PyExc_RuntimeError, "Unknown arhictecture type in initialisation");
    };

    // Create object
    return PyArch_FromArch(arch, false);

}

PyObject* PyArch_FromArch(Arch* arch, bool is_ref)
{
    Arch_Object* object;

    PyType_Ready(&Arch_Type);
    object = PyObject_New(Arch_Object, &Arch_Type);

    if (object != nullptr) {
        object->arch = arch;
        object->is_ref = is_ref;
    }

    return (PyObject*) object;
}

} // namespace py
} // namespace maat
