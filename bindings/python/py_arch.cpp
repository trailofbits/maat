#include "python_bindings.hpp"
#include "maat/arch.hpp"

namespace maat{
namespace py{

static void Arch_dealloc(PyObject* self) {
    delete as_arch_object(self).arch;
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

/*
static pyMethodDef Arch_methods[] = {
    // reg_size()
    // pc()
    // sp()
    // tsc()
    {None},
};


// ================= GETSETTERS =================

static PyObject* Arch_get_nbregs(PyObject* self, void* closure)
{
    return PyLong_FromLong(as_arch_object(self).arch->nb_regs);
}

static PyObject* Arch_get_type(PyObject* self, void* closure)
{
    // TODO: is there a way to return string version? Is that better?
    // perhaps if we have logic here which assigns string value to 
    // the enum values and returns the pystring from that?
    // alternative: this returns long, have a second function which
    return PyLong_FromLong(as_arch_object(self).arch->type);
}

static PyGetSetDef Arch_getset[] = {
    { "nb_regs", Arch_get_nbregs, NULL, "Number of registers in this architecture", NULL },
    { "type", Arch_get_type, NULL, "Type of this architecture", NULL },
    {NULL}
};*/

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
    "Dynamic Symbolic Execution Engine",        /* tp_doc */
    0,                                          /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    0,                                          /* tp_iter */
    0,                                          /* tp_iternext */
    0,//Arch_methods,                               /* tp_methods */
    0,//Arch_members,                               /* tp_members */
    0,//Arch_getset,                                /* tp_getset */
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
    // Parse arguments

    // Arch will be determined exclusively by type
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
        // raise error?
            break;
    };

    // Create object
    return PyArch_FromArch(arch);

}

PyObject* PyArch_FromArch(Arch* arch)
{
    Arch_Object* object;

    // Create object
    PyType_Ready(&Arch_Type);
    object = PyObject_New(Arch_Object, &Arch_Type);
    PyObject_Init( (PyObject*)object, &Arch_Type );

    if (object != nullptr) {
        object->arch = arch;
        object->type = arch->type; 
        object->nb_regs = arch->nb_regs;
    }

    return (PyObject*) object;
}

} // namespace py
} // namespace maat
