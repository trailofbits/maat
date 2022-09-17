#include "python_bindings.hpp"
#include "maat/arch.hpp"

namespace maat{
namespace py{

void init_arch(PyObject* module)
{
    // ARCH enum
    PyObject* arch_enum = PyDict_New();
    PyDict_SetItemString(arch_enum, "X86", PyLong_FromLong((int)Arch::Type::X86));
    PyDict_SetItemString(arch_enum, "X64", PyLong_FromLong((int)Arch::Type::X64));
    PyDict_SetItemString(arch_enum, "EVM", PyLong_FromLong((int)Arch::Type::EVM));
    PyDict_SetItemString(arch_enum, "RISCV", PyLong_FromLong((int)Arch::Type::RISCV));

    PyObject* arch_class = create_class(PyUnicode_FromString("ARCH"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "ARCH", arch_class);
};

} // namespace py
} // namespace maat
