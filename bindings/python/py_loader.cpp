#include "python_bindings.hpp"

namespace maat{
namespace py{

void init_loader(PyObject* module)
{
    // BIN enum
    PyObject* bin_enum = PyDict_New();
    PyDict_SetItemString(bin_enum, "ELF32", PyLong_FromLong((int)loader::Format::ELF32));
    PyDict_SetItemString(bin_enum, "ELF64", PyLong_FromLong((int)loader::Format::ELF64));
    // PyDict_SetItemString(bin_enum, "PE32", PyLong_FromLong((int)loader::Format::PE32));
    // PyDict_SetItemString(bin_enum, "PE64", PyLong_FromLong((int)loader::Format::PE64));
    PyObject* bin_class = create_class(PyUnicode_FromString("BIN"), PyTuple_New(0), bin_enum);
    PyModule_AddObject(module, "BIN", bin_class);
    
};

} // namespace py
} // namespace maat
