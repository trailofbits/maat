#include "Python.h"
#include "python_bindings.hpp"
#include <filesystem>
#include <optional>

namespace maat
{
namespace py
{

// Module methods
PyMethodDef module_methods[] = {
    // Expressions
    {"Cst", (PyCFunction)maat_Cst, METH_VARARGS | METH_KEYWORDS, "Create a constant abstract expression"},
    {"Var", (PyCFunction)maat_Var, METH_VARARGS | METH_KEYWORDS, "Create an abstract variable expression"},
    {"VarContext", (PyCFunction)maat_VarContext, METH_VARARGS, "Create a new VarContext"},
    {"Concat", (PyCFunction)maat_Concat, METH_VARARGS, "Concatenate two abstract expressions"},
    {"Extract", (PyCFunction)maat_Extract, METH_VARARGS, "Bitfield extract from an abstract expression"},
    // Engine
    {"MaatEngine", (PyCFunction)maat_MaatEngine, METH_VARARGS, "Create a new DSE engine"},
    // Solver
    {"Solver", (PyCFunction)maat_Solver, METH_NOARGS, "Create a constraint solver"},
    {NULL}
};

// Module information
PyModuleDef maat_module_def = {
    PyModuleDef_HEAD_INIT,
    "maat",
    nullptr,
    -1,      // m_size
    module_methods, // m_methods
    nullptr, // m_slots
    nullptr, // m_traverse
    nullptr, // m_clear
    nullptr  // m_free    
};

std::optional<std::filesystem::path> get_maat_module_directory()
{
    // Add a lookup directory for sleigh files based on the module location
    PyObject* maat_module = PyState_FindModule(&maat_module_def);
    if (not maat_module)
        return std::nullopt;
    PyObject* filename_obj = PyModule_GetFilenameObject(maat_module);
    if (not filename_obj)
        return std::nullopt;
    const char* filename = PyUnicode_AsUTF8(filename_obj);
    if (not filename)
        return std::nullopt;
    return std::filesystem::path(filename).parent_path();
}

} // namespace py
} // namespace maat

using namespace maat;
using namespace maat::py;
PyMODINIT_FUNC PyInit_maat()
{
    Py_Initialize();
    PyObject* module = PyModule_Create(&maat_module_def);

    init_arch(module);
    init_expression(module);
    init_constraint(module);
    init_memory(module);
    init_engine(module);
    init_event(module);
    init_loader(module);
    init_env(module);
    init_config(module);
    init_stats(module);

    PyState_AddModule(module, &maat_module_def);

    return module;
}