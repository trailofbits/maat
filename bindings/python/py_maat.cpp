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
    {"Sext", (PyCFunction)maat_Sext, METH_VARARGS, "Sign-extend an abstract value"},
    {"ULE", (PyCFunction)maat_ULE, METH_VARARGS, "Unsigned less-equal constraint on abstract values"},
    {"ULT", (PyCFunction)maat_ULT, METH_VARARGS, "Unsigned less-than constraint on abstract values"},
    {"Zext", (PyCFunction)maat_Zext, METH_VARARGS, "Zero-extend an abstract value"},
    {"ITE", (PyCFunction)maat_ITE, METH_VARARGS, "Create an If-Then-Else expression from a Constraint and two abstract expressions"},
    // Engine
    {"MaatEngine", (PyCFunction)maat_MaatEngine, METH_VARARGS, "Create a new DSE engine"},
    // Solver
    {"Solver", (PyCFunction)maat_Solver, METH_NOARGS, "Create a constraint solver"},
    // SimpleStateManager
    {"SimpleStateManager", (PyCFunction)maat_SimpleStateManager, METH_VARARGS, "Create a new helper for serializing/deserializing engine states"},
    // EVM
    {"EVMTransaction", (PyCFunction)maat_Transaction, METH_VARARGS, "Create an ethereum transaction"},
    {"contract", (PyCFunction)maat_contract, METH_VARARGS, "Get EVM contract associated with a MaatEngine"},
    {"new_evm_runtime", (PyCFunction)maat_new_evm_runtime, METH_VARARGS, "Create new EVM contract runtime for 'new_engine' based on runtime for 'old_engine'"},
    {"increment_block_number", (PyCFunction)maat_increment_block_number, METH_VARARGS, "Increment the current block number by an abstract value"},
    {"increment_block_timestamp", (PyCFunction)maat_increment_block_timestamp, METH_VARARGS, "Increment the current block timestamp by an abstract value"},
    {"set_evm_bytecode", (PyCFunction)maat_set_evm_bytecode, METH_VARARGS, "Set runtime bytecode for the contract associated to an engine"},
    {"allow_symbolic_keccak", (PyCFunction)maat_allow_symbolic_keccak, METH_VARARGS, "Enable/disable symbolic KECCAK hashes"},
    {"evm_get_static_flag", (PyCFunction)maat_evm_get_static_flag, METH_VARARGS, "Get EVM static flag"},
    {"evm_set_static_flag", (PyCFunction)maat_evm_set_static_flag, METH_VARARGS, "Set EVM static flag"},
    {"evm_set_gas_price", (PyCFunction)maat_evm_set_gas_price, METH_VARARGS, "Set EVM gas price"},
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
    init_evm(module);

    PyState_AddModule(module, &maat_module_def);

    return module;
}
