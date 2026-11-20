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
#ifdef MAAT_HAS_SOLVER_BACKEND
    {"Solver", (PyCFunction)maat_Solver, METH_NOARGS, "Create a constraint solver"},
#endif
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

static const struct {
    PyTypeObject* BindingTypes::*member;
    PyType_Spec* spec;
} type_definitions[] = {
    {&BindingTypes::Branch, &BindingTypes::Branch_spec},
    {&BindingTypes::CPU, &BindingTypes::CPU_spec},
    {&BindingTypes::Config, &BindingTypes::Config_spec},
    {&BindingTypes::Constraint, &BindingTypes::Constraint_spec},
    {&BindingTypes::EVMContract, &BindingTypes::EVMContract_spec},
    {&BindingTypes::EVMMemory, &BindingTypes::EVMMemory_spec},
    {&BindingTypes::EVMStack, &BindingTypes::EVMStack_spec},
    {&BindingTypes::EVMStorage, &BindingTypes::EVMStorage_spec},
    {&BindingTypes::EVMTransaction, &BindingTypes::EVMTransaction_spec},
    {&BindingTypes::EVMTransactionResult, &BindingTypes::EVMTransactionResult_spec},
    {&BindingTypes::Env, &BindingTypes::Env_spec},
    {&BindingTypes::EventManager, &BindingTypes::EventManager_spec},
    {&BindingTypes::File, &BindingTypes::File_spec},
    {&BindingTypes::FileAccessor, &BindingTypes::FileAccessor_spec},
    {&BindingTypes::FileSystem, &BindingTypes::FileSystem_spec},
    {&BindingTypes::Info, &BindingTypes::Info_spec},
    {&BindingTypes::MaatEngine, &BindingTypes::MaatEngine_spec},
    {&BindingTypes::MemAccess, &BindingTypes::MemAccess_spec},
    {&BindingTypes::MemEngine, &BindingTypes::MemEngine_spec},
    {&BindingTypes::Path, &BindingTypes::Path_spec},
    {&BindingTypes::PathIterator, &BindingTypes::PathIterator_spec},
    {&BindingTypes::ProcessInfo, &BindingTypes::ProcessInfo_spec},
    {&BindingTypes::RegAccess, &BindingTypes::RegAccess_spec},
    {&BindingTypes::Settings, &BindingTypes::Settings_spec},
    {&BindingTypes::SimpleStateManager, &BindingTypes::SimpleStateManager_spec},
#ifdef MAAT_HAS_SOLVER_BACKEND
    {&BindingTypes::Solver, &BindingTypes::Solver_spec},
#endif
    {&BindingTypes::Stats, &BindingTypes::Stats_spec},
    {&BindingTypes::StorageIterator, &BindingTypes::StorageIterator_spec},
    {&BindingTypes::Value, &BindingTypes::Value_spec},
    {&BindingTypes::VarContext, &BindingTypes::VarContext_spec},
};

struct ModuleState
{
    BindingTypes types;
    PyObject* exports;
};

static ModuleState* module_state(PyObject* module)
{
    return static_cast<ModuleState*>(PyModule_GetState(module));
}

static int traverse_state(PyObject* module, visitproc visit, void* arg)
{
    auto* state = module_state(module);
    if (!state)
        return 0;
    for (const auto& def : type_definitions)
        Py_VISIT(state->types.*def.member);
    Py_VISIT(state->exports);
    return 0;
}

static int clear_state(PyObject* module)
{
    auto* state = module_state(module);
    if (!state)
        return 0;
    for (const auto& def : type_definitions)
        Py_CLEAR(state->types.*def.member);
    Py_CLEAR(state->exports);
    return 0;
}

static void free_state(void* module)
{
    clear_state(static_cast<PyObject*>(module));
}

// Module information
PyModuleDef maat_module_def = {
    PyModuleDef_HEAD_INIT,
    "maat",
    nullptr,
    sizeof(ModuleState),
    nullptr, // Methods are bound to each fresh module after restoring its exports.
    nullptr, // m_slots
    traverse_state,
    clear_state,
    free_state
};

BindingTypes& binding_types()
{
    return module_state(PyState_FindModule(&maat_module_def))->types;
}

std::optional<std::filesystem::path> get_maat_module_directory()
{
    // Add a lookup directory for sleigh files based on the module location
    PyObject* maat_module = PyState_FindModule(&maat_module_def);
    if (not maat_module)
        return std::nullopt;
    PyObject* filename_obj = PyModule_GetFilenameObject(maat_module);
    if (not filename_obj)
        return std::nullopt;
    const char* filename = PyUnicode_AsUTF8AndSize(filename_obj, nullptr);
    std::optional<std::filesystem::path> directory;
    if (filename)
        directory = std::filesystem::path(filename).parent_path();
    Py_DECREF(filename_obj);
    return directory;
}

static PyObject* create_exports(PyObject* module, const BindingTypes& types)
{
    for (auto* type : {types.Value, types.Constraint, types.Info, types.Config, types.EVMContract})
    {
        if (PyModule_AddType(module, type) < 0)
            return nullptr;
    }
    init_arch(module);
    init_memory(module);
    init_engine(module);
    init_event(module);
    init_loader(module);
    init_env(module);
    init_stats(module, types.Stats);
    init_evm(module);
    if (PyErr_Occurred())
        return nullptr;

    // Save the original bindings before adding methods that reference the module.
    return PyDict_Copy(PyModule_GetDict(module));
}

} // namespace py
} // namespace maat

using namespace maat::py;
PyMODINIT_FUNC PyInit_maat()
{
    PyObject* previous = PyState_FindModule(&maat_module_def);
    ModuleState* previous_state = previous ? module_state(previous) : nullptr;
    PyObject* module = PyModule_Create(&maat_module_def);
    if (!module)
        return nullptr;

    auto* state = module_state(module);
    for (const auto& def : type_definitions)
    {
        auto& type = state->types.*def.member;
        if (previous_state)
        {
            type = previous_state->types.*def.member;
            Py_INCREF(type);
            continue;
        }
        type = reinterpret_cast<PyTypeObject*>(PyType_FromSpec(def.spec));
        if (!type)
        {
            Py_DECREF(module);
            return nullptr;
        }
    }

    if (previous_state)
    {
        state->exports = Py_NewRef(previous_state->exports);
        // Preserve the new module's own metadata while restoring shared exports.
        if (PyDict_Merge(PyModule_GetDict(module), state->exports, 0) < 0)
        {
            Py_DECREF(module);
            return nullptr;
        }
    }
    else
    {
        state->exports = create_exports(module, state->types);
    }

    if (!state->exports || PyModule_AddFunctions(module, module_methods) < 0)
    {
        Py_DECREF(module);
        return nullptr;
    }
    return module;
}
