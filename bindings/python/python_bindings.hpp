#ifndef MAAT_PYTHON_BINDINGS_H
#define MAAT_PYTHON_BINDINGS_H

#define PY_SSIZE_T_CLEAN // Required by python
#include "Python.h"
#include "structmember.h"
#include "maat/maat.hpp"
#include <memory>
#include <filesystem>
#include <optional>
#include <set>
#include <string>

namespace maat
{
namespace py
{

// Util function
PyObject* create_class(PyObject* name, PyObject* bases, PyObject* dict);
std::optional<std::filesystem::path> get_maat_module_directory();

// ================= Arch =======================
void init_arch(PyObject* module);

// ================= Expressions ====================
void init_expression(PyObject* module);

typedef struct {
    PyObject_HEAD
    Value* value;
    std::shared_ptr<VarContext>* varctx;
} Value_Object;

PyObject* maat_Cst(PyObject* self, PyObject* args, PyObject* keywords);
PyObject* maat_Var(PyObject* self, PyObject* args, PyObject* keywords);
PyObject* maat_Concat(PyObject* self, PyObject* args);
PyObject* maat_ITE(PyObject* self, PyObject* args);
PyObject* maat_Extract(PyObject* self, PyObject* args);
PyObject* maat_Sext(PyObject* self, PyObject* args);
PyObject* maat_ULE(PyObject* self, PyObject* args);
PyObject* maat_ULT(PyObject* self, PyObject* args);
PyObject* maat_Zext(PyObject* self, PyObject* args);
PyObject* PyValue_FromValue(const Value& val);
PyObject* PyValue_FromValueAndVarContext(const Value& val, std::shared_ptr<VarContext> ctx);
PyObject* get_Value_Type();
#define as_value_object(x) (*((Value_Object*)x))

typedef struct {
    PyObject_HEAD
    VarContext* ctx;
    bool is_ref; // Tells if it is owned or just a reference
} VarContext_Object;
PyObject* maat_VarContext(PyObject* self, PyObject* args);
PyObject* PyVarContext_FromVarContext(VarContext* ctx, bool is_ref);
PyObject* get_VarContext_Type();
#define as_varctx_object(x) (*((VarContext_Object*)x))

// =============== Constraints ==================
void init_constraint(PyObject* module);

typedef struct {
    PyObject_HEAD
    Constraint* constr;
} Constraint_Object;
PyObject* PyConstraint_FromConstraint(Constraint c);
PyObject* get_Constraint_Type();
#define as_constraint_object(x) (*((Constraint_Object*)x))

// ================= Memory ==================
void init_memory(PyObject* module);
typedef struct{
    PyObject_HEAD
    MemEngine* mem;
    bool is_ref;
} MemEngine_Object;
PyObject* PyMemEngine_FromMemEngine(MemEngine* mem, bool is_ref);
#define as_mem_object(x) (*((MemEngine_Object*)x))

// ================== Events ==================
void init_event(PyObject* module);

typedef struct{
    PyObject_HEAD
    event::EventManager* manager;
    bool is_ref;
} EventManager_Object;
PyObject* PyEventManager_FromEventManager(event::EventManager* m, bool is_ref);
#define as_event_object(x) (*((EventManager_Object*)x))

// =================== Engine ====================
void init_engine(PyObject* module);

typedef struct{
    PyObject_HEAD
    MaatEngine* engine;
    /* Wrappers to members */
    PyObject* vars;
    PyObject* cpu; 
    PyObject* mem; 
    PyObject* hooks;
    PyObject* info;
    PyObject* path;
    PyObject* env;
    // PyObject* stats;
    PyObject* settings;
    PyObject* process;
} MaatEngine_Object;
PyObject* get_MaatEngine_Type();
PyObject* maat_MaatEngine(PyObject* self, PyObject* args);
PyObject* PyMaatEngine_FromMaatEngine(MaatEngine*);
// This method initializes all the attributes of a python MaatEngine object. It
// is separate from the constructor because we also need to call it when deserializing
// a MaatEngine. Indeed, attributes like 'vars', 'cpu', are already initialized
// and point to members of the MaatEngine, but if we deserialize a new state into the engine
// those pointers are invalid (they point to the old engine objects, not the new one).
void _init_MaatEngine_attributes(MaatEngine_Object* object);
void _clear_MaatEngine_attributes(MaatEngine_Object* object);
#define as_engine_object(x)  (*((MaatEngine_Object*)x))

// ====================== Info ======================
typedef struct{
    PyObject_HEAD
    info::RegAccess* access;
    bool is_ref;
    Arch* arch; // Always ref, can be null, used for printing register names only
} RegAccess_Object;
PyObject* PyRegAccess_FromRegAccess(info::RegAccess* access, bool is_ref);
#define as_regaccess_object(x)  (*((RegAccess_Object*)x))

typedef struct{
    PyObject_HEAD
    info::MemAccess* access;
    bool is_ref;
} MemAccess_Object;
PyObject* PyMemAccess_FromMemAccess(info::MemAccess* access, bool is_ref);
#define as_memaccess_object(x)  (*((MemAccess_Object*)x))

typedef struct{
    PyObject_HEAD
    info::Branch* branch;
    bool is_ref;
} Branch_Object;
PyObject* PyBranch_FromBranch(info::Branch* access, bool is_ref);
#define as_branch_object(x)  (*((Branch_Object*)x))

typedef struct{
    PyObject_HEAD
    info::Info* info;
    bool is_ref;
    Arch* arch; // Always ref, can be null, used to pass to RegAccess
} Info_Object;
PyObject* PyInfo_FromInfo(info::Info* info, bool is_ref);
PyObject* PyInfo_FromInfoAndArch(info::Info* info, bool is_ref, Arch* arch);
PyObject* get_Info_Type();
#define as_info_object(x)  (*((Info_Object*)x))

typedef struct {
    PyObject_HEAD
    ir::CPU* cpu;
    bool is_ref;
    Arch* arch; // Always ref, needed to get registers by name
    std::shared_ptr<VarContext>* varctx; // Always ref, needed to build expressions
} CPU_Object;

PyObject* PyCPU_FromCPUAndArchAndVarContext(
    ir::CPU* cpu,
    bool is_ref,
    Arch* arch,
    std::shared_ptr<VarContext>& varctx
);
#define as_cpu_object(x) (*((CPU_Object*)x))

// ====================== Loader ========================
void init_loader(PyObject* module);

// ====================== Settings ======================
typedef struct{
    PyObject_HEAD
    Settings* settings;
    bool is_ref;
} Settings_Object;
PyObject* PySettings_FromSettings(Settings* settings, bool is_ref);
#define as_settings_object(x)  (*((Settings_Object*)x))

// ====================== PathManager ======================
typedef struct{
    PyObject_HEAD
    PathManager* path;
    bool is_ref;
} Path_Object;
PyObject* PyPath_FromPath(PathManager* path, bool is_ref);
#define as_path_object(x)  (*((Path_Object*)x))

typedef struct {
    PyObject_HEAD
    PathManager::IteratorWrapper* wrapper; // Owned
    PathManager::iterator current;
    PathManager::iterator end;
} PathIterator_Object;
PyObject* PyPathIterator_FromWrapper(const PathManager::IteratorWrapper& wrapper);
#define as_pathiterator_object(x) (*((PathIterator_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::ProcessInfo* process;
    bool is_ref;
} ProcessInfo_Object;
PyObject* PyProcessInfo_FromProcessInfo(ProcessInfo* info, bool is_ref);
#define as_process_object(x)  (*((ProcessInfo_Object*)x))

// ================== Env ======================
void init_env(PyObject* module);

typedef struct{
    PyObject_HEAD
    env::PhysicalFile* file;
    bool is_ref;
} File_Object;
PyObject* get_File_Type();
PyObject* PyFile_FromPhysicalFile(env::PhysicalFile* file, bool is_ref);
#define as_file_object(x)  (*((File_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::FileAccessor* fa;
    bool is_ref;
} FileAccessor_Object;
PyObject* get_FileAccessor_Type();
PyObject* PyFileAccessor_FromFileAccessor(env::FileAccessor* fa, bool is_ref);
#define as_fileaccessor_object(x)  (*((FileAccessor_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::FileSystem* fs;
    bool is_ref;
} FileSystem_Object;
PyObject* get_FileSystem_Type();
PyObject* PyFileSystem_FromFileSystem(env::FileSystem* fs, bool is_ref);
#define as_fs_object(x)  (*((FileSystem_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::EnvEmulator* env;
    bool is_ref;
    /* Wrappers to members */
    PyObject* fs;
} Env_Object;
PyObject* get_Env_Type();
PyObject* PyEnv_FromEnvEmulator(env::EnvEmulator* env, bool is_ref);
#define as_env_object(x)  (*((Env_Object*)x))

// ================= Solver ===================
#ifdef MAAT_HAS_SOLVER_BACKEND
typedef struct{
    PyObject_HEAD
    maat::solver::Solver* solver;
} Solver_Object;
PyObject* get_Solver_Type();
PyObject* maat_Solver(PyObject* module);
#define as_solver_object(x)  (*((Solver_Object*)x))
#endif


// ================= Config =================
void init_config(PyObject* module);
typedef struct{
    PyObject_HEAD
} Config_Object;
PyObject* get_Config_Type();
PyObject* maat_Config();
#define as_config_object(x)  (*((Config_Object*)x))

// ================= Stats ==================
void init_stats(PyObject* module);
typedef struct{
    PyObject_HEAD
} Stats_Object;
PyObject* get_Stats_Type();
PyObject* maat_Stats();
#define as_stats_object(x)  (*((Stats_Object*)x))

// ============ SimpleStateManager ============

typedef struct{
    PyObject_HEAD
    maat::serial::SimpleStateManager* s;
} SimpleStateManager_Object;
PyObject* get_SimpleStateManager_Type();
PyObject* maat_SimpleStateManager(PyObject* self, PyObject* args);
#define as_simple_serializer_object(x)  (*((SimpleStateManager_Object*)x))

// ============== EVM ======================
void init_evm(PyObject* module);

typedef struct {
    PyObject_HEAD
    env::EVM::Storage::const_iterator current;
    env::EVM::Storage::const_iterator end;
} StorageIterator_Object;

PyObject* PyStorageIterator(
    env::EVM::Storage::const_iterator current,
    env::EVM::Storage::const_iterator end
);
#define as_storageiterator_object(x) (*((StorageIterator_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::EVM::Storage* storage;
} EVMStorage_Object;
PyObject* PyEVMStorage_FromStorage(env::EVM::Storage*);
#define as_storage_object(x)  (*((EVMStorage_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::EVM::Memory* memory;
} EVMMemory_Object;
PyObject* PyEVMMemory_FromMemory(env::EVM::Memory*);
#define as_evm_memory_object(x)  (*((EVMMemory_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::EVM::Stack* stack;
} EVMStack_Object;
PyObject* PyEVMStack_FromStack(env::EVM::Stack*);
#define as_stack_object(x)  (*((EVMStack_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::EVM::Contract* contract;
    PyObject* storage;
    PyObject* stack;
    PyObject* memory;
} EVMContract_Object;
PyObject* get_EVMContract_Type();
PyObject* PyEVMContract_FromContract(env::EVM::Contract*);
#define as_contract_object(x)  (*((EVMContract_Object*)x))

typedef struct{
    PyObject_HEAD
    bool is_ref;
    maat::env::EVM::Transaction* transaction;
} EVMTransaction_Object;
PyObject* get_EVMTransaction_Type();
PyObject* PyEVMTx_FromTx(env::EVM::Transaction*, bool is_ref);
PyObject* maat_Transaction(PyObject* self, PyObject* args);
#define as_tx_object(x)  (*((EVMTransaction_Object*)x))

typedef struct{
    PyObject_HEAD
    maat::env::EVM::TransactionResult* result;
} EVMTransactionResult_Object;
PyObject* get_EVMTransactionResult_Type();
PyObject* PyEVMTxResult_FromTxResult(env::EVM::TransactionResult*);
#define as_tx_result_object(x)  (*((EVMTransactionResult_Object*)x))

// Return the contract associated with an engine
PyObject* maat_contract(PyObject* mod, PyObject* args);
PyObject* maat_new_evm_runtime(PyObject* mod, PyObject* args);
PyObject* maat_increment_block_timestamp(PyObject* mod, PyObject* args);
PyObject* maat_increment_block_number(PyObject* mod, PyObject* args);
PyObject* maat_set_evm_bytecode(PyObject* mod, PyObject* args);
PyObject* maat_allow_symbolic_keccak(PyObject* mod, PyObject* args);
PyObject* maat_evm_get_static_flag(PyObject* mod, PyObject* args);
PyObject* maat_evm_set_static_flag(PyObject* mod, PyObject* args);
PyObject* maat_evm_set_gas_price(PyObject* mod, PyObject* args);

// ====== Utils =======
// Transform a list of values into a list of python values,
// returns a python error on error
PyObject* native_to_py(const std::vector<Value>&);
PyObject* native_to_py(const std::unordered_set<Constraint>& constraints);

// Python bigint into multiprecision number
// num MUST be a PyLong object (no further type checks in the function)
Number bigint_to_number(size_t bits, PyObject* num);
// Multiprecision number to python bigint
PyObject* number_to_bigint(const Number& num);

// Expose a type in python module
void register_type(PyObject* module, PyTypeObject* type_obj);

// Translate a python set to a set of strings in C++. Returns false on error
bool py_to_c_string_set(PySetObject* set, std::set<std::string>& res);

} // namespace py
} // namespace maat
#endif
