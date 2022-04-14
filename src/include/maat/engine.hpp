#ifndef MAAT_ENGINE_H
#define MAAT_ENGINE_H

#include <optional>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>

#include "maat/arch.hpp"
#include "maat/memory.hpp"
#include "maat/expression.hpp"
#include "maat/ir.hpp"
#include "maat/cpu.hpp"
#include "maat/constraint.hpp"
#include "maat/lifter.hpp"
#include "maat/info.hpp"
#include "maat/event.hpp"
#include "maat/settings.hpp"
#include "maat/loader.hpp"
#include "maat/path.hpp"
#include "maat/simplification.hpp"
#include "maat/env/env.hpp"
#include "maat/symbol.hpp"
#include "maat/logger.hpp"
#include "maat/process.hpp"
#include "maat/callother.hpp"
#include "maat/varcontext.hpp"
#include "maat/serializer.hpp"

namespace maat
{

/** \defgroup engine Engine
 * \brief The main Maat engine interface for users */

/** \addtogroup engine
 * \{ */
 
 
/** \brief The main engine class of the Maat framework. It
 * is a wrapper around core components (lifter, memory engine, IR CPU, 
 * binary loader, environment simulation, etc) that enables to symbolically
 * emulate a process */
class MaatEngine: public serial::Serializable
{
private:
    /** \typedef branch_type_t 
     * The type of branch taken */
    using branch_type_t = int;
    static constexpr int branch_none = 0;
    static constexpr int branch_native = 1;
    static constexpr int branch_pcode = 2;
private:
    CPUMode _current_cpu_mode;
private:
    // Convenience variable to avoid passing it to all subfunctions
    bool _halt_after_inst;
    // Indicates the last addr before which the engine halted because of an EXEC event
    // handler. It is used to avoid halting forever on the same instr once we resume 
    // execution
    addr_t _previous_halt_before_exec;
private:
    /** This field is used when the engine stops running in the middle
     * of a native instruction. It indicates the exact IR instruction 
     * whom to resume execution from. Typically it will only be useful
     * for snapshoting */
    std::optional<ir::IRMap::InstLocation> current_ir_state;
private:
    std::unordered_map<CPUMode, std::shared_ptr<Lifter>> lifters;
    std::shared_ptr<SnapshotManager<Snapshot>> snapshots;
    std::shared_ptr<ExprSimplifier> simplifier;
    callother::HandlerMap callother_handlers;
public:
    std::shared_ptr<Arch> arch;
    std::shared_ptr<VarContext> vars;
    std::shared_ptr<MemEngine> mem;
    ir::CPU cpu;
    event::EventManager hooks;
    PathManager path; // TODO: make this a shared_ptr<> when adding support for multi-engine runs
    std::shared_ptr<env::EnvEmulator> env;
    std::shared_ptr<SymbolManager> symbols;
    std::shared_ptr<ProcessInfo> process;
public:
    /** \brief Public field used by the engine to provide relevant contextual 
     * information */
    info::Info info;
    /// Engine's tweakable settings and options
    Settings settings;
    /// Logger
    Logger log;
public:
#ifdef MAAT_PYTHON_BINDINGS
    /** \brief Pointer to the python objcet wrapping the MaatEngine if it was created using the
     * python API. This class is used internally to pass the 'Python' engine to potential callbacks
     * written in Python. DO NOT MODIFY. */
    PyObject* self_python_wrapper_object;
#endif

public:
    /// Instanciate an engine for architecture 'arch' and operating system 'os'
    MaatEngine(Arch::Type arch, env::OS os = env::OS::NONE);
    MaatEngine(const MaatEngine& other) = delete;
    virtual ~MaatEngine() = default; ///< Destructor

public:
    /** \brief Continue executing from the current state. Execute at most
     * 'max_inst' before stopping */
    info::Stop run(int max_inst = 0);
    /** \brief Set the instruction pointer to address 'addr' and start 
     * executing from there. Execute at most 'max_inst' before stopping */
    info::Stop run_from(addr_t addr, unsigned int max_inst=0);
    /** \brief Lift and execute a single instruction located at virtual address 'addr',
     *  'raw_inst' points to the raw assembly of the instruction to be lifted */
    info::Stop run_inst(addr_t addr, uint8_t* raw_inst, size_t raw_instr_size);
    /** \brief Terminate the process emulated by the engine */
    void terminate_process(Value status);
public:
    using snapshot_t = int;
    /// Take a snapshot of the current engine state
    snapshot_t take_snapshot();
    /** \brief Restore the engine state to 'snapshot'. If remove is true, the 
     * snapshot is removed after being restored */
    void restore_snapshot(snapshot_t snapshot, bool remove=false);
    /** \brief Restore the engine state to the lastest snapshot. If remove is true, the 
     * snapshot is removed after being restored */
    void restore_last_snapshot(bool remove=false);
    /// Return the current number of active snapshots
    int nb_snapshots();
public:
    /** \brief Load an executable
     * 
     * @param binary Path of the executable file to load 
     * @param type Executable format of the file to load
     * @param base Base address where to load the binary  (used for relocatable binaries and position independent code)
     * @param args Command line arguments with whom to invoke the loaded executable
     * @param virtual_fs Location of loaded binaries and libraries in the emulated filesystem.
     *   Maps the object(s) filenames to their path(s) in the virtual filesystem, eg: { "libc.so.6": "/usr/lib" }
     * @param libdirs Directories where to search for shared objects the binary might depend on
     * @param ignore_libs List of libraries to **NOT** load even though the binary lists them as dependencies. This option has no effect when 'load_interp' is 'true'
     * @param load_interp If set to <code>True</code>, load and emulate the interpreter and let it load
     *   the binary and dependencies by itself. The interpreter binary must be found in one of 
     *   the 'libdirs' directories. If the interpreter is missing, Maat loads the binary and 
     *   dependencies manually
     */
    void load(
        const std::string& binary,
        loader::Format type,
        addr_t base,
        const std::vector<loader::CmdlineArg>& args,
        const loader::environ_t& envp,
        const std::unordered_map<std::string, std::string>& virtual_fs,
        const std::list<std::string>& libdirs,
        const std::list<std::string>& ignore_libs,
        bool load_interp = true
    );
public:
    /** \brief Return a solver-refined value set for expression *e*. The refined
     * value set takes into account potential path constraints */
    ValueSet refine_value_set(Expr e);
public:
    /** \brief Return the assembly string for instruction at address 'addr' */ 
    const std::string& get_inst_asm(addr_t addr);
public:
    /** \brief Treat 'addr' as an Address parameter, load the actual value located
     * in memory and store it back in 'addr'. The previous address value stored in
     * 'addr' is put in its auxiliary field.
     * 
     * 'param' is a reference either to the parameter corresponding to 'addr' or - when
     * invoked by 'process_load' - to the output parameter. It's used to get the number
     * of bits to read in memory 
     * 
     * 'mem' is the memory engine to use to read
     */
    bool resolve_addr_param(
        const ir::Param& param,
        ir::ProcessedInst::param_t& addr,
        MemEngine& mem
    );

    /** \brief Perform STORE operation. If 'current_block' was lifted from a memory
     * address that is overwritten by the operation, 'automodifying_block' is
     * set to 'true' and 'current_block' is removed from the pool of lifted blocks.
     * 
     * This method returns 'true' on success and 'false' if an error occured
     *
     * 'treat_as_pcode_store' tells the engine to process the instruction just as
     * a pcode STORE instruction event if it's not a STORE. 
     * In that case the address MUST be in pinst.in1 and the value to store MUST be in pinst.in2
     *
     * WARNING: this method is for internal use. It is exposed only so that callother
     * handlers might use it if needed */
    bool process_store(
        const ir::Inst& inst,
        ir::ProcessedInst& pinst,
        MemEngine& mem_engine,
        bool treat_as_pcode_store = false
    );
private:
    /** \brief Resolve all Address parameters in the instruction if needed. This method
     * returns 'true' on success and 'false' if an error occured */
    bool process_addr_params(const ir::Inst& inst, ir::ProcessedInst& pinst);
    /** \brief Perform branching operations.
     * 
     * 'is_native_branch' is set to false if 
     * the branch operation is a pcode relative branch within an instruction,
     * to true otherwise. 
     * 
     * If the branch is 'pcode relative' then update 'inst_id' to make it refer
     * to the next pcode instruction to execute within the basic block.
     * 
     * This method returns 'true' on success and 'false' if an error occured
     * */
    bool process_branch(
        const ir::AsmInst& asm_inst,
        const ir::Inst& inst,
        ir::ProcessedInst& pinst,
        branch_type_t& branch_type,
        ir::AsmInst::inst_id& inst_id
    );

    /** \brief Perform LOAD operation. The result of the load to be assigned to the 
     * output parameter is properly set in 'pinst.res'.
     * 
     * This method returns 'true' on success and 'false' if an error occured */ 
    bool process_load(const ir::Inst& inst, ir::ProcessedInst& pinst);
    
    /** \brief Perform CALLOTHER operation. CALLOTHER are used when sleigh
     * can not express an instruction semantics using the available pcode operations.
     * We need to define special handlers for them that will perform the operation.
     * This method calls the appropriate CALLOTHER handler for 'inst' to emulate the
     * instruction. 
     * 
     * If 'inst' has an output parameter, the result to be assigned is stored in pinst.res,
     * and must then be committed by a call to cpu.apply_semantics().
     *
     * This method returns 'true' on success and 'false' if an error occured */
    bool process_callother(const ir::Inst& inst, ir::ProcessedInst& pinst);
    bool process_callback_emulated_function(addr_t addr);
private:
    /** \brief Get the AsmInst at address 'addr', lift to PCODE if needed.
     * If an error occurs, sets info.stop and raises lifter_exception */
    const ir::AsmInst& get_asm_inst(addr_t addr);
private:
    /** \brief Removes the instructions whose memory content has been tampered
     * by user callbacks or user scripts, and thus whose lift is no longer valid */
    void handle_pending_x_mem_overwrites();
public:
    virtual serial::uid_t class_uid() const;
    /** Serialize the engine state
     *
     * This serializes the whole engine state except:
     * - Event hooks
     * - Internal expression simplifier
     * - Logger
     * - Library emulation callbacks
     * - Callother callbacks
     *
     * In order to keep those members (especially the event hooks), it is 
     * necessary to deserialize the engine **in place** using the same object
     * instance that was serialized.
     */
    virtual void dump(serial::Serializer& s) const;
    /** Deserialize a state into the engine
     *
     * See notes in 'MaatEngine::dump()' about members that are
     * not included in serialization.
     */
    virtual void load(serial::Deserializer& d);
};


/** \} */ // doxygen Engine group
    
} // namespace maat

#endif