#ifndef MAAT_SNAPSHOT_H
#define MAAT_SNAPSHOT_H

#include <vector>
#include "cpu.hpp"
#include "types.hpp"
#include "info.hpp"
#include "memory_page.hpp"
#include "path.hpp"

namespace maat
{

/** \addtogroup engine
 * \{ */
 
/// (Internal) Used to record writes on abstract memory
typedef std::vector<std::pair<Expr, uint8_t>> abstract_mem_chunk_t;
 
/// (Internal) Used for snapshoting symbolic memory engine
typedef unsigned int symbolic_mem_snapshot_t;
 
/// Struct used by snapshots to record previous contents of an overwritten memory area
typedef struct 
{
    size_t size;
    addr_t addr;
    cst_t concrete_content;
    abstract_mem_chunk_t abstract_content;
} SavedMemState;

 
/** \brief Data container class used by the engine for snapshoting.
 * 
 * It holds copies of some objects and states when the snapshot was taken,
 * in particular the CPU state, optional IR state, engine information.
 * 
 * It also holds data dynamically added by the engine during execution after
 * the snapshot is taken, typically memory modifications (read/write, segment creation,
 * permission changes, ...).
 * */
class Snapshot
{
public:
    // TODO path snapshot_id
    /// CPU state snapshot
    ir::CPU<ir::max_cpu_regs> cpu;
    /// Snapshot id for the symbolic memory engine
    symbolic_mem_snapshot_t symbolic_mem;
    /// Backup of memory overwritten since snapshot
    std::list<SavedMemState> saved_mem;
    /// List of segments created since snapshot
    std::list<addr_t> created_segments;
    /// Pending IR state (optional, used if snapshoting in the middle of native instructions)
    std::optional<ir::BlockMap::InstLocation> pending_ir_state;
    /// Page permissions snapshot
    std::list<PageSet> page_permissions;
    /// Path constraints
    PathManager::path_snapshot_t path;
    /// Engine info snapshot
    info::Info info;
    /// Breakpoint triggers state when taking the snapshot (map <id:triggered>)
    std::list<std::pair<int, bool>> bp_triggers;
public:
    Snapshot() = default;
    Snapshot(const Snapshot& other) = delete;
    Snapshot& operator=(const Snapshot& other) = delete;
public:
    void add_saved_mem(SavedMemState&& content);
    void add_created_segment(addr_t segment_start);
};


/// Wrapper class to manage a list of snapshots
template<typename T>
class SnapshotManager
{
friend class MaatEngine;
friend class EnvEmulator;
private:
    std::list<T> _snapshots;
protected:
    // Protected because only MaatEngine should have the right to add/remove breakpoints
    /// Add a new snapshot a return a reference to it
    T& emplace_back()
    {
        return _snapshots.emplace_back();
    }

    /// Remove the last added snapshot
    void pop_back()
    {
        _snapshots.pop_back();
    }

public:
    /// Return a reference to the last added snapshot
    T& back()
    {
        return _snapshots.back();
    }

    /// Return true if there is at least one active snapshot
    bool active()
    {
        return not _snapshots.empty();
    }
    
    /// Return the number of active snapshots
    int size()
    {
        return _snapshots.size();
    }
};

namespace env
{

class PhysicalFile; // forward decl
// Env Snapshot 
class Snapshot
{
public:
    std::list<std::pair<std::shared_ptr<PhysicalFile>, SavedMemState>> saved_file_contents;
public:
    Snapshot() = default;
    Snapshot(const Snapshot& other) = delete;
    Snapshot& operator=(const Snapshot& other) = delete;
public:
    void add_saved_file_content(std::shared_ptr<PhysicalFile> file, SavedMemState&& content);
};

}

/** \} */ // doxygen Engine group
} // namespace maat
#endif