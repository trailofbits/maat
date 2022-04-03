#ifndef MAAT_SNAPSHOT_H
#define MAAT_SNAPSHOT_H

#include <vector>
#include "maat/cpu.hpp"
#include "maat/types.hpp"
#include "maat/info.hpp"
#include "maat/memory_page.hpp"
#include "maat/path.hpp"
#include "maat/process.hpp"
#include "maat/exception.hpp"
#include "maat/serializer.hpp"

namespace maat
{

/** \addtogroup engine
 * \{ */
 
/// (Internal) Used to record writes on abstract memory
typedef std::vector<std::pair<Expr, uint8_t>> abstract_mem_chunk_t;
 
/// (Internal) Used for snapshoting symbolic memory engine
typedef unsigned int symbolic_mem_snapshot_t;
 
/// Struct used by snapshots to record previous contents of an overwritten memory area
struct SavedMemState: public serial::Serializable
{
public:
    size_t size;
    addr_t addr;
    cst_t concrete_content;
    abstract_mem_chunk_t abstract_content;

public:
    SavedMemState();
    SavedMemState(size_t size, addr_t addr, cst_t concrete, abstract_mem_chunk_t abstract);
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

 
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
    /// CPU state snapshot
    ir::CPU cpu;
    /// Snapshot id for the symbolic memory engine
    symbolic_mem_snapshot_t symbolic_mem;
    /// Backup of memory overwritten since snapshot
    std::list<SavedMemState> saved_mem;
    /// List of segments created since snapshot
    std::list<addr_t> created_segments;
    /// Pending IR state (optional, used if snapshoting in the middle of native instructions)
    std::optional<ir::IRMap::InstLocation> pending_ir_state;
    /// Page permissions snapshot
    std::list<PageSet> page_permissions;
    /// Mappings snapshot
    std::list<MemMap> mem_mappings;
    /// Path constraints
    PathManager::path_snapshot_t path;
    /// Engine info snapshot
    info::Info info;
    /// Process info snapshot
    std::shared_ptr<ProcessInfo> process;
    /// Environment
    int env;
public:
    Snapshot() = default;
    Snapshot(const Snapshot& other) = delete;
    Snapshot& operator=(const Snapshot& other) = delete;
public:
    void add_saved_mem(SavedMemState&& content);
    void add_created_segment(addr_t segment_start);
};

// Forward decl
namespace env
{
    class FileSystem;
}

/// Wrapper class to manage a list of snapshots
template<typename T>
class SnapshotManager
{
friend class MaatEngine;
friend class maat::env::FileSystem;
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
        if (not active())
            throw snapshot_exception("SnashotManager::back(): no active snapshot!");
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
/** \} */ // doxygen Engine group

} // namespace maat
#endif
