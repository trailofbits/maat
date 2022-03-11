#ifndef MEMORY_H
#define MEMORY_H

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include <list>
#include "maat/types.hpp"
#include "maat/expression.hpp"
#include "maat/settings.hpp"
#include "maat/snapshot.hpp"
#include "maat/memory_page.hpp"

namespace maat
{

/** \defgroup memory Memory 
 * \brief Modeling a process's main memory.
 * 
 * This module contains classes that simulates the main memory of
 * a process. The main relevant class to use as a user is **MemEngine**. It basically
 * models a flattened memory address space (<code>0x0</code> to <code>0xffffffffffffffff)</code> in which
 * we can map/delete memory segments, and perform read/write operations.
 * */

/** \addtogroup memory
 * \{ */

/** \typedef offset_t
 * \brief Type used internally by Maat's memory engine */
typedef addr_t offset_t;

/**
This class is used to keep track of the symbolic or concrete state
of memory. Each bit represents one address (BYTE PTR). A bit set to 1 
means that the value at the corresponding address is an abstract object,
a bit to zero means that the value is a concrete numerical value.

Each byte in the bitmap represents a QWORD, so 8 bytes. The lower address
is represented as the lowest significant bit of the bitmap byte. The 
higher address is represented by the highest significant bit. 

            HSB           LSB
             0 0 1 0 0 0 1 1
    0x107----*     *       *--- 0x100
                   *--- 0x104
*Note: is_abstract_until() and is_concrete_until() functions take a 'max' 
parameter. This parameter specifies the maximum number of bytes we want 
to check for before returning. It is used to reduce the overhead that
appears when checking a huge memory area of the same type when we want 
to write only a few bytes. Therefore, for performance reasons, it is possible
for the functions to return an offset bigger than off+nb_bytes-1, just
keep that in mind when using it.
*/
class MemStatusBitmap
{
private:
    uint8_t* _bitmap;
    unsigned int _size;
public:
    /** Constructor */
    MemStatusBitmap();
    /** Constructor */
    MemStatusBitmap(offset_t nb_bytes);
    /** Destructor */
    ~MemStatusBitmap();
    /** Extend the bitmap to make it represent 'nb_bytes' more bytes of
     * memory. The new bytes are inserted at the end of the bitmap.
     * For example if nb_bytes is 16, the actual bitmap size will
     * be increased by 16/8 = 2 bytes */
    void extend_after(offset_t nb_bytes);
    /** Extend the bitmap to make it represent 'nb_bytes' more bytes of
     * memory. The new bytes are inserted at the beginning of the bitmap.
     * For example if nb_bytes is 16, the actual bitmap size will
     * be increased by 16/8 = 2 bytes */
    void extend_before(offset_t nb_bytes);
    void mark_as_abstract(offset_t off);
    void mark_as_abstract(offset_t start, offset_t end);
    void mark_as_concrete(offset_t off);
    void mark_as_concrete(offset_t start, offset_t end);
    bool is_abstract(offset_t off);
    bool is_concrete(offset_t off);
    offset_t is_abstract_until(offset_t off, offset_t max=0xffffffff);
    offset_t is_concrete_until(offset_t off, offset_t max=0xffffffff);
};

/**This class represents a concrete memory area. It's basically a wrapper 
around a buffer that enables to read/write constants of different sizes

For performance reasons, no checks are performed on the read/write operations
to make sure that they don't overflow the bounds of the buffer. It is up
to the caller to verify that the arguments passed are consistent.
*/
class MemConcreteBuffer
{
private:
    unsigned int _size;
    uint8_t* _mem;
public:
    MemConcreteBuffer(); ///< Constructor
    MemConcreteBuffer(offset_t nb_bytes); ///< Constructor
    ~MemConcreteBuffer(); ///< Destructor
    /** Extend the buffer to make it represent 'nb_bytes' more bytes of
     * memory. The new bytes are inserted at the end of the buffer */
    void extend_after(offset_t nb_bytes); 
    /** Extend the buffer to make it represent 'nb_bytes' more bytes of
     * memory. The new bytes are inserted at the beginning of the buffer */
    void extend_before(offset_t nb_bytes);

public:
    uint64_t read(offset_t off, int nb_bytes);
    /// Write the value 'val' on 'nb_bytes' starting from offset 'off'
    void write(offset_t off, int64_t val, int nb_bytes);
    /// Write the value 'val' on 'nb_bytes' starting from offset 'off'
    void write(offset_t off, const Number& val, int nb_bytes);
    void write_buffer(offset_t off, uint8_t* buf, int buf_len);

    /** \brief Returns the closest offset from 'start' and before 'end' (included) which 
     * holds a value different from 'val' */
    offset_t is_identical_until(offset_t start, offset_t end, uint8_t val);

    /// Returns a raw pointer to the concrete memory buffer at offset 'off'
    uint8_t* raw_mem_at(offset_t off);
};

/** This class represents a memory area where abstract expressions are stored.
It enables to read/write any expression of size 8, 16, 32, or 64 bits.

For performance reasons, no checks are performed on the read/write operations
to make sure that they don't overflow the bounds of the buffer. It is up
to the caller to verify that the arguments passed are consistent.

Abstract expressions are stored in a hashmap <offset : (expr, byte_num)>. 
 - offset: is the offset in the buffer (the address) 
 - expr: expr is the expression written at address addr
 - byte_num: is the number of the particular octet of 'expr' that is at 
        address addr
  For example, assuming little endian,  writing v1 = exprvar(32, "var1")
  at offset 0x100 gives:
    - <0x100: (v1, 0)>
    - <0x101: (v1, 1)>
    - <0x102: (v1, 2)>
    - <0x103: (v1, 3)>

For read operations, if the value read overlaps between two different
expressions stored in memory, the class automatically concatenates/extracts
the corresponding parts
*/

class MemAbstractBuffer
{
public:
    // TODO: use std::map, and use iterator successors in read() implementation
    using abstract_mem_t = std::unordered_map<offset_t, std::pair<Expr, uint8_t>>;
private:
    abstract_mem_t _mem;
public:
    MemAbstractBuffer(); ///< Constructor
    Expr read(offset_t off, unsigned int nb_bytes); ///< Read 'nb_bytes' bytes as an abstract value from offset 'off'
    void write(offset_t off, Expr val); ///< Write an abstract value at offset 'off'
    std::pair<Expr, uint8_t>& at(offset_t off); ///< Return the abstract value pair stored at offset 'off'
    void set(offset_t off, std::pair<Expr, uint8_t>& pair); ///< Set the abstract value pair at offset 'off' 
};

/** This class is a wrapper that represents a mapped memory area. It can
be used transparently to write and read both abstract and concrete values.
To do so, it uses a concrete buffer, an abstract buffer, and a memory status
bitmap to keep track of what is abstract and what is concrete 
*/
class MemSegment
{
private:
    MemStatusBitmap _bitmap;
    MemConcreteBuffer _concrete;
    MemAbstractBuffer _abstract;
    bool _is_engine_special_segment;

public:
    addr_t start; ///< Beginning of the memory segment 
    addr_t end; ///< End of the memory segment (included in the segment)
    std::string name; ///< Optional. Name of the segment

public:
    MemSegment(addr_t start, addr_t end, const std::string& name="", bool is_engine_special_segment=false); ///< Constructor
    bool contains(addr_t addr);
    addr_t size(); ///< Number of bytes 
    bool intersects_with_range(addr_t addr_min, addr_t addr_max);
    bool is_engine_special_segment();
    /** \brief Extend the buffer to make it represent 'nb_bytes' more bytes of
     * memory. The new bytes are inserted at the end of the buffer */
    void extend_after(addr_t nb_bytes);
    /** \brief Extend the buffer to make it represent 'nb_bytes' more bytes of
     * memory. The new bytes are inserted at the beginning of the segment */
    void extend_before(addr_t nb_bytes);

public:
    Value read(addr_t addr, unsigned int nb_bytes); ///< Read memory
    void read(Value& res, addr_t addr, unsigned int nb_bytes); ///< Read memory
    void write(addr_t addr, const Value& val, VarContext& ctx); ///< Write value
    void write(addr_t addr, cst_t val, unsigned int nb_bytes); ///< Write concrete value
    void write(addr_t addr, uint8_t* src, int nb_bytes); ///< Write concrete buffer
    void write(addr_t addr, const std::vector<Value>& buf, VarContext& ctx); ///< Write buffer of values

    /** \brief Read memory at the address pointed by a symbolic pointer */
    void symbolic_ptr_read(Value& res, const Expr& addr, ValueSet& addr_value_set, unsigned int nb_bytes, const Expr& base);

public:
    /* Special reading and writing (for snapshoting) */
    abstract_mem_chunk_t abstract_snapshot(addr_t addr, int nb_bytes); // Used for files
    /** \brief (Internal) Takes an abstract snapshot. If the segment finishes before 'nb_bytes',
     * 'addr' and 'nb_bytes' are updated to finish the snapshot in the next segment */
    void abstract_snapshot(addr_t& addr, int& nb_bytes, abstract_mem_chunk_t& snap); // Used for main memory
    /** \brief (Internal) Takes a concrete snapshot. If the segment finishes before 'nb_bytes',
     * 'addr' and 'nb_bytes' are updated to finish the snapshot in the next segment. Shouldn't be
     * called with nb_bytes > 8 */
    cst_t concrete_snapshot(addr_t& addr, int& nb_bytes);
    void write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes);
    void write_from_abstract_snapshot(addr_t addr, abstract_mem_chunk_t& snap);

    /** \brief  Returns a raw pointer to the concrete memory buffer at address 'addr' */
    uint8_t* raw_mem_at(addr_t addr);

    /** \brief  Returns the first address holding a non-abstract value starting
     * from 'start' and before address 'start+max' */
    addr_t is_abstract_until(addr_t start, addr_t max);
    /** \brief Returns the first address holding an abstract value starting
     * from 'start' and before address 'start+max' */
    addr_t is_concrete_until(addr_t start, addr_t max);

    /** \brief Finds the first address holding a value different that 'byte' 
     * starting from 'start' */
    addr_t is_identical_until(addr_t start, cst_t byte);
};


/** \brief Represents a symbolic pointer memory write */
class SymbolicMemWrite
{
public:
    Expr addr; ///< Address of the write (symbolic pointer)
    Value value; ///< Value written
    ValueSet refined_value_set;
    SymbolicMemWrite(Expr a, const Value& val, ValueSet& vs): addr(a), value(val), refined_value_set(vs){};
    SymbolicMemWrite(addr_t a, size_t size, const Value& val)
    {
        addr = exprcst(size, a);
        value = val;
        refined_value_set.size = size;
        refined_value_set.set_cst(a);
    };
};

/** \brief Class used internally for symbolic memory management */
class SimpleInterval
{
public:
    ucst_t min, max;
    int write_count;
    SimpleInterval(ucst_t a, ucst_t b, int wc):min(a), max(b), write_count(wc){};
    bool contains(ucst_t val)
    {
        return min <= val && max >= val;
    };
};

/** \brief Class used internally for symbolic memory management.

Binary tree of intervals, for each node:

    - center is an integer
    - left is a subtree of the intervals strictly under 'center'
    - right is a subtree of the intervals strictly over 'center'
    - match_min is the list a intervals containing 'center' ordered
      by their starting value
    - match_max is the list of intervals containing 'center' ordered
      by their higher value
*/
class IntervalTree
{
public:
    ucst_t center;
    std::unique_ptr<IntervalTree> left;
    std::unique_ptr<IntervalTree> right;
    std::list<SimpleInterval> match_min; // Sorted by min
    std::list<SimpleInterval> match_max; // Sorted by max

    IntervalTree(ucst_t min=-1, ucst_t max=-1);
    void add_interval(ucst_t min, ucst_t max, int write_count);
    bool contains_addr(ucst_t val, unsigned int max_count=0xffffffff);
    bool contains_interval(ucst_t min, ucst_t max, unsigned int max_count=0xffffffff);
    void restore(int write_count);
    ~IntervalTree();
};


class MaatEngine;

/** \brief Dedicated memory engine handling the 'symbolic' memory state resulting from symbolic
 * pointer writes */
class SymbolicMemEngine
{
private:
    unsigned int write_count; ///< Number of symbolic writes that have been performed
    std::vector<SymbolicMemWrite> writes; ///< List of memory writes performed
    IntervalTree write_intervals;
private:
    std::shared_ptr<VarContext> _varctx;
public:
    Expr _unfold_concrete_ptr_exprmem(Expr expr, bool force_aligned=false);
    Expr _unfold_symbolic_ptr_exprmem(Expr expr, bool force_aligned=false);

public:
    SymbolicMemEngine(size_t arch_bits, std::shared_ptr<VarContext> varctx);
    /** \brief Record symbolic pointer write. 'addr_min' and 'addr_max' are the
     * minimal and maximal concrete values that the 'addr' expression can take */
    void symbolic_ptr_write(const Expr& addr, const Value& val, addr_t addr_min, addr_t addr_max);
    /// Record concrete pointer write
    void concrete_ptr_write(Expr addr, const Value& val);
    void concrete_ptr_write_buffer(Expr addr, uint8_t* src, int nb_bytes, size_t arch_bits);

    /// Read from concrete address 'addr'
    Expr concrete_ptr_read(Expr addr, int nb_bytes, Expr base);
    /** \brief Read from symbolic address 'addr'. 'addr_value_set' is a reference to
     * the set of values that can be taken by 'addr' */
    Expr symbolic_ptr_read(Expr& addr, ValueSet& addr_value_set, int nb_bytes, Expr base);

    /// Return true if the memory area contains a recorded symbolic write
    bool contains_symbolic_write(addr_t start, addr_t end);

    symbolic_mem_snapshot_t take_snapshot();
    void restore_snapshot(symbolic_mem_snapshot_t id);
public:
    /** \brief If set to **true**, force symbolic pointers to be aligned with the
     * size of the memory access. This can be used to reduce the set of
     * possible ways memory content is affected by symbolic stores */
    bool symptr_force_aligned;
};


// Memory alerts when writing memory
typedef uint8_t mem_alert_t;
/* No alert */
static constexpr mem_alert_t mem_alert_none = 0x0;
/* Writting in executable segment */
static constexpr mem_alert_t mem_alert_x_overwrite = 0x1;
/* Symbolic read/write has bounds that go out of allocated memory segments */
static constexpr mem_alert_t mem_alert_possible_out_of_bounds = 0x2;

/** A memory engine representing a process's memory */
class MemEngine
{
private:
    size_t _arch_bits;
    std::list<std::shared_ptr<MemSegment>> _segments;
    std::shared_ptr<VarContext> _varctx;
    std::shared_ptr<SnapshotManager<Snapshot>> _snapshots;
public:
    SymbolicMemEngine symbolic_mem_engine;
    MemPageManager page_manager;
    MemMapManager mappings;
public:
    /** \brief Create new memory engine
     * 
     * @param varctx VarContext to use when concretising abstract expressions
     * @param arch_bits Default address size in bits
     * @param snap Snapshot manager to use if snapshots are enabled */
    MemEngine(std::shared_ptr<VarContext> varctx=nullptr, size_t arch_bits=64, std::shared_ptr<SnapshotManager<Snapshot>> snap=nullptr);
    ~MemEngine();

    /** \brief Map memory from 'start' to 'end' (included), with permissions 'mflags'. 
    Necessary segments are created in order to fill the map. The map is NOT initialised with zeros */
    void map(addr_t start, addr_t end, mem_flag_t mflags = mem_flag_rwx, const std::string& map_name = "");
    /** \brief Allocate a new memory map of 'size' bytes. The map wills
     * be aligned according to the 'align' value. Returns the start address of the map */
    addr_t allocate(
        addr_t init_base, addr_t size, addr_t align,
        mem_flag_t flags, const std::string& name
    );
    /// Unmap memory from 'start' to 'end'. Memory is NOT reset to zeros
    void unmap(addr_t start, addr_t end);
public:
    /// Create a new memory segment from addresses 'start' to 'end' (included)
    void new_segment(
        addr_t start, addr_t end,
        mem_flag_t flags = maat::mem_flag_rwx, 
        const std::string& name = "",
        bool is_special_segment = false
    );
    /** \brief Allocate new memory segment of 'size' bytes. The segment will
     * be aligned according to the 'align' value */
    addr_t allocate_segment(
        addr_t base_addr, addr_t size, addr_t align,
        mem_flag_t flags = maat::mem_flag_rwx,
        const std::string& name = "",
        bool is_special_segment = false
    );
    /// Delete segment starting at address 'start'
    void delete_segment(addr_t start);
public:
    std::list<std::shared_ptr<MemSegment>>& segments();
    std::shared_ptr<MemSegment> get_segment_containing(addr_t addr);
    std::shared_ptr<MemSegment> get_segment_by_name(const std::string& name);
    /// Return 'true' if nothing is mapped between 'start' and 'end'
    bool is_free(addr_t start, addr_t end);
protected:
    /// Return 'true' if there is a MemSegment that overlaps with [start:end]
    bool has_segment_containing(addr_t start, addr_t end);

// Main read/Write interface for the core engine operations (most performant functions)
public:
    /// Read 'nb_bytes' at address 'addr'
    void read(Value& res, addr_t addr, unsigned int nb_bytes, mem_alert_t* alert=nullptr, bool force_concrete_read=false);
    /** \brief Read a buffer in memory
     * @param res Vector where to store the buffer elements
     * @param addr Start address of the buffer
     * @param nb_elems Number of elements to read in the buffer
     * @param elem_size Size of a single buffer element in bytes */
    void read_buffer(std::vector<Value>& res, const Value& addr, unsigned int nb_elems, unsigned int elem_size=1);
    /** \brief Read a concrete string of length *len* from address *addr*. If len=0,
     * it reads a C-style string and stops at the first null-byte. If *addr* is not concrete,
     * the function raises a **mem_exception**. */
    std::string read_string(const Value& addr, unsigned int len=0);
    /// Write 'value' at address 'addr'
    void write(
        addr_t addr,
        const Value& value,
        mem_alert_t* alert = nullptr,
        bool ignore_mem_permissions = false,  
        bool called_by_engine = false
    );
    /// Write at a symbolic memory address. *range* is the range of possible values for *addr*
    void symbolic_ptr_write(Expr addr, const ValueSet& range, const Value& val, const Settings& settings, mem_alert_t* alert=nullptr, bool called_by_engine=false);
    /// Read at a symbolic memory address. *range* is the range of possible values for *addr*. Write result in 'res'
    void symbolic_ptr_read(Value& res, Expr addr, const ValueSet& range, unsigned int nb_bytes, const Settings& settings);

// Convenience read/write methods (less peformant)
public:
    /// Read 'nb_bytes' at address 'addr'
    Value read(addr_t addr, unsigned int nb_bytes, mem_alert_t* alert=nullptr, bool force_concrete_read=false);
    /// Read 'nb_bytes' at address 'addr'
    Value read(const Value& addr, unsigned int nb_bytes, bool ignore_mem_permissions=false);
    /** \brief Read *nb_bytes* at address *addr*. If *addr* is not concrete, this
     * function automatically performs a symbolic pointer read. */
    Expr read(Expr addr, unsigned int nb_bytes);
    /// Write concrete value in memory
    void write(
        const Value& addr,
        cst_t val,
        int nb_bytes,
        bool ignore_mem_permissions=false
    );
    /// Write 'value' at address 'addr'
    void write(
        const Value& addr,
        const Value& value,
        bool ignore_mem_permissions = false
    );
    /// Write concrete value to memory
    void write(
        addr_t addr,
        cst_t val,
        int nb_bytes,
        bool ignore_mem_permissions = false
    );

// Legacy read/write methods
public:
    void write(addr_t addr, Expr e);

// Convenience methods to read/write buffers and strings
public:
    /** \brief Read a buffer in memory
     * @param addr Start address of the buffer
     * @param nb_elems Number of elements to read in the buffer
     * @param elem_size Size of a single buffer element in bytes */ 
    std::vector<Value> read_buffer(const Value& addr, unsigned int nb_elems, unsigned int elem_size=1);
    /// Read a buffer of 'nb_elems' elements of size 'elem_size' from address 'addr'
    std::vector<Value> read_buffer(addr_t addr, unsigned int nb_elems, unsigned int elem_size=1);
    /** \brief Read a buffer of 'nb_elems' elements of size 'elem_size' from address 'addr'
     * and writes each element as an abstract expression in the vector 'res' */
    void read_buffer(std::vector<Value>& buffer, addr_t addr, unsigned int nb_elems, unsigned int elem_size=1);
    /** \brief Read a concrete string of length 'len' from address 'addr'. If len=0,
     * it reads a C-style string and stops at the first null-byte */
    std::string read_string(addr_t addr, unsigned int len=0);
    /// Write concrete buffer in memory
    void write_buffer(const Value& addr, uint8_t* src, int nb_bytes, bool ignore_mem_permissions=false);
    /// Write abstract buffer in memory 
    void write_buffer(const Value& addr, const std::vector<Value>& src, bool ignore_mem_permissions=false);    
    /// Write a concrete buffer in memory 
    void write_buffer(addr_t addr, uint8_t* src, int nb_bytes, bool ignore_mem_permissions=false);
    /// Write an abstract buffer in memory 
    void write_buffer(addr_t addr, const std::vector<Value>& src, bool ignore_mem_permissions=false);

public:
    /// Make a buffer purely symbolic, return the symbolic name of the buffer 
    std::string make_symbolic(addr_t addr, unsigned int nb_elems, unsigned int elem_size,  const std::string& basename);
    /// Make a buffer concolic, return the symbolic name of the buffer 
    std::string make_concolic(addr_t addr, unsigned int nb_elems, unsigned int elem_size,  const std::string& basename);
    /** \brief Make a buffer tainted. If 'name' is specified, the buffer is made concolic then tainted, otherwise
     * the memory contents are tainted without being transformed into symbolic variables */
    std::string make_tainted(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& basename="");

private:
    // Remove those and keep only make_symbolic/make_concolic
    void make_tainted_no_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size);
    std::string make_tainted_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& basename);

public:
    /// Take snapshot of abstract memory for nb_bytes from 'addr' 
    abstract_mem_chunk_t abstract_snapshot(addr_t addr, int nb_bytes);
    /// Take snapshot of concrete memory for nb_bytes from 'addr' (nb_bytes must be inferior or equal to 8)
    cst_t concrete_snapshot(addr_t addr, int nb_bytes);
    void write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes, mem_alert_t& alert);
    void write_from_abstract_snapshot(addr_t addr, abstract_mem_chunk_t& snap, mem_alert_t& alert);
    ValueSet limit_symptr_range(Expr addr, const ValueSet& range, const Settings& settings);
private:
    /// (Internal) Record a memory write in the snapshot manager if it's active
    void record_mem_write(addr_t addr, int nb_bytes);

public:
    /** \brief Returns a raw pointer to the raw concrete memory buffer at address 'addr'.
     * If the address isn't mapped, throws an exception */
    uint8_t * raw_mem_at(addr_t addr);
    /** \brief Check memory status between start and end (included): is it symbolic/concrete/tainted ?
     * If at least one byte is symbolic, set is_symbolic
     * It at least one byte is tainted, set is_tainted */
    void check_status(addr_t start, addr_t end, bool& is_symbolic, bool& is_tainted);
    /// Print the memory engine to a stream
    friend std::ostream& operator<<(std::ostream& os, MemEngine& mem);
    // TODO std::string read_instr(addr_t addr, unsigned int nb_instr, CPUMode mode = CPUMode::NONE);

public:
    using mem_access_t = std::pair<addr_t, addr_t>;

private:
    /** This vector holds a list of intervalls (as a pair of addresses,
     * both included in the interval) of addresses that were once executable
     * and that got overwritten by a write() method that was *not called by
     * the engine itself* (e.g by the user script or by a breakpoint callback).
     * 
     * Its purpose is to be consumed by the main engine when it resumes execution
     * to update its map of lifted IR blocks */
    std::list<mem_access_t> pending_x_mem_overwrites;

public:
    /** \brief Get the list of pending executable memory overwrites that happened
     * (to be used by the engine only) */
    std::list<mem_access_t>& _get_pending_x_mem_overwrites();
    /** \brief Clear the list of pending executable memory overwrites (to be used
     * by the engine only) */
    void _clear_pending_x_mem_overwrites();
};

/** \brief This helper function returns the
 * start address of a segment of size 0x1000 with RW
 * permission named "Reserved". This segment is used
 * internally to emulate some instructions/syscalls.
 * If the segment doesn't yet exist it is created */
addr_t reserved_memory(MemEngine& mem);

/** \} */ // Memory doxygen group

} // namespace maat
#endif
