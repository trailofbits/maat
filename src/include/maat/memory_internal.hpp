#ifndef MAAT_MEMORY_INTERNAL_H
#define MAAT_MEMORY_INTERNAL_H

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include <list>
#include "maat/value.hpp"
#include "maat/types.hpp"
#include "maat/expression.hpp"
#include "maat/settings.hpp"
#include "maat/serializer.hpp"

namespace maat
{

using serial::bits;

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
class MemStatusBitmap: public serial::Serializable
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
public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

/**This class represents a concrete memory area. It's basically a wrapper 
around a buffer that enables to read/write constants of different sizes

For performance reasons, no checks are performed on the read/write operations
to make sure that they don't overflow the bounds of the buffer. It is up
to the caller to verify that the arguments passed are consistent.
*/
class MemConcreteBuffer: public serial::Serializable
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

    /** \brief Returns the closest offset from 'start' and before 'end' which 
     * holds a value different from 'val' */
    offset_t is_identical_until(offset_t start, offset_t end, uint8_t val);

    /// Returns a raw pointer to the concrete memory buffer at offset 'off'
    uint8_t* raw_mem_at(offset_t off);

public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
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

class MemAbstractBuffer: public serial::Serializable
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
public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

/** This class is a wrapper that represents a mapped memory area. It can
be used transparently to write and read both abstract and concrete values.
To do so, it uses a concrete buffer, an abstract buffer, and a memory status
bitmap to keep track of what is abstract and what is concrete 
*/
class MemSegment: public serial::Serializable
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

public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};


/** \brief Represents a symbolic pointer memory write */
class SymbolicMemWrite: public serial::Serializable
{
public:
    Expr addr; ///< Address of the write (symbolic pointer)
    Value value; ///< Value written
    ValueSet refined_value_set;
    /// Dummy constructor used for deserialization
    SymbolicMemWrite(): addr(nullptr) {} 
    SymbolicMemWrite(Expr a, const Value& val, ValueSet& vs): addr(a), value(val), refined_value_set(vs){};
    SymbolicMemWrite(addr_t a, size_t size, const Value& val)
    {
        addr = exprcst(size, a);
        value = val;
        refined_value_set.size = size;
        refined_value_set.set_cst(a);
    };

public:
    virtual uid_t class_uid() const
    {
        return serial::ClassId::SYMBOLIC_MEM_WRITE;
    }
    virtual void dump(serial::Serializer& s) const
    {
        s << addr << value << refined_value_set;
    }
    virtual void load(serial::Deserializer& d)
    {
        d >> addr >> value >> refined_value_set;
    }
};

/** \brief Class used internally for symbolic memory management */
class SimpleInterval: public serial::Serializable
{
public:
    ucst_t min, max;
    int write_count;
    SimpleInterval(ucst_t a=0, ucst_t b=0, int wc=0):min(a), max(b), write_count(wc){};
    bool contains(ucst_t val)
    {
        return min <= val && max >= val;
    };
public:
    virtual uid_t class_uid() const
    {
        return serial::ClassId::SIMPLE_INTERVAL;
    }
    virtual void dump(serial::Serializer& s) const
    {
        s << bits(min) << bits(max) << bits(write_count);
    }
    virtual void load(serial::Deserializer& d)
    {
        d >> bits(min) >> bits(max) >> bits(write_count);
    }
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
class IntervalTree: public serial::Serializable
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
public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};


class MaatEngine;

/** \brief Dedicated memory engine handling the 'symbolic' memory state resulting from symbolic
 * pointer writes */
class SymbolicMemEngine: public serial::Serializable
{
private:
    unsigned int write_count; ///< Number of symbolic writes that have been performed
    std::vector<SymbolicMemWrite> writes; ///< List of memory writes performed
    IntervalTree write_intervals;
private:
    std::shared_ptr<VarContext> _varctx;
public:
    /** \brief If set to **true**, force symbolic pointers to be aligned with the
     * size of the memory access. This can be used to reduce the set of
     * possible ways memory content is affected by symbolic stores */
    bool symptr_force_aligned;

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
    Expr _unfold_concrete_ptr_exprmem(Expr expr, bool force_aligned=false);
    Expr _unfold_symbolic_ptr_exprmem(Expr expr, bool force_aligned=false);
public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};


// Memory alerts when writing memory
typedef uint8_t mem_alert_t;
/* No alert */
static constexpr mem_alert_t mem_alert_none = 0x0;
/* Writting in executable segment */
static constexpr mem_alert_t mem_alert_x_overwrite = 0x1;
/* Symbolic read/write has bounds that go out of allocated memory segments */
static constexpr mem_alert_t mem_alert_possible_out_of_bounds = 0x2;


/** \} */ // Memory doxygen group

} // namespace maat
#endif
