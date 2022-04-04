#ifndef MAAT_SAVED_MEM_STATE_H
#define MAAT_SAVED_MEM_STATE_H

#include <vector>
#include "maat/expression.hpp"
#include "maat/exception.hpp"
#include "maat/serializer.hpp"

namespace maat
{

/** \addtogroup engine
 * \{ */
 
/// (Internal) Used to record writes on abstract memory
typedef std::vector<std::pair<Expr, uint8_t>> abstract_mem_chunk_t;

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
public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};
/** \} */ // doxygen Engine group

} // namespace maat
#endif