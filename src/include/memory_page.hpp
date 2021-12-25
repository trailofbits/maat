#ifndef MAAT_MEMORY_PAGE_H
#define MAAT_MEMORY_PAGE_H

#include <list>
#include "types.hpp"

namespace maat
{

/** \addtogroup memory
 * \{ */

/** \typedef page_flag_t 
 * \brief Permission flags for memory pages */
typedef uint8_t mem_flag_t;

static constexpr mem_flag_t mem_flag_none = 0U;
static constexpr mem_flag_t mem_flag_r = 1U;
static constexpr mem_flag_t mem_flag_w = 2U;
static constexpr mem_flag_t mem_flag_rw = 3U;
static constexpr mem_flag_t mem_flag_x = 4U;
static constexpr mem_flag_t mem_flag_rx = 5U;
static constexpr mem_flag_t mem_flag_wx = 6U;
static constexpr mem_flag_t mem_flag_rwx = 7U;

/// A set of contiguous memory pages
class PageSet
{
public:
    addr_t start;
    addr_t end;
    mem_flag_t flags;
    bool was_once_executable;

    PageSet(addr_t start, addr_t end, mem_flag_t f, bool was_once_executable=false);
    bool intersects_with_range(addr_t min, addr_t max) const;
    bool contains(addr_t addr);
};

/// Basic manager for page permissions
class MemPageManager
{
private:
    const size_t _page_size;
    std::list<PageSet> _regions;
private:
    void merge_regions();
public:
    MemPageManager(size_t page_size=0x1000);
    size_t page_size();
    void set_flags(addr_t start, addr_t end, mem_flag_t flags);
    mem_flag_t get_flags(addr_t addr);
    bool has_flags(addr_t addr, mem_flag_t f);
    /** \brief Return true if 'addr' belongs to a memory page that has had X 
     * permissions at some points. This function is useful to detect 
     * modifications to executable pages that have been lifted to IR
     * so that the IR is re-generated upon runtime modification of the
     * opcodes in the page */
    bool was_once_executable(addr_t addr);
public:
    /// Return 'true' if all addresses in the range have at least one R/W/X permission flag
    bool is_mapped(addr_t start, addr_t end);
    /// Return 'true' if all addresses in the range have no permission flag
    bool is_unmapped(addr_t start, addr_t end);
public:
    const std::list<PageSet>& regions();
    void set_regions(std::list<PageSet>&& regions);
public:
    friend std::ostream& operator<<(std::ostream& os, MemPageManager& mem);
};

/** \} */ // doxygen memory group
} // namespace maat

#endif
