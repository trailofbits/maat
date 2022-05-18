#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <iso646.h>

#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline))
#endif // _MSC_VER

/// Main namespace for Maat's API
namespace maat
{

/* Numeric types typedefs */
/** \addtogroup expression
 * \{ */
typedef uint32_t hash_t; ///< Unique hash identifying an abstract expression object
typedef int64_t cst_t; ///< Signed constant integer value
typedef uint64_t ucst_t; ///< Unsigned constant integer value
typedef double fcst_t; ///< Float constant value (double precision / 64 bits)
/** \} */

/** \addtogroup memory
 * \{ */
typedef uint64_t addr_t; ///< Concrete memory address
/** \} */

/** \addtogroup engine
 * \{ */
/// (Internal) Used for snapshoting symbolic memory engine
typedef unsigned int symbolic_mem_snapshot_t;
/** \} */
}

#endif
