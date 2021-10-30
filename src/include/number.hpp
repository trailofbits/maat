#ifndef MAAT_NUMBER_H
#define MAAT_NUMBER_H

#include <iostream>
#include "types.hpp"
#include "exception.hpp"
#include "gmp.h"
#include "gmpxx.h"

namespace maat
{

/** \addtogroup expression
 * \{ */

/** \brief Represents a constant value on an arbitrary number of bits. 
 * 
 * This class is mainly intended to be used internally by Maat's engine.
 * If the number of bits is inferior or equal to 64, the value will be stored in a **cst_t** variable.
 * If the number of bits is superior to 64, the classes uses a multiprecision
 * integer from the GMP library */
class Number
{
public:
    size_t size;
    cst_t cst_;
    mpz_class mpz_;

public:
    /// Constructor (defaults size to 64 bits)
    Number();
    /// Constructor
    Number(size_t bits);
    /// Constructor
    Number(size_t bits, cst_t value);
    /// Destructor
    ~Number();
    /// Copy constructor
    Number(const Number& x) = default;
    /// Assignement
    Number& operator=(const Number& x) = default;
    /// Move Assignement
    Number& operator=(Number&& x) = default;

private:
    /// Adjust mpz bits to not exceed size
    void adjust_mpz();
    
public:
    /// Set the number to simple value 'val'
    void set_cst(cst_t val);
    /// Set the number to multiprecision value 'val'
    void set_mpz(cst_t val);
    /// Set the number to a multiprevision value 'val'
    void set_mpz(const std::string& val, int base);
    /** \brief Set the number to value 'val' without changing 
     * its current type (simple integer or mpz) */
    void set(cst_t val);

public:
    /// Get the number value as a 'cst_t', truncate if needed
    cst_t get_cst() const;
    /// Get the number value as a 'ucst_t', truncate if needed
    ucst_t get_ucst() const;
public:
    // TODO: doc
    void set_neg(const Number& n);
    void set_not(const Number& n);
    void set_add(const Number& n1, const Number& n2);
    void set_sub(const Number& n1, const Number& n2);
    void set_mul(const Number& n1, const Number& n2);
    void set_xor(const Number& n1, const Number& n2);
    void set_shl(const Number& n1, const Number& n2);
    void set_shr(const Number& n1, const Number& n2);
    void set_sar(const Number& n1, const Number& n2);
    void set_and(const Number& n1, const Number& n2);
    void set_or(const Number& n1, const Number& n2);
    void set_sdiv(const Number& n1, const Number& n2);
    void set_div(const Number& n1, const Number& n2);
    void set_extract(const Number& n, unsigned int high, unsigned int low);
    void set_concat(const Number& n1, const Number& n2);
    // Write n2 over n1 starting from lowest byte 'lb'
    void set_overwrite(const Number& n1, const Number& n2, int lb);
    void set_popcount(int dest_size, const Number& n);
    void set_zext(int ext_size, const Number& n);
    void set_sext(int ext_size, const Number& n);
    void set_rem(const Number& n1, const Number& n2);
    void set_srem(const Number& n1, const Number& n2);
    void set_mask(int size);
public:
    bool is_mpz() const;
public:
    /// Return true if this number is unsigned less than 'other'
    bool less_than(const Number& other);
    /// Return true if this number is unsigned less or equal than 'other'
    bool lessequal_than(const Number& other);
    /// Return true if this number is signed less than 'other'
    bool sless_than(const Number& other);
    /// Return true if this number is signed less or equal than 'other'
    bool slessequal_than(const Number& other);
    /// Return true if this number is equal to 'other'
    bool equal_to(const Number& other);
public:
    /// Return the value (0 or 1) of the bit 'idx' in the number
    int get_bit(unsigned int idx) const;
public:
    void print(std::ostream& os, bool decimal=false) const;
    /// Print number to a stream
    friend std::ostream& operator<<(std::ostream& os, const Number& n);
};

/** \} */ // doxygen Expressions group

} // namespace maat

#endif
