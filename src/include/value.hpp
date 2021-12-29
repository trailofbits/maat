#ifndef MAAT_VALUE_H
#define MAAT_VALUE_H

#include "expression.hpp"
#include "number.hpp"
#include "constraint.hpp"

namespace maat
{
/** \addtogroup expression
 * \{ */

/** A value is a wrapper class that represent data on a fixed number of bits.
The data can be either concrete, or abstract. The underlying implementation
uses the `Expr` and `Number` classes to represent abstract and concrete values.
*/
class Value
{
public:
    enum class Type
    {
        NONE,
        ABSTRACT,
        CONCRETE
    };

private:
    Expr _expr;
    Number _number;
    Type type;

public:
    Value(); ///< Empty value
    Value(const Value& other) = default; ///< Copy constructor
    Value(const Expr& expr); ///< Build value from abstract expression
    Value(const Number& number); ///< Build value from concrete number
    Value(size_t size, cst_t val); ///< Build value from concrete value
    Value& operator=(const Value& other) = default; ///< Copy assignment
    Value& operator=(Value&& other) = default; ///< Move assignment
    ~Value() = default;
public:
    Value& operator=(const Expr& e); ///< Build Value from expression
    Value& operator=(Expr&& e); ///< Build Value from expression
    Value& operator=(const Number& n); ///< Build Value from number
    Value& operator=(Number&& n); ///< Build Value from number
    void set_cst(size_t size, cst_t val); ///< Build Value from constant and size in bits
    void set_none(); // Set to NONE (no value)
public:
    const Expr& expr() const;
    const Number& number() const;
    size_t size() const;
public:
    bool is_abstract() const;
    bool is_none() const;
public:
    bool is_symbolic(const VarContext&) const;
    bool is_concolic(const VarContext&) const;
    bool is_concrete(const VarContext&) const;
public:
    Expr as_expr() const; ///< Return the value as an abstract expression
    cst_t as_int() const; ///< Return the value as a concrete signed value
    ucst_t as_uint() const; /// Return the value as a concrete unsigned value
    cst_t as_int(const VarContext&) const; ///< Return the value as a concrete signed value
    ucst_t as_uint(const VarContext&) const; /// Return the value as a concrete unsigned value
    const Number& as_number() const; ///< Return the value as a concrete number
    const Number& as_number(const VarContext&) const; ///< Return the value as a concrete number
// In-place operators
public:
    // TODO: doc
    void set_neg(const Value& n);
    void set_not(const Value& n);
    void set_add(const Value& n1, const Value& n2);
    void set_sub(const Value& n1, const Value& n2);
    void set_mul(const Value& n1, const Value& n2);
    void set_xor(const Value& n1, const Value& n2);
    void set_shl(const Value& n1, const Value& n2);
    void set_shr(const Value& n1, const Value& n2);
    void set_sar(const Value& n1, const Value& n2);
    void set_and(const Value& n1, const Value& n2);
    void set_or(const Value& n1, const Value& n2);
    void set_sdiv(const Value& n1, const Value& n2);
    void set_div(const Value& n1, const Value& n2);
    void set_extract(const Value& n, unsigned int high, unsigned int low);
    void set_concat(const Value& n1, const Value& n2);
    // Write n2 over n1 starting from lowest byte 'lb'
    void set_overwrite(const Value& n1, const Value& n2, int lb);
    void set_popcount(int dest_size, const Value& n);
    void set_zext(int ext_size, const Value& n);
    void set_sext(int ext_size, const Value& n);
    void set_rem(const Value& n1, const Value& n2);
    void set_srem(const Value& n1, const Value& n2);
    void set_less_than(const Value& n1, const Value& n2, size_t size);
    void set_lessequal_than(const Value& n1, const Value& n2, size_t size);
    void set_sless_than(const Value& n1, const Value& n2, size_t size);
    void set_slessequal_than(const Value& n1, const Value& n2, size_t size);
    void set_equal_to(const Value& n1, const Value& n2, size_t size);
    void set_notequal_to(const Value& n1, const Value& n2, size_t size);
    void set_carry(const Value& n1, const Value& n2, size_t size);
    void set_scarry(const Value& n1, const Value& n2, size_t size);
    void set_sborrow(const Value& n1, const Value& n2, size_t size);
    void set_subpiece(const Value& n1, const Value& n2, size_t size);
    void set_bool_negate(const Value& n, size_t size);
    void set_bool_and(const Value& n1, const Value& n2, size_t size);
    void set_bool_or(const Value& n1, const Value& n2, size_t size);
    void set_bool_xor(const Value& n1, const Value& n2, size_t size);

    friend std::ostream& operator<<(std::ostream& os, const Value& val);
};

// Overloaded native operators
// TODO: rest of operators
Value operator+(const Value& left, const Value& right); ///< Add two values
Value operator+(const Value& left, cst_t right); ///< Add two values
Value operator+(cst_t left, const Value& right); ///< Add two values

Value operator-(const Value& left, const Value& right); ///< Subtract two values
Value operator-(const Value& left, cst_t right); ///< Subtract two values
Value operator-(cst_t left, const Value& right); ///< Subtract two values

Value operator*(const Value& left, const Value& right); ///< Multiply two values
Value operator*(const Value& left, cst_t right); ///< Multiply two values
Value operator*(cst_t left, const Value& right); ///< Multiply two values

Value extract(const Value& arg, unsigned long higher, unsigned long lower); ///< Extract bitfield from value

// Constraints
Constraint operator==(const Value& left, const Value& right); ///< Create equality constraint 
Constraint operator==(const Value& left, cst_t right); ///< Create equality constraint 
Constraint operator==(cst_t left, const Value& right); ///< Create equality constraint 

Constraint operator!=(const Value& left, const Value& right); ///< Create a not-equal constraint 
Constraint operator!=(const Value& left, cst_t right); ///< Create a not-equal constraint 
Constraint operator!=(cst_t left, const Value& right); ///< Create a not-equal constraint 

/** }/ */ // doxygen expression group

} // namespace maat
#endif