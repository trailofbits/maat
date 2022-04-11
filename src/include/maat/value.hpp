#ifndef MAAT_VALUE_H
#define MAAT_VALUE_H

#include "maat/expression.hpp"
#include "maat/number.hpp"
#include "maat/constraint.hpp"
#include "maat/serializer.hpp"

namespace maat
{
/** \addtogroup expression
 * \{ */

/** A value is a wrapper class that represent data on a fixed number of bits.
The data can be either concrete, or abstract. The underlying implementation
uses the `Expr` and `Number` classes to represent abstract and concrete values.
*/
class Value: public serial::Serializable
{
public:
    enum class Type : uint8_t
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
    Value(size_t size, const std::string& val, int base=16); ///< Build value from string and base
    Value& operator=(const Value& other) = default; ///< Copy assignment
    Value& operator=(Value&& other) = default; ///< Move assignment
    virtual ~Value() = default;
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
    ucst_t as_uint() const; ///< Return the value as a concrete unsigned value
    fcst_t as_float() const; ///< Return the value as a concrete floating point value
    cst_t as_int(const VarContext&) const; ///< Return the value as a concrete signed value
    ucst_t as_uint(const VarContext&) const; /// Return the value as a concrete unsigned value
    fcst_t as_float(const VarContext&) const; ///< Return the value as a concrete floating point value
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
    void set_ITE(
        const Value& c1, ITECond cond, const Value& c2,
        const Value& if_true, const Value& if_false
    );
public:
    friend std::ostream& operator<<(std::ostream& os, const Value& val);
public:
    virtual uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

// Overloaded native operators
Value operator+(const Value& left, const Value& right); ///< Add two values
Value operator+(const Value& left, cst_t right); ///< Add two values
Value operator+(cst_t left, const Value& right); ///< Add two values

Value operator-(const Value& left, const Value& right); ///< Subtract two values
Value operator-(const Value& left, cst_t right); ///< Subtract two values
Value operator-(cst_t left, const Value& right); ///< Subtract two values

Value operator*(const Value& left, const Value& right); ///< Multiply two values
Value operator*(const Value& left, cst_t right); ///< Multiply two values
Value operator*(cst_t left, const Value& right); ///< Multiply two values

Value operator/(const Value& left, const Value& right); ///< Unsigned divide two values
Value operator/(const Value& left, cst_t right); ///< Unisgned divide two values
Value operator/(cst_t left, const Value& right); ///< Unisigned divide two values

Value operator&(const Value& left, const Value& right); ///< Logical AND between two values
Value operator&(const Value& left, cst_t right); ///< Logical AND between two values
Value operator&(cst_t left, const Value& right); ///< Logical AND between two values

Value operator|(const Value& left, const Value& right); ///< Logical OR between two values
Value operator|(const Value& left, cst_t right); ///< Logical OR between two values
Value operator|(cst_t left, const Value& right); ///< Logical OR between two values

Value operator^(const Value& left, const Value& right); ///< Logical XOR between two values
Value operator^(const Value& left, cst_t right); ///< Logical XOR between two values
Value operator^(cst_t left, const Value& right); ///< Logical XOR between two values

Value operator%(const Value& left, const Value& right); ///< Unsigned modulo
Value operator%(const Value& left, cst_t right); ///< Unsigned modulo
Value operator%(cst_t left, const Value& right); ///< Unsigned modulo

Value operator>>(const Value& left, const Value& right); ///< Logical shift right
Value operator>>(const Value& left, cst_t right); ///< Logical shift right
Value operator>>(cst_t left, const Value& right); ///< Logical shift right

Value operator<<(const Value& left, const Value& right); ///< Logical shift left
Value operator<<(const Value& left, cst_t right); ///< Logical shift left
Value operator<<(cst_t left, const Value& right); ///< Logical shift left

Value sar(const Value& arg, const Value& shift); ///< Arithmetic shift right
Value sar(const Value& arg, cst_t shift); ///< Arithmetic shift right
Value sar(cst_t arg, const Value& shift); ///< Arithmetic shift right

Value sdiv(const Value& left, const Value& right); ///< Signed divide two values
Value sdiv(const Value& left, cst_t right); ///< Signed divide two values
Value sdiv(cst_t left, const Value& right); ///< Signed divide two values

Value smod(const Value& val, const Value& mod); ///< Signed modulo
Value smod(const Value& val, cst_t mod); ///< Signed modulo
Value smod(cst_t val, const Value& mod); ///< Signed modulo

Value operator~(const Value& arg); ///< Negate an expression
Value operator-(const Value& arg); ///< Logical invert an expression

Value extract(const Value& arg, unsigned long higher, unsigned long lower); ///< Extract bitfield from value
Value concat(const Value& upper, const Value& lower); ///< Concatenate two values


// Constraints
Constraint operator==(const Value& left, const Value& right); ///< Equality constraint 
Constraint operator==(const Value& left, cst_t right); ///< Equality constraint 
Constraint operator==(cst_t left, const Value& right); ///< Equality constraint 

Constraint operator!=(const Value& left, const Value& right); ///< Not-equal constraint 
Constraint operator!=(const Value& left, cst_t right); ///< Not-equal constraint 
Constraint operator!=(cst_t left, const Value& right); ///< Not-equal constraint 

Constraint operator<(const Value& left, const Value& right); ///< Less-than constraint 
Constraint operator<(const Value& left, cst_t right); ///< Less-than constraint 
Constraint operator<(cst_t left, const Value& right); ///< Less-than constraint 

Constraint operator<=(const Value& left, const Value& right); ///< Less-or-equal constraint 
Constraint operator<=(const Value& left, cst_t right); ///< Less-or-equal constraint 
Constraint operator<=(cst_t left, const Value& right); ///< Less-or-equal constraint 

Constraint operator>(const Value& left, const Value& right); ///< Greater-than constraint 
Constraint operator>(const Value& left, cst_t right); ///< Greater-than constraint
Constraint operator>(cst_t left, const Value& right); ///< Greater-than constraint

Constraint operator>=(const Value& left, const Value& right); ///< Greater-or-equal constraint
Constraint operator>=(const Value& left, cst_t right); ///< Greater-or-equal constraint
Constraint operator>=(cst_t left, const Value& right); ///< Greater-or-equal constraint

/** }/ */ // doxygen expression group

} // namespace maat
#endif