#ifndef MAAT_VALUE_H
#define MAAT_VALUE_H

#include "expression.hpp"
#include "number.hpp"

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
    Value& operator=(const Value& other) = default; ///< Copy assignment
    Value& operator=(Value&& other) = default; ///< Move assignment
    ~Value() = default;
public:
    Value& operator=(const Expr& e); ///< Build Value from expression
    Value& operator=(Expr&& e); ///< Build Value from expression
    Value& operator=(const Number& n); ///< Build Value from number
    Value& operator=(Number&& n); ///< Build Value from number
    void set_cst(size_t size, cst_t val); ///< Build Value from constant and size in bits
public:
    Expr& expr();
    const Number& number() const;
    size_t size() const;
public:
    bool is_abstract() const;
    bool is_none() const;
public:
    bool is_symbolic(const VarContext&) const;
    bool is_concolic(const VarContext&) const;
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
    void set_neg(Value& n);
    void set_not(Value& n);
    void set_add(Value& n1, Value& n2);
    void set_sub(Value& n1, Value& n2);
    void set_mul(Value& n1, Value& n2);
    void set_xor(Value& n1, Value& n2);
    void set_shl(Value& n1, Value& n2);
    void set_shr(Value& n1, Value& n2);
    void set_sar(Value& n1, Value& n2);
    void set_and(Value& n1, Value& n2);
    void set_or(Value& n1, Value& n2);
    void set_sdiv(Value& n1, Value& n2);
    void set_div(Value& n1, Value& n2);
    void set_extract(Value& n, unsigned int high, unsigned int low);
    void set_concat(Value& n1, Value& n2);
    // Write n2 over n1 starting from lowest byte 'lb'
    void set_overwrite(Value& n1, Value& n2, int lb);
    void set_popcount(int dest_size, Value& n);
    void set_zext(int ext_size, Value& n);
    void set_sext(int ext_size, Value& n);
    void set_rem(Value& n1, Value& n2);
    void set_srem(Value& n1, Value& n2);
    void set_less_than(Value& n1, Value& n2, size_t size);
    void set_lessequal_than(Value& n1, Value& n2, size_t size);
    void set_sless_than(Value& n1, Value& n2, size_t size);
    void set_slessequal_than(Value& n1, Value& n2, size_t size);
    void set_equal_to(Value& n1, Value& n2, size_t size);
    void set_notequal_to(Value& n1, Value& n2, size_t size);
};

// TODO: overloaded native operators

/** }/ */ // doxygen expression group

} // namespace maat
#endif