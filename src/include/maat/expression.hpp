#ifndef EXPRESSION_H
#define EXPRESSION_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <ostream>
#include <map>
#include <set>
#include <variant>
#include "maat/exception.hpp"
#include "maat/number.hpp"
#include "maat/types.hpp"
#include "maat/serializer.hpp"

namespace maat
{

using maat::serial::Serializer;
using maat::serial::Deserializer;
using maat::serial::uid_t;

/** \defgroup expression Expressions
 * \brief Creating and manipulating abstract expressions.
 * 
 * This module implements all the classes representing abstract expressions
 * (as Abstract Syntax Trees), as well as many operators used to build new
 * expressions from existing ones. Abstract expressions are the most basic
 * object in Maat and are used everywhere: to represent register values, 
 * memory content, etc.
 * 
 * Abstract expressions should always be manipulated transparently through
 * ::Expr instances.
 * */

/** \addtogroup expression
 * \{ */

/// Different types of abstract expressions
enum class ExprType
{
    VAR, ///< Symbolic variable
    MEM, ///< Result of a memory read
    EXTRACT, ///< Bitfield extract
    CONCAT, ///< Concatenation of two expressions
    UNOP, ///< Unary arithmetic/logical operation 
    BINOP, ///< Binary arithmetic/logical operation
    ITE, ///< If-Then-Else expression
    CST, ///< Constant value
    NONE
};

/// Computes the priority of expression types. Used exclusively for expression canonization
bool operator<(ExprType t1, ExprType t2);

/** The conditions for ITE expressions */
enum class ITECond : uint8_t
{
    EQ, ///< Equal
    LT, ///< Unsigned Lesser Than
    LE, ///< Unsigned Lesser or Equal
    SLT, ///< Signed Lesser Than
    SLE, ///< Signed Lesser or Equal
    FEQ, ///< Equal (float)
    FLT, ///< Lesser Than (float)
    FLE ///< Lesser or Equal (float)
};

/** Types of operations that can be applied on expressions */
// TODO, remove THE MULH/SMULH ???
enum class Op : uint8_t
{
    ADD=0, ///< Addition
    MUL, ///< Unsigned multiply (lower half)
    MULH, ///< Unsigned multiply (higher half)
    SMULL, ///< Signed multiply (lower half)
    SMULH, ///< Signed multiply (higher half)
    DIV, ///< Unsigned divide
    SDIV, ///< Signed divide
    NEG, ///< Unary negation
    AND, ///< Logical AND
    OR, ///< Logical OR
    XOR, ///< Logical XOR
    SHL, ///< Logical shift left
    SHR, ///< Logical shift right
    SAR, ///< Arithmetic shift right
    MOD, ///< Unsigned modulo
    SMOD, ///< Signed modulo
    NOT, ///< Unary logical NOT
    NONE
};

std::string op_to_str(Op op);
bool operator<(Op op1, Op op2);
bool op_is_symetric(Op op);
bool op_is_associative(Op op);
bool op_is_left_associative(Op op);
bool op_is_distributive_over(Op op1, Op op2);
bool op_is_multiplication(Op op);

/** Symbolic status of an expression */
enum class ExprStatus: uint8_t
{
    CONCRETE, ///< Concrete expression (no symbolic variables)
    SYMBOLIC, ///< Symbolic expression (contains fully symbolic variables)
    CONCOLIC, ///< Concolic expression (contains symbolic variables that have a contextual concrete value)
    NOT_COMPUTED ///< Status was not yet computed
};

ExprStatus operator|(ExprStatus s1, ExprStatus s2);

/** Taint of an expression */
enum class Taint: uint8_t
{
    NOT_TAINTED = 0, ///< No bit is tainted
    TAINTED = 1, ///< At least one bit is tainted
    NOT_COMPUTED = 2 ///< Taint was not yet computed
};

/** Default mask to use when tainting expressions (all bits are tainted) */
static const uint64_t default_expr_taint_mask = 0xffffffffffffffff;

/** A value set is a strided interval used to represent the 
* possible range of values that an expression can take. The range is
* represented by lower and higher bounds that are unsigned values */
class ValueSet: public serial::Serializable
{
    protected:
    static const uint64_t vs_min  = 0; ///< Minimal lower bound
    static const uint64_t vs_max = 0xffffffffffffffff; ///< Maximal upper bound

    public:
    /** Size in bits of the expression whose range of possible values is
     * represented by this interval */
    int size;
    ucst_t min;  ///< Lower bound
    ucst_t max; ///< Upper bound
    ucst_t stride; ///< Stride

    ValueSet();
    ValueSet(size_t size);
    ValueSet(size_t size, ucst_t min, ucst_t max, ucst_t stride);
    virtual ~ValueSet() = default;

    void set(ucst_t min, ucst_t max, ucst_t stride);
    void set_cst(ucst_t val); ///< Set value set as just one constant value
    bool is_cst(); ///< Return true if the value set represents a constant (min==max) 
    void set_all(); ///< Make value set as big as possible (min = vs_min, max = vs_max)
    ucst_t range(); ///< Return the difference between max and min

    bool contains(ucst_t val);

    void set_not(ValueSet& vs);
    void set_neg(ValueSet& vs);
    void set_add(ValueSet& vs1, ValueSet& vs2);
    void set_or(ValueSet& vs1, ValueSet& vs2);
    void set_and(ValueSet& vs1, ValueSet& vs2);
    void set_xor(ValueSet& vs1, ValueSet& vs2);
    void set_mod(ValueSet& vs1, ValueSet& vs2);
    void set_smod(ValueSet& vs1, ValueSet& vs2);
    void set_shl(ValueSet& vs1, ValueSet& vs2);
    void set_shr(ValueSet& vs1, ValueSet& vs2);
    void set_sar(ValueSet& vs1, ValueSet& vs2);
    void set_mul(ValueSet& vs1, ValueSet& vs2);
    void set_mulh(ValueSet& vs1, ValueSet& vs2);
    void set_div(ValueSet& vs1, ValueSet& vs2);
    void set_concat(ValueSet& high, ValueSet& low);    
    void set_union(ValueSet& vs1, ValueSet& vs2);

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};


class ExprObject;
class VarContext;

/** \typedef Expr 
 * Shared pointer to an ExprObject instance. Expressions should be manipulated
 * only through Expr instances, the base class ExprObject and its child classes
 * should never be used directly. Using ::Expr enables to
 * seemlessly create and manipulate abstract expressions without worrying
 * about their scope and lifetime.
 */
typedef std::shared_ptr<ExprObject> Expr;

/** Expressions are represented in a generic way with the base class ExprObject.

The different types are implemented in separate classes inheriting from
ExprObject: ExprCst, ExprVar, ExprMem, etc. They have specific fields and
methods */
class ExprObject : public serial::Serializable
{
friend class ExprSimplifier;

protected:
    // ValueSet
    ValueSet _value_set;
    bool _value_set_computed;
    // Hash
    bool _hashed;
    hash_t _hash;
    // Simplification
    Expr _simplified_expr; ///< Pointer to the simplified version of this expression if it has already been simplified
    bool _is_simplified; ///< True if this expression is the result of a simplification
    int _simplifier_id; ///< ID of the simplifier that has simplified the expression
    // Taint
    Taint _taint;
    int _taint_ctx_id; ///< The ID of the VarContext that was used to compute the taint
    ucst_t _taint_mask; ///< The bits that are tainted in the expression (if _taint == TAINTED)
    // Concretization
    maat::Number _concrete; ///< The concrete value of the expression
    int _concrete_ctx_id = -1; ///< The ID of the VarContext that was used to concretize the expression
    // State
    ExprStatus _status;
    int _status_ctx_id; ///< The ID of the VarContext that was used to compute the epression status

public:
    /// Constructor
    ExprObject(
        ExprType type, size_t size, 
        bool _is_simp=false, 
        Taint _t = Taint::NOT_COMPUTED, 
        ucst_t _taint_mask=maat::default_expr_taint_mask
    );
    virtual ~ExprObject() = default;
protected:
    /// Return the concrete value of the expression evaluated in the context 'ctx'
    virtual const maat::Number& concretize(const VarContext* ctx = nullptr){throw runtime_exception("No implementation");};

public:
    ExprType type; ///< Expression type
    size_t size; ///< Expression size in bits
    std::vector<Expr> args; ///< Expression arguments (sub-expressions)

public:
    virtual void get_associative_args(Op op, std::vector<Expr>& vec){};
    virtual void get_left_associative_args(Op op, std::vector<Expr>& vec, Expr& leftmost){};

    /// Return true if the expression contains at least one of the given symbolic variable names
    bool contains_vars(std::set<std::string>& var_names);
    /// Fill 'var_names' with the names of symbolic variables contained in the expression
    void get_vars(std::set<std::string>& var_names);

    /// Return the expression hash. Every expression has a unique hash
    virtual hash_t hash(){throw runtime_exception("No implementation");};

    /** \brief Return true if the expression is of type 't'. If type is UNOP or BINOP,
     * also check if the operation is the one specified in 'op' */
    bool is_type(ExprType t, Op op=Op::NONE);

    /// Return true if at least one bit set in 'taint_mask' is tainted in the epression
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask){throw runtime_exception("No implementation");};
    /// Make the bits specified by 'taint_mask' tainted in the expression
    void make_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    /// Return the bit mask of tainted bits in the expression
    ucst_t taint_mask();

public:
    /** \brief Return the concrete value of the expression as an unsigned value. If the expression is concolic,
     * or is on more than 64 bits, this function will throw an 'expression_exception' */
    ucst_t as_uint();
    /** \brief Return the concrete value of the expression evaluated in the context 'ctx' as an unsigned value.
     * If the expression is on more than 64 bits this function will throw an 'expression_exception' */
    ucst_t as_uint(const VarContext& ctx);
    /** \brief Return the concrete value of the expression as an signed value. If the expression is concolic,
     * or is on more than 64 bits, this function will throw an 'expression_exception' */
    cst_t as_int();
    /** \brief Return the concrete value of the expression evaluated in the context 'ctx' as a signed value.
     * If the expression is on more than 64 bits this function will throw an 'expression_exception' */
    cst_t as_int(const VarContext& ctx);
    /** \brief Return the concrete value of the expression as a *maat::Number* instance */
    const maat::Number& as_number();
    /** \brief Return the concrete value of the expression as a *maat::Number instance.
     * If the expression is concolic this function will throw an 'expression_exception' */
    const maat::Number& as_number(const VarContext& ctx);
    /** \brief Return the concrete value of the expression as a floating point value. If the
     * expression is concolic, this function will throw an 'expression_exception' */
    fcst_t as_float();
    /// Return the concrete value of the expression evaluated in the context 'ctx' as a floating point value
    fcst_t as_float(const VarContext& ctx);

public:
    /** \brief Return the value set of the expression, which is the set of possible numerical
     * values it can take expressed as a strided interval */ 
    virtual ValueSet& value_set(){throw runtime_exception("No implementation");};

    /// Return the expression symbolic status 
    virtual ExprStatus status(const VarContext& ctx){throw runtime_exception("No implementation");};
    /// Return true if expression is symbolic
    virtual bool is_symbolic(const VarContext& ctx);
    /// Return true if expression is concrete
    bool is_concrete(const VarContext& ctx);
    /// Return true if expression is concolic
    virtual bool is_concolic(const VarContext& ctx);

    /* Simplification */
    bool already_simplified_by(int simplifier_id);

    /** \brief Checks equality between two expressions. The method returns true if
     * the expressions are syntactically equivalent, but doesn't test 
     * semantic equivalence */
    bool eq(Expr other);
    /// Opposite of the eq() method
    bool neq(Expr other);
    bool inf(Expr other);
    
    /* Accessors for child classes functions */
    virtual cst_t cst(){throw runtime_exception("No implementation");};
    virtual const std::string& name(){throw runtime_exception("No implementation");};
    virtual Op op(){throw runtime_exception("No implementation");};
    virtual cst_t mode(){throw runtime_exception("No implementation");};
    virtual unsigned int access_count(){throw runtime_exception("No implementation");};
    virtual Expr cond_left(){throw runtime_exception("No implementation");};
    virtual Expr cond_right(){throw runtime_exception("No implementation");};
    virtual Expr if_true(){throw runtime_exception("No implementation");};
    virtual Expr if_false(){throw runtime_exception("No implementation");};
    virtual ITECond cond_op(){throw runtime_exception("No implementation");};
    virtual Expr base_expr(){throw runtime_exception("No implementation");};

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);

public:
    // Printing
    virtual void print(std::ostream& out){out << "???";};
};

/* Child specialized classes */
/// Constant expression
class ExprCst: public ExprObject
{
protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprCst();
    /// Constructor for constants on 64 bits or less
    ExprCst(size_t size, cst_t cst);
    /// Constructor for constants on more than 64 bits. 
    ExprCst(size_t size, const std::string& value, int base=16);
    /// Constructor for constants directly from number
    ExprCst(const Number& value);
    virtual ~ExprCst() = default;
    cst_t cst();
    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

/// Abstract variable
class ExprVar: public ExprObject
{
private:
    std::string _name;
    static const int max_name_length = 1024;

protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprVar();
    /// Constructor
    ExprVar(size_t size, std::string name, Taint tainted=Taint::NOT_TAINTED);
    virtual ~ExprVar() = default;
    /// Get the variable name
    const std::string& name();
    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

class ExprMem: public ExprObject
{
friend class SymbolicMemEngine;
    
private:
    unsigned int _access_count;
    ValueSet _addr_value_set;
    Expr _base_expr;
    // Unfolding cache
    Expr _unfolded;
    bool _unfolded_with_forced_align;

protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprMem(size_t size, Expr addr, unsigned int access_count=0, Expr base=nullptr);
    ExprMem(size_t size, Expr addr, unsigned int access_count, Expr base, ValueSet& vs);
    virtual ~ExprMem() = default;
    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    unsigned int access_count();
    virtual ValueSet& value_set();
    Expr base_expr();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

/// Unary operation
class ExprUnop: public ExprObject
{
private:
    Op _op;
    
protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprUnop();
    /// Constructor
    ExprUnop(Op op, Expr arg);
    virtual ~ExprUnop() = default;
    Op op(); ///< Return the operation of the expression

    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

/// Binary operation
class ExprBinop: public ExprObject
{
private:
    Op _op;

protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprBinop();
    /// Constructor
    ExprBinop(Op op, Expr left, Expr right);
    virtual ~ExprBinop() = default;
    Op op(); ///< Return the operation of the expression

    virtual hash_t hash();
    virtual void get_associative_args(Op op, std::vector<Expr>& vec);
    virtual void get_left_associative_args(Op op, std::vector<Expr>& vec, Expr& leftmost);
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

/// Bitfield extract
class ExprExtract: public ExprObject{
  
protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprExtract();
    /// Constructor
    ExprExtract(Expr arg, Expr higher, Expr lower);
    virtual ~ExprExtract() = default;
    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

/// Concatenation of two expressions
class ExprConcat: public ExprObject{

protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprConcat();
    /// Constructor
    ExprConcat(Expr upper, Expr lower);
    virtual ~ExprConcat() = default;
    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};

/// If-Then-Else expression
class ExprITE: public ExprObject{
private:
    ITECond _cond_op;

protected:
    virtual const Number& concretize(const VarContext* ctx=nullptr);

public:
    ExprITE();
    /// Constructor
    ExprITE(Expr cond1, ITECond cond_op, Expr cond2, Expr if_true, Expr if_false);
    virtual ~ExprITE() = default;
    ITECond cond_op(); ///< Condition comparison operator (==, !=, <, <=, ...)
    Expr cond_left(); ///< Left member of condition
    Expr cond_right(); ///< Right member of condition
    Expr if_true(); ///< Value of the expression if the condition is true
    Expr if_false(); ///< Value of the expression if the condition is false

    virtual hash_t hash();
    virtual void print(std::ostream& out);
    virtual bool is_tainted(ucst_t taint_mask=maat::default_expr_taint_mask);
    virtual ExprStatus status(const VarContext& ctx);
    virtual ValueSet& value_set();

public:
    virtual uid_t class_uid() const;
    virtual void dump(Serializer& s) const;
    virtual void load(Deserializer& d);
};


/* Helper functions to create new expressions */
Expr exprcst(size_t size, cst_t cst); ///< Create new ExprCst instance
Expr exprcst(size_t size, std::string&& value, int base=16); ///< Create new ExprCst instance
Expr exprcst(const Number& value); ///< Create a new ExprCst instance
Expr exprvar(size_t size, std::string name, Taint tainted = Taint::NOT_TAINTED); ///< Create new ExprVar instance
Expr exprmem(size_t size, Expr addr, unsigned int access_count = 0xffffffff, Expr base=nullptr); ///< Create new ExprMem instance
Expr exprmem(size_t size, Expr addr, unsigned int access_count, Expr base, ValueSet& addr_value_set); ///< Create new ExprMem instance
Expr exprbinop(Op op, Expr left, Expr right);
Expr extract(Expr arg, unsigned long higher, unsigned long lower); ///< Create new ExprExtract instance
Expr extract(Expr arg, Expr higher, Expr lower); ///< Create new ExprExtract instance
Expr concat(Expr upper, Expr lower); ///< Create new ExprConcat instance
Expr ITE(Expr cond_left, ITECond cond_op, Expr cond_right, Expr if_true, Expr if_false); ///< Create new ExprITE instance

// Binary operations 
Expr operator+(Expr left, Expr right); ///< Add two expressions
Expr operator+(Expr left, cst_t right); ///< Add two expressions
Expr operator+(cst_t left, Expr right); ///< Add two expressions

Expr operator-(Expr left, Expr right); ///< Subtract two expressions
Expr operator-(Expr left, cst_t right); ///< Subtract two expressions
Expr operator-(cst_t left, Expr right); ///< Subtract two expressions

Expr operator*(Expr left, Expr right); ///< Unsigned multiply two expressions (lower bits of result)
Expr operator*(Expr left, cst_t right); ///< Unsigned multiply two expressions (lower bits of result)
Expr operator*(cst_t left, Expr right); ///< Unsigned multiply two expressions (lower bits of result)

Expr operator/(Expr left, Expr right); ///< Unsigned divide two expressions
Expr operator/(Expr left, cst_t right); ///< Unsigned divide two expressions
Expr operator/(cst_t left, Expr right); ///< Unsigned divide two expressions

Expr operator&(Expr left, Expr right); ///< Logical and between two expressions
Expr operator&(Expr left, cst_t right); ///< Logical and between two expressions
Expr operator&(cst_t left, Expr right); ///< Logical and between two expressions

Expr operator|(Expr left, Expr right); ///< Logical or between two expressions
Expr operator|(Expr left, cst_t right); ///< Logical or between two expressions
Expr operator|(cst_t left, Expr right); ///< Logical or between two expressions

Expr operator^(Expr left, Expr right); ///< Logical xor between two expressions
Expr operator^(Expr left, cst_t right); ///< Logical xor between two expressions
Expr operator^(cst_t left, Expr right); ///< Logical xor between two expressions

Expr operator%(Expr val, Expr mod);  ///< Unsigned modulo of two expressions
Expr operator%(Expr val, cst_t mod); ///< Unsigned modulo of two expressions
Expr operator%(cst_t val, Expr mod); ///< Unsigned modulo of two expressions

Expr operator<<(Expr val, Expr shift); ///< Shift an expression to the left
Expr operator<<(Expr val, cst_t shift); ///< Shift an expression to the left
Expr operator<<(cst_t val, Expr shift); ///< Shift an expression to the left

Expr operator>>(Expr val, Expr shift); ///< Shift an expression to the right
Expr operator>>(Expr val, cst_t shift); ///< Shift an expression to the right
Expr operator>>(cst_t val, Expr shift); ///< Shift an expression to the right

Expr shl(Expr arg, Expr shift); 
Expr shl(Expr arg, cst_t shift);
Expr shl(cst_t arg, Expr shift);

Expr shr(Expr arg, Expr shift);
Expr shr(Expr arg, cst_t shift);
Expr shr(cst_t arg, Expr shift);

Expr sar(Expr arg, Expr shift); ///< Arithmetic shift an expression to the right
Expr sar(Expr arg, cst_t shift); ///< Arithmetic shift an expression to the right
Expr sar(cst_t arg, Expr shift); ///< Arithmetic shift an expression to the right

Expr sdiv(Expr left, Expr right); ///< Signed divide two expressions
Expr sdiv(Expr left, cst_t right); ///< Signed divide two expressions
Expr sdiv(cst_t left, Expr right); ///< Signed divide two expressions

Expr smod(Expr val, Expr mod); ///< Signed modulo between two expressions
Expr smod(Expr val, cst_t mod); ///< Signed modulo between two expressions
Expr smod(cst_t val, Expr mod); ///< Signed modulo between two expressions

Expr mulh(Expr left, Expr right); ///< Unsigned multiply two expressions (higher bits of result)
Expr mulh(Expr left, cst_t right); ///< Unsigned multiply two expressions (higher bits of result)
Expr mulh(cst_t left, Expr right); ///< Unsigned multiply two expressions (higher bits of result)

Expr smull(Expr left, Expr right); ///< Signed multiply two expressions (lower bits of result)
Expr smull(Expr left, cst_t right); ///< Signed multiply two expressions (lower bits of result)
Expr smull(cst_t left, Expr right); ///< Signed multiply two expressions (lower bits of result)

Expr smulh(Expr left, Expr right); ///< Signed multiply two expressions (higher bits of result)
Expr smulh(Expr left, cst_t right); ///< Signed multiply two expressions (higher bits of result) 
Expr smulh(cst_t left, Expr right); ///< Signed multiply two expressions (higher bits of result)

Expr operator~(Expr arg); ///< Negate an expression
Expr operator-(Expr arg); ///< Logical invert an expression

std::ostream& operator<< (std::ostream& os, Expr e); ///< Print an expression in a stream

/* Canonizing expressions */
Expr expr_canonize(Expr e);
cst_t cst_sign_trunc(size_t size, cst_t val);
cst_t cst_mask(size_t size);
cst_t cst_sign_extend(size_t size, cst_t val);
ucst_t cst_unsign_trunc(size_t size, cst_t val);
ucst_t cst_gcd( ucst_t c1, ucst_t c2);
ucst_t cst_lcm( ucst_t c1, ucst_t c2);
ucst_t cst_extract(ucst_t c, int high, int low);
ucst_t cst_concat(ucst_t c_1, int size_c1, ucst_t c2, int size_c2);
cst_t fcst_to_cst(size_t size, fcst_t f);

/** \} */

// Utils functions
std::string ite_cond_to_string(ITECond c);
bool ite_evaluate(Expr left, ITECond cond, Expr right, const VarContext* ctx = nullptr);

/** \brief Returns the expression resulting from overwriting the bits *higher_bit*
 * to *higher_bit-new_expr.size()+1* with the expression 'new_expr'. **WARNING**:
 * 'new_expr' is expected to be small enough to overwrite 'old_expr' from the 
 * specified bit, no check for potential overflow is performed */
inline Expr __attribute__((always_inline)) overwrite_expr_bits(Expr old_expr, Expr new_expr, size_t higher_bit) 
{
    if (new_expr->size >= old_expr->size)
        return new_expr;
    else if(higher_bit == new_expr->size-1)
    {
        return concat(extract(old_expr, old_expr->size-1, higher_bit+1), new_expr);
    }
    else if(higher_bit == old_expr->size-1)
    {
        return concat(new_expr, extract(old_expr, higher_bit-new_expr->size, 0));
    }
    else
    {
        return concat(extract(old_expr, old_expr->size-1, higher_bit+1),
                      concat(new_expr, extract(old_expr, higher_bit-new_expr->size, 0))); 
    }
}

} // namespace maat

#endif
