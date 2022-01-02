#include "expression.hpp"
#include "varcontext.hpp"
#include "exception.hpp"
#include <cstring>
#include "murmur3.h"
#include <algorithm>
#include <iostream>
#include <sstream>

namespace maat
{

ExprStatus operator|(ExprStatus s1, ExprStatus s2){
    if( s1 == ExprStatus::SYMBOLIC || s2 == ExprStatus::SYMBOLIC)
    {
        return ExprStatus::SYMBOLIC;
    }
    else if( s1 == ExprStatus::CONCOLIC || s2 == ExprStatus::CONCOLIC )
    {
        return ExprStatus::CONCOLIC;
    }
    return ExprStatus::CONCRETE;
}


/* Expression hashes
 * =================

In order to enabe quick equality checks between expressions, each
expression has a 32-bit hash that 'uniquely' identifies it (colisions
are estimated unlikely enough to be ignored).  

The hash is not computed at expression creation. Some benchmarks seemed
to indicate that it was increasing the creation time by about 80%. For
this reason, hashes are computed dynamically when needed. 

The current implementation uses the murmur3 hash function C implementation
available on https://github.com/PeterScott/murmur3.  

Hash computation:
Several util functions named "prepare_hash_with_<type>" enable to add data
to the input buffer, and the exprhash() function computes the hash of the
buffer contents.

*/
#define MAXLEN_HASH_IN 1024

/* Set of functions to add a value to be hashed in the hash input buffer
 * 'hash_in' and returns the number of bytes added */ 
inline int prepare_hash_with_i64(uint8_t* hash_in, int64_t val, int index=0)
{
     *(int64_t*)(hash_in+index) = val;
     return index + 8; 
}

inline int prepare_hash_with_str(uint8_t* hash_in, const std::string& str, int index=0)
{
    strncpy((char*)hash_in+index, str.data(), str.length());
    return index + str.length();
}

inline int prepare_hash_with_i32(uint8_t* hash_in, int32_t val, int index=0)
{
    *(int32_t*)(hash_in+index) = val;
     return (index + 4);
}

inline int prepare_hash_with_op(uint8_t* hash_in, Op op, int index=0)
{
    *((uint8_t*)((char*)hash_in+index)) = static_cast<uint8_t>(op);
    return index + 1; 
}
/* Hash the currently prepared buffer */ 
hash_t exprhash(void* hash_in, int len, uint32_t seed)
{
    unsigned char hash_out[4];
    MurmurHash3_x86_32(hash_in, len, seed, hash_out);
    return *((hash_t*)hash_out);
}


/* Implementation of Expr* classes */
ExprObject::ExprObject(ExprType t, size_t _size, bool _is_simp, Taint _t, ucst_t _tm):
    type(t),
    size(_size),
    _hashed(false),
    _hash(0),
    _simplified_expr(nullptr),
    _is_simplified(_is_simp),
    _status(ExprStatus::NOT_COMPUTED),
    _taint(_t),
    _concrete_ctx_id(-1),
    _taint_ctx_id(-1),
    _status_ctx_id(-1),
    _value_set_computed(false),
    _taint_mask(_tm),
    _concrete(_size)
{
    _value_set = ValueSet(_size);
}


bool ExprObject::is_type(ExprType t, Op op)
{
    if(op == Op::NONE)
    {
        return type == t;
    }
    else if(type == ExprType::UNOP)
    {
        return type == t && op == static_cast<ExprUnop*>(this)->op();
    }
    else if(type == ExprType::BINOP)
    {
        return type == t && op == static_cast<ExprBinop*>(this)->op();
    }
    else
        return false;
}

void ExprObject::make_tainted(ucst_t _tm)
{
    _taint = Taint::TAINTED;
    _taint_mask = _tm;
}

ucst_t ExprObject::taint_mask()
{
    return _taint_mask;
}

ucst_t ExprObject::as_uint()
{
    if (size > 64)
        throw expression_exception("as_uint() can not be called on expressions bigger than 64 bits");
    return cst_sign_trunc(size, concretize().cst_);
}

ucst_t ExprObject::as_uint(const VarContext& ctx)
{
    if (size > 64)
        throw expression_exception("as_uint() can not be called on expressions bigger than 64 bits");
    return cst_sign_trunc(size, concretize(&ctx).cst_);
}

cst_t ExprObject::as_int()
{
    if (size > 64)
        throw expression_exception("as_int() can not be called on expressions bigger than 64 bits");
    return concretize().cst_;
}

cst_t ExprObject::as_int(const VarContext& ctx)
{
    if (size > 64)
        throw expression_exception("as_int() can not be called on expressions bigger than 64 bits");
    return concretize(&ctx).cst_;
}

const maat::Number& ExprObject::as_number()
{
    return concretize();
}

const maat::Number& ExprObject::as_number(const VarContext& ctx)
{
    return concretize(&ctx);
}

fcst_t ExprObject::as_float()
{
    fcst_t res;
    if (size > 64)
        throw expression_exception("as_float() can not be called on expressions bigger than 64 bits");

    if( size == 32 )
    {
        int32_t concrete_32 = (int32_t)(concretize().cst_);
        float float_32 = (float)*((float*)&concrete_32);
        res = (fcst_t)float_32;
    }
    else if( size == 64 )
    {
        int64_t concrete_64 = (int64_t)(concretize().cst_);
        double double_64 = (double)*((double*)&concrete_64);
        res = (fcst_t)double_64;
    }
    else
    {
        throw expression_exception( Fmt()
                << "Unable to interpret expression of size " 
                << size << " as float value" 
                >> Fmt::to_str);
    }
    return res;
}

fcst_t ExprObject::as_float(const VarContext& ctx)
{
    fcst_t res;
    if (size > 64)
        throw expression_exception("as_float() can not be called on expressions bigger than 64 bits");

    if( size == 32 )
    {
        int32_t concrete_32 = (int32_t)(concretize(&ctx).cst_);
        float float_32 = (float)*((float*)&concrete_32);
        res = (fcst_t)float_32;
    }
    else if( size == 64 )
    {
        int64_t concrete_64 = (int64_t)(concretize(&ctx).cst_);
        double double_64 = (double)*((double*)&concrete_64);
        res = (fcst_t)double_64;
    }
    else
    {
        throw expression_exception( Fmt()
                << "Unable to interpret expression of size " 
                << size << " as float value" 
                >> Fmt::to_str);
    }
    return res;
}

void ExprObject::get_vars(std::set<std::string>& vars)
{
    if(type == ExprType::VAR)
    {
        vars.insert(static_cast<ExprVar*>(this)->name());
    }
    else
    {
        for(auto e : args)
            e->get_vars(vars);
    }
}

bool ExprObject::is_symbolic(const VarContext& ctx)
{
    return status(ctx) == ExprStatus::SYMBOLIC;
}

bool ExprObject::is_concrete(const VarContext& ctx)
{
    return status(ctx) == ExprStatus::CONCRETE;
}

bool ExprObject::is_concolic(const VarContext& ctx)
{
    return status(ctx) == ExprStatus::CONCOLIC;
}

bool ExprObject::already_simplified_by(int id)
{
    return _is_simplified && _simplifier_id == id;
}

bool ExprObject::eq(Expr other)
{
    return hash() == other->hash();
}

bool ExprObject::neq(Expr other)
{
    return hash() != other->hash();
}

bool ExprObject::inf(Expr e2)
{
    if( type != e2->type )
    {
        return type < e2->type;
    }
    else
    {
        switch(type)
        {
            case ExprType::CST: return cst() < e2->cst();
            case ExprType::VAR: return name().compare(e2->name()) > 0;
            case ExprType::MEM: return args[0] < e2->args[0];
            case ExprType::UNOP:
                return( op() < e2->op() || 
                        args[0]->inf(e2->args[0]));
            case ExprType::BINOP:
                if( op() == e2->op() )
                {
                    if( args[0]->eq(e2->args[0]) )
                        return args[1]->inf(e2->args[1]);
                    else
                        return args[0]->inf(e2->args[0]); 
                }else
                    return op() < e2->op(); 
            case ExprType::EXTRACT:
            case ExprType::CONCAT:
                for( int i = 0; i < (this->is_type(ExprType::EXTRACT)? 3:2 ); i++)
                {
                    if( args[i]->eq(e2->args[i]) )
                        continue;
                    return args[i]->inf(e2->args[i]); 
                }
                return false;
            case ExprType::ITE:
                return (int)cond_op() < (int)e2->cond_op() ||
                       cond_left()->inf(e2->cond_left()) ||
                       cond_right()->inf(e2->cond_right()) ||
                       if_true()->inf(e2->if_true()) ||
                       if_false()->inf(e2->if_false());
            default:
                throw runtime_exception("ExprObject::inf() got unsupported ExprType");
        }
    }
}

bool ExprObject::contains_vars(std::set<std::string>& var_names)
{
    for( Expr arg : args )
    {
        if( arg->contains_vars(var_names))
        {
            return true;
        }
    }
    return false;
}

// ==================================
ExprCst::ExprCst(size_t s, cst_t c): ExprObject(ExprType::CST, s, true, Taint::NOT_TAINTED)
{
    if( s > 64 )
    {
        _concrete.set_mpz(c);
    }
    else
    {
        _concrete.set_cst(cst_sign_extend(s, c));
    }
}

ExprCst::ExprCst(size_t s, const std::string& value, int base): ExprObject(ExprType::CST, s, true, Taint::NOT_TAINTED)
{
    if( s <= 64 )
    {
        throw expression_exception("ExprCst(): called wrong constructor for constant of size 64 bits or less");
    }
    else
    {
        try
        {
            _concrete.set_mpz(value, base);
        }
        catch(const std::invalid_argument& e)
        {
            throw expression_exception(
                Fmt() << "ExprCst(): Invalid constant string and/or base: "
                << value << " (base " << std::dec << base << ")"
                >> Fmt::to_str
            );
        }
    }
}

ExprCst::ExprCst(const Number& value): ExprObject(ExprType::CST, value.size, true, Taint::NOT_TAINTED)
{
    _concrete = value;
}

hash_t ExprCst::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN];
    if (!_hashed)
    {
        if (size <= 64)
            _hash = exprhash(hash_in, prepare_hash_with_i64(hash_in, _concrete.get_ucst()), size);
        else
        {
            char _cst_string[500];  // Enough to store the string representation
                                    // of a number on 512 bits
            mpz_get_str(_cst_string, 36, _concrete.mpz_.get_mpz_t()); // Base 36 to be quicker
            _hash = exprhash(hash_in, prepare_hash_with_str(hash_in, _cst_string), size); 
        }
        _hashed = true;
    }
    return _hash;
}

cst_t ExprCst::cst()
{
    return _concrete.cst_;
}

void ExprCst::print(std::ostream& os)
{
    os << _concrete;
}

bool ExprCst::is_tainted(ucst_t mask)
{
  return _taint == Taint::TAINTED && (_taint_mask & mask );
}

const Number& ExprCst::concretize(const VarContext* ctx)
{
    return _concrete;
}

ExprStatus ExprCst::status(const VarContext& ctx)
{
    return ExprStatus::CONCRETE;
}

ValueSet& ExprCst::value_set()
{
    if (!_value_set_computed)
    {
        _value_set_computed = true;
        _value_set.set_cst(_concrete.get_ucst());
    }
    return _value_set;
}


// ==================================
ExprVar::ExprVar(size_t s, std::string n, Taint t): ExprObject(ExprType::VAR, s, true, t), _name(n)
{
    if (n.size() > ExprVar::max_name_length)
    {
        throw expression_exception("Variable name is too long!");
    }
    _value_set.set_all();
    _value_set_computed = true;
}

hash_t ExprVar::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN]; 

    if( !_hashed )
    {
        _hash = exprhash(hash_in, prepare_hash_with_str(hash_in, _name), size); 
        _hashed = true;
    }
    return _hash;
}

const std::string& ExprVar::name()
{
    return _name;
}
 
void ExprVar::print(std::ostream& os)
{
    os << _name;
}

bool ExprVar::is_tainted(ucst_t mask)
{
    return _taint == Taint::TAINTED && (mask & _taint_mask);
}

const Number& ExprVar::concretize(const VarContext* ctx)
{
    if( ctx == nullptr)
    {
        throw expression_exception("Cannot concretize symbolic variable without supplying a context");
    }
    else if( _concrete_ctx_id != ctx->id )
    {
         _concrete_ctx_id = ctx->id;
         _concrete = ctx->get_as_number(_name);
         _concrete.size = this->size; // Ajust size because VarContext doesn't keep size info
    }
    return _concrete;
}

ExprStatus ExprVar::status(const VarContext& ctx)
{
    if( ctx.id != _status_ctx_id )
    {
        _status = ctx.contains(_name)? ExprStatus::CONCOLIC : ExprStatus::SYMBOLIC;
        _status_ctx_id = ctx.id;
    }
    return _status;
}

ValueSet& ExprVar::value_set()
{
    return _value_set;
}

// ==================================
ExprMem::ExprMem(size_t s, Expr addr, unsigned int ac, Expr base): 
    ExprObject(ExprType::MEM, s, false),
    _access_count(ac),
    _unfolded(nullptr),
    _unfolded_with_forced_align(false),
    _base_expr(base)
{
    args.push_back(addr);
    _addr_value_set = addr->value_set();
}

ExprMem::ExprMem(size_t s, Expr addr, unsigned int ac, Expr base, ValueSet& vs):
    ExprObject(ExprType::MEM, s, false),
    _access_count(ac),
    _unfolded(nullptr),
    _unfolded_with_forced_align(false),
    _addr_value_set(vs),
    _base_expr(base)
{
    args.push_back(addr);
}

hash_t ExprMem::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed )
    {
        _hash = exprhash(
                    hash_in, 
                    prepare_hash_with_i32(hash_in, args[0]->hash(),
                    prepare_hash_with_i32(hash_in, _access_count)),
                    size);
        _hashed = true;
    }
    return _hash; 
}

void ExprMem::print(std::ostream& os)
{
    os  << "@" << std::dec << size << "[" << std::hex << args[0]
        << "]<" << std::dec << access_count() << ">";
}

bool ExprMem::is_tainted(ucst_t mask)
{
    // TODO: makes no real sense because tainted address doesn't mean 
    // that the expression in memory is tainted....
    if( _taint == Taint::NOT_COMPUTED )
    {
        _taint = args[0]->is_tainted() ? Taint::TAINTED : Taint::NOT_TAINTED;
        _taint_mask = 0xffffffffffffffff;
    }
    return _taint == Taint::TAINTED;
}

const Number& ExprMem::concretize(const VarContext* ctx)
{
    throw runtime_exception("concretize() not imlemented for memory expressions!");
}

ExprStatus ExprMem::status(const VarContext& ctx)
{
    return ExprStatus::SYMBOLIC;
}

unsigned int ExprMem::access_count()
{
    return _access_count;
}

Expr ExprMem::base_expr()
{
    return _base_expr;
}

ValueSet& ExprMem::value_set()
{
    _value_set.set_all(); // For now assume all possible values
    return _value_set;
}

// ==================================
ExprUnop::ExprUnop(Op o, Expr arg): ExprObject(ExprType::UNOP, arg->size), _op(o)
{
    args.push_back(arg);
}

hash_t ExprUnop::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed )
    {
        _hash = exprhash(
                    hash_in,
                    prepare_hash_with_i32(hash_in, args[0]->hash(),
                    prepare_hash_with_op(hash_in, _op)),
                    size);
        _hashed = true;
    }
    return _hash;
}

Op ExprUnop::op()
{
    return _op;
}

void ExprUnop::print(std::ostream& os)
{
    os << op_to_str(_op) << std::hex << args[0];
}

bool ExprUnop::is_tainted(ucst_t mask)
{
    if( _taint == Taint::NOT_COMPUTED )
    {
      _taint = args[0]->is_tainted() ? Taint::TAINTED : Taint::NOT_TAINTED; 
      switch(_op)
      {
            case Op::NEG:
            case Op::NOT: 
                _taint_mask = args[0]->taint_mask();
                break;
            default:
                throw runtime_exception("Missing case in ExprUnop::is_tainted()");
        }
    }
    return _taint == Taint::TAINTED  && (_taint_mask & mask );
}

const Number& ExprUnop::concretize(const VarContext* ctx)
{
    if( ctx != nullptr && _concrete_ctx_id == ctx->id )
        return _concrete;
    else
    {
        const Number& n = (ctx != nullptr)? args[0]->as_number(*ctx) : args[0]->as_number();
        switch(_op)
        {
            case Op::NEG:
                _concrete.set_neg(n);
                break;
            case Op::NOT:
                _concrete.set_not(n);
                break;
            default:
                throw runtime_exception("Missing case in ExprUnop::concretize()");
        }
    }
    if( ctx != nullptr )
    {
        _concrete_ctx_id = ctx->id; 
    }
    return _concrete;
}

ExprStatus ExprUnop::status(const VarContext& ctx)
{
    if( ctx.id != _status_ctx_id )
    {
        _status = args[0]->status(ctx);
        _status_ctx_id = ctx.id;
    }
    return _status;
}

ValueSet& ExprUnop::value_set()
{
    if( _value_set_computed ){
        return _value_set;
    }
    // Not yet computed
    ValueSet& arg_vs = args[0]->value_set();
    switch(_op)
    {
        case Op::NEG:
            _value_set.set_neg(arg_vs);
            break;
        case Op::NOT:
            _value_set.set_not(arg_vs);
            break;
        default:
            throw runtime_exception("ExprUnop::value_set(): got unexpected Op");
    }
    _value_set_computed = true;
    return _value_set;
}

// ==================================
ExprBinop::ExprBinop(Op o, Expr left, Expr right): ExprObject(ExprType::BINOP, left->size), _op(o)
{
    if(
        left->size != right->size
        and o != Op::SHR
        and o != Op::SHL
        and o != Op::SAR
    )
    {
        throw expression_exception(Fmt() 
            << "Cannot use binary operator on expressions of different sizes (got "
            << left->size << " and " << right->size << ")"
            >> Fmt::to_str);
    }
    args.push_back(left);
    args.push_back(right);
}

hash_t ExprBinop::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed )
    {
        _hash = exprhash(
                    hash_in,
                    prepare_hash_with_i32(hash_in, args[1]->hash(), 
                    prepare_hash_with_op(hash_in, _op,
                    prepare_hash_with_i32(hash_in, args[0]->hash()))),
                    size);
        _hashed = true;
    }
    return _hash; 
}
Op ExprBinop::op()
{
    return _op;
}

void ExprBinop::get_associative_args(Op o, std::vector<Expr>& vec)
{
    if( _op == o )
    {
        if( args[0]->is_type(ExprType::BINOP) && args[0]->op() == o )
            args[0]->get_associative_args(o, vec);
        else
            vec.push_back(args[0]);
        if( args[1]->is_type(ExprType::BINOP, o) )
            args[1]->get_associative_args(o, vec);
        else
            vec.push_back(args[1]);
    }
    /* No else statement
     * This function should never be called recursively when the operand
     * is not equal to the argument 'o'. The reason is that leaf expressions
     * (i.e that are not from the requested operator) cannot return shared_ptr
     * to themselves without losing the type information. So all checks are done
     * by the enclosing binary operations */ 
}

void ExprBinop::get_left_associative_args(Op o, std::vector<Expr>& vec, Expr& leftmost)
{
    if( _op == o )
    {
        vec.push_back(args[1]);
        if( args[0]->is_type(ExprType::BINOP, o))
            args[0]->get_left_associative_args(o, vec, leftmost );
        else
            leftmost = args[0];
    }
    else
    {
        leftmost = std::make_shared<ExprObject>(*this);
    }
}

void ExprBinop::print(std::ostream& os)
{
    os  << "(" << std::hex
        << args[0]
        << op_to_str(_op) << std::hex
        << args[1]
        << ")";
}

bool ExprBinop::is_tainted(ucst_t mask)
{
    bool prev_tainted = false;
    bool curr_tainted = false;

    if( _taint == Taint::NOT_COMPUTED )
    {
        if( args[0]->is_tainted() )
            _taint = Taint::TAINTED;
        else if( args[1]->is_tainted())
            _taint = Taint::TAINTED;
        else
            _taint = Taint::NOT_TAINTED;
        if( _taint == Taint::TAINTED ){
            // Update taint mask
            switch(_op)
            {
                case Op::ADD:
                {
                    // Propagate taint on addition
                    _taint_mask = 0;
                    prev_tainted = false;
                    curr_tainted = false;
                    for( ucst_t i = 0; i < size; i++ ){
                        curr_tainted = ((args[0]->taint_mask() & args[1]->taint_mask()) & (1UL << i));
                        if( curr_tainted || prev_tainted )
                            _taint_mask |= (1UL << i);
                        prev_tainted = curr_tainted;
                    }
                    break;
                }
                case Op::AND:
                case Op::OR:
                case Op::XOR:
                    _taint_mask = args[0]->taint_mask() | args[1]->taint_mask();
                    break;
                case Op::MUL:
                case Op::MULH:
                case Op::DIV:
                case Op::SDIV:
                case Op::MOD: 
                case Op::SMOD:
                case Op::SMULL:
                case Op::SMULH:
                    _taint_mask = 0xffffffffffffffff;
                    break;
                case Op::SHL:
                {
                    if( args[1]->is_type(ExprType::CST))
                        _taint_mask = args[0]->taint_mask() << (ucst_t)args[1]->cst();
                    else
                        _taint_mask = 0xffffffffffffffff;
                    break;
                }
                case Op::SAR:
                {
                    if( args[1]->is_type(ExprType::CST))
                        _taint_mask = ((cst_t)args[0]->taint_mask() >> (cst_t)args[1]->cst());
                    else
                        _taint_mask = 0xffffffffffffffff;
                    
                    break;
                }
                case Op::SHR:
                {
                    if( args[1]->is_type(ExprType::CST))
                        _taint_mask = args[0]->taint_mask() >> (ucst_t)args[1]->cst();
                    else
                        _taint_mask = 0xffffffffffffffff;
                    break;
                }
                default:
                    throw runtime_exception("Missing case in ExprBinop::is_tainted()");
            }
        }
    }
    return _taint == Taint::TAINTED  && (_taint_mask & mask );
}

const maat::Number& ExprBinop::concretize(const VarContext* ctx)
{
    if( ctx != nullptr && _concrete_ctx_id == ctx->id )
        return _concrete;
    else
    {
        const Number& n1 = (ctx != nullptr)? args[0]->as_number(*ctx) : args[0]->as_number();
        const Number& n2 = (ctx != nullptr)? args[1]->as_number(*ctx) : args[1]->as_number();
        switch(_op)
        {
            case Op::ADD:   _concrete.set_add(n1, n2); break;
            case Op::MUL:   _concrete.set_mul(n1, n2); break;
            case Op::SDIV:  _concrete.set_sdiv(n1, n2); break;
            case Op::XOR:   _concrete.set_xor(n1, n2); break;
            case Op::OR:    _concrete.set_or(n1, n2); break;
            case Op::SHL:   _concrete.set_shl(n1, n2); break;
            case Op::SHR:   _concrete.set_shr(n1, n2); break;
            case Op::SAR:   _concrete.set_sar(n1, n2); break;
            case Op::DIV:   _concrete.set_div(n1, n2); break;
            case Op::MOD:   _concrete.set_rem(n1, n2); break;
            case Op::SMOD:  _concrete.set_srem(n1, n2); break;
            case Op::AND:   _concrete.set_and(n1, n2); break;
            /* TODO, keep or remove that ??
            case Op::MULH:
            {
                if( size == 64 )
                    _concrete.cst = _mulh64to128(args[0]->as_uint(*ctx), args[1]->as_uint(*ctx));
                else
                    _concrete.cst = (ucst_t)(args[0]->as_uint(*ctx) * args[1]->as_uint(*ctx)) >> size ;
                break;
            }
            case Op::DIV: _concrete.cst = ((ucst_t)cst_sign_trunc(args[0]->size, args[0]->as_int(*ctx)) / (ucst_t)cst_sign_trunc(args[1]->size, args[1]->as_int(*ctx))); break;
            
            case Op::SMOD: _concrete.cst = (args[0]->as_int(*ctx) % args[1]->as_int(*ctx)); break;
            case Op::SMULL: _concrete.cst = (cst_t)((__int128_t)args[0]->as_int(*ctx) * args[1]->as_int(*ctx)); break;
            case Op::SMULH: _concrete.cst = (cst_t)(((__int128_t)args[0]->as_int(*ctx) * args[1]->as_int(*ctx)) >> size); break;
            */
            default:
                throw runtime_exception("Missing case in ExprBinop::concretize()");
        }
        /* TODO ??
        _concrete.cst = cst_sign_extend(size, _concrete.cst);
        */
    }
    if( ctx != nullptr )
    {
        _concrete_ctx_id = ctx->id;
    }
    return _concrete;
}

ValueSet& ExprBinop::value_set()
{
    // Already computed for this ctx
    if ( _value_set_computed )
    {
        return _value_set;
    }
    // Not yet computed
    ValueSet& arg0_vs = args[0]->value_set();
    ValueSet& arg1_vs = args[1]->value_set();
    switch( _op )
    {
        case Op::ADD:
            _value_set.set_add(arg0_vs, arg1_vs);
            break;
        case Op::MUL:
            _value_set.set_mul(arg0_vs, arg1_vs);
            break;
        case Op::MULH: 
            _value_set.set_mulh(arg0_vs, arg1_vs);
            break;
        case Op::DIV:
            _value_set.set_div(arg0_vs, arg1_vs);
            break;
        case Op::SDIV:
            _value_set.set_all(); // Not supported
        case Op::AND: 
            _value_set.set_and(arg0_vs, arg1_vs);
            break;
        case Op::OR:
            _value_set.set_or(arg0_vs, arg1_vs);
            break;
        case Op::XOR: 
            _value_set.set_xor(arg0_vs, arg1_vs);
            break;
        case Op::MOD:
            _value_set.set_mod(arg0_vs, arg1_vs);
            break;
        case Op::SMOD: 
            _value_set.set_smod(arg0_vs, arg1_vs);
            break;
        case Op::SMULL: 
            _value_set.set_all(); // Not supported
            break;
        case Op::SMULH:
            _value_set.set_all(); // Not supported
            break;
        case Op::SHL:
            _value_set.set_shl(arg0_vs, arg1_vs);
            break;
        case Op::SHR:
            _value_set.set_shr(arg0_vs, arg1_vs);
            break;
        case Op::SAR:
          _value_set.set_sar(arg0_vs, arg1_vs);
          break;
        default:
            throw runtime_exception("ExprUnop::value_set(): got unexpected Op");
    }
    _value_set_computed = true;
    return _value_set;
}

ExprStatus ExprBinop::status(const VarContext& ctx)
{
    if( ctx.id != _status_ctx_id )
    {
        _status = args[0]->status(ctx) | args[1]->status(ctx);
        _status_ctx_id = ctx.id;
    }
    return _status;
}

// ==================================
ExprExtract::ExprExtract(Expr arg, Expr higher, Expr lower) 
try : ExprObject(ExprType::EXTRACT, (ucst_t)higher->cst() - (ucst_t)lower->cst() + 1)
{
    if(!higher->is_type(ExprType::CST) || !lower->is_type(ExprType::CST))
    {
        throw expression_exception("Cannot create extract with bit parameters that are not constant expressions");
    }
    if( (ucst_t)higher->cst() < (ucst_t)lower->cst() )
    {
        throw expression_exception("Can not use Extract() with higher bit smaller than lower bit");
    }
    if( (ucst_t)higher->cst() >= arg->size )
    {
        throw expression_exception(Fmt() 
            << "Can not extract bit " 
            << higher->cst() << " from expression of size " 
            << arg->size 
            >> Fmt::to_str );
    }
    args.push_back(arg);
    args.push_back(higher);
    args.push_back(lower);
}
catch(const expression_exception& e)
{
    throw expression_exception(Fmt()
        << "Error while creating Extract expression: "
        << e.what()
        >> Fmt::to_str);
}

hash_t ExprExtract::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN];
    if(!_hashed){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[2]->hash(),
                    prepare_hash_with_i32(hash_in, args[1]->hash(),
                    prepare_hash_with_i32(hash_in, args[0]->hash()))), size);
        _hashed = true;
    }
    return _hash; 
}

void ExprExtract::print(std::ostream& os)
{
    os  << std::hex
        << args[0]
        << "[" << std::dec
        << args[1]
        << ":" << std::dec
        << args[2]
        << "]";
}

bool ExprExtract::is_tainted(ucst_t mask)
{
    if( _taint == Taint::NOT_COMPUTED )
    {
        if( args[0]->is_tainted() )
            _taint = Taint::TAINTED;
        else
            _taint = Taint::NOT_TAINTED;
        // Propagate taint
        _taint_mask = (args[0]->taint_mask() & cst_mask(args[1]->cst()+1)) >> args[2]->cst();
    }
    return _taint == Taint::TAINTED  && (_taint_mask & mask );
}


const maat::Number& ExprExtract::concretize(const VarContext* ctx)
{
    ucst_t high, low;
    ucst_t mask;
    
    if( ctx != nullptr && _concrete_ctx_id == ctx->id )
        return _concrete;
    
    high = (ctx != nullptr) ? args[1]->as_uint(*ctx) : args[1]->as_uint();
    low = (ctx != nullptr) ? args[2]->as_uint(*ctx) : args[2]->as_uint();
    if (ctx != nullptr)
    {
        _concrete.set_extract(args[0]->as_number(*ctx), high, low);
        _concrete_ctx_id = ctx->id;
    }
    else
    {
        _concrete.set_extract(args[0]->as_number(), high, low);
    }
    return _concrete;
}

ExprStatus ExprExtract::status(const VarContext& ctx)
{
    if( ctx.id != _status_ctx_id )
    {
        _status = args[0]->status(ctx);
        _status_ctx_id = ctx.id;
    }
    return _status;
}

ValueSet& ExprExtract::value_set(){
    // Already computed for this ctx
    if ( _value_set_computed )
    {
        return _value_set;
    }
    // Not yet computed
    _value_set.set_all();
    _value_set_computed = true;
    return _value_set;
}

// ==================================
ExprConcat::ExprConcat(Expr upper, Expr lower): ExprObject(ExprType::CONCAT, upper->size+lower->size)
{
    args.push_back(upper);
    args.push_back(lower);
}

hash_t ExprConcat::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed )
    {
        _hash = exprhash(
                    hash_in,
                    prepare_hash_with_i32(hash_in, args[1]->hash(), 
                    prepare_hash_with_i32(hash_in, args[0]->hash())),
                    size);
        _hashed = true;
    }
    return _hash; 
}

void ExprConcat::print(std::ostream& os)
{
    os  << "{" << std::hex
        << args[0] 
        << "," << std::hex
        << args[1] 
        << "}";
}

bool ExprConcat::is_tainted(ucst_t mask)
{
    if( _taint == Taint::NOT_COMPUTED )
    {
        if( args[0]->is_tainted() )
            _taint = Taint::TAINTED;
        else if( args[1]->is_tainted() )
            _taint = Taint::TAINTED;
        else
            _taint = Taint::NOT_TAINTED;
        // Propagate taint
        _taint_mask = args[1]->taint_mask() | (args[0]->taint_mask() << (ucst_t)args[1]->size);
    }
    return _taint == Taint::TAINTED  && (_taint_mask & mask );
}

const maat::Number& ExprConcat::concretize(const VarContext* ctx)
{
    cst_t upper, lower; 
    if( ctx != nullptr && _concrete_ctx_id == ctx->id )
        return _concrete;

    if (ctx != nullptr)
    {
        _concrete.set_concat(args[0]->as_number(*ctx), args[1]->as_number(*ctx)); 
        _concrete_ctx_id = ctx->id;
    }
    else
    {
        _concrete.set_concat(args[0]->as_number(), args[1]->as_number());
    }

    return _concrete;
}

ExprStatus ExprConcat::status(const VarContext& ctx)
{
    if( ctx.id != _status_ctx_id )
    {
        _status = args[0]->status(ctx) | args[1]->status(ctx);
        _status_ctx_id = ctx.id;
    }
    return _status;
}

ValueSet& ExprConcat::value_set()
{
    if( _value_set_computed )
    {
        return _value_set;
    }

    ValueSet& high_vs = args[0]->value_set();
    ValueSet& low_vs = args[1]->value_set();
    _value_set.set_concat(high_vs, low_vs);
    _value_set_computed = true;
    return _value_set;
}

// ==================================
ExprITE::ExprITE(Expr cond_left, ITECond cond_op, Expr cond_right, Expr if_true, Expr if_false): 
        ExprObject(ExprType::ITE, if_false->size),
        _cond_op(cond_op)
{
    if( if_true->size != if_false->size )
    {
        throw expression_exception(Fmt() 
            << "Cannot build ITE with expressions of different sizes (got " 
            << if_false->size << " and " << if_true->size << ")" 
            >> Fmt::to_str);
    }
    else if( cond_left->size != cond_right->size )
    {
        throw expression_exception(Fmt()
        << "Cannot build ITE with condition-expressions of different sizes (got "
        << cond_left->size << " and " << cond_right->size << ")"
        >> Fmt::to_str);
    }
    args.push_back(cond_left);
    args.push_back(cond_right);
    args.push_back(if_true);
    args.push_back(if_false);
}

hash_t ExprITE::hash()
{
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed )
    {
        _hash = exprhash(
                    hash_in,
                    prepare_hash_with_i32(hash_in, cond_left()->hash(), 
                    prepare_hash_with_i32(hash_in, (int)_cond_op,
                    prepare_hash_with_i32(hash_in, cond_right()->hash(),
                    prepare_hash_with_i32(hash_in, if_true()->hash(),
                    prepare_hash_with_i32(hash_in, if_false()->hash()))))),
                    size);
        _hashed = true;
    }
    return _hash; 
}

ITECond ExprITE::cond_op()
{
    return _cond_op;
}

Expr ExprITE::cond_left()
{
    return args[0];
}

Expr ExprITE::cond_right()
{
    return args[1];
}

Expr ExprITE::if_true()
{
    return args[2];
}

Expr ExprITE::if_false()
{
    return args[3];
}

void ExprITE::print(std::ostream& os)
{
    os  << "ITE[" << std::hex
        << cond_left()
        << ite_cond_to_string(_cond_op)
        << cond_right()
        << "]("
        << if_true()
        << ","
        << if_false()
        << ")";
}

bool ExprITE::is_tainted(ucst_t mask)
{
    if( _taint == Taint::NOT_COMPUTED )
    {
        if( if_true()->is_tainted() )
            _taint = Taint::TAINTED;
        else if( if_false()->is_tainted() )
            _taint = Taint::TAINTED;
        else
            _taint = Taint::NOT_TAINTED; // We don't consider the taint in the condition

        // Propagate taint
        _taint_mask = if_true()->taint_mask() | if_false()->taint_mask();
    }
    return _taint == Taint::TAINTED  && (_taint_mask & mask );
}

const maat::Number& ExprITE::concretize(const VarContext* ctx)
{
    if( ctx != nullptr && _concrete_ctx_id == ctx->id )
    {
        return _concrete;
    }
    else
    {
        if( ite_evaluate(cond_left(), _cond_op, cond_right(), ctx))
            _concrete = (ctx!=nullptr)? if_true()->as_number(*ctx) : if_true()->as_number();
        else
            _concrete = (ctx!=nullptr)? if_false()->as_number(*ctx) : if_false()->as_number();
        if( ctx != nullptr )
            _concrete_ctx_id = ctx->id;
    }
    return _concrete;
}

ValueSet& ExprITE::value_set()
{
    // Already computed for this ctx
    if ( _value_set_computed )
    {
        return _value_set;
    }
    // Not supported for ITE (should be the union of if_true() and if_false()
    _value_set.set_union(if_true()->value_set(), if_false()->value_set());
    _value_set_computed = true;
    return _value_set;
}

ExprStatus ExprITE::status(const VarContext& ctx)
{
    if( ctx.id != _status_ctx_id )
    {
        _status = args[0]->status(ctx) | args[1]->status(ctx) | args[2]->status(ctx) | args[3]->status(ctx);
        _status_ctx_id = ctx.id;
    }
    return _status;
}

// ==================================

/* Helper functions to create new expressions */
// Create from scratch  
Expr exprcst(size_t size, cst_t cst)
{
    return std::make_shared<ExprCst>(size, cst);
}

Expr exprcst(size_t size, std::string&& value, int base)
{
    return std::make_shared<ExprCst>(size, value, base);
}

Expr exprcst(const Number& value)
{
    return std::make_shared<ExprCst>(value);
}

Expr exprvar(size_t size, std::string name, Taint tainted)
{
    return std::make_shared<ExprVar>(size, name, tainted);
}

Expr exprmem(size_t size, Expr addr, unsigned int access_count, Expr base)
{
    return std::make_shared<ExprMem>(size, addr, access_count, base);
}

Expr exprmem(size_t size, Expr addr, unsigned int access_count, Expr base, ValueSet& addr_value_set)
{
    return std::make_shared<ExprMem>(size, addr, access_count, base, addr_value_set);
}

Expr exprbinop(Op op, Expr left, Expr right)
{
    return expr_canonize(std::make_shared<ExprBinop>(op, left, right));
} 

Expr extract(Expr arg, unsigned long higher, unsigned long lower)
{
    return std::make_shared<ExprExtract>(arg, exprcst(sizeof(cst_t)*8, higher), exprcst(sizeof(cst_t)*8, lower));
}

Expr extract(Expr arg, Expr higher, Expr lower)
{
    return std::make_shared<ExprExtract>(arg, higher, lower);
}

Expr concat(Expr upper, Expr lower)
{
    return expr_canonize(std::make_shared<ExprConcat>(upper, lower));
}

Expr ITE(Expr cond_left, ITECond c, Expr cond_right, Expr if_true, Expr if_false)
{
    return expr_canonize(std::make_shared<ExprITE>(cond_left, c, cond_right, if_true, if_false));
}

// Binary operations 
Expr operator+(Expr left, Expr right)
{
    return exprbinop(Op::ADD, left, right);
}

Expr operator+(Expr left, cst_t right )
{
    return exprbinop(Op::ADD, left, exprcst(left->size, right));
}

Expr operator+(cst_t left, Expr right)
{
    return exprbinop(Op::ADD, exprcst(right->size, left), right);
}

Expr operator-(Expr left, Expr right)
{
    return exprbinop(Op::ADD, left, std::make_shared<ExprUnop>(Op::NEG,right));
}

Expr operator-(Expr left, cst_t right )
{
    return left - exprcst(left->size, right);
}

Expr operator-(cst_t left, Expr right)
{
    return exprcst(right->size, left) - right;
}

Expr operator*(Expr left, Expr right)
{
    return exprbinop(Op::MUL, left, right);
}

Expr operator*(Expr left, cst_t right )
{
    return exprbinop(Op::MUL, left, exprcst(left->size, right));
}

Expr operator*(cst_t left, Expr right)
{
    return exprbinop(Op::MUL, exprcst(right->size, left), right);
}

Expr operator/(Expr left, Expr right)
{
    return exprbinop(Op::DIV, left, right);
}

Expr operator/(Expr left, cst_t right )
{
    return exprbinop(Op::DIV, left, exprcst(left->size, right));
}

Expr operator/(cst_t left, Expr right)
{
    return exprbinop(Op::DIV, exprcst(right->size, left), right);
}

Expr operator&(Expr left, Expr right)
{
    return exprbinop(Op::AND, left, right);
}

Expr operator&(Expr left, cst_t right )
{
    return exprbinop(Op::AND, left, exprcst(left->size, right));
}

Expr operator&(cst_t left, Expr right)
{
    return exprbinop(Op::AND, exprcst(right->size, left), right);
}

Expr operator|(Expr left, Expr right)
{
    return exprbinop(Op::OR, left, right);
}

Expr operator|(Expr left, cst_t right )
{
    return exprbinop(Op::OR, left, exprcst(left->size, right));
}

Expr operator|(cst_t left, Expr right)
{
    return exprbinop(Op::OR, exprcst(right->size, left), right);
}

Expr operator^(Expr left, Expr right)
{
    return exprbinop(Op::XOR, left, right);
}

Expr operator^(Expr left, cst_t right )
{
    return exprbinop(Op::XOR, left, exprcst(left->size, right));
}

Expr operator^(cst_t left, Expr right)
{
    return exprbinop(Op::XOR, exprcst(right->size, left), right);
}

Expr operator%(Expr left, Expr right)
{
    return exprbinop(Op::MOD, left, right);
}

Expr operator%(Expr left, cst_t right )
{
    return exprbinop(Op::MOD, left, exprcst(left->size, right));
}

Expr operator%(cst_t left, Expr right)
{
    return exprbinop(Op::MOD, exprcst(right->size, left), right);
}

Expr operator<<(Expr left, Expr right)
{
    return exprbinop(Op::SHL, left, right);
}

Expr operator<<(Expr left, cst_t right )
{
    return exprbinop(Op::SHL, left, exprcst(left->size, right));
}

Expr operator<<(cst_t left, Expr right)
{
    return exprbinop(Op::SHL, exprcst(right->size, left), right);
}

Expr operator>>(Expr left, Expr right)
{
    return exprbinop(Op::SHR, left, right);
}

Expr operator>>(Expr left, cst_t right )
{
    return exprbinop(Op::SHR, left, exprcst(left->size, right));
}

Expr operator>>(cst_t left, Expr right)
{
    return exprbinop(Op::SHR, exprcst(right->size, left), right);
}

Expr shl(Expr arg, Expr shift)
{
    return exprbinop(Op::SHL, arg, shift);
}

Expr shl(Expr arg, cst_t shift)
{
    return exprbinop(Op::SHL, arg, exprcst(arg->size,shift));
}

Expr shl(cst_t arg, Expr shift)
{
    return exprbinop(Op::SHL, exprcst(shift->size,arg), shift);
}

Expr shr(Expr arg, Expr shift)
{
    return exprbinop(Op::SHR, arg, shift);
}

Expr shr(Expr arg, cst_t shift)
{
    return exprbinop(Op::SHR, arg, exprcst(arg->size,shift));
}

Expr shr(cst_t arg, Expr shift)
{
    return exprbinop(Op::SHR, exprcst(shift->size,arg), shift);
}

Expr sar(Expr arg, Expr shift)
{
    return exprbinop(Op::SAR, arg, shift);
}

Expr sar(Expr arg, cst_t shift)
{
    return exprbinop(Op::SAR, arg, exprcst(arg->size,shift));
}

Expr sar(cst_t arg, Expr shift)
{
    return exprbinop(Op::SAR, exprcst(shift->size,arg), shift);
}

Expr sdiv(Expr left, Expr right)
{
    return exprbinop(Op::SDIV, left, right);
}

Expr sdiv(Expr left, cst_t right)
{
    return exprbinop(Op::SDIV, left, exprcst(left->size, right));
}

Expr sdiv(cst_t left, Expr right)
{
    return exprbinop(Op::SDIV, exprcst(right->size, left), right);
}

Expr smod(Expr left, Expr right)
{
    return exprbinop(Op::SMOD, left, right);
}

Expr smod(Expr left, cst_t right)
{
    return exprbinop(Op::SMOD, left, exprcst(left->size, right));
}

Expr smod(cst_t left, Expr right)
{
    return exprbinop(Op::SMOD, exprcst(right->size, left), right);
}

Expr mulh(Expr left, Expr right)
{
    return exprbinop(Op::MULH, left, right);
}

Expr mulh(Expr left, cst_t right)
{
    return exprbinop(Op::MULH, left, exprcst(left->size, right));
}

Expr mulh(cst_t left, Expr right)
{
    return exprbinop(Op::MULH, exprcst(right->size, left), right);
}

Expr smull(Expr left, Expr right)
{
    return exprbinop(Op::SMULL, left, right);
}

Expr smull(Expr left, cst_t right)
{
    return exprbinop(Op::SMULL, left, exprcst(left->size, right));
}

Expr smull(cst_t left, Expr right)
{
    return exprbinop(Op::SMULL, exprcst(right->size, left), right);
}

Expr smulh(Expr left, Expr right)
{
    return exprbinop(Op::SMULH, left, right);
}

Expr smulh(Expr left, cst_t right)
{
    return exprbinop(Op::SMULH, left, exprcst(left->size, right));
}

Expr smulh(cst_t left, Expr right)
{
    return exprbinop(Op::SMULH, exprcst(right->size, left), right);
}

// Unary operations
Expr operator~(Expr arg)
{
    return std::make_shared<ExprUnop>(Op::NOT, arg);
}

Expr operator-(Expr arg)
{
    return std::make_shared<ExprUnop>(Op::NEG, arg);
}

/* Printing operators */ 
std::ostream& operator<<(std::ostream& os, Expr e)
{
    os << std::hex; // Default, print constants in hex
    e->print(os);
    return os;
}

std::string op_to_str(Op op)
{
    switch(op)
    {
        case Op::ADD: return "+";
        case Op::MUL: return "*";
        case Op::MULH: return "*h ";
        case Op::SMULL: return "*lS ";
        case Op::SMULH: return "*hS ";
        case Op::DIV: return "/";
        case Op::SDIV: return "/S ";
        case Op::NEG: return "-";
        case Op::AND: return "&"; 
        case Op::OR: return "|";
        case Op::XOR: return "^";  
        case Op::SHL: return "<<";
        case Op::SHR: return ">>";
        case Op::SAR: return "A>>";
        case Op::NOT: return "~";
        case Op::MOD: return "%";
        case Op::SMOD: return "%S ";
        default: throw expression_exception("op_to_str(): got unknown operation!");
    }
}

/* ======= Canonize an expression ========== */

/* This function can be used to build an associative binary operation from 
 * an expression and a list of arguments.
 *  
 * This function is used when canonizing associative binary expressions where
 * arguments should be reordered and grouped by higher priority first. 
 * 
 * The function takes several arguments:
 *  - e : an expression that must be combined with the expressions in 'new_args'
 *        to build the new associative expression. It will be handled differently
 *        if it is a binop corresponding to 'op' or if it's a normal expression
 *  - op : the associative operation we build
 *  - new_args : a list of args that must be combined to 'e' with operation 'op'.
 *               the arguments are expected to be sorted from higher priority to
 *               lower priority
 * 
 * The function combines the arguments in the canonic way ! 
 * */
Expr build_associative_from_args(Expr e, Op op, std::vector<Expr>& new_args)
{
    Expr new_arg = nullptr, next_arg = nullptr;
    Expr res = nullptr;
    if( new_args.empty() ){
        return e;
    }
    if( !e->is_type(ExprType::BINOP, op)){
        // e is not a binop of type 'op', we stop here and combine all args by priority
        bool added_leaf = false;
        for( auto it = new_args.begin(); it != new_args.end(); it++ ){
            if( !added_leaf && (*it)->inf(e)){
                // Time to add args[0]
                next_arg = e;
                added_leaf = true;
                it = it-1; // Dont forget to stay on the same new_arg then
            }else{
                // Get next arg
                next_arg = *it;
            }
            if( res == nullptr){
                res = next_arg;
            }else{
                res = std::make_shared<ExprBinop>(op, res, next_arg);
            }
        }
        if( !added_leaf){
            res = std::make_shared<ExprBinop>(op, res, e);
        }
        return res;
    }else if( new_args.back()->inf(e->args[1]) ){
        // e is a binop of type 'op' and the smaller new argument is smaller than
        // the right side of 'e'.  So we insert the rest of the new arguments and
        // add the smaller one in the end
        new_arg = new_args.back();
        new_args.pop_back();
        res = build_associative_from_args(e, op, new_args);
        return std::make_shared<ExprBinop>(op, res, new_arg);
    }else{
        // e is a binop of type 'op' and the smaller new argument is bigger than
        // the right side of 'e'. So we need to insert all new args to the left side
        // and finally add the right one in the end (because smallest priority)
        res = build_associative_from_args(e->args[0], op, new_args);
        return std::make_shared<ExprBinop>(op, res, e->args[1]);
    }
}

Expr build_left_associative_from_args(Expr e, Op op, std::vector<Expr>& new_args)
{
    Expr new_arg = nullptr, next_arg = nullptr;
    Expr res = nullptr;
    if( new_args.empty() ){
        return e;
    }
    if( !e->is_type(ExprType::BINOP, op)){
        // e is not a binop of type 'op', we stop here and combine all args by priority
        res = e;
        for( auto it = new_args.begin(); it != new_args.end(); it++ ){
            res = std::make_shared<ExprBinop>(op, res, *it);
        }
        return res;
    }else if( new_args.back()->inf(e->args[1]) ){
        // e is a binop of type 'op' and the smaller new argument is smaller than
        // the right side of 'e'.  So we insert the rest of the new arguments and
        // add the smaller one in the end
        new_arg = new_args.back();
        new_args.pop_back();
        res = build_left_associative_from_args(e, op, new_args);
        return std::make_shared<ExprBinop>(op, res, new_arg);
    }else{
        // e is a binop of type 'op' and the smaller new argument is bigger than
        // the right side of 'e'. So we need to insert all new args to the left side
        // and finally add the right one in the end (because smallest priority)
        res = build_left_associative_from_args(e->args[0], op, new_args);
        return std::make_shared<ExprBinop>(op, res, e->args[1]);
    }
}


Expr expr_canonize(Expr e)
{
    std::vector<Expr> new_args;
    Expr e1, e2, leftmost; 
    Expr res;
    /* Binop */
    if( e->is_type(ExprType::BINOP) )
    {
        if( op_is_associative(e->op()) && op_is_symetric(e->op()))
        {
            // Associative and symetric -> re-order arguments
            // First get arguments list as long as the operator is used for
            // right side argument 
            if( e->args[1]->is_type(ExprType::BINOP, e->op()))
                e->args[1]->get_associative_args(e->op(), new_args);
            else
                new_args.push_back(e->args[1]);
            // Sort the arguments to call build_associative_from_args
            std::reverse(new_args.begin(), new_args.end()); // Invert vector to have the bigger ones first
            res = build_associative_from_args(e->args[0], e->op(), new_args);
            return res;
        }
        else if( op_is_left_associative(e->op()) && e->args[0]->is_type(ExprType::BINOP, e->op()))
        {
            // Left associative -> (a/b)/c -> (a/c)/b
            new_args.push_back(e->args[1]);
            res = build_left_associative_from_args(e->args[0], e->op(), new_args);
            return res;
        }
        // Canonize and return
        if( new_args.size() > 0 )
        {
            // Group higher args together first
            while( new_args.size() > 1 ){
                e1 = new_args.back();
                new_args.pop_back();
                e2 = new_args.back();
                new_args.pop_back();
                new_args.push_back(std::make_shared<ExprBinop>(e->op(), e1, e2));
            }
            return new_args.back();
        }
        else
        {
            // Nothing to do, return the same expression
            return e;
        }
    }
    /* Concat */
    else if( e->is_type(ExprType::CONCAT) )
    {
        if( e->args[0]->is_type(ExprType::CONCAT) )
            return concat(e->args[0]->args[0], concat(e->args[0]->args[1], e->args[1]));
        else
            return e;
    }
    else if( e->is_type(ExprType::ITE))
    {
        if( e->cond_op() == ITECond::EQ || e->cond_op() == ITECond::FEQ)
        {
            // Put bigger arg on the left
            if( e->cond_left()->inf(e->cond_right()))
            {
                // Swap cond left and right in args[0:1]
                Expr tmp = e->args[0];
                e->args[0] = e->args[1];
                e->args[1] = tmp;
            }
        }
        return e;
    }
    else
    {
        return e; 
    }
}

/* ====================================== */
/* Misc operations and functions on enums */ 
bool operator<(Op op1, Op op2)
{
    return static_cast<int>(op1) < static_cast<int>(op2);
}

bool op_is_symetric(Op op)
{
    return (op == Op::ADD || op == Op::AND || op == Op::MUL || op == Op::MULH ||
            op == Op::OR || op == Op::XOR || op == Op::SMULL ||
            op == Op::SMULH );
}

bool op_is_associative(Op op)
{
    return (op == Op::ADD || op == Op::AND || op == Op::MUL || op == Op::MULH ||
            op == Op::OR || op == Op::XOR || op == Op::SMULL ||
            op == Op::SMULH );
}

bool op_is_left_associative(Op op)
{
    return (op == Op::DIV);
}

bool op_is_multiplication(Op op)
{
    return (op == Op::MUL || op == Op::SMULL || op == Op::SMULH || op == Op::MULH);
}

bool op_is_distributive_over(Op op1, Op op2)
{
    switch(op1){
        case Op::MUL:
        case Op::MULH: 
        case Op::SMULL:
        case Op::SMULH: 
            return (op2 == Op::ADD);
        case Op::AND: return (op2 == Op::AND || op2 == Op::OR);
        case Op::OR: return (op2 == Op::OR || op2 == Op::AND);
        default: return false;
    }
}

bool operator<(ExprType t1, ExprType t2)
{
    return static_cast<int>(t1) < static_cast<int>(t2);
}

/* Constant manipulation */
cst_t cst_sign_trunc(size_t size, cst_t val)
{
    if( size == sizeof(cst_t)*8 )
        return val;
    else
        return val & (((ucst_t)1<<(ucst_t)size)-1);
}
cst_t cst_mask(size_t size)
{
    if( size == sizeof(cst_t)*8 )
        return -1;
    else
        return ((ucst_t)1<<size)-1; 
}

cst_t cst_sign_extend(size_t size, cst_t c)
{
    if( size == sizeof(cst_t)*8 )
    {
        return c;
    }
    else
    {
        /* Adjust the sign to whole variable  */
        if( ((ucst_t)1<<((ucst_t)size-1)) & (ucst_t)c )
        {
            // Negative, set higher bits to 1
            return ((ucst_t)0xffffffffffffffff<< size) | c; 
        }
        else
        {
            // Positive, set higher bits to 0
            return ((((ucst_t)1<<size)-1) & c);
        }
    }
}

// Clear upper bits to make the constant on 'size' bits
ucst_t cst_unsign_trunc(size_t size, cst_t c)
{
    if( size == sizeof(cst_t)*8)
    {
        return c;
    }
    return (ucst_t)cst_mask(size) & (ucst_t)c;
}

ucst_t cst_extract(ucst_t c, int high, int low)
{
    ucst_t mask = cst_mask(high+1); 
    return ((ucst_t)c & mask) >> (ucst_t)low;
}

ucst_t cst_concat(ucst_t c1, int size_c1, ucst_t c2, int size_c2)
{
    ucst_t res = (c1 << (ucst_t)size_c2) | c2;
    return cst_unsign_trunc(size_c1 + size_c2, res);
}

// Translate float to int -->! BITWISE, no conversion !<--
cst_t fcst_to_cst(size_t size, fcst_t f)
{
    cst_t res;
    if( size == 32 )
    {
        float as_float = (float)f;
        int32_t as_int = (int32_t)*((int32_t*)&as_float);
        res = (cst_t)as_int;
    }
    else if( size == 64 )
    {
        double as_double = (double)f;
        int64_t as_long = (int64_t)*((int64_t*)&as_double);
        res = (cst_t)as_long;
    }
    else
    {
        throw runtime_exception("fcst_to_cst(): got invalid size (neither 32 nor 64)");
    }
    return res;
}

ucst_t cst_gcd( ucst_t c1, ucst_t c2)
{
    ucst_t r;

    if( c1 == 0 )
        return c2;
    if( c2 == 0 )
        return c1;
        
    while( c2 != 0 )
    {
        r = c1 % c2;
        c1 = c2;
        c2 = r;
    }
    return c1;
}

ucst_t cst_lcm( ucst_t c1, ucst_t c2)
{
    return (c1*c2) / cst_gcd(c1, c2);
}


// MISC
std::string ite_cond_to_string(ITECond c)
{
    switch(c)
    {
        case ITECond::FEQ:
        case ITECond::EQ: return "==";
        case ITECond::FLT:
        case ITECond::SLT:
        case ITECond::LT: return "<";
        case ITECond::FLE:
        case ITECond::SLE:
        case ITECond::LE: return "<=";
        default: throw runtime_exception("ite_cond_to_string(): got unknown ITECond");
    }
}

bool ite_evaluate(Expr l, ITECond cond, Expr r, const VarContext* ctx)
{
    switch (cond)
    {
        case ITECond::EQ: return l->as_uint(*ctx) == r->as_uint(*ctx);
        case ITECond::LT: return l->as_uint(*ctx) < r->as_uint(*ctx);
        case ITECond::LE: return l->as_uint(*ctx) <= r->as_uint(*ctx);
        case ITECond::FEQ: return l->as_float(*ctx) == r->as_float(*ctx);
        case ITECond::FLE: return l->as_float(*ctx) <= r->as_float(*ctx);
        case ITECond::FLT: return l->as_float(*ctx) < r->as_float(*ctx);
        case ITECond::SLT: return l->as_int(*ctx) < r->as_int(*ctx);
        case ITECond::SLE: return l->as_int(*ctx) <= r->as_int(*ctx);
        default: throw runtime_exception("ite_evaluate(): got unknown ITECond");
    }
}

} // namespace maat
