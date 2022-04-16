#include "maat/value.hpp"

namespace maat
{

using serial::bits;

Value::Value(): _expr(nullptr), type(Value::Type::NONE){}

Value::Value(const Expr& expr)
{
    *this = expr;
}

Value::Value(const Number& number)
{
    *this = number;
}

Value::Value(size_t size, cst_t val)
{
    set_cst(size, val);
}

Value::Value(size_t size, const std::string& val, int base)
{
    Number n(size);
    n.set_mpz(val, base);
    *this = n;
}

Value& Value::operator=(const Expr& e)
{
    _expr = e;
    type = Value::Type::ABSTRACT;
    return *this;
}

Value& Value::operator=(Expr&& e)
{
    _expr = e;
    type = Value::Type::ABSTRACT;
    return *this;
}

Value& Value::operator=(const Number& n)
{
    _number = n;
    type = Value::Type::CONCRETE;
    return *this;
}

Value& Value::operator=(Number&& n)
{
    _number = n;
    type = Value::Type::CONCRETE;
    return *this;
}

void Value::set_cst(size_t size, cst_t val)
{
    _number = Number(size, val);
    type = Value::Type::CONCRETE;
}

void Value::set_none()
{
    type = Value::Type::NONE;
}

size_t Value::size() const
{
    if (is_abstract())
        return _expr->size;
    else
        return _number.size;
}

bool Value::is_abstract() const
{
    return type == Value::Type::ABSTRACT;
}


bool Value::is_none() const
{
    return type == Value::Type::NONE;
}

bool Value::is_symbolic(const VarContext& ctx) const
{
    return is_abstract() and _expr->is_symbolic(ctx);
}

bool Value::is_concolic(const VarContext& ctx) const
{
    return is_abstract() and _expr->is_concolic(ctx);
}

bool Value::is_concrete(const VarContext& ctx) const
{
    return not is_abstract() or _expr->is_concrete(ctx);
}

Expr Value::as_expr() const
{
    return is_abstract()? _expr : exprcst(_number);
}

cst_t Value::as_int() const
{
    return is_abstract()? _expr->as_int() : _number.get_cst();
}

cst_t Value::as_int(const VarContext& ctx) const
{
    return is_abstract()? _expr->as_int(ctx) : _number.get_cst();
}

ucst_t Value::as_uint() const
{
    return is_abstract()? _expr->as_uint() : _number.get_ucst();
}

ucst_t Value::as_uint(const VarContext& ctx) const
{
    return is_abstract()? _expr->as_uint(ctx) : _number.get_ucst();
}

fcst_t Value::as_float() const
{
    if (is_abstract())
        return  _expr->as_float();
    else
        throw expression_exception("Value::as_float(): not implemented for concrete values");
}

fcst_t Value::as_float(const VarContext& ctx) const
{
    if (is_abstract())
        return  _expr->as_float(ctx);
    else
        throw expression_exception("Value::as_float(): not implemented for concrete values");
}

const Number& Value::as_number() const
{
    return is_abstract()? _expr->as_number() : _number;
}

const Number& Value::as_number(const VarContext& ctx) const
{
    return is_abstract()? _expr->as_number(ctx) : _number;
}

const Expr& Value::expr() const
{
    return _expr;
}

const Number& Value::number() const
{
    return _number;
}

void Value::set_neg(const Value& n)
{
    if (n.is_abstract())
        *this = -n.expr();
    else
    {
        _number.set_neg(n.number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_not(const Value& n)
{
    if (n.is_abstract())
        *this = ~n.expr();
    else
    {
        _number.set_not(n.number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_add(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() + n2.as_expr();
    }
    else
    {
        _number.set_add(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_sub(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() - n2.as_expr();
    }
    else
    {
        _number.set_sub(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_mul(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() * n2.as_expr();
    }
    else
    {
        _number.set_mul(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_xor(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() ^ n2.as_expr();
    }
    else
    {
        _number.set_xor(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_shl(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() << n2.as_expr();
    }
    else
    {
        _number.set_shl(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_shr(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() >> n2.as_expr();
    }
    else
    {
        _number.set_shr(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_sar(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = sar(n1.as_expr(), n2.as_expr());
    }
    else
    {
        _number.set_sar(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_and(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() & n2.as_expr();
    }
    else
    {
        _number.set_and(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_or(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() | n2.as_expr();
    }
    else
    {
        _number.set_or(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_sdiv(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = sdiv(n1.as_expr(), n2.as_expr());
    }
    else
    {
        _number.set_sdiv(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_div(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() / n2.as_expr();
    }
    else
    {
        _number.set_div(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_extract(const Value& n, unsigned int high, unsigned int low)
{
    if (n.is_abstract())
    {
        *this = extract(n.as_expr(), high, low);
    }
    else
    {
        _number.set_extract(n.as_number(), high, low);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_concat(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = concat(n1.as_expr(), n2.as_expr());
    }
    else
    {
        _number.set_concat(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_rem(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = n1.as_expr() % n2.as_expr();
    }
    else
    {
        _number.set_rem(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_srem(const Value& n1, const Value& n2)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = smod(n1.as_expr(), n2.as_expr());
    }
    else
    {
        _number.set_srem(n1.as_number(), n2.as_number());
        type = Value::Type::CONCRETE;
    }
}

// Write n2 over n1 starting from lowest byte 'lb'
void Value::set_overwrite(const Value& n1, const Value& n2, int lb)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        // overwrite_expr_bits takes higher bit
        *this = overwrite_expr_bits(n1.as_expr(), n2.as_expr(), lb+n2.size()-1);
    }
    else
    {
        _number.set_overwrite(n1.as_number(), n2.as_number(), lb);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_popcount(int dest_size, const Value& n)
{
    if (n.is_abstract())
    {
        Expr e = n.as_expr();
        Expr tmp_res = maat::concat(exprcst(dest_size-1,0), maat::extract(e, 0, 0));
        // Add other bits
        for (int i = 1; i < e->size; i++)
        {
            tmp_res = tmp_res + maat::concat(exprcst(tmp_res->size-1, 0), maat::extract(e, i, i));
        }
        *this = tmp_res;
    }
    else
    {
        _number.set_popcount(dest_size, n.as_number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_zext(int ext_size, const Value& n)
{
    if (n.is_abstract())
    {
        *this = maat::concat(
                    exprcst(ext_size-n.size(), 0),
                    n.expr()
                );
    }
    else
    {
        _number.set_zext(ext_size, n.number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_sext(int ext_size, const Value& n)
{
    if (n.is_abstract())
    {
        // Create mask
        Expr tmp;
        if (ext_size > 64)
        {
            // Need number
            Number num(ext_size-n.size());
            num.set_mask(num.size);
            tmp = exprcst(num);
        }
        else
        {
            tmp = exprcst(ext_size-n.size(), cst_mask(ext_size));
        }

        *this = ITE(
            extract(n.expr(), n.size()-1, n.size()-1),
            ITECond::EQ,
            exprcst(1,0),
            concat(
                exprcst(ext_size-n.size(), 0),
                n.expr()
            ),
            concat(
                tmp,
                n.expr()
            )
        );
    }
    else
    {
        _number.set_sext(ext_size, n.number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_less_than(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(n1.as_expr(), ITECond::LT, n2.as_expr(),
                    exprcst(size,1),
                    exprcst(size,0)
                );
    }
    else
    {
        _number = Number(size, n1.as_number().less_than(n2.as_number()) ? 1 : 0 );
        type = Value::Type::CONCRETE;
    }
}

void Value::set_lessequal_than(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(n1.as_expr(), ITECond::LE, n2.as_expr(),
                    exprcst(size,1),
                    exprcst(size,0)
                );
    }
    else
    {
        _number = Number(size, n1.as_number().lessequal_than(n2.as_number()) ? 1 : 0 );
        type = Value::Type::CONCRETE;
    }
}

void Value::set_sless_than(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(n1.as_expr(), ITECond::SLT, n2.as_expr(),
                    exprcst(size,1),
                    exprcst(size,0)
                );
    }
    else
    {
        _number = Number(size, n1.as_number().sless_than(n2.as_number()) ? 1 : 0 );
        type = Value::Type::CONCRETE;
    }
}

void Value::set_slessequal_than(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(n1.as_expr(), ITECond::SLE, n2.as_expr(),
                    exprcst(size,1),
                    exprcst(size,0)
                );
    }
    else
    {
        _number = Number(size, n1.as_number().slessequal_than(n2.as_number()) ? 1 : 0 );
        type = Value::Type::CONCRETE;
    }
}

void Value::set_equal_to(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(n1.as_expr(), ITECond::EQ, n2.as_expr(),
                    exprcst(size,1),
                    exprcst(size,0)
                );
    }
    else
    {
        _number = Number(size, n1.as_number().equal_to(n2.as_number()) ? 1 : 0 );
        type = Value::Type::CONCRETE;
    }
}

void Value::set_notequal_to(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(n1.as_expr(), ITECond::EQ, n2.as_expr(),
                    exprcst(size,0),
                    exprcst(size,1)
                );
    }
    else
    {
        _number = Number(size, n1.as_number().equal_to(n2.as_number()) ? 0 : 1);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_carry(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        // carry is set if result is smaller than one of the operand
        Expr    in0 = n1.as_expr(),
                in1 = n2.as_expr();
        Expr tmp = in0 + in1;
        *this = ITE(
            tmp, 
            ITECond::LT,
            in0,
            exprcst(size, 1),
            ITE(
                tmp,
                ITECond::LT,
                in1,
                exprcst(size, 1),
                exprcst(size, 0)
            )
        );
    }
    else
    {
        Number tmp(n1.size());
        _number.size = size;
        const Number&   in0 = n1.as_number(),
                        in1 = n2.as_number();
        tmp.set_add(in0, in1);
        if (tmp.less_than(in0) or tmp.less_than(in1))
            _number.set_cst(1);
        else
            _number.set_cst(0);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_scarry(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        // signed carry (i.e overflow) is set if:
        // - (1) both operands are positive and result negative
        // - (2) both operands are negative and result postive
        Expr    in0 = n1.as_expr(),
                in1 = n2.as_expr();
        Expr tmp = in0 + in1;
        Expr zero = exprcst(in0->size, 0);
        *this = ITE(in0, ITECond::SLT, zero,
                    ITE(in1, ITECond::SLT, zero,
                        ITE(zero, ITECond::SLE, tmp,
                            exprcst(size, 1), // case (2)
                            exprcst(size, 0)
                        ),
                        exprcst(size, 0)
                    ),
                    ITE(zero, ITECond::SLE, in1,
                        ITE(tmp, ITECond::SLT, zero,
                            exprcst(size, 1), // case (1)
                            exprcst(size, 0)
                        ),
                        exprcst(size, 0)
                    )
                );
    }
    else
    {
        Number tmp(n1.size());
        _number.size = size;
        const Number&   in0 = n1.as_number(),
                        in1 = n2.as_number();
        tmp.set_add(in0, in1);
        Number zero(in0.size, 0);
        if (
            zero.slessequal_than(in0) and
            zero.slessequal_than(in1) and
            tmp.sless_than(zero)
        )
        {
            _number.set_cst(1);
        }
        else if (
            in0.sless_than(zero) and
            in1.sless_than(zero) and
            zero.slessequal_than(tmp)
        )
        {
            _number.set_cst(1);
        }
        else
        {
            _number.set_cst(0);
        }
        type = Value::Type::CONCRETE;
    }
}

void Value::set_sborrow(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        // signed borrow (i.e overflow) is set when the MSB of
        // both operands is different and result's MSB is the 
        // same as the one of the second operand
        Expr    in0 = n1.as_expr(),
                in1 = n2.as_expr();
        Expr tmp = in0 - in1;
        Expr zero = exprcst(in0->size, 0);
        *this = ITE(
                    in0, 
                    ITECond::SLT, 
                    zero,
                    ITE(
                        in1, 
                        ITECond::SLT,
                        zero,
                        exprcst(size, 0),
                        ITE(tmp, ITECond::SLT, zero,
                            exprcst(size,0),
                            exprcst(size,1) // in0 < 0, in1 >= 0, tmp >= 0
                        )
                    ),
                    ITE(
                        in1,
                        ITECond::SLT,
                        zero,
                        ITE(tmp, ITECond::SLT, zero,
                            exprcst(size,1), // in0 >= 0, in1 < 0, tmp < 0
                            exprcst(size,0)
                        ),
                        exprcst(size, 0)
                    )
                );
    }
    else
    {
        Number tmp;
        _number.size = size;
        const Number&   in0 = n1.as_number(),
                        in1 = n2.as_number();
        tmp.set_sub(in0, in1);
        Number zero(in0.size, 0);
        if (
            zero.slessequal_than(in0) and
            in1.sless_than(zero) and
            tmp.sless_than(zero)
        )
        {
            _number.set_cst(1);
        }
        else if (
            in0.sless_than(zero) and
            zero.slessequal_than(in1) and
            zero.slessequal_than(tmp)
        )
        {
            _number.set_cst(1);
        }
        else
        {
            _number.set_cst(0);
        }
        type = Value::Type::CONCRETE;
    }
}

void Value::set_subpiece(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        Expr    in0 = n1.as_expr(),
                in1 = n2.as_expr();
        int trunc = in1->as_uint()*8; // Number of bits to truncate

        if (size < (in0->size - trunc))
        {
            *this = extract(
                in0,
                trunc + size-1,
                trunc
            );
        }
        else if (size == (in0->size - trunc))
        {
            *this = extract(in0, in0->size-1, trunc);
        }
        else
        {
            *this = concat(
                exprcst(size - in0->size + trunc, 0),
                extract(
                    in0,
                    in0->size-1,
                    trunc
                )
            );
        }
    }
    else
    {
        const Number&   in0 = n1.as_number(),
                        in1 = n2.as_number();
        int trunc = in1.get_cst()*8; // Number of bits to truncate
        if (size < (in0.size - trunc))
        {
            _number.set_extract(
                in0,
                trunc + size-1,
                trunc
            );
        }
        else if (size == (in0.size - trunc))
        {
            _number.set_extract(
                in0,
                in0.size-1,
                trunc
            );
        }
        else
        {
            _number.set_extract(
                in0,
                in0.size-1,
                trunc
            );
            Number zero(size - _number.size, 0);
            _number.set_concat(
                zero,
                _number // Note: passing _number to _number method might crash??
            );
        }
        type = Value::Type::CONCRETE;
    }
}

void Value::set_bool_negate(const Value& n, size_t size)
{
    if (n.is_abstract())
    {
        *this = ITE(
                    n.expr(), 
                    ITECond::EQ,
                    exprcst(n.size(), 0),
                    exprcst(size, 1),
                    exprcst(size, 0)
                );
    }
    else
    {
        Number zero(n.size(), 0);
        _number.size = size;
        if (n.number().equal_to(zero))
            _number.set(1);
        else
            _number.set(0);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_bool_and(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(
                    n1.as_expr(), 
                    ITECond::EQ,
                    exprcst(n1.size(), 0),
                    exprcst(size, 0),
                    ITE(
                        n2.as_expr(),
                        ITECond::EQ,
                        exprcst(n2.size(), 0),
                        exprcst(size, 0),
                        exprcst(size, 1)
                    )
                );
    }
    else
    {
        Number zero(n1.size(), 0);
        Number zero1(n2.size(), 0);
        _number.size = size;
        if (
            n1.as_number().equal_to(zero)
            or n2.as_number().equal_to(zero1)
        )
            _number.set(0);
        else
            _number.set(1);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_bool_or(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(
                    n1.as_expr(), 
                    ITECond::EQ,
                    exprcst(n1.size(), 0),
                    ITE(
                        n2.as_expr(),
                        ITECond::EQ,
                        exprcst(n2.size(), 0),
                        exprcst(size, 0),
                        exprcst(size, 1)
                    ),
                    exprcst(size, 1)
                );
    }
    else
    {
        Number zero(n1.size(), 0);
        Number zero1(n2.size(), 0);
        _number.size = size;
        if (
            !n1.as_number().equal_to(zero)
            or !n2.as_number().equal_to(zero1)
        )
            _number.set(1);
        else
            _number.set(0);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_bool_xor(const Value& n1, const Value& n2, size_t size)
{
    if (n1.is_abstract() or n2.is_abstract())
    {
        *this = ITE(
                    n1.as_expr(), 
                    ITECond::EQ,
                    exprcst(n1.size(), 0),
                    ITE(
                        n2.as_expr(),
                        ITECond::EQ,
                        exprcst(n2.size(), 0),
                        exprcst(size, 0),
                        exprcst(size, 1)
                    ),
                    ITE(
                        n2.as_expr(),
                        ITECond::EQ,
                        exprcst(n2.size(), 0),
                        exprcst(size, 1),
                        exprcst(size, 0)
                    )
                );
    }
    else
    {
        Number zero(n1.size(), 0);
        Number zero1(n2.size(), 0);
        _number.size = size;
        if (
            (!n1.as_number().equal_to(zero) and n2.as_number().equal_to(zero1))
            or (n1.as_number().equal_to(zero) and !n2.as_number().equal_to(zero1))
        )
            _number.set(1);
        else
            _number.set(0);
        type = Value::Type::CONCRETE;
    }
}

void Value::set_ITE(
    const Value& c1, ITECond cond, const Value& c2,
    const Value& if_true, const Value& if_false
)
{
    bool is_true = true;
    if (c1.is_abstract() or c2.is_abstract()
        or if_true.is_abstract() or if_false.is_abstract())
    {
        *this = ITE(c1.as_expr(), cond, c2.as_expr(), if_true.as_expr(), if_false.as_expr());
    }
    else
    {
        switch (cond)
        {
            case ITECond::EQ: is_true = c1.as_number().equal_to(c2.as_number()); break;
            case ITECond::LE: is_true = c1.as_number().lessequal_than(c2.as_number()); break;
            case ITECond::LT: is_true = c1.as_number().less_than(c2.as_number()); break;
            case ITECond::SLT: is_true = c1.as_number().sless_than(c2.as_number()); break;
            case ITECond::SLE: is_true = c1.as_number().slessequal_than(c2.as_number()); break;
            default:
                throw expression_exception("Value::set_ITE(): got unimplemented ITE condition");
        }
        // Assign result depending on condition
        *this = is_true? if_true : if_false;
    }
}

bool Value::eq(const Value& other) const
{
    if (is_abstract())
        if (other.is_abstract())
            return as_expr()->eq(other.as_expr());
        else
            return false;
    else
        if (other.is_abstract())
            return false;
        else
            return as_number().equal_to(other.as_number());
}

std::ostream& operator<<(std::ostream& os, const Value& val)
{
    if (val.is_none())
        os << "<NONE>";
    else if (val.is_abstract())
        os << val._expr;
    else
        os << val._number;
    return os;
}


// Operators
Value operator+(const Value& left, const Value& right)
{
    Value res;
    res.set_add(left, right);
    return res;
}

Value operator+(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr()+right;
    else
    {
        Number n(left.size(), right);
        n.set_add(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator+(cst_t left, const Value& right)
{
    return right+left;
}

Value operator-(const Value& left, const Value& right)
{
    Value res;
    res.set_sub(left, right);
    return res;
}

Value operator-(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr()-right;
    else
    {
        Number n(left.size(), right);
        n.set_sub(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator-(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = left - right.expr();
    else
    {
        Number n(right.size(), left);
        n.set_sub(n, right.as_number());
        res = n;
    }
    return res;
}

Value operator*(const Value& left, const Value& right)
{
    Value res;
    res.set_mul(left, right);
    return res;
}

Value operator*(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr()*right;
    else
    {
        Number n(left.size(), right);
        n.set_mul(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator*(cst_t left, const Value& right)
{
    return right*left;
}

Value operator/(const Value& left, const Value& right)
{
    Value res;
    res.set_div(left, right);
    return res;
}

Value operator/(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr()/right;
    else
    {
        Number n(left.size(), right);
        n.set_div(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator/(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = left / right.expr();
    else
    {
        Number n(right.size(), left);
        n.set_div(n, right.as_number());
        res = n;
    }
    return res;
}

Value operator&(const Value& left, const Value& right)
{
    Value res;
    res.set_and(left, right);
    return res;
}

Value operator&(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr()&right;
    else
    {
        Number n(left.size(), right);
        n.set_and(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator&(cst_t left, const Value& right)
{
    return right&left;
}

Value operator|(const Value& left, const Value& right)
{
    Value res;
    res.set_or(left, right);
    return res;
}

Value operator|(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr() | right;
    else
    {
        Number n(left.size(), right);
        n.set_or(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator|(cst_t left, const Value& right)
{
    return right | left;
}

Value operator^(const Value& left, const Value& right)
{
    Value res;
    res.set_xor(left, right);
    return res;
}

Value operator^(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr() ^ right;
    else
    {
        Number n(left.size(), right);
        n.set_xor(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator^(cst_t left, const Value& right)
{
    return right ^ left;
}

Value operator%(const Value& left, const Value& right)
{
    Value res;
    res.set_rem(left, right);
    return res;
}

Value operator%(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr() % right;
    else
    {
        Number n(left.size(), right);
        n.set_rem(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator%(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = left % right.expr();
    else
    {
        Number n(right.size(), left);
        n.set_rem(n, right.as_number());
        res = n;
    }
    return res;
}

Value operator>>(const Value& left, const Value& right)
{
    Value res;
    res.set_shr(left, right);
    return res;
}

Value operator>>(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr() >> right;
    else
    {
        Number n(left.size(), right);
        n.set_shr(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator>>(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = left >> right.expr();
    else
    {
        Number n(right.size(), left);
        n.set_shr(n, right.as_number());
        res = n;
    }
    return res;
}

Value operator<<(const Value& left, const Value& right)
{
    Value res;
    res.set_shl(left, right);
    return res;
}

Value operator<<(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = left.expr() << right;
    else
    {
        Number n(left.size(), right);
        n.set_shl(left.as_number(), n);
        res = n;
    }
    return res;
}

Value operator<<(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = left << right.expr();
    else
    {
        Number n(right.size(), left);
        n.set_shl(n, right.as_number());
        res = n;
    }
    return res;
}

Value sar(const Value& arg, const Value& shift)
{
    Value res;
    res.set_sar(arg, shift);
    return res;
}

Value sar(const Value& arg, cst_t shift)
{
    Value res;
    if (arg.is_abstract())
        res = sar(arg.expr(), shift);
    else
    {
        Number n(arg.size(), shift);
        n.set_sar(arg.as_number(), n);
        res = n;
    }
    return res;
}

Value sar(cst_t arg, const Value& shift)
{
    Value res;
    if (shift.is_abstract())
        res = sar(arg, shift.expr());
    else
    {
        Number n(shift.size(), arg);
        n.set_sar(n, shift.as_number());
        res = n;
    }
    return res;
}

Value smod(const Value& left, const Value& right)
{
    Value res;
    res.set_srem(left, right);
    return res;
}

Value smod(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = smod(left.expr(), right);
    else
    {
        Number n(left.size(), right);
        n.set_srem(left.as_number(), n);
        res = n;
    }
    return res;
}

Value smod(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = smod(left, right.expr());
    else
    {
        Number n(right.size(), left);
        n.set_srem(n, right.as_number());
        res = n;
    }
    return res;
}

Value sdiv(const Value& left, const Value& right)
{
    Value res;
    res.set_sdiv(left, right);
    return res;
}

Value sdiv(const Value& left, cst_t right)
{
    Value res;
    if (left.is_abstract())
        res = sdiv(left.expr(), right);
    else
    {
        Number n(left.size(), right);
        n.set_sdiv(left.as_number(), n);
        res = n;
    }
    return res;
}

Value sdiv(cst_t left, const Value& right)
{
    Value res;
    if (right.is_abstract())
        res = sdiv(left, right.expr());
    else
    {
        Number n(right.size(), left);
        n.set_sdiv(n, right.as_number());
        res = n;
    }
    return res;
}

Value operator~(const Value& arg)
{
    Value res;
    if (arg.is_abstract())
        res = ~arg.expr();
    else
    {
        Number n;
        n.set_not(arg.as_number());
        res = n;
    }
    return res;
}

Value operator-(const Value& arg)
{
    Value res;
    if (arg.is_abstract())
        res = -arg.expr();
    else
    {
        Number n;
        n.set_neg(arg.as_number());
        res = n;
    }
    return res;
}

Value extract(const Value& arg, unsigned long higher, unsigned long lower)
{
    Value res;
    if (arg.is_abstract())
        res = extract(arg.expr(), higher, lower);
    else
    {
        Number n;
        n.set_extract(arg.as_number(), higher, lower);
        res = n;
    }
    return res;
}

Value concat(const Value& upper, const Value& lower)
{
    Value res;
    if (upper.is_abstract() or lower.is_abstract())
        res = concat(upper.as_expr(), lower.as_expr());
    else
    {
        Number n;
        n.set_concat(upper.as_number(), lower.as_number());
        res = n;
    }
    return res;
}

uid_t Value::class_uid() const
{
    return serial::ClassId::VALUE;
}

void Value::dump(Serializer& s) const
{
    s << bits(type);
    if (is_abstract())
        s << _expr;
    else
        s << _number;
}

void Value::load(Deserializer& d)
{
    d >> bits(type);
    if (type == Value::Type::ABSTRACT)
        d >> _expr;
    else
        d >> _number;
}


Constraint operator==(const Value& left, const Value& right)
{
    return left.as_expr() == right.as_expr();
}

Constraint operator==(const Value& left, cst_t right)
{
    return left.as_expr() == exprcst(left.size(), right);
}

Constraint operator==(cst_t left, const Value& right)
{
    return exprcst(right.size(), left) == right.as_expr();
}

Constraint operator!=(const Value& left, const Value& right)
{
    return left.as_expr() != right.as_expr();
}

Constraint operator!=(const Value& left, cst_t right)
{
    return left.as_expr() != exprcst(left.size(), right);
}

Constraint operator!=(cst_t left, const Value& right)
{
    return exprcst(right.size(), left) != right.as_expr();
}

Constraint operator<(const Value& left, const Value& right)
{
    return left.as_expr() < right.as_expr();
}

Constraint operator<(const Value& left, cst_t right)
{
    return left.as_expr() < exprcst(left.size(), right);
}

Constraint operator<(cst_t left, const Value& right)
{
    return exprcst(right.size(), left) < right.as_expr();
}

Constraint operator<=(const Value& left, const Value& right)
{
    return left.as_expr() <= right.as_expr();
}

Constraint operator<=(const Value& left, cst_t right)
{
    return left.as_expr() <= exprcst(left.size(), right);
}

Constraint operator<=(cst_t left, const Value& right)
{
    return exprcst(right.size(), left) <= right.as_expr();
}

Constraint operator>(const Value& left, const Value& right)
{
    return left.as_expr() > right.as_expr();
}

Constraint operator>(const Value& left, cst_t right)
{
    return left.as_expr() > exprcst(left.size(), right);
}

Constraint operator>(cst_t left, const Value& right)
{
    return exprcst(right.size(), left) > right.as_expr();
}

Constraint operator>=(const Value& left, const Value& right)
{
    return left.as_expr() >= right.as_expr();
}

Constraint operator>=(const Value& left, cst_t right)
{
    return left.as_expr() >= exprcst(left.size(), right);
}

Constraint operator>=(cst_t left, const Value& right)
{
    return exprcst(right.size(), left) >= right.as_expr();
}


} // namespace maat