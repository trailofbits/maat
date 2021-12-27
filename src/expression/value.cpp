#include "value.hpp"

namespace maat
{

Value::Value(): _expr(nullptr), type(Value::Type::NONE){}

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

const Number& Value::as_number() const
{
    return is_abstract()? _expr->as_number() : _number;
}

const Number& Value::as_number(const VarContext& ctx) const
{
    return is_abstract()? _expr->as_number(ctx) : _number;
}

Expr& Value::expr()
{
    return _expr;
}

const Number& Value::number() const
{
    return _number;
}

void Value::set_neg(Value& n)
{
    if (n.is_abstract())
        *this = -n.expr();
    else
    {
        _number.set_neg(n.number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_not(Value& n)
{
    if (n.is_abstract())
        *this = ~n.expr();
    else
    {
        _number.set_not(n.number());
        type = Value::Type::CONCRETE;
    }
}

void Value::set_add(Value& n1, Value& n2)
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

void Value::set_sub(Value& n1, Value& n2)
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

void Value::set_mul(Value& n1, Value& n2)
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

void Value::set_xor(Value& n1, Value& n2)
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

void Value::set_shl(Value& n1, Value& n2)
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

void Value::set_shr(Value& n1, Value& n2)
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

void Value::set_sar(Value& n1, Value& n2)
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

void Value::set_and(Value& n1, Value& n2)
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

void Value::set_or(Value& n1, Value& n2)
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

void Value::set_sdiv(Value& n1, Value& n2)
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

void Value::set_div(Value& n1, Value& n2)
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

void Value::set_extract(Value& n, unsigned int high, unsigned int low)
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

void Value::set_concat(Value& n1, Value& n2)
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

void Value::set_rem(Value& n1, Value& n2)
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

void Value::set_srem(Value& n1, Value& n2)
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
void Value::set_overwrite(Value& n1, Value& n2, int lb)
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

void Value::set_popcount(int dest_size, Value& n)
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

void Value::set_zext(int ext_size, Value& n)
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

void Value::set_sext(int ext_size, Value& n)
{
    if (n.is_abstract())
    {
        // Create mask
        Expr tmp;
        if (ext_size > 64)
        {
            // Need number
            Number num(ext_size);
            num.set_mask(ext_size);
            tmp = exprcst(num);
        }
        else
        {
            tmp = exprcst(ext_size, cst_mask(ext_size));
        }

        *this = ITE(
            extract(n.expr(), n.size()-1, n.size()-1),
            ITECond::EQ,
            exprcst(1,0),
            concat(
                exprcst(ext_size, 0),
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
void Value::set_less_than(Value& n1, Value& n2, size_t size)
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

void Value::set_lessequal_than(Value& n1, Value& n2, size_t size)
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

void Value::set_sless_than(Value& n1, Value& n2, size_t size)
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

void Value::set_slessequal_than(Value& n1, Value& n2, size_t size)
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

void Value::set_equal_to(Value& n1, Value& n2, size_t size)
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

void Value::set_notequal_to(Value& n1, Value& n2, size_t size)
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


} // namespace maat