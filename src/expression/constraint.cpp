#include "maat/constraint.hpp"
#include "maat/exception.hpp"
#include <iostream>
#include <set>
#include <algorithm>

namespace maat
{

ConstraintObject::ConstraintObject()
:left_expr(nullptr), right_expr(nullptr), left_constr(nullptr), right_constr(nullptr)
{}

ConstraintObject::ConstraintObject(ConstraintType t, Expr l, Expr r):
    type(t), left_expr(l), right_expr(r), 
    left_constr(nullptr), right_constr(nullptr)
{
    if( l->size != r->size )
    {
        throw constraint_exception(Fmt() 
            << "Can not create arithmetic constraint with expressions of different sizes (got "
            << l->size << " and " << r->size << ")"
            >> Fmt::to_str
        );
    }
    
    // TODO: do same transformations that we were doing on BISZ but on ITE expressions (check old code)
}

ConstraintObject::ConstraintObject(ConstraintType t, Constraint l, Constraint r):
    type(t), left_expr(nullptr), right_expr(nullptr), 
    left_constr(l), right_constr(r)
{}

Constraint ConstraintObject::invert()
{
    switch(type)
    {
        case ConstraintType::AND:
            return left_constr->invert() || right_constr->invert();
        case ConstraintType::OR:
            return left_constr->invert() && right_constr->invert();
        case ConstraintType::EQ:
            return left_expr != right_expr;
        case ConstraintType::NEQ:
            return left_expr == right_expr;
        case ConstraintType::LE:
            return left_expr > right_expr;
        case ConstraintType::LT:
            return left_expr >= right_expr;
        case ConstraintType::ULE:
            return ULT(right_expr, left_expr);
        case ConstraintType::ULT:
            return ULE(right_expr, left_expr);
        default:
            throw runtime_exception("ConstraintObject::invert() got unknown constraint type");
    }
}

const std::set<std::string>& ConstraintObject::contained_vars()
{
    // We already computed the set of contained vars
    if (_contained_vars.has_value())
        return *_contained_vars;

    // We need to compute the set of containted vars
    _contained_vars.emplace();
    switch (type)
    {
    case ConstraintType::EQ:
        case ConstraintType::NEQ:
        case ConstraintType::LE:
        case ConstraintType::LT:
        case ConstraintType::ULE:
        case ConstraintType::ULT:
            left_expr->get_vars(*_contained_vars);
            right_expr->get_vars(*_contained_vars);
            break;
        case ConstraintType::AND:
        case ConstraintType::OR:
            std::set_union(
                left_constr->contained_vars().begin(),
                left_constr->contained_vars().end(),
                right_constr->contained_vars().begin(),
                right_constr->contained_vars().end(),
                std::inserter(*_contained_vars, _contained_vars->begin())
            );
            break;
        default:
            throw runtime_exception("ConstraintObject::contained_vars() got unknown constraint type");
    }
    return *_contained_vars;
}

// Inspired from https://en.cppreference.com/w/cpp/algorithm/set_intersection
template<class InputIt1, class InputIt2>
bool fast_set_intersect(
    InputIt1 first1, InputIt1 last1,
    InputIt2 first2, InputIt2 last2
)
{
    while (first1 != last1 && first2 != last2) 
    {
        if (*first1 < *first2)
            ++first1;
        else  
        {
            if (*first2 == *first1)
                return true; // Same string, sets intersect!
            else
                ++first2;
        }
    }
    return false;
}

bool ConstraintObject::contains_vars(const std::set<std::string>& vars)
{
    const auto& s = contained_vars();
    return fast_set_intersect(
        s.begin(), s.end(),
        vars.begin(), vars.end()
    );
}

serial::uid_t ConstraintObject::class_uid() const
{
    return serial::ClassId::CONSTRAINT;
}

void ConstraintObject::dump(serial::Serializer& s) const
{
    // Note: we skip serializing the contained_vars set. It will just be recalculated
    // if contained_vars() is called
    s << serial::bits(type) << left_expr << right_expr << left_constr << right_constr;
}

void ConstraintObject::load(serial::Deserializer& d)
{
    // Note: we skip deserializing the contained_vars set. It will just be recalculated
    // if contained_vars() is called
    d >> serial::bits(type) >> left_expr >> right_expr >> left_constr >> right_constr; 
}


std::ostream& operator<<(std::ostream& os, const Constraint& constr)
{
    switch(constr->type)
    {
        case ConstraintType::AND:
            os << "(" << constr->left_constr << " && " << constr->right_constr << ")"; break;
        case ConstraintType::OR:
            os << "(" << constr->left_constr << " || " << constr->right_constr << ")"; break;
        case ConstraintType::EQ:
            os << "(" << constr->left_expr << " == " << constr->right_expr << ")"; break;
        case ConstraintType::NEQ:
            os << "(" << constr->left_expr << " != " << constr->right_expr << ")"; break;
        case ConstraintType::LE:
            os << "(" << constr->left_expr << " <= " << constr->right_expr << ")"; break;
        case ConstraintType::LT:
            os << "(" << constr->left_expr << " < " << constr->right_expr << ")"; break;
        case ConstraintType::ULE:
            os << "(" << constr->left_expr << " ULE " << constr->right_expr << ")"; break;
        case ConstraintType::ULT:
            os << "(" << constr->left_expr << " ULT " << constr->right_expr << ")"; break;
        default:
            throw runtime_exception("operator<<(ostream&, Constraint): got unknown ConstraintType");
    }
    return os;
}

Constraint operator==(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::EQ, left, right);
}
Constraint operator==(Expr left, cst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::EQ, left, exprcst(left->size,right));
}
Constraint operator==(cst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::EQ, exprcst(right->size, left), right);
}

Constraint operator!=(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::NEQ, left, right);
}

Constraint operator!=(Expr left, cst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::NEQ, left, exprcst(left->size, right));
}

Constraint operator!=(cst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::NEQ, exprcst(right->size, left), right);
}

Constraint operator<=(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LE, left, right);
}

Constraint operator<=(Expr left, cst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LE, left, exprcst(left->size,right));
}

Constraint operator<=(cst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LE, exprcst(right->size, left), right);
}

Constraint operator<(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LT, left, right);
}

Constraint operator<(Expr left, cst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LT, left, exprcst(left->size,right));
}

Constraint operator<(cst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LT, exprcst(right->size, left), right);
}

Constraint operator>=(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LE, right, left);
}

Constraint operator>=(Expr left, cst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LE, exprcst(left->size,right), left);
}

Constraint operator>=(cst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LE, right, exprcst(right->size, left));
}

Constraint operator>(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LT, right, left);
}

Constraint operator>(Expr left, cst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LT, exprcst(left->size,right), left);
}

Constraint operator>(cst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::LT, right, exprcst(right->size, left));
}

Constraint ULE(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::ULE, right, left);
}

Constraint ULE(Expr left, ucst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::ULE, left, exprcst(left->size,right));
}

Constraint ULE(ucst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::ULE, exprcst(right->size, left), right);
}

Constraint ULT(Expr left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::ULT, right, left);
}

Constraint ULT(Expr left, ucst_t right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::ULT, left, exprcst(left->size,right));
}

Constraint ULT(ucst_t left, Expr right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::ULT, exprcst(right->size, left), right);
}

Constraint operator&&(Constraint left, Constraint right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::AND, left, right);
}

Constraint operator||(Constraint left, Constraint right)
{
    return std::make_shared<ConstraintObject>(ConstraintType::OR, left, right);
}

Expr ITE(Constraint cond, Expr if_true, Expr if_false)
{
    ITECond itecond;
    bool swap = false;
    auto& l_e = cond->left_expr;
    auto& r_e = cond->right_expr;

    switch(cond->type)
    {
        case ConstraintType::AND:
            l_e = ITE(cond->left_constr, exprcst(1, 1), exprcst(1, 0)) &
				ITE(cond->right_constr, exprcst(1, 1), exprcst(1, 0));
            r_e = exprcst(1, 1);
            itecond = ITECond::EQ;
            break;
        case ConstraintType::OR:
            l_e = ITE(cond->left_constr, exprcst(1, 1), exprcst(1, 0)) |
				ITE(cond->right_constr, exprcst(1, 1), exprcst(1, 0));
            r_e = exprcst(1, 1);
            itecond = ITECond::EQ;
            break;
        case ConstraintType::EQ:
            itecond = ITECond::EQ;
            break;
        case ConstraintType::NEQ:
            itecond = ITECond::EQ;
            swap = true;
            break;
        case ConstraintType::LE:
            itecond = ITECond::SLE;
            break;
        case ConstraintType::LT:
            itecond = ITECond::SLT;
            break;
        case ConstraintType::ULE:
            itecond = ITECond::LE;
            break;
        case ConstraintType::ULT:
            itecond = ITECond::LT;
            break;
        default:
            throw runtime_exception("ConstraintObject::invert() got unknown constraint type");
    }

	if (swap) {
		return ITE(l_e, itecond, r_e, if_false, if_true);
	} else {
		return ITE(l_e, itecond, r_e, if_true, if_false);
	}
}


} // namespace maat
