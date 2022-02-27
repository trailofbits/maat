#ifdef MAAT_Z3_BACKEND

#include "maat/solver.hpp"
#include "maat/stats.hpp"

namespace maat
{
namespace solver
{

/* =========================================
 * Translations from maat to z3 expressions 
 * ========================================= */

z3::expr expr_to_z3(z3::context* c, Expr e, size_t extend_to_size=0); // Forward declaration

z3::expr ITE_cond_to_z3(z3::context* c, Expr left, ITECond cond, Expr right)
{
    z3::expr l = expr_to_z3(c, left);
    z3::expr r = expr_to_z3(c, right);
    switch (cond)
    {
        case ITECond::EQ: return l == r;
        case ITECond::LE: return z3::ule(l,r);
        case ITECond::LT: return z3::ult(l,r);
        case ITECond::SLT: return l < r;
        case ITECond::SLE: return l <= r;
        default:
            throw runtime_exception("solver::ITE_cond_to_z3(): got unsupported condition type");
    }
}

z3::expr expr_to_z3(z3::context* c, Expr e, size_t extend_to_size)
{
    // This is used to have the same sizes in SHL/SHR
    if (extend_to_size != 0 and e->size < extend_to_size)
    {
        e = concat(exprcst(extend_to_size-e->size, 0), e);
    }

    switch(e->type)
    {
        case ExprType::CST: 
            if (e->size <= 64)
                return c->bv_val(e->as_uint(), e->size);
            else
            {
                std::stringstream ss;
                e->as_number().print(ss, true); // Decimal = true
                return c->bv_val(ss.str().c_str(), e->size);
            }
        case ExprType::VAR: return c->bv_const(e->name().c_str(), e->size);
        case ExprType::BINOP:
            switch (e->op())
            {
                case Op::ADD: return expr_to_z3(c, e->args[0]) + expr_to_z3(c, e->args[1]);
                case Op::MUL:
                case Op::SMULL: return expr_to_z3(c, e->args[0]) * expr_to_z3(c, e->args[1]);
                case Op::MULH: return ( z3::zext(expr_to_z3(c, e->args[0]), e->size)*z3::zext(expr_to_z3(c, e->args[1]), e->size))
                                .extract(e->size*2 - 1, e->size); 
                case Op::SMULH: return ( z3::sext(expr_to_z3(c, e->args[0]), e->size)*z3::sext(expr_to_z3(c, e->args[1]), e->size))
                                .extract(e->size*2 - 1, e->size);
                case Op::DIV: return z3::udiv(expr_to_z3(c, e->args[0]), expr_to_z3(c, e->args[1]));
                case Op::SDIV: return expr_to_z3(c, e->args[0]) / expr_to_z3(c, e->args[1]);
                case Op::MOD: return z3::mod(expr_to_z3(c, e->args[0]), expr_to_z3(c, e->args[1]));
                case Op::SMOD: return z3::srem(expr_to_z3(c, e->args[0]), expr_to_z3(c, e->args[1]));
                case Op::SHL: return z3::shl(
                    expr_to_z3(c, e->args[0]),
                    expr_to_z3(c, e->args[1], e->args[0]->size)
                );
                case Op::SHR: return z3::lshr(
                    expr_to_z3(c, e->args[0]),
                    expr_to_z3(c, e->args[1], e->args[0]->size)
                );
                case Op::SAR: return z3::ashr(
                    expr_to_z3(c, e->args[0]),
                    expr_to_z3(c, e->args[1], e->args[0]->size)
                );
                case Op::AND: return expr_to_z3(c, e->args[0]) & expr_to_z3(c, e->args[1]);
                case Op::OR: return expr_to_z3(c, e->args[0]) | expr_to_z3(c, e->args[1]);
                case Op::XOR: return expr_to_z3(c, e->args[0]) ^ expr_to_z3(c, e->args[1]);
                default:
                    throw runtime_exception("solver::expr_to_z3() got unsupported operation");
            }
        case ExprType::UNOP:
            switch(e->op()){
                case Op::NEG: return -expr_to_z3(c, e->args[0]);
                case Op::NOT: return ~expr_to_z3(c, e->args[0]);
                default:
                    throw runtime_exception("expr_to_z3() got unsupported operation");
            }
        case ExprType::CONCAT:
            return z3::concat(expr_to_z3(c, e->args[0]), expr_to_z3(c, e->args[1]));
        case ExprType::EXTRACT:
            return expr_to_z3(c, e->args[0]).extract(e->args[1]->cst(), e->args[2]->cst());
        case ExprType::ITE:
            return z3::ite(ITE_cond_to_z3(c, e->cond_left(), e->cond_op(), e->cond_right()), 
                           expr_to_z3(c, e->if_true()),
                           expr_to_z3(c, e->if_false()));
        default: throw runtime_exception("expr_to_z3() got unsupported ExprType");
    }
}


z3::expr constraint_to_z3(z3::context* c, const Constraint& constr)
{
    switch(constr->type)
    {
        case ConstraintType::AND: return constraint_to_z3(c, constr->left_constr) && constraint_to_z3(c, constr->right_constr);
        case ConstraintType::OR: return constraint_to_z3(c, constr->left_constr) || constraint_to_z3(c, constr->right_constr);
        case ConstraintType::EQ: return expr_to_z3(c, constr->left_expr) == expr_to_z3(c, constr->right_expr);
        case ConstraintType::NEQ: return expr_to_z3(c, constr->left_expr) != expr_to_z3(c, constr->right_expr);
        case ConstraintType::LE: return expr_to_z3(c, constr->left_expr) <= expr_to_z3(c, constr->right_expr);
        case ConstraintType::LT: return expr_to_z3(c, constr->left_expr) < expr_to_z3(c, constr->right_expr);
        case ConstraintType::ULE: return z3::ule(expr_to_z3(c, constr->left_expr), expr_to_z3(c, constr->right_expr));
        case ConstraintType::ULT: return z3::ult(expr_to_z3(c, constr->left_expr), expr_to_z3(c, constr->right_expr));
        default:
            throw runtime_exception("solver::constr_to_z3() got unsupported ConstraintType");
    }
}


SolverZ3::SolverZ3(): Solver(), has_model(false)
{
    _model_id_cnt = model_id_cnt;
    ctx = new z3::context();
    sol = new z3::solver(*ctx);
}

SolverZ3::~SolverZ3()
{
    delete sol;
    sol = nullptr;
    delete ctx;
    ctx = nullptr;
}

void SolverZ3::reset()
{
    constraints.clear();
    has_model = false;
}

void SolverZ3::add(const Constraint& constr)
{
    constraints.push_back(constr);
    has_model = false;
}

void SolverZ3::pop()
{
    constraints.pop_back();
}

bool SolverZ3::check()
{

    // If already has model, don't recompute it
    if (has_model)
        return true;

    // Reset solver
    sol->reset();

    // Statistics
    MaatStats::instance().start_solving();

    // Add constraints to the solver
    for (const auto& constr : constraints)
    {
        sol->add(constraint_to_z3(ctx, constr));
    }
    z3::params p(*ctx);
    p.set(":timeout", static_cast<unsigned>(timeout));
    sol->set(p);
    has_model =  (sol->check() == z3::check_result::sat);

    // Statistics
    MaatStats::instance().done_solving();

    return has_model;
}

std::shared_ptr<VarContext> SolverZ3::get_model()
{
    return std::shared_ptr<VarContext>(_get_model_raw());
}

VarContext* SolverZ3::_get_model_raw()
{
    if (not has_model)
        return nullptr;

    z3::model m = sol->get_model();
    auto res = new VarContext(_model_id_cnt++);
    for (int i = 0; i < m.num_consts(); i++)
    {
        res->set(
            m[i].name().str(), 
            cst_sign_extend( 
                Z3_get_bv_sort_size(*ctx, m.get_const_interp(m[i]).get_sort()), 
                m.get_const_interp(m[i]).get_numeral_uint64()
            )
        );
    }
    return res;
}

} // namespace solver
} // namespace maat
#endif // #ifdef MAAT_Z3_BACKEND
