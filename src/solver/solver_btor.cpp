#ifdef MAAT_BOOLECTOR_BACKEND

#include "maat/solver.hpp"
#include "maat/stats.hpp"
#include "maat/exception.hpp"

namespace maat
{
namespace solver
{

SolverBtor::SolverBtor(): Solver(), has_model(false)
{}

SolverBtor::~SolverBtor()
{}

void SolverBtor::reset()
{
    constraints.clear();
    has_model = false;
    _did_time_out = false;
}

void SolverBtor::add(const Constraint& constr)
{
    constraints.push_back(constr);
    has_model = false;
}

void SolverBtor::pop()
{
    constraints.pop_back();
}

bool SolverBtor::check()
{
    // If already has model, don't recompute it
    if (has_model)
        return true;

    // Statistics
    MaatStats::instance().start_solving();

    // TODO 

    // Statistics
    MaatStats::instance().done_solving();

    return has_model;
}

std::shared_ptr<VarContext> SolverBtor::get_model()
{
    return std::shared_ptr<VarContext>(_get_model_raw());
}

VarContext* SolverBtor::_get_model_raw()
{
    if (not has_model)
        return nullptr;

    // TODO
}

} // namespace solver
} // namespace maat
#endif // #ifdef MAAT_BOOLECTOR_BACKEND
