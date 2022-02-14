#include "maat/solver.hpp"

namespace maat
{
namespace solver
{
    
unsigned int Solver::model_id_cnt = 0x80000000;

Solver::Solver()
{
    model_id_cnt += 0x10000;
    timeout = 300000; // 300 sec 
}
    
Solver::~Solver()
{}

std::unique_ptr<Solver> new_solver()
{
#ifdef MAAT_Z3_BACKEND
    return std::make_unique<SolverZ3>();
#else
    return nullptr;
#endif
}

Solver* _new_solver_raw()
{
#ifdef MAAT_Z3_BACKEND
    return new SolverZ3();
#else
    return nullptr;
#endif
}

} // namespace solver
} // namespace maat
