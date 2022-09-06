#ifdef MAAT_BOOLECTOR_BACKEND

#include "maat/solver.hpp"
#include "maat/stats.hpp"
#include "maat/exception.hpp"
#include <fstream>

namespace maat
{
namespace solver
{

SolverBtor::SolverBtor(): Solver(), has_model(false)
{
    btor = boolector_new();
    boolector_set_opt (btor, BTOR_OPT_MODEL_GEN, 1);
    boolector_set_opt (btor, BTOR_OPT_INCREMENTAL, 1);
}

SolverBtor::~SolverBtor()
{
    boolector_delete(btor);
    btor = nullptr;
}

void SolverBtor::reset()
{
    constraints.clear();
    has_model = false;
    _did_time_out = false;
    boolector_reset_assumptions(btor);
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

    boolector_reset_assumptions(btor);

    // Dump constraints to temporary file
    // TODO(boyan): use mkstemp instead of tmpnam
    const char *smt_file = tmpnam(NULL);  // Get temp name
    if (smt_file == nullptr)
        throw solver_exception("SolverBtor::check(): couldn't create temporary filename");
    std::ofstream f(smt_file);
    if (not f.good())
        throw solver_exception("SolverBtor::check(): couldn't create temporary SMT file");
    std::string smt_string = constraints_to_smt2(constraints);
    f << smt_string;
    f.close();

    // Load SMT in boolector
    int status = boolector_parse_smt2(
        btor,
        nullptr, // infile
        smt_file, // infile_name
        nullptr, // outfile
        nullptr, // error_msg
        nullptr // status
    );
    if (status != BOOLECTOR_PARSE_UNKNOWN)
        throw solver_exception(
            Fmt() << "SolverBtor::check(): error parsing SMT file: "
            << smt_file >> Fmt::to_str
        );
    status = boolector_sat(btor);
    has_model = (status == BOOLECTOR_SAT);

    // Remove temporary file
    remove(smt_file);

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
