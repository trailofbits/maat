#ifdef MAAT_BOOLECTOR_BACKEND

#include "maat/solver.hpp"
#include "maat/stats.hpp"
#include "maat/exception.hpp"
#include <fstream>

namespace maat
{
namespace solver
{

SolverBtor::SolverBtor(): 
    Solver(), 
    has_model(false),
    btor(nullptr),
    model_file(nullptr)
{
    reset_btor();
}

SolverBtor::~SolverBtor()
{
    boolector_delete(btor);
    btor = nullptr;
}

void SolverBtor::reset_btor()
{
    if (btor != nullptr)
    {
        // TODO(boyan)
        // DEBUG: are these calls useful ?
        boolector_reset_assumptions(btor);
        boolector_release_all(btor);
        boolector_delete(btor);
    }
    btor = boolector_new();
    boolector_set_opt (btor, BTOR_OPT_MODEL_GEN, 1);
    boolector_set_opt (btor, BTOR_OPT_INCREMENTAL, 1);
}

void SolverBtor::reset()
{
    constraints.clear();
    has_model = false;
    _did_time_out = false;
    reset_btor();
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

    reset_btor();

    // Statistics
    MaatStats::instance().start_solving();

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

    std::cout << "DEBUG SMT QUERY iN " << smt_file << "\n";

    // Load SMT in boolector
    // TODO(boyan): don't reopen smt_file
    // TODO(boyan): don't hardcode dev/null but make it dependent on
    // the platform, and find a solution for Windows
    FILE* infile = fopen(smt_file, "r");
    FILE* outfile = fopen("/dev/null", "w");
    char* error_msg;
    int _status;
    int status = boolector_parse_smt2(
        btor,
        infile, // infile
        smt_file, // infile_name
        outfile, // outfile
        &error_msg, // error_msg
        &_status // status
    );
    fclose(outfile);
    fclose(infile);

    // DEBUG
    // if (status == BOOLECTOR_PARSE_UNKNOWN)
    //     status = boolector_sat(btor);
    if (status == BOOLECTOR_PARSE_UNKNOWN)
        throw solver_exception(
            Fmt() << "SolverBtor::check(): error solving SMT file: "
            << smt_file >> Fmt::to_str
        );

    has_model = (status == BOOLECTOR_SAT);

    // Remove temporary file
    // DEBUG remove(smt_file);

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

    // TODO(boyan): don't hardcode
    if (model_file == nullptr)
    {
        model_file = tmpnam(NULL);  // Get temp name
        if (model_file == nullptr)
            throw solver_exception("SolverBtor::_get_model_raw(): couldn't create temporary filename");
    }
    FILE* f = fopen(model_file, "w");
    boolector_print_model(btor, "smt2", f);
    fclose(f);

    std::ifstream in(model_file, std::ios::binary);
    std::vector<char> data(
        (std::istreambuf_iterator<char>(in)),
        (std::istreambuf_iterator<char>())
    );
    std::vector<char> clean_data{'(', 'm', 'o', 'd', 'e', 'l', '\n'};
    for (int i = 2; i < data.size(); i++)
    {
        // DEBUG remove false??
        if (
            false && i+2 < data.size() && data[i] == '\n' 
            && data[i+1] == ' ' && data[i+2] == ' '
        ){
            clean_data.push_back('\n');
            i += 2;
        }
        else
            clean_data.push_back(data[i]);
    }
    remove(model_file);
    ctx_from_smt2(clean_data.data());
}

} // namespace solver
} // namespace maat
#endif // #ifdef MAAT_BOOLECTOR_BACKEND
