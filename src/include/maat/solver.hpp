#ifndef MAAT_SOLVER_H
#define MAAT_SOLVER_H

#include "maat/constraint.hpp"
#include "maat/varcontext.hpp"
#include <list>

#ifdef MAAT_Z3_BACKEND
#include "z3++.h"
#endif

namespace maat
{

namespace solver
{
    
/** \defgroup solver Solver
 * \brief The Maat's constraint solver interface */

/** \addtogroup solver
 * \{ */

/** \brief The generic solver interface. It should be sub-classed for implementations
 * using specific backends (z3, yices, cvc4, ...) */
class Solver
{
protected:
    static unsigned int model_id_cnt;
public:
    /// Timeout in milliseconds when calling *check()* (default: 300000ms/5min)
    unsigned int timeout;
public:
    Solver();
    virtual ~Solver();
    /// Remove all current constraints
    virtual void reset() = 0;
    /// Add a constraint to the solver
    virtual void add(const Constraint& constr) = 0;
    /// Remove the lastest added constraint
    virtual void pop() = 0;
    /** \brief Solve the current constraints. Return *true* on success and *false*
     * on failure. If the check was successful, the generated model can be obtained
     * by calling *get_model()* */
    virtual bool check() = 0;
    /** Get model for the last solved constraints. If the previous call to *check()*
     * had returned *false*, the function will return a null pointer */
    virtual std::shared_ptr<VarContext> get_model() = 0;
    // Mainly for use in python bindings
    virtual VarContext* _get_model_raw() = 0;
};

/// Return a solver instance
std::unique_ptr<Solver> new_solver();
// Mainly for use in python bindings
Solver* _new_solver_raw();

#ifdef MAAT_Z3_BACKEND
class SolverZ3 : public Solver
{
private:
    z3::context* ctx;
    z3::solver* sol;
private:
    unsigned int _model_id_cnt;
    std::list<Constraint> constraints;
    bool has_model; ///< Set to true if check() returned true
public:
    SolverZ3();
    virtual ~SolverZ3();
    void reset();
    void add(const Constraint& constr);
    void pop();
    bool check();
    virtual std::shared_ptr<VarContext> get_model();
    virtual VarContext* _get_model_raw();
};
#endif

/** \} */ // doxygen groupe Solver
} // namespace solver
} // namespace maat

#endif
