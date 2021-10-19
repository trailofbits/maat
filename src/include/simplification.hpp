#ifndef SIMPLIFICATION_H
#define SIMPLIFICATION_H

#include "expression.hpp"
#include <vector>



namespace maat
{

/* Forward declaration */ 
class ExprSimplifier;

/** \addtogroup expression
 * \{ */

/* Type aliasing */
/** \typedef ExprSimplifierFunc 
 * A function that takes an expression and returns a simplified expression
 */
typedef Expr (*ExprSimplifierFunc)(Expr);
typedef Expr (*RecExprSimplifierFunc)(Expr, ExprSimplifier&);

/** An expression simplifier can be used to simplify expressions. It holds
 * a list of simplification functions that can be applied successively to 
 * the expression in onrder to simplify it */
class ExprSimplifier
{
private:
    static unsigned int _id_cnt;

protected:
    unsigned int _id; ///< Unique ID of the simplifier instance
    std::vector<ExprSimplifierFunc> simplifiers;
    std::vector<RecExprSimplifierFunc> rec_simplifiers;
    // vector<RecExprSimplifierFunc> restruct_simplifiers;
    Expr run_simplifiers(Expr e); ///< Run all simplifier functions once on expression 'e' and return the resulting expression

public:
    ExprSimplifier(); ///< Constructor
    Expr simplify(Expr e, bool mark_as_simplified=true); ///< Simplify the expression 'e'
    void add(ExprSimplifierFunc func); ///< Add a simplifier function to the expression simplifier
    void add(RecExprSimplifierFunc func); ///< Add a recursive simplifier function to the expression simplifier
    // void add_restruct(RecExprSimplifierFunc func);
};

/** \brief Instanciate a new expression simplifier that uses all of Maat's built-in 
 * simplifier functions */
std::unique_ptr<ExprSimplifier> NewDefaultExprSimplifier();

/* Simplification functions */
Expr es_constant_folding(Expr e); ///< Constant folding simplifier function
Expr es_neutral_elements(Expr e); ///< Neutral elements simplifier function
Expr es_absorbing_elements(Expr e); ///< Absorbing elements simplifier function
Expr es_arithmetic_properties(Expr e); ///< Arithmetic simplification function
Expr es_involution(Expr e); ///< Involution simplifier function
Expr es_extract_patterns(Expr e); ///< Simplifier function for 'Extract' expressions
Expr es_basic_transform(Expr e); ///< simplifier function
Expr es_logical_properties(Expr e); ///< Logical properties simplifier function 
Expr es_concat_patterns(Expr e); ///< Simplifier function for 'Concat' expressions
Expr es_basic_ite(Expr e); ///< Simplifier function on If-Then-Else expressions
Expr es_arithmetic_factorize(Expr e); ///< Factorization simplifier function
Expr es_generic_factorize(Expr e); ///< Generic factorization simplifier function
Expr es_generic_distribute(Expr e);
Expr es_deep_associative(Expr e, ExprSimplifier& simp); ///< Simplifier for repeated associative operation 

/** \} */ // Expression doxygen group

} // namespace maat

#endif
