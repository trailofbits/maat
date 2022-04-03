#ifndef CONSTRAINT_H
#define CONSTRAINT_H

#include <set>
#include <memory>
#include <optional>
#include <string>
#include "maat/expression.hpp"
#include "maat/serializer.hpp"

namespace maat
{

/** \defgroup constraint Constraints 
 * \brief Expressing constraints on abstract expressions
 * 
 * This module implements the classes used to represent arithmetical and
 * logical constraints on abstract expressions.
 * */

/** \addtogroup constraint
 * \{ */

/// Different types of logical and arithmetic constraints
enum class ConstraintType
{
    AND, ///< Logical AND
    OR, ///< Logical OR
    EQ, ///< Arithmetic EQUAL
    NEQ, ///< Arithmetic NOT EQUAL
    LE, ///< Arithmetic SIGNED LESS OR EQUAL
    LT, ///< Arithmetic SIGNED LESS
    ULE, ///< Arithmetic UNSIGNED LESS OR EQUAL
    ULT ///< Arithmetic UNSIGNED LESS
};

/* Forward declarations */
class ConstraintObject;
/** \typedef Constraint 
 * \brief Shared pointer to an constraint object. Constraints should be manipulated
 * only through 'Constraint' instances. Unless used in Maat's core internals,
 * the base class ConstraintObject and its child classes should never be
 * used directly
 */
typedef std::shared_ptr<ConstraintObject> Constraint;

/** \brief Constraint object representing constraints between symbolic expressions. This class
 *  should never be manipulated directly but used transparently through ::Constraint instances */
class ConstraintObject: public serial::Serializable
{
private:
    // std::nullopt until we get the variables 
    std::optional<std::set<std::string>> _contained_vars;
public:
    ConstraintType type; ///< Type of constraint (equal, less than, less or equal, AND, OR, ...)
    Expr left_expr; ///< Left member of the constraint if arithmetic constraint between symbolic expressions
    Expr right_expr; ///< Right member of the constraint if arithmetic constraint between symbolic expressions
    Constraint left_constr; ///< Left member of the constraint if combination of other constraints (OR/AND)
    Constraint right_constr; ///< Right member of the constraint if combination of other constraints (OR/AND)
public:
    ConstraintObject(ConstraintType t, Expr l, Expr r); ///< Constructor 
    ConstraintObject(ConstraintType t, Constraint l, Constraint r); ///< Constructor
    Constraint invert(); ///< Returns the inverse of the constraint
    /** \brief Return true if the constraint contains at least one of the variables
     * listed in 'var_names' */
    bool contains_vars(const std::set<std::string>& var_names);
    /// Returns a reference to the set of abstract variables containted in the constraint
    const std::set<std::string>& contained_vars();
public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

/// Print a constraint to an out stream
std::ostream& operator<<(std::ostream& os, const Constraint& constr);

Constraint operator==(Expr left, Expr right); ///< Create equality constraint 
Constraint operator==(Expr left, cst_t right); ///< Create equality constraint 
Constraint operator==(cst_t left, Expr right); ///< Create equality constraint 

Constraint operator!=(Expr left, Expr right); ///< Create a not-equal constraint 
Constraint operator!=(Expr left, cst_t right); ///< Create a not-equal constraint 
Constraint operator!=(cst_t left, Expr right); ///< Create a not-equal constraint 

Constraint operator<=(Expr left, Expr right); ///< Create a signed less-or-equal constraint 
Constraint operator<=(Expr left, cst_t right); ///< Create a signed less-or-equal constraint 
Constraint operator<=(cst_t left, Expr right); ///< Create a signed less-or-equal constraint 

Constraint operator<(Expr left, Expr right); ///< Create a signed less-than constraint 
Constraint operator<(Expr left, cst_t right); ///< Create a signed less-than constraint 
Constraint operator<(cst_t left, Expr right); ///< Create a signed less-than constraint 

Constraint operator>=(Expr left, Expr right); ///< Create a signed greater or equal constraint 
Constraint operator>=(Expr left, cst_t right); ///< Create a signed greater or equal constraint 
Constraint operator>=(cst_t left, Expr right); ///< Create a signed greater or equal constraint 

Constraint operator>(Expr left, Expr right); ///< Create a signed greater-than constraint 
Constraint operator>(Expr left, cst_t right); ///< Create a signed greater-than constraint 
Constraint operator>(cst_t left, Expr right); ///< Create a signed greater-than constraint 

Constraint ULE(Expr left, Expr right); ///< Create an unsigned less or equal constraint 
Constraint ULE(Expr left, ucst_t right); ///< Create an unsigned less or equal constraint 
Constraint ULE(ucst_t left, Expr right); ///< Create an unsigned less or equal constraint 

Constraint ULT(Expr left, Expr right); ///< Create an unsigned less-than constraint 
Constraint ULT(Expr left, ucst_t right); ///< Create an unsigned less-than constraint 
Constraint ULT(ucst_t left, Expr right); ///< Create an unsigned less-than constraint 

Constraint operator&&(Constraint left, Constraint right); ///< Combine constraints (*left* AND *right*)
Constraint operator||(Constraint left, Constraint right); ///< Combine constraints (*left* OR *right*)

/** \} */ // End of doxygen group constraint

// TODO add a .evaluate(VarContext) method...

} // namespace maat
#endif
