#ifndef MAAT_VARCONTEXT_H
#define MAAT_VARCONTEXT_H

#include <map>
#include <optional>
#include "maat/number.hpp"
#include <vector>

namespace maat 
{

/** \addtogroup expression
 * \{ */

class Value; // Forward decl

/** A context that associates concrete values to symbolic variables*/
class VarContext
{
private:
    static unsigned int _id_cnt;

private:
    /** Map concrete values to symbolic variables */
    std::map<std::string, maat::Number> varmap;
    
public:
    VarContext(unsigned int id=0); ///< Constructor
    VarContext(const VarContext&) = default;
    VarContext& operator=(const VarContext&) = default;
    ~VarContext() = default;

public:
    unsigned int id; ///< Unique identifier for the VarContext instance
    void set(const std::string& var, cst_t value); ///< Give a concrete value to a symbolic variable
    void set(const std::string& var, const Number& number); ///< Give a concrete value to a symbolic variable as a *maat::Number* instance
    cst_t get(const std::string& var) const; ///< Get the concrete value given to a symbolic variable
    const maat::Number& get_as_number(const std::string& var) const;
    std::vector<uint8_t> get_as_buffer(std::string var, unsigned int elem_size=1) const;
    std::string get_as_string(std::string var) const;
    void remove(const std::string& var); ///< Remove concrete value for symbolic variable 
    bool contains(const std::string& var) const; ///< Return true if a concrete value is associated to the symbolic variable
    std::string new_name_from(const std::string& hint) const;
    /** \brief Create a new buffer of symbolic variables.
     * @param name Base name after whom to name variables
     * @param nb_elems Number of variables in the buffer
     * @param elem_size Size in bytes of each variable
     * @param trailing_value Optional concrete value to add at the end of the buffer (not counted by 'nb_elems')
     */
    std::vector<Value> new_symbolic_buffer(
        const std::string& name,
        int nb_elems,
        int elem_size=1,
        std::optional<cst_t> trailing_value=std::nullopt
    );
    /** \brief Create a new buffer of concolic variables.
     * @param name Base name after whom to name variables
     * @param concrete_buffer The concrete values with whom to initialize variables
     * @param nb_elems Number of variables in the buffer
     * @param elem_size Size in bytes of each variable 
     * @param trailing_value Optional concrete value to add at the end of the buffer (not counted by 'nb_elems')
     */
    std::vector<Value> new_concolic_buffer(
        const std::string& name,
        const std::vector<cst_t>& concrete_buffer,
        int nb_elems=-1,
        int elem_size=1,
        std::optional<cst_t> trailing_value=std::nullopt
    );
    /** \brief Create a new buffer of concolic variables.
     * @param name Base name after whom to name variables
     * @param concrete_buffer The concrete values with whom to initialize variables
     * @param nb_elems Number of variables in the buffer
     * @param trailing_value Optional concrete value to add at the end of the buffer (not counted by 'nb_elems')
     */
    std::vector<Value> new_concolic_buffer(
        const std::string& name,
        const std::string& concrete_buffer,
        std::optional<cst_t> trailing_value=std::nullopt
    );
    /** \brief Copy the mapping between concrete values and symbolic variables from 'other'.
     * - If a variable is contained in both 'other' and this context, it takes the value
     *   that it has in 'other'. 
     * - If a variable is contained only in 'other', it is added to this context.
     * - Variables present in this context but not in 'other' are kept as they are 
     * */
    void update_from(VarContext& other);
    void print(std::ostream& os) const; ///< Print the context to a stream
};

/** Print the context to a stream */
std::ostream& operator<<(std::ostream& os, const VarContext& c);

/** \} */ // doxygen expression group

} // namespace maat
#endif
