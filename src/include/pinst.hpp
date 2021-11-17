#ifndef MAAT_PINST_H
#define MAAT_PINST_H

namespace maat
{
namespace ir
{
/** \addtogroup ir
 * \{ */


/** A ProcessedInst holds all the current values (in CPU and memory) of 
 * an IR instruction parameters for the current CPU context and memory state.
 * It is an internal intermediary structure used by the symbolic emulation engine to process
 * IR code.
 * 
 * The values held by the member fields depend on the type of operation that was
 * processed. For *in0*, *in1*, *in2*, the current value is computed. For *out*,
 * the FULL value is used (without performing potential bitfield extracts).
 * */
class ProcessedInst
{
public:
    /** \brief A processed parameter, it can hold either an abstract value,
     * a concrete value, or no value at all */
    class Param
    {
    public:
        enum class Type
        {
            NONE,
            ABSTRACT,
            CONCRETE
        };
    
        Expr expr;
        Number number;
        ProcessedInst::Param::Type type;
        /** \brief Optional auxilliary value, used to store the original address 
         * expression when processing a parameter that is a memory address
         * (the original parameter 'expr' gets replaced by the loaded expression 
         * */
        Expr auxilliary;
    public:
        Param();
        Param(const Param& other);
        Param& operator=(const Param& other);
        Param& operator=(Param&& other) = delete;
        ~Param() = default;
    public:
        bool is_abstract() const;
        bool is_concrete() const;
        bool is_none() const;
    public:
        Expr as_expr() const;
    public:
        Param& operator=(const Expr& e);
        Param& operator=(Expr&& e);
        Param& operator=(const Number& c);
        void set_none();
    };
    /** \typedef param_t
     * Parameter of an processed instruction */
    using param_t = Param;
public:
    bool is_concrete;
public:
    ProcessedInst() = default ;
    ProcessedInst(const ProcessedInst& other) = default;
    ProcessedInst& operator=(const ProcessedInst& other) = default;
    ~ProcessedInst() = default;
public:
    Param res; ///< Result of the operation to be assigned to destination operand (if applicable)
    Param out; ///< Value of output variable
    Param in0; ///< Value of first input parameter
    Param in1; ///< Value fo second input parameter
    Param in2; ///< Value of third input parameter
public:
    const Param& in(int i) const; ///< Return processed parameter 'i'
public:
    void reset(); ///< Empty the contents of the processed instruction
};

} // namespace ir
} // namespace maat
#endif