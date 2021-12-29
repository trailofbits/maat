#ifndef MAAT_PINST_H
#define MAAT_PINST_H

#include "value.hpp"

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
    using value_ptr = const Value*;
    /** \brief A processed parameter, it can hold either an abstract value,
     * a concrete value, or no value at all */
    class Param
    {
    public:
        enum class Type
        {
            INPLACE,
            PTR,
            NONE
        };
    public:
        ProcessedInst::value_ptr val_ptr; // For IN params
        Value val; // For OUT param (need to compute result in place)
        /** \brief Optional auxilliary value, used to store the original address 
         * expression when processing a parameter that is a memory address
         * (the original parameter 'expr' gets replaced by the loaded expression 
         * */
        Value auxilliary;
        Type type;
    public:
        Param();
        Param(const Param& other);
        Param& operator=(const Param& other);
        Param& operator=(Param&& other) = delete;
        ~Param() = default;
    public:
        Param& operator=(const Value& val); ///< Not performant
        Param& operator=(Value&& val);
        void set_value_by_ref(const Value& val); ///< Performant, 'val' reference needs to stay valid!!
        void set_cst(size_t size, cst_t val);
        void set_none();
    public:
        const Value& value() const;
    public:
        bool is_none() const;
        bool is_abstract() const;
    };

    /** \typedef param_t
     * Parameter of an processed instruction */
    using param_t = Param;
public:
    ProcessedInst() = default;
    ProcessedInst(const ProcessedInst& other) = default;
    ProcessedInst& operator=(const ProcessedInst& other) = default;
    ProcessedInst& operator=(ProcessedInst&& other) = delete;
    ~ProcessedInst() = default;
public:
    Value res; ///< Result of the operation to be assigned to destination operand (if applicable)
    Param out; ///< Value of output variable
    Param in0; ///< Value of first input parameter
    Param in1; ///< Value of second input parameter
    Param in2; ///< Value of third input parameter
public:
    void reset();
};

} // namespace ir
} // namespace maat
#endif