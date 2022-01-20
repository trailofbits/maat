#ifndef MAAT_IR_H
#define MAAT_IR_H

#include <vector>
#include <optional>
#include <functional>
#include <unordered_map>
#include "maat/expression.hpp"
#include "maat/callother.hpp"

namespace maat
{

/** \defgroup ir IR 
 * \brief Maat's binary code Intermediate Representation
 * 
 * This module contains the implementation of the IR used to lift binary
 * code in Maat.
 * */

/// Intermediate Representation of machine code in Maat
namespace ir
{

/** \addtogroup ir
 * \{ */
/** Maat's IR is basically Ghidra's PCODE */
enum class Op : uint8_t
{
        COPY,
        LOAD,
        STORE,
        BRANCH,            
        CBRANCH,           
        BRANCHIND,
        CALL,         
        CALLIND,           
        CALLOTHER,         
        RETURN,            
        INT_EQUAL,        
        INT_NOTEQUAL,     
        INT_SLESS,
        INT_SLESSEQUAL,   
        INT_LESS,
        INT_LESSEQUAL,     
        INT_ZEXT,         
        INT_SEXT,         
        INT_ADD,           
        INT_SUB,           
        INT_CARRY,        
        INT_SCARRY,        
        INT_SBORROW,   
        INT_2COMP,         
        INT_NEGATE,
        INT_XOR,           
        INT_AND,           
        INT_OR,           
        INT_LEFT,          
        INT_RIGHT,        
        INT_SRIGHT,       
        INT_MULT,         
        INT_DIV,          
        INT_SDIV,         
        INT_REM,          
        INT_SREM,         
        BOOL_NEGATE,     
        BOOL_XOR,         
        BOOL_AND,         
        BOOL_OR,         
        FLOAT_EQUAL,      
        FLOAT_NOTEQUAL,  
        FLOAT_LESS,
        FLOAT_LESSEQUAL,            
        FLOAT_NAN,         
        FLOAT_ADD,         
        FLOAT_DIV,        
        FLOAT_MULT,       
        FLOAT_SUB,        
        FLOAT_NEG,        
        FLOAT_ABS,        
        FLOAT_SQRT,
        FLOAT_INT2FLOAT,  
        FLOAT_FLOAT2FLOAT,
        FLOAT_TRUNC,     
        FLOAT_CEIL,      
        FLOAT_FLOOR,      
        FLOAT_ROUND,
        MULTIEQUAL,     
        INDIRECT,        
        PIECE,           
        SUBPIECE,        
        CAST,           
        PTRADD,           
        PTRSUB,         
        SEGMENTOP,
        CPOOLREF,
        NEW,
        INSERT,        
        EXTRACT,        
        POPCOUNT,
        NONE
};

/** Return True if the operation assigns a value to a variable */
bool is_assignment_op(const ir::Op& op);
/** Return True if the operation loads of stores memory */
bool is_memory_op(const ir::Op& op);
/** Return True if the operation is a control flow branch */
bool is_branch_op(const ir::Op& op);
/** Print IR operation to a stream */ 
std::ostream& operator<<(std::ostream& os, const ir::Op& op);

/* Values for syscalls */
/* TODO: put this in Arch module / OR: this will likely disappear in favor to callother
#define SYSCALL_X86_INT80 1
#define SYSCALL_X86_SYSENTER 2 
#define SYSCALL_X64_SYSCALL 3 */

/** \typedef reg_t
 * Represents a CPU register in Maat's IR */
typedef uint16_t reg_t;

/** \typedef tmp_t
 * Represents a temporary register in Maat's IR */
typedef uint16_t tmp_t;

/** \typedef addr_t
 * Represents a memory address in Maat's IR */
typedef uint64_t addr_t;

class Inst;
/** \brief Base class for parameters to be used in IR instructions */
class Param
{
friend class Inst;
public:
    /** Types of parameters/operands in the IR */
    enum class Type : uint8_t
    {
        CST, ///< A constant value 
        REG, ///< References an actual CPU register in the arch being lifted
        TMP, ///< References a temporary register used to hold temporary values but don't correspond to actual CPU registers
        ADDR, ///< References a value stored in the RAM at a given address
        NONE ///< None
    };

private:
    /** This value's meaning depends on the param type.
     * If cst then the constant, if reg or tmp then the reg_t
     * or tmp_t for this register */
    // TODO - support for constants on more than 64 bits ???? Need to use a 'Number'
    uint64_t _val;
    size_t _size;
public:
    Type type; ///< Type of this parameter
    size_t hb; ///< Higher bit of the parameter
    size_t lb; ///< Lower bit of the parameter

public:
    Param(); ///< Constructor, create an empty None parameter
    Param(const Param& other) = default; ///< Copy constructor
    Param(Type type, uint64_t val, size_t hb, size_t lb); ///< Constructor
    Param& operator=(const Param& other); ///< Assignment operator
    Param& operator=(Param&& other) = default; ///< Move semantics operator 
public:
    bool is_cst() const; ///< Return true if it is a constant parameter
    bool is_cst(cst_t val) const; ///< Return true if it is a constant parameter of value 'val'
    bool is_reg() const; ///< Return true if it is a CPU register parameter
    bool is_reg(reg_t reg) const; ///< Return if it is the CPU register parameter for 'reg'
    bool is_tmp() const; ///< Return true if it is a tmp register parameter
    bool is_tmp(tmp_t tmp) const; ///< Return true if it is the tmp register parameter for 'tmp'
    bool is_addr() const; ///< Return true if it is a memory address
    bool is_none() const; ///< Return true if the parameter is empty

    cst_t cst() const; ///< Return the constant if constant parameter
    reg_t reg() const; ///< Return the CPU register if register parameter
    tmp_t tmp() const; ///< Return the tmp register if tmp parameter
    addr_t addr() const; ///< Return the address if address parameter

    size_t size() const; ///< Return the size in bits of the parameter
public:
    static const Param& None(); ///< Return the 'None' parameter

public:
    friend std::ostream& operator<<(std::ostream& os, const Param& param);
};

/** Build a constant parameter of value 'val' of size 'size' bits */
Param Cst(cst_t val, size_t size);
/** Build an address parameter for address 'addr' and accessing 'size' bits */
Param Addr(addr_t addr, size_t size);
/** Build a constant parameter of value 'val[hb:lb]' (extract bits lb
 * to hb included from the constant) of size 'hb-lb+1' bits */
Param Cst(cst_t val, size_t hb, size_t lb);
/** Build a parameter for register 'reg' of size 'size' bits */
Param Reg(reg_t reg, size_t size);
/** Build a parameter for value 'reg[hb:lb]' (extract bits lb
 * to hb included from the register) of size 'hb-lb+1' bits */
Param Reg(reg_t reg, size_t hb, size_t lb);
/** Build a parameter for register 'tmp' of size 'size' bits */
Param Tmp(tmp_t tmp, size_t size);
/** Build a parameter for value 'tmp[hb:lb]' (extract bits lb
 * to hb included from the tmp register) of size 'hb-lb+1' bits */
Param Tmp(tmp_t tmp, size_t hb, size_t lb);

/** \brief Maat IR instructions. \n
 * An IR instruction is made of an operation followed by one or several
 * parameters 
 * */
class Inst
{
public:
    using param_list_t = std::vector<std::reference_wrapper<const Param>>;
public:
    Op op; ///< Operation
    Param out; ///< Output parameter
    Param in[3]; ///< Input parameters 
    callother::Id callother_id; ///< Callother Id if CALLOTHER operation
public:
    /// Empty constructor
    Inst();
    /// Basic constructor
    Inst(
        Op op,
        const std::optional<Param>& out = std::nullopt,
        const std::optional<Param>& in0 = std::nullopt,
        const std::optional<Param>& in1 = std::nullopt,
        const std::optional<Param>& in2 = std::nullopt
    );
    /// Copy constructor
    Inst(const Inst& other) = default;
    /// Default destructor
    ~Inst() = default;
private:
    bool _reads_type(Param::Type type, uint64_t val) const;
    bool _writes_type(Param::Type type, uint64_t val) const;
    void _get_read_types(Param::Type type, param_list_t& res) const;
    void _get_written_types(Param::Type type, param_list_t& res) const;
public:
    bool reads_reg(reg_t reg) const; ///< Return True if instruction reads the register 'reg'
    bool writes_reg(reg_t reg)  const; ///< Return True if instruction modifies the register 'reg'
    bool uses_reg(reg_t reg)  const; ///< Return True if instruction reads or modifies the register 'reg'
    bool reads_tmp(tmp_t tmp)  const; ///< Return True if instruction reads the temporary 'tmp'
    bool writes_tmp(tmp_t tmp)  const; ///< Return True if instruction modifies the temporary 'tmp'
    void get_written_regs(param_list_t& res) const; ///< Writes the list of CPU registers modified by this instruction in 'res'
    void get_read_regs(param_list_t& res) const; ///< Writes the list of CPU registers read by this instruction in 'res'
    void get_written_tmps(param_list_t& res) const; ///< Writes the list of temporaries modified by this instruction in 'res'
    void get_read_tmps(param_list_t& res) const; ///< Writes the list of temporaries modified by this instruction in 'res'
public:
    friend std::ostream& operator<<(std::ostream& os, const Inst& inst);
};

/** \brief A native instruction lifted into a sequence of IR/PCODE instructions. */
class AsmInst
{
public:
    using inst_id = int; 
    using inst_list_t = std::vector<Inst>;

private:
    inst_list_t _instructions; ///< Sequence of IR instructions for this instructions
    unsigned int _tmp_cnt; ///< Number of tmp regs used in the inst
protected:
    /// Size of the instruction in bytes
    unsigned int _raw_size;
    /// Address of the instruction in memory
    uint64_t _addr;

public:
    std::string name; ///< Optional name of the basic block

public:
    AsmInst();
    AsmInst(uint64_t addr, unsigned int raw_size); ///< Constructor
    AsmInst& operator=(const AsmInst& other); ///< Copy assignment
    AsmInst& operator=(AsmInst&& other); ///< Move assignment
public:
    /// Address of the first instruction in the block
    uint64_t addr() const;
    /// Size of the instruction in bytes
    unsigned int raw_size() const;
    /// Return the number of IR instructions of the AsmInst
    size_t nb_ir_inst() const;
    bool contains(addr_t start, addr_t end);
    /// Append the IR instruction 'inst' to the AsmInst and return the id for this instruction
    AsmInst::inst_id add_inst(const Inst& instr);
    /// Append the IR instruction 'inst' to the AsmInst and return the id for this instruction
    AsmInst::inst_id add_inst(Inst&& instr);
    /// Append the IR instructions to the AsmInst and return the id of the last added instruction
    AsmInst::inst_id add_insts(const inst_list_t& insts);
    /// Append the IR instructions to the AsmInst and return the id of the last added instruction
    AsmInst::inst_id add_insts(inst_list_t&& insts);
    tmp_t new_tmp(); ///< Return a free temporary register
    AsmInst::inst_list_t& instructions(); ///< Get the list of instructions composing this AsmInst
    const AsmInst::inst_list_t& instructions() const; ///< Get the list of instructions composing this AsmInst
public:
    friend std::ostream& operator<<(std::ostream& os, const AsmInst& inst);
};

/** A simple class that maps addresses to lifted assembly instructions */ 
class IRMap
{
public:
    // Use unordered_map since the map won't change much once populated
    using inst_map_t = std::unordered_map<uint64_t /** inst address */, AsmInst>;
public:
    /** \brief The location of a given IR instruction, it is made of an IR block and the id of
     * the instruction within the block */
    struct InstLocation
    {
        InstLocation(uint64_t address, AsmInst::inst_id id): addr(address), inst_id(id){};
        uint64_t addr; ///< Address of the asm instruction
        AsmInst::inst_id inst_id; ///< The instruction id within the AsmInst at 'addr'
    };

private:
    inst_map_t asm_insts;
public:
    /// Add an AsmInst to the map and return the start address of this AsmInst
    uint64_t add(const AsmInst& inst);
    /// Add an AsmInst to the map and return the start address of this AsmInst
    uint64_t add(AsmInst&& inst);
    /// Returns AsmInst at address 'addr'. Raises an exception if the AsmInst is missing 
    AsmInst& get_inst_at(uint64_t addr);
    /// Returns true if the map contains the AsmInst for address 'addr'
    bool contains_inst_at(uint64_t addr);
    /** \brief Remove the AsmInsts whose raw bytes location overlaps
     * with ['start_addr','end_addr'] (included) */ 
    void remove_insts_containing(uint64_t start, uint64_t end);
    /// Remove instruction at address 'addr'
    void remove_inst_at(uint64_t addr);
};


/** \} */ // IR doxygen group

} // namespace ir
} // namespace maat
#endif 

