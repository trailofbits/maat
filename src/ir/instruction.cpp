#include "ir.hpp"
#include <iomanip>

namespace maat
{
namespace ir
{

bool is_assignment_op(const Op& op)
{
    return  op != ir::Op::LOAD and
            op != ir::Op::STORE and
            op != ir::Op::BRANCH and            
            op != ir::Op::CBRANCH and           
            op != ir::Op::BRANCHIND and
            op != ir::Op::CALL and         
            op != ir::Op::CALLIND and           
            op != ir::Op::CALLOTHER and         
            op != ir::Op::RETURN and
            op != ir::Op::INDIRECT and     
            op != ir::Op::CAST and                 
            op != ir::Op::SEGMENTOP and
            op != ir::Op::CPOOLREF and
            op != ir::Op::NEW;
}

bool is_memory_op(const Op& op)
{
    return  op == ir::Op::LOAD ||
            op == ir::Op::STORE ;
}

bool is_branch_op(const Op& op)
{
    return  op == ir::Op::BRANCH ||
            op == ir::Op::BRANCHIND ||
            op == ir::Op::CBRANCH ||
            op == ir::Op::CALL ||
            op == ir::Op::CALLIND ||
            op == ir::Op::RETURN;
}

/** Print an operation to a stream */
std::ostream& operator<<(std::ostream& os, const ir::Op& op)
{
    switch(op)
    {
        case ir::Op::COPY: os << "COPY"; break;
        case ir::Op::LOAD: os << "LOAD"; break;
        case ir::Op::STORE: os << "STORE"; break;
        case ir::Op::BRANCH: os << "BRANCH"; break;            
        case ir::Op::CBRANCH: os << "CBRANCH"; break;           
        case ir::Op::BRANCHIND: os << "BRANCHIND"; break;
        case ir::Op::CALL: os << "CALL"; break;         
        case ir::Op::CALLIND: os << "CALLIND"; break;           
        case ir::Op::CALLOTHER: os << "CALLOTHER"; break;         
        case ir::Op::RETURN: os << "RETURN"; break;            
        case ir::Op::INT_EQUAL: os << "INT_EQUAL"; break;        
        case ir::Op::INT_NOTEQUAL: os << "INT_NOTEQUAL"; break;     
        case ir::Op::INT_SLESS: os << "INT_SLESS"; break;        
        case ir::Op::INT_SLESSEQUAL: os << "INT_SLESSEQUAL"; break;   
        case ir::Op::INT_LESS: os << "INT_LESS"; break;         
        case ir::Op::INT_LESSEQUAL: os << "INT_LESSEQUAL"; break;     
        case ir::Op::INT_ZEXT: os << "INT_ZEXT"; break;         
        case ir::Op::INT_SEXT: os << "INT_SEXT"; break;         
        case ir::Op::INT_ADD: os << "INT_ADD"; break;           
        case ir::Op::INT_SUB: os << "INT_SUB"; break;           
        case ir::Op::INT_CARRY: os << "INT_CARRY"; break;        
        case ir::Op::INT_SCARRY: os << "INT_SCARRY"; break;        
        case ir::Op::INT_SBORROW: os << "INT_SBORROW"; break;       
        case ir::Op::INT_2COMP: os << "INT_2COMP"; break;         
        case ir::Op::INT_NEGATE: os << "INT_NEGATE"; break;        
        case ir::Op::INT_XOR: os << "INT_XOR"; break;           
        case ir::Op::INT_AND: os << "INT_AND"; break;           
        case ir::Op::INT_OR: os << "INT_OR"; break;           
        case ir::Op::INT_LEFT: os << "INT_SHL"; break;          
        case ir::Op::INT_RIGHT: os << "INT_SHR"; break;        
        case ir::Op::INT_SRIGHT: os << "INT_SAR"; break;       
        case ir::Op::INT_MULT: os << "INT_MULT"; break;         
        case ir::Op::INT_DIV: os << "INT_DIV"; break;          
        case ir::Op::INT_SDIV: os << "INT_SDIV"; break;         
        case ir::Op::INT_REM: os << "INT_REM"; break;          
        case ir::Op::INT_SREM: os << "INT_SREM"; break;         
        case ir::Op::BOOL_NEGATE: os << "BOOL_NEGATE"; break;     
        case ir::Op::BOOL_XOR: os << "BOOL_XOR"; break;         
        case ir::Op::BOOL_AND: os << "BOOL_AND"; break;         
        case ir::Op::BOOL_OR: os << "BOOL_OR"; break;          
        case ir::Op::FLOAT_EQUAL: os << "FLOAT_EQUAL"; break;      
        case ir::Op::FLOAT_NOTEQUAL: os << "FLOAT_NOTEQUAL"; break;  
        case ir::Op::FLOAT_LESS: os << "FLOAT_LESS"; break;      
        case ir::Op::FLOAT_LESSEQUAL: os << "FLOAT_LESSEQUAL"; break;            
        case ir::Op::FLOAT_NAN: os << "FLOAT_NAN"; break;         
        case ir::Op::FLOAT_ADD: os << "FLOAT_ADD"; break;         
        case ir::Op::FLOAT_DIV: os << "FLOAT_DIV"; break;        
        case ir::Op::FLOAT_MULT: os << "FLOAT_MULT"; break;       
        case ir::Op::FLOAT_SUB: os << "FLOAT_SUB"; break;        
        case ir::Op::FLOAT_NEG: os << "FLOAT_NEG"; break;        
        case ir::Op::FLOAT_ABS: os << "FLOAT_ABS"; break;        
        case ir::Op::FLOAT_SQRT: os << "FLOAT_SQRT"; break;      
        case ir::Op::FLOAT_INT2FLOAT: os << "FLOAT_INT2FLOAT"; break;  
        case ir::Op::FLOAT_FLOAT2FLOAT: os << "FLOAT_FLOAT2FLOAT"; break;
        case ir::Op::FLOAT_TRUNC: os << "FLOAT_TRUNC"; break;     
        case ir::Op::FLOAT_CEIL: os << "FLOAT_CEIL"; break;      
        case ir::Op::FLOAT_FLOOR: os << "FLOAT_FLOOR"; break;      
        case ir::Op::FLOAT_ROUND: os << "FLOAT_ROUND"; break;
        case ir::Op::MULTIEQUAL: os << "MULTIEQUAL"; break;     
        case ir::Op::INDIRECT: os << "INDIRECT"; break;        
        case ir::Op::PIECE: os << "PIECE"; break;           
        case ir::Op::SUBPIECE: os << "SUBPIECE"; break;        
        case ir::Op::CAST: os << "CAST"; break;           
        case ir::Op::PTRADD: os << "PTRADD"; break;           
        case ir::Op::PTRSUB: os << "PTRSUB"; break;         
        case ir::Op::SEGMENTOP: os << "SEGMENTOP"; break;       
        case ir::Op::CPOOLREF: os << "CPOOLREF"; break;         
        case ir::Op::NEW: os << "NEW"; break;              
        case ir::Op::INSERT: os << "INSERT"; break;          
        case ir::Op::EXTRACT: os << "EXTRACT"; break;          
        case ir::Op::POPCOUNT: os << "POPCOUNT"; break;  
        default: os << "???"; break;
    }
    return os;
}

Param::Param():
    type(Type::NONE),
    _val(0),
    hb(0),
    lb(0),
    _size(0)
{}

Param::Param(Type t, uint64_t val, size_t h, size_t l): 
    type(t),
    _val(val),
    hb(h),
    lb(l),
    _size(h-l+1)
{}

Param& Param::operator=(const Param& other)
{
    type = other.type;
    _val = other._val;
    hb = other.hb;
    lb = other.lb;
    _size = other._size;
    return *this;
}

bool Param::is_cst() const { return type == Type::CST; }
bool Param::is_cst(cst_t cst) const { return type == Param::Type::CST and _val == cst; }
bool Param::is_reg() const { return type == Type::REG; }
bool Param::is_reg(reg_t reg) const { return type == Param::Type::REG and _val == reg; }
bool Param::is_tmp() const { return type == Type::TMP; }
bool Param::is_tmp(tmp_t tmp) const { return type == Param::Type::TMP and _val == tmp; }
bool Param::is_addr() const { return type == Param::Type::ADDR; }
bool Param::is_none() const { return type == Type::NONE; }

cst_t Param::cst() const { return (cst_t)_val; }
reg_t Param::reg() const { return (reg_t)_val; }
tmp_t Param::tmp() const { return (tmp_t)_val; }
addr_t Param::addr() const { return (addr_t)_val; }

size_t Param::size() const { return _size; }

std::ostream& operator<<(std::ostream& os, const Param& param)
{
    switch(param.type)
    {
        case Param::Type::CST: os << param.cst(); break;
        case Param::Type::TMP: os << "TMP_" << std::dec << param.tmp(); break;
        case Param::Type::REG: os << "REG_" << std::dec << param.reg(); break;
        case Param::Type::ADDR: os << "@[0x" << std::hex << param.cst() << ":"
                                   << std::dec << param.size() << "]"; break;
        case Param::Type::NONE: os << "_" ; break;
    }
    if (param.is_reg() or param.is_tmp() or param.is_cst())
        os << "[" << param.hb << ":" << param.lb << "]";
    return os;
}

Param Cst(cst_t val, size_t size)
{
    return Param(Param::Type::CST, val, size-1, 0);
}

Param Cst(cst_t val, size_t hb, size_t lb)
{
    return Param(Param::Type::CST, val, hb, lb);
}

Param Addr(addr_t addr, size_t size)
{
    return Param(Param::Type::ADDR, addr, size-1, 0);
}

Param Reg(reg_t reg, size_t size)
{
    return Param(Param::Type::REG, reg, size-1, 0);
}

Param Reg(reg_t reg, size_t hb, size_t lb)
{
    return Param(Param::Type::REG, reg, hb, lb);
}

Param Tmp(tmp_t tmp, size_t size)
{
    return Param(Param::Type::TMP, tmp, size-1, 0);
}

Param Tmp(tmp_t tmp, size_t hb, size_t lb)
{
    return Param(Param::Type::TMP, tmp, hb, lb);
}

Param param_none = Param(Param::Type::NONE, 0, 0, 0);
const Param& Param::None()
{
    return param_none;
}

Inst::Inst():
    op(maat::ir::Op::NONE),
    out(Param::None()),
    in{Param::None(), Param::None(), Param::None()},
    callother_id(callother::Id::UNSUPPORTED)
{}

Inst::Inst(
        Op _op,
        const std::optional<Param>& _out,
        const std::optional<Param>& _in0,
        const std::optional<Param>& _in1,
        const std::optional<Param>& _in2
):  op(_op),
    callother_id(callother::Id::UNSUPPORTED)
{
    out = _out ? _out.value() : Param::None();
    in[0] = _in0 ? _in0.value() : Param::None();
    in[1] = _in1 ? _in1.value() : Param::None();
    in[2] = _in2 ? _in2.value() : Param::None();
}

inline bool Inst::_reads_type(Param::Type t, uint64_t v) const
{
    // TODO: not sure that CALLOTHER belongs here...
    if( ir::is_assignment_op(op) or op == ir::Op::CALLOTHER)
    {
        return      (in[0]._val == v and in[0].type == t)
                or  (in[1]._val == v and in[1].type == t);
    }
    else if (op == ir::Op::LOAD)
    {
        return (in[1]._val == v and in[1].type == t);
    }
    else if (op == ir::Op::STORE)
    {
        return      (in[1]._val == v and in[1].type == t)
                or  (in[2]._val == v and in[2].type == t);
    }
    else if (ir::is_branch_op(op))
    {
        // Only in[1] for CBRANCH
        return  (in[1]._val == v and in[1].type == t);
    }
    else
    {
        throw runtime_exception("Inst::_reads_type(): unsupported operation");
    }
}

inline bool Inst::_writes_type(Param::Type type, uint64_t v) const
{
    if (
        ir::is_assignment_op(op)
        or op == ir::Op::LOAD
        or op == ir::Op::CALLOTHER
    )
    {
        return out._val == v and out.type == type;
    }
    else if (op == ir::Op::STORE or ir::is_branch_op(op))
    {
        return false;
    }
    else
    {
        throw runtime_exception("Inst::_writes_type(): got unsupported operation");
    }
}

bool Inst::reads_reg(reg_t reg) const
{
    return _reads_type(Param::Type::REG, reg); 
}

bool Inst::writes_reg(reg_t reg) const
{
    return _writes_type(Param::Type::REG, reg);
}

bool Inst::uses_reg(reg_t reg) const
{
    return reads_reg(reg) or writes_reg(reg);
}

bool Inst::reads_tmp(tmp_t tmp) const
{
    return _reads_type(Param::Type::TMP, tmp); 
}

bool Inst::writes_tmp(tmp_t tmp) const
{
    return _writes_type(Param::Type::TMP, tmp);
}

void Inst::_get_read_types(Param::Type type, Inst::param_list_t& res) const
{
    // TODO: not sure that CALLOTHER belongs here
    if( ir::is_assignment_op(op) or op == ir::Op::CALLOTHER)
    {
        if(in[0].type == type)
            res.push_back(std::cref(in[0]));
        if( in[1].type == type)
            res.push_back(std::cref(in[1]));
    }
    else if (op == ir::Op::LOAD)
    {
        if (in[1].type == type)
            res.push_back(std::cref(in[1]));
    }
    else if (op == ir::Op::STORE)
    {
        if (in[1].type == type)
            res.push_back(std::cref(in[1]));
        if (in[2].type == type)
            res.push_back(std::cref(in[2]));
    }
    else if (ir::is_branch_op(op))
    {
        if(in[1].type == type)
            res.push_back(std::cref(in[1]));
        if( in[0].type == type )
            res.push_back(std::cref(in[0]));
    }
    else
    {
        throw runtime_exception("Inst::_read_types(): got unsupported operation");
    }
}

void Inst::_get_written_types(Param::Type type, Inst::param_list_t& res) const
{
    if (
        ir::is_assignment_op(op)
        or op == ir::Op::LOAD
        or op == ir::Op::CALLOTHER
    )
    {
        if(out.type == type)
            res.push_back(std::cref(out));
    }
    else if (ir::is_branch_op(op) or op == ir::Op::STORE)
    {
        return;
    }
    else
    {
        throw runtime_exception("Inst::_written_types(): got unsupported operation");
    }
}

void Inst::get_read_regs(Inst::param_list_t& res) const 
{
    return _get_read_types(Param::Type::REG, res);
}

void Inst::get_written_regs(Inst::param_list_t& res) const 
{
    return _get_written_types(Param::Type::REG, res);
}

void Inst::get_read_tmps(Inst::param_list_t& res) const 
{
    return _get_read_types(Param::Type::TMP, res);
}

void Inst::get_written_tmps(Inst::param_list_t& res) const 
{
    return _get_written_types(Param::Type::TMP, res);
}


std::ostream& operator<<(std::ostream& os, const Inst& inst)
{
    os << " " << std::setw(12) << std::left << inst.op;
    if (!inst.out.is_none())
        os << "    " << inst.out;
    if (!inst.in[0].is_none())
        os << "    " << inst.in[0];
    if (!inst.in[1].is_none())
        os << "    " << inst.in[1];
    if (!inst.in[2].is_none())
        os << "    " << inst.in[2];
    return os;
}

} // namespace ir
} // namespace maat
