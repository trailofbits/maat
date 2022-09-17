#include "maat/sleigh_interface.hpp"

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include <sleigh/loadimage.hh>
#include <sleigh/sleigh.hh>
#include <sleigh/types.h>

#include "maat/ir.hpp"
#include "maat/exception.hpp"
#include "maat/arch.hpp"
#include "maat/callother.hpp"
#include "maat/stats.hpp"

#include <optional>

// #define DEBUG
#ifdef DEBUG
#define LOG(fmt, ...) fprintf(stderr, "sleigh: " fmt "\n", ## __VA_ARGS__);
#else
#define LOG(fmt, ...) do {} while (0)
#endif

namespace maat
{

class SimpleLoadImage : public LoadImage
{
    uintb                m_baseaddr;
    int4                 m_length;
    const unsigned char *m_data;

public:
    SimpleLoadImage()
    : LoadImage("nofile")
    {
        m_baseaddr = 0;
        m_data = NULL;
        m_length = 0;
    }

    void setData(uintb ad, const unsigned char *ptr,int4 sz)
    {
        m_baseaddr = ad;
        m_data = ptr;
        m_length = sz;
    }

    void loadFill(uint1 *ptr, int4 size, const Address &addr)
    {
        uintb start = addr.getOffset();
        uintb max = m_baseaddr + m_length - 1;

        //
        // When decoding an instruction, SLEIGH will attempt to pull in several
        // bytes at a time, starting at each instruction boundary.
        //
        // If the start address is outside of the defined range, bail out.
        // Otherwise, if we have some data to provide but cannot sastisfy the
        // entire request, fill the remainder of the buffer with zero.
        //
        if (start > max || start < m_baseaddr) {
            throw std::out_of_range("Attempting to lift outside buffer range");
        }

        for(int4 i = 0; i < size; i++) {
            uintb curoff = start + i;
            if ((curoff < m_baseaddr) || (curoff>max)) {
                ptr[i] = 0;
                continue;
            }
            uintb diff = curoff - m_baseaddr;
            ptr[i] = m_data[(int4)diff];
        }
    }

    virtual string getArchType(void) const { return "myload"; }
    virtual void adjustVma(long adjust) { }
};

std::string opcode_to_str(OpCode op);
maat::ir::Op translate_pcode_op(OpCode op)
{
    switch (op)
    {
        case OpCode::CPUI_COPY: return maat::ir::Op::COPY;
        case OpCode::CPUI_LOAD: return maat::ir::Op::LOAD;
        case OpCode::CPUI_STORE: return maat::ir::Op::STORE;
        case OpCode::CPUI_BRANCH: return maat::ir::Op::BRANCH;            
        case OpCode::CPUI_CBRANCH: return maat::ir::Op::CBRANCH;           
        case OpCode::CPUI_BRANCHIND: return maat::ir::Op::BRANCHIND;
        case OpCode::CPUI_CALL: return maat::ir::Op::CALL;         
        case OpCode::CPUI_CALLIND: return maat::ir::Op::CALLIND;           
        case OpCode::CPUI_CALLOTHER: return maat::ir::Op::CALLOTHER;         
        case OpCode::CPUI_RETURN: return maat::ir::Op::RETURN;            
        case OpCode::CPUI_INT_EQUAL: return maat::ir::Op::INT_EQUAL;        
        case OpCode::CPUI_INT_NOTEQUAL: return maat::ir::Op::INT_NOTEQUAL;     
        case OpCode::CPUI_INT_SLESS: return maat::ir::Op::INT_SLESS;        
        case OpCode::CPUI_INT_SLESSEQUAL: return maat::ir::Op::INT_SLESSEQUAL;   
        case OpCode::CPUI_INT_LESS: return maat::ir::Op::INT_LESS;         
        case OpCode::CPUI_INT_LESSEQUAL: return maat::ir::Op::INT_LESSEQUAL;     
        case OpCode::CPUI_INT_ZEXT: return maat::ir::Op::INT_ZEXT;         
        case OpCode::CPUI_INT_SEXT: return maat::ir::Op::INT_SEXT;         
        case OpCode::CPUI_INT_ADD: return maat::ir::Op::INT_ADD;           
        case OpCode::CPUI_INT_SUB: return maat::ir::Op::INT_SUB;           
        case OpCode::CPUI_INT_CARRY: return maat::ir::Op::INT_CARRY;        
        case OpCode::CPUI_INT_SCARRY: return maat::ir::Op::INT_SCARRY;        
        case OpCode::CPUI_INT_SBORROW: return maat::ir::Op::INT_SBORROW;       
        case OpCode::CPUI_INT_2COMP: return maat::ir::Op::INT_2COMP;         
        case OpCode::CPUI_INT_NEGATE: return maat::ir::Op::INT_NEGATE;        
        case OpCode::CPUI_INT_XOR: return maat::ir::Op::INT_XOR;           
        case OpCode::CPUI_INT_AND: return maat::ir::Op::INT_AND;           
        case OpCode::CPUI_INT_OR: return maat::ir::Op::INT_OR;           
        case OpCode::CPUI_INT_LEFT: return maat::ir::Op::INT_LEFT;          
        case OpCode::CPUI_INT_RIGHT: return maat::ir::Op::INT_RIGHT;        
        case OpCode::CPUI_INT_SRIGHT: return maat::ir::Op::INT_SRIGHT;       
        case OpCode::CPUI_INT_MULT: return maat::ir::Op::INT_MULT;         
        case OpCode::CPUI_INT_DIV: return maat::ir::Op::INT_DIV;          
        case OpCode::CPUI_INT_SDIV: return maat::ir::Op::INT_SDIV;         
        case OpCode::CPUI_INT_REM: return maat::ir::Op::INT_REM;          
        case OpCode::CPUI_INT_SREM: return maat::ir::Op::INT_SREM;         
        case OpCode::CPUI_BOOL_NEGATE: return maat::ir::Op::BOOL_NEGATE;     
        case OpCode::CPUI_BOOL_XOR: return maat::ir::Op::BOOL_XOR;         
        case OpCode::CPUI_BOOL_AND: return maat::ir::Op::BOOL_AND;         
        case OpCode::CPUI_BOOL_OR: return maat::ir::Op::BOOL_OR;          
        case OpCode::CPUI_FLOAT_EQUAL: return maat::ir::Op::FLOAT_EQUAL;      
        case OpCode::CPUI_FLOAT_NOTEQUAL: return maat::ir::Op::FLOAT_NOTEQUAL;  
        case OpCode::CPUI_FLOAT_LESS: return maat::ir::Op::FLOAT_LESS;      
        case OpCode::CPUI_FLOAT_LESSEQUAL: return maat::ir::Op::FLOAT_LESSEQUAL;            
        case OpCode::CPUI_FLOAT_NAN: return maat::ir::Op::FLOAT_NAN;         
        case OpCode::CPUI_FLOAT_ADD: return maat::ir::Op::FLOAT_ADD;         
        case OpCode::CPUI_FLOAT_DIV: return maat::ir::Op::FLOAT_DIV;        
        case OpCode::CPUI_FLOAT_MULT: return maat::ir::Op::FLOAT_MULT;       
        case OpCode::CPUI_FLOAT_SUB: return maat::ir::Op::FLOAT_SUB;        
        case OpCode::CPUI_FLOAT_NEG: return maat::ir::Op::FLOAT_NEG;        
        case OpCode::CPUI_FLOAT_ABS: return maat::ir::Op::FLOAT_ABS;        
        case OpCode::CPUI_FLOAT_SQRT: return maat::ir::Op::FLOAT_SQRT;      
        case OpCode::CPUI_FLOAT_INT2FLOAT: return maat::ir::Op::FLOAT_INT2FLOAT;  
        case OpCode::CPUI_FLOAT_FLOAT2FLOAT: return maat::ir::Op::FLOAT_FLOAT2FLOAT;
        case OpCode::CPUI_FLOAT_TRUNC: return maat::ir::Op::FLOAT_TRUNC;     
        case OpCode::CPUI_FLOAT_CEIL: return maat::ir::Op::FLOAT_CEIL;      
        case OpCode::CPUI_FLOAT_FLOOR: return maat::ir::Op::FLOAT_FLOOR;      
        case OpCode::CPUI_FLOAT_ROUND: return maat::ir::Op::FLOAT_ROUND;
        case OpCode::CPUI_MULTIEQUAL: return maat::ir::Op::MULTIEQUAL;     
        case OpCode::CPUI_INDIRECT: return maat::ir::Op::INDIRECT;        
        case OpCode::CPUI_PIECE: return maat::ir::Op::PIECE;           
        case OpCode::CPUI_SUBPIECE: return maat::ir::Op::SUBPIECE;        
        case OpCode::CPUI_CAST: return maat::ir::Op::CAST;           
        case OpCode::CPUI_PTRADD: return maat::ir::Op::PTRADD;           
        case OpCode::CPUI_PTRSUB: return maat::ir::Op::PTRSUB;         
        case OpCode::CPUI_SEGMENTOP: return maat::ir::Op::SEGMENTOP;       
        case OpCode::CPUI_CPOOLREF: return maat::ir::Op::CPOOLREF;         
        case OpCode::CPUI_NEW: return maat::ir::Op::NEW;              
        case OpCode::CPUI_INSERT: return maat::ir::Op::INSERT;          
        case OpCode::CPUI_EXTRACT: return maat::ir::Op::EXTRACT;          
        case OpCode::CPUI_POPCOUNT: return maat::ir::Op::POPCOUNT;
        default: throw maat::runtime_exception(maat::Fmt()
                            << "translate_pcode_op(): Got unsupported PCODE operation: "
                            << opcode_to_str(op)
                            >> maat::Fmt::to_str
                        );
    }
}

class TmpCache
{
private:
    // tmp_map[x] = y <==> unique[x] in pcode is tmp(y) in maat
    std::unordered_map<int, int> tmp_map;
    int tmp_cnt;
public:
    TmpCache(): tmp_cnt(0){}
public:
    int get_tmp_from_unique(int unique)
    {
        auto it = tmp_map.find(unique);
        if (it != tmp_map.end())
            return it->second;
        else
        {
            tmp_map[unique] = tmp_cnt++;
            return tmp_map[unique];
        }
    }
    
    void clear()
    {
        tmp_cnt = 0;
        tmp_map.clear();
    }
};

class TranslationContext;
maat::ir::Param translate_pcode_param(TranslationContext* ctx, VarnodeData* v);

class PcodeEmitCacher : public PcodeEmit
{
public:
    uintm m_uniq;
    std::vector<maat::ir::Inst> m_insts;
    TranslationContext* translation_ctx;

    PcodeEmitCacher() : m_uniq(0), translation_ctx(nullptr)
    {}

    PcodeEmitCacher(TranslationContext* ctx) : m_uniq(0), translation_ctx(ctx)
    {}

    void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
              VarnodeData *vars, int4 isize)
    {
        assert(isize > 0);

        m_insts.emplace_back();
        maat::ir::Inst& inst = m_insts.back();
        // TODO remove addr and size in header also
        inst.op = translate_pcode_op(opc);

        if (outvar)
        {
            inst.out = translate_pcode_param(translation_ctx, outvar);
        }

        for (int i = 0; i < isize; i++)
        {
            inst.in[i] = translate_pcode_param(translation_ctx, &vars[i]);
        }
    }

    std::vector<ir::Inst>&& get_pcode_instructions()
    {
        return std::move(m_insts);
    }

    void clear()
    {
        m_insts.clear();
    }
};


static std::string missing_str = "<missing asm>";
class AssemblyEmitCacher : public AssemblyEmit
{
public:
    std::map<uintptr_t, std::string> cache;

    void dump(const Address &addr, const string &mnem, const string &body)
    {
        cache[addr.getOffset()] = mnem + " " + body;
    }

    bool contains(uintptr_t addr)
    {
        return cache.find(addr) != cache.end();
    }

    const std::string& get_asm(uintptr_t addr)
    {
        if (not contains(addr))
            return missing_str;
        else
            return cache[addr];
    }

    const std::string get_mnemonic(uintptr_t addr)
    {
        if (not contains(addr))
            return missing_str;
        std::string res = get_asm(addr);
        return res.substr(0, res.find(" "));
    }

    void clear(uintptr_t addr_min, uintptr_t addr_max)
    {
        throw runtime_exception("AssemblyEmitCacher::clear() not implemented!");
    }
};

class TranslationContext
{
public:
    SimpleLoadImage     m_loader;
    ContextInternal     m_context_internal;
    DocumentStorage     m_document_storage;
    Document           *m_document;
    Element            *m_tags;
    unique_ptr<Sleigh>  m_sleigh;
    string              m_register_name_cache;
    TmpCache            tmp_cache;
    maat::Arch::Type    arch;
    AssemblyEmitCacher  asm_cache;
    std::unordered_map<uintm, maat::callother::Id> callother_mapping;

    TranslationContext(maat::Arch::Type a, const std::string& slafile, const std::string& pspecfile): arch(a)
    {
        if (not loadSlaFile(slafile.c_str()))
        {
            throw runtime_exception(Fmt() << "Sleigh: failed to load slafile: " << slafile >> Fmt::to_str);
        }
        if (not pspecfile.empty() and not loadPspecFile(pspecfile.c_str()))
        {
            throw runtime_exception(Fmt() << "Sleigh: failed to load pspecfile: " << pspecfile >> Fmt::to_str);
        }

        // For EVM we add special callother operations, need to build the mapping to callother::Id
        // for them
        if (a == maat::Arch::Type::EVM)
            build_callother_mapping_EVM();
    }

    ~TranslationContext()
    {}

    bool loadSlaFile(const char *path)
    {
        LOG("%p Loading slafile...", this);
        // TODO try/catch XmlError
        m_document = m_document_storage.openDocument(path);
        m_tags = m_document->getRoot();
        m_document_storage.registerTag(m_tags);

        LOG("Setting up translator");
        m_sleigh.reset(new Sleigh(&m_loader, &m_context_internal));
        m_sleigh->initialize(m_document_storage);

        return true;
    }

    bool loadPspecFile(const char *path)
    {
        LOG("%p Loading pspec file...", this);
        DocumentStorage storage;
        Element *root = storage.openDocument(path)->getRoot();
        if (root == NULL)
            return false;
        std::string name;
        std::string value;
        for (Element* elem : root->getChildren())
        {
            if (elem->getName() != "context_data")
                continue;
            for (Element* child : elem->getChildren())
            {
                if (child->getName() == "context_set")
                {
                    for (Element* item : child->getChildren())
                    {
                        if (item->getName() == "set")
                        {
                            name = item->getAttributeValue("name");
                            value = item->getAttributeValue("val");
                            m_context_internal.setVariableDefault(name, std::stoi(value));
                        }
                    }
                    break;
                }
            }
        }
        return true;
    }


    const std::string& get_asm(uintb address, const unsigned char* bytes)
    {
        // TODO: force relifting everytime until we support clearing the
        // asm cache on X memory overwrites
        // if (asm_cache.contains(address))
        //     return asm_cache.get_asm(address);

        // Get asm
        // 16 bytes is the max instruction length supported by sleigh
        m_loader.setData(address, bytes, 16); 
        Address addr(m_sleigh->getDefaultCodeSpace(), address);
        m_sleigh->printAssembly(asm_cache, addr);

        return asm_cache.get_asm(address);
    }

    void translate(
        ir::IRMap& ir_map,
        const unsigned char *bytes,
        unsigned int num_bytes,
        uintb address,
        unsigned int max_instructions,
        bool bb_terminating
    )
    {
        unsigned int    inst_count = 0;
        int4            offset = 0;
        bool            end_bb = false;

        PcodeEmitCacher    m_pcode(this);
        AssemblyEmitCacher& tmp_cacher = asm_cache;

        // Reset state
        // TODO - is this useful ? will this hinder performance ?
        // Needs to be here apparently but maybe we could tweak setData so we don't need to reset...
        m_sleigh->reset(&m_loader, &m_context_internal);
        m_sleigh->initialize(m_document_storage);
        // setData doesn't affect performance for a big num_bytes :)
        m_loader.setData(address, bytes, num_bytes);

        // Translate instructions
        while ( !end_bb && (offset < num_bytes) && 
                (!max_instructions || (inst_count++ < max_instructions))) 
        {
            try
            {
                Address addr(m_sleigh->getDefaultCodeSpace(), address + offset);
                
                // Get instruction length
                int4 ilen = m_sleigh->instructionLength(addr);

                // Process pcode for this instruction
                tmp_cache.clear();
                m_pcode.clear();
                m_sleigh->oneInstruction(m_pcode, addr);

                // Create AsmInst
                ir::AsmInst asm_inst(address+offset, ilen);
                asm_inst.add_insts(m_pcode.get_pcode_instructions());

                // Record lifted instruction in statistics
                MaatStats::instance().inc_lifted_insts();

                // Increment offset to point to next instruction
                offset += ilen;

                // for (auto& inst : asm_inst.instructions())
                // {
                //     std::cout << "DEBUG " << inst << "\n";
                // }

                for (ir::Inst& inst : asm_inst.instructions())
                {
                    // Check for CALLOTHER, we need dedicated handlers to support them
                    if (inst.op == maat::ir::Op::CALLOTHER)
                    {
                        // Get inst name
                        addr_t tmp_addr = address + offset -ilen;
                        m_sleigh->printAssembly(
                            tmp_cacher,
                            Address(m_sleigh->getDefaultCodeSpace(), tmp_addr)
                        );
                        std::string mnem = tmp_cacher.get_mnemonic(tmp_addr);
                        // Get callother id in maat
                        callother::Id id = callother::Id::UNSUPPORTED;
                        // Try using the sleigh symbol id directly
                        uintm sleigh_pcodeop_id = inst.in[0].cst();
                        auto match = callother_mapping.find(sleigh_pcodeop_id);
                        if (match != callother_mapping.end())
                            id = match->second;
                        // If no match found in sleigh_id <-> callother_id mapping,
                        // try matching the mnemonic
                        if (id == callother::Id::UNSUPPORTED)
                            id = callother::mnemonic_to_id(mnem, arch);

                        // Set the callother_id in inst
                        inst.callother_id = id;

                        if (id == callother::Id::UNSUPPORTED)
                        {
                            inst = ir::Inst(ir::Op::UNSUPPORTED);
                        }
                    }

                    // Check for branch instruction (basic block terminates)
                    if (bb_terminating)
                    {
                        // CALL or BRANCH but we ignore CBRANCH because if the
                        // branch is not taken execution might continue
                        if (
                            inst.op == maat::ir::Op::CALL or
                            inst.op == maat::ir::Op::BRANCH
                        )
                        {
                            if (
                                (inst.in[0].is_addr() and inst.in[0].addr() != asm_inst.addr())
                                or inst.in[0].is_tmp() 
                                or inst.in[0].is_reg()
                            )
                            {
                                end_bb = true;
                                break;
                            }
                        }
                        else if (
                            inst.op == maat::ir::Op::RETURN or
                            inst.op == maat::ir::Op::BRANCHIND or
                            inst.op == maat::ir::Op::CALLIND
                        )
                        {
                            end_bb = true;
                            break;
                        }
                    }
                }
                // Add AsmInst to the IR map
                ir_map.add(std::move(asm_inst));

            } catch (UnimplError &e) {
                throw maat::lifter_exception(
                    Fmt() << "Sleigh raised an unimplemented exception: " << e.explain
                    >> Fmt::to_str
                );

            } catch (BadDataError &e) {
                throw maat::lifter_exception(
                    Fmt() << "Sleigh raised a bad data exception: " << e.explain
                    >> Fmt::to_str
                );
            }
        }
    }

    const std::string getRegisterName(AddrSpace* as, uintb off, int4 size)
    {
        return m_sleigh->getRegisterName(as, off, size);
    }

    void build_callother_mapping_EVM()
    {
        SleighSymbol* symbol = nullptr;
        // Note: the operator names MUST match the names in EVM.slaspec
        std::unordered_map<std::string, callother::Id> operators = {
            {"stack_pop",callother::Id::EVM_STACK_POP}, 
            {"stack_push",callother::Id::EVM_STACK_PUSH},
            {"stop",callother::Id::EVM_STOP},
            {"evm_div",callother::Id::EVM_DIV},
            {"evm_sdiv",callother::Id::EVM_SDIV},
            {"evm_mod",callother::Id::EVM_MOD},
            {"evm_smod",callother::Id::EVM_SMOD},
            {"evm_signextend", callother::Id::EVM_SIGNEXTEND},
            {"evm_byte", callother::Id::EVM_BYTE},
            {"evm_mload", callother::Id::EVM_MLOAD},
            {"evm_mstore", callother::Id::EVM_MSTORE},
            {"evm_mstore8", callother::Id::EVM_MSTORE8},
            {"evm_msize", callother::Id::EVM_MSIZE},
            {"evm_dup", callother::Id::EVM_DUP},
            {"evm_swap", callother::Id::EVM_SWAP},
            {"evm_sload", callother::Id::EVM_SLOAD},
            {"evm_sstore", callother::Id::EVM_SSTORE},
            {"evm_env_info", callother::Id::EVM_ENV_INFO},
            {"evm_keccak", callother::Id::EVM_KECCAK},
            {"evm_return", callother::Id::EVM_RETURN},
            {"evm_invalid", callother::Id::EVM_INVALID},
            {"evm_revert", callother::Id::EVM_REVERT},
            {"evm_exp", callother::Id::EVM_EXP},
            {"evm_call", callother::Id::EVM_CALL},
            {"evm_callcode", callother::Id::EVM_CALLCODE},
            {"evm_delegatecall", callother::Id::EVM_DELEGATECALL},
            {"evm_create", callother::Id::EVM_CREATE},
            {"evm_selfdestruct", callother::Id::EVM_SELFDESTRUCT},
            {"evm_log", callother::Id::EVM_LOG}
        };

        for (const auto& [op_str, op_id] : operators)
        {
            symbol = m_sleigh->findSymbol(op_str);
            if (symbol == nullptr)
                throw lifter_exception(
                    Fmt() << "Error instanciating sleigh lifter, didn't find symbol for operator "
                    << op_str >> Fmt::to_str
                );
            if (symbol->getType() != SleighSymbol::symbol_type::userop_symbol)
                throw lifter_exception(
                    Fmt() << "Error instanciating sleigh lifter, wrong symbol type for operator "
                    << op_str >> Fmt::to_str
                );
            callother_mapping[((UserOpSymbol*)symbol)->getIndex()] = op_id;
        }
    }
};

// Translate a sleigh register name into a maat::ir::Param register
maat::ir::Param reg_name_to_maat_reg(maat::Arch::Type arch, const std::string& reg_name);
// Translate a pcode varnode into an parameter and add it to inst
maat::ir::Param translate_pcode_param(TranslationContext* ctx, VarnodeData* v)
{
    assert(v->space != NULL);

    // Check if constant
    Address addr(v->space, v->offset);
    if (addr.isConstant())
    {
        return maat::ir::Cst(v->offset, v->size*8);
    }
    else
    {
        // TODO(boyan): use v->space->getType() here instead of the name :/
        // Is reg or tmp
        const std::string& addr_space_name = v->space->getName();
        if (addr_space_name == "register")
        {
            const std::string& reg_name = ctx->getRegisterName(v->space, v->offset, v->size);
            return std::move(reg_name_to_maat_reg(ctx->arch, reg_name));
        }
        else if (addr_space_name == "unique")
        {
            int tmp = ctx->tmp_cache.get_tmp_from_unique(v->offset);
            return std::move(maat::ir::Tmp(tmp, v->size*8));
        }
        else if (addr_space_name == "ram" or addr_space_name == "code")
        {
            // just store the address
            // the size of the output var will give the nb of accessed bytes
            return std::move(maat::ir::Addr(v->offset, v->size*8));
        }
        else
        {
            throw maat::runtime_exception(maat::Fmt()
                << "translate_pcode_param(): Got unsupported address space : "
                << addr_space_name
                >> maat::Fmt::to_str
            );
        }
    }
    return maat::ir::Param::None();
}

maat::ir::Param reg_name_to_maat_reg(maat::Arch::Type arch, const std::string& reg_name)
{
    if (arch == Arch::Type::X86)
        return sleigh_reg_translate_X86(reg_name);
    else if (arch == Arch::Type::X64)
        return sleigh_reg_translate_X64(reg_name);
    else if (arch == Arch::Type::EVM)
        return sleigh_reg_translate_EVM(reg_name);
    else if (arch == Arch::Type::RISCV)
        return sleigh_reg_translate_RISCV(reg_name);
    else
        throw maat::runtime_exception("Register translation from SLEIGH to MAAT not implemented for this architecture!");
}


std::shared_ptr<TranslationContext> new_sleigh_ctx(
    maat::Arch::Type arch,
    const std::string& slafile,
    const std::string& pspecfile
)
{
    return std::make_shared<TranslationContext>(arch, slafile, pspecfile);
}

void sleigh_translate(
    std::shared_ptr<TranslationContext> ctx,
    ir::IRMap& ir_map,
    const unsigned char *bytes,
    unsigned int num_bytes,
    uintptr_t address,
    unsigned int max_instructions,
    bool bb_terminating
){
    return ctx->translate(
        ir_map,
        bytes,
        num_bytes,
        address,
        max_instructions,
        bb_terminating
    );
}

const std::string& sleigh_get_asm(
    std::shared_ptr<TranslationContext> ctx,
    uintptr_t address,
    const unsigned char* bytes
)
{
    return ctx->get_asm(address, bytes);
}

std::string opcode_to_str(OpCode op)
{
    std::string res;
    switch (op)
    {
        case OpCode::CPUI_COPY: res = "COPY"; break;
        case OpCode::CPUI_LOAD: res = "LOAD"; break;
        case OpCode::CPUI_STORE: res = "STORE"; break;
        case OpCode::CPUI_BRANCH: res = "BRANCH"; break;            
        case OpCode::CPUI_CBRANCH: res = "CBRANCH"; break;           
        case OpCode::CPUI_BRANCHIND: res = "BRANCHIND"; break;
        case OpCode::CPUI_CALL: res = "CALL"; break;         
        case OpCode::CPUI_CALLIND: res = "CALLIND"; break;           
        case OpCode::CPUI_CALLOTHER: res = "CALLOTHER"; break;         
        case OpCode::CPUI_RETURN: res = "RETURN"; break;            
        case OpCode::CPUI_INT_EQUAL: res = "INT_EQUAL"; break;        
        case OpCode::CPUI_INT_NOTEQUAL: res = "INT_NOTEQUAL"; break;     
        case OpCode::CPUI_INT_SLESS: res = "INT_SLESS"; break;        
        case OpCode::CPUI_INT_SLESSEQUAL: res = "INT_SLESSEQUAL"; break;   
        case OpCode::CPUI_INT_LESS: res = "INT_LESS"; break;         
        case OpCode::CPUI_INT_LESSEQUAL: res = "INT_LESSEQUAL"; break;     
        case OpCode::CPUI_INT_ZEXT: res = "INT_ZEXT"; break;         
        case OpCode::CPUI_INT_SEXT: res = "INT_SEXT"; break;         
        case OpCode::CPUI_INT_ADD: res = "INT_ADD"; break;           
        case OpCode::CPUI_INT_SUB: res = "INT_SUB"; break;           
        case OpCode::CPUI_INT_CARRY: res = "INT_CARRY"; break;        
        case OpCode::CPUI_INT_SCARRY: res = "INT_SCARRY"; break;        
        case OpCode::CPUI_INT_SBORROW: res = "INT_SBORROW"; break;       
        case OpCode::CPUI_INT_2COMP: res = "INT_2COMP"; break;         
        case OpCode::CPUI_INT_NEGATE: res = "INT_NEGATE"; break;        
        case OpCode::CPUI_INT_XOR: res = "INT_XOR"; break;           
        case OpCode::CPUI_INT_AND: res = "INT_AND"; break;           
        case OpCode::CPUI_INT_OR: res = "INT_OR"; break;           
        case OpCode::CPUI_INT_LEFT: res = "INT_SHL"; break;          
        case OpCode::CPUI_INT_RIGHT: res = "INT_SHR"; break;        
        case OpCode::CPUI_INT_SRIGHT: res = "INT_SAR"; break;       
        case OpCode::CPUI_INT_MULT: res = "INT_MULT"; break;         
        case OpCode::CPUI_INT_DIV: res = "INT_DIV"; break;          
        case OpCode::CPUI_INT_SDIV: res = "INT_SDIV"; break;         
        case OpCode::CPUI_INT_REM: res = "INT_REM"; break;          
        case OpCode::CPUI_INT_SREM: res = "INT_SREM"; break;         
        case OpCode::CPUI_BOOL_NEGATE: res = "BOOL_NEGATE"; break;     
        case OpCode::CPUI_BOOL_XOR: res = "BOOL_XOR"; break;         
        case OpCode::CPUI_BOOL_AND: res = "BOOL_AND"; break;         
        case OpCode::CPUI_BOOL_OR: res = "BOOL_OR"; break;          
        case OpCode::CPUI_FLOAT_EQUAL: res = "FLOAT_EQUAL"; break;      
        case OpCode::CPUI_FLOAT_NOTEQUAL: res = "FLOAT_NOTEQUAL"; break;  
        case OpCode::CPUI_FLOAT_LESS: res = "FLOAT_LESS"; break;      
        case OpCode::CPUI_FLOAT_LESSEQUAL: res = "FLOAT_LESSEQUAL"; break;            
        case OpCode::CPUI_FLOAT_NAN: res = "FLOAT_NAN"; break;         
        case OpCode::CPUI_FLOAT_ADD: res = "FLOAT_ADD"; break;         
        case OpCode::CPUI_FLOAT_DIV: res = "FLOAT_DIV"; break;        
        case OpCode::CPUI_FLOAT_MULT: res = "FLOAT_MULT"; break;       
        case OpCode::CPUI_FLOAT_SUB: res = "FLOAT_SUB"; break;        
        case OpCode::CPUI_FLOAT_NEG: res = "FLOAT_NEG"; break;        
        case OpCode::CPUI_FLOAT_ABS: res = "FLOAT_ABS"; break;        
        case OpCode::CPUI_FLOAT_SQRT: res = "FLOAT_SQRT"; break;      
        case OpCode::CPUI_FLOAT_INT2FLOAT: res = "FLOAT_INT2FLOAT"; break;  
        case OpCode::CPUI_FLOAT_FLOAT2FLOAT: res = "FLOAT_FLOAT2FLOAT"; break;
        case OpCode::CPUI_FLOAT_TRUNC: res = "FLOAT_TRUNC"; break;     
        case OpCode::CPUI_FLOAT_CEIL: res = "FLOAT_CEIL"; break;      
        case OpCode::CPUI_FLOAT_FLOOR: res = "FLOAT_FLOOR"; break;      
        case OpCode::CPUI_FLOAT_ROUND: res = "FLOAT_ROUND"; break;
        case OpCode::CPUI_MULTIEQUAL: res = "MULTIEQUAL"; break;     
        case OpCode::CPUI_INDIRECT: res = "INDIRECT"; break;        
        case OpCode::CPUI_PIECE: res = "PIECE"; break;           
        case OpCode::CPUI_SUBPIECE: res = "SUBPIECE"; break;        
        case OpCode::CPUI_CAST: res = "CAST"; break;           
        case OpCode::CPUI_PTRADD: res = "PTRADD"; break;           
        case OpCode::CPUI_PTRSUB: res = "PTRSUB"; break;         
        case OpCode::CPUI_SEGMENTOP: res = "SEGMENTOP"; break;       
        case OpCode::CPUI_CPOOLREF: res = "CPOOLREF"; break;         
        case OpCode::CPUI_NEW: res = "NEW"; break;              
        case OpCode::CPUI_INSERT: res = "INSERT"; break;          
        case OpCode::CPUI_EXTRACT: res = "EXTRACT"; break;          
        case OpCode::CPUI_POPCOUNT: res = "POPCOUNT"; break;          
        default: res = "????"; break;
    }
    return res;
}

} // namespace maat
