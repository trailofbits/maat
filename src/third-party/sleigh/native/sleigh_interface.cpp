//
// Minimal SLEIGH library C API, for disassembly and translation to P-code.
//
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include "sleigh/loadimage.hh"
#include "sleigh/sleigh.hh"
#include "sleigh_interface.hpp"
#include "sleigh/types.h"

#include "ir.hpp"
#include "exception.hpp"
#include "arch.hpp"
#include "callother.hpp"

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
    int inst_size = 0;

    PcodeEmitCacher() : m_uniq(0), translation_ctx(nullptr)
    {}

    PcodeEmitCacher(TranslationContext* ctx, int is) : m_uniq(0), translation_ctx(ctx), inst_size(is)
    {}

    void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
              VarnodeData *vars, int4 isize)
    {
        assert(isize > 0);

        m_insts.emplace_back();
        maat::ir::Inst& inst = m_insts.back();
        inst.addr = addr.getOffset();
        inst.size = inst_size;
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
    const std::string   arch;
    AssemblyEmitCacher  asm_cache;

    TranslationContext(const std::string a, const std::string& slafile, const std::string& pspecfile): arch(a)
    {
        if (not loadSlaFile(slafile.c_str()))
        {
            throw runtime_exception(Fmt() << "Sleigh: failed to load slafile: " << slafile >> Fmt::to_str);
        }
        if (not pspecfile.empty() and not loadPspecFile(pspecfile.c_str()))
        {
            throw runtime_exception(Fmt() << "Sleigh: failed to load pspecfile: " << pspecfile >> Fmt::to_str);
        }
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
        if (asm_cache.contains(address))
            return asm_cache.get_asm(address);

        // Get asm
        m_loader.setData(address, bytes, 100); // TODO, 100 is arbitrary here
        Address addr(m_sleigh->getDefaultCodeSpace(), address);
        m_sleigh->printAssembly(asm_cache, addr);

        return asm_cache.get_asm(address);
    }

    std::shared_ptr<maat::ir::Block> translate(
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
        
        tmp_cache.clear();

        vector<PcodeEmitCacher>    m_pcodes;
        AssemblyEmitCacher tmp_cacher;

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
                m_pcodes.emplace_back(this, ilen);
                m_sleigh->oneInstruction(m_pcodes.back(), addr);
                
                // Increment offset to point to next instruction
                offset += ilen;

                // for (auto& inst : m_pcodes.back().m_insts)
                // {
                //     std::cout << "DEBUG " << inst << "\n";
                // }

                for (auto& inst : m_pcodes.back().m_insts)
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
                        callother::Id id = callother::mnemonic_to_id(mnem, arch);
                        // Set the callother_id in inst
                        inst.callother_id = id;

                        if (id == callother::Id::UNSUPPORTED)
                        {
                            throw maat::lifter_exception(
                                maat::Fmt() << ": Can not lift instruction at 0x"
                                << std::hex << tmp_addr << ": " << tmp_cacher.get_asm(tmp_addr)
                                << " (unsupported callother occurence)"
                                >> maat::Fmt::to_str
                            );
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
                                (inst.in[0].is_addr() and inst.in[0].addr() != inst.addr)
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
            } catch (UnimplError &e) {
                // TODO: handle exception
                break;
            } catch (BadDataError &e) {
                // TODO: handle exception
                break;
            }
        }

        // Create ir block and fill it
        std::shared_ptr<maat::ir::Block> block = std::make_shared<maat::ir::Block>("", address, address+offset-1);
        for (int i = 0; i < inst_count; i++)
        {
            // Add IR instructions
            block->add_insts(m_pcodes[i].m_insts);
            // TODO add asm info in bblock directly
        }

        return block;
    }

    const std::string getRegisterName(AddrSpace* as, uintb off, int4 size)
    {
        return m_sleigh->getRegisterName(as, off, size);
    }
};

// Translate a sleigh register name into a maat::ir::Param register
maat::ir::Param reg_name_to_maat_reg(const std::string& arch, const std::string& reg_name);
// Translate a pcode varnode into an parameter and add it to inst
maat::ir::Param translate_pcode_param(TranslationContext* ctx, VarnodeData* v)
{
    assert(var->space != NULL);

    // Check if constant
    Address addr(v->space, v->offset);
    if (addr.isConstant())
    {
        return maat::ir::Cst(v->offset, v->size*8);
    }
    else
    {
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
        else if (addr_space_name == "ram")
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

maat::ir::Param reg_name_to_maat_reg(const std::string& arch, const std::string& reg_name)
{
    if (arch == "X86")
    {
        if (reg_name == "AL") return maat::ir::Reg(maat::X86::EAX, 7, 0);
        if (reg_name == "AH") return maat::ir::Reg(maat::X86::EAX, 15, 8);
        if (reg_name == "AX") return maat::ir::Reg(maat::X86::EAX, 15, 0);
        if (reg_name == "EAX") return maat::ir::Reg(maat::X86::EAX, 31, 0);
        if (reg_name == "BL") return maat::ir::Reg(maat::X86::EBX, 7, 0);
        if (reg_name == "BH") return maat::ir::Reg(maat::X86::EBX, 15, 8);
        if (reg_name == "BX") return maat::ir::Reg(maat::X86::EBX, 15, 0);
        if (reg_name == "EBX") return maat::ir::Reg(maat::X86::EBX , 31, 0);
        if (reg_name == "CL") return maat::ir::Reg(maat::X86::ECX, 7, 0);
        if (reg_name == "CH") return maat::ir::Reg(maat::X86::ECX, 15, 8);
        if (reg_name == "CX") return maat::ir::Reg(maat::X86::ECX, 15, 0);
        if (reg_name == "ECX") return maat::ir::Reg(maat::X86::ECX, 31, 0);
        if (reg_name == "DL") return maat::ir::Reg(maat::X86::EDX, 7, 0);
        if (reg_name == "DH") return maat::ir::Reg(maat::X86::EDX, 15, 8);
        if (reg_name == "DX") return maat::ir::Reg(maat::X86::EDX, 15, 0);
        if (reg_name == "EDX") return maat::ir::Reg(maat::X86::EDX, 31, 0);
        if (reg_name == "DIL") return maat::ir::Reg(maat::X86::EDI, 7, 0);
        if (reg_name == "DI") return maat::ir::Reg(maat::X86::EDI, 15, 0);
        if (reg_name == "EDI") return maat::ir::Reg(maat::X86::EDI, 31, 0);
        if (reg_name == "SIL") return maat::ir::Reg(maat::X86::ESI, 7, 0);
        if (reg_name == "SI") return maat::ir::Reg(maat::X86::ESI, 15, 0);
        if (reg_name == "ESI") return maat::ir::Reg(maat::X86::ESI, 31, 0);
        if (reg_name == "BPL") return maat::ir::Reg(maat::X86::EBP, 7, 0);
        if (reg_name == "BP") return maat::ir::Reg(maat::X86::EBP, 15, 0);
        if (reg_name == "EBP") return maat::ir::Reg(maat::X86::EBP, 31, 0);
        if (reg_name == "SPL") return maat::ir::Reg(maat::X86::ESP, 7, 0);
        if (reg_name == "SP") return maat::ir::Reg(maat::X86::ESP, 15, 0);
        if (reg_name == "ESP") return maat::ir::Reg(maat::X86::ESP, 31, 0);
        if (reg_name == "IP") return maat::ir::Reg(maat::X86::EIP, 15, 0);
        if (reg_name == "EIP") return maat::ir::Reg(maat::X86::EIP, 31, 0);
        if (reg_name == "CS") return maat::ir::Reg(maat::X86::CS, 31, 0);
        if (reg_name == "DS") return maat::ir::Reg(maat::X86::DS, 31, 0);
        if (reg_name == "ES") return maat::ir::Reg(maat::X86::ES, 31, 0);
        if (reg_name == "GS") return maat::ir::Reg(maat::X86::GS, 31, 0);
        if (reg_name == "FS" or reg_name == "FS_OFFSET")
            return maat::ir::Reg(maat::X86::FS, 31, 0);
        if (reg_name == "SS") return maat::ir::Reg(maat::X86::SS, 31, 0);

        if (reg_name == "PF") return maat::ir::Reg(maat::X86::PF, 8);
        if (reg_name == "AF") return maat::ir::Reg(maat::X86::AF, 8);
        if (reg_name == "CF") return maat::ir::Reg(maat::X86::CF, 8);
        if (reg_name == "ZF") return maat::ir::Reg(maat::X86::ZF, 8);
        if (reg_name == "SF") return maat::ir::Reg(maat::X86::SF, 8);
        if (reg_name == "TF") return maat::ir::Reg(maat::X86::TF, 8);
        if (reg_name == "IF") return maat::ir::Reg(maat::X86::IF, 8);
        if (reg_name == "DF") return maat::ir::Reg(maat::X86::DF, 8);
        if (reg_name == "OF") return maat::ir::Reg(maat::X86::OF, 8);
        if (reg_name == "IOPL") return maat::ir::Reg(maat::X86::IOPL, 8);
        if (reg_name == "NT") return maat::ir::Reg(maat::X86::NT, 8);
        if (reg_name == "RF") return maat::ir::Reg(maat::X86::RF, 8);
        if (reg_name == "VM") return maat::ir::Reg(maat::X86::VM, 8);
        if (reg_name == "AC") return maat::ir::Reg(maat::X86::AC, 8);
        if (reg_name == "VIF") return maat::ir::Reg(maat::X86::VIF, 8);
        if (reg_name == "VIP") return maat::ir::Reg(maat::X86::VIP, 8);
        if (reg_name == "ID") return maat::ir::Reg(maat::X86::ID, 8);

        if (reg_name == "MM0") return maat::ir::Reg(maat::X86::MM0, 64);
        if (reg_name == "MM0_Da") return maat::ir::Reg(maat::X86::MM0, 31, 0);
        if (reg_name == "MM0_Db") return maat::ir::Reg(maat::X86::MM0, 63, 32);
        if (reg_name == "MM0_Wa") return maat::ir::Reg(maat::X86::MM0, 15, 0);
        if (reg_name == "MM0_Wb") return maat::ir::Reg(maat::X86::MM0, 31, 16);
        if (reg_name == "MM0_Wc") return maat::ir::Reg(maat::X86::MM0, 47, 32);
        if (reg_name == "MM0_Wd") return maat::ir::Reg(maat::X86::MM0, 63, 48);
        if (reg_name == "MM0_Ba") return maat::ir::Reg(maat::X86::MM0, 7, 0);
        if (reg_name == "MM0_Bb") return maat::ir::Reg(maat::X86::MM0, 15, 8);
        if (reg_name == "MM0_Bc") return maat::ir::Reg(maat::X86::MM0, 23, 16);
        if (reg_name == "MM0_Bd") return maat::ir::Reg(maat::X86::MM0, 31, 24);
        if (reg_name == "MM0_Be") return maat::ir::Reg(maat::X86::MM0, 39, 32);
        if (reg_name == "MM0_Bf") return maat::ir::Reg(maat::X86::MM0, 47, 40);
        if (reg_name == "MM0_Bg") return maat::ir::Reg(maat::X86::MM0, 55, 48);
        if (reg_name == "MM0_Bh") return maat::ir::Reg(maat::X86::MM0, 63, 56);

        if (reg_name == "MM1") return maat::ir::Reg(maat::X86::MM1, 64);
        if (reg_name == "MM1_Da") return maat::ir::Reg(maat::X86::MM1, 31, 0);
        if (reg_name == "MM1_Db") return maat::ir::Reg(maat::X86::MM1, 63, 32);
        if (reg_name == "MM1_Wa") return maat::ir::Reg(maat::X86::MM1, 15, 0);
        if (reg_name == "MM1_Wb") return maat::ir::Reg(maat::X86::MM1, 31, 16);
        if (reg_name == "MM1_Wc") return maat::ir::Reg(maat::X86::MM1, 47, 32);
        if (reg_name == "MM1_Wd") return maat::ir::Reg(maat::X86::MM1, 63, 48);
        if (reg_name == "MM1_Ba") return maat::ir::Reg(maat::X86::MM1, 7, 0);
        if (reg_name == "MM1_Bb") return maat::ir::Reg(maat::X86::MM1, 15, 8);
        if (reg_name == "MM1_Bc") return maat::ir::Reg(maat::X86::MM1, 23, 16);
        if (reg_name == "MM1_Bd") return maat::ir::Reg(maat::X86::MM1, 31, 24);
        if (reg_name == "MM1_Be") return maat::ir::Reg(maat::X86::MM1, 39, 32);
        if (reg_name == "MM1_Bf") return maat::ir::Reg(maat::X86::MM1, 47, 40);
        if (reg_name == "MM1_Bg") return maat::ir::Reg(maat::X86::MM1, 55, 48);
        if (reg_name == "MM1_Bh") return maat::ir::Reg(maat::X86::MM1, 63, 56);
        
        if (reg_name == "MM2") return maat::ir::Reg(maat::X86::MM2, 64);
        if (reg_name == "MM2_Da") return maat::ir::Reg(maat::X86::MM2, 31, 0);
        if (reg_name == "MM2_Db") return maat::ir::Reg(maat::X86::MM2, 63, 32);
        if (reg_name == "MM2_Wa") return maat::ir::Reg(maat::X86::MM2, 15, 0);
        if (reg_name == "MM2_Wb") return maat::ir::Reg(maat::X86::MM2, 31, 16);
        if (reg_name == "MM2_Wc") return maat::ir::Reg(maat::X86::MM2, 47, 32);
        if (reg_name == "MM2_Wd") return maat::ir::Reg(maat::X86::MM2, 63, 48);
        if (reg_name == "MM2_Ba") return maat::ir::Reg(maat::X86::MM2, 7, 0);
        if (reg_name == "MM2_Bb") return maat::ir::Reg(maat::X86::MM2, 15, 8);
        if (reg_name == "MM2_Bc") return maat::ir::Reg(maat::X86::MM2, 23, 16);
        if (reg_name == "MM2_Bd") return maat::ir::Reg(maat::X86::MM2, 31, 24);
        if (reg_name == "MM2_Be") return maat::ir::Reg(maat::X86::MM2, 39, 32);
        if (reg_name == "MM2_Bf") return maat::ir::Reg(maat::X86::MM2, 47, 40);
        if (reg_name == "MM2_Bg") return maat::ir::Reg(maat::X86::MM2, 55, 48);
        if (reg_name == "MM2_Bh") return maat::ir::Reg(maat::X86::MM2, 63, 56);
        
        if (reg_name == "MM3") return maat::ir::Reg(maat::X86::MM3, 64);
        if (reg_name == "MM3_Da") return maat::ir::Reg(maat::X86::MM3, 31, 0);
        if (reg_name == "MM3_Db") return maat::ir::Reg(maat::X86::MM3, 63, 32);
        if (reg_name == "MM3_Wa") return maat::ir::Reg(maat::X86::MM3, 15, 0);
        if (reg_name == "MM3_Wb") return maat::ir::Reg(maat::X86::MM3, 31, 16);
        if (reg_name == "MM3_Wc") return maat::ir::Reg(maat::X86::MM3, 47, 32);
        if (reg_name == "MM3_Wd") return maat::ir::Reg(maat::X86::MM3, 63, 48);
        if (reg_name == "MM3_Ba") return maat::ir::Reg(maat::X86::MM3, 7, 0);
        if (reg_name == "MM3_Bb") return maat::ir::Reg(maat::X86::MM3, 15, 8);
        if (reg_name == "MM3_Bc") return maat::ir::Reg(maat::X86::MM3, 23, 16);
        if (reg_name == "MM3_Bd") return maat::ir::Reg(maat::X86::MM3, 31, 24);
        if (reg_name == "MM3_Be") return maat::ir::Reg(maat::X86::MM3, 39, 32);
        if (reg_name == "MM3_Bf") return maat::ir::Reg(maat::X86::MM3, 47, 40);
        if (reg_name == "MM3_Bg") return maat::ir::Reg(maat::X86::MM3, 55, 48);
        if (reg_name == "MM3_Bh") return maat::ir::Reg(maat::X86::MM3, 63, 56);
        
        if (reg_name == "MM4") return maat::ir::Reg(maat::X86::MM4, 64);
        if (reg_name == "MM4_Da") return maat::ir::Reg(maat::X86::MM4, 31, 0);
        if (reg_name == "MM4_Db") return maat::ir::Reg(maat::X86::MM4, 63, 32);
        if (reg_name == "MM4_Wa") return maat::ir::Reg(maat::X86::MM4, 15, 0);
        if (reg_name == "MM4_Wb") return maat::ir::Reg(maat::X86::MM4, 31, 16);
        if (reg_name == "MM4_Wc") return maat::ir::Reg(maat::X86::MM4, 47, 32);
        if (reg_name == "MM4_Wd") return maat::ir::Reg(maat::X86::MM4, 63, 48);
        if (reg_name == "MM4_Ba") return maat::ir::Reg(maat::X86::MM4, 7, 0);
        if (reg_name == "MM4_Bb") return maat::ir::Reg(maat::X86::MM4, 15, 8);
        if (reg_name == "MM4_Bc") return maat::ir::Reg(maat::X86::MM4, 23, 16);
        if (reg_name == "MM4_Bd") return maat::ir::Reg(maat::X86::MM4, 31, 24);
        if (reg_name == "MM4_Be") return maat::ir::Reg(maat::X86::MM4, 39, 32);
        if (reg_name == "MM4_Bf") return maat::ir::Reg(maat::X86::MM4, 47, 40);
        if (reg_name == "MM4_Bg") return maat::ir::Reg(maat::X86::MM4, 55, 48);
        if (reg_name == "MM4_Bh") return maat::ir::Reg(maat::X86::MM4, 63, 56);
        
        if (reg_name == "MM5") return maat::ir::Reg(maat::X86::MM5, 64);
        if (reg_name == "MM5_Da") return maat::ir::Reg(maat::X86::MM5, 31, 0);
        if (reg_name == "MM5_Db") return maat::ir::Reg(maat::X86::MM5, 63, 32);
        if (reg_name == "MM5_Wa") return maat::ir::Reg(maat::X86::MM5, 15, 0);
        if (reg_name == "MM5_Wb") return maat::ir::Reg(maat::X86::MM5, 31, 16);
        if (reg_name == "MM5_Wc") return maat::ir::Reg(maat::X86::MM5, 47, 32);
        if (reg_name == "MM5_Wd") return maat::ir::Reg(maat::X86::MM5, 63, 48);
        if (reg_name == "MM5_Ba") return maat::ir::Reg(maat::X86::MM5, 7, 0);
        if (reg_name == "MM5_Bb") return maat::ir::Reg(maat::X86::MM5, 15, 8);
        if (reg_name == "MM5_Bc") return maat::ir::Reg(maat::X86::MM5, 23, 16);
        if (reg_name == "MM5_Bd") return maat::ir::Reg(maat::X86::MM5, 31, 24);
        if (reg_name == "MM5_Be") return maat::ir::Reg(maat::X86::MM5, 39, 32);
        if (reg_name == "MM5_Bf") return maat::ir::Reg(maat::X86::MM5, 47, 40);
        if (reg_name == "MM5_Bg") return maat::ir::Reg(maat::X86::MM5, 55, 48);
        if (reg_name == "MM5_Bh") return maat::ir::Reg(maat::X86::MM5, 63, 56);
        
        if (reg_name == "MM6") return maat::ir::Reg(maat::X86::MM6, 64);
        if (reg_name == "MM6_Da") return maat::ir::Reg(maat::X86::MM6, 31, 0);
        if (reg_name == "MM6_Db") return maat::ir::Reg(maat::X86::MM6, 63, 32);
        if (reg_name == "MM6_Wa") return maat::ir::Reg(maat::X86::MM6, 15, 0);
        if (reg_name == "MM6_Wb") return maat::ir::Reg(maat::X86::MM6, 31, 16);
        if (reg_name == "MM6_Wc") return maat::ir::Reg(maat::X86::MM6, 47, 32);
        if (reg_name == "MM6_Wd") return maat::ir::Reg(maat::X86::MM6, 63, 48);
        if (reg_name == "MM6_Ba") return maat::ir::Reg(maat::X86::MM6, 7, 0);
        if (reg_name == "MM6_Bb") return maat::ir::Reg(maat::X86::MM6, 15, 8);
        if (reg_name == "MM6_Bc") return maat::ir::Reg(maat::X86::MM6, 23, 16);
        if (reg_name == "MM6_Bd") return maat::ir::Reg(maat::X86::MM6, 31, 24);
        if (reg_name == "MM6_Be") return maat::ir::Reg(maat::X86::MM6, 39, 32);
        if (reg_name == "MM6_Bf") return maat::ir::Reg(maat::X86::MM6, 47, 40);
        if (reg_name == "MM6_Bg") return maat::ir::Reg(maat::X86::MM6, 55, 48);
        if (reg_name == "MM6_Bh") return maat::ir::Reg(maat::X86::MM6, 63, 56);
        
        if (reg_name == "MM7") return maat::ir::Reg(maat::X86::MM7, 64);
        if (reg_name == "MM7_Da") return maat::ir::Reg(maat::X86::MM7, 31, 0);
        if (reg_name == "MM7_Db") return maat::ir::Reg(maat::X86::MM7, 63, 32);
        if (reg_name == "MM7_Wa") return maat::ir::Reg(maat::X86::MM7, 15, 0);
        if (reg_name == "MM7_Wb") return maat::ir::Reg(maat::X86::MM7, 31, 16);
        if (reg_name == "MM7_Wc") return maat::ir::Reg(maat::X86::MM7, 47, 32);
        if (reg_name == "MM7_Wd") return maat::ir::Reg(maat::X86::MM7, 63, 48);
        if (reg_name == "MM7_Ba") return maat::ir::Reg(maat::X86::MM7, 7, 0);
        if (reg_name == "MM7_Bb") return maat::ir::Reg(maat::X86::MM7, 15, 8);
        if (reg_name == "MM7_Bc") return maat::ir::Reg(maat::X86::MM7, 23, 16);
        if (reg_name == "MM7_Bd") return maat::ir::Reg(maat::X86::MM7, 31, 24);
        if (reg_name == "MM7_Be") return maat::ir::Reg(maat::X86::MM7, 39, 32);
        if (reg_name == "MM7_Bf") return maat::ir::Reg(maat::X86::MM7, 47, 40);
        if (reg_name == "MM7_Bg") return maat::ir::Reg(maat::X86::MM7, 55, 48);
        if (reg_name == "MM7_Bh") return maat::ir::Reg(maat::X86::MM7, 63, 56);


        if (reg_name == "MM2") return maat::ir::Reg(maat::X86::MM2, 64);
        if (reg_name == "MM3") return maat::ir::Reg(maat::X86::MM3, 64);
        if (reg_name == "MM4") return maat::ir::Reg(maat::X86::MM4, 64);
        if (reg_name == "MM5") return maat::ir::Reg(maat::X86::MM5, 64);
        if (reg_name == "MM6") return maat::ir::Reg(maat::X86::MM6, 64);
        if (reg_name == "MM7") return maat::ir::Reg(maat::X86::MM7, 64);

        if (reg_name == "YMM0") return maat::ir::Reg(maat::X86::ZMM0, 256);
        if (reg_name == "XMM0") return maat::ir::Reg(maat::X86::ZMM0, 128);
        if (reg_name == "XMM0_Qa") return maat::ir::Reg(maat::X86::ZMM0, 63, 0);
        if (reg_name == "XMM0_Qb") return maat::ir::Reg(maat::X86::ZMM0, 127, 64);
        if (reg_name == "XMM0_Da") return maat::ir::Reg(maat::X86::ZMM0, 31, 0);
        if (reg_name == "XMM0_Db") return maat::ir::Reg(maat::X86::ZMM0, 63, 32);
        if (reg_name == "XMM0_Dc") return maat::ir::Reg(maat::X86::ZMM0, 95, 64);
        if (reg_name == "XMM0_Dd") return maat::ir::Reg(maat::X86::ZMM0, 127, 96);
        if (reg_name == "XMM0_Wa") return maat::ir::Reg(maat::X86::ZMM0, 15, 0);
        if (reg_name == "XMM0_Wb") return maat::ir::Reg(maat::X86::ZMM0, 31, 16);
        if (reg_name == "XMM0_Wc") return maat::ir::Reg(maat::X86::ZMM0, 47, 32);
        if (reg_name == "XMM0_Wd") return maat::ir::Reg(maat::X86::ZMM0, 63, 48);
        if (reg_name == "XMM0_We") return maat::ir::Reg(maat::X86::ZMM0, 79, 64);
        if (reg_name == "XMM0_Wf") return maat::ir::Reg(maat::X86::ZMM0, 95, 80);
        if (reg_name == "XMM0_Wg") return maat::ir::Reg(maat::X86::ZMM0, 111, 96);
        if (reg_name == "XMM0_Wh") return maat::ir::Reg(maat::X86::ZMM0, 127, 112);
        if (reg_name == "XMM0_Ba") return maat::ir::Reg(maat::X86::ZMM0, 7, 0);
        if (reg_name == "XMM0_Bb") return maat::ir::Reg(maat::X86::ZMM0, 15, 8);
        if (reg_name == "XMM0_Bc") return maat::ir::Reg(maat::X86::ZMM0, 23, 16);
        if (reg_name == "XMM0_Bd") return maat::ir::Reg(maat::X86::ZMM0, 31, 24);
        if (reg_name == "XMM0_Be") return maat::ir::Reg(maat::X86::ZMM0, 39, 32);
        if (reg_name == "XMM0_Bf") return maat::ir::Reg(maat::X86::ZMM0, 47, 40);
        if (reg_name == "XMM0_Bg") return maat::ir::Reg(maat::X86::ZMM0, 55, 48);
        if (reg_name == "XMM0_Bh") return maat::ir::Reg(maat::X86::ZMM0, 63, 56);
        if (reg_name == "XMM0_Bi") return maat::ir::Reg(maat::X86::ZMM0, 71, 64);
        if (reg_name == "XMM0_Bj") return maat::ir::Reg(maat::X86::ZMM0, 79, 72);
        if (reg_name == "XMM0_Bk") return maat::ir::Reg(maat::X86::ZMM0, 87, 80);
        if (reg_name == "XMM0_Bl") return maat::ir::Reg(maat::X86::ZMM0, 95, 88);
        if (reg_name == "XMM0_Bm") return maat::ir::Reg(maat::X86::ZMM0, 103, 96);
        if (reg_name == "XMM0_Bn") return maat::ir::Reg(maat::X86::ZMM0, 111, 104);
        if (reg_name == "XMM0_Bo") return maat::ir::Reg(maat::X86::ZMM0, 119, 112);
        if (reg_name == "XMM0_Bp") return maat::ir::Reg(maat::X86::ZMM0, 127, 120);

        if (reg_name == "YMM1") return maat::ir::Reg(maat::X86::ZMM1, 256);
        if (reg_name == "XMM1") return maat::ir::Reg(maat::X86::ZMM1, 128);
        if (reg_name == "XMM1_Qa") return maat::ir::Reg(maat::X86::ZMM1, 63, 0);
        if (reg_name == "XMM1_Qb") return maat::ir::Reg(maat::X86::ZMM1, 127, 64);
        if (reg_name == "XMM1_Da") return maat::ir::Reg(maat::X86::ZMM1, 31, 0);
        if (reg_name == "XMM1_Db") return maat::ir::Reg(maat::X86::ZMM1, 63, 32);
        if (reg_name == "XMM1_Dc") return maat::ir::Reg(maat::X86::ZMM1, 95, 64);
        if (reg_name == "XMM1_Dd") return maat::ir::Reg(maat::X86::ZMM1, 127, 96);
        if (reg_name == "XMM1_Ba") return maat::ir::Reg(maat::X86::ZMM1, 7, 0);
        if (reg_name == "XMM1_Bb") return maat::ir::Reg(maat::X86::ZMM1, 15, 8);
        if (reg_name == "XMM1_Bc") return maat::ir::Reg(maat::X86::ZMM1, 23, 16);
        if (reg_name == "XMM1_Bd") return maat::ir::Reg(maat::X86::ZMM1, 31, 24);
        if (reg_name == "XMM1_Be") return maat::ir::Reg(maat::X86::ZMM1, 39, 32);
        if (reg_name == "XMM1_Bf") return maat::ir::Reg(maat::X86::ZMM1, 47, 40);
        if (reg_name == "XMM1_Bg") return maat::ir::Reg(maat::X86::ZMM1, 55, 48);
        if (reg_name == "XMM1_Bh") return maat::ir::Reg(maat::X86::ZMM1, 63, 56);
        if (reg_name == "XMM1_Bi") return maat::ir::Reg(maat::X86::ZMM1, 71, 64);
        if (reg_name == "XMM1_Bj") return maat::ir::Reg(maat::X86::ZMM1, 79, 72);
        if (reg_name == "XMM1_Bk") return maat::ir::Reg(maat::X86::ZMM1, 87, 80);
        if (reg_name == "XMM1_Bl") return maat::ir::Reg(maat::X86::ZMM1, 95, 88);
        if (reg_name == "XMM1_Bm") return maat::ir::Reg(maat::X86::ZMM1, 103, 96);
        if (reg_name == "XMM1_Bn") return maat::ir::Reg(maat::X86::ZMM1, 111, 104);
        if (reg_name == "XMM1_Bo") return maat::ir::Reg(maat::X86::ZMM1, 119, 112);
        if (reg_name == "XMM1_Bp") return maat::ir::Reg(maat::X86::ZMM1, 127, 120);
        if (reg_name == "XMM1_Wa") return maat::ir::Reg(maat::X86::ZMM1, 15, 0);
        if (reg_name == "XMM1_Wb") return maat::ir::Reg(maat::X86::ZMM1, 31, 16);
        if (reg_name == "XMM1_Wc") return maat::ir::Reg(maat::X86::ZMM1, 47, 32);
        if (reg_name == "XMM1_Wd") return maat::ir::Reg(maat::X86::ZMM1, 63, 48);
        if (reg_name == "XMM1_We") return maat::ir::Reg(maat::X86::ZMM1, 79, 64);
        if (reg_name == "XMM1_Wf") return maat::ir::Reg(maat::X86::ZMM1, 95, 80);
        if (reg_name == "XMM1_Wg") return maat::ir::Reg(maat::X86::ZMM1, 111, 96);
        if (reg_name == "XMM1_Wh") return maat::ir::Reg(maat::X86::ZMM1, 127, 112);


        if (reg_name == "YMM2") return maat::ir::Reg(maat::X86::ZMM2, 256);
        if (reg_name == "XMM2") return maat::ir::Reg(maat::X86::ZMM2, 128);
        if (reg_name == "XMM2_Qa") return maat::ir::Reg(maat::X86::ZMM2, 63, 0);
        if (reg_name == "XMM2_Qb") return maat::ir::Reg(maat::X86::ZMM2, 127, 64);
        if (reg_name == "XMM2_Da") return maat::ir::Reg(maat::X86::ZMM2, 31, 0);
        if (reg_name == "XMM2_Db") return maat::ir::Reg(maat::X86::ZMM2, 63, 32);
        if (reg_name == "XMM2_Dc") return maat::ir::Reg(maat::X86::ZMM2, 95, 64);
        if (reg_name == "XMM2_Dd") return maat::ir::Reg(maat::X86::ZMM2, 127, 96);
        if (reg_name == "XMM2_Ba") return maat::ir::Reg(maat::X86::ZMM2, 7, 0);
        if (reg_name == "XMM2_Bb") return maat::ir::Reg(maat::X86::ZMM2, 15, 8);
        if (reg_name == "XMM2_Bc") return maat::ir::Reg(maat::X86::ZMM2, 23, 16);
        if (reg_name == "XMM2_Bd") return maat::ir::Reg(maat::X86::ZMM2, 31, 24);
        if (reg_name == "XMM2_Be") return maat::ir::Reg(maat::X86::ZMM2, 39, 32);
        if (reg_name == "XMM2_Bf") return maat::ir::Reg(maat::X86::ZMM2, 47, 40);
        if (reg_name == "XMM2_Bg") return maat::ir::Reg(maat::X86::ZMM2, 55, 48);
        if (reg_name == "XMM2_Bh") return maat::ir::Reg(maat::X86::ZMM2, 63, 56);
        if (reg_name == "XMM2_Bi") return maat::ir::Reg(maat::X86::ZMM2, 71, 64);
        if (reg_name == "XMM2_Bj") return maat::ir::Reg(maat::X86::ZMM2, 79, 72);
        if (reg_name == "XMM2_Bk") return maat::ir::Reg(maat::X86::ZMM2, 87, 80);
        if (reg_name == "XMM2_Bl") return maat::ir::Reg(maat::X86::ZMM2, 95, 88);
        if (reg_name == "XMM2_Bm") return maat::ir::Reg(maat::X86::ZMM2, 103, 96);
        if (reg_name == "XMM2_Bn") return maat::ir::Reg(maat::X86::ZMM2, 111, 104);
        if (reg_name == "XMM2_Bo") return maat::ir::Reg(maat::X86::ZMM2, 119, 112);
        if (reg_name == "XMM2_Bp") return maat::ir::Reg(maat::X86::ZMM2, 127, 120);
        if (reg_name == "XMM2_Wa") return maat::ir::Reg(maat::X86::ZMM2, 15, 0);
        if (reg_name == "XMM2_Wb") return maat::ir::Reg(maat::X86::ZMM2, 31, 16);
        if (reg_name == "XMM2_Wc") return maat::ir::Reg(maat::X86::ZMM2, 47, 32);
        if (reg_name == "XMM2_Wd") return maat::ir::Reg(maat::X86::ZMM2, 63, 48);
        if (reg_name == "XMM2_We") return maat::ir::Reg(maat::X86::ZMM2, 79, 64);
        if (reg_name == "XMM2_Wf") return maat::ir::Reg(maat::X86::ZMM2, 95, 80);
        if (reg_name == "XMM2_Wg") return maat::ir::Reg(maat::X86::ZMM2, 111, 96);
        if (reg_name == "XMM2_Wh") return maat::ir::Reg(maat::X86::ZMM2, 127, 112);
        
        if (reg_name == "YMM3") return maat::ir::Reg(maat::X86::ZMM3, 256);
        if (reg_name == "XMM3") return maat::ir::Reg(maat::X86::ZMM3, 128);
        if (reg_name == "XMM3_Qa") return maat::ir::Reg(maat::X86::ZMM3, 63, 0);
        if (reg_name == "XMM3_Qb") return maat::ir::Reg(maat::X86::ZMM3, 127, 64);
        if (reg_name == "XMM3_Da") return maat::ir::Reg(maat::X86::ZMM3, 31, 0);
        if (reg_name == "XMM3_Db") return maat::ir::Reg(maat::X86::ZMM3, 63, 32);
        if (reg_name == "XMM3_Dc") return maat::ir::Reg(maat::X86::ZMM3, 95, 64);
        if (reg_name == "XMM3_Dd") return maat::ir::Reg(maat::X86::ZMM3, 127, 96);
        if (reg_name == "XMM3_Ba") return maat::ir::Reg(maat::X86::ZMM3, 7, 0);
        if (reg_name == "XMM3_Bb") return maat::ir::Reg(maat::X86::ZMM3, 15, 8);
        if (reg_name == "XMM3_Bc") return maat::ir::Reg(maat::X86::ZMM3, 23, 16);
        if (reg_name == "XMM3_Bd") return maat::ir::Reg(maat::X86::ZMM3, 31, 24);
        if (reg_name == "XMM3_Be") return maat::ir::Reg(maat::X86::ZMM3, 39, 32);
        if (reg_name == "XMM3_Bf") return maat::ir::Reg(maat::X86::ZMM3, 47, 40);
        if (reg_name == "XMM3_Bg") return maat::ir::Reg(maat::X86::ZMM3, 55, 48);
        if (reg_name == "XMM3_Bh") return maat::ir::Reg(maat::X86::ZMM3, 63, 56);
        if (reg_name == "XMM3_Bi") return maat::ir::Reg(maat::X86::ZMM3, 71, 64);
        if (reg_name == "XMM3_Bj") return maat::ir::Reg(maat::X86::ZMM3, 79, 72);
        if (reg_name == "XMM3_Bk") return maat::ir::Reg(maat::X86::ZMM3, 87, 80);
        if (reg_name == "XMM3_Bl") return maat::ir::Reg(maat::X86::ZMM3, 95, 88);
        if (reg_name == "XMM3_Bm") return maat::ir::Reg(maat::X86::ZMM3, 103, 96);
        if (reg_name == "XMM3_Bn") return maat::ir::Reg(maat::X86::ZMM3, 111, 104);
        if (reg_name == "XMM3_Bo") return maat::ir::Reg(maat::X86::ZMM3, 119, 112);
        if (reg_name == "XMM3_Bp") return maat::ir::Reg(maat::X86::ZMM3, 127, 120);
        if (reg_name == "XMM3_Wa") return maat::ir::Reg(maat::X86::ZMM3, 15, 0);
        if (reg_name == "XMM3_Wb") return maat::ir::Reg(maat::X86::ZMM3, 31, 16);
        if (reg_name == "XMM3_Wc") return maat::ir::Reg(maat::X86::ZMM3, 47, 32);
        if (reg_name == "XMM3_Wd") return maat::ir::Reg(maat::X86::ZMM3, 63, 48);
        if (reg_name == "XMM3_We") return maat::ir::Reg(maat::X86::ZMM3, 79, 64);
        if (reg_name == "XMM3_Wf") return maat::ir::Reg(maat::X86::ZMM3, 95, 80);
        if (reg_name == "XMM3_Wg") return maat::ir::Reg(maat::X86::ZMM3, 111, 96);
        if (reg_name == "XMM3_Wh") return maat::ir::Reg(maat::X86::ZMM3, 127, 112);
        
        if (reg_name == "YMM4") return maat::ir::Reg(maat::X86::ZMM4, 256);
        if (reg_name == "XMM4") return maat::ir::Reg(maat::X86::ZMM4, 128);
        if (reg_name == "XMM4_Qa") return maat::ir::Reg(maat::X86::ZMM4, 63, 0);
        if (reg_name == "XMM4_Qb") return maat::ir::Reg(maat::X86::ZMM4, 127, 64);
        if (reg_name == "XMM4_Da") return maat::ir::Reg(maat::X86::ZMM4, 31, 0);
        if (reg_name == "XMM4_Db") return maat::ir::Reg(maat::X86::ZMM4, 63, 32);
        if (reg_name == "XMM4_Dc") return maat::ir::Reg(maat::X86::ZMM4, 95, 64);
        if (reg_name == "XMM4_Dd") return maat::ir::Reg(maat::X86::ZMM4, 127, 96);
        if (reg_name == "XMM4_Ba") return maat::ir::Reg(maat::X86::ZMM4, 7, 0);
        if (reg_name == "XMM4_Bb") return maat::ir::Reg(maat::X86::ZMM4, 15, 8);
        if (reg_name == "XMM4_Bc") return maat::ir::Reg(maat::X86::ZMM4, 23, 16);
        if (reg_name == "XMM4_Bd") return maat::ir::Reg(maat::X86::ZMM4, 31, 24);
        if (reg_name == "XMM4_Be") return maat::ir::Reg(maat::X86::ZMM4, 39, 32);
        if (reg_name == "XMM4_Bf") return maat::ir::Reg(maat::X86::ZMM4, 47, 40);
        if (reg_name == "XMM4_Bg") return maat::ir::Reg(maat::X86::ZMM4, 55, 48);
        if (reg_name == "XMM4_Bh") return maat::ir::Reg(maat::X86::ZMM4, 63, 56);
        if (reg_name == "XMM4_Bi") return maat::ir::Reg(maat::X86::ZMM4, 71, 64);
        if (reg_name == "XMM4_Bj") return maat::ir::Reg(maat::X86::ZMM4, 79, 72);
        if (reg_name == "XMM4_Bk") return maat::ir::Reg(maat::X86::ZMM4, 87, 80);
        if (reg_name == "XMM4_Bl") return maat::ir::Reg(maat::X86::ZMM4, 95, 88);
        if (reg_name == "XMM4_Bm") return maat::ir::Reg(maat::X86::ZMM4, 103, 96);
        if (reg_name == "XMM4_Bn") return maat::ir::Reg(maat::X86::ZMM4, 111, 104);
        if (reg_name == "XMM4_Bo") return maat::ir::Reg(maat::X86::ZMM4, 119, 112);
        if (reg_name == "XMM4_Bp") return maat::ir::Reg(maat::X86::ZMM4, 127, 120);
        if (reg_name == "XMM4_Wa") return maat::ir::Reg(maat::X86::ZMM4, 15, 0);
        if (reg_name == "XMM4_Wb") return maat::ir::Reg(maat::X86::ZMM4, 31, 16);
        if (reg_name == "XMM4_Wc") return maat::ir::Reg(maat::X86::ZMM4, 47, 32);
        if (reg_name == "XMM4_Wd") return maat::ir::Reg(maat::X86::ZMM4, 63, 48);
        if (reg_name == "XMM4_We") return maat::ir::Reg(maat::X86::ZMM4, 79, 64);
        if (reg_name == "XMM4_Wf") return maat::ir::Reg(maat::X86::ZMM4, 95, 80);
        if (reg_name == "XMM4_Wg") return maat::ir::Reg(maat::X86::ZMM4, 111, 96);
        if (reg_name == "XMM4_Wh") return maat::ir::Reg(maat::X86::ZMM4, 127, 112);
        
        if (reg_name == "YMM5") return maat::ir::Reg(maat::X86::ZMM5, 256);
        if (reg_name == "XMM5") return maat::ir::Reg(maat::X86::ZMM5, 128);
        if (reg_name == "XMM5_Qa") return maat::ir::Reg(maat::X86::ZMM5, 63, 0);
        if (reg_name == "XMM5_Qb") return maat::ir::Reg(maat::X86::ZMM5, 127, 64);
        if (reg_name == "XMM5_Da") return maat::ir::Reg(maat::X86::ZMM5, 31, 0);
        if (reg_name == "XMM5_Db") return maat::ir::Reg(maat::X86::ZMM5, 63, 32);
        if (reg_name == "XMM5_Dc") return maat::ir::Reg(maat::X86::ZMM5, 95, 64);
        if (reg_name == "XMM5_Dd") return maat::ir::Reg(maat::X86::ZMM5, 127, 96);
        if (reg_name == "XMM5_Ba") return maat::ir::Reg(maat::X86::ZMM5, 7, 0);
        if (reg_name == "XMM5_Bb") return maat::ir::Reg(maat::X86::ZMM5, 15, 8);
        if (reg_name == "XMM5_Bc") return maat::ir::Reg(maat::X86::ZMM5, 23, 16);
        if (reg_name == "XMM5_Bd") return maat::ir::Reg(maat::X86::ZMM5, 31, 24);
        if (reg_name == "XMM5_Be") return maat::ir::Reg(maat::X86::ZMM5, 39, 32);
        if (reg_name == "XMM5_Bf") return maat::ir::Reg(maat::X86::ZMM5, 47, 40);
        if (reg_name == "XMM5_Bg") return maat::ir::Reg(maat::X86::ZMM5, 55, 48);
        if (reg_name == "XMM5_Bh") return maat::ir::Reg(maat::X86::ZMM5, 63, 56);
        if (reg_name == "XMM5_Bi") return maat::ir::Reg(maat::X86::ZMM5, 71, 64);
        if (reg_name == "XMM5_Bj") return maat::ir::Reg(maat::X86::ZMM5, 79, 72);
        if (reg_name == "XMM5_Bk") return maat::ir::Reg(maat::X86::ZMM5, 87, 80);
        if (reg_name == "XMM5_Bl") return maat::ir::Reg(maat::X86::ZMM5, 95, 88);
        if (reg_name == "XMM5_Bm") return maat::ir::Reg(maat::X86::ZMM5, 103, 96);
        if (reg_name == "XMM5_Bn") return maat::ir::Reg(maat::X86::ZMM5, 111, 104);
        if (reg_name == "XMM5_Bo") return maat::ir::Reg(maat::X86::ZMM5, 119, 112);
        if (reg_name == "XMM5_Bp") return maat::ir::Reg(maat::X86::ZMM5, 127, 120);
        if (reg_name == "XMM5_Wa") return maat::ir::Reg(maat::X86::ZMM5, 15, 0);
        if (reg_name == "XMM5_Wb") return maat::ir::Reg(maat::X86::ZMM5, 31, 16);
        if (reg_name == "XMM5_Wc") return maat::ir::Reg(maat::X86::ZMM5, 47, 32);
        if (reg_name == "XMM5_Wd") return maat::ir::Reg(maat::X86::ZMM5, 63, 48);
        if (reg_name == "XMM5_We") return maat::ir::Reg(maat::X86::ZMM5, 79, 64);
        if (reg_name == "XMM5_Wf") return maat::ir::Reg(maat::X86::ZMM5, 95, 80);
        if (reg_name == "XMM5_Wg") return maat::ir::Reg(maat::X86::ZMM5, 111, 96);
        if (reg_name == "XMM5_Wh") return maat::ir::Reg(maat::X86::ZMM5, 127, 112);
        
        if (reg_name == "YMM6") return maat::ir::Reg(maat::X86::ZMM6, 256);
        if (reg_name == "XMM6") return maat::ir::Reg(maat::X86::ZMM6, 128);
        if (reg_name == "XMM6_Qa") return maat::ir::Reg(maat::X86::ZMM6, 63, 0);
        if (reg_name == "XMM6_Qb") return maat::ir::Reg(maat::X86::ZMM6, 127, 64);
        if (reg_name == "XMM6_Da") return maat::ir::Reg(maat::X86::ZMM6, 31, 0);
        if (reg_name == "XMM6_Db") return maat::ir::Reg(maat::X86::ZMM6, 63, 32);
        if (reg_name == "XMM6_Dc") return maat::ir::Reg(maat::X86::ZMM6, 95, 64);
        if (reg_name == "XMM6_Dd") return maat::ir::Reg(maat::X86::ZMM6, 127, 96);
        if (reg_name == "XMM6_Ba") return maat::ir::Reg(maat::X86::ZMM6, 7, 0);
        if (reg_name == "XMM6_Bb") return maat::ir::Reg(maat::X86::ZMM6, 15, 8);
        if (reg_name == "XMM6_Bc") return maat::ir::Reg(maat::X86::ZMM6, 23, 16);
        if (reg_name == "XMM6_Bd") return maat::ir::Reg(maat::X86::ZMM6, 31, 24);
        if (reg_name == "XMM6_Be") return maat::ir::Reg(maat::X86::ZMM6, 39, 32);
        if (reg_name == "XMM6_Bf") return maat::ir::Reg(maat::X86::ZMM6, 47, 40);
        if (reg_name == "XMM6_Bg") return maat::ir::Reg(maat::X86::ZMM6, 55, 48);
        if (reg_name == "XMM6_Bh") return maat::ir::Reg(maat::X86::ZMM6, 63, 56);
        if (reg_name == "XMM6_Bi") return maat::ir::Reg(maat::X86::ZMM6, 71, 64);
        if (reg_name == "XMM6_Bj") return maat::ir::Reg(maat::X86::ZMM6, 79, 72);
        if (reg_name == "XMM6_Bk") return maat::ir::Reg(maat::X86::ZMM6, 87, 80);
        if (reg_name == "XMM6_Bl") return maat::ir::Reg(maat::X86::ZMM6, 95, 88);
        if (reg_name == "XMM6_Bm") return maat::ir::Reg(maat::X86::ZMM6, 103, 96);
        if (reg_name == "XMM6_Bn") return maat::ir::Reg(maat::X86::ZMM6, 111, 104);
        if (reg_name == "XMM6_Bo") return maat::ir::Reg(maat::X86::ZMM6, 119, 112);
        if (reg_name == "XMM6_Bp") return maat::ir::Reg(maat::X86::ZMM6, 127, 120);
        if (reg_name == "XMM6_Wa") return maat::ir::Reg(maat::X86::ZMM6, 15, 0);
        if (reg_name == "XMM6_Wb") return maat::ir::Reg(maat::X86::ZMM6, 31, 16);
        if (reg_name == "XMM6_Wc") return maat::ir::Reg(maat::X86::ZMM6, 47, 32);
        if (reg_name == "XMM6_Wd") return maat::ir::Reg(maat::X86::ZMM6, 63, 48);
        if (reg_name == "XMM6_We") return maat::ir::Reg(maat::X86::ZMM6, 79, 64);
        if (reg_name == "XMM6_Wf") return maat::ir::Reg(maat::X86::ZMM6, 95, 80);
        if (reg_name == "XMM6_Wg") return maat::ir::Reg(maat::X86::ZMM6, 111, 96);
        if (reg_name == "XMM6_Wh") return maat::ir::Reg(maat::X86::ZMM6, 127, 112);
        
        if (reg_name == "YMM7") return maat::ir::Reg(maat::X86::ZMM7, 256);
        if (reg_name == "XMM7") return maat::ir::Reg(maat::X86::ZMM7, 128);
        if (reg_name == "XMM7_Qa") return maat::ir::Reg(maat::X86::ZMM7, 63, 0);
        if (reg_name == "XMM7_Qb") return maat::ir::Reg(maat::X86::ZMM7, 127, 64);
        if (reg_name == "XMM7_Da") return maat::ir::Reg(maat::X86::ZMM7, 31, 0);
        if (reg_name == "XMM7_Db") return maat::ir::Reg(maat::X86::ZMM7, 63, 32);
        if (reg_name == "XMM7_Dc") return maat::ir::Reg(maat::X86::ZMM7, 95, 64);
        if (reg_name == "XMM7_Dd") return maat::ir::Reg(maat::X86::ZMM7, 127, 96);
        if (reg_name == "XMM7_Ba") return maat::ir::Reg(maat::X86::ZMM7, 7, 0);
        if (reg_name == "XMM7_Bb") return maat::ir::Reg(maat::X86::ZMM7, 15, 8);
        if (reg_name == "XMM7_Bc") return maat::ir::Reg(maat::X86::ZMM7, 23, 16);
        if (reg_name == "XMM7_Bd") return maat::ir::Reg(maat::X86::ZMM7, 31, 24);
        if (reg_name == "XMM7_Be") return maat::ir::Reg(maat::X86::ZMM7, 39, 32);
        if (reg_name == "XMM7_Bf") return maat::ir::Reg(maat::X86::ZMM7, 47, 40);
        if (reg_name == "XMM7_Bg") return maat::ir::Reg(maat::X86::ZMM7, 55, 48);
        if (reg_name == "XMM7_Bh") return maat::ir::Reg(maat::X86::ZMM7, 63, 56);
        if (reg_name == "XMM7_Bi") return maat::ir::Reg(maat::X86::ZMM7, 71, 64);
        if (reg_name == "XMM7_Bj") return maat::ir::Reg(maat::X86::ZMM7, 79, 72);
        if (reg_name == "XMM7_Bk") return maat::ir::Reg(maat::X86::ZMM7, 87, 80);
        if (reg_name == "XMM7_Bl") return maat::ir::Reg(maat::X86::ZMM7, 95, 88);
        if (reg_name == "XMM7_Bm") return maat::ir::Reg(maat::X86::ZMM7, 103, 96);
        if (reg_name == "XMM7_Bn") return maat::ir::Reg(maat::X86::ZMM7, 111, 104);
        if (reg_name == "XMM7_Bo") return maat::ir::Reg(maat::X86::ZMM7, 119, 112);
        if (reg_name == "XMM7_Bp") return maat::ir::Reg(maat::X86::ZMM7, 127, 120);
        if (reg_name == "XMM7_Wa") return maat::ir::Reg(maat::X86::ZMM7, 15, 0);
        if (reg_name == "XMM7_Wb") return maat::ir::Reg(maat::X86::ZMM7, 31, 16);
        if (reg_name == "XMM7_Wc") return maat::ir::Reg(maat::X86::ZMM7, 47, 32);
        if (reg_name == "XMM7_Wd") return maat::ir::Reg(maat::X86::ZMM7, 63, 48);
        if (reg_name == "XMM7_We") return maat::ir::Reg(maat::X86::ZMM7, 79, 64);
        if (reg_name == "XMM7_Wf") return maat::ir::Reg(maat::X86::ZMM7, 95, 80);
        if (reg_name == "XMM7_Wg") return maat::ir::Reg(maat::X86::ZMM7, 111, 96);
        if (reg_name == "XMM7_Wh") return maat::ir::Reg(maat::X86::ZMM7, 127, 112);
    
        if (reg_name == "C0") return maat::ir::Reg(maat::X86::C0, 8);
        if (reg_name == "C1") return maat::ir::Reg(maat::X86::C1, 8);
        if (reg_name == "C2") return maat::ir::Reg(maat::X86::C2, 8);
        if (reg_name == "C3") return maat::ir::Reg(maat::X86::C3, 8);

        if (reg_name == "CR0") return maat::ir::Reg(maat::X86::CR0, 32);

        throw maat::runtime_exception(maat::Fmt()
                << "X86: Register translation from SLEIGH to MAAT missing for register "
                << reg_name
                >> maat::Fmt::to_str
              );
    }
    else if (arch == "X64")
    {
        if (reg_name == "AL") return maat::ir::Reg(maat::X64::RAX, 7, 0);
        if (reg_name == "AH") return maat::ir::Reg(maat::X64::RAX, 15, 8);
        if (reg_name == "AX") return maat::ir::Reg(maat::X64::RAX, 15, 0);
        if (reg_name == "EAX") return maat::ir::Reg(maat::X64::RAX, 31, 0);
        if (reg_name == "RAX") return maat::ir::Reg(maat::X64::RAX, 63, 0);
        if (reg_name == "BL") return maat::ir::Reg(maat::X64::RBX, 7, 0);
        if (reg_name == "BH") return maat::ir::Reg(maat::X64::RBX, 15, 8);
        if (reg_name == "BX") return maat::ir::Reg(maat::X64::RBX, 15, 0);
        if (reg_name == "EBX") return maat::ir::Reg(maat::X64::RBX , 31, 0);
        if (reg_name == "RBX") return maat::ir::Reg(maat::X64::RBX, 63, 0);
        if (reg_name == "CL") return maat::ir::Reg(maat::X64::RCX, 7, 0);
        if (reg_name == "CH") return maat::ir::Reg(maat::X64::RCX, 15, 8);
        if (reg_name == "CX") return maat::ir::Reg(maat::X64::RCX, 15, 0);
        if (reg_name == "ECX") return maat::ir::Reg(maat::X64::RCX, 31, 0);
        if (reg_name == "RCX") return maat::ir::Reg(maat::X64::RCX, 63, 0);
        if (reg_name == "DL") return maat::ir::Reg(maat::X64::RDX, 7, 0);
        if (reg_name == "DH") return maat::ir::Reg(maat::X64::RDX, 15, 8);
        if (reg_name == "DX") return maat::ir::Reg(maat::X64::RDX, 15, 0);
        if (reg_name == "EDX") return maat::ir::Reg(maat::X64::RDX, 31, 0);
        if (reg_name == "RDX") return maat::ir::Reg(maat::X64::RDX, 63, 0);
        if (reg_name == "DIL") return maat::ir::Reg(maat::X64::RDI, 7, 0);
        if (reg_name == "DI") return maat::ir::Reg(maat::X64::RDI, 15, 0);
        if (reg_name == "EDI") return maat::ir::Reg(maat::X64::RDI, 31, 0);
        if (reg_name == "RDI") return maat::ir::Reg(maat::X64::RDI, 63, 0);
        if (reg_name == "SIL") return maat::ir::Reg(maat::X64::RSI, 7, 0);
        if (reg_name == "SI") return maat::ir::Reg(maat::X64::RSI, 15, 0);
        if (reg_name == "ESI") return maat::ir::Reg(maat::X64::RSI, 31, 0);
        if (reg_name == "RSI") return maat::ir::Reg(maat::X64::RSI, 63, 0);
        if (reg_name == "BPL") return maat::ir::Reg(maat::X64::RBP, 7, 0);
        if (reg_name == "BP") return maat::ir::Reg(maat::X64::RBP, 15, 0);
        if (reg_name == "EBP") return maat::ir::Reg(maat::X64::RBP, 31, 0);
        if (reg_name == "RBP") return maat::ir::Reg(maat::X64::RBP, 63, 0);
        if (reg_name == "SPL") return maat::ir::Reg(maat::X64::RSP, 7, 0);
        if (reg_name == "SP") return maat::ir::Reg(maat::X64::RSP, 15, 0);
        if (reg_name == "ESP") return maat::ir::Reg(maat::X64::RSP, 31, 0);
        if (reg_name == "RSP") return maat::ir::Reg(maat::X64::RSP, 63, 0);
        if (reg_name == "IP") return maat::ir::Reg(maat::X64::RIP, 15, 0);
        if (reg_name == "EIP") return maat::ir::Reg(maat::X64::RIP, 31, 0);
        if (reg_name == "RIP") return maat::ir::Reg(maat::X64::RIP, 63, 0);
        if (reg_name == "R8") return maat::ir::Reg(maat::X64::R8, 63, 0);
        if (reg_name == "R8B") return maat::ir::Reg(maat::X64::R8, 7, 0);
        if (reg_name == "R8D") return maat::ir::Reg(maat::X64::R8, 31, 0);
        if (reg_name == "R8W") return maat::ir::Reg(maat::X64::R8, 15, 0);
        if (reg_name == "R9") return maat::ir::Reg(maat::X64::R9, 63, 0);
        if (reg_name == "R9B") return maat::ir::Reg(maat::X64::R9, 7, 0);
        if (reg_name == "R9D") return maat::ir::Reg(maat::X64::R9, 31, 0);
        if (reg_name == "R9W") return maat::ir::Reg(maat::X64::R9, 15, 0);
        if (reg_name == "R10") return maat::ir::Reg(maat::X64::R10, 63, 0);
        if (reg_name == "R10B") return maat::ir::Reg(maat::X64::R10, 7, 0);
        if (reg_name == "R10D") return maat::ir::Reg(maat::X64::R10, 31, 0);
        if (reg_name == "R10W") return maat::ir::Reg(maat::X64::R10, 15, 0);
        if (reg_name == "R11") return maat::ir::Reg(maat::X64::R11, 63, 0);
        if (reg_name == "R11B") return maat::ir::Reg(maat::X64::R11, 7, 0);
        if (reg_name == "R11D") return maat::ir::Reg(maat::X64::R11, 31, 0);
        if (reg_name == "R11W") return maat::ir::Reg(maat::X64::R11, 15, 0);
        if (reg_name == "R12") return maat::ir::Reg(maat::X64::R12, 63, 0);
        if (reg_name == "R12B") return maat::ir::Reg(maat::X64::R12, 7, 0);
        if (reg_name == "R12D") return maat::ir::Reg(maat::X64::R12, 31, 0);
        if (reg_name == "R12W") return maat::ir::Reg(maat::X64::R12, 15, 0);
        if (reg_name == "R13") return maat::ir::Reg(maat::X64::R13, 63, 0);
        if (reg_name == "R13B") return maat::ir::Reg(maat::X64::R13, 7, 0);
        if (reg_name == "R13D") return maat::ir::Reg(maat::X64::R13, 31, 0);
        if (reg_name == "R13W") return maat::ir::Reg(maat::X64::R13, 15, 0);
        if (reg_name == "R14") return maat::ir::Reg(maat::X64::R14, 63, 0);
        if (reg_name == "R14B") return maat::ir::Reg(maat::X64::R14, 7, 0);
        if (reg_name == "R14D") return maat::ir::Reg(maat::X64::R14, 31, 0);
        if (reg_name == "R14W") return maat::ir::Reg(maat::X64::R14, 15, 0);
        if (reg_name == "R15") return maat::ir::Reg(maat::X64::R15, 63, 0);
        if (reg_name == "R15B") return maat::ir::Reg(maat::X64::R15, 7, 0);
        if (reg_name == "R15D") return maat::ir::Reg(maat::X64::R15, 31, 0);
        if (reg_name == "R15W") return maat::ir::Reg(maat::X64::R15, 15, 0);
        if (reg_name == "CS") return maat::ir::Reg(maat::X64::CS, 63, 0);
        if (reg_name == "DS") return maat::ir::Reg(maat::X64::DS, 63, 0);
        if (reg_name == "ES") return maat::ir::Reg(maat::X64::ES, 63, 0);
        if (reg_name == "GS") return maat::ir::Reg(maat::X64::GS, 63, 0);
        if (reg_name == "FS" or reg_name == "FS_OFFSET")
            return maat::ir::Reg(maat::X64::FS, 63, 0);
        if (reg_name == "SS") return maat::ir::Reg(maat::X64::SS, 63, 0);

        if (reg_name == "PF") return maat::ir::Reg(maat::X64::PF, 8);
        if (reg_name == "AF") return maat::ir::Reg(maat::X64::AF, 8);
        if (reg_name == "CF") return maat::ir::Reg(maat::X64::CF, 8);
        if (reg_name == "ZF") return maat::ir::Reg(maat::X64::ZF, 8);
        if (reg_name == "SF") return maat::ir::Reg(maat::X64::SF, 8);
        if (reg_name == "TF") return maat::ir::Reg(maat::X64::TF, 8);
        if (reg_name == "IF") return maat::ir::Reg(maat::X64::IF, 8);
        if (reg_name == "DF") return maat::ir::Reg(maat::X64::DF, 8);
        if (reg_name == "OF") return maat::ir::Reg(maat::X64::OF, 8);
        if (reg_name == "IOPL") return maat::ir::Reg(maat::X64::IOPL, 8);
        if (reg_name == "NT") return maat::ir::Reg(maat::X64::NT, 8);
        if (reg_name == "RF") return maat::ir::Reg(maat::X64::RF, 8);
        if (reg_name == "VM") return maat::ir::Reg(maat::X64::VM, 8);
        if (reg_name == "AC") return maat::ir::Reg(maat::X64::AC, 8);
        if (reg_name == "VIF") return maat::ir::Reg(maat::X64::VIF, 8);
        if (reg_name == "VIP") return maat::ir::Reg(maat::X64::VIP, 8);
        if (reg_name == "ID") return maat::ir::Reg(maat::X64::ID, 8);

        if (reg_name == "MM0") return maat::ir::Reg(maat::X64::MM0, 64);
        if (reg_name == "MM0_Da") return maat::ir::Reg(maat::X64::MM0, 31, 0);
        if (reg_name == "MM0_Db") return maat::ir::Reg(maat::X64::MM0, 63, 32);
        if (reg_name == "MM0_Wa") return maat::ir::Reg(maat::X64::MM0, 15, 0);
        if (reg_name == "MM0_Wb") return maat::ir::Reg(maat::X64::MM0, 31, 16);
        if (reg_name == "MM0_Wc") return maat::ir::Reg(maat::X64::MM0, 47, 32);
        if (reg_name == "MM0_Wd") return maat::ir::Reg(maat::X64::MM0, 63, 48);
        if (reg_name == "MM0_Ba") return maat::ir::Reg(maat::X64::MM0, 7, 0);
        if (reg_name == "MM0_Bb") return maat::ir::Reg(maat::X64::MM0, 15, 8);
        if (reg_name == "MM0_Bc") return maat::ir::Reg(maat::X64::MM0, 23, 16);
        if (reg_name == "MM0_Bd") return maat::ir::Reg(maat::X64::MM0, 31, 24);
        if (reg_name == "MM0_Be") return maat::ir::Reg(maat::X64::MM0, 39, 32);
        if (reg_name == "MM0_Bf") return maat::ir::Reg(maat::X64::MM0, 47, 40);
        if (reg_name == "MM0_Bg") return maat::ir::Reg(maat::X64::MM0, 55, 48);
        if (reg_name == "MM0_Bh") return maat::ir::Reg(maat::X64::MM0, 63, 56);

        if (reg_name == "MM1") return maat::ir::Reg(maat::X64::MM1, 64);
        if (reg_name == "MM1_Da") return maat::ir::Reg(maat::X64::MM1, 31, 0);
        if (reg_name == "MM1_Db") return maat::ir::Reg(maat::X64::MM1, 63, 32);
        if (reg_name == "MM1_Wa") return maat::ir::Reg(maat::X64::MM1, 15, 0);
        if (reg_name == "MM1_Wb") return maat::ir::Reg(maat::X64::MM1, 31, 16);
        if (reg_name == "MM1_Wc") return maat::ir::Reg(maat::X64::MM1, 47, 32);
        if (reg_name == "MM1_Wd") return maat::ir::Reg(maat::X64::MM1, 63, 48);
        if (reg_name == "MM1_Ba") return maat::ir::Reg(maat::X64::MM1, 7, 0);
        if (reg_name == "MM1_Bb") return maat::ir::Reg(maat::X64::MM1, 15, 8);
        if (reg_name == "MM1_Bc") return maat::ir::Reg(maat::X64::MM1, 23, 16);
        if (reg_name == "MM1_Bd") return maat::ir::Reg(maat::X64::MM1, 31, 24);
        if (reg_name == "MM1_Be") return maat::ir::Reg(maat::X64::MM1, 39, 32);
        if (reg_name == "MM1_Bf") return maat::ir::Reg(maat::X64::MM1, 47, 40);
        if (reg_name == "MM1_Bg") return maat::ir::Reg(maat::X64::MM1, 55, 48);
        if (reg_name == "MM1_Bh") return maat::ir::Reg(maat::X64::MM1, 63, 56);
        
        if (reg_name == "MM2") return maat::ir::Reg(maat::X64::MM2, 64);
        if (reg_name == "MM2_Da") return maat::ir::Reg(maat::X64::MM2, 31, 0);
        if (reg_name == "MM2_Db") return maat::ir::Reg(maat::X64::MM2, 63, 32);
        if (reg_name == "MM2_Wa") return maat::ir::Reg(maat::X64::MM2, 15, 0);
        if (reg_name == "MM2_Wb") return maat::ir::Reg(maat::X64::MM2, 31, 16);
        if (reg_name == "MM2_Wc") return maat::ir::Reg(maat::X64::MM2, 47, 32);
        if (reg_name == "MM2_Wd") return maat::ir::Reg(maat::X64::MM2, 63, 48);
        if (reg_name == "MM2_Ba") return maat::ir::Reg(maat::X64::MM2, 7, 0);
        if (reg_name == "MM2_Bb") return maat::ir::Reg(maat::X64::MM2, 15, 8);
        if (reg_name == "MM2_Bc") return maat::ir::Reg(maat::X64::MM2, 23, 16);
        if (reg_name == "MM2_Bd") return maat::ir::Reg(maat::X64::MM2, 31, 24);
        if (reg_name == "MM2_Be") return maat::ir::Reg(maat::X64::MM2, 39, 32);
        if (reg_name == "MM2_Bf") return maat::ir::Reg(maat::X64::MM2, 47, 40);
        if (reg_name == "MM2_Bg") return maat::ir::Reg(maat::X64::MM2, 55, 48);
        if (reg_name == "MM2_Bh") return maat::ir::Reg(maat::X64::MM2, 63, 56);
        
        if (reg_name == "MM3") return maat::ir::Reg(maat::X64::MM3, 64);
        if (reg_name == "MM3_Da") return maat::ir::Reg(maat::X64::MM3, 31, 0);
        if (reg_name == "MM3_Db") return maat::ir::Reg(maat::X64::MM3, 63, 32);
        if (reg_name == "MM3_Wa") return maat::ir::Reg(maat::X64::MM3, 15, 0);
        if (reg_name == "MM3_Wb") return maat::ir::Reg(maat::X64::MM3, 31, 16);
        if (reg_name == "MM3_Wc") return maat::ir::Reg(maat::X64::MM3, 47, 32);
        if (reg_name == "MM3_Wd") return maat::ir::Reg(maat::X64::MM3, 63, 48);
        if (reg_name == "MM3_Ba") return maat::ir::Reg(maat::X64::MM3, 7, 0);
        if (reg_name == "MM3_Bb") return maat::ir::Reg(maat::X64::MM3, 15, 8);
        if (reg_name == "MM3_Bc") return maat::ir::Reg(maat::X64::MM3, 23, 16);
        if (reg_name == "MM3_Bd") return maat::ir::Reg(maat::X64::MM3, 31, 24);
        if (reg_name == "MM3_Be") return maat::ir::Reg(maat::X64::MM3, 39, 32);
        if (reg_name == "MM3_Bf") return maat::ir::Reg(maat::X64::MM3, 47, 40);
        if (reg_name == "MM3_Bg") return maat::ir::Reg(maat::X64::MM3, 55, 48);
        if (reg_name == "MM3_Bh") return maat::ir::Reg(maat::X64::MM3, 63, 56);
        
        if (reg_name == "MM4") return maat::ir::Reg(maat::X64::MM4, 64);
        if (reg_name == "MM4_Da") return maat::ir::Reg(maat::X64::MM4, 31, 0);
        if (reg_name == "MM4_Db") return maat::ir::Reg(maat::X64::MM4, 63, 32);
        if (reg_name == "MM4_Wa") return maat::ir::Reg(maat::X64::MM4, 15, 0);
        if (reg_name == "MM4_Wb") return maat::ir::Reg(maat::X64::MM4, 31, 16);
        if (reg_name == "MM4_Wc") return maat::ir::Reg(maat::X64::MM4, 47, 32);
        if (reg_name == "MM4_Wd") return maat::ir::Reg(maat::X64::MM4, 63, 48);
        if (reg_name == "MM4_Ba") return maat::ir::Reg(maat::X64::MM4, 7, 0);
        if (reg_name == "MM4_Bb") return maat::ir::Reg(maat::X64::MM4, 15, 8);
        if (reg_name == "MM4_Bc") return maat::ir::Reg(maat::X64::MM4, 23, 16);
        if (reg_name == "MM4_Bd") return maat::ir::Reg(maat::X64::MM4, 31, 24);
        if (reg_name == "MM4_Be") return maat::ir::Reg(maat::X64::MM4, 39, 32);
        if (reg_name == "MM4_Bf") return maat::ir::Reg(maat::X64::MM4, 47, 40);
        if (reg_name == "MM4_Bg") return maat::ir::Reg(maat::X64::MM4, 55, 48);
        if (reg_name == "MM4_Bh") return maat::ir::Reg(maat::X64::MM4, 63, 56);
        
        if (reg_name == "MM5") return maat::ir::Reg(maat::X64::MM5, 64);
        if (reg_name == "MM5_Da") return maat::ir::Reg(maat::X64::MM5, 31, 0);
        if (reg_name == "MM5_Db") return maat::ir::Reg(maat::X64::MM5, 63, 32);
        if (reg_name == "MM5_Wa") return maat::ir::Reg(maat::X64::MM5, 15, 0);
        if (reg_name == "MM5_Wb") return maat::ir::Reg(maat::X64::MM5, 31, 16);
        if (reg_name == "MM5_Wc") return maat::ir::Reg(maat::X64::MM5, 47, 32);
        if (reg_name == "MM5_Wd") return maat::ir::Reg(maat::X64::MM5, 63, 48);
        if (reg_name == "MM5_Ba") return maat::ir::Reg(maat::X64::MM5, 7, 0);
        if (reg_name == "MM5_Bb") return maat::ir::Reg(maat::X64::MM5, 15, 8);
        if (reg_name == "MM5_Bc") return maat::ir::Reg(maat::X64::MM5, 23, 16);
        if (reg_name == "MM5_Bd") return maat::ir::Reg(maat::X64::MM5, 31, 24);
        if (reg_name == "MM5_Be") return maat::ir::Reg(maat::X64::MM5, 39, 32);
        if (reg_name == "MM5_Bf") return maat::ir::Reg(maat::X64::MM5, 47, 40);
        if (reg_name == "MM5_Bg") return maat::ir::Reg(maat::X64::MM5, 55, 48);
        if (reg_name == "MM5_Bh") return maat::ir::Reg(maat::X64::MM5, 63, 56);
        
        if (reg_name == "MM6") return maat::ir::Reg(maat::X64::MM6, 64);
        if (reg_name == "MM6_Da") return maat::ir::Reg(maat::X64::MM6, 31, 0);
        if (reg_name == "MM6_Db") return maat::ir::Reg(maat::X64::MM6, 63, 32);
        if (reg_name == "MM6_Wa") return maat::ir::Reg(maat::X64::MM6, 15, 0);
        if (reg_name == "MM6_Wb") return maat::ir::Reg(maat::X64::MM6, 31, 16);
        if (reg_name == "MM6_Wc") return maat::ir::Reg(maat::X64::MM6, 47, 32);
        if (reg_name == "MM6_Wd") return maat::ir::Reg(maat::X64::MM6, 63, 48);
        if (reg_name == "MM6_Ba") return maat::ir::Reg(maat::X64::MM6, 7, 0);
        if (reg_name == "MM6_Bb") return maat::ir::Reg(maat::X64::MM6, 15, 8);
        if (reg_name == "MM6_Bc") return maat::ir::Reg(maat::X64::MM6, 23, 16);
        if (reg_name == "MM6_Bd") return maat::ir::Reg(maat::X64::MM6, 31, 24);
        if (reg_name == "MM6_Be") return maat::ir::Reg(maat::X64::MM6, 39, 32);
        if (reg_name == "MM6_Bf") return maat::ir::Reg(maat::X64::MM6, 47, 40);
        if (reg_name == "MM6_Bg") return maat::ir::Reg(maat::X64::MM6, 55, 48);
        if (reg_name == "MM6_Bh") return maat::ir::Reg(maat::X64::MM6, 63, 56);
        
        if (reg_name == "MM7") return maat::ir::Reg(maat::X64::MM7, 64);
        if (reg_name == "MM7_Da") return maat::ir::Reg(maat::X64::MM7, 31, 0);
        if (reg_name == "MM7_Db") return maat::ir::Reg(maat::X64::MM7, 63, 32);
        if (reg_name == "MM7_Wa") return maat::ir::Reg(maat::X64::MM7, 15, 0);
        if (reg_name == "MM7_Wb") return maat::ir::Reg(maat::X64::MM7, 31, 16);
        if (reg_name == "MM7_Wc") return maat::ir::Reg(maat::X64::MM7, 47, 32);
        if (reg_name == "MM7_Wd") return maat::ir::Reg(maat::X64::MM7, 63, 48);
        if (reg_name == "MM7_Ba") return maat::ir::Reg(maat::X64::MM7, 7, 0);
        if (reg_name == "MM7_Bb") return maat::ir::Reg(maat::X64::MM7, 15, 8);
        if (reg_name == "MM7_Bc") return maat::ir::Reg(maat::X64::MM7, 23, 16);
        if (reg_name == "MM7_Bd") return maat::ir::Reg(maat::X64::MM7, 31, 24);
        if (reg_name == "MM7_Be") return maat::ir::Reg(maat::X64::MM7, 39, 32);
        if (reg_name == "MM7_Bf") return maat::ir::Reg(maat::X64::MM7, 47, 40);
        if (reg_name == "MM7_Bg") return maat::ir::Reg(maat::X64::MM7, 55, 48);
        if (reg_name == "MM7_Bh") return maat::ir::Reg(maat::X64::MM7, 63, 56);


        if (reg_name == "MM2") return maat::ir::Reg(maat::X64::MM2, 64);
        if (reg_name == "MM3") return maat::ir::Reg(maat::X64::MM3, 64);
        if (reg_name == "MM4") return maat::ir::Reg(maat::X64::MM4, 64);
        if (reg_name == "MM5") return maat::ir::Reg(maat::X64::MM5, 64);
        if (reg_name == "MM6") return maat::ir::Reg(maat::X64::MM6, 64);
        if (reg_name == "MM7") return maat::ir::Reg(maat::X64::MM7, 64);

        if (reg_name == "ZMM0") return maat::ir::Reg(maat::X64::ZMM0, 512);
        if (reg_name == "YMM0") return maat::ir::Reg(maat::X64::ZMM0, 256);
        if (reg_name == "XMM0") return maat::ir::Reg(maat::X64::ZMM0, 128);
        if (reg_name == "XMM0_Qa") return maat::ir::Reg(maat::X64::ZMM0, 63, 0);
        if (reg_name == "XMM0_Qb") return maat::ir::Reg(maat::X64::ZMM0, 127, 64);
        if (reg_name == "XMM0_Da") return maat::ir::Reg(maat::X64::ZMM0, 31, 0);
        if (reg_name == "XMM0_Db") return maat::ir::Reg(maat::X64::ZMM0, 63, 32);
        if (reg_name == "XMM0_Dc") return maat::ir::Reg(maat::X64::ZMM0, 95, 64);
        if (reg_name == "XMM0_Dd") return maat::ir::Reg(maat::X64::ZMM0, 127, 96);
        if (reg_name == "XMM0_Wa") return maat::ir::Reg(maat::X64::ZMM0, 15, 0);
        if (reg_name == "XMM0_Wb") return maat::ir::Reg(maat::X64::ZMM0, 31, 16);
        if (reg_name == "XMM0_Wc") return maat::ir::Reg(maat::X64::ZMM0, 47, 32);
        if (reg_name == "XMM0_Wd") return maat::ir::Reg(maat::X64::ZMM0, 63, 48);
        if (reg_name == "XMM0_We") return maat::ir::Reg(maat::X64::ZMM0, 79, 64);
        if (reg_name == "XMM0_Wf") return maat::ir::Reg(maat::X64::ZMM0, 95, 80);
        if (reg_name == "XMM0_Wg") return maat::ir::Reg(maat::X64::ZMM0, 111, 96);
        if (reg_name == "XMM0_Wh") return maat::ir::Reg(maat::X64::ZMM0, 127, 112);
        if (reg_name == "XMM0_Ba") return maat::ir::Reg(maat::X64::ZMM0, 7, 0);
        if (reg_name == "XMM0_Bb") return maat::ir::Reg(maat::X64::ZMM0, 15, 8);
        if (reg_name == "XMM0_Bc") return maat::ir::Reg(maat::X64::ZMM0, 23, 16);
        if (reg_name == "XMM0_Bd") return maat::ir::Reg(maat::X64::ZMM0, 31, 24);
        if (reg_name == "XMM0_Be") return maat::ir::Reg(maat::X64::ZMM0, 39, 32);
        if (reg_name == "XMM0_Bf") return maat::ir::Reg(maat::X64::ZMM0, 47, 40);
        if (reg_name == "XMM0_Bg") return maat::ir::Reg(maat::X64::ZMM0, 55, 48);
        if (reg_name == "XMM0_Bh") return maat::ir::Reg(maat::X64::ZMM0, 63, 56);
        if (reg_name == "XMM0_Bi") return maat::ir::Reg(maat::X64::ZMM0, 71, 64);
        if (reg_name == "XMM0_Bj") return maat::ir::Reg(maat::X64::ZMM0, 79, 72);
        if (reg_name == "XMM0_Bk") return maat::ir::Reg(maat::X64::ZMM0, 87, 80);
        if (reg_name == "XMM0_Bl") return maat::ir::Reg(maat::X64::ZMM0, 95, 88);
        if (reg_name == "XMM0_Bm") return maat::ir::Reg(maat::X64::ZMM0, 103, 96);
        if (reg_name == "XMM0_Bn") return maat::ir::Reg(maat::X64::ZMM0, 111, 104);
        if (reg_name == "XMM0_Bo") return maat::ir::Reg(maat::X64::ZMM0, 119, 112);
        if (reg_name == "XMM0_Bp") return maat::ir::Reg(maat::X64::ZMM0, 127, 120);

        if (reg_name == "ZMM1") return maat::ir::Reg(maat::X64::ZMM1, 512);
        if (reg_name == "YMM1") return maat::ir::Reg(maat::X64::ZMM1, 256);
        if (reg_name == "XMM1") return maat::ir::Reg(maat::X64::ZMM1, 128);
        if (reg_name == "XMM1_Qa") return maat::ir::Reg(maat::X64::ZMM1, 63, 0);
        if (reg_name == "XMM1_Qb") return maat::ir::Reg(maat::X64::ZMM1, 127, 64);
        if (reg_name == "XMM1_Da") return maat::ir::Reg(maat::X64::ZMM1, 31, 0);
        if (reg_name == "XMM1_Db") return maat::ir::Reg(maat::X64::ZMM1, 63, 32);
        if (reg_name == "XMM1_Dc") return maat::ir::Reg(maat::X64::ZMM1, 95, 64);
        if (reg_name == "XMM1_Dd") return maat::ir::Reg(maat::X64::ZMM1, 127, 96);
        if (reg_name == "XMM1_Ba") return maat::ir::Reg(maat::X64::ZMM1, 7, 0);
        if (reg_name == "XMM1_Bb") return maat::ir::Reg(maat::X64::ZMM1, 15, 8);
        if (reg_name == "XMM1_Bc") return maat::ir::Reg(maat::X64::ZMM1, 23, 16);
        if (reg_name == "XMM1_Bd") return maat::ir::Reg(maat::X64::ZMM1, 31, 24);
        if (reg_name == "XMM1_Be") return maat::ir::Reg(maat::X64::ZMM1, 39, 32);
        if (reg_name == "XMM1_Bf") return maat::ir::Reg(maat::X64::ZMM1, 47, 40);
        if (reg_name == "XMM1_Bg") return maat::ir::Reg(maat::X64::ZMM1, 55, 48);
        if (reg_name == "XMM1_Bh") return maat::ir::Reg(maat::X64::ZMM1, 63, 56);
        if (reg_name == "XMM1_Bi") return maat::ir::Reg(maat::X64::ZMM1, 71, 64);
        if (reg_name == "XMM1_Bj") return maat::ir::Reg(maat::X64::ZMM1, 79, 72);
        if (reg_name == "XMM1_Bk") return maat::ir::Reg(maat::X64::ZMM1, 87, 80);
        if (reg_name == "XMM1_Bl") return maat::ir::Reg(maat::X64::ZMM1, 95, 88);
        if (reg_name == "XMM1_Bm") return maat::ir::Reg(maat::X64::ZMM1, 103, 96);
        if (reg_name == "XMM1_Bn") return maat::ir::Reg(maat::X64::ZMM1, 111, 104);
        if (reg_name == "XMM1_Bo") return maat::ir::Reg(maat::X64::ZMM1, 119, 112);
        if (reg_name == "XMM1_Bp") return maat::ir::Reg(maat::X64::ZMM1, 127, 120);
        if (reg_name == "XMM1_Wa") return maat::ir::Reg(maat::X64::ZMM1, 15, 0);
        if (reg_name == "XMM1_Wb") return maat::ir::Reg(maat::X64::ZMM1, 31, 16);
        if (reg_name == "XMM1_Wc") return maat::ir::Reg(maat::X64::ZMM1, 47, 32);
        if (reg_name == "XMM1_Wd") return maat::ir::Reg(maat::X64::ZMM1, 63, 48);
        if (reg_name == "XMM1_We") return maat::ir::Reg(maat::X64::ZMM1, 79, 64);
        if (reg_name == "XMM1_Wf") return maat::ir::Reg(maat::X64::ZMM1, 95, 80);
        if (reg_name == "XMM1_Wg") return maat::ir::Reg(maat::X64::ZMM1, 111, 96);
        if (reg_name == "XMM1_Wh") return maat::ir::Reg(maat::X64::ZMM1, 127, 112);

        if (reg_name == "ZMM2") return maat::ir::Reg(maat::X64::ZMM2, 512);
        if (reg_name == "YMM2") return maat::ir::Reg(maat::X64::ZMM2, 256);
        if (reg_name == "XMM2") return maat::ir::Reg(maat::X64::ZMM2, 128);
        if (reg_name == "XMM2_Qa") return maat::ir::Reg(maat::X64::ZMM2, 63, 0);
        if (reg_name == "XMM2_Qb") return maat::ir::Reg(maat::X64::ZMM2, 127, 64);
        if (reg_name == "XMM2_Da") return maat::ir::Reg(maat::X64::ZMM2, 31, 0);
        if (reg_name == "XMM2_Db") return maat::ir::Reg(maat::X64::ZMM2, 63, 32);
        if (reg_name == "XMM2_Dc") return maat::ir::Reg(maat::X64::ZMM2, 95, 64);
        if (reg_name == "XMM2_Dd") return maat::ir::Reg(maat::X64::ZMM2, 127, 96);
        if (reg_name == "XMM2_Ba") return maat::ir::Reg(maat::X64::ZMM2, 7, 0);
        if (reg_name == "XMM2_Bb") return maat::ir::Reg(maat::X64::ZMM2, 15, 8);
        if (reg_name == "XMM2_Bc") return maat::ir::Reg(maat::X64::ZMM2, 23, 16);
        if (reg_name == "XMM2_Bd") return maat::ir::Reg(maat::X64::ZMM2, 31, 24);
        if (reg_name == "XMM2_Be") return maat::ir::Reg(maat::X64::ZMM2, 39, 32);
        if (reg_name == "XMM2_Bf") return maat::ir::Reg(maat::X64::ZMM2, 47, 40);
        if (reg_name == "XMM2_Bg") return maat::ir::Reg(maat::X64::ZMM2, 55, 48);
        if (reg_name == "XMM2_Bh") return maat::ir::Reg(maat::X64::ZMM2, 63, 56);
        if (reg_name == "XMM2_Bi") return maat::ir::Reg(maat::X64::ZMM2, 71, 64);
        if (reg_name == "XMM2_Bj") return maat::ir::Reg(maat::X64::ZMM2, 79, 72);
        if (reg_name == "XMM2_Bk") return maat::ir::Reg(maat::X64::ZMM2, 87, 80);
        if (reg_name == "XMM2_Bl") return maat::ir::Reg(maat::X64::ZMM2, 95, 88);
        if (reg_name == "XMM2_Bm") return maat::ir::Reg(maat::X64::ZMM2, 103, 96);
        if (reg_name == "XMM2_Bn") return maat::ir::Reg(maat::X64::ZMM2, 111, 104);
        if (reg_name == "XMM2_Bo") return maat::ir::Reg(maat::X64::ZMM2, 119, 112);
        if (reg_name == "XMM2_Bp") return maat::ir::Reg(maat::X64::ZMM2, 127, 120);
        if (reg_name == "XMM2_Wa") return maat::ir::Reg(maat::X64::ZMM2, 15, 0);
        if (reg_name == "XMM2_Wb") return maat::ir::Reg(maat::X64::ZMM2, 31, 16);
        if (reg_name == "XMM2_Wc") return maat::ir::Reg(maat::X64::ZMM2, 47, 32);
        if (reg_name == "XMM2_Wd") return maat::ir::Reg(maat::X64::ZMM2, 63, 48);
        if (reg_name == "XMM2_We") return maat::ir::Reg(maat::X64::ZMM2, 79, 64);
        if (reg_name == "XMM2_Wf") return maat::ir::Reg(maat::X64::ZMM2, 95, 80);
        if (reg_name == "XMM2_Wg") return maat::ir::Reg(maat::X64::ZMM2, 111, 96);
        if (reg_name == "XMM2_Wh") return maat::ir::Reg(maat::X64::ZMM2, 127, 112);
        
        if (reg_name == "ZMM3") return maat::ir::Reg(maat::X64::ZMM3, 512);
        if (reg_name == "YMM3") return maat::ir::Reg(maat::X64::ZMM3, 256);
        if (reg_name == "XMM3") return maat::ir::Reg(maat::X64::ZMM3, 128);
        if (reg_name == "XMM3_Qa") return maat::ir::Reg(maat::X64::ZMM3, 63, 0);
        if (reg_name == "XMM3_Qb") return maat::ir::Reg(maat::X64::ZMM3, 127, 64);
        if (reg_name == "XMM3_Da") return maat::ir::Reg(maat::X64::ZMM3, 31, 0);
        if (reg_name == "XMM3_Db") return maat::ir::Reg(maat::X64::ZMM3, 63, 32);
        if (reg_name == "XMM3_Dc") return maat::ir::Reg(maat::X64::ZMM3, 95, 64);
        if (reg_name == "XMM3_Dd") return maat::ir::Reg(maat::X64::ZMM3, 127, 96);
        if (reg_name == "XMM3_Ba") return maat::ir::Reg(maat::X64::ZMM3, 7, 0);
        if (reg_name == "XMM3_Bb") return maat::ir::Reg(maat::X64::ZMM3, 15, 8);
        if (reg_name == "XMM3_Bc") return maat::ir::Reg(maat::X64::ZMM3, 23, 16);
        if (reg_name == "XMM3_Bd") return maat::ir::Reg(maat::X64::ZMM3, 31, 24);
        if (reg_name == "XMM3_Be") return maat::ir::Reg(maat::X64::ZMM3, 39, 32);
        if (reg_name == "XMM3_Bf") return maat::ir::Reg(maat::X64::ZMM3, 47, 40);
        if (reg_name == "XMM3_Bg") return maat::ir::Reg(maat::X64::ZMM3, 55, 48);
        if (reg_name == "XMM3_Bh") return maat::ir::Reg(maat::X64::ZMM3, 63, 56);
        if (reg_name == "XMM3_Bi") return maat::ir::Reg(maat::X64::ZMM3, 71, 64);
        if (reg_name == "XMM3_Bj") return maat::ir::Reg(maat::X64::ZMM3, 79, 72);
        if (reg_name == "XMM3_Bk") return maat::ir::Reg(maat::X64::ZMM3, 87, 80);
        if (reg_name == "XMM3_Bl") return maat::ir::Reg(maat::X64::ZMM3, 95, 88);
        if (reg_name == "XMM3_Bm") return maat::ir::Reg(maat::X64::ZMM3, 103, 96);
        if (reg_name == "XMM3_Bn") return maat::ir::Reg(maat::X64::ZMM3, 111, 104);
        if (reg_name == "XMM3_Bo") return maat::ir::Reg(maat::X64::ZMM3, 119, 112);
        if (reg_name == "XMM3_Bp") return maat::ir::Reg(maat::X64::ZMM3, 127, 120);
        if (reg_name == "XMM3_Wa") return maat::ir::Reg(maat::X64::ZMM3, 15, 0);
        if (reg_name == "XMM3_Wb") return maat::ir::Reg(maat::X64::ZMM3, 31, 16);
        if (reg_name == "XMM3_Wc") return maat::ir::Reg(maat::X64::ZMM3, 47, 32);
        if (reg_name == "XMM3_Wd") return maat::ir::Reg(maat::X64::ZMM3, 63, 48);
        if (reg_name == "XMM3_We") return maat::ir::Reg(maat::X64::ZMM3, 79, 64);
        if (reg_name == "XMM3_Wf") return maat::ir::Reg(maat::X64::ZMM3, 95, 80);
        if (reg_name == "XMM3_Wg") return maat::ir::Reg(maat::X64::ZMM3, 111, 96);
        if (reg_name == "XMM3_Wh") return maat::ir::Reg(maat::X64::ZMM3, 127, 112);
        
        if (reg_name == "ZMM4") return maat::ir::Reg(maat::X64::ZMM4, 512);
        if (reg_name == "YMM4") return maat::ir::Reg(maat::X64::ZMM4, 256);
        if (reg_name == "XMM4") return maat::ir::Reg(maat::X64::ZMM4, 128);
        if (reg_name == "XMM4_Qa") return maat::ir::Reg(maat::X64::ZMM4, 63, 0);
        if (reg_name == "XMM4_Qb") return maat::ir::Reg(maat::X64::ZMM4, 127, 64);
        if (reg_name == "XMM4_Da") return maat::ir::Reg(maat::X64::ZMM4, 31, 0);
        if (reg_name == "XMM4_Db") return maat::ir::Reg(maat::X64::ZMM4, 63, 32);
        if (reg_name == "XMM4_Dc") return maat::ir::Reg(maat::X64::ZMM4, 95, 64);
        if (reg_name == "XMM4_Dd") return maat::ir::Reg(maat::X64::ZMM4, 127, 96);
        if (reg_name == "XMM4_Ba") return maat::ir::Reg(maat::X64::ZMM4, 7, 0);
        if (reg_name == "XMM4_Bb") return maat::ir::Reg(maat::X64::ZMM4, 15, 8);
        if (reg_name == "XMM4_Bc") return maat::ir::Reg(maat::X64::ZMM4, 23, 16);
        if (reg_name == "XMM4_Bd") return maat::ir::Reg(maat::X64::ZMM4, 31, 24);
        if (reg_name == "XMM4_Be") return maat::ir::Reg(maat::X64::ZMM4, 39, 32);
        if (reg_name == "XMM4_Bf") return maat::ir::Reg(maat::X64::ZMM4, 47, 40);
        if (reg_name == "XMM4_Bg") return maat::ir::Reg(maat::X64::ZMM4, 55, 48);
        if (reg_name == "XMM4_Bh") return maat::ir::Reg(maat::X64::ZMM4, 63, 56);
        if (reg_name == "XMM4_Bi") return maat::ir::Reg(maat::X64::ZMM4, 71, 64);
        if (reg_name == "XMM4_Bj") return maat::ir::Reg(maat::X64::ZMM4, 79, 72);
        if (reg_name == "XMM4_Bk") return maat::ir::Reg(maat::X64::ZMM4, 87, 80);
        if (reg_name == "XMM4_Bl") return maat::ir::Reg(maat::X64::ZMM4, 95, 88);
        if (reg_name == "XMM4_Bm") return maat::ir::Reg(maat::X64::ZMM4, 103, 96);
        if (reg_name == "XMM4_Bn") return maat::ir::Reg(maat::X64::ZMM4, 111, 104);
        if (reg_name == "XMM4_Bo") return maat::ir::Reg(maat::X64::ZMM4, 119, 112);
        if (reg_name == "XMM4_Bp") return maat::ir::Reg(maat::X64::ZMM4, 127, 120);
        if (reg_name == "XMM4_Wa") return maat::ir::Reg(maat::X64::ZMM4, 15, 0);
        if (reg_name == "XMM4_Wb") return maat::ir::Reg(maat::X64::ZMM4, 31, 16);
        if (reg_name == "XMM4_Wc") return maat::ir::Reg(maat::X64::ZMM4, 47, 32);
        if (reg_name == "XMM4_Wd") return maat::ir::Reg(maat::X64::ZMM4, 63, 48);
        if (reg_name == "XMM4_We") return maat::ir::Reg(maat::X64::ZMM4, 79, 64);
        if (reg_name == "XMM4_Wf") return maat::ir::Reg(maat::X64::ZMM4, 95, 80);
        if (reg_name == "XMM4_Wg") return maat::ir::Reg(maat::X64::ZMM4, 111, 96);
        if (reg_name == "XMM4_Wh") return maat::ir::Reg(maat::X64::ZMM4, 127, 112);
        
        if (reg_name == "ZMM5") return maat::ir::Reg(maat::X64::ZMM5, 512);
        if (reg_name == "YMM5") return maat::ir::Reg(maat::X64::ZMM5, 256);
        if (reg_name == "XMM5") return maat::ir::Reg(maat::X64::ZMM5, 128);
        if (reg_name == "XMM5_Qa") return maat::ir::Reg(maat::X64::ZMM5, 63, 0);
        if (reg_name == "XMM5_Qb") return maat::ir::Reg(maat::X64::ZMM5, 127, 64);
        if (reg_name == "XMM5_Da") return maat::ir::Reg(maat::X64::ZMM5, 31, 0);
        if (reg_name == "XMM5_Db") return maat::ir::Reg(maat::X64::ZMM5, 63, 32);
        if (reg_name == "XMM5_Dc") return maat::ir::Reg(maat::X64::ZMM5, 95, 64);
        if (reg_name == "XMM5_Dd") return maat::ir::Reg(maat::X64::ZMM5, 127, 96);
        if (reg_name == "XMM5_Ba") return maat::ir::Reg(maat::X64::ZMM5, 7, 0);
        if (reg_name == "XMM5_Bb") return maat::ir::Reg(maat::X64::ZMM5, 15, 8);
        if (reg_name == "XMM5_Bc") return maat::ir::Reg(maat::X64::ZMM5, 23, 16);
        if (reg_name == "XMM5_Bd") return maat::ir::Reg(maat::X64::ZMM5, 31, 24);
        if (reg_name == "XMM5_Be") return maat::ir::Reg(maat::X64::ZMM5, 39, 32);
        if (reg_name == "XMM5_Bf") return maat::ir::Reg(maat::X64::ZMM5, 47, 40);
        if (reg_name == "XMM5_Bg") return maat::ir::Reg(maat::X64::ZMM5, 55, 48);
        if (reg_name == "XMM5_Bh") return maat::ir::Reg(maat::X64::ZMM5, 63, 56);
        if (reg_name == "XMM5_Bi") return maat::ir::Reg(maat::X64::ZMM5, 71, 64);
        if (reg_name == "XMM5_Bj") return maat::ir::Reg(maat::X64::ZMM5, 79, 72);
        if (reg_name == "XMM5_Bk") return maat::ir::Reg(maat::X64::ZMM5, 87, 80);
        if (reg_name == "XMM5_Bl") return maat::ir::Reg(maat::X64::ZMM5, 95, 88);
        if (reg_name == "XMM5_Bm") return maat::ir::Reg(maat::X64::ZMM5, 103, 96);
        if (reg_name == "XMM5_Bn") return maat::ir::Reg(maat::X64::ZMM5, 111, 104);
        if (reg_name == "XMM5_Bo") return maat::ir::Reg(maat::X64::ZMM5, 119, 112);
        if (reg_name == "XMM5_Bp") return maat::ir::Reg(maat::X64::ZMM5, 127, 120);
        if (reg_name == "XMM5_Wa") return maat::ir::Reg(maat::X64::ZMM5, 15, 0);
        if (reg_name == "XMM5_Wb") return maat::ir::Reg(maat::X64::ZMM5, 31, 16);
        if (reg_name == "XMM5_Wc") return maat::ir::Reg(maat::X64::ZMM5, 47, 32);
        if (reg_name == "XMM5_Wd") return maat::ir::Reg(maat::X64::ZMM5, 63, 48);
        if (reg_name == "XMM5_We") return maat::ir::Reg(maat::X64::ZMM5, 79, 64);
        if (reg_name == "XMM5_Wf") return maat::ir::Reg(maat::X64::ZMM5, 95, 80);
        if (reg_name == "XMM5_Wg") return maat::ir::Reg(maat::X64::ZMM5, 111, 96);
        if (reg_name == "XMM5_Wh") return maat::ir::Reg(maat::X64::ZMM5, 127, 112);
        
        if (reg_name == "ZMM6") return maat::ir::Reg(maat::X64::ZMM6, 512);
        if (reg_name == "YMM6") return maat::ir::Reg(maat::X64::ZMM6, 256);
        if (reg_name == "XMM6") return maat::ir::Reg(maat::X64::ZMM6, 128);
        if (reg_name == "XMM6_Qa") return maat::ir::Reg(maat::X64::ZMM6, 63, 0);
        if (reg_name == "XMM6_Qb") return maat::ir::Reg(maat::X64::ZMM6, 127, 64);
        if (reg_name == "XMM6_Da") return maat::ir::Reg(maat::X64::ZMM6, 31, 0);
        if (reg_name == "XMM6_Db") return maat::ir::Reg(maat::X64::ZMM6, 63, 32);
        if (reg_name == "XMM6_Dc") return maat::ir::Reg(maat::X64::ZMM6, 95, 64);
        if (reg_name == "XMM6_Dd") return maat::ir::Reg(maat::X64::ZMM6, 127, 96);
        if (reg_name == "XMM6_Ba") return maat::ir::Reg(maat::X64::ZMM6, 7, 0);
        if (reg_name == "XMM6_Bb") return maat::ir::Reg(maat::X64::ZMM6, 15, 8);
        if (reg_name == "XMM6_Bc") return maat::ir::Reg(maat::X64::ZMM6, 23, 16);
        if (reg_name == "XMM6_Bd") return maat::ir::Reg(maat::X64::ZMM6, 31, 24);
        if (reg_name == "XMM6_Be") return maat::ir::Reg(maat::X64::ZMM6, 39, 32);
        if (reg_name == "XMM6_Bf") return maat::ir::Reg(maat::X64::ZMM6, 47, 40);
        if (reg_name == "XMM6_Bg") return maat::ir::Reg(maat::X64::ZMM6, 55, 48);
        if (reg_name == "XMM6_Bh") return maat::ir::Reg(maat::X64::ZMM6, 63, 56);
        if (reg_name == "XMM6_Bi") return maat::ir::Reg(maat::X64::ZMM6, 71, 64);
        if (reg_name == "XMM6_Bj") return maat::ir::Reg(maat::X64::ZMM6, 79, 72);
        if (reg_name == "XMM6_Bk") return maat::ir::Reg(maat::X64::ZMM6, 87, 80);
        if (reg_name == "XMM6_Bl") return maat::ir::Reg(maat::X64::ZMM6, 95, 88);
        if (reg_name == "XMM6_Bm") return maat::ir::Reg(maat::X64::ZMM6, 103, 96);
        if (reg_name == "XMM6_Bn") return maat::ir::Reg(maat::X64::ZMM6, 111, 104);
        if (reg_name == "XMM6_Bo") return maat::ir::Reg(maat::X64::ZMM6, 119, 112);
        if (reg_name == "XMM6_Bp") return maat::ir::Reg(maat::X64::ZMM6, 127, 120);
        if (reg_name == "XMM6_Wa") return maat::ir::Reg(maat::X64::ZMM6, 15, 0);
        if (reg_name == "XMM6_Wb") return maat::ir::Reg(maat::X64::ZMM6, 31, 16);
        if (reg_name == "XMM6_Wc") return maat::ir::Reg(maat::X64::ZMM6, 47, 32);
        if (reg_name == "XMM6_Wd") return maat::ir::Reg(maat::X64::ZMM6, 63, 48);
        if (reg_name == "XMM6_We") return maat::ir::Reg(maat::X64::ZMM6, 79, 64);
        if (reg_name == "XMM6_Wf") return maat::ir::Reg(maat::X64::ZMM6, 95, 80);
        if (reg_name == "XMM6_Wg") return maat::ir::Reg(maat::X64::ZMM6, 111, 96);
        if (reg_name == "XMM6_Wh") return maat::ir::Reg(maat::X64::ZMM6, 127, 112);
        
        if (reg_name == "ZMM7") return maat::ir::Reg(maat::X64::ZMM7, 512);
        if (reg_name == "YMM7") return maat::ir::Reg(maat::X64::ZMM7, 256);
        if (reg_name == "XMM7") return maat::ir::Reg(maat::X64::ZMM7, 128);
        if (reg_name == "XMM7_Qa") return maat::ir::Reg(maat::X64::ZMM7, 63, 0);
        if (reg_name == "XMM7_Qb") return maat::ir::Reg(maat::X64::ZMM7, 127, 64);
        if (reg_name == "XMM7_Da") return maat::ir::Reg(maat::X64::ZMM7, 31, 0);
        if (reg_name == "XMM7_Db") return maat::ir::Reg(maat::X64::ZMM7, 63, 32);
        if (reg_name == "XMM7_Dc") return maat::ir::Reg(maat::X64::ZMM7, 95, 64);
        if (reg_name == "XMM7_Dd") return maat::ir::Reg(maat::X64::ZMM7, 127, 96);
        if (reg_name == "XMM7_Ba") return maat::ir::Reg(maat::X64::ZMM7, 7, 0);
        if (reg_name == "XMM7_Bb") return maat::ir::Reg(maat::X64::ZMM7, 15, 8);
        if (reg_name == "XMM7_Bc") return maat::ir::Reg(maat::X64::ZMM7, 23, 16);
        if (reg_name == "XMM7_Bd") return maat::ir::Reg(maat::X64::ZMM7, 31, 24);
        if (reg_name == "XMM7_Be") return maat::ir::Reg(maat::X64::ZMM7, 39, 32);
        if (reg_name == "XMM7_Bf") return maat::ir::Reg(maat::X64::ZMM7, 47, 40);
        if (reg_name == "XMM7_Bg") return maat::ir::Reg(maat::X64::ZMM7, 55, 48);
        if (reg_name == "XMM7_Bh") return maat::ir::Reg(maat::X64::ZMM7, 63, 56);
        if (reg_name == "XMM7_Bi") return maat::ir::Reg(maat::X64::ZMM7, 71, 64);
        if (reg_name == "XMM7_Bj") return maat::ir::Reg(maat::X64::ZMM7, 79, 72);
        if (reg_name == "XMM7_Bk") return maat::ir::Reg(maat::X64::ZMM7, 87, 80);
        if (reg_name == "XMM7_Bl") return maat::ir::Reg(maat::X64::ZMM7, 95, 88);
        if (reg_name == "XMM7_Bm") return maat::ir::Reg(maat::X64::ZMM7, 103, 96);
        if (reg_name == "XMM7_Bn") return maat::ir::Reg(maat::X64::ZMM7, 111, 104);
        if (reg_name == "XMM7_Bo") return maat::ir::Reg(maat::X64::ZMM7, 119, 112);
        if (reg_name == "XMM7_Bp") return maat::ir::Reg(maat::X64::ZMM7, 127, 120);
        if (reg_name == "XMM7_Wa") return maat::ir::Reg(maat::X64::ZMM7, 15, 0);
        if (reg_name == "XMM7_Wb") return maat::ir::Reg(maat::X64::ZMM7, 31, 16);
        if (reg_name == "XMM7_Wc") return maat::ir::Reg(maat::X64::ZMM7, 47, 32);
        if (reg_name == "XMM7_Wd") return maat::ir::Reg(maat::X64::ZMM7, 63, 48);
        if (reg_name == "XMM7_We") return maat::ir::Reg(maat::X64::ZMM7, 79, 64);
        if (reg_name == "XMM7_Wf") return maat::ir::Reg(maat::X64::ZMM7, 95, 80);
        if (reg_name == "XMM7_Wg") return maat::ir::Reg(maat::X64::ZMM7, 111, 96);
        if (reg_name == "XMM7_Wh") return maat::ir::Reg(maat::X64::ZMM7, 127, 112);
    
        if (reg_name == "C0") return maat::ir::Reg(maat::X64::C0, 8);
        if (reg_name == "C1") return maat::ir::Reg(maat::X64::C1, 8);
        if (reg_name == "C2") return maat::ir::Reg(maat::X64::C2, 8);
        if (reg_name == "C3") return maat::ir::Reg(maat::X64::C3, 8);

        if (reg_name == "CR0") return maat::ir::Reg(maat::X64::CR0, 64);
        if (reg_name == "XCR0") return maat::ir::Reg(maat::X64::XCR0, 64);

        throw maat::runtime_exception(maat::Fmt()
                << "X64: Register translation from SLEIGH to MAAT missing for register "
                << reg_name
                >> maat::Fmt::to_str
              );
    }
    else
    {
        throw maat::runtime_exception("Register translation from SLEIGH to MAAT not implemented for this architecture!");
    }
}


std::shared_ptr<TranslationContext> new_sleigh_ctx(
    const std::string arch,
    const std::string& slafile,
    const std::string& pspecfile
)
{
    return std::make_shared<TranslationContext>(arch, slafile, pspecfile);
}

std::shared_ptr<maat::ir::Block> sleigh_translate(
    std::shared_ptr<TranslationContext> ctx,
    const unsigned char *bytes,
    unsigned int num_bytes,
    uintptr_t address,
    unsigned int max_instructions,
    bool bb_terminating
){
    return ctx->translate(
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
