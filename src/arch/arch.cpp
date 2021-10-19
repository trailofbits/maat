#include "arch.hpp"
#include "exception.hpp"

namespace maat
{
    
int Arch::bits() const
{
    return _bits;
}

int Arch::octets() const
{
    return _bits/8;
}

namespace X86
{
    
    // Register names
    const std::string EAX_str = "eax";
    const std::string EBX_str = "ebx";
    const std::string ECX_str = "ecx";
    const std::string EDX_str = "edx";
    const std::string EDI_str = "edi";
    const std::string ESI_str = "esi";
    const std::string EBP_str = "ebp";
    const std::string ESP_str = "esp";
    const std::string EIP_str = "eip";
    const std::string CS_str = "cs";
    const std::string DS_str = "ds";
    const std::string ES_str = "es";
    const std::string FS_str = "fs";
    const std::string GS_str = "gs";
    const std::string SS_str = "ss";
    const std::string CF_str = "cf";
    const std::string PF_str = "pf";
    const std::string AF_str = "af";
    const std::string ZF_str = "zf";
    const std::string SF_str = "sf";
    const std::string TF_str = "tf";
    const std::string IF_str = "if";
    const std::string DF_str = "df";
    const std::string OF_str = "of";
    const std::string IOPL_str = "iopl";
    const std::string VM_str = "vm";
    const std::string NT_str = "nt";
    const std::string RF_str = "rf";
    const std::string AC_str = "ac";
    const std::string VIP_str = "vip";
    const std::string VIF_str = "vif";
    const std::string ID_str = "id";
    const std::string TSC_str = "tsc";
    const std::string MM0_str = "mm0";
    const std::string MM1_str = "mm1";
    const std::string MM2_str = "mm2";
    const std::string MM3_str = "mm3";
    const std::string MM4_str = "mm4";
    const std::string MM5_str = "mm5";
    const std::string MM6_str = "mm6";
    const std::string MM7_str = "mm7";
    const std::string ZMM0_str = "zmm0";
    const std::string ZMM1_str = "zmm1";
    const std::string ZMM2_str = "zmm2";
    const std::string ZMM3_str = "zmm3";
    const std::string ZMM4_str = "zmm4";
    const std::string ZMM5_str = "zmm5";
    const std::string ZMM6_str = "zmm6";
    const std::string ZMM7_str = "zmm7";
    const std::string XCR0_str = "xcr0";
    const std::string FPUCW_str = "fpucw";
    const std::string C0_str = "c0";
    const std::string C1_str = "c1";
    const std::string C2_str = "c2";
    const std::string C3_str = "c3";

    
    ArchX86::ArchX86(): Arch(Arch::Type::X86, 32, X86::NB_REGS)
    {
        available_modes = {CPUMode::X86};
    }

    const std::string& ArchX86::reg_name(reg_t num) const 
    {
        switch(num)
        {
            case EAX: return EAX_str;
            case EBX: return EBX_str;
            case ECX: return ECX_str;
            case EDX: return EDX_str;
            case EDI: return EDI_str;
            case ESI: return ESI_str;
            case EBP: return EBP_str;
            case ESP: return ESP_str;
            case EIP: return EIP_str;
            case CS: return CS_str;
            case DS: return DS_str;
            case ES: return ES_str;
            case FS: return FS_str;
            case GS: return GS_str;
            case SS: return SS_str;
            case CF: return CF_str;
            case PF: return PF_str;
            case AF: return AF_str;
            case ZF: return ZF_str;
            case SF: return SF_str;
            case TF: return TF_str;
            case IF: return IF_str;
            case DF: return DF_str;
            case OF: return OF_str;
            case IOPL: return IOPL_str;
            case VM: return VM_str;
            case NT: return NT_str;
            case RF: return RF_str;
            case AC: return AC_str;
            case VIP: return VIP_str;
            case VIF: return VIF_str;
            case ID: return ID_str;
            case TSC: return TSC_str;
            case MM0: return MM0_str;
            case MM1: return MM1_str;
            case MM2: return MM2_str;
            case MM3: return MM3_str;
            case MM4: return MM4_str;
            case MM5: return MM5_str;
            case MM6: return MM6_str;
            case MM7: return MM7_str;
            case ZMM0: return ZMM0_str;
            case ZMM1: return ZMM1_str;
            case ZMM2: return ZMM2_str;
            case ZMM3: return ZMM3_str;
            case ZMM4: return ZMM4_str;
            case ZMM5: return ZMM5_str;
            case ZMM6: return ZMM6_str;
            case ZMM7: return ZMM7_str;
            case XCR0: return XCR0_str;
            case FPUCW: return FPUCW_str;
            case C0: return C0_str;
            case C1: return C1_str;
            case C2: return C2_str;
            case C3: return C3_str;
            default:
                throw runtime_exception(Fmt()
                    << "ArchX86::reg_name() got unknown reg num: "
                    << num
                    >> Fmt::to_str
                );
        }

    }

    reg_t ArchX86::reg_num(const std::string& name) const 
    {
        if( name == EAX_str) return EAX;
        else if( name == EBX_str) return EBX;
        else if( name == ECX_str) return ECX;
        else if( name == EDX_str) return EDX;
        else if( name == EDI_str) return EDI;
        else if( name == ESI_str) return ESI;
        else if( name == EBP_str) return EBP;
        else if( name == ESP_str) return ESP;
        else if( name == EIP_str) return EIP;
        else if( name == CS_str) return CS;
        else if( name == DS_str) return DS;
        else if( name == ES_str) return ES;
        else if( name == FS_str) return FS;
        else if( name == GS_str) return GS;
        else if( name == SS_str) return SS;
        else if( name == CF_str) return CF;
        else if( name == PF_str) return PF;
        else if( name == AF_str) return AF;
        else if( name == ZF_str) return ZF;
        else if( name == SF_str) return SF;
        else if( name == TF_str) return TF;
        else if( name == IF_str) return IF;
        else if( name == DF_str) return DF;
        else if( name == OF_str) return OF;
        else if( name == IOPL_str) return IOPL;
        else if( name == VM_str) return VM;
        else if( name == NT_str) return NT;
        else if( name == RF_str) return RF;
        else if( name == AC_str) return AC;
        else if( name == VIP_str) return VIP;
        else if( name == VIF_str) return VIF;
        else if( name == ID_str) return ID;
        else if( name == TSC_str) return TSC;
        else if( name == MM0_str) return MM0;
        else if( name == MM1_str) return MM1;
        else if( name == MM2_str) return MM2;
        else if( name == MM3_str) return MM3;
        else if( name == MM4_str) return MM4;
        else if( name == MM5_str) return MM5;
        else if( name == MM6_str) return MM6;
        else if( name == MM7_str) return MM7;
        else if( name == ZMM0_str) return ZMM0;
        else if( name == ZMM1_str) return ZMM1;
        else if( name == ZMM2_str) return ZMM2;
        else if( name == ZMM3_str) return ZMM3;
        else if( name == ZMM4_str) return ZMM4;
        else if( name == ZMM5_str) return ZMM5;
        else if( name == ZMM6_str) return ZMM6;
        else if( name == ZMM7_str) return ZMM7;
        else if( name == XCR0_str) return XCR0;
        else if( name == FPUCW_str) return FPUCW;
        else if( name == C0_str) return C0;
        else if( name == C1_str) return C1;
        else if( name == C2_str) return C2;
        else if( name == C3_str) return C3;
        else 
            throw runtime_exception(Fmt ()
                    << "ArchX86::reg_num() got unknown reg name: " << name
                    >> Fmt::to_str
                  );
    }
    
    size_t ArchX86::reg_size(reg_t reg_num) const 
    {
        switch (reg_num)
        {
            case EAX:
            case EBX:
            case ECX:
            case EDX:
            case EDI:
            case ESI:
            case EBP:
            case ESP:
            case EIP:
            case CS:
            case DS:
            case ES:
            case FS:
            case GS:
            case SS:
                return 32;
            case CF:
            case PF:
            case AF:
            case ZF: 
            case SF:
            case TF:
            case IF:
            case DF:
            case OF:
            case IOPL:
            case VM:
            case NT:
            case RF:
            case AC:
            case VIP:
            case VIF:
            case ID: 
            case C0:
            case C1:
            case C2:
            case C3:
                return 8; // In sleigh/pcode, boolean flags are represented as bytes
            case TSC:
            case MM0:
            case MM1:
            case MM2:
            case MM3:
            case MM4:
            case MM5:
            case MM6:
            case MM7:
                return 64;
            case ZMM0:
            case ZMM1:
            case ZMM2:
            case ZMM3:
            case ZMM4:
            case ZMM5:
            case ZMM6:
            case ZMM7:
                return 512;
            case XCR0:
                return 64;
            case FPUCW:
                return 16;
            default:
                throw runtime_exception("ArchX86::reg_size(): got unsupported reg num");
        }
    }

    reg_t ArchX86::sp() const 
    {
        return X86::ESP;
    }

    reg_t ArchX86::pc() const 
    {
        return X86::EIP;
    }

    reg_t ArchX86::tsc() const 
    {
        return X86::TSC;
    }
} // namespace X86
    
    
    
namespace X64
{
    
    // Register names
    const std::string RAX_str = "rax";
    const std::string RBX_str = "rbx";
    const std::string RCX_str = "rcx";
    const std::string RDX_str = "rdx";
    const std::string RDI_str = "rdi";
    const std::string RSI_str = "rsi";
    const std::string RBP_str = "rbp";
    const std::string RSP_str = "rsp";
    const std::string RIP_str = "rip";
    const std::string R8_str = "r8";
    const std::string R9_str = "r9";
    const std::string R10_str = "r10";
    const std::string R11_str = "r11";
    const std::string R12_str = "r12";
    const std::string R13_str = "r13";
    const std::string R14_str = "r14";
    const std::string R15_str = "r15";
    const std::string CS_str = "cs";
    const std::string DS_str = "ds";
    const std::string ES_str = "es";
    const std::string FS_str = "fs";
    const std::string GS_str = "gs";
    const std::string SS_str = "ss";
    const std::string CF_str = "cf";
    const std::string PF_str = "pf";
    const std::string AF_str = "af";
    const std::string ZF_str = "zf";
    const std::string SF_str = "sf";
    const std::string TF_str = "tf";
    const std::string IF_str = "if";
    const std::string DF_str = "df";
    const std::string OF_str = "of";
    const std::string IOPL_str = "iopl";
    const std::string VM_str = "vm";
    const std::string NT_str = "nt";
    const std::string RF_str = "rf";
    const std::string AC_str = "ac";
    const std::string VIP_str = "vip";
    const std::string VIF_str = "vif";
    const std::string ID_str = "id";
    const std::string TSC_str = "tsc";
    const std::string MM0_str = "mm0";
    const std::string MM1_str = "mm1";
    const std::string MM2_str = "mm2";
    const std::string MM3_str = "mm3";
    const std::string MM4_str = "mm4";
    const std::string MM5_str = "mm5";
    const std::string MM6_str = "mm6";
    const std::string MM7_str = "mm7";
    const std::string ZMM0_str = "zmm0";
    const std::string ZMM1_str = "zmm1";
    const std::string ZMM2_str = "zmm2";
    const std::string ZMM3_str = "zmm3";
    const std::string ZMM4_str = "zmm4";
    const std::string ZMM5_str = "zmm5";
    const std::string ZMM6_str = "zmm6";
    const std::string ZMM7_str = "zmm7";
    const std::string XCR0_str = "xcr0";
    const std::string FPUCW_str = "fpucw";
    const std::string C0_str = "c0";
    const std::string C1_str = "c1";
    const std::string C2_str = "c2";
    const std::string C3_str = "c3";

    
    ArchX64::ArchX64(): Arch(Arch::Type::X64, 64, X64::NB_REGS)
    {
        available_modes = {CPUMode::X64};
    }

    const std::string& ArchX64::reg_name(reg_t num) const 
    {
        switch(num)
        {
            case RAX: return RAX_str;
            case RBX: return RBX_str;
            case RCX: return RCX_str;
            case RDX: return RDX_str;
            case RDI: return RDI_str;
            case RSI: return RSI_str;
            case RBP: return RBP_str;
            case RSP: return RSP_str;
            case RIP: return RIP_str;
            case R8: return R8_str;
            case R9: return R9_str;
            case R10: return R10_str;
            case R11: return R11_str;
            case R12: return R12_str;
            case R13: return R13_str;
            case R14: return R14_str;
            case R15: return R15_str;
            case CS: return CS_str;
            case DS: return DS_str;
            case ES: return ES_str;
            case FS: return FS_str;
            case GS: return GS_str;
            case SS: return SS_str;
            case CF: return CF_str;
            case PF: return PF_str;
            case AF: return AF_str;
            case ZF: return ZF_str;
            case SF: return SF_str;
            case TF: return TF_str;
            case IF: return IF_str;
            case DF: return DF_str;
            case OF: return OF_str;
            case IOPL: return IOPL_str;
            case VM: return VM_str;
            case NT: return NT_str;
            case RF: return RF_str;
            case AC: return AC_str;
            case VIP: return VIP_str;
            case VIF: return VIF_str;
            case ID: return ID_str;
            case TSC: return TSC_str;
            case MM0: return MM0_str;
            case MM1: return MM1_str;
            case MM2: return MM2_str;
            case MM3: return MM3_str;
            case MM4: return MM4_str;
            case MM5: return MM5_str;
            case MM6: return MM6_str;
            case MM7: return MM7_str;
            case ZMM0: return ZMM0_str;
            case ZMM1: return ZMM1_str;
            case ZMM2: return ZMM2_str;
            case ZMM3: return ZMM3_str;
            case ZMM4: return ZMM4_str;
            case ZMM5: return ZMM5_str;
            case ZMM6: return ZMM6_str;
            case ZMM7: return ZMM7_str;
            case XCR0: return XCR0_str;
            case FPUCW: return FPUCW_str;
            case C0: return C0_str;
            case C1: return C1_str;
            case C2: return C2_str;
            case C3: return C3_str;
            default:
                throw runtime_exception(
                    Fmt() << "ArchX64::reg_name() got unknown reg num: "
                    << num
                    >> Fmt::to_str
                );
        }
    }

    reg_t ArchX64::reg_num(const std::string& name) const 
    {
        if( name == RAX_str) return RAX;
        else if( name == RBX_str) return RBX;
        else if( name == RCX_str) return RCX;
        else if( name == RDX_str) return RDX;
        else if( name == RDI_str) return RDI;
        else if( name == RSI_str) return RSI;
        else if( name == RBP_str) return RBP;
        else if( name == RSP_str) return RSP;
        else if( name == RIP_str) return RIP;
        else if( name == R8_str) return R8;
        else if( name == R9_str) return R9;
        else if( name == R10_str) return R10;
        else if( name == R11_str) return R11;
        else if( name == R12_str) return R12;
        else if( name == R13_str) return R13;
        else if( name == R14_str) return R14;
        else if( name == R15_str) return R15;
        else if( name == CS_str) return CS;
        else if( name == DS_str) return DS;
        else if( name == ES_str) return ES;
        else if( name == FS_str) return FS;
        else if( name == GS_str) return GS;
        else if( name == SS_str) return SS;
        else if( name == CF_str) return CF;
        else if( name == PF_str) return PF;
        else if( name == AF_str) return AF;
        else if( name == ZF_str) return ZF;
        else if( name == SF_str) return SF;
        else if( name == TF_str) return TF;
        else if( name == IF_str) return IF;
        else if( name == DF_str) return DF;
        else if( name == OF_str) return OF;
        else if( name == IOPL_str) return IOPL;
        else if( name == VM_str) return VM;
        else if( name == NT_str) return NT;
        else if( name == RF_str) return RF;
        else if( name == AC_str) return AC;
        else if( name == VIP_str) return VIP;
        else if( name == VIF_str) return VIF;
        else if( name == ID_str) return ID;
        else if( name == TSC_str) return TSC;
        else if( name == MM0_str) return MM0;
        else if( name == MM1_str) return MM1;
        else if( name == MM2_str) return MM2;
        else if( name == MM3_str) return MM3;
        else if( name == MM4_str) return MM4;
        else if( name == MM5_str) return MM5;
        else if( name == MM6_str) return MM6;
        else if( name == MM7_str) return MM7;
        else if( name == ZMM0_str) return ZMM0;
        else if( name == ZMM1_str) return ZMM1;
        else if( name == ZMM2_str) return ZMM2;
        else if( name == ZMM3_str) return ZMM3;
        else if( name == ZMM4_str) return ZMM4;
        else if( name == ZMM5_str) return ZMM5;
        else if( name == ZMM6_str) return ZMM6;
        else if( name == ZMM7_str) return ZMM7;
        else if( name == XCR0_str) return XCR0;
        else if( name == FPUCW_str) return FPUCW;
        else if( name == C0_str) return C0;
        else if( name == C1_str) return C1;
        else if( name == C2_str) return C2;
        else if( name == C3_str) return C3;
        else 
            throw runtime_exception(Fmt ()
                    << "ArchX64::reg_num() got unknown reg name: " << name
                    >> Fmt::to_str
                  );
    }
    
    size_t ArchX64::reg_size(reg_t reg_num) const 
    {
        switch (reg_num)
        {
            case RAX:
            case RBX:
            case RCX:
            case RDX:
            case RDI:
            case RSI:
            case RBP:
            case RSP:
            case RIP:
            case R8:
            case R9:
            case R10:
            case R11:
            case R12:
            case R13:
            case R14:
            case R15:
            case CS:
            case DS:
            case ES:
            case FS:
            case GS:
            case SS:
                return 64;
            case CF:
            case PF:
            case AF:
            case ZF: 
            case SF:
            case TF:
            case IF:
            case DF:
            case OF:
            case IOPL:
            case VM:
            case NT:
            case RF:
            case AC:
            case VIP:
            case VIF:
            case ID: 
            case C0:
            case C1:
            case C2:
            case C3:
                return 8; // In sleigh/pcode, boolean flags are represented as bytes
            case TSC:
            case MM0:
            case MM1:
            case MM2:
            case MM3:
            case MM4:
            case MM5:
            case MM6:
            case MM7:
                return 64;
            case ZMM0:
            case ZMM1:
            case ZMM2:
            case ZMM3:
            case ZMM4:
            case ZMM5:
            case ZMM6:
            case ZMM7:
                return 512;
            case XCR0:
                return 64;
            case FPUCW:
                return 16;
            default:
                throw runtime_exception("ArchX64::reg_size(): got unsupported reg num");
        }
    }

    reg_t ArchX64::sp() const 
    {
        return X64::RSP;
    }

    reg_t ArchX64::pc() const 
    {
        return X64::RIP;
    }

    reg_t ArchX64::tsc() const 
    {
        return X64::TSC;
    }
} // namespace X64
    
} // namespace maat

