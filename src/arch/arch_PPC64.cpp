#include "maat/arch.hpp"
#include "maat/exception.hpp"
#include "maat/cpu.hpp"

namespace maat
{

namespace PPC64
{
    ArchPPC64::ArchPPC64(): Arch(Arch::Type::PPC64, 64, PPC64::NB_REGS)
    {
        available_modes = {CPUMode::PPC64};
        reg_map =
        {
            {"r0", R0},
            {"r1", R1},
            {"r2", R2},
            {"r3", R3},
            {"r4", R4},
            {"r5", R5},
            {"r6", R6},
            {"r7", R7},
            {"r8", R8},
            {"r9", R9},
            {"r10", R10},
            {"r11", R11},
            {"r12", R12},
            {"r13", R13},
            {"r14", R14},
            {"r15", R15},
            {"r16", R16},
            {"r17", R17},
            {"r18", R18},
            {"r19", R19},
            {"r20", R20},
            {"r21", R21},
            {"r22", R22},
            {"r23", R23},
            {"r24", R24},
            {"r25", R25},
            {"r26", R26},
            {"r27", R27},
            {"r28", R28},
            {"r29", R29},
            {"r30", R30},
            {"r31", R31},
            {"f0", F0},
            {"f1", F1},
            {"f2", F2},
            {"f3", F3},
            {"f4", F4},
            {"f5", F5},
            {"f6", F6},
            {"f7", F7},
            {"f8", F8},
            {"f9", F9},
            {"f10", F10},
            {"f11", F11},
            {"f12", F12},
            {"f13", F13},
            {"f14", F14},
            {"f15", F15},
            {"f16", F16},
            {"f17", F17},
            {"f18", F18},
            {"f19", F19},
            {"f20", F20},
            {"f21", F21},
            {"f22", F22},
            {"f23", F23},
            {"f24", F24},
            {"f25", F25},
            {"f26", F26},
            {"f27", F27},
            {"f28", F28},
            {"f29", F29},
            {"f30", F30},
            {"f31", F31},
            {"pc", PC},
            {"sp", SP},
            {"cr", CR},
            {"lr", LR},
            {"ctr", CTR},
            {"xer",XER},
            {"cr0",CR0},
            {"cr1",CR1},
            {"cr2",CR2},
            {"cr3",CR3},
            {"cr4",CR4},
            {"cr5",CR5},
            {"cr6",CR6},
            {"cr7",CR7},
            {"xer_so",XER_SO},
            {"xer_ov",XER_OV},
            {"xer_ca",XER_CA},
            {"tbl",TBL},
            {"tbu",TBU},
            {"fpscr",FPSCR},
            {"fx",FX},
            {"fex",FEX},
            {"vx",VX},
            {"ox",OX},
            {"ux",UX},
            {"zx",ZX},
            {"xx",XX},
            {"vxsnan",VXSNAN},
            {"vxisi",VXISI},
            {"vxidi",VXIDI},
            {"vxzdz",VXZDZ},
            {"vximz",VXIMZ},
            {"vxvc",VXVC},
            {"fr",FR},
            {"fi",FI},
            {"fprf",FPRF},
            {"vxsoft",VXSOFT},
            {"vxsqrt",VXSQRT},
            {"vxcvi",VXCVI},
            {"ve",VE},
            {"oe",OE},
            {"ue",UE},
            {"ze",ZE},
            {"xe",XE},
            {"ni",NI},
            {"rn",RN},
            {"msr",MSR},
            {"pvr",PVR},
            {"r2save",R2SAVE},
            {"reserve",RESERVE}
        };
    }
    size_t ArchPPC64::reg_size(reg_t reg_num) const 
    {
        switch (reg_num)
        {
            case R0:
            case R1:
            case R2:
            case R3:
            case R4:
            case R5:
            case R6:
            case R7:
            case R8:
            case R9:
            case R10:
            case R11:
            case R12:
            case R13:
            case R14:
            case R15:
            case R16:
            case R17:
            case R18:
            case R19:
            case R20:
            case R21:
            case R22:
            case R23:
            case R24:
            case R25:
            case R26:
            case R27:
            case R28:
            case R29:
            case R30:
            case R31:
            case F0:
            case F1:
            case F2:
            case F3:
            case F4:
            case F5:
            case F6:
            case F7:
            case F8:
            case F9:
            case F10:
            case F11:
            case F12:
            case F13:
            case F14:
            case F15:
            case F16:
            case F17:
            case F18:
            case F19:
            case F20:
            case F21:
            case F22:
            case F23:
            case F24:
            case F25:
            case F26:
            case F27:
            case F28:
            case F29:
            case F30:
            case F31:
                return 64;
            case CR:
            case XER:
                return 32;
            case PC:
            case LR:
            case MSR:
            case CTR:
            case R2SAVE:
                return 64;
            case CR0:
            case CR1:
            case CR2:
            case CR3:
            case CR4:
            case CR5:
            case CR6:
            case CR7:
            case XER_SO:
            case XER_OV:
            case XER_CA:
                return 8;
            case TBL:
            case TBU:
            case FPSCR:
            case PVR:
            case RESERVE:
                return 32;
            case FX:
            case FEX:
            case VX:
            case OX:
            case UX:
            case ZX:
            case XX:
            case VXSNAN:
            case VXISI:
            case VXIDI:
            case VXZDZ:
            case VXIMZ:
            case VXVC:
            case FR:
            case FI:
            case FPRF:
            case VXSOFT:
            case VXSQRT:
            case VXCVI:
            case VE:
            case OE:
            case UE:
            case ZE:
            case XE:
            case NI:
            case RN:
                return 8;
            default:
                throw runtime_exception("ArchPPC64::reg_size(): got unsupported reg num");
        }
    }

    reg_t ArchPPC64::sp() const
    {
        return PPC64::R1;
    }
    
    reg_t ArchPPC64::pc() const
    {
        return PPC64::PC;
    }

    reg_t ArchPPC64::tsc() const
    {
        throw runtime_exception("ArchPPC64::tsc(): method not available");
    }

} // namespace PPC64
} // namespace maat