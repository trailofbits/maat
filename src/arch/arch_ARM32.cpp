#include "maat/arch.hpp"
#include "maat/exception.hpp"
#include "maat/cpu.hpp"

namespace maat
{
namespace ARM32
{
    ArchARM32::ArchARM32(): Arch(Arch::Type::ARM32, 32, ARM32::NB_REGS)
    {
        available_modes = {CPUMode::A32,CPUMode::T32};
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
            {"fp", FP},
            {"ip", IP},
            {"sp", SP},
            {"lr", LR},
            {"pc", PC},
            {"cpsr", CPSR},
            {"nf", NF},
            {"zf", ZF},
            {"cf", CF},
            {"vf", VF},
            {"qf", QF},
            {"jf", JF},
            {"ge1", GE1},
            {"ge2", GE2},
            {"ge3", GE3},
            {"ge4", GE4},
            {"tf", TF},
            {"tmpNG", tmpNG},
            {"tmpZR", tmpZR},
            {"tmpCY", tmpCY},
            {"tmpOV", tmpOV},
            {"sc", SC},
            {"ISAModeSwitch", ISAModeSwitch} 
        };
    }

    size_t ArchARM32::reg_size(reg_t reg_num) const
    {
        switch (reg_num) {
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
            case CPSR:
            case mult_addr:
                return 32;
            case mult_dat8:
                return 64;
            case mult_dat16:
                return 128;
            case NF:
            case ZF:
            case CF:
            case VF:
            case QF:
            case JF:
            case GE1:
            case GE2:
            case GE3:
            case GE4:
            case TF:
            case tmpNG:
            case tmpZR:
            case tmpCY:
            case tmpOV:
            case SC:
            case ISAModeSwitch: 
                return 8;
            default:
                throw runtime_exception("ArchARM32::reg_size(): got unsupported reg num");
        }
    }

    reg_t ArchARM32::sp() const
    {
        return ARM32::SP;
    }

    reg_t ArchARM32::pc() const
    {
        return ARM32::PC;
    }

    reg_t ArchARM32::tsc() const
    {
        throw runtime_exception("ArchARM32::tsc(): method not available");
    }
} // namespace ARM32
} // namespace maat
