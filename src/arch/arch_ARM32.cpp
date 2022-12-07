#include "maat/arch.hpp"
#include "maat/exception.hpp"
#include "maat/cpu.hpp"

namespace maat
{
namespace ARM32
{
    ArchARM32::ArchARM32(): Arch(Arch::Type::ARM32, 32, ARM32::NB_REGS)
    {
        available_modes = {CPUMode::A32};
        reg_map =
        {
            {"R0", R0},
            {"R1", R1},
            {"R2", R2},
            {"R3", R3},
            {"R4", R4},
            {"R5", R5},
            {"R6", R6},
            {"R7", R7},
            {"R8", R8},
            {"R9", R9},
            {"R10", R10},
            {"R11", R11},
            {"R12", R12},
            {"R13", R13},
            {"R14", R14},
            {"R15", R15},

            {"FP", FP},
            {"IP", IP},
            {"SP", SP},
            {"LR", LR},
            {"PC", PC},

            {"CPSR", CPSR},

            {"NF", NF},
            {"ZF", ZF},
            {"CF", CF},
            {"VF", VF},
            {"QF", QF},

            {"JF", JF},
            {"GE1", GE1},
            {"GE2", GE2},
            {"GE3", GE3},
            {"GE4", GE4},
            {"TF", TF},

            {"tmpNG", tmpNG},
            {"tmpZR", tmpZR},
            {"tmpCY", tmpCY},
            {"tmpOV", tmpOV},
            {"SC", SC}  //shift_carry
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
                return 32;

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
} // namespace RISCV

} // namespace maat
