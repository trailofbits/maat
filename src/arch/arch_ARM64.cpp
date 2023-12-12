/*
Commonwealth of Australia represented by the Department of Defence

Produced by Nathan Do, Student Intern at DSTG (Defence Science and Technology Group)
*/

#include "maat/arch.hpp"
#include "maat/exception.hpp"
#include "maat/cpu.hpp"

namespace maat
{
namespace ARM64
{
    ArchARM64::ArchARM64(): Arch(Arch::Type::ARM64, 64, ARM64::NB_REGS)
    {
        available_modes = {CPUMode::A64};
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
            {"lr", LR},
            {"v0", V0},
            {"v1", V1},
            {"v2", V2},
            {"v3", V3},
            {"v4", V4},
            {"v5", V5},
            {"v6", V6},
            {"v7", V7},
            {"v8", V8},
            {"v9", V9},
            {"v10", V10},
            {"v11", V11},
            {"v12", V12},
            {"v13", V13},
            {"v14", V14},
            {"v15", V15},
            {"v16", V16},
            {"v17", V17},
            {"v18", V18},
            {"v19", V19},
            {"v20", V20},
            {"v21", V21},
            {"v22", V22},
            {"v23", V23},
            {"v24", V24},
            {"v25", V25},
            {"v26", V26},
            {"v27", V27},
            {"v28", V28},
            {"v29", V29},
            {"v30", V30},
            {"v31", V31},
            {"zr", ZR},
            {"pc", PC},
            {"sp", SP},
            {"pstate",PSTATE},
            {"zf", ZF},
            {"nf", NF},
            {"cf", CF},
            {"vf", VF},
            {"cntpct_el0", CNTPCT_EL0}
        };
    }

    size_t ArchARM64::reg_size(reg_t reg_num) const
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
            case ZR:
            case PC:
            case SP:
            case PSTATE:
            case SPSR:
            case ELR:
            case CNTPCT_EL0:
                return 64;
            case V0:
            case V1:
            case V2:
            case V3:
            case V4:
            case V5:
            case V6:
            case V7:
            case V8:
            case V9:
            case V10:
            case V11:
            case V12:
            case V13:
            case V14:
            case V15:
            case V16:
            case V17:
            case V18:
            case V19:
            case V20:
            case V21:
            case V22:
            case V23:
            case V24:
            case V25:
            case V26:
            case V27:
            case V28:
            case V29:
            case V30:
            case V31:
                return 128;
            case ZF:
            case NF:
            case CF:
            case VF:
                return 8;
            default:
                throw runtime_exception("ArchARM64::reg_size(): got unsupported reg num");
        }
    }

    reg_t ArchARM64::sp() const
    {
        return ARM64::SP;
    }

    reg_t ArchARM64::pc() const
    {
        return ARM64::PC;
    }

    reg_t ArchARM64::tsc() const
    {
        throw runtime_exception("ArchARM64::tsc(): method not available");
    }
} // namespace RISCV

} // namespace maat
