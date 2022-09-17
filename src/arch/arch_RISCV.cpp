#include "maat/arch.hpp"
#include "maat/exception.hpp"
#include "maat/cpu.hpp"

namespace maat
{
namespace RISCV
{
    ArchRISCV::ArchRISCV(): Arch(Arch::Type::RISCV, 64, RISCV::NB_REGS)
    {
        available_modes = {CPUMode::RISCV};
        reg_map =
        {
            {"zero", ZERO},
            {"ra", RA},
            {"sp", SP},
            {"gp", GP},
            {"tp", TP},
            {"t0", T0},
            {"t1", T1},
            {"t2", T2},
            {"s0", S0},
            {"fp", FP},
            {"s1", S1},
            {"a0", A0},
            {"a1", A1},
            {"a2", A2},
            {"a3", A3},
            {"a4", A4},
            {"a5", A5},
            {"a6", A6},
            {"a7", A7},
            {"s2", S2},
            {"s3", S3},
            {"s4", S4},
            {"s5", S5},
            {"s6", S6},
            {"s7", S7},
            {"s8", S8},
            {"s9", S9},
            {"s10", S10},
            {"s11", S11},
            {"t3", T3},
            {"t4", T4},
            {"t5", T5},
            {"t6", T6},

            {"ft0", FT0},
            {"ft1", FT1},
            {"ft2", FT2},
            {"ft3", FT3},
            {"ft4", FT4},
            {"ft5", FT5},
            {"ft6", FT6},
            {"ft7", FT7},
            {"fs0", FS0},
            {"fs1", FS1},
            {"fa0", FA0},
            {"fa1", FA1},
            {"fa2", FA2},
            {"fa3", FA3},
            {"fa4", FA4},
            {"fa5", FA5},
            {"fa6", FA6},
            {"fa7", FA7},
            {"fs2", FS2},
            {"fs3", FS3},
            {"fs4", FS4},
            {"fs5", FS5},
            {"fs6", FS6},
            {"fs7", FS7},
            {"fs8", FS8},
            {"fs9", FS9},
            {"fs10", FS10},
            {"fs11", FS11},
            {"ft8", FT8},
            {"ft9", FT9},
            {"ft10", FT10},
            {"ft11", FT11},

            {"pc", PC}
        };
    }

    size_t ArchRISCV::reg_size(reg_t reg_num) const
    {
        return 64;
    }

    reg_t ArchRISCV::sp() const
    {
        return RISCV::SP;
    }

    reg_t ArchRISCV::pc() const
    {
        return RISCV::PC;
    }

    reg_t ArchRISCV::tsc() const
    {
        throw runtime_exception("ArchRISCV::tsc(): method not available");
    }
} // namespace RISCV

} // namespace maat
