#ifndef MAAT_ARCH_H
#define MAAT_ARCH_H

#include <cstdint>
#include <string>
#include "maat/types.hpp"
#include <vector>
#include <unordered_map>
#include "maat/serializer.hpp"

namespace maat
{

/** \defgroup arch Arch 
 * \brief Module regrouping classes and enums used to represent various
 * computer architectures. 
 * 
 * An architecture is represented by a class deriving from the *Arch* 
 * generic class. Each architecture has its own namespace which regroups
 * the specialised Arch class (X86::ArchX86, X64::ArchX64, ...) and static
 * variables for each available CPU register (X86::EAX, X64::RAX, ...)
 * */

/** \addtogroup arch
 * \{ */

/// Generic representation of a CPU register in Maat's engine
typedef uint16_t reg_t;

/// CPU modes
enum class CPUMode
{
    X86,   ///< Intel X86
    X64,   ///< Intel X86_64
    A32,   ///< ARM 32-bits
    T32,   ///< ARM Thumb
    A64,   ///< ARM 64-bits
    EVM,   ///< Ethereum byte-code
    RISCV, ///< RISCV
    NONE
};


/** \brief Base class representing an architecture.
 * 
 * It holds information such as
 * the size of the registers, the number of registers, and available CPU modes for 
 * architectures that can have several modes (like ARMv7)
*/
class Arch: public serial::Serializable
{
public:
    /// Architectures supported by Maat's engine 
    enum class Type
    {
        X86,   ///< Intel X86
        X64,   ///< Intel X86_64
        ARM32, // TODO ///< armv7 (32 bits)
        ARM64, // TODO ///< armv8 (64 bits)
        EVM,   ///< Ethereum byte-code
        RISCV, ///< RISCV
        NONE
    };

private: 
    const int _bits; ///< Size of the architecture in bits
protected:
    std::unordered_map<std::string, reg_t> reg_map; ///< name to reg mapping
public:
    const Arch::Type type; ///< Architecture identifier
    const int nb_regs; ///< Number of registers in this architecture
    std::vector<CPUMode> available_modes; ///< CPU modes available for the architecture
public:
    /** Constructor */
    Arch(Arch::Type type, int bits, int nb_regs): type(type), _bits(bits), nb_regs(nb_regs){};
    virtual ~Arch() = default;
    const std::string& reg_name(reg_t num) const; ///< Get name of register 'num'
    reg_t reg_num(const std::string& name) const; ///< Get num of register named 'name'
    virtual size_t reg_size(reg_t reg) const = 0; ///< Get size in bits of register 'reg'
    virtual reg_t sp() const = 0; ///< Stack pointer for this architecture
    virtual reg_t pc() const = 0; ///< Program counter for this architecture
    virtual reg_t tsc() const = 0; ///< Timestamp/Clock counter for this architecture
public:
    int bits() const; ///< Return the size of the architecture in bits
    int octets() const; ///< Return the size of the architecture in bytes/octets
public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

// A dummy implementation of an architecture, used for tests
class ArchNone: public Arch
{
public:
    ArchNone(): Arch(Arch::Type::NONE, 32, 20)
    {
        available_modes = {CPUMode::NONE};
    };
    virtual ~ArchNone() = default;
    size_t reg_size(reg_t reg_num) const {return 32;};
    reg_t sp() const {return 19;};
    reg_t pc() const {return 18;};
    reg_t tsc() const {return 17;};
};

/* ==================================================
 *                      Arch X86
 * ================================================= */

/// Namespace for X86-32 specific definitions and classes
namespace X86
{
    /* Registers */
    static constexpr reg_t EAX = 0; ///< General purpose register
    static constexpr reg_t EBX = 1; ///< General purpose register
    static constexpr reg_t ECX = 2; ///< General purpose register
    static constexpr reg_t EDX = 3; ///< General purpose register
    static constexpr reg_t EDI = 4; ///< General purpose register
    static constexpr reg_t ESI = 5; ///< General purpose register
    static constexpr reg_t EBP = 6; ///< Stack base
    static constexpr reg_t ESP = 7; ///< Stack pointer
    static constexpr reg_t EIP = 8; ///< Program counter
    /* Segment Registers */
    static constexpr reg_t CS = 9; ///< Segment register
    static constexpr reg_t DS = 10; ///< Segment register
    static constexpr reg_t ES = 11; ///< Segment register
    static constexpr reg_t FS = 12; ///< Segment register
    static constexpr reg_t GS = 13; ///< Segment register
    static constexpr reg_t SS = 14; ///< Segment register
    /* Flag Registers */
    static constexpr reg_t CF = 15; ///< Carry flag
    static constexpr reg_t PF = 16; ///< Parity flag
    static constexpr reg_t AF = 17; ///< Auxiliary carry flag
    static constexpr reg_t ZF = 18; ///< Zero flag
    static constexpr reg_t SF = 19; ///< Sign flag
    static constexpr reg_t TF = 20; ///< Trap flag
    static constexpr reg_t IF = 21; ///< Interrupt enable flag
    static constexpr reg_t DF = 22; ///< Direction flag
    static constexpr reg_t OF = 23; ///< Overflow flag
    static constexpr reg_t IOPL = 24; ///< I/O Priviledge level
    static constexpr reg_t NT = 25; ///< Nested task flag
    static constexpr reg_t RF = 26; ///< Resume flag
    static constexpr reg_t VM = 27; ///< Virtual 8086 mode flag
    static constexpr reg_t AC = 28; ///< Alignment check flag (486+)
    static constexpr reg_t VIF = 29; ///< Virutal interrupt flag
    static constexpr reg_t VIP = 30; ///< Virtual interrupt pending flag
    static constexpr reg_t ID = 31; ///< ID Flag
    static constexpr reg_t TSC = 32; ///< TImeSTamp counter
    /* MMX registers */
    static constexpr reg_t MM0 = 33; ///< MMX register
    static constexpr reg_t MM1 = 34; ///< MMX register
    static constexpr reg_t MM2 = 35; ///< MMX register
    static constexpr reg_t MM3 = 36; ///< MMX register
    static constexpr reg_t MM4 = 37; ///< MMX register
    static constexpr reg_t MM5 = 38; ///< MMX register
    static constexpr reg_t MM6 = 39; ///< MMX register
    static constexpr reg_t MM7 = 40; ///< MMX register
    /* ZMM, YMM, XMM registers */
    static constexpr reg_t ZMM0 = 41; ///< AVX register
    static constexpr reg_t ZMM1 = 42; ///< AVX register
    static constexpr reg_t ZMM2 = 43; ///< AVX register
    static constexpr reg_t ZMM3 = 44; ///< AVX register
    static constexpr reg_t ZMM4 = 45; ///< AVX register
    static constexpr reg_t ZMM5 = 46; ///< AVX register
    static constexpr reg_t ZMM6 = 47; ///< AVX register
    static constexpr reg_t ZMM7 = 48; ///< AVX register
    /* Control registers */
    static constexpr reg_t XCR0 = 49; ///< Extended control register
    static constexpr reg_t CR0 = 50; ///< Control register
    /* FPU registers */
    static constexpr reg_t FPUCW = 51; ///< FPU control word (16 bits)
    static constexpr reg_t C0 = 52; ///< FPU flag
    static constexpr reg_t C1 = 53; ///< FPU flag
    static constexpr reg_t C2 = 54; ///< FPU flag
    static constexpr reg_t C3 = 55; ///< FPU flag
    static constexpr reg_t FPUSW = 56; ///< FPU status word (16 bits)
    static constexpr reg_t FPUTW = 57; ///< FPU tag word (16 bits)
    static constexpr reg_t FPUIP = 58; ///< FPU instruction pointer
    static constexpr reg_t FPUDP = 59; ///< FPU data pointer
    static constexpr reg_t FPUOP = 60; ///< FPU tag word (11 bits)
    static constexpr reg_t FPUCS = 70; ///< FPU instruction pointer selector (16 bits)
    static constexpr reg_t FPUDS = 71; ///< FPU data selector (16 bits)
    static constexpr reg_t ST0 = 61;
    static constexpr reg_t ST1 = 62;
    static constexpr reg_t ST2 = 63;
    static constexpr reg_t ST3 = 64;
    static constexpr reg_t ST4 = 65;
    static constexpr reg_t ST5 = 66;
    static constexpr reg_t ST6 = 67;
    static constexpr reg_t ST7 = 68;
    static constexpr reg_t EFLAGS = 69;
    static constexpr reg_t NB_REGS = 72;

    /** \addtogroup arch
     * \{ */
    /// Intel X86-32 architecture
    class ArchX86: public Arch
    {
    public:
        ArchX86();
        virtual ~ArchX86() = default;
        size_t reg_size(reg_t reg_num) const;
        reg_t sp() const ;
        reg_t pc() const ;
        reg_t tsc() const ;
    };
    /** \} */ // Arch doxygen group

} // namespace x86


/// Namespace for X86-64 specific definitions and classes
namespace X64
{
    /* Registers */
    static constexpr reg_t RAX = 0; ///< General purpose register
    static constexpr reg_t RBX = 1; ///< General purpose register
    static constexpr reg_t RCX = 2; ///< General purpose register
    static constexpr reg_t RDX = 3; ///< General purpose register
    static constexpr reg_t RDI = 4; ///< General purpose register
    static constexpr reg_t RSI = 5; ///< General purpose register
    static constexpr reg_t RBP = 6; ///< Stack base
    static constexpr reg_t RSP = 7; ///< Stack pointer
    static constexpr reg_t RIP = 8; ///< Program counter
    static constexpr reg_t R8 = 9; ///< General purpose register
    static constexpr reg_t R9 = 10; ///< General purpose register
    static constexpr reg_t R10 = 11; ///< General purpose register
    static constexpr reg_t R11 = 12; ///< General purpose register
    static constexpr reg_t R12 = 13; ///< General purpose register
    static constexpr reg_t R13 = 14; ///< General purpose register
    static constexpr reg_t R14 = 15; ///< General purpose register
    static constexpr reg_t R15 = 16; ///< General purpose register
    /* Segment Registers */
    static constexpr reg_t CS = 17; ///< Segment register
    static constexpr reg_t DS = 18; ///< Segment register
    static constexpr reg_t ES = 19; ///< Segment register
    static constexpr reg_t FS = 20; ///< Segment register
    static constexpr reg_t GS = 21; ///< Segment register
    static constexpr reg_t SS = 22; ///< Segment register
    /* Flag Registers */
    static constexpr reg_t CF = 23; ///< Carry flag
    static constexpr reg_t PF = 24; ///< Parity flag
    static constexpr reg_t AF = 25; ///< Auxiliary carry flag
    static constexpr reg_t ZF = 26; ///< Zero flag
    static constexpr reg_t SF = 27; ///< Sign flag
    static constexpr reg_t TF = 28; ///< Trap flag
    static constexpr reg_t IF = 29; ///< Interrupt enable flag
    static constexpr reg_t DF = 30; ///< Direction flag
    static constexpr reg_t OF = 31; ///< Overflow flag
    static constexpr reg_t IOPL = 32; ///< I/O Priviledge level
    static constexpr reg_t NT = 33; ///< Nested task flag
    static constexpr reg_t RF = 34; ///< Resume flag
    static constexpr reg_t VM = 35; ///< Virtual 8086 mode flag
    static constexpr reg_t AC = 36; ///< Alignment check flag (486+)
    static constexpr reg_t VIF = 37; ///< Virutal interrupt flag
    static constexpr reg_t VIP = 38; ///< Virtual interrupt pending flag
    static constexpr reg_t ID = 39; ///< ID Flag
    static constexpr reg_t TSC = 40; ///< Timestamp counter
    /* MMX registers */
    static constexpr reg_t MM0 = 41; ///< MMX register
    static constexpr reg_t MM1 = 42; ///< MMX register
    static constexpr reg_t MM2 = 43; ///< MMX register
    static constexpr reg_t MM3 = 44; ///< MMX register
    static constexpr reg_t MM4 = 45; ///< MMX register
    static constexpr reg_t MM5 = 46; ///< MMX register
    static constexpr reg_t MM6 = 47; ///< MMX register
    static constexpr reg_t MM7 = 48; ///< MMX register
    /* ZMM, YMM, XMM registers */
    static constexpr reg_t ZMM0 = 49; ///< AVX register
    static constexpr reg_t ZMM1 = 50; ///< AVX register
    static constexpr reg_t ZMM2 = 51; ///< AVX register
    static constexpr reg_t ZMM3 = 52; ///< AVX register
    static constexpr reg_t ZMM4 = 53; ///< AVX register
    static constexpr reg_t ZMM5 = 54; ///< AVX register
    static constexpr reg_t ZMM6 = 55; ///< AVX register
    static constexpr reg_t ZMM7 = 56; ///< AVX register
    static constexpr reg_t ZMM8 = 79; ///< AVX register
    static constexpr reg_t ZMM9 = 80; ///< AVX register
    static constexpr reg_t ZMM10 = 81; ///< AVX register
    static constexpr reg_t ZMM11 = 82; ///< AVX register
    static constexpr reg_t ZMM12 = 83; ///< AVX register
    static constexpr reg_t ZMM13 = 84; ///< AVX register
    static constexpr reg_t ZMM14 = 85; ///< AVX register
    static constexpr reg_t ZMM15 = 86; ///< AVX register
    /* Control registers */
    static constexpr reg_t XCR0 = 57;
    static constexpr reg_t CR0 = 58;
    /* FPU registers */
    static constexpr reg_t C0 = 59; ///< FPU flag
    static constexpr reg_t C1 = 60; ///< FPU flag
    static constexpr reg_t C2 = 61; ///< FPU flag
    static constexpr reg_t C3 = 62; ///< FPU flag
    static constexpr reg_t FPUCW = 63; ///< FPU control word (16 bits)
    static constexpr reg_t FPUSW = 64; ///< FPU status word (16 bits)
    static constexpr reg_t FPUTW = 65; ///< FPU tag word (16 bits)
    static constexpr reg_t FPUIP = 66; ///< FPU instruction pointer
    static constexpr reg_t FPUDP = 67; ///< FPU data pointer
    static constexpr reg_t FPUOP = 68; ///< FPU tag word (11 bits)
    static constexpr reg_t FPUCS = 88; ///< FPU instruction pointer selector (16 bits)
    static constexpr reg_t FPUDS = 89; ///< FPU data selector (16 bits)
    // Shadow memory
    static constexpr reg_t SSP = 69; ///< Shadow stack pointer
    static constexpr reg_t MXCSR = 70; ///< SSE control register
    // FP Stack, experimental
    static constexpr reg_t ST0 = 71;
    static constexpr reg_t ST1 = 72;
    static constexpr reg_t ST2 = 73;
    static constexpr reg_t ST3 = 74;
    static constexpr reg_t ST4 = 75;
    static constexpr reg_t ST5 = 76;
    static constexpr reg_t ST6 = 77;
    static constexpr reg_t ST7 = 78;
    static constexpr reg_t RFLAGS = 87;
    static constexpr reg_t NB_REGS = 90;

    /** \addtogroup arch
     * \{ */

    /// Intel X86-64 architecture
    class ArchX64: public Arch
    {
    public:
        ArchX64();
        ~ArchX64() = default;
        size_t reg_size(reg_t reg_num) const ;
        reg_t sp() const ;
        reg_t pc() const ;
        reg_t tsc() const ;
    };

    /** \} */ // Arch doxygen group
} // namespace X64


/// Namespace for EVM specific definitions and classes
namespace EVM
{
    /* Registers */
    static constexpr reg_t PC = 0; ///< Program counter
    static constexpr reg_t NB_REGS = 1;

    /** \addtogroup arch
     * \{ */

    /// Ethereum Virtual Machine architecture
    class ArchEVM: public Arch
    {
    public:
        ArchEVM();
        ~ArchEVM() = default;
        size_t reg_size(reg_t reg_num) const;
        reg_t sp() const;
        reg_t pc() const;
        reg_t tsc() const;
    };

    /** \} */ // Arch doxygen group
} // namespace EVM


// TODO add to doxygen when ready
// Namespace for ARMv8 (64-bits) specific definitions and classes
namespace ARM64
{
    static constexpr reg_t R0 = 0;
    static constexpr reg_t R1 = 1;
    static constexpr reg_t R2 = 2;
    static constexpr reg_t R3 = 3;
    static constexpr reg_t R4 = 4;
    static constexpr reg_t R5 = 5;
    static constexpr reg_t R6 = 6;
    static constexpr reg_t R7 = 7;
    static constexpr reg_t R8 = 8;
    static constexpr reg_t R9 = 9;
    static constexpr reg_t R10 = 10;
    static constexpr reg_t R11 = 11;
    static constexpr reg_t R12 = 12;
    static constexpr reg_t R13 = 13;
    static constexpr reg_t R14 = 14;
    static constexpr reg_t R15 = 15;
    static constexpr reg_t R16 = 16;
    static constexpr reg_t R17 = 17;
    static constexpr reg_t R18 = 18;
    static constexpr reg_t R19 = 19;
    static constexpr reg_t R20 = 20;
    static constexpr reg_t R21 = 21;
    static constexpr reg_t R22 = 22;
    static constexpr reg_t R23 = 23;
    static constexpr reg_t R24 = 24;
    static constexpr reg_t R25 = 25;
    static constexpr reg_t R26 = 26;
    static constexpr reg_t R27 = 27;
    static constexpr reg_t R28 = 28;
    static constexpr reg_t R29 = 29;
    static constexpr reg_t R30 = 30;
    static constexpr reg_t LR = 30; // Same as R30
    static constexpr reg_t R31 = 31;
    static constexpr reg_t PC = 32;
    static constexpr reg_t SP = 33;
    static constexpr reg_t ZR = 34;
    static constexpr reg_t ZF = 35;
    static constexpr reg_t NF = 36;
    static constexpr reg_t CF = 37;
    static constexpr reg_t VF = 38;
    static constexpr reg_t CNTPCT_EL0 = 39; // Physical cycle counter
    static constexpr reg_t NB_REGS = 40;

     /** \addtogroup arch
     * \{ */
    class ArchARM64: public Arch
    {
    public:
        ArchARM64();
        virtual ~ArchARM64() = default;
        const std::string& reg_name(reg_t num) const;
        reg_t reg_num(const std::string& name) const;
        size_t reg_size(reg_t reg_num) const;
        reg_t sp() const;
        reg_t pc() const;
        reg_t tsc() const;
    };
    /** \} */ // Arch doxygen group

} // namespace ARM64

namespace ARM32
{
    static constexpr reg_t R0 = 0;
    static constexpr reg_t R1 = 1;
    static constexpr reg_t R2 = 2;
    static constexpr reg_t R3 = 3;
    static constexpr reg_t R4 = 4;
    static constexpr reg_t R5 = 5;
    static constexpr reg_t R6 = 6;
    static constexpr reg_t R7 = 7;
    static constexpr reg_t R8 = 8;
    static constexpr reg_t R9 = 9;
    static constexpr reg_t R10 = 10;
    static constexpr reg_t R11 = 11;
    static constexpr reg_t FP = 11; // Same as R11
    static constexpr reg_t R12 = 12;
    static constexpr reg_t IP = 12; // Same as R12
    static constexpr reg_t R13 = 13;
    static constexpr reg_t SP = 13; // Same as R13
    static constexpr reg_t R14 = 14;
    static constexpr reg_t LR = 14; // Same as R14
    static constexpr reg_t R15 = 15;
    static constexpr reg_t PC = 15; // Same as R15

    static constexpr reg_t CPSR = 16; // Current Program Status Register

    // CPSR bits; TODO: add other flags
    static constexpr reg_t NF = 17;
    static constexpr reg_t ZF = 18;
    static constexpr reg_t CF = 19;
    static constexpr reg_t VF = 20;
    static constexpr reg_t QF = 21;

    static constexpr reg_t NB_REGS = 22;

     /** \addtogroup arch
     * \{ */
    class ArchARM32: public Arch
    {
    public:
        ArchARM32();
        virtual ~ArchARM32() = default;
        const std::string& reg_name(reg_t num) const;
        reg_t reg_num(const std::string& name) const;
        size_t reg_size(reg_t reg_num) const;
        reg_t sp() const;
        reg_t pc() const;
        reg_t tsc() const;
    };
    /** \} */ // Arch doxygen group

} // namespace ARM32

namespace RISCV {
    static constexpr reg_t ZERO = 0;
    static constexpr reg_t RA = 1;
    static constexpr reg_t SP = 2;
    static constexpr reg_t GP = 3;
    static constexpr reg_t TP = 4;
    static constexpr reg_t T0 = 5;
    static constexpr reg_t T1 = 6;
    static constexpr reg_t T2 = 7;
    static constexpr reg_t S0 = 8;
    static constexpr reg_t FP = 8; // Same as S0
    static constexpr reg_t S1 = 9;
    static constexpr reg_t A0 = 10;
    static constexpr reg_t A1 = 11;
    static constexpr reg_t A2 = 12;
    static constexpr reg_t A3 = 13;
    static constexpr reg_t A4 = 14;
    static constexpr reg_t A5 = 15;
    static constexpr reg_t A6 = 16;
    static constexpr reg_t A7 = 17;
    static constexpr reg_t S2 = 18;
    static constexpr reg_t S3 = 19;
    static constexpr reg_t S4 = 20;
    static constexpr reg_t S5 = 21;
    static constexpr reg_t S6 = 22;
    static constexpr reg_t S7 = 23;
    static constexpr reg_t S8 = 24;
    static constexpr reg_t S9 = 25;
    static constexpr reg_t S10 = 26;
    static constexpr reg_t S11 = 27;
    static constexpr reg_t T3 = 28;
    static constexpr reg_t T4 = 29;
    static constexpr reg_t T5 = 30;
    static constexpr reg_t T6 = 31;

    static constexpr reg_t FT0 = 32;
    static constexpr reg_t FT1 = 33;
    static constexpr reg_t FT2 = 34;
    static constexpr reg_t FT3 = 35;
    static constexpr reg_t FT4 = 36;
    static constexpr reg_t FT5 = 37;
    static constexpr reg_t FT6 = 38;
    static constexpr reg_t FT7 = 39;
    static constexpr reg_t FS0 = 40;
    static constexpr reg_t FS1 = 41;
    static constexpr reg_t FA0 = 42;
    static constexpr reg_t FA1 = 43;
    static constexpr reg_t FA2 = 44;
    static constexpr reg_t FA3 = 45;
    static constexpr reg_t FA4 = 46;
    static constexpr reg_t FA5 = 47;
    static constexpr reg_t FA6 = 48;
    static constexpr reg_t FA7 = 49;
    static constexpr reg_t FS2 = 50;
    static constexpr reg_t FS3 = 51;
    static constexpr reg_t FS4 = 52;
    static constexpr reg_t FS5 = 53;
    static constexpr reg_t FS6 = 54;
    static constexpr reg_t FS7 = 55;
    static constexpr reg_t FS8 = 56;
    static constexpr reg_t FS9 = 57;
    static constexpr reg_t FS10 = 58;
    static constexpr reg_t FS11 = 59;
    static constexpr reg_t FT8 = 60;
    static constexpr reg_t FT9 = 61;
    static constexpr reg_t FT10 = 62;
    static constexpr reg_t FT11 = 63;

    static constexpr reg_t PC = 64;

    static constexpr reg_t NB_REGS = 65;

    /** \addtogroup arch
    * \{ */
   class ArchRISCV: public Arch
   {
   public:
       ArchRISCV();
       virtual ~ArchRISCV() = default;
       const std::string& reg_name(reg_t num) const;
       reg_t reg_num(const std::string& name) const;
       size_t reg_size(reg_t reg_num) const;
       reg_t sp() const;
       reg_t pc() const;
       reg_t tsc() const;
   };
   /** \} */ // Arch doxygen group

} // namespace RISCV

/** \} */ // Arch doxygen group

} // namespace maat

#endif
