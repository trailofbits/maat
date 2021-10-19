#ifndef MAAT_LIFTER_H
#define MAAT_LIFTER_H

#include <cstdint>
#include <vector>
#include <utility>
#include <memory>
#include <unordered_map>
#include "ir.hpp"
#include "sleigh_interface.hpp"

namespace maat
{

/** \addtogroup ir
 * \{ */

/** \typedef code_t 
 * A raw pointer to binary executable code */
typedef uint8_t* code_t;


/** \brief The lifter is responsible for translating binary assembly code into Maat's IR */
class Lifter
{
public:
    virtual ~Lifter();
    /** \brief Disassemble instructions until next branch instruction.
     * 
     *  @param addr Address of the first instruction to disassemble 
     *  @param code Raw pointer to the code to disassemble 
     *  @param code_size Max size of the code region to disassemble in memory
     *  @param nb_instr Max number of instructions to disassemble before stopping
     *  @param is_symbolic Set to **true** if disassembled code is symbolic/concolic
     *  @param is_tainted Set to **true** if disassembled code is tainted
     *  @param check_mappings If enabled, the method will throw an exception if disassembled code is located in a memory area that doesn't have the RX flags set 
     */
    virtual std::shared_ptr<ir::Block> lift_block(
        uintptr_t addr,
        code_t code,
        size_t code_size=0xffffffff,
        unsigned int nb_instr=0xffffffff,
        bool* is_symbolic=nullptr,
        bool* is_tainted=nullptr,
        bool check_mappings=false
    ) = 0;

    /** \brief Get assembly string of instruction at address 'addr' */
    virtual const std::string& get_inst_asm(uintptr_t addr, code_t inst) = 0;

    /* \brief Dynamically disassemble instructions at a given address.
     * **WARNING**: this method has very poor performance! */
    std::vector<std::pair<uintptr_t, std::string>> _raw_read_instr(uintptr_t addr, code_t code, unsigned int nb_instr=1);
};

/// Lifter for Intel X86 and X86_64 binary code
class LifterX86: public Lifter
{
private:
    const int mode;
    std::shared_ptr<TranslationContext> sleigh_ctx;
public:
    LifterX86(int mode=32);
    ~LifterX86() = default;
    virtual std::shared_ptr<ir::Block> lift_block(
        uintptr_t addr,
        code_t code,
        size_t code_size=0xffffffff,
        unsigned int nb_instr=0xffffffff,
        bool* is_symbolic=nullptr,
        bool* is_tainted=nullptr,
        bool check_mappings=false
    );
    virtual const std::string& get_inst_asm(addr_t addr, code_t inst);
};

// TODO Lifter for ARMv8 64-bits binary code
class LifterARM64: public Lifter
{
public:
    LifterARM64();
    ~LifterARM64();
    virtual std::shared_ptr<ir::Block> lift_block(
        uintptr_t addr,
        code_t code,
        size_t code_size=0xffffffff,
        unsigned int nb_instr=0xffffffff,
        bool* is_symbolic=nullptr,
        bool* is_tainted=nullptr,
        bool check_mappings=false
    );
};

/** \} */ // doxygen group ir

} // namespace maat

#endif
