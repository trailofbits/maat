#ifndef MAAT_LIFTER_H
#define MAAT_LIFTER_H

#include <cstdint>
#include <vector>
#include <utility>
#include <memory>
#include <unordered_map>
#include "maat/ir.hpp"
#include "sleigh_interface.hpp"
#include "maat/arch.hpp"

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
protected:
    const CPUMode mode;
    std::shared_ptr<TranslationContext> sleigh_ctx;
public:
    Lifter(CPUMode mode);
    ~Lifter() = default;
    /** \brief Disassemble instructions until next branch instruction.
     * 
     *  @param ir_map The IR cache where to add lifted instructions
     *  @param addr Address of the first instruction to disassemble 
     *  @param code Raw pointer to the code to disassemble 
     *  @param code_size Max size of the code region to disassemble in memory
     *  @param nb_instr Max number of instructions to disassemble before stopping
     *  @param is_symbolic Set to **true** if disassembled code is symbolic/concolic
     *  @param is_tainted Set to **true** if disassembled code is tainted
     *  @param check_mappings If enabled, the method will throw an exception if disassembled code is located in a memory area that doesn't have the RX flags set 
     *
     *  @returns True on success and false on failure
     */
    virtual bool lift_block(
        ir::IRMap& ir_map,
        uintptr_t addr,
        code_t code,
        size_t code_size=0xffffffff,
        unsigned int nb_instr=0xffffffff,
        bool* is_symbolic=nullptr,
        bool* is_tainted=nullptr,
        bool check_mappings=false
    );

    /** \brief Get assembly string of instruction at address 'addr' */
    virtual const std::string& get_inst_asm(addr_t addr, code_t inst);
};

/** \} */ // doxygen group ir

} // namespace maat

#endif
