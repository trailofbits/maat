// Based on Angr's pypcode

#ifndef MAAT_SLEIGH_H
#define MAAT_SLEIGH_H


#include <string>
#include <map>
#include "maat/arch.hpp"
#include "maat/ir.hpp"

namespace maat
{
    
    class TranslationContext;

    std::shared_ptr<TranslationContext> new_sleigh_ctx(
        const Arch::Type arch,
        const std::string& slafile,
        const std::string& pspecfile
    );

    void sleigh_translate(
        std::shared_ptr<TranslationContext> ctx,
        ir::IRMap& ir_map,
        const unsigned char *bytes,
        unsigned int num_bytes,
        uintptr_t address,
        unsigned int max_instructions,
        bool bb_terminating
    );
    
    const std::string& sleigh_get_asm(
        std::shared_ptr<TranslationContext> ctx,
        uintptr_t address,
        const unsigned char* bytes
    );

    // Register SLEIGH to MAAT translator functions
    inline maat::ir::Param sleigh_reg_translate_X86(const std::string& reg_name);
    inline maat::ir::Param sleigh_reg_translate_X64(const std::string& reg_name);
    inline maat::ir::Param sleigh_reg_translate_EVM(const std::string& reg_name);
    inline maat::ir::Param sleigh_reg_translate_RISCV(const std::string& reg_name);

}

#endif
