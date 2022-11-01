#include "maat/lifter.hpp"
#include "maat/config.hpp"
#include "maat/arch.hpp"
#include <string>
#include <filesystem>

namespace maat
{

Lifter::Lifter(CPUMode m): mode(m)
{
    std::optional<std::filesystem::path> slafile, pspecfile;
    Arch::Type arch;

    MaatConfig& config = MaatConfig::instance();

    if (m == CPUMode::NONE)
        return;

    // Init disassembly context
    try
    {
        if (mode == CPUMode::X86)
        {
            slafile = config.find_sleigh_file("x86.sla");
            pspecfile = config.find_sleigh_file("x86.pspec");
            arch = Arch::Type::X86;
        }
        else if (mode == CPUMode::X64)
        {
            slafile = config.find_sleigh_file("x86-64.sla");
            pspecfile = config.find_sleigh_file("x86-64.pspec");
            arch = Arch::Type::X64;
        }
        else if (mode == CPUMode::EVM)
        {
            slafile = config.find_sleigh_file("EVM.sla");
            pspecfile = config.find_sleigh_file("EVM.pspec");
            arch = Arch::Type::EVM;
        }
        else if (mode == CPUMode::RISCV)
        {
            slafile = config.find_sleigh_file("riscv.lp64d.sla");
            pspecfile = config.find_sleigh_file("RV64G.pspec");
            arch = Arch::Type::RISCV;
        }
        else if (mode == CPUMode::A32)
        {
            slafile = config.find_sleigh_file("ARM8_le.sla");
            pspecfile = config.find_sleigh_file("ARMCortex.pspec");
            arch = Arch::Type::ARM32;
        }
        else
        {
            throw lifter_exception("Lifter: this CPU mode is not supported");
        }

        if (not (slafile and pspecfile))
        {
            throw lifter_exception("Lifter: didn't find sleigh files for this CPU");
        }

        // Try to get cached sleigh context if it exists
        sleigh_ctx = serial::get_cached_sleigh_ctx(mode);
        // No cached context, create a new one
        if (sleigh_ctx == nullptr)
            sleigh_ctx = new_sleigh_ctx(arch, slafile->string(), pspecfile->string());
    }
    catch(std::exception& e)
    {
        throw lifter_exception(Fmt() 
                << "Lifter: Error while opening CPU spec file: " 
                << e.what()
                >> Fmt::to_str
              );
    }

    if (sleigh_ctx == nullptr)
    {
        throw lifter_exception(Fmt() 
                <<"Lifter: Failed to instanciate SLEIGH context from file: "
                << slafile->string()
                >> Fmt::to_str
              );
    }
}

bool Lifter::lift_block(
    maat::Logger& logger,
    ir::IRMap& ir_map,
    uintptr_t addr,
    code_t code,
    size_t code_size,
    unsigned int nb_inst,
    bool* is_symbolic,
    bool* is_tainted,
    bool check_mappings
){
    // TODO: check memory mappings
    try
    {
        sleigh_translate(
            sleigh_ctx,
            ir_map,
            code,
            code_size,
            addr,
            nb_inst, 
            true
        );
    }
    catch(std::exception& e)
    {
        logger.error(
            "Sleigh failed to decode instructions in basic block starting at 0x",
            std::hex, addr, ". Raised the following error: \"", e.what(), "\""
        );
        return false;
    }

    return true;
}

const std::string& Lifter::get_inst_asm(addr_t addr, code_t inst)
{
    return sleigh_get_asm(sleigh_ctx, addr, inst);
}

serial::uid_t Lifter::class_uid() const
{
    return serial::ClassId::LIFTER;
}

void Lifter::dump(serial::Serializer& s) const
{
    s << serial::bits(mode);
    serial::cache_sleigh_ctx(mode, sleigh_ctx); // Cache sleigh context for performance
}

void Lifter::load(serial::Deserializer& d)
{
    CPUMode m;
    // Get mode and call constructor again to initialize everything properly
    d >> serial::bits(m);
    *this = Lifter(m);
}

} // namespace maat
