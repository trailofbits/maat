#include "lifter.hpp"
#include <string>

namespace maat
{

LifterX86::LifterX86(int m): mode(m)
{
    std::string slafile;
    std::string pspecfile;
    std::string arch;
    // Init disassembly context
    try
    {
        if (mode == 32)
        {
            slafile = "/usr/local/etc/maat/processors/x86.sla";
            pspecfile = "/usr/local/etc/maat/processors/x86.pspec";
            arch = "X86";
        }
        else if (mode == 64)
        {
            slafile = "/usr/local/etc/maat/processors/x86-64.sla";
            pspecfile = "/usr/local/etc/maat/processors/x86-64.pspec";
            arch = "X64";
        }
        else
        {
            throw lifter_exception("LifterX86: supported modes are only '32' and '64'");
        }
         sleigh_ctx = new_sleigh_ctx(arch, slafile, pspecfile);
    }
    catch(std::exception& e)
    {
        throw lifter_exception(Fmt() 
                << "Error while opening CPU spec file: " 
                << e.what()
                >> Fmt::to_str
              );
    }

    if (sleigh_ctx == nullptr)
    {
        throw lifter_exception(Fmt() 
                <<"LifterX86: Failed to instanciate SLEIGH context from file: "
                << slafile
                >> Fmt::to_str
              );
    }
}

bool LifterX86::lift_block(
    ir::IRMap& ir_map,
    uintptr_t addr,
    code_t code,
    size_t code_size,
    unsigned int nb_inst,
    bool* is_symbolic,
    bool* is_tainted,
    bool check_mappings
)
{
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
        // TODO: log error properly (need ref to Logger)
        std::cout << "FATAL: Error in sleigh translate(): " << e.what() << std::endl;
        return false;
    }

    return true;
}

const std::string& LifterX86::get_inst_asm(addr_t addr, code_t inst)
{
    return sleigh_get_asm(sleigh_ctx, addr, inst);
}

} // namespace maat
