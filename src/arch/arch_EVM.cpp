#include "maat/arch.hpp"
#include "maat/exception.hpp"

namespace maat{
namespace EVM{

    ArchEVM::ArchEVM(): Arch(Arch::Type::EVM, 32, EVM::NB_REGS)
    {
        available_modes = {CPUMode::EVM};
        reg_map =
        {
            {"pc", PC}
        };
    }

    size_t ArchEVM::reg_size(reg_t reg_num) const 
    {
        switch (reg_num)
        {
            case PC:
                return 32;
            default:
                throw runtime_exception("ArchEVM::reg_size(): got unsupported reg num");
        }
    }

    reg_t ArchEVM::sp() const 
    {
        throw runtime_exception("ArchEVM::sp(): method not available");
    }

    reg_t ArchEVM::pc() const 
    {
        return EVM::PC;
    }

    reg_t ArchEVM::tsc() const 
    {
        throw runtime_exception("ArchEVM::tsc(): method not available");
    }
} // namespace EVM

} // namespace maat