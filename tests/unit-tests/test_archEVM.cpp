#include "maat/arch.hpp"
#include "maat/engine.hpp"
#include "maat/exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "maat/env/env_EVM.hpp"

using std::string;

namespace test{
    namespace archEVM{

        using namespace maat;
        using namespace maat::env::EVM;

        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl << std::flush; 
                throw test_exception();
            }
            return 1;
        }
 
        void setup_dummy_contract(MaatEngine& engine)
        {
            engine.process->pid = get_ethereum(engine)->add_contract(
                std::make_shared<Contract>(Value(256, "86984651684651a5a65665b65f", 16))
            );
        }

        unsigned int reg_translation()
        {
            unsigned int nb = 0;
            reg_t reg;
            EVM::ArchEVM arch = EVM::ArchEVM();
            for (reg = 0; reg < EVM::NB_REGS; reg++)
            {
                nb += _assert( arch.reg_num(arch.reg_name(reg)) == reg , "ArchEVM: translation reg_num <-> reg_name failed");
            }
            nb += _assert(arch.pc() == EVM::PC, "ArchEVM: translation reg_num <-> reg_name failed");
            return nb;
        }

        void write_inst(MaatEngine& engine, addr_t addr, const std::string& code)
        {
            engine.mem->write_buffer(addr, (uint8_t*)code.c_str(), code.size());
            engine.mem->write(addr+code.size(), 0x0, 1);
        }

        unsigned int test_add(MaatEngine& engine)
        {
            unsigned int nb = 0;
            std::string code;
    
            code = std::string("\x01", 1);
            write_inst(engine, 0x10, code);

            contract_t contract = get_contract_for_engine(engine);
            contract->stack.push(Value(256, "21", 10));
            contract->stack.push(Value(256, "7", 10));
            engine.run_from(0x10, 1);

            nb += _assert( contract->stack.get(0).as_uint() == 28,
                            "ArchEVM: failed to disassembly and/or execute ADD");

            return nb;
        }
    }
}

using namespace test::archEVM; 
// All unit tests 
void test_archEVM()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";
    
    // Start testing
    std::cout << bold << "[" << green << "+" 
         << def << bold << "]" << def << std::left << std::setw(34)
         << " Testing arch EVM support... " << std::flush;

    MaatEngine engine(Arch::Type::EVM);
    engine.mem->map(0x0, 0xfff);
    setup_dummy_contract(engine);

    total += reg_translation();
    total += test_add(engine);

    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}
