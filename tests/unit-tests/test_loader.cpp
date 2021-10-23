#include "expression.hpp"
#include "loader.hpp"
#include "exception.hpp"
#include "engine.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

namespace test
{
    namespace loader
    {
        using namespace maat;
        using namespace maat::loader;
#ifdef HAS_LOADER_BACKEND
        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int load_simple_algo_2()
        {
            unsigned int nb = 0;
            MaatEngine engine(Arch::Type::X86); // TODO add env::System::LINUX
            addr_t tmp;
            engine.load(
                "tests/ressources/simple_algo_2/simple_algo_2",
                loader::Format::ELF32,
                0x56555000,
                std::vector<CmdlineArg>{CmdlineArg("12345678")},
                {},
                "",
                {},
                {}
            );

            nb += _assert(engine.cpu.ctx().get(X86::EIP)->as_uint() == 0x56555430, "Loader: ELF X86: instruction pointer not set correctly");
            nb += _assert(engine.mem->read(0x565555dd, 4)->as_uint() == 0x56555680, "Loader: ELF X86: relocation failed");
            nb += _assert(engine.mem->read(0x56556ecc, 4)->as_uint() == 0x56555560, "Loader: ELF X86: relocation failed");
            nb += _assert(engine.mem->read(0x56556ed0, 4)->as_uint() == 0x56555510, "Loader: ELF X86: relocation failed");
            nb += _assert(engine.mem->read(0x56556ff8, 4)->as_uint() == 0x56555598, "Loader: ELF X86: relocation failed");
            nb += _assert(engine.mem->read(0x56557004, 4)->as_uint() == 0x56557004, "Loader: ELF X86: relocation failed");
            
            nb += _assert(engine.mem->read(engine.cpu.ctx().get(X86::ESP), 4)->as_uint() == 2, "Loader: ELF X86: argc not set correctly");
            tmp = engine.mem->read((engine.cpu.ctx().get(X86::ESP)) + 4 + 4, 4)->as_uint();
            nb += _assert(engine.mem->read(tmp, 8)->as_uint() == 0x3837363534333231, "Loader: ELF X86: failed to setup argument in stack");
            nb += _assert(engine.mem->read(tmp+8, 1)->as_uint() == 0, "Loader: ELF X86: failed to setup argument in stack (missing termination '\0')");

            return nb;
        }

#endif // ifdef HAS_LOADER_BACKEND
    }
}

using namespace test::loader;
// All unit tests
void test_loader()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

#ifdef HAS_LOADER_BACKEND
    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing loader interface... " << std::flush;

    total += load_simple_algo_2();

    std::cout   << "\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
#endif
}
