#include "maat/arch.hpp"
#include "maat/varcontext.hpp"
#include "maat/engine.hpp"
#include "maat/exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>

using std::cout;
using std::endl; 
using std::string;

namespace test
{
    namespace archARM32 
    {
        
        using namespace maat;

        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int test_ARM32 () {
            string code;
            MaatEngine sym = MaatEngine(Arch::Type::ARM32);
            sym.mem->map(0x1000, 0x2000);
            code = "\x00\x00\x20\xe0\x01\x00\x80\xe2\x00\x10\xa0\xe1\x0a\x00\x80\xe2"; 
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.cpu.ctx().set(ARM32::R2, exprcst(32, 0xDEADBEEF));
            sym.run_from(0x1000, 4);

            unsigned int return_val = 0;
            return_val += _assert(sym.cpu.ctx().get(ARM32::R2).as_uint() == 0xDEADBEEF, "R2 is not DEADBEEF");
            //return_val += _assert(sym.cpu.ctx().get(ARM32::R0).as_int() == 11, "R0 is not equal to 11");
            cout << 
            "\nR0 = " << sym.cpu.ctx().get(ARM32::R0).as_uint() << 
            "\nR1 = " << sym.cpu.ctx().get(ARM32::R1).as_uint() << 
            "\nR2 = " << sym.cpu.ctx().get(ARM32::R2).as_uint() << "\n\n"; 
            
            return return_val;

        }

    }
}

using namespace test::archARM32;

void test_archARM32() {
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing arch ARM32 support... " << std::flush;  

    MaatEngine engine(Arch::Type::ARM32);
    engine.mem->map(0x0, 0x10000);

    total += test_ARM32();
    cout << "\t" << total << "/" << total << green << "\tOK" << def << endl;
}