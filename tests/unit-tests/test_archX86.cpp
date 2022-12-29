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
    namespace archX86
    {
        
        using namespace maat;
        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int _assert_bignum_eq(
            const Value& var,
            std::string expected_value,
            std::string error_msg
        )
        {
            const Number& number = var.as_number();
            std::stringstream ss;
            ss << number;
            if (ss.str() != expected_value)
            {
                std::cout << "\nFail: _assert_bignum_eq: " << ss.str() << " is not " << expected_value << std::endl;
                std::cout << "\nFail: " << error_msg << std::endl;
                throw test_exception(); 
            }
            return 1; 
        }
        
        unsigned int some_bench()
        {
            string code;
            MaatEngine sym = MaatEngine(Arch::Type::X86);
            sym.mem->map(0x1000, 0x2000);
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write_buffer(0x1150, (uint8_t*)code.c_str(), 2);
            code = string("\x66\x0F\x38\xF6\xC3", 5); // adcx eax, ebx
            sym.mem->write_buffer(0x1152, (uint8_t*)code.c_str(), 5);
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write_buffer(0x1157, (uint8_t*)code.c_str(), 2);
            code = string("\x37", 1); // aaa
            sym.mem->write_buffer(0x1159, (uint8_t*)code.c_str(), 1);
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));

            for( int i = 0; i < 250000; i++){
                if( i % 10000 == 0 ){
                    sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
                    sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10));
                    sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
                }
                sym.run_from(0x1150, 4);
            }
            return 0;
        }
        
        unsigned int reg_translation()
        {
            unsigned int nb = 0;
            reg_t reg;
            X86::ArchX86 arch;
            for( reg = 0; reg < X86::NB_REGS; reg++ ){
                nb += _assert( arch.reg_num(arch.reg_name(reg)) == reg , "ArchX86: translation reg_num <-> reg_name failed");
            }
            nb += _assert(arch.sp() == X86::ESP, "ArchX86: translation reg_num <-> reg_name failed");
            nb += _assert(arch.pc() == X86::EIP, "ArchX86: translation reg_num <-> reg_name failed");
            return nb;
        }

        unsigned int disass_aaa(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            code = string("\x37", 1); // aaa
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Test with AF set */
            // AL = 7
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7));
            sym.run_from(0x1000, 1);


            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0b100001101)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            // AL = 7 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b1101));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0b100000011)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
                            
            // AL = 3 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b0011));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0b100001001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            
             /* Test when the 4 LSB are > 9 and AF not set*/
            // AL = 10 
            sym.cpu.ctx().set(X86::AF, 0); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b1010));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0b100000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            // AL = 15 
            sym.cpu.ctx().set(X86::AF, 0); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b1111));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0b100000101)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            
             /* Test when the 4 LSB are <= 9 and AF not set*/
            // AL = 0b11110000
            sym.cpu.ctx().set(X86::AF, 0); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b11110000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            // AL = 0x59
            sym.cpu.ctx().set(X86::AF, 0); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x59));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x09)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");

            return nb;
        }
        
        unsigned int disass_aad(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\xD5\x0A", 2); // aad
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // AX = 7 
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 7));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 7)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
                            
            // AX =  0x107
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x107));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 17)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
                            
            // AX =  0xd01
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xd01));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x83)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            /* TODO: error in ghidra...
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            */
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            
            // AX =  0x8000
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x8000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            
            // AX =  0xc88
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xc88));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            
            return nb;
        }
        
        unsigned int disass_aam(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\xD4\x0A", 2); // aam
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // AX = 7
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 7));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 7)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
                            
            // AX =  0x107
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x107));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 7)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
                            
            // AX =  33
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 33));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0303)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            
            // AX =  89
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 89));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0809)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            /* TODO - sleigh bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            */

            // AX =  123
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 123));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xc03)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
                            
            // AX =  0xa
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xa));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x100)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAM");
            /* TODO sleigh bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            */
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            /* TODO sleigh bug ?
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            */
            return nb;
        }
        
        
        unsigned int disass_aas(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\x3F", 1); // aas
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Test with AF set */
            // AX = 0x107 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x107));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            
            // AX = 0x007 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x007));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xff01)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
                            
            // AL = 0x203 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x203));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10d)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            
             /* Test when the 4 LSB are > 9 and AF not set*/
            // AX = 0x30a 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 0)); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x30a));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x204)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            // AL = 0x00f 
            sym.cpu.ctx().set(X86::AF, exprcst(8, 0)); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x00f));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xff09)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            
             /* Test when the 4 LSB are <= 9 and AF not set*/
            // AL = 0b11110000
            sym.cpu.ctx().set(X86::AF, exprcst(8, 0)); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b11110000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            // AL = 0x59
            sym.cpu.ctx().set(X86::AF, exprcst(8, 0)); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x59));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x09)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
                            
            // AX = 0x259
            sym.cpu.ctx().set(X86::AF, exprcst(8, 0)); // Clear carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x259));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x209)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            return nb;
        }
        
         unsigned int disass_adcx(MaatEngine& sym)
         {
            unsigned int nb = 0;
            string code;
            code = string("\x66\x0F\x38\xF6\xC3", 5); // adcx eax, ebx
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // 0x10 + 0x20 with CF set
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x31)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
            // 0x10 + 0x20 with CF cleared
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x30)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
                            
            // 0xffffffff + 0xfffffffd with carry 
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xfffffffd));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xfffffffd)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
                            
            // 0xffffffff + 0xfffffffd with CF cleared 
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xfffffffd));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xfffffffc)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
            // 0x7fff0000 + 0x0f000000
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0f000000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x8eff0001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
            // 0x8fff0000 + 0x80000001
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x8fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0fff0002)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");

            // 0xffffff00 + 0x00000100
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffff00));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x00000100));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            return nb;
        }

        unsigned int disass_add(MaatEngine& sym)
        {
            unsigned int nb = 0;
            std::string code;

            sym.cpu.ctx().set(X86::EAX, exprvar(32, "eax"));
            sym.cpu.ctx().set(X86::EBX, exprvar(32, "ebx"));
            sym.cpu.ctx().set(X86::ECX, exprvar(32, "ecx"));
            sym.cpu.ctx().set(X86::EDX, exprvar(32, "edx"));

            /* ADD REG,IMM */
            // add eax, 1
            code = "\x83\xC0\x01";
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_expr()->eq(exprvar(32, "eax")+exprcst(32,1)), 
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // add bl, 0xff
            code = "\x80\xC3\xFF";
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_expr()->eq(concat(extract(exprvar(32, "ebx"), 31, 8),
                                                               extract(exprvar(32, "ebx"), 7, 0)+exprcst(8,0xff))), 
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // add ch, 0x10
            code = "\x80\xC5\x10";
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_expr()->eq( 
                    concat( concat( extract(exprvar(32, "ecx"), 31, 16),
                                    extract(exprvar(32, "ecx"), 15, 8)+exprcst(8,0x10)),
                            extract(exprvar(32, "ecx"), 7, 0))),
                    "ArchX86: failed to disassembly and/or execute ADD"); 

            // add dx, 0xffff
            code = "\x66\x83\xC2\xFF";
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_expr()->eq(concat(extract(exprvar(32, "edx"), 31, 16),
                                                               extract(exprvar(32, "edx"), 15, 0)+exprcst(16,0xffff))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            
            
            // ADD REG, REG
            sym.cpu.ctx().set(X86::EAX, exprvar(32, "eax")); // reset 
            sym.cpu.ctx().set(X86::EBX, exprvar(32, "ebx")); // reset 
            sym.cpu.ctx().set(X86::ECX, exprvar(32, "ecx")); // reset 
            sym.cpu.ctx().set(X86::EDX, exprvar(32, "edx")); // reset 
            // add al,bl
            code = string("\x00\xD8",2);
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_expr()->eq(concat(extract(exprvar(32, "eax"), 31, 8),
                                                    extract(exprvar(32, "eax"), 7, 0)+extract(exprvar(32,"ebx"), 7, 0))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.cpu.ctx().set(X86::EAX, exprvar(32, "eax")); // reset 
            // add ch,dh
            code = string("\x00\xF5", 2);
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_expr()->eq(
                concat( concat( extract(exprvar(32, "ecx"), 31, 16),
                                extract(exprvar(32, "ecx"), 15, 8)+extract(exprvar(32,"edx"), 15, 8)),
                        extract(exprvar(32, "ecx"), 7, 0 ))),
                "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.cpu.ctx().set(X86::ECX, exprvar(32, "ecx")); // reset 
            // add ax,bx
            code = string("\x66\x01\xD8", 3);
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_expr()->eq(concat(extract(exprvar(32, "eax"), 31, 16),
                                                    extract(exprvar(32, "eax"), 15, 0)+extract(exprvar(32,"ebx"), 15, 0))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.cpu.ctx().set(X86::EAX, exprvar(32, "eax")); // reset 
            // add ecx, edx
            code = string("\x01\xD1",2);
            sym.mem->write_buffer(0x1070, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1070+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1070, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_expr()->eq(exprvar(32, "ecx")+ exprvar(32,"edx")),
                "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.cpu.ctx().set(X86::ECX, exprvar(32, "ecx")); // reset


            // ADD REG, MEM
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x612)); 
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x612)); 
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0x612));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x612));

            sym.mem->write(0x612, exprcst(32, 0x12345678));
            // add al, BYTE PTR [eax]
            code = string("\x02\x00",2);
            sym.mem->write_buffer(0x1080, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1080+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1080, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x68a, "ArchX86: failed to disassembly and/or execute ADD");
            // add bx, WORD PTR [ebx]
            code = string("\x66\x03\x1B", 3);
            sym.mem->write_buffer(0x1090, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1090+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1090, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x5c8a, "ArchX86: failed to disassembly and/or execute ADD");
            // add ecx, DWORD PTR [ecx]
            code = string("\x03\x09", 2);
            sym.mem->write_buffer(0x1100, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1100+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1100, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_uint() == 0x12345c8a, "ArchX86: failed to disassembly and/or execute ADD");

            // ADD MEM, IMM
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x2010));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x12345678));
            
            // add BYTE PTR [eax], 0x42
            code = string("\x80\x00\x42",3);
            sym.mem->write_buffer(0x1110, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1110+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1110, 1);
            nb += _assert(  sym.mem->read(0x2000, 1).as_uint() == 0x42,
                            "ArchX86: failed to disassembly and/or execute ADD");
            // add DWORD PTR [ebx], 0xffffffff
            code = string("\x83\x03\xFF", 3);
            sym.mem->write_buffer(0x1120, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1120+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1120, 1);
            nb += _assert(  sym.mem->read(0x2010, 4).as_expr()->eq(exprcst(32, 0xffffffff)),
                            "ArchX86: failed to disassembly and/or execute ADD");


            // ADD MEM, REG
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x2100));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x2110));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x12345678));
            // add BYTE PTR [eax], cl
            code = string("\x00\x08", 2);
            sym.mem->write_buffer(0x1130, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1130+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1130, 1);
            nb += _assert(  sym.mem->read(0x2100, 1).as_expr()->eq(exprcst(8, 0x78)),
                            "ArchX86: failed to disassembly and/or execute ADD");
            // add DWORD PTR [ebx], edi
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x10));
            sym.mem->write(0x2110, exprcst(32, 0x12345678));
            code = string("\x01\x3B", 2); 
            sym.mem->write_buffer(0x1140, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1140+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1140, 1);
            nb += _assert(  sym.mem->read(0x2110, 4).as_uint() == 0x12345688,
                            "ArchX86: failed to disassembly and/or execute ADD");
            // 0x10 + 0x20
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            code = string("\x01\xD8", 2); // add eax, ebx
            sym.mem->write_buffer(0x1150, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1150+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1150, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // -1 + -3
            sym.cpu.ctx().set(X86::EAX, exprcst(32, -1));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, -3));
            code = string("\x01\xD8", 2); // add eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");

            // 16 + 56
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 16));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 56));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
                            
            // 0x7fff0000 + 0x0f000000
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0f000000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
                            
            // 0x7fff0000 + 0x7000001f
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0f00001f));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // 0x8fff0000 + 0x80000001
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x8fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // 0xffffffff + 0xfffffffe
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xfffffffe));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");

            // 0xffffff00 + 0x00000100
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffff00));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x00000100));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            return nb;
        }

        
        unsigned int disass_adc(MaatEngine& sym)
        {
            unsigned int nb = 0;
            std::string code;

            /* Test ADC with carry set */
            // 0x10 + 0x20
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write_buffer(0x1150, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1150+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1150, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x31)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // -1 + -3
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, -1));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, -3));
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, -3)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // 16 + 56
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 16));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 56));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 73)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            
            // 0x7fff0000 + 0x0f000000
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0f000000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x8eff0001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // 0x7fff0000 + 0x7000001f
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0f00001f));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x8eff0020)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            
            // 0x8fff0000 + 0x80000001
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x8fff0000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0fff0002)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // 0xffffffff + 0xfffffffe
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xfffffffe));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xfffffffe)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
                            
            // 0xffffff00 + 0x00000100
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1)); // Set carry flag
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffff00));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x00000100));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");

            return nb;
        }

        unsigned int disass_and(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            // On 32 bits
            // 678 & 0xfff.....
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 678));
            code = string("\x21\xD8", 2); // and eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            
            // 0xfffff000 & 0x000fffff
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xfffff000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x000fffff));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x000ff000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
                            
            // 0x8000000 + 0x80000001
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x80000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
                            
            // On 16 bits... 
            // 0xa00000f0 & 0x0b0000ff
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xa00000f0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0b0000ff));
            code = string("\x66\x21\xD8", 3); // and ax, bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xa00000f0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            
            // 0xab00000f & 0xba0000f0
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xab00000f));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xba0000f0));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xab000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            return nb;
        }
        
        unsigned int disass_andn(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\xC4\xE2\x78\xF2\xC3", 5); // andn eax, eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0xfff..... n& 678
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 678));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            
            // 0xfffff000 n& 0x000fffff
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xfffff000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x000fffff));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x00000fff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
                            
            // 0x7ffffffe n& 0x80000001
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x7ffffffe));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x80000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            return nb;
        }
        
        unsigned int disass_blsi(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\xC4\xE2\x78\xF3\xDB", 5); // blsi eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x00001010
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00001010));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            
            // 0xffffff01
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xffffff01));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x1)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
                            
            // 0
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
                            
            // 0x80000000
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x80000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            return nb;
        }
        
        unsigned int disass_blsmsk(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\xC4\xE2\x78\xF3\xD3", 5); // blsmsk eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x00001010 : 0x00000010
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x00001010));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00000010));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x001f)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            
            // 0x00001010 : 0x00100000
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x00001010));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00100000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x001fffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
                            
            // 0 : 0
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xffffffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
                            
            // 0xffffffff : 0x00200000
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x00200000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x003fffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            return nb;
        }
        
        unsigned int disass_blsr(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            code = string("\xC4\xE2\x78\xF3\xCB", 5); // blsr eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x000000f0
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x000000f0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xe0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            
            // 0x00100000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00100000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
                            
            // 0
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
                            
            // 0xffffffff
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xffffffff));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xfffffffe)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BLSR");
            return nb;
        }

        unsigned int disass_bsf(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            /* On 16 bits */
            code = string("\x66\x0F\xBC\xC3", 4); // bsf ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            sym.cpu.ctx().set(X86::EAX, 0);
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00001100));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 8)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
            // bsf 0x0
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");
            // bsf 0x8000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x8000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 15)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");

            // bsf 0x10000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");
            
            /* On 32 bits */
            code = string("\x0F\xBC\xC3", 3); // bsf eax, ebx
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00001100));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 8)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
                            
                            
            // bsf 0x80000000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x80000000));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 31)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
                            
            // bsf 0
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");         
            return nb;
        }
        
        unsigned int disass_bsr(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 16 bits */
            code = string("\x66\x0F\xBD\xC3", 4); // bsr ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bsr 0x1100
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00001100));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 12)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSR");
            // bsr 0x0
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BSR");
            // bsr 0x8000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x8000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 15)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSR");
            
            // bsr 0x10000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BSR");
            
            /* On 32 bits */
            code = string("\x0F\xBD\xC3", 3); // bsr eax, ebx
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bsr 0x1100
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x00001100));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 12)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSR");
                            
                            
            // bsr 0x80000000
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x80000000));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 31)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BSR");
                            
            // bsr 0
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BSR");         
            return nb;
        }
        
        unsigned int disass_bswap(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            
            /* On 32 bits */
            code = string("\x0F\xC8", 2); // bswap eax
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bswap 0x12345678
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.run_from(0x1160, 1);
            
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x78563412)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSWAP");
                            
            // bswap 0x00111100
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x00111100));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x00111100)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BSWAP");
             
            // On vars
            Expr eax = exprvar(32, "eax");
            sym.cpu.ctx().set(X86::EAX, eax);
            sym.vars->set("eax", 0x12345678);
            sym.run_from(0x1160, 1);
            nb += _assert( sym.cpu.ctx().get(X86::EAX).as_uint(*sym.vars) == 
                (concat(concat(concat(extract(eax, 7,0),
                               extract(eax, 15, 8)),
                               extract(eax,23,16)),
                               extract(eax, 31, 24)))->as_uint(*sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSWAP");
            return nb;
        }
    
    
        unsigned int disass_bt(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 16 bits */
            code = string("\x66\x0F\xA3\xD8", 4); // bt ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x8, 3)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,3));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BT");

            // bit(0x8, 4)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,4));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,19));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BT");
            
            // from memory
            code = string("\x66\x0F\xA3\x18", 4); // bt word ptr [eax], bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1701));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,8));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            /* On 32 bits */
            code = string("\x0F\xA3\xD8", 3); // bt eax, ebx
            sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x10000000, 28)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,28));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            // bit(0x10000000, 29)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,29));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            // bit(0x10000000, 60)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,60));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            /* With an imm */
            code = string("\x0F\xBA\xE0\x0D", 4); // bt eax, 13
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,13));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            code = string("\x0F\xBA\xE0\x0C", 4); // bt eax, 12
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,13));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BT");
            return nb;
        }
        
        unsigned int disass_bts(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 16 bits */
            code = string("\x66\x0F\xAB\xD8", 4); // bts ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x8, 3)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,3));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x8)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTS");

            // bit(0x8, 4)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,4));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x18)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,19));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTS");
            
            // from memory
            code = string("\x66\x0F\xAB\x18", 4); // bts word ptr [eax], bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(16, 0xfffe));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 2).as_uint() == exprcst(16 , 0xffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* On 32 bits */
            code = string("\x0F\xAB\xD8", 3); // bts eax, ebx
             sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
             sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bit(0x10000000, 28)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,28));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 29)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,29));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x30000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 60)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,60));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* With an imm */
            code = string("\x0F\xBA\xE8\x0D", 4); // bts eax, 13
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x2000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            code = string("\x0F\xBA\xE8\x0C", 4); // bts eax, 12
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x3000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTS");
            return nb;
        }
        
        unsigned int disass_btc(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 16 bits */
            code = string("\x66\x0F\xBB\xD8", 4); // btc ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bit(0x8, 3)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,3));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTC");

            // bit(0x8, 4)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,4));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x18)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTC");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,19));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTC");
            
            // from memory
            code = string("\x66\x0F\xBB\x18", 4); // btc word ptr [eax], bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(16, 0xfffe));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 2).as_uint() == exprcst(16 , 0xffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTC");
                            
            /* On 32 bits */
            code = string("\x0F\xBB\xD8", 3); // btc eax, ebx
            sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
             
            // bit(0x10000000, 28)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,28));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTC");
                            
            // bit(0x10000000, 29)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,29));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x30000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTC");
                            
            // bit(0x10000000, 60)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,60));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTC");
                            
            /* With an imm */
            code = string("\x0F\xBA\xF8\x0D", 4); // btc eax, 13
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTC");
                            
            code = string("\x0F\xBA\xF8\x0C", 4); // btc eax, 12
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x3000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTC");
            return nb;
        }
    
        unsigned int disass_btr(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 16 bits */
            code = string("\x66\x0F\xB3\xD8", 4); // btr ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bit(0x8, 3)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,3));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTR");

            // bit(0x8, 4)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,4));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x8)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTR");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,19));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTR");
            
            // from memory
            code = string("\x66\x0F\xB3\x18", 4); // btr word ptr [eax], bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1700, exprcst(16, 0xffff));
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 2).as_uint() == exprcst(16 , 0xfffe)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTR");
                            
            /* On 32 bits */
            code = string("\x0F\xB3\xD8", 3); // btr eax, ebx
            sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2); 
             
            // bit(0x10000000, 28)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,28));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTR");
                            
            // bit(0x10000000, 29)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,29));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTR");
                            
            // bit(0x10000000, 60)
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,60));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTR");
                            
            /* With an imm */
            code = string("\x0F\xBA\xF0\x0D", 4); // bts eax, 13
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BTR");
                            
            code = string("\x0F\xBA\xF0\x0C", 4); // bts eax, 12
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2000));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x2000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BTR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BTR");
            return nb;
        }
        
        unsigned int disass_bzhi(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 32 bits */
            code = string("\xC4\xE2\x70\xF5\xC3", 5); // bzhi eax, ebx, ecx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Normal */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xff0f000f));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,8));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xf)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");

            /* Index on more than 8 bits */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xff0f000f));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0x1008));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xf)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            /* Index on more than 8 bits */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xff0f000f));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0x1008));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xf)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            /* Index bigger than operand size */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xff0f000f));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,33));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == sym.cpu.ctx().get(X86::EBX).as_uint(),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            /* Index zero */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xff0f000f));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32,0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            return nb;
        }

        unsigned int disass_cbw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x66\x98", 2); // cbw
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CBW");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x7f));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x7f)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CBW");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x80));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xff80)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CBW");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000106));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000006)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CBW");

            return nb;
        }
        
        unsigned int disass_cwd(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            code = string("\x66\x99", 2); // cwd
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1234));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x7f98));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1234));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x7f98)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8000));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1234));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x8000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0xffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000106));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1234));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000106)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CWD");

            return nb;
        }
        
        unsigned int disass_cwde(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            
            code = string("\x98", 1); // cwde
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWDE");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x7f98));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x7f98)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWDE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x8000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xffff8000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWDE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000106));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x00000106)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CWDE");

            return nb;
        }
        
        unsigned int disass_cdq(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            
            code = string("\x99", 1); // cdq
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x12345678));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x7f980000));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x12345678));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x7f980000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x0)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x80000001));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x12345678));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x80000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0xffffffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000106));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x12345678));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000106)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CDQ");

            return nb;
        }
        
        unsigned int disass_clc(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xF8", 1); // clc
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::CF, exprcst(8,0x1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CLC");
                            
            sym.cpu.ctx().set(X86::CF, exprcst(8,0x0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CLC");
            return nb;
        }
        
        unsigned int disass_cld(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xFC", 1); // cld
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::DF, exprcst(8,0x1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::DF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CLD");
                            
            sym.cpu.ctx().set(X86::DF, exprcst(8,0x0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::DF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CLD");
            return nb;
        }
        
        unsigned int disass_cli(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xFA", 1); // cli
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::IF, exprcst(8,0x1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::IF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CLI");
 
            sym.cpu.ctx().set(X86::IF, exprcst(8,0x0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::IF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CLI");
            return nb;
        }
        
        unsigned int disass_cmc(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xF5", 1); // cmc
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::CF, exprcst(8,0x1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMC");
                            
            sym.cpu.ctx().set(X86::CF, exprcst(8,0x0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMC");
            return nb;
        }


        unsigned int disass_cmova(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            /* With zf == 0 && cf == 0 */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            /* 16 bits */
            code = string("\x66\x0F\x47\xC3", 4); // cmova ax, bx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVA");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVA");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMOVA");
            
            /* 32 bits */
            code = string("\x0F\x47\xC3", 3); // cmova eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVA");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVA");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
            return nb;
        }
        
        unsigned int disass_cmovae(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            code = string("\x0F\x43\xC3", 3); // cmovae eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            return nb;
        }
        
        unsigned int disass_cmovb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            code = string("\x0F\x42\xC3", 3); // cmovb eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            return nb;
        }
        
        unsigned int disass_cmovbe(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            code = string("\x0F\x46\xC3", 3); // cmovbe eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
            
            return nb;
        }
        
        unsigned int disass_cmove(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            code = string("\x0F\x44\xC3", 3); // cmove eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            return nb;
        }
         
        unsigned int disass_cmovg(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            code = string("\x0F\x4F\xC3", 3); // cmovg eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
            
            return nb;
        }
        
        unsigned int disass_cmovge(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            code = string("\x0F\x4D\xC3", 3); // cmovge eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
            
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
                            
            
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
                            
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
            
            return nb;
        }
        
        unsigned int disass_cmovl(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            code = string("\x0F\x4C\xC3", 3); // cmovl eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVL");
            
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
                            
            
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
                            
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
            
            return nb;
        }
         
        unsigned int disass_cmovle(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            code = string("\x0F\x4E\xC3", 3); // cmovle eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
            
            return nb;
        } 
     
        unsigned int disass_cmovne(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            code = string("\x0F\x45\xC3", 3); // cmovne eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            return nb;
        }
        
        unsigned int disass_cmovno(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            code = string("\x0F\x41\xC3", 3); // cmovno eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            return nb;
        }
        
        unsigned int disass_cmovnp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            code = string("\x0F\x4B\xC3", 3); // cmovnp eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            return nb;
        }
         
        unsigned int disass_cmovns(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            code = string("\x0F\x49\xC3", 3); // cmovns eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            return nb;
        }
        
        unsigned int disass_cmovo(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            code = string("\x0F\x40\xC3", 3); // cmovo eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            return nb;
        }
        
        unsigned int disass_cmovp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            code = string("\x0F\x4A\xC3", 3); // cmovp eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            return nb;
        }
        
        unsigned int disass_cmovs(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* Condition verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            code = string("\x0F\x48\xC3", 3); // cmovs eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x10000001));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x12340000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12340000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x12345678)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            return nb;
        }
        
        unsigned int disass_cmp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            /* cmp reg, imm */
            code = string("\x3C\x0f", 2); // cmp al(ff), f
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xff));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10ff));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            code = string("\x3C\x81", 2); // cmp al(0x80), 0x81
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x80));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
            
            code = string("\x66\x3d\xff\x00", 4); // cmp ax, ff
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1ffff));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
                            
            code = string("\x66\x83\xF8\x01", 4); // cmp ax, 1
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xfa000009));
            sym.run_from(0x1200, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
            
            code = string("\x83\xF8\x48", 3); // cmp eax, 0x48
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xff000000));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
            
            code = string("\x3D\x34\x12\x00\x00", 5); // cmp eax, 0x1234
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10001235));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
            
            code = string("\x3D\x00\x00\x00\xFF", 5); // cmp eax, 0xff000000
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xffff0000));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
                            
            code = string("\x3D\x00\x00\xFF\xFF", 5); // cmp eax, 0xffff0000
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xff000000));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */

            /* cmp reg,reg */
            code = string("\x38\xFC", 2); // cmp ah, bh
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xf800));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x7900));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            /* TODO - ghidra bug ? 
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            */
            
            /* cmp imm, mem */
            code = string("\x80\x3d\x00\x17\x00\x00\x03", 7); // cmp byte ptr [0x1700], 0x3 
            sym.mem->write_buffer(0x1080, (uint8_t*)code.c_str(), 7);
            sym.mem->write_buffer(0x1080+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x01f62303));
            sym.run_from(0x1080, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            /* cmp reg,mem */
            code = string("\x3B\x03", 2); // cmp eax, dword ptr [ebx] 
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0xAAAA));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xAAAA));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x1700));
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            /* cmp mem,reg */
            code = string("\x39\x18", 2); // cmp dword ptr [eax], ebx 
            sym.mem->write_buffer(0x1070, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1070+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1800));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xffffffff));
            sym.run_from(0x1070, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            return nb;
        }
        
        unsigned int disass_cmpsb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xA6", 1); // cmpsb
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.mem->write(0x1000, exprcst(8, 0xff));
            sym.mem->write(0x1500, exprcst(8, 0xf));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::ESI, exprcst(32,0x1000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == exprcst(32, 0xfff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x14ff,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            /* TODO - ghidra bug ?
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            */

            sym.mem->write(0x1000, exprcst(8, 0x1));
            sym.mem->write(0x1500, exprcst(8, 0xff));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::ESI, exprcst(32,0x1000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == exprcst(32, 0x1001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x1501)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            /* TODO - ghidra bug ?
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            */
            return nb;
        }
        
        unsigned int disass_cmpsd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xA7", 1); // cmpsd
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1000, exprcst(32, 0xAAAA));
            sym.mem->write(0x1500, exprcst(32, 0xAAAA));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::ESI, exprcst(32,0x1000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == exprcst(32, 0xffc)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x14fc)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            
            sym.mem->write(0x1000, exprcst(32, 0x1234));
            sym.mem->write(0x1500, exprcst(32, 0x1235));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::ESI, exprcst(32,0x1000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == exprcst(32, 0x1004)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x1504)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSD");

            return nb;
        }
        

        unsigned int disass_cmpsw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;            

            code = string("\x66\xA7", 2); // cmpsw
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1000, exprcst(16, 0xAAAA));
            sym.mem->write(0x1500, exprcst(16, 0xAAAA));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::ESI, exprcst(32,0x1000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == exprcst(32, 0xffe)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x14fe)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            
            sym.mem->write(0x1000, exprcst(32, 0x1234));
            sym.mem->write(0x1500, exprcst(32, 0x1235));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::ESI, exprcst(32,0x1000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == exprcst(32, 0x1002)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x1502)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            
            return nb;
        }
        
        unsigned int disass_cmpxchg(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* On 8 bits */
            code = string("\x0F\xB0\xEF", 3); // cmpxchg bh, ch
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x21));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x2100));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0x4200));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x21)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == exprcst(32, 0x4200)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_uint() == exprcst(32, 0x4200)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            
            /* On 16 bits */
            code = string("\x66\x0F\xB1\x0B", 4); // cmpxchg word ptr [ebx], cx
            sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
        
            sym.mem->write(0x1700, exprcst(16, 0x1111));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x4321));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x1700));
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0x1000BBBB));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x1111)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == exprcst(32, 0x1700)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_uint() == exprcst(32, 0x1000BBBB)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            return nb;
        }
        
        unsigned int disass_dec(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x48", 1); // dec eax
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x21));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x20)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            
           sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xffffff01));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xffffff00)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute DEC");
            return nb;
        }
        
        unsigned int disass_div(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            /* On 8 bits */
            code = string("\xF6\xF3", 2); // div bl
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000015));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x4));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000105)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute DIV");
            
            
            /* On 16 bits */
            code = string("\x66\xF7\xF3", 3); // div bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000015));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x4));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x10000000));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x10000005)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute DIV");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x10000001)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute DIV");
                            
            /* On 32 bits */
            code = string("\xF7\x33", 2); // div dword ptr [ebx]
            sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.mem->write(0x1700, exprcst(32, 24));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xb));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x1700));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1));
            sym.run_from(0x1180, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xaaaaaab,
                            "ArchX86: failed to disassembly and/or execute DIV");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 3,
                            "ArchX86: failed to disassembly and/or execute DIV");

            return nb;
        }
        
        unsigned int disass_idiv(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
      
            /* On 8 bits */
            code = string("\xF6\xFB", 2); // idiv bl
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000015));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,-4));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x100001fb)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute IDIV");

            /* On 16 bits */
            code = string("\x66\xF7\xFB", 3); // idiv bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,-21));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x4));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1000ffff));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, -5)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x1000ffff)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute IDIV");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,-24));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x67));
            sym.cpu.ctx().set(X86::EDX, exprcst(32,0x1000ffff));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xffff0000)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == exprcst(32, 0x1000ffe8)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            
            return nb;
        }
        
        unsigned int disass_inc(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x40", 1); // inc eax
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x22));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0x23)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xffffff01));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == exprcst(32, 0xffffff02)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute INC");
            return nb;
        }
        
        unsigned int disass_leave(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xC9", 1); // leave
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::ESP, exprcst(32,0x0));
            sym.cpu.ctx().set(X86::EBP, exprcst(32,0x1704));
            sym.mem->write(0x1704, exprcst(32, 0x1234));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1708, "ArchX86: failed to disassembly and/or execute LEAVE");
            nb += _assert(  sym.cpu.ctx().get(X86::EBP).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute LEAVE");
            
            return nb;
        }
        
        unsigned int disass_imul(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* One-operand */
            code = string("\xF6\xEB", 2); // imul bl
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,48));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 4));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x00C0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 4, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute IMUL");

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x4200fc));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 4));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x42fff0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 4, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");

            code = string("\x66\xF7\xEB", 3); // imul bx
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,48));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 4));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x11001234));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xC0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 4, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0x11000000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");

            code = string("\xF7\xEB", 2); // imul ebx
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,4823424));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, -423));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x11001234));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x86635d80, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0xfffffe59, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0xffffffff, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            
            /* Two-operands */
            code = string("\x66\x0F\xAF\xC3", 4); // imul ax, bx
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10000002)); // 2 * -2 
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1000fffe));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1000fffc, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x1000fffe, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            
            code = string("\x0F\xAF\xC3", 3); // imul eax, ebx
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x2)); // 2 * -2 
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x00000002, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            
            /* Three-operands */
            code = string("\x6B\xC3\x07", 3); // imul eax, ebx, 7
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x00100000));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x00700000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x00100000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_int() == -7, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_int() == -1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            
            code = string("\x69\xC3\x00\x00\x00\x10", 6); // imul eax, ebx, 0x10000000
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 17));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10000000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 17, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, -1));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xf0000000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_int() == -1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            
            return nb;
        }
        
        unsigned int disass_ja(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x77\x10", 2); // ja 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JA");
            
            
            
            code = string("\x0f\x87\x50\x34\x12\x00", 6 ); // ja 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2006, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JA");
            
            return nb;
        }
        
        unsigned int disass_jae(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x73\x10", 2); // jae 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JAE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JAE");
            
            
            code = string("\x0f\x83\x50\x34\x12\x00", 6 ); // jae 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JAE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JAE");
            
            
            return nb;
        }
        
        unsigned int disass_jb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x72\x10", 2); // jb 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JB");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JB");
            
            
            code = string("\x0f\x82\x50\x34\x12\x00", 6 ); // jb 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JB");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JB");
            
            
            return nb;
        }
        
        unsigned int disass_jbe(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x76\x10", 2); // jbe 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JBE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JBE");
            
            
            
            code = string("\x0f\x86\x50\x34\x12\x00", 6 ); // jbe 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JBE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JBE");
            
            return nb;
        }
        
        unsigned int disass_jcxz(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            /* TODO - ghidra disassembles this as JECXZ not JCXZ...
            code = string("\x67\xe3\x0f", 3); // jcxz 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            // Taken
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0x12340000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JCXZ");

            // Not taken
            sym.cpu.ctx().set(X86::ECX, exprcst(32,2));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1003, "ArchX86: failed to disassembly and/or execute JCXZ");
            */
            return nb;
        }

        unsigned int disass_je(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x74\x10", 2); // je 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JE");
            
            
            code = string("\x0f\x84\x50\x34\x12\x00", 6 ); // je 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JE");
            
            
            return nb;
        }
        
        unsigned int disass_jecxz(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\xe3\x10", 2); // jecxz 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JCXZ");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ECX, exprcst(32,0x80000000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JCXZ");
            
            return nb;
        }
        
        unsigned int disass_jg(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x7f\x10", 2); // jg 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JG");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JG");
            
            
            
            code = string("\x0f\x8f\x50\x34\x12\x00", 6 ); // jg 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JG");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JG");
            
            return nb;
        }
     
        unsigned int disass_jge(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x7d\x10", 2); // jge 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JGE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JGE");
            
            
            
            code = string("\x0f\x8d\x50\x34\x12\x00", 6 ); // jge 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JGE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JGE");
            
            return nb;
        }
        
        unsigned int disass_jl(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x7c\x10", 2); // jl 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JL");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JL");
            
            
            
            code = string("\x0f\x8c\x50\x34\x12\x00", 6 ); // jl 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JL");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JL");
            
            return nb;
        }
        
        unsigned int disass_jle(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x7e\x10", 2); // jle 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JLE");
            
            
            
            code = string("\x0f\x8e\x50\x34\x12\x00", 6 ); // jle 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JLE");
            
            
            return nb;
        }
        
        unsigned int disass_jne(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x75\x10", 2); // jne 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JNE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JNE");
            
            
            code = string("\x0f\x85\x50\x34\x12\x00", 6 ); // jne 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JNE");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JNE");
            
            
            return nb;
        }
        
        unsigned int disass_jno(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x71\x10", 2); // jno 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JNO");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JNO");
            
            
            code = string("\x0f\x81\x50\x34\x12\x00", 6 ); // jno 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JNO");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JNO");
            
            
            return nb;
        }
        
        unsigned int disass_jnp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x7b\x10", 2); // jnp 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JNP");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JNP");
            
            
            code = string("\x0f\x8b\x50\x34\x12\x00", 6 ); // jnp 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JNP");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JNP");
            
            
            return nb;
        }
        
        unsigned int disass_jns(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x79\x10", 2); // jns 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JNS");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JNS");
            
            
            code = string("\x0f\x89\x50\x34\x12\x00", 6 ); // jns 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JNS");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JNS");
            
            
            return nb;
        }
        
        unsigned int disass_jo(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x70\x10", 2); // jo 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JO");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JO");
            
            
            code = string("\x0f\x80\x50\x34\x12\x00", 6 ); // jo 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JO");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JO");
            
            
            return nb;
        }
        
        unsigned int disass_jp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x7a\x10", 2); // jp 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JP");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JP");
            
            
            code = string("\x0f\x8a\x50\x34\x12\x00", 6 ); // jp 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JP");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JP");
            
            
            return nb;
        }
        
        unsigned int disass_js(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x78\x10", 2); // js 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JS");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute JS");
            
            code = string("\x0f\x88\x50\x34\x12\x00", 6 ); // js 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JS");
            
            /* Not taken */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x2006, "ArchX86: failed to disassembly and/or execute JS");
            
            
            return nb;
        }
        
        unsigned int disass_lahf(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x9f", 1); // lahf
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::SF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::ZF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::PF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0b1101011100000000, "ArchX86: failed to disassembly and/or execute LAHF");
           
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0b0010101000000000));
            sym.cpu.ctx().set(X86::SF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::ZF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::AF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::PF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0b1101011100000000, "ArchX86: failed to disassembly and/or execute LAHF");
            return nb;
        }
        
        unsigned int disass_lea(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\x8d\x04\x9d\x02\x00\x00\x00", 7); // lea eax, dword ptr [ebx*4 + 2]
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 7);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x82, "ArchX86: failed to disassembly and/or execute LEA");
           
            code = string("\x8d\x04\x9d\x02\x00\x01\x00", 7); // lea eax, dword ptr[ 0x10000 + ebx*4 + 2]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 7);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10082, "ArchX86: failed to disassembly and/or execute LEA");
            
            code = string("\x66\x8d\x04\x9d\x02\x00\x01\x00", 8); // lea ax, dword ptr[ 0x10000 + ebx*4 + 2]
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 8);
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x20));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x82, "ArchX86: failed to disassembly and/or execute LEA");
            
            code = string("\x67\x8D\x87\x34\x12", 5); // lea eax, [ 0x1234 + bx]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 34));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x10020));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1254, "ArchX86: failed to disassembly and/or execute LEA");
            
            return nb;
        }
        
        unsigned int disass_lodsb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\xac", 1); // lodsb
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(8, 0xAA));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12AA, "ArchX86: failed to disassembly and/or execute LODSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x1801, "ArchX86: failed to disassembly and/or execute LODSB");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12AA, "ArchX86: failed to disassembly and/or execute LODSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x17ff, "ArchX86: failed to disassembly and/or execute LODSB");
            
            return nb;
        }
        
        unsigned int disass_lodsd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\xad", 1); // lodsd
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0x12345678));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x2));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12345678, "ArchX86: failed to disassembly and/or execute LODSD");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x1804, "ArchX86: failed to disassembly and/or execute LODSD");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12345678, "ArchX86: failed to disassembly and/or execute LODSD");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x17fc, "ArchX86: failed to disassembly and/or execute LODSD");
            
            return nb;
        }
        
        unsigned int disass_lodsw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\x66\xad", 2); // lodsw
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(16, 0x1234));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 42));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute LODSW");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x1802, "ArchX86: failed to disassembly and/or execute LODSW");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10000));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x11234, "ArchX86: failed to disassembly and/or execute LODSW");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x17fe, "ArchX86: failed to disassembly and/or execute LODSW");
            
            return nb;
        }
        
        unsigned int disass_mov(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\xb0\x12", 2); // mov al, 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1100));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1112, "ArchX86: failed to disassembly and/or execute MOV");
            
            code = string("\x66\xb8\x34\x12", 4); // mov ax, 0x1234
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1100));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute MOV");
            
            code = string("\xa1\x00\x17\x00\x00", 5); // mov eax, dword ptr [0x1700]
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(32, 0x07654321));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x11dd00));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x07654321, "ArchX86: failed to disassembly and/or execute MOV");
            
            code = string("\x88\x18", 2); // mov byte ptr [eax], bl
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1234));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.mem->read(0x1800, 1).as_uint() == 0x34, "ArchX86: failed to disassembly and/or execute MOV");
            
            return nb;
        }
        
        unsigned int disass_movapd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x28\xC1", 4); // movapd xmm0, xmm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "0000045600000123"));
            sym.run_from(0x1000, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x45600000123", "ArchX86: failed to disassembly and/or execute MOVAPD");   

            code = string("\x66\x0F\x28\x00", 4); // movapd xmm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.mem->write(0x1908, 0xabcd, 8);
            sym.run_from(0x1010, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xabcddeadbeef87654321", "ArchX86: failed to disassembly and/or execute MOVAPD");

            code = string("\x66\x0F\x29\x30", 4); // movapd [eax], xmm6
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM6, exprcst(512, "89769876aaaa000000001234"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.mem->read(0x1800, 8).as_uint() == 0xaaaa000000001234, "ArchX86: failed to disassembly and/or execute MOVAPD");
            nb += _assert(  sym.mem->read(0x1808, 8).as_uint() == 0x89769876, "ArchX86: failed to disassembly and/or execute MOVAPD");

            return nb;
        }

        
        unsigned int disass_movaps(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\x28\xC1", 3); // movaps xmm0, xmm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "0000045600000123"));
            sym.run_from(0x1000, 1);
            nb += _assert_bignum_eq(sym.cpu.ctx().get(X86::ZMM0), "0x45600000123", "ArchX86: failed to disassembly and/or execute MOVAPS");   

            code = string("\x0F\x28\x00", 3); // movaps xmm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.mem->write(0x1908, 0xabcd, 8);
            sym.run_from(0x1010, 1);
            nb += _assert_bignum_eq(sym.cpu.ctx().get(X86::ZMM0), "0xabcddeadbeef87654321", "ArchX86: failed to disassembly and/or execute MOVAPS");   

            code = string("\x0F\x29\x30", 3); // movaps [eax], xmm6
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM6, exprcst(512, "f000000089769876aaaabbbb00001234"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.mem->read(0x1800, 8).as_uint() == 0xaaaabbbb00001234, "ArchX86: failed to disassembly and/or execute MOVAPS");
            nb += _assert(  sym.mem->read(0x1808, 8).as_uint() == 0xf000000089769876, "ArchX86: failed to disassembly and/or execute MOVAPS");

            return nb;
        }

        unsigned int disass_movd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            // On XMM registers
            code = string("\x66\x0F\x7E\xC0", 4); // movd eax, xmm0
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 123));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 456));
            sym.run_from(0x1000, 1);
            nb += _assert( sym.cpu.ctx().get(X86::EAX).as_uint() == 123, "ArchX86: failed to disassembly and/or execute MOVD");

            code = string("\x66\x0F\x7E\x00", 4); // movd [eax], xmm0
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 123));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.mem->read(0x1900, 4).as_uint() == 123, "ArchX86: failed to disassembly and/or execute MOVD");

            code = string("\x66\x0F\x6E\xC0", 4); // movd xmm0, eax
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "35165451354615165121", 16));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xdeadbeef));
            sym.run_from(0x1010, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xdeadbeef", "ArchX86: failed to disassembly and/or execute MOVD");

            code = string("\x66\x0F\x6E\x00", 4); // movd xmm0, [eax]
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "8976987600001234", 16));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.mem->write(0x1800, 0xdeadbeef, 8);
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xdeadbeef", "ArchX86: failed to disassembly and/or execute MOVD");

            // On MMX registers
            code = string("\x0F\x7E\xC0", 3); // movd eax, mm0
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1234567812345678));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 456));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12345678, "ArchX86: failed to disassembly and/or execute MOVD");

            code = string("\x0F\x7E\x00", 3); // movd [eax], mm0
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 12345));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.mem->read(0x1900, 4).as_uint() == 12345, "ArchX86: failed to disassembly and/or execute MOVD");

            code = string("\x0F\x6E\xC0", 3); // movd mm0, eax
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1354615165121));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xdeadbeef));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xdeadbeef, "ArchX86: failed to disassembly and/or execute MOVD");
          
            code = string("\x0F\x6E\x00", 3); // movd mm0, [eax]
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1111189769876));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.mem->write(0x1800, 0xdeadbeef, 4);
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xdeadbeef, "ArchX86: failed to disassembly and/or execute MOVD");
          
            return nb;
        }
        
        
        unsigned int disass_movdqa(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x6F\xC1", 4); // movdqa xmm0, xmm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "0000045600000123"));
            sym.run_from(0x1000, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x45600000123", "ArchX86: failed to disassembly and/or execute MOVDQA");   

            code = string("\x66\x0F\x6F\x00", 4); // movdqa xmm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.mem->write(0x1908, 0xabcd, 8);
            sym.run_from(0x1010, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0) , "0xabcddeadbeef87654321", "ArchX86: failed to disassembly and/or execute MOVDQA");

            code = string("\x66\x0F\x7F\x30", 4); // movdqa [eax], xmm6
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM6, exprcst(512, "897698760000000000001234"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.mem->read(0x1800, 8).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute MOVDQA");
            nb += _assert(  sym.mem->read(0x1808, 8).as_uint() == 0x89769876, "ArchX86: failed to disassembly and/or execute MOVDQA");

            return nb;
        }

        unsigned int disass_movhps(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\x16\x00", 3); // movhps xmm0, [eax]
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 1));
            sym.mem->write(0x1800, 0xdeadbeef3333, 8);
            sym.run_from(0x1000, 1);
            nb += _assert_bignum_eq(sym.cpu.ctx().get(X86::ZMM0), "0xdeadbeef33330000000000000001", "ArchX86: failed to disassembly and/or execute MOVHPS");   

            code = string("\x0F\x17\x00", 3); // movhps [eax], xmm0
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "12340000000000000000"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.mem->read(0x1900, 8).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute MOVHPS");

            return nb;
        }
        
        unsigned int disass_movq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\x6F\xC1", 3); // movq mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x12345678deadbeef));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x12345678deadbeef, "ArchX86: failed to disassembly and/or execute MOVQ");   

            code = string("\x0F\x6F\x00", 3); // movq mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xdeadbeef87654321, "ArchX86: failed to disassembly and/or execute MOVQ");

            code = string("\xF3\x0F\x7E\xC7", 4); // movq xmm0, xmm7
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "8976987600000000"));
            sym.cpu.ctx().set(X86::ZMM7, exprcst(512, 0x1234));
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1234", "ArchX86: failed to disassembly and/or execute MOVQ");   

            code = string("\xF3\x0F\x7E\x00", 4); // movq xmm0, [rax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xabcd, 8);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "8976987600000000"));
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xabcd", "ArchX86: failed to disassembly and/or execute MOVQ");   

            return nb;
        }
        
        
        unsigned int disass_movsb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xa4", 1); // movsb
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(8, 0x12));
            sym.mem->write(0x1900, exprcst(8, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x18ff, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x17ff, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.mem->read(0x1900, 1).as_uint() == 0x12, "ArchX86: failed to disassembly and/or execute MOVSB");
            
            sym.mem->write(0x1800, exprcst(16, 0x12));
            sym.mem->write(0x1900, exprcst(16, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x1901, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x1801, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.mem->read(0x1900, 1).as_uint() == 0x12, "ArchX86: failed to disassembly and/or execute MOVSB");
            
            return nb;
        }
        
        unsigned int disass_movsd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xA5", 1); // movsd
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(32, 0x1000babe));
            sym.mem->write(0x1900, exprcst(32, 0xAAAAAAAA));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x18fc, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x17fc, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.mem->read(0x1900, 4).as_uint() == 0x1000babe, "ArchX86: failed to disassembly and/or execute MOVSD");
            
            sym.mem->write(0x1800, exprcst(32, 0x1000babe));
            sym.mem->write(0x1900, exprcst(32, 0xAAAAAAAA));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x1904, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x1804, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.mem->read(0x1900, 4).as_uint() == 0x1000babe, "ArchX86: failed to disassembly and/or execute MOVSD");
            
            code = string("\xF2\x0F\x10\xC1", 4); // movsd xmm0, xmm1
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, 0x1234));
            sym.run_from(0x1010, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1234", "ArchX86: failed to disassembly and/or execute MOVSD");

            code = string("\xF2\x0F\x10\x00", 4); // movsd xmm0, [eax]
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "976987689675454545"));
            sym.mem->write(0x1900, 0xabcdef, 8);
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq(sym.cpu.ctx().get(X86::ZMM0), "0xabcdef", "ArchX86: failed to disassembly and/or execute MOVSD");

            code = string("\xF2\x0F\x11\x08", 4); // movsd [eax], xmm1
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, 0xcafebabe1234));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.mem->read(0x1900, 8).as_uint() == 0xcafebabe1234, "ArchX86: failed to disassembly and/or execute MOVSD");

            return nb;
        }

        unsigned int disass_movsw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xA5", 2); // movsw
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0x1234));
            sym.mem->write(0x1900, exprcst(16, 0xAAAA));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x18fe, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x17fe, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.mem->read(0x1900, 2).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute MOVSW");
            
            sym.mem->write(0x1800, exprcst(16, 0x1234));
            sym.mem->write(0x1900, exprcst(16, 0xAAAA));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x1800));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x1902, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x1802, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.mem->read(0x1900, 2).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute MOVSW");
            
            return nb;
        }
        
        unsigned int disass_movsx(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\xBE\xC3", 4); // movsx ax, bl
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1A));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1A, "ArchX86: failed to disassembly and/or execute MOVSX");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x1A, "ArchX86: failed to disassembly and/or execute MOVSX");
            
            
            code = string("\x0F\xBF\x03", 3); // movsx eax, word ptr [ebx]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0xAAAA));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1800));
            sym.run_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xffffAAAA, "ArchX86: failed to disassembly and/or execute MOVSX");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x1800, "ArchX86: failed to disassembly and/or execute MOVSX");
            
            return nb;
        }
        
        unsigned int disass_movzx(MaatEngine& sym){
            unsigned int nb = 0;
            string code;            

            code = string("\x66\x0F\xB6\xC3", 4); // movzx ax, bl
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xff));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xff, "ArchX86: failed to disassembly and/or execute MOVZX");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0xff, "ArchX86: failed to disassembly and/or execute MOVZX");
            
            
            code = string("\x0F\xB7\x03", 3); // movzx eax, word ptr [ebx]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0xAAAA));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1800));
            sym.run_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xAAAA, "ArchX86: failed to disassembly and/or execute MOVZX");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x1800, "ArchX86: failed to disassembly and/or execute MOVZX");
            
            return nb;
        }
        
        unsigned int disass_mul(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* One-operand */
            code = string("\xF6\xE3", 2); // mul bl
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x23));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x10));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x230, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x10, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute MUL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 3));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 6, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 3, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute MUL");
            
            
            code = string("\x66\xF7\xE3", 3); // mul bx
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10001234));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xffff));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x11001234));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1000edcc, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0xffff, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0x11001233, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1013, "ArchX86: failed to disassembly and/or execute MUL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1234));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0x11001234));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x0000, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0x11000000, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1013, "ArchX86: failed to disassembly and/or execute MUL");
            
            
            code = string("\xf7\xe3", 2); // mul ebx
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x4823424));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0xAAAAAA));
            sym.run_from(0x1020, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xf9dc88e0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x12345678, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EDX).as_uint() == 0x5213a2, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1022, "ArchX86: failed to disassembly and/or execute MUL");
            
            return nb;
            
        }
        
        unsigned int disass_neg(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xF6\xDC", 2); // neg ah
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x8000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x8000, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            // nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xff00));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x0100, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            // nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            
            code = string("\xF7\xD8", 2); // neg eax
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1));
            sym.run_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xffffffff, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            // nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x0));
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            // nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute NEG");
            
            return nb;
        }
        
        unsigned int disass_nop(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            /* TODO - ghidra just ommits NOP entirely 
             * no pcode is generated
            code = string("\x90", 1); // nop
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1001, "ArchX86: failed to disassembly and/or execute NOP");
            */
            return nb;
        }
        
        unsigned int disass_not(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xF6\xD4", 2); // not ah
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x11110f11));
            sym.run_from(0x1000, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1111f011, "ArchX86: failed to disassembly and/or execute NOT");
            
            code = string("\xF7\xD0", 2); // not eax
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x80000000));
            sym.run_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x7fffffff, "ArchX86: failed to disassembly and/or execute NOT");
            
            return nb;
        }
        
        unsigned int disass_or(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            // On 32 bits
            // 678 | 0xfff.....
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 678));
            code = string("\x09\xD8", 2); // or eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xffffffff,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            
            // 0xff000000 | 0x000000ff
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xff000000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xff));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xff0000ff,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
                            
            // 0 | 0 
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
                            
            // On 16 bits... 
            // 0xa00000f0 | 0x0b0000ff
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xa00000f0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0b0000fe));
            code = string("\x66\x09\xD8", 3); // or ax, bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xa00000fe,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            
            return nb;
        }


        unsigned int disass_paddd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\x0F\xFE\xC1", 3); // paddd mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1234));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xffff000000000000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffff000000001234, "ArchX86: failed to disassembly and/or execute PADDD");

            code = string("\x0F\xFE\x00", 3); // paddd mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ffffffffff));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 1, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab1112ff00000000, "ArchX86: failed to disassembly and/or execute PADDD");

            code = string("\x66\x0F\xFE\xC1", 4); // paddd xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "0ffffffffffffffe0000000100000012"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "00000001000000020000000100000001"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x10000000000000000000000200000013", "ArchX86: failed to disassembly and/or execute PADDD");

            code = string("\x66\x0F\xFE\x00", 4); // paddd xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00000004"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0x1ffffffff, 8);
            sym.mem->write(0x1908, 0x1000, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq(  sym.cpu.ctx().get(X86::ZMM0), "0xbbcdab11130000000003", "ArchX86: failed to disassembly and/or execute PADDD");

            return nb;
        }
        
        
        unsigned int disass_paddq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xD4\xC1", 3); // paddq mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1234));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xffff000000000000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffff000000001234, "ArchX86: failed to disassembly and/or execute PADDQ");

            code = string("\x0F\xD4\x00", 3); // paddq mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ff00cd77ef));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 1, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab1112ff00cd77f0, "ArchX86: failed to disassembly and/or execute PADDQ");

            code = string("\x66\x0F\xD4\xC1", 4); // paddq xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcd000000000000000c"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "10000000000000001"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xabce000000000000000d", "ArchX86: failed to disassembly and/or execute PADDQ");

            code = string("\x66\x0F\xD4\x00", 4); // paddq xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 2, 8);
            sym.mem->write(0x1908, 0x1000, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xbbcdab1112ff00cd77f1", "ArchX86: failed to disassembly and/or execute PADDQ");

            return nb;
        }

        unsigned int disass_pcmpeqb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\x74\xC1", 3); // pcmpeqb mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab00120000cd00ef));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xab33123333cd33ef));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xff00ff0000ff00ff, "ArchX86: failed to disassembly and/or execute PCMPEQB");   
            nb += _assert(  sym.cpu.ctx().get(X86::MM1).as_uint() == 0xab33123333cd33ef, "ArchX86: failed to disassembly and/or execute PCMPEQB");

            code = string("\x0F\x74\x00", 3); // pcmpeqb mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef00000000));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.run_from(0x1010, 1);
            nb += _assert( sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffffffff00000000, "ArchX86: failed to disassembly and/or execute PCMPEQB");

            code = string("\x66\x0F\x74\xC1", 4); // pcmpeqb xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234ab00120000cd00ef"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "1234ab33123333cd33ef"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffffffffffffff00ff0000ff00ff", "ArchX86: failed to disassembly and/or execute PCMPEQB");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x1234ab33123333cd33ef", "ArchX86: failed to disassembly and/or execute PCMPEQB");

            code = string("\x66\x0F\x74\x00", 4); // pcmpeqb xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234ab00120000cd00ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0x1200, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffffffffff00ffffffff00000000", "ArchX86: failed to disassembly and/or execute PCMPEQB");
            return nb;
        }

        unsigned int disass_pcmpeqd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\x76\xC1", 3); // pcmpeqd mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab33123300cd33ef));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xab33123333cd33ef));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffffffff00000000, "ArchX86: failed to disassembly and/or execute PCMPEQD");   
            nb += _assert(  sym.cpu.ctx().get(X86::MM1).as_uint() == 0xab33123333cd33ef, "ArchX86: failed to disassembly and/or execute PCMPEQD");

            code = string("\x0F\x76\x00", 3); // pcmpeqd mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef00000000));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffffffff00000000, "ArchX86: failed to disassembly and/or execute PCMPEQD");

            code = string("\x66\x0F\x76\xC1", 4); // pcmpeqd xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234ab00120033cd33ef"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "1234ab33123333cd33ef"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffffffffffff00000000ffffffff", "ArchX86: failed to disassembly and/or execute PCMPEQD");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x1234ab33123333cd33ef", "ArchX86: failed to disassembly and/or execute PCMPEQD");

            code = string("\x66\x0F\x76\x00", 4); // pcmpeqd xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234ab00120000cd00ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0x1200, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffff00000000ffffffff00000000", "ArchX86: failed to disassembly and/or execute PCMPEQD");

            return nb;
        }
        
        unsigned int disass_pcmpgtd(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\x0F\x66\xC1", 3); // pcmpgtd mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab33126000cdffef));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xab33123333cd33ef));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffffffff00000000, "ArchX86: failed to disassembly and/or execute PCMPGTD");   
            nb += _assert(  sym.cpu.ctx().get(X86::MM1).as_uint() == 0xab33123333cd33ef, "ArchX86: failed to disassembly and/or execute PCMPGTD");

            code = string("\x0F\x66\x00", 3); // pcmpgtd mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef00000000));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffffffff, "ArchX86: failed to disassembly and/or execute PCMPGTD");

            code = string("\x66\x0F\x66\xC1", 4); // pcmpgtd xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "12340b00120042cd33ef"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "12340b33123333cd33ef"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffff", "ArchX86: failed to disassembly and/or execute PCMPGTD");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x12340b33123333cd33ef", "ArchX86: failed to disassembly and/or execute PCMPGTD");

            code = string("\x66\x0F\x66\x00", 4); // pcmpgtd xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234ab001200ffffffff"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200fffff000, 8);
            sym.mem->write(0x1908, 0x1200, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffff00000000ffffffff", "ArchX86: failed to disassembly and/or execute PCMPGTD");

            return nb;
        }

        unsigned int disass_pextrb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x3A\x14\xC0\x03", 6); // pextrb eax, xmm0, 3
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdf68761234567811223344"));
            sym.cpu.ctx().set(X86::EAX, 0xffffffff);
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).size() == 32, "ArchX86: failed to disassembly and/or execute PEXTRB");
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x11, "ArchX86: failed to disassembly and/or execute PEXTRB");

            code = string("\x66\x0F\x3A\x14\xC0\x08", 6); // pextrb eax, xmm0, 8
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdf68761234567811223344"));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).size() == 32, "ArchX86: failed to disassembly and/or execute PEXTRB");
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x76, "ArchX86: failed to disassembly and/or execute PEXTRB");

            code = string("\x66\x0F\x3A\x14\x00\x02", 6); // pextrb [eax], xmm0, 2
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));

            sym.run_from(0x1030, 1);
            nb += _assert(  sym.mem->read(0x1900, 1).as_uint() == 0xcd, "ArchX86: failed to disassembly and/or execute PEXTRB");

            return nb;
        }
        
        unsigned int disass_pminub(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xDA\xC1", 3); // pminub mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ff00cd77ef));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xab33123333cd33ef));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab11123300cd33ef, "ArchX86: failed to disassembly and/or execute PMINUB");

            code = string("\x0F\xDA\x00", 3); // pminub mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ff00cd77ef));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab33123333cd33ef, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab11123300cd33ef, "ArchX86: failed to disassembly and/or execute PMINUB");

            code = string("\x66\x0F\xDA\xC1", 4); // pminub xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "ff1234ab33123333cd33ef"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1234ab11123300cd33ef", "ArchX86: failed to disassembly and/or execute PMINUB");
        
            code = string("\x66\x0F\xDA\x00", 4); // pminub xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab33123333cd33ef, 8);
            sym.mem->write(0x1908, 0xff1234, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1234ab11123300cd33ef", "ArchX86: failed to disassembly and/or execute PMINUB");

            return nb;
        }

        unsigned int disass_pmovmskb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xD7\xC0", 3); // pmovmskb eax, mm0
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xff7f8012cc63ff77));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0b10101010, "ArchX86: failed to disassembly and/or execute PMOVMSKB");   

            code = string("\x66\x0F\xD7\xC0", 4); // pmovmskb eax, xmm0
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "ffffffff7f7f7f7fff7f8012cc63ff77"));

            sym.run_from(0x1010, 1);
            nb += _assert( sym.cpu.ctx().get(X86::EAX).as_uint() == 0b1111000010101010, "ArchX86: failed to disassembly and/or execute PMOVMSKB");

            return nb;
        }
        
        unsigned int disass_pop(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1800));
            code = string("\x58", 1); // pop eax
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(32, 0x12345678));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12345678,
                            "ArchX86: failed to disassembly and/or execute POP");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1804,
                            "ArchX86: failed to disassembly and/or execute POP");
                            
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1800));
            code = string("\x66\x8F\x00", 3); // pop word ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.mem->write(0x1800, exprcst(16, 0x1234));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1700,
                            "ArchX86: failed to disassembly and/or execute POP");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1802,
                            "ArchX86: failed to disassembly and/or execute POP");
            nb += _assert(  sym.mem->read(0x1700, 2).as_uint() == 0x1234,
                            "ArchX86: failed to disassembly and/or execute POP");
            return nb;
        }
        
        unsigned int disass_popad(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1800));
            code = string("\x61", 1); // popad
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(32, 0xAAAAAAAA));
            sym.mem->write(0x1804, exprcst(32, 0xBBBBBBBB));
            sym.mem->write(0x1808, exprcst(32, 0xCCCCCCCC));
            sym.mem->write(0x180C, exprcst(32, 0x12345678));
            sym.mem->write(0x1810, exprcst(32, 0xDDDDDDDD));
            sym.mem->write(0x1814, exprcst(32, 0xEEEEEEEE));
            sym.mem->write(0x1818, exprcst(32, 0xFFFFFFFF));
            sym.mem->write(0x181c, exprcst(32, 0x11111111));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EDI).as_uint() == 0xAAAAAAAA,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESI).as_uint() == 0xBBBBBBBB,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EBP).as_uint() == 0xCCCCCCCC,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EBX).as_uint() == 0xDDDDDDDD,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EDX).as_uint() == 0xEEEEEEEE,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ECX).as_uint() == 0xFFFFFFFF,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x11111111,
                            "ArchX86: failed to disassembly and/or execute POPAD");
                            
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1820,
                            "ArchX86: failed to disassembly and/or execute POPAD");

            return nb;
        }
        
        unsigned int disass_por(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xEB\xC1", 3); // por mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xffff0000));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xffff0000ffff0000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffff0000ffff0000, "ArchX86: failed to disassembly and/or execute POR");   
            
            code = string("\x0F\xEB\x00", 3); // por mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef12340000, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xdeadbeef12340001, "ArchX86: failed to disassembly and/or execute POR");

            code = string("\x66\x0F\xEB\xC1", 4); // por xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 0));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "897698760000000000001234"));
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x897698760000000000001234", "ArchX86: failed to disassembly and/or execute POR");

            code = string("\x66\x0F\xEB\x00", 4); // por xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "10000000000000002"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.mem->write(0x1800, 0x12345, 8);
            sym.mem->write(0x1808, 0xaabbccddee, 8);
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xaabbccddef0000000000012347", "ArchX86: failed to disassembly and/or execute POR");

            return nb;
        }

        unsigned int disass_pshufd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x70\xC1\x1B", 5); // pshufd xmm0, xmm1, 0b00011011
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "deadbeef1111111112345678cafebabe"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xcafebabe1234567811111111deadbeef", "ArchX86: failed to disassembly and/or execute PSHUFD");

            code = string("\x66\x0F\x70\xC1\xCF", 5); // pshufd xmm0, xmm1, 0b11001111
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "deadbeef1111111112345678cafebabe"));

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xdeadbeefcafebabedeadbeefdeadbeef", "ArchX86: failed to disassembly and/or execute PSHUFD");

            code = string("\x66\x0F\x70\x00\xCF", 5); // pshufd xmm0, [eax], 0b11001111
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0x1111111122222222, 8);
            sym.mem->write(0x1908, 0x3333333344444444, 8);

            sym.run_from(0x1040, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x33333333222222223333333333333333", "ArchX86: failed to disassembly and/or execute PSHUFD");

            return nb;
        }
        
        unsigned int disass_pslld(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xF2\xC1", 3); // pslld mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1234));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x4));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x12340, "ArchX86: failed to disassembly and/or execute PSLLD");

            code = string("\x0F\xF2\x00", 3); // pslld mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ff00cd77ef));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 64, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0, "ArchX86: failed to disassembly and/or execute PSLLD");

            code = string("\x66\x0F\xF2\xC1", 4); // pslld xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "ffffffffffffffff0000000000000012"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "135246535440000000000000008"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffff00ffffff000000000000001200", "ArchX86: failed to disassembly and/or execute PSLLD");

            code = string("\x66\x0F\xF2\x00", 4); // pslld xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 560, 8);
            sym.mem->write(0x1908, 0, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq(  sym.cpu.ctx().get(X86::ZMM0), "0x0", "ArchX86: failed to disassembly and/or execute PSLLD");

            code = string("\x66\x0F\x72\xF0\x0C", 5); // pslld xmm0, 12
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));

            sym.run_from(0x1040, 1);
            nb += _assert_bignum_eq(sym.cpu.ctx().get(X86::ZMM0), "0xabcd000112ff000d77ef000", "ArchX86: failed to disassembly and/or execute PSLLD");

            code = string("\x0F\x72\xF0\x08", 4); // pslld mm0, 8
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x123400001234));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x12340000123400, "ArchX86: failed to disassembly and/or execute PSLLD");

            return nb;
        }
        
        unsigned int disass_pslldq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            code = string("\x66\x0F\x73\xF8\x03", 5); // pslldq xmm0, 3
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcd00000000abcd12345678deadbeef"));

            sym.run_from(0x1040, 1);
            nb += _assert_bignum_eq(  sym.cpu.ctx().get(X86::ZMM0), "0xabcd12345678deadbeef000000", "ArchX86: failed to disassembly and/or execute PSLLDQ");

            code = string("\x66\x0F\x73\xF8\x0a", 5); // pslldq xmm0, 10
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcd00000000abcd12345678deadbeef"));

            sym.run_from(0x1050, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x5678deadbeef00000000000000000000", "ArchX86: failed to disassembly and/or execute PSLLDQ");
            
            code = string("\x66\x0F\x73\xF8\x42", 5); // pslldq xmm0, 0x42
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcd00000000abcd12345678deadbeef"));

            sym.run_from(0x1060, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x0", "ArchX86: failed to disassembly and/or execute PSLLDQ");

            return nb;
        }

        unsigned int disass_psllq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xF3\xC1", 3); // psllq mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1234));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x4));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x12340, "ArchX86: failed to disassembly and/or execute PSLLQ");

            code = string("\x0F\xF3\x00", 3); // psllq mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ff00cd77ef));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 64, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0, "ArchX86: failed to disassembly and/or execute PSLLQ");

            code = string("\x66\x0F\xF3\xC1", 4); // psllq xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "ffffffffffffffff0000000000000012"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "135246535440000000000000008"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "ffffffffffffff000000000000001200", "ArchX86: failed to disassembly and/or execute PSLLQ");

            code = string("\x66\x0F\xF3\x00", 4); // psllq xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 560, 8);
            sym.mem->write(0x1908, 0, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x0", "ArchX86: failed to disassembly and/or execute PSLLQ");

            code = string("\x66\x0F\x73\xF0\x0C", 5); // psllq xmm0, 12
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00cd77ef"));

            sym.run_from(0x1040, 1);
            nb += _assert_bignum_eq(sym.cpu.ctx().get(X86::ZMM0), "0xabcd000112ff00cd77ef000", "ArchX86: failed to disassembly and/or execute PSLLQ");

            code = string("\x0F\x73\xF0\x08", 4); // psllq mm0, 8
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0x1234));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x123400, "ArchX86: failed to disassembly and/or execute PSLLQ");

            return nb;
        }

        unsigned int disass_psubb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            /* TODO - error in ghidra lifter 
            code = string("\x0F\xF8\xC1", 3); // psubb mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xffff000000001234));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xffff000000001212));
            sym.run_from(0x1000, 1);

            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x0000000000000022, "ArchX86: failed to disassembly and/or execute PSUBB");
            

            code = string("\x0F\xF8\x00", 3); // psubb mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xab1112ffffffffff));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 1, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab1112fffffffffe, "ArchX86: failed to disassembly and/or execute PSUBB");
            */

            code = string("\x66\x0F\xF8\xC1", 4); // psubb xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "0ffffffffffffffe0000000100000012"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "00000001000000020000000100000001"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffefffffffc0000000000000011", "ArchX86: failed to disassembly and/or execute PSUBB");

            code = string("\x66\x0F\xF8\x00", 4); // psubb xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "abcdab1112ff00000004"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab00000000000003, 8);
            sym.mem->write(0x1908, 0x1000, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x9bcd001112ff00000001", "ArchX86: failed to disassembly and/or execute PSUBB");

            return nb;
        }
        
        unsigned int disass_punpckhdq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x6A\xC1", 4); // punpckhdq xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "123412345678cafebabe"));
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x123400001234", "ArchX86: failed to disassembly and/or execute PUNPCKHDQ");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x123412345678cafebabe", "ArchX86: failed to disassembly and/or execute PUNPCKHDQ");

            code = string("\x66\x0F\x6A\x00", 4); // punpckhdq xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0xffffffffffffffff, 8);
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffff00000000ffffffff00001234", "ArchX86: failed to disassembly and/or execute PUNPCKHDQ");

            code = string("\x0F\x6A\xC1", 3); // punpckhdq mm0, mm1
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x12345678cafebabe));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0x12345678deadbeef, "ArchX86: failed to disassembly and/or execute PUNPCKHDQ");

            code = string("\x0F\x6A\x00", 3); // punpckhdq mm0, [eax]
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200abababab, 8);
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab001200deadbeef, "ArchX86: failed to disassembly and/or execute PUNPCKHDQ");

            return nb;
        }


        unsigned int disass_punpckhqdq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x6D\xC1", 4); // punpckhqdq xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "123412345678cafebabe"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x12340000000000001234", "ArchX86: failed to disassembly and/or execute PUNPCKHQDQ");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x123412345678cafebabe", "ArchX86: failed to disassembly and/or execute PUNPCKHQDQ");

            code = string("\x66\x0F\x6D\x00", 4); // punpckhqdq xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0xffffffffffffffff, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xffffffffffffffff0000000000001234", "ArchX86: failed to disassembly and/or execute PUNPCKHQDQ");

            return nb;
        }
        
        unsigned int disass_punpcklbw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x60\xC1", 4); // punpcklbw xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "123412345678cafebabe"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x12de34ad56be78efca12fe12ba12be12", "ArchX86: failed to disassembly and/or execute PUNPCKLBW");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x123412345678cafebabe", "ArchX86: failed to disassembly and/or execute PUNPCKLBW");

            code = string("\x66\x0F\x60\x00", 4); // punpcklbw xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0xffffffffffffffff, 8);
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xabde00ad12be00efff12ff12ff12ff12", "ArchX86: failed to disassembly and/or execute PUNPCKLBW");

            code = string("\x0F\x60\xC1", 3); // punpcklbw mm0, mm1
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x12345678cafebabe));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xca12fe12ba12be12, "ArchX86: failed to disassembly and/or execute PUNPCKLBW");
            
            code = string("\x0F\x60\x00", 3); // punpcklbw mm0, [eax]
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200abababab, 8);
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xab12ab12ab12ab12, "ArchX86: failed to disassembly and/or execute PUNPCKLBW");

            return nb;
        }

        unsigned int disass_punpckldq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;            

            code = string("\x66\x0F\x62\xC1", 4); // punpckldq xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "123412345678cafebabe"));

            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x12345678deadbeefcafebabe12121212", "ArchX86: failed to disassembly and/or execute PUNPCKLDQ");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x123412345678cafebabe", "ArchX86: failed to disassembly and/or execute PUNPCKLDQ");

            code = string("\x66\x0F\x62\x00", 4); // punpckldq xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0xffffffffffffffff, 8);
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xab001200deadbeefffffffff12121212", "ArchX86: failed to disassembly and/or execute PUNPCKLDQ");

            code = string("\x0F\x62\xC1", 3); // punpckldq mm0, mm1
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x12345678cafebabe));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xcafebabe12121212, "ArchX86: failed to disassembly and/or execute PUNPCKLDQ");
            
            code = string("\x0F\x62\x00", 3); // punpckldq mm0, [eax]
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200abababab, 8);
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xabababab12121212, "ArchX86: failed to disassembly and/or execute PUNPCKLDQ");

            return nb;
        }

        unsigned int disass_punpcklqdq(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x6C\xC1", 4); // punpcklqdq xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "123412345678cafebabe"));
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x12345678cafebabedeadbeef12121212", "ArchX86: failed to disassembly and/or execute PUNPCKLQDQ");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x123412345678cafebabe", "ArchX86: failed to disassembly and/or execute PUNPCKLQDQ");

            code = string("\x66\x0F\x6C\x00", 4); // punpcklqdq xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0xffffffffffffffff, 8);

            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xab001200ffffffffdeadbeef12121212", "ArchX86: failed to disassembly and/or execute PUNPCKLQDQ");

            return nb;
        }
        
        unsigned int disass_punpcklwd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x61\xC1", 4); // punpcklwd xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "123412345678cafebabe"));
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1234dead5678beefcafe1212babe1212", "ArchX86: failed to disassembly and/or execute PUNPCKLWD");   
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM1), "0x123412345678cafebabe", "ArchX86: failed to disassembly and/or execute PUNPCKLWD");

            code = string("\x66\x0F\x61\x00", 4); // punpcklwd xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "1234deadbeef12121212"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200ffffffff, 8);
            sym.mem->write(0x1908, 0xffffffffffffffff, 8);
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xab00dead1200beefffff1212ffff1212", "ArchX86: failed to disassembly and/or execute PUNPCKLWD");

            code = string("\x0F\x61\xC1", 3); // punpcklwd mm0, mm1
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0x12345678cafebabe));
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xcafe1212babe1212, "ArchX86: failed to disassembly and/or execute PUNPCKLWD");
            
            code = string("\x0F\x61\x00", 3); // punpcklwd mm0, [eax]
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xdeadbeef12121212));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xab001200abababab, 8);
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xabab1212abab1212, "ArchX86: failed to disassembly and/or execute PUNPCKLWD");

            return nb;
        }
        
        unsigned int disass_push(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1804));
            code = string("\x50", 1); // push eax
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1800,
                            "ArchX86: failed to disassembly and/or execute PUSH");
            nb += _assert(  (uint32_t)sym.mem->read(0x1800, 4).as_uint() == 0xffffffff,
                            "ArchX86: failed to disassembly and/or execute PUSH");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1804));
            code = string("\x66\xFF\x30", 3); // push word ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(16, 0x1234));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1802,
                            "ArchX86: failed to disassembly and/or execute PUSH");
            nb += _assert(  (uint16_t)sym.mem->read(0x1802, 2).as_uint() == 0x1234,
                            "ArchX86: failed to disassembly and/or execute PUSH");
                            
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1804));
            code = string("\x66\xFF\x34\x24", 4); // push word ptr [esp]
            sym.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1804, exprcst(16, 0xABCD));
            sym.run_from(0x1180, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1802,
                            "ArchX86: failed to disassembly and/or execute PUSH");
            nb += _assert(  (uint16_t)sym.mem->read(0x1802, 2).as_uint() == 0xABCD,
                            "ArchX86: failed to disassembly and/or execute PUSH");
               
            return nb;
        }

        unsigned int disass_pushad(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1820));
            code = string("\x60", 1); // pushad
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xAAAAAAAA));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0xBBBBBBBB));
            sym.cpu.ctx().set(X86::EDX, exprcst(32, 0xCCCCCCCC));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xDDDDDDDD));
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1820));
            sym.cpu.ctx().set(X86::EBP, exprcst(32, 0xEEEEEEEE));
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0xFFFFFFFF));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x11111111));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x181c, 4).as_uint() == 0xAAAAAAAA,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1818, 4).as_uint() == 0xBBBBBBBB,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1814, 4).as_uint() == 0xCCCCCCCC,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1810, 4).as_uint() == 0xDDDDDDDD,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x180c, 4).as_uint() == 0x1820,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1808, 4).as_uint() == 0xEEEEEEEE,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1804, 4).as_uint() == 0xFFFFFFFF,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1800, 4).as_uint() == 0x11111111,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");

            return nb;
        }

        unsigned int disass_pushfd(MaatEngine& sym){
            unsigned int nb = 0;
            string code("\x9C", 1); // pushfd
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EFLAGS, 13);
            sym.cpu.ctx().set(X86::ESP, 0x1904);
            
            sym.run_from(0x1000, 1);
            nb += _assert(
                sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1900,
                "ArchX86: failed to disassembly and/or execute PUSHFD"
            );
            nb += _assert(
                sym.mem->read(0x1900, 4).as_uint() == sym.cpu.ctx().get(X86::EFLAGS).as_uint(),
                "ArchX86: failed to disassembly and/or execute PUSHFD"
            );

            return nb;
        }

        unsigned int disass_pxor(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xEF\xC1", 3); // pxor mm0, mm1
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 0xffff0000));
            sym.cpu.ctx().set(X86::MM1, exprcst(64, 0xffff0000ffff0000));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xffff000000000000, "ArchX86: failed to disassembly and/or execute PXOR");   
            
            code = string("\x0F\xEF\x00", 3); // pxor mm0, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::MM0, exprcst(64, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef12340000, 8);
            sym.run_from(0x1010, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::MM0).as_uint() == 0xdeadbeef12340001, "ArchX86: failed to disassembly and/or execute PXOR");

            code = string("\x66\x0F\xEF\xC1", 4); // pxor xmm0, xmm1
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, 0x0));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "12340000000089769876"));
            sym.run_from(0x1020, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x12340000000089769876", "ArchX86: failed to disassembly and/or execute PXOR");

            code = string("\x66\x0F\xEF\x00", 4); // pxor xmm0, [eax]
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "10000000000000002"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1800));
            sym.mem->write(0x1800, 0x12345, 8);
            sym.mem->write(0x1808, 0xaabbccddee, 8);
            sym.run_from(0x1030, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0xaabbccddef0000000000012347", "ArchX86: failed to disassembly and/or execute PXOR");

            return nb;
        }

        unsigned int disass_rcl(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xC1\xD0\x07", 4); // rcl ax, 7
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x100c0, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute RCL");

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10010));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10800, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCL");

            code = string("\xD1\x10", 2); // rcl dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x44444445, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCL");

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000000));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute RCL");
            
            return nb;
        }
        
        unsigned int disass_rcr(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            code = string("\x66\xc1\xd8\x07", 4); // rcr ax, 7
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x11200));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10224, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x11240));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10024, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute RCR");
            
            code = string("\xD1\x18", 2); // rcr dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);   
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x91111111, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute RCR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x10000001));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x08000000, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute RCR");
            
            return nb;
        }
        
        unsigned int disass_ret(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xC3", 1); // ret
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1800));
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1700, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0x1700));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1804,
                            "ArchX86: failed to disassembly and/or execute RET");
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1700,
                            "ArchX86: failed to disassembly and/or execute RET");
                            
            
            code = string("\xc2\x30\x00", 3); // ret 0x30
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x1800));
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1700, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0x1700));

            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::ESP).as_uint() == 0x1834,
                            "ArchX86: failed to disassembly and/or execute RET");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1700,
                            "ArchX86: failed to disassembly and/or execute RET");
               
            return nb;
        }
        
        unsigned int disass_rol(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xC1\xC0\x07", 4); // rol ax, 7
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10081, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute ROL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10010));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10800, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROL");
            
            code = string("\xD1\x00", 2); // rol dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x44444444, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 3, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute ROL");
            
            return nb;
        }
        
        unsigned int disass_ror(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xC1\xC8\x07", 4); // ror ax, 7
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10204, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10018));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x13000, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROR");
            
            code = string("\xD1\x08", 2); // ror dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x11111111, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000000));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x40000000, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute ROR");
            
            return nb;
        }
        
        
        unsigned int disass_rorx(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xC4\xE3\x7B\xF0\xD8\x07", 6); // rorx ebx, eax, 7
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2); 

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x02000204, "ArchX86: failed to disassembly and/or execute RORX");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10018));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x30000200, "ArchX86: failed to disassembly and/or execute RORX");
            
            code = string("\xC4\xE3\x7B\xF0\x18\x01", 6); // rorx ebx, dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size()); 
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);  

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x11111111, "ArchX86: failed to disassembly and/or execute RORX");

            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000000));

            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() == 0x40000000, "ArchX86: failed to disassembly and/or execute RORX");

            return nb;
        }

        unsigned int disass_sal(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x66\xc1\xe0\x04", 4); // sal ax, 4
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x12010, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x11010));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10100, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SAL");
            
            code = string("\xd1\x20", 2); // sal dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x44444444, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAL");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 2, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SAL");
            
            return nb;
        }
        
        unsigned int disass_sar(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            code = string("\x66\xc1\xf8\x04", 4); // sar ax, 4
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10020, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1f008));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1ff00, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SAR");
            
            code = string("\xd1\x38", 2); // sar dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x11111111, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0xc0000000, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SAR");
            
            return nb;
        }
        
        unsigned int disass_shr(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            code = string("\x66\xc1\xe8\x04", 4); // shr ax, 4
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x10201));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10020, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SHR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1f008));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10f00, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SHR");
            
            code = string("\xd1\x28", 2); // shr dword ptr [eax], 1
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 1));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x11111111, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute SHR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::CF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::OF, exprcst(8, 0));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() == 0x40000000, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::CF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SHR");
            /* TODO - ghidra error, they forget to set OF for 1-bit shifts
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::OF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute SHR");
            */
            return nb;
        }

        unsigned int disass_scasb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xae", 1); // scasb
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1500, exprcst(8, 0xf));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xff));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x14ff,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            */

            sym.mem->write(0x1500, exprcst(8, 0xff));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x1501)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASB");
            */
            return nb;
        }
        
        unsigned int disass_scasd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xAf", 1); // scasd
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1500, exprcst(32, 0xAAAA));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xAAAA));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x14fc)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            */
            sym.mem->write(0x1500, exprcst(32, 0x1235));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1234));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x1504)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASD");
            */
            return nb;
        }
        
        unsigned int disass_scasw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xAf", 2); // scasw
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1500, exprcst(16, 0xAAAA));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xAAAA));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x14fe)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            */

            sym.mem->write(0x1500, exprcst(32, 0x1235));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1234));
            sym.cpu.ctx().set(X86::EDI, exprcst(32,0x1500));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == exprcst(32, 0x1502)->as_uint(),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SCASW");
            */
            return nb;
        }
     
        unsigned int disass_seta(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* With zf == 0 && cf == 0 */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x97\xc0", 3); // seta al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETA");
            
            
            /* Mem */
            code = string("\x0f\x97\x00", 3); // seta byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETA");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETA");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETA");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETA");
            return nb;
        }
        
        unsigned int disass_setae(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            /* With cf == 0 */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x93\xc0", 3); // setae al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETAE");
            
            
            /* Mem */
            code = string("\x0f\x93\x00", 3); // setae byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETAE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETAE");
                            
            
            return nb;
        }
        
        unsigned int disass_setb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* With cf == 1 */
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            
            /* Reg */
            code = string("\x0f\x92\xc0", 3); // setb al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETB");
            
            
            /* Mem */
            code = string("\x0f\x92\x00", 3); // setb byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETB");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETB");
                            
            
            return nb;
        }
        
        unsigned int disass_setbe(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With zf == 0 && cf == 0 */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x96\xc0", 3); // setbe al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETBE");
            
            
            /* Mem */
            code = string("\x0f\x96\x00", 3); // setbe byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETBE");
                            
            /* With condition -verified- */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETBE");
                            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETBE");
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETBE");
            return nb;
        }
        
        unsigned int disass_setg(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With zf == 0 && sf == of */

            /* Reg */
            code = string("\x0f\x9f\xc0", 3); // setg al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETG");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            /* Mem */
            code = string("\x0f\x9f\x00", 3); // setg byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETG");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            return nb;
        }
        
        unsigned int disass_setge(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With sf == of */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x9d\xc0", 3); // setge al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETGE");
            
            
            /* Mem */
            code = string("\x0f\x9d\x00", 3); // setge byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETGE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETGE");
                            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETGE");
            
            return nb;
        }
        
        unsigned int disass_setl(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With sf != of */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x9c\xc0", 3); // setl al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETL");
            
            
            /* Mem */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            code = string("\x0f\x9c\x00", 3); // setl byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETL");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETL");
                            
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETL");
            
            return nb;
        }
        
        unsigned int disass_setle(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With zf == 1 || sf != of */

            /* Reg */
            code = string("\x0f\x9e\xc0", 3); // setle al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETLE");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETLE");
            
            /* Mem */
            code = string("\x0f\x9e\x00", 3); // setle byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETLE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETLE");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETLE");
            
            return nb;
        }
        
        unsigned int disass_sete(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With zf == 1 */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            
            /* Reg */
            code = string("\x0f\x94\xc0", 3); // sete al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETE");
            
            
            /* Mem */
            code = string("\x0f\x94\x00", 3); // sete byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETE");
                            
            
            return nb;
        }
        
        unsigned int disass_setne(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With zf == 0 */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x95\xc0", 3); // setne al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNE");
            
            
            /* Mem */
            code = string("\x0f\x95\x00", 3); // setne byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNE");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETNE");
                            
            
            return nb;
        }
        
        unsigned int disass_setno(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With of == 0 */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x91\xc0", 3); // setno al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNO");
            
            
            /* Mem */
            code = string("\x0f\x91\x00", 3); // setno byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNO");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETNO");
                            
            
            return nb;
        }
        
        unsigned int disass_setnp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With pf == 0 */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x9b\xc0", 3); // setnp al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNP");
            
            
            /* Mem */
            code = string("\x0f\x9b\x00", 3); // setnp byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNP");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETNP");                   
            return nb;
        }
        
        unsigned int disass_setns(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With sf == 0 */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            
            /* Reg */
            code = string("\x0f\x99\xc0", 3); // setns al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNS");
            
            
            /* Mem */
            code = string("\x0f\x99\x00", 3); // setns byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETNS");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETNS");                   
            return nb;
        }
        
        unsigned int disass_seto(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With of == 1 */
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            
            /* Reg */
            code = string("\x0f\x90\xc0", 3); // seto al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETO");
            
            
            /* Mem */
            code = string("\x0f\x90\x00", 3); // seto byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETO");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::OF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETO");
                            
            
            return nb;
        }
        
        unsigned int disass_setp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With pf == 1 */
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            
            /* Reg */
            code = string("\x0f\x9a\xc0", 3); // setp al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETP");
            
            
            /* Mem */
            code = string("\x0f\x9a\x00", 3); // setp byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETP");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETP");                   
            return nb;
        }
        
        unsigned int disass_sets(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* With sf == 1 */
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            
            /* Reg */
            code = string("\x0f\x98\xc0", 3); // sets al
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,2));
            
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETS");
            
            
            /* Mem */
            code = string("\x0f\x98\x00", 3); // sets byte ptr [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SETS");
                            
            /* With condition not verified */
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SETS");                   
            return nb;
        }
        
        unsigned int disass_stc(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            sym.cpu.ctx().set(X86::CF, exprcst(8,0));

            code = string("\xf9", 1); // stc
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute STC");

            return nb;
        }
        
        unsigned int disass_std(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            sym.cpu.ctx().set(X86::DF, exprcst(8,0));

            code = string("\xfd", 1); // stc
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::DF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute STD");

            return nb;
        }
        
        unsigned int disass_sti(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            
            
            sym.cpu.ctx().set(X86::IF, exprcst(8,0));

            code = string("\xfb", 1); // sti
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1160, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::IF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute STI");

            return nb;
        }
        
        unsigned int disass_stosb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\xaa", 1); // stosb
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(8, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x18ff, "ArchX86: failed to disassembly and/or execute STOSB");
            nb += _assert(  sym.mem->read(0x1900, 1).as_uint() == 0x12, "ArchX86: failed to disassembly and/or execute STOSB");
            
            sym.mem->write(0x1900, exprcst(16, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x1901, "ArchX86: failed to disassembly and/or execute STOSB");
            nb += _assert(  sym.mem->read(0x1900, 1).as_uint() == 0x12, "ArchX86: failed to disassembly and/or execute STOSB");
            
            return nb;
        }
        
        unsigned int disass_stosd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            code = string("\xab", 1); // stosd
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(32, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x18fc, "ArchX86: failed to disassembly and/or execute STOSD");
            nb += _assert(  sym.mem->read(0x1900, 4).as_uint() == 0x12345678, "ArchX86: failed to disassembly and/or execute STOSD");
            
            sym.mem->write(0x1900, exprcst(32, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x1904, "ArchX86: failed to disassembly and/or execute STOSD");
            nb += _assert(  sym.mem->read(0x1900, 4).as_uint() == 0x12345678, "ArchX86: failed to disassembly and/or execute STOSD");
            
            return nb;
        }
        
        unsigned int disass_stosw(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xab", 2); // stosw
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(16, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x18fe, "ArchX86: failed to disassembly and/or execute STOSW");
            nb += _assert(  sym.mem->read(0x1900, 2).as_uint() == 0x5678, "ArchX86: failed to disassembly and/or execute STOSW");
            
            sym.mem->write(0x1900, exprcst(32, 0x23));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x1900));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0x0));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x1902, "ArchX86: failed to disassembly and/or execute STOSW");
            nb += _assert(  sym.mem->read(0x1900, 2).as_uint() == 0x5678, "ArchX86: failed to disassembly and/or execute STOSW");
            
            return nb;
        }
        
        unsigned int disass_sub(MaatEngine& sym){
            unsigned int nb = 0;
            string code;            

            /* sub reg, imm */
            code = string("\x2c\x0f", 2); // sub al(ff), f
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xff));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xf0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10ff));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10f0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            code = string("\x2c\x81", 2); // sub al(0x80), 0x81
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x80));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xff,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */
            
            code = string("\x66\x2d\xff\x00", 4); // sub ax, ff
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1ffff));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1ff00,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            code = string("\x66\x83\xe8\x01", 4); // sub ax, 1
            sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xfa000009));
            sym.run_from(0x1200, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xfa000008,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            code = string("\x2d\x34\x12\x00\x00", 5); // sub eax, 0x1234
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10001235));
            sym.run_from(0x1020, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10000001,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            code = string("\x2d\x00\x00\x00\xff", 5); // sub eax, 0xff000000
            sym.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xffff0000));
            sym.run_from(0x1030, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x00ff0000,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            /* sub reg,reg */
            code = string("\x28\xfc", 2); // sub ah, bh
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xf800));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x7900));
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x7f00,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            /* sub reg,mem */
            code = string("\x2B\x03", 2); // sub eax, dword ptr [ebx] 
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0xAAAA));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xAAAA));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x1700));
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */

            /* sub mem,reg */
            code = string("\x29\x18", 2); // sub dword ptr [eax], ebx 
            sym.mem->write_buffer(0x1070, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1070+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1800));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0xffffffff));
            sym.run_from(0x1070, 1);
            nb += _assert(  sym.mem->read(0x1800, 4).as_uint() == 0x0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            */
            return nb;
        }

        unsigned int disass_sbb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            /* sbb reg, imm */
            code = string("\x1c\x0e", 2); // sbb al(ff), e
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0xff));
            sym.cpu.ctx().set(X86::CF, exprcst(8,0x1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xf0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            */
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x10ff));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x10f0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            */

            code = string("\x1c\x80", 2); // sbb al(0x80), 0x80
            sym.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x80));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1190, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0xff,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            */
            
            code = string("\x66\x1D\xFE\x00", 4); // sbb ax, fe
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0x1ffff));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() == 0x1ff00,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute SBB");
            /*
            nb += _assert(  sym.cpu.ctx().get(X86::AF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute SBB");
            */
            return nb;
        }
        
        unsigned int disass_test(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\x85\xd8", 2); // test eax, ebx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x16545));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,0));
            sym.cpu.ctx().set(X86::SF, exprcst(8,1));
            sym.cpu.ctx().set(X86::PF, exprcst(8,0));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
            
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32,0X81230004));
            sym.cpu.ctx().set(X86::EBX, exprcst(32,0x80001234));
            sym.cpu.ctx().set(X86::ZF, exprcst(8,1));
            sym.cpu.ctx().set(X86::SF, exprcst(8,0));
            sym.cpu.ctx().set(X86::PF, exprcst(8,1));
            sym.cpu.ctx().set(X86::OF, exprcst(8,1));
            sym.cpu.ctx().set(X86::CF, exprcst(8,1));
            sym.run_from(0x1170, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute TEST");
                            
            return nb;
        }

        
        unsigned int disass_vpaddb(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xC5\xF1\xFC\xC2", 4); // vpaddb xmm0, xmm1, xmm2
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "11223344556677881111111111111111"));
            sym.cpu.ctx().set(X86::ZMM2, exprcst(512, "112211221122112212345678abcdef00"));
            sym.run_from(0x1000, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x22444466668888aa23456789bcde0011", "ArchX86: failed to disassembly and/or execute VPADDB");

            code = string("\xC5\xF1\xFC\x00", 4); //  vpaddb xmm0, xmm1, [eax]
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, 0xdeadbeef87654321, 8);
            sym.mem->write(0x1908, 0x000000000000abcd, 8);
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "11223344556677881111111111111111"));
            sym.run_from(0x1010, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1122334455662255efbecf0098765432", "ArchX86: failed to disassembly and/or execute VPADDB");

            return nb;
        }

        unsigned int disass_xadd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            
            

            // xadd al,bl
            code = string("\x0f\xc0\xd8",3);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x23));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1));
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() ==  0x24, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() ==  0x23, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() ==  0x0, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() ==  0x0, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() ==  0x1, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() ==  0x0, "ArchX86: failed to disassembly and/or execute XADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() ==  0x0, "ArchX86: failed to disassembly and/or execute XADD");

            // xadd DWORD PTR [ecx], ecx
            /* TODO, ghidra bug - they affect ecx too quickly so the store
             * is made at the wrong address .... 
            code = string("\x0f\xc1\x09", 3);
            sym.mem->write_buffer(0x1100, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1100+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x7fffffff));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0x1700));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1));
            sym.run_from(0x1100, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() ==  0x800016ff, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_uint() ==  0x7fffffff, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() ==  0x0, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() ==  0x1, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() ==  0x1, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() ==  0x0, "ArchX86: failed to disassembly and/or execute XADD");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() ==  0x1, "ArchX86: failed to disassembly and/or execute XADD");
            */
            return nb;
        }

        unsigned int disass_xchg(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            // xchg al,bl
            code = string("\x86\xd8",2);
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x23));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x1));
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() ==  0x1, "ArchX86: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X86::EBX).as_uint() ==  0x23, "ArchX86: failed to disassembly and/or execute XCHG"); 
            
            // xchg DWORD PTR [ecx], ecx 
            code = string("\x87\x09", 2);
            sym.mem->write_buffer(0x1100, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1100+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0x1700));
            sym.run_from(0x1100, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() ==  0x1700, "ArchX86: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X86::ECX).as_uint() ==  0x12345678, "ArchX86: failed to disassembly and/or execute XCHG"); 
            
            // xchg al, BYTE PTR [bx]
            code = string("\x67\x86\x07", 3);
            sym.mem->write_buffer(0x1110, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1110+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x20, exprcst(32, 0x12));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xfAA));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x10020));
            sym.run_from(0x1110, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EAX).as_uint() ==  0xf12, "ArchX86: failed to disassembly and/or execute XCHG");
            nb += _assert(  (uint8_t)sym.mem->read(0x20, 1).as_uint() ==  0xAA, "ArchX86: failed to disassembly and/or execute XCHG");
            return nb;
        }
        
        unsigned int disass_xor(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            // On 32 bits
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xffffffff));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0000ffff));
            code = string("\x31\xd8", 2); // xor eax, ebx
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xffff0000, 
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xfffff000));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x000fffff));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xfff00fff, 
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
                            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x80000001));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x80000001));
            sym.run_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
                            
            // On 16 bits 
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xa0000001));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0x0b000000));
            code = string("\x66\x31\xd8", 3); // xor ax, bx
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xa0000001,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0xab00000f));
            sym.cpu.ctx().set(X86::EBX, exprcst(32, 0xba00000f));
            sym.run_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.cpu.ctx().get(X86::EAX).as_uint() == 0xab000000,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::CF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::OF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::SF).as_uint() == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.cpu.ctx().get(X86::PF).as_uint() == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            return nb;
        }
        
        unsigned int disass_xorpd(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\x66\x0F\x57\xC1", 4); // xorpd xmm0, xmm1
            sym.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "ffff00000000ffffffff"));
            sym.cpu.ctx().set(X86::ZMM1, exprcst(512, "10000ff00000000000fffffff"));
            sym.run_from(0x1160, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x1000000ff00000000f0000000", "ArchX86: failed to disassembly and/or execute XORPD");

            code = string("\x66\x0F\x57\x00", 4); // xorpd xmm0, [eax]
            sym.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ZMM0, exprcst(512, "ffff0000000affffffff"));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1900));
            sym.mem->write(0x1900, exprcst(64, 0));
            sym.mem->write(0x1908, exprcst(64, 0x100000000));
            sym.run_from(0x1170, 1);
            nb += _assert_bignum_eq( sym.cpu.ctx().get(X86::ZMM0), "0x10000ffff0000000affffffff", "ArchX86: failed to disassembly and/or execute XORPD");

            return nb;
        }

         unsigned int disass_jmp(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xeb\x10", 2); // jmp 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.run_from(0x1000, 1);
            
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute JMP");
            
            
            code = string("\xe9\x51\x34\x12\x00", 5 ); // jmp 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute JMP");
            
            code = string("\x66\xff\xe0", 3 ); // jmp ax
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.mem->write_buffer(0x3000, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1234, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x3000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x3000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute JMP");
            
            code = string("\xff\xe0", 2 ); // jmp eax
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x00123456));
            sym.mem->write_buffer(0x5000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x123456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x5000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x5000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x00123456, "ArchX86: failed to disassembly and/or execute JMP");
            
            code = string("\xff\x20", 2 ); // jmp dword ptr [eax]
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x4010));
            sym.mem->write_buffer(0x4000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x4010, exprcst(32, 0x111111));
            sym.mem->write_buffer(0x111111, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x4000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x4000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x111111, "ArchX86: failed to disassembly and/or execute JMP");
            
            return nb;
        }

        unsigned int disass_call(MaatEngine& sym){
            unsigned int nb = 0;
            string code;
            
            code = string("\xe8\x0d\x00\x00\x00", 5); // call 0x12
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x10004));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1012, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4).as_uint() == 0x1005, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            code = string("\xe8\x51\x34\x12\x00", 5 ); // call 0x123456
            sym.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 5);
            sym.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x10004));
            sym.run_from(0x2000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x125456, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4).as_uint() == 0x2005, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            /* 
            code = string("\x66\xff\xd0", 3 ); // call ax
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x1234));
            sym.mem->write_buffer(0x3000, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1234, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x10004));
            sym.run_from(0x3000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1234, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4).as_uint() == 0x3003, "ArchX86: failed to disassembly and/or execute CALL");
            */
            
            code = string("\xff\xd0", 2 ); // call eax
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x00123456));
            sym.mem->write_buffer(0x5000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x123456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x10004));
            sym.run_from(0x5000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x00123456, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4).as_uint() == 0x5002, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            code = string("\xff\x10", 2 ); // call dword ptr [eax]
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x4010));
            sym.mem->write_buffer(0x4000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x4010, exprcst(32, 0x111111));
            sym.mem->write_buffer(0x111111, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X86::ESP, exprcst(32, 0x10004));
            sym.run_from(0x4000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x111111, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.cpu.ctx().get(X86::ESP).as_uint() == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4).as_uint() == 0x4002, "ArchX86: failed to disassembly and/or execute CALL");
            
            return nb;
        }
        
        unsigned int disass_rep(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xf3\xa4", 2); // rep movsb
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write_buffer(0x2000, (uint8_t*)"ABCDEFGH", 8);

            sym.mem->write_buffer(0x3000, (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x3000));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 4));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.run_from(0x1000, 5);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x3004, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x2004, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.mem->read(0x3000, 8).as_uint() == 0x0000000044434241, "ArchX86: failed to disassembly and/or execute REP MOVSB");

            sym.mem->write_buffer(0x3000, (uint8_t*)"\x00\x00\x00\x00", 4);
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x3000));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 0));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 1));
            sym.run_from(0x1000, 1);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x3000, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x2000, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.mem->read(0x3000, 8).as_uint() == 0, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            
            return nb;
        }
        
        unsigned int disass_repe(MaatEngine& sym){
            unsigned int nb = 0;
            string code;

            code = string("\xf3\xa6", 2); // repe cmpsb
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.mem->write_buffer(0x2000, (uint8_t*)"ABCDEFGH", 8);
            sym.mem->write_buffer(0x3000, (uint8_t*)"ABCDA", 5);
            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x3000));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 7));
            sym.cpu.ctx().set(X86::ZF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.run_from(0x1000, 5);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x3005, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x2005, "ArchX86: failed to disassembly and/or execute REPE CMPSB");

            sym.cpu.ctx().set(X86::ESI, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x3000));
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 3));
            sym.cpu.ctx().set(X86::ZF, exprcst(8, 1));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.run_from(0x1000, 4);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x3003, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.cpu.ctx().get(X86::ESI).as_uint() == 0x2003, "ArchX86: failed to disassembly and/or execute REPE CMPSB");

            return nb;
        }

        unsigned int disass_repne(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            code = string("\xf2\xae", 2); // repne scasb
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write_buffer(0x2000, (uint8_t*)"ABCDEFGH", 8);
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x47)); // "G"
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 7));
            sym.cpu.ctx().set(X86::ZF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.run_from(0x1000, 7);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x2007, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 1, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            
            
            sym.cpu.ctx().set(X86::EDI, exprcst(32, 0x2000));
            sym.cpu.ctx().set(X86::EAX, exprcst(32, 0x47)); // "G"
            sym.cpu.ctx().set(X86::ECX, exprcst(32, 4));
            sym.cpu.ctx().set(X86::ZF, exprcst(8, 0));
            sym.cpu.ctx().set(X86::DF, exprcst(8, 0));
            sym.run_from(0x1000, 5);
            nb += _assert(  sym.cpu.ctx().get(X86::EIP).as_uint() == 0x1002, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::EDI).as_uint() == 0x2004, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.cpu.ctx().get(X86::ZF).as_uint() == 0, "ArchX86: failed to disassembly and/or execute REPNE SCASB");

            return nb;
        }

        /* =================================== */

        unsigned int block_branch_info()
        {
            unsigned int nb = 0;
            /* TODO
            
            DisassemblerX86 disasm = DisassemblerX86(CPUMode::X86); 
            string code;
            
            IRBlock* block;
            IRBasicBlock bblkid;
            
            // Undefined single jmp
            code = string("\xff\xe0", 2); // jmp eax
            block = disasm.disasm_block(0, (code_t)code.c_str());
            nb += _assert( block->branch_type == BranchType::UNDEFINED, "IRBlock: got wrong branching info after 'jmp eax'");
            delete block;
            
            // Single jmp
            code = string("\xe8\x2f\x12\x00\x00", 5); // call 0x1234
            block = disasm.disasm_block(0, (code_t)code.c_str());
            nb += _assert( block->branch_type == BranchType::BRANCH, "IRBlock: got wrong branching info after 'call 0x1234'");
            nb += _assert( block->branch_target[1] == 0x1234, "IRBlock: got wrong branching info after 'call 0x1234'");
            delete block;
            
            // Multibranch
            code = string("\x77\x0e", 2); // ja 0x10
            block = disasm.disasm_block(0, (code_t)code.c_str());
            nb += _assert( block->branch_type == BranchType::MULTIBRANCH, "IRBlock: got wrong branching info after 'ja 0x10'");
            nb += _assert( block->branch_target[1] == 0x2, "IRBlock: got wrong branching info after 'ja 0x10'");
            nb += _assert( block->branch_target[0] == 0x10, "IRBlock: got wrong branching info after 'ja 0x10'");
            delete block;
            */
            return nb;
            
        }
    }
}

using namespace test::archX86; 
// All unit tests 
void test_archX86(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing arch X86 support... " << std::flush;  

    MaatEngine engine(Arch::Type::X86);
    engine.mem->map(0x0, 0x11000);
    engine.mem->map(0x110000, 0x130000);

    total += reg_translation();

    total += disass_aaa(engine);
    total += disass_aad(engine);
    total += disass_aam(engine);
    total += disass_aas(engine);
    total += disass_adc(engine);
    total += disass_adcx(engine);
    total += disass_add(engine);
    total += disass_and(engine);
    total += disass_andn(engine);
    total += disass_blsi(engine);
    total += disass_blsmsk(engine);
    total += disass_blsr(engine);
    total += disass_bsf(engine);
    total += disass_bsr(engine);
    total += disass_bswap(engine);
    total += disass_bt(engine);
    total += disass_btc(engine);
    total += disass_btr(engine);
    total += disass_bts(engine);
    total += disass_bzhi(engine);
    total += disass_call(engine);
    total += disass_cbw(engine);
    total += disass_cdq(engine);
    total += disass_clc(engine);
    total += disass_cld(engine);
    total += disass_cli(engine);
    total += disass_cmc(engine);
    total += disass_cmova(engine);
    total += disass_cmovae(engine);
    total += disass_cmovb(engine);
    total += disass_cmovbe(engine);
    total += disass_cmove(engine);
    total += disass_cmovg(engine);
    total += disass_cmovge(engine);
    total += disass_cmovl(engine);
    total += disass_cmovle(engine);
    total += disass_cmovne(engine);
    total += disass_cmovno(engine);
    total += disass_cmovnp(engine);
    total += disass_cmovns(engine);
    total += disass_cmovo(engine);
    total += disass_cmovp(engine);
    total += disass_cmovs(engine);
    total += disass_cmp(engine);
    total += disass_cmpsb(engine);
    total += disass_cmpsd(engine);
    total += disass_cmpsw(engine);
    total += disass_cmpxchg(engine);
    total += disass_cwd(engine);
    total += disass_cwde(engine);

    total += disass_dec(engine);
    total += disass_div(engine);
    total += disass_idiv(engine);
    total += disass_imul(engine);
    total += disass_inc(engine);
    total += disass_ja(engine);
    total += disass_jae(engine);
    total += disass_jb(engine);
    total += disass_jbe(engine);
    total += disass_jcxz(engine);
    total += disass_je(engine);
    total += disass_jecxz(engine);
    total += disass_jg(engine);
    total += disass_jge(engine);
    total += disass_jl(engine);
    total += disass_jle(engine);
    total += disass_jmp(engine);
    total += disass_jne(engine);
    total += disass_jno(engine);
    total += disass_jnp(engine);
    total += disass_jns(engine);
    total += disass_jo(engine);
    total += disass_jp(engine);
    total += disass_js(engine);

    total += disass_lahf(engine);
    total += disass_lea(engine);
    total += disass_leave(engine);
    total += disass_lodsb(engine);
    total += disass_lodsd(engine);
    total += disass_lodsw(engine);
    total += disass_mov(engine);
    total += disass_movapd(engine);
    total += disass_movaps(engine);
    total += disass_movd(engine);
    total += disass_movdqa(engine);
    total += disass_movhps(engine);
    total += disass_movq(engine);
    total += disass_movsb(engine);
    total += disass_movsd(engine);
    total += disass_movsw(engine);
    total += disass_movsx(engine);
    total += disass_movzx(engine);
    total += disass_mul(engine);
    total += disass_neg(engine);
    total += disass_nop(engine);
    total += disass_not(engine);
    total += disass_or(engine);

    total += disass_paddd(engine);
    total += disass_paddq(engine);
    total += disass_pcmpeqb(engine);
    total += disass_pcmpeqd(engine);
    total += disass_pcmpgtd(engine);
    // total += disass_pextrb(engine);
    total += disass_pminub(engine);
    // total += disass_pmovmskb(engine);
    total += disass_pop(engine);
    total += disass_popad(engine);
    total += disass_por(engine);
    total += disass_pshufd(engine);
    // TODO - ghidra bug: total += disass_pslld(engine); 
    total += disass_pslldq(engine);
    // TODO - ghidra bug: total += disass_psllq(engine);
    total += disass_psubb(engine);
    total += disass_punpckhdq(engine);
    // TODO - ghidra bug: total += disass_punpckhqdq(engine);
    total += disass_punpcklbw(engine);
    total += disass_punpckldq(engine);
    total += disass_punpcklqdq(engine);
    total += disass_punpcklwd(engine);
    total += disass_push(engine);
    total += disass_pushad(engine);
    total += disass_pushfd(engine);
    total += disass_pxor(engine);

    total += disass_rcl(engine);
    total += disass_rcr(engine);
    total += disass_ret(engine);
    total += disass_rol(engine);
    total += disass_ror(engine);
    total += disass_rorx(engine);
    total += disass_sal(engine);
    total += disass_sar(engine);
    total += disass_sbb(engine);
    total += disass_scasb(engine);
    total += disass_scasd(engine);
    total += disass_scasw(engine);
    total += disass_seta(engine);
    total += disass_setae(engine);
    total += disass_setb(engine);
    total += disass_setbe(engine);
    total += disass_sete(engine);
    total += disass_setg(engine);
    total += disass_setge(engine);
    total += disass_setl(engine);
    total += disass_setle(engine);
    total += disass_setne(engine);
    total += disass_setno(engine);
    total += disass_setnp(engine);
    total += disass_setns(engine);
    total += disass_seto(engine);
    total += disass_setp(engine);
    total += disass_sets(engine);
    total += disass_shr(engine);
    total += disass_stc(engine);
    total += disass_std(engine);
    total += disass_sti(engine);
    total += disass_stosb(engine);
    total += disass_stosd(engine);
    total += disass_stosw(engine);
    total += disass_sub(engine);
    total += disass_test(engine);

    // TODO - ghidra bug: total += disass_vpaddb(engine);

    total += disass_xadd(engine);
    // TODO - ghidra bug: total += disass_xchg(engine);
    total += disass_xor(engine);
    total += disass_xorpd(engine);

    // Prefixes 
    total += disass_rep(engine);
    total += disass_repe(engine);
    total += disass_repne(engine);
    total += disass_cmova(engine);

    // Other
    total += block_branch_info();
    //total += some_bench();

    cout << "\t" << total << "/" << total << green << "\tOK" << def << endl;
}
