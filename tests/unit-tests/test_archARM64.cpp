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
namespace archARM64
{
    using namespace maat;
    // assert test if true 
    unsigned int _assert(bool val, const string& msg){
        if( !val){
            cout << "\nFail: " << msg << std::endl; 
            throw test_exception();
        }
        return 1; 
    }

    unsigned int disass_addition(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;
        sym.cpu.ctx().set(ARM64::R2, exprcst(64,15));
        sym.cpu.ctx().set(ARM64::R1, exprcst(64,25));

        code = string("\x20\x00\x02\x8b", 4); // add x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 40, "ArchARM64: failed to disassembly and/or execute add");
        
        /* lets test the carry bit 
           load a 64-bit constant in x0*/ 
        code = string("\x80\x46\x82\xd2", 4); // movz    x0, #0x1234
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\xA0\x79\xb5\xf2", 4); // movk    x0, #0xABCD, LSL #16
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());

        code = string("\xe0\xff\xdf\xf2", 4); // movk    x0, #0xFFFF, LSL #32
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());

        code = string("\xe0\xff\xff\xf2", 4); // movk    x0, #0xFFFF, LSL #48
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());

        code = string("\x81\x46\x82\xd2", 4); // movz    x1, #0x1234
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());

        code = string("\xa1\x79\xb5\xf2", 4); // movk    x1, #0xABCD, LSL #16
        sym.mem->write_buffer(0x1014, (uint8_t*)code.c_str(), code.size());

        code = string("\xe1\xff\xdf\xf2", 4); // movk    x1, #0xFFFF, LSL #32
        sym.mem->write_buffer(0x1018, (uint8_t*)code.c_str(), code.size());

        code = string("\xe1\xff\xef\xf2", 4); // movk    x1, #0x7FFF, LSL #48
        sym.mem->write_buffer(0x101c, (uint8_t*)code.c_str(), code.size());

        code = string("\x22\x00\x00\xab", 4); // adds x2, x0, x1
        sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,9);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xffffffffabcd1234, "1: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R1).as_uint() == 0x7fffffffabcd1234, "2: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0x7fffffff579a2468, "3: ArchARM64: failed to disassembly and/or execute add");

        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1, "4: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0, "5: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x0, "6: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "7: ArchARM64: failed to disassembly and/or execute add");

        /* Check overflow bit now */
        code = string("\xe0\xff\xef\xf2", 4); // movk    x0, #0x7FFF, LSL #48
        sym.mem->write_buffer(0x101c, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,9);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0x7fffffffabcd1234, "8: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R1).as_uint() == 0xffffabcd1234, "9: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0x8000ffff579a2468, "10: ArchARM64: failed to disassembly and/or execute add");

        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x1, "11:ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x0, "12:ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x1, "13:ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x0, "14:ArchARM64: failed to disassembly and/or execute add");

        /* Add a number and its complement then check the Zero Flag */
        code = string("\x00\x00\x80\x92", 4); // mov x0, #-1
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x21\x00\x80\xD2", 4); // mov x1, #1
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());

        code = string("\x02\x00\x01\xAB", 4); // adds x2, x0, x1
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,3);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xffffffffffffffff, "8: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R1).as_uint() == 0x1, "9: ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0x0, "10: ArchARM64: failed to disassembly and/or execute add");

        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0, "11:ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x1, "12:ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "13:ArchARM64: failed to disassembly and/or execute add");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1, "14:ArchARM64: failed to disassembly and/or execute add");

        return ret_value;
    }

    unsigned int disass_subtraction(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;
        
        code = string("\x40\x00\x80\xd2", 4); // mov x0, #2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x21\x00\x80\xd2", 4); // mov x1, #1
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());

        code = string("\x02\x00\x01\xeb",4); // subs x0, x1, x2
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,3);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0x2, "1 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R1).as_uint() == 0x1, "2 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0x1, "3 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1, "4 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0, "4 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x0, "4 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "4 ArchARM64: failed to disassembly and/or execute sub");
        
        code = string("\x40\x00\x80\xd2", 4); //mov x0 #2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x41\x01\x80\xD2", 4); // mov x1, #10
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());

        code = string("\x02\x00\x01\xeb", 4); // subs x2, x0, x1
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,3);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0x2, "5 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R1).as_uint() == 0xa, "6 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == -0x8, "7 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x0, "8 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x1, "9 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "8 ArchARM64: failed to disassembly and/or execute sub");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x0, "9 ArchARM64: failed to disassembly and/or execute sub");


        code = string("\x02\x00\x01\xDA", 4); // sbc x2, x0, x1
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x100c,1);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == -0x9, "10 ArchARM64: failed to disassembly and/or execute sub");


        return ret_value;
    }

    unsigned int disass_zero(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;

        sym.cpu.ctx().set(ARM64::R1, exprcst(64,0x3000));
        sym.cpu.ctx().set(ARM64::R2, exprcst(64,0x1234));
        code = string("\x20\x00\x1f\x0b", 4); // add w0, w1, wzr
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0x3000, "ArchARM64: failed to disassembly and/or execute zero");
        return ret_value;
    }

    unsigned int disass_branch(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;

        code = string("\xE0\x01\x80\xD2", 4); // mov x0, #15
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x1f\x28\x00\xf1", 4); //  cmp x0, #10
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x4d\x00\x00\x54", 4); //  b.le #8
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x05\x00\x80\x92", 4); // mov x5, #-1
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());

        code = string("\x25\x00\x80\xD2", 4); // mov x5, #1
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,4);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xf,    "1: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R5).as_uint() == -0x1,   "2: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1,    "3: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0,    "4: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0,    "5: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x0,    "6: ArchARM64: failed to disassembly and/or execute Branch Conditional");

        code = string("\xE0\x01\x80\xD2", 4); // mov x0, #15
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x1f\x28\x00\xf1", 4); //  cmp x0, #10
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x4a\x00\x00\x54", 4); //  b.ge #8
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x05\x00\x80\x92", 4); // mov x5, #-1
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());

        code = string("\x25\x00\x80\xD2", 4); // mov x5, #1
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,4);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xf, "7: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R5).as_uint() == 0x1, "8: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1, "9: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0, "10: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "11: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x0, "12: ArchARM64: failed to disassembly and/or execute Branch Conditional");

        code = string("\xE0\x01\x80\xD2", 4); // mov x0, #15
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x1F\x3C\x00\xF1", 4); //  cmp x0, #15
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x40\x00\x00\x54", 4); //  b.eq #8
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x05\x00\x80\x92", 4); // mov x5, #-1
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());

        code = string("\x25\x00\x80\xD2", 4); // mov x5, #1
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,4);
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xf, "13: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R5).as_uint() == 0x1, "14: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1, "15: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0, "16: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "17: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x1, "18: ArchARM64: failed to disassembly and/or execute Branch Conditional");

        // test branch and link
        code = string("\xE0\x01\x80\xD2", 4); // mov x0, #15
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());  
                
        code = string("\x1F\x3C\x00\xF1", 4); //  cmp x0, #15
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());

        code = string("\x02\x00\x00\x94", 4); //  bl #8
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        
        code = string("\x05\x00\x80\x92", 4); // mov x5, #-1
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());

        code = string("\x25\x00\x80\xd2", 4); // mov x5, #1
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,4);

        ret_value += _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xf, "19: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::R5).as_uint() == 0x1, "21: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        
        ret_value += _assert( sym.cpu.ctx().get(ARM64::CF).as_uint() == 0x1, "22: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::NF).as_uint() == 0x0, "23: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::VF).as_uint() == 0x0, "24: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::ZF).as_uint() == 0x1, "25: ArchARM64: failed to disassembly and/or execute Branch Conditional");
        ret_value += _assert( sym.cpu.ctx().get(ARM64::LR).as_uint() == 0x100c, "26: ArchARM64: failed to disassembly and/or execute Branch Conditional");

        return ret_value;
    }

    unsigned int disass_store_load(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;
        // Set Registers
        sym.cpu.ctx().set(ARM64::LR, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R0, exprcst(64,0xDEADBEEF));
        sym.cpu.ctx().set(ARM64::R1, exprcst(64,0x110000));
        sym.cpu.ctx().set(ARM64::R2, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R3, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R4, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R5, exprcst(64,0));
        
        code = string("\x20\x00\x00\xb9", 4); // str w0 [x1]
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());  

        sym.run_from(0x1000,1);
        ret_value += _assert((uint32_t)sym.mem->read(0x110000, 4).as_uint() == 0xDEADBEEF, "1: ArchARM64: failed to disassemble store and load instructions.");

        code = string("\x22\x00\x40\xb9", 4); //  ldr w2 [x1]
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());  

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0xDEADBEEF, "2: ArchARM64: failed to disassemble store and load instructions.");

        // Set Register
        sym.cpu.ctx().set(ARM64::R0, exprcst(64,0xBADC0FFEE0DDF00D));
        sym.cpu.ctx().set(ARM64::R1, exprcst(64,0x110000));

        code = string("\x20\x00\x00\xf9", 4); // str x0 [x1]
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        
        sym.run_from(0x1000,1);
        ret_value += _assert((uint32_t)sym.mem->read(0x110000, 4).as_uint() == 0xe0ddf00d, "3: ArchARM64: failed to disassemble store and load instructions.");
        ret_value += _assert((uint32_t)sym.mem->read(0x110004, 4).as_uint() == 0xbadc0ffe, "4: ArchARM64: failed to disassemble store and load instructions.");

        code = string("\x22\x00\x40\xf9", 4); // ldr x2 [x1]
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0xBADC0FFEE0DDF00D, "5: ArchARM64: failed to disassemble store and load instructions.");

        return ret_value;
    }

    unsigned int logical_shift(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;
        // Set Registers
        sym.cpu.ctx().set(ARM64::LR, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R0, exprcst(64,0xDEAD));
        sym.cpu.ctx().set(ARM64::R1, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R2, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R3, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R4, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R5, exprcst(64,0));

        code = string("\x01\xf4\x7e\xd3",4); // lsl x1, x0, #2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        code = string("\x02\xfc\x42\xd3",4); // lsr x2, x0, #2
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());

        code = string("\x03\xfc\x42\xd3",4); // asr x3, x0, #2
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,3);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R1).as_uint() == 0x37ab4, "1: ArchARM64: failed to disassemble Logical Shifts instructions.");
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R2).as_uint() == 0x37ab, "2: ArchARM64: failed to disassemble Logical Shifts instructions.");
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R3).as_uint() == 0x37ab, "3: ArchARM64: failed to disassemble Logical Shifts instructions.");

        return ret_value;
    }

    unsigned int disass_bitwise(MaatEngine& sym)
    {
        unsigned int ret_value = 0;
        string code;
        // Set Registers
        sym.cpu.ctx().set(ARM64::R0, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R1, exprcst(64,0x6));
        sym.cpu.ctx().set(ARM64::R2, exprcst(64,0xf));
        sym.cpu.ctx().set(ARM64::R3, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R4, exprcst(64,0));
        sym.cpu.ctx().set(ARM64::R5, exprcst(64,0));
        
        code = string("\x20\x00\x02\x8a",4); // and x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0x6, "1: ArchARM64: failed to disassemble bitwise operations");

        code = string("\x20\x00\x02\xaa",4); // or x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xf, "2: ArchARM64: failed to disassemble bitwise operations");
        
        code = string("\x20\x00\x22\x8a",4); // bic x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0x0, "3: ArchARM64: failed to disassemble bitwise operations");

        code = string("\x20\x00\x22\xaa",4); // orn x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xfffffffffffffff6, "4: ArchARM64: failed to disassemble bitwise operations");

        code = string("\x20\x00\x02\xca",4); // eor x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 9, "5: ArchARM64: failed to disassemble bitwise operations");

        sym.cpu.ctx().set(ARM64::R2, exprcst(64,0x9));
        code = string("\x20\x00\x22\xca",4); // eon x0, x1, x2
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        
        sym.run_from(0x1000,1);
        ret_value +=  _assert( sym.cpu.ctx().get(ARM64::R0).as_uint() == 0xfffffffffffffff0, "6: ArchARM64: failed to disassemble bitwise operations");

        return ret_value;
    }

}// Namespace ARM64
}// Namespace Test
using namespace test::archARM64;

void test_archARM64() {
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";

    // Start testing
    std::cout << bold << "[" << green << "+" 
         << def << bold << "]" << def << std::left << std::setw(34)
         << " Testing Arch ARM64 support... " << std::flush;

    MaatEngine engine(Arch::Type::ARM64);
    engine.mem->map(0x0, 0x11000);
    engine.mem->map(0x110000, 0x130000);

    total += disass_addition(engine);
    total += disass_subtraction(engine);
    total += disass_zero(engine);
    total += disass_branch(engine);
    total += disass_store_load(engine);
    total += logical_shift(engine);
    total += disass_bitwise(engine);
    // total += disass_float(engine);


    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}