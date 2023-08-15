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

        unsigned int test_THUMB () {
            string code;
            MaatEngine sym = MaatEngine(Arch::Type::ARM32);
            unsigned int return_val = 0;

            sym.mem->map(0x1000, 0x2000);
            code = string("\x1e\xff\x2f\xe1",4); // bx lr (branch and change to thumb mode)
            sym.cpu.ctx().set(ARM32::LR, exprcst(32, 0x101d)); // set link register to 0x101c
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            code = string("\x88\x18",2); // add r0, r1, r2
            sym.cpu.ctx().set(ARM32::R1, exprcst(32, 0x1111)); // set r1 to 0x1111
            sym.cpu.ctx().set(ARM32::R2, exprcst(32, 0x1234)); // set r2 to 0x1234

            sym.mem->write_buffer(0x101c, (uint8_t*)code.c_str(), code.size());

            code = string("\x10\x46",2); // mov r0, r2
            sym.mem->write_buffer(0x101e, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,2);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R0).as_uint() == 0x2345, "1: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x1111, "2: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::R2).as_uint() == 0x1234, "3: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::TF).as_uint() == 0x1, "4: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ISAModeSwitch).as_uint() == 0x1, "5: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x20, "6: ArchARM32: Failed to test Thumb mode");

            sym.run_from(0x101e,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R0).as_uint() == 0x1234, "7: ArchARM32: Failed to test Thumb mode");

            sym.cpu.ctx().set(ARM32::LR, exprcst(32,0x1024));
            code = string("\x70\x47", 2); // bx lr (thumb mode)
            sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());

            code = string("\x01\x3a\xa0\xe3",4); // mov         r3,0x1000
            sym.mem->write_buffer(0x1024, (uint8_t*)code.c_str(),code.size());

            sym.run_from(0x1020,2);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0x1000, "7: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ISAModeSwitch).as_uint() == 0x0, "8: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::TF).as_uint() == 0x0, "9: ArchARM32: Failed to test Thumb mode");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x0, "10: ArchARM32: Failed to test Thumb mode");

            sym.cpu.ctx().set(ARM32::TF,exprcst(8,0x1));
            sym.run_from(0x101c,2);

            return return_val;
        }

        unsigned int disass_mov(MaatEngine &sym) {
            unsigned int return_val = 0;
            string code;
            
            code = string("\x01\x3a\xa0\xe3",4); // mov         r3,0x1000
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0x1000, "1: ArchARM32: Failed to disassembly and/or execute move instruction");
            
            // Test Logical Shift Left By 2
            sym.cpu.ctx().set(ARM32::R3, exprcst(32, 0xf)); // set r3 to 0xf
            code = string("\x03\x31\xa0\xe1",4); // mov        r3,r3, lsl #0x2
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0x3c, "2: ArchARM32: Failed to disassembly and/or execute move instruction");

            // Test Logical Shift Right By 2
            sym.cpu.ctx().set(ARM32::R3, exprcst(32, 0xf)); // set r3 to 0xf
            code = string("\x23\x31\xa0\xe1",4); // mov        r3,r3, lsr #0x2
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0x3, "3: ArchARM32: Failed to disassembly and/or execute move instruction");
            // Test Arithmetic Shift Right
            sym.cpu.ctx().set(ARM32::R3, exprcst(32, 0xf0000000)); // set r3 to 0xf0000000
            code = string("\x43\x31\xa0\xe1",4); // mov        r3,r3, asr #0x2
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0xfc000000, "4: ArchARM32: Failed to disassembly and/or execute move instruction");

            // test Rotate Right Shift
            sym.cpu.ctx().set(ARM32::R3, exprcst(32, 0x80000007)); // set r3 to 0x80000007
            code = string("\x63\x31\xa0\xe1",4); // mov        r3,r3, ror #0x2
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0xe0000001, "5: ArchARM32: Failed to disassembly and/or execute move instruction");

            sym.cpu.ctx().set(ARM32::CF, exprcst(8,0x0));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0xf)); // set r3 to 0x1
            code = string("\x63\x30\xa0\xe1"); // mov        r3,r3, rrx
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R3).as_uint() == 0x7, "6: ArchARM32: Failed to disassembly and/or execute move instruction");
            
            return_val += _assert(sym.cpu.ctx().get(ARM32::SC).as_uint() == 0x1, "7: ArchARM32: Failed to disassembly and/or execute move instruction");

            return return_val;
        }

        unsigned int disass_add(MaatEngine &sym) {
            unsigned int return_val = 0;
            string code;
            
            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0x1000));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x1234));

            code = string("\x03\x10\x82\xe0",4); // add r1, r2, r3
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());


            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x2234, "1: ArchARM32: Failed to disassembly and/or execute add instruction");

            code = string("\x03\x10\x92\xe0",4); // adds r1, r2, r3
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x2234, "2: ArchARM32: Failed to disassembly and/or execute add instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x0, "3: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "4: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x0, "5: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "6: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x0, "7: ArchARM32: Failed to disassembly and/or execute add instruction, CPSR is incorrect");

            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0x7fffffff));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x1));
            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x80000000, "8: ArchARM32: Failed to disassembly and/or execute add instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x1, "9: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x1, "10: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x0, "11: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "12: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x90000000, "13: ArchARM32: Failed to disassembly and/or execute add instruction, CPSR is incorrect");


            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0xffffabcd));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0xffffabcd));
            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0xffff579a, "7: ArchARM32: Failed to disassembly and/or execute add instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x1, "8: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "9: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x1, "10: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "11: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0xa0000000, "12: ArchARM32: Failed to disassembly and/or execute add instruction");

            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0x0));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x0));
            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x0, "13: ArchARM32: Failed to disassembly and/or execute add instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x0, "14: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "15: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x0, "16: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x1, "17: ArchARM32: Failed to disassembly and/or execute add instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x40000000, "18: ArchARM32: Failed to disassembly and/or execute add instruction");

            return return_val;
        }

        unsigned int disass_sub(MaatEngine &sym) {
            unsigned int return_val = 0;
            string code;
            
            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0x1000));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x1234));

            code = string("\x03\x10\x42\xe0",4); // sub r1, r2, r3
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());


            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0xfffffdcc, "1: ArchARM32: Failed to disassembly and/or execute sub instruction");


            code = string("\x03\x10\x52\xe0",4); // subs r1, r2, r3
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            
            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0xfffffdcc, "2: ArchARM32: Failed to disassembly and/or execute sub instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x1, "3: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "4: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x0, "5: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "6: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x80000000, "7: ArchARM32: Failed to disassembly and/or execute add instruction");

            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0x1111));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x1111));
            sym.run_from(0x1000,1);
            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x0, "8: ArchARM32: Failed to disassembly and/or execute sub instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x0, "9: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "10: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x1, "11: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x1, "12: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x60000000, "13: ArchARM32: Failed to disassembly and/or execute add instruction");

            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0xffffabcd));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x7fff6543));
            sym.run_from(0x1000,1);

            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_uint() == 0x8000468a, "14: ArchARM32: Failed to disassembly and/or execute sub instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x1, "15: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "16: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x1, "17: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "18: ArchARM32: Failed to disassembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0xa0000000, "19: ArchARM32: Failed to disassembly and/or execute add instruction");

            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0xc7000000));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0x56000000));
            sym.run_from(0x1000,1);

            return_val += _assert(sym.cpu.ctx().get(ARM32::R1).as_int() == 0x71000000, "20. ArchArm32: Failed to disaseembly and/or execute sub instruction");
            // Test Flag Bits
            return_val += _assert(sym.cpu.ctx().get(ARM32::NF).as_int() == 0x0, "21. ArchArm32: Failed to disaseembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::VF).as_int() == 0x1, "22. ArchArm32: Failed to disaseembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CF).as_int() == 0x1, "23. ArchArm32: Failed to disaseembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::ZF).as_int() == 0x0, "24. ArchArm32: Failed to disaseembly and/or execute sub instruction");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x30000000, "25: ArchARM32: Failed to disassembly and/or execute add instruction");

            return return_val;
        }

        unsigned int disass_branch(MaatEngine& sym){
            unsigned int return_val = 0;
            string code;

            code = string("\x0f\x00\xa0\xe3", 4); // mov r0, #15
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

            code = string("\x0a\x00\x50\xe3", 4); //  cmp r0, #10
            sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
            
            code = string("\x00\x00\x00\xda", 4); //  b.le #8
            sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
            
            code = string("\x01\x50\xa0\xe3", 4); // mov r5, #1
            sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());

            code = string("\x02\x50\xa0\xe3", 4); // mov r5, #2
            sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,4);
            return_val += _assert( sym.cpu.ctx().get(ARM32::R0).as_uint() == 0xf, "1: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::R5).as_uint() == 0x1, "2: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x0, "3: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "4: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x1, "5: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "6: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x20000000, "7: ArchARM32: Failed to disassembly and/or execute add instruction");

            code = string("\x00\x00\x00\xaa", 4); //  b.ge #8
            sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,4);
            return_val += _assert( sym.cpu.ctx().get(ARM32::R0).as_uint() == 0xf, "8: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::R5).as_uint() == 0x2, "9: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x0, "10: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "10: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x1, "11: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x0, "12: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x20000000, "25: ArchARM32: Failed to disassembly and/or execute add instruction");

            code = string("\x0f\x00\x50\xe3", 4); //  cmp r0, #15
            sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
            code = string("\x00\x00\x00\x0a", 4); //  b.eq #8
            sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());

            sym.run_from(0x1000,4);
            return_val += _assert( sym.cpu.ctx().get(ARM32::R0).as_uint() == 0xf, "13: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::R5).as_uint() == 0x2, "14: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::NF).as_uint() == 0x0, "15: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::VF).as_uint() == 0x0, "16: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::CF).as_uint() == 0x1, "17: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert( sym.cpu.ctx().get(ARM32::ZF).as_uint() == 0x1, "18: ArchARM64: failed to disassembly and/or execute Branch Conditional");
            return_val += _assert(sym.cpu.ctx().get(ARM32::CPSR).as_uint() == 0x60000000, "25: ArchARM32: Failed to disassembly and/or execute add instruction");

            return return_val;
        }

        unsigned int disass_store_load(MaatEngine& sym){
            unsigned int return_val = 0;
            string code;

            // Set Registers
            sym.cpu.ctx().set(ARM32::R0, exprcst(32,0xDEADBEEF));
            sym.cpu.ctx().set(ARM32::R1, exprcst(32,0x110000));
            sym.cpu.ctx().set(ARM32::R2, exprcst(32,0));
            sym.cpu.ctx().set(ARM32::R3, exprcst(32,0));
            sym.cpu.ctx().set(ARM32::R4, exprcst(32,0));
            sym.cpu.ctx().set(ARM32::R5, exprcst(32,0));
            
            code = string("\x00\x00\x01\xe4", 4); // str r0 [r1] 0x0
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());  

            sym.run_from(0x1000,1);
            return_val += _assert((uint32_t)sym.mem->read(0x110000, 4).as_uint() == 0xDEADBEEF, "1: ArchARM64: failed to disassemble store and load instructions.");

            code = string("\x00\x20\x11\xe4", 4); //  ldr r2 [r1]
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());  

            sym.run_from(0x1000,1);
            return_val += _assert( sym.cpu.ctx().get(ARM32::R2).as_uint() == 0xDEADBEEF, "1: ArchARM64: failed to disassemble store and load instructions.");

            return return_val;
        }

        unsigned int test_binary()
        {
            unsigned int return_val = 0;
            MaatEngine sym = MaatEngine(Arch::Type::X64);
            sym.load("tests/resources/simple_algo_2/crackmex86", 
            loader::Format::ELF64,        
            0x100000,
            {},
            {},
            {},
            {},
            {}
            );
            Expr value = exprvar(64,"input");
            sym.settings.log_insts = true;
            sym.cpu.ctx().set(X64::RDI, value);
            sym.cpu.ctx().set(X64::RIP, exprcst(64,0x1011c9)); // transform
            
            sym.run();
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
    engine.mem->map(0x110000, 0x130000);
    
    total += disass_mov(engine);
    total += disass_add(engine);
    total += disass_sub(engine);
    total += disass_branch(engine);
    total += disass_store_load(engine);

    total += test_THUMB();
    // total += test_binary();

    // total += test_float();
    cout << "\t" << total << "/" << total << green << "\tOK" << def << endl;
}