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
namespace archPPC32
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

    // register check test
    unsigned int simple_move()
    {
        string code;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);

        // write to mem map
        sym.mem->map(0x1000,0x2000);
        code = string("\x38\x80\x00\x03",4); // assembly code = li r4 0x03
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);

        unsigned int ret_value =0;
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R4).as_uint() == 0x03, "R4 is not equal to 0x3");

        return ret_value;        
    }

    unsigned int simple_branch()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");
        
        code = string("\x7c\x05\x48\x00",4); // cpmw r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        code = string("\x48\x00\x00\x08",4); //b skip 1 instruction?
        sym.mem->write_buffer(0x100c,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,4);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::PC).as_uint()==0x01014,"PC didn't increment by 8");

        code = string("\x38\x80\x00\x01",4); // li r4, 0x01
        sym.mem->write_buffer(0x1010,(uint8_t*)code.c_str(), code.size());
        code = string("\x38\xa0\x00\x03",4); //li r5, 0x02
        sym.mem->write_buffer(0x1014,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,5);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R4).as_uint()!=0x01,"R4 not equal to 2");    

        return ret_value;
    }

    unsigned int simple_addition()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");

        code = string("\x7c\x65\x4a\x14",4); // add r3 r5 r9 
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R3).as_uint()==0x0f,"R3 is not equal to 0x0F");
        
        return ret_value;
    }

    unsigned int addition_16bits()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x00",4); //  li r9,0x00 ori r9, r9, 60000
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x0,"R9 is not equal to 0x0");

        code = string("\x61\x29\xea\x60",4); // ori r9 r9 0xea60
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0xea60,"R9 is not equal to 0xEA60");

        code = string("\x38\xa0\x00\x00",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x0,"R5 is not equal to 0x0");

        code = string("\x60\xa5\xea\x60",4); // ori r5 r5 0xea60
        sym.mem->write_buffer(0x100c,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,4);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0xea60,"R5 is not equal to 0x0");

        code = string("\x7c\x65\x4a\x15",4); // addc r3 r5 r9 
        sym.mem->write_buffer(0x1010,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,5);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R3).as_uint()==0x1D4C0,"R3 is not equal to 0x1FE");
        
        return ret_value;
    }

    unsigned int compare_default()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");

        code = string("\x7c\x05\x48\x00",4); // cmpw r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::CR0).as_uint()==0x04, "CR0 isn't set to 4 meaning r5 not greater than r9");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::CR).as_uint()==1073741824, "CR0 isn't set in the right spot of in CR");

        return ret_value;
    }

    unsigned int compare_CR3()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x05",4); // li r5, 0x05
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x05,"R5 is not equal to 0x0A");

        code = string("\x7d\x85\x48\x00",4); // cmpw cr3, r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::CR3).as_uint()==0x02, "CR3 isn't set to 1 meaning r5 not equal to r9");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::CR).as_uint()==131072, "CR3 isn't set in the right spot of in CR");

        return ret_value;
    }

    unsigned int addition_overflow()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x3d\x20\x80\x00",4); //  lis r9 0x8000
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x80000000,"R9 is not equal to 0x8000 0000");

        code = string("\x61\x29\x70\x00",4); // ori r9 r9 7000
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x80007000,"R9 is not equal to 0x8000 7000");
        
        code = string("\x3c\xa0\x80\x00",4); //  lis r5 8000
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x80000000,"R5 is not equal to 0x8000 0000");

        code = string("\x7c\xc5\x4c\x15",4);// addco. 6 5 9
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,4);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R6).as_uint()==0x00007000,"R6 is not equal to 0x0000 7000");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::XER_SO).as_uint()==1, "Overflow flag not set");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::XER_CA).as_uint()==1, "Overflow flag not set");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::XER_OV).as_uint()==1, "Overflow flag not set");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::XER).as_uint()==0xe0000000, "XER Register not the same as bit flags");
        ret_value += _assert(sym.cpu.ctx().get(PPC32::CR0).as_uint()==0x5, "CR0 flag not set or isn't equal to 0x05");
        
        return ret_value;
    }

    // RET_VALUE NOT BEING CALLED IN BOTTOM THREE BLOCKS
    unsigned int bge_branch()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");

        code = string("\x7c\x05\x48\x00",4); // cmpw r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        
        code = string("\x40\x80\x00\x08",4); // bge 8 
        sym.mem->write_buffer(0x100c,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,4);

        code = string("\x38\x80\x00\x02",4); //li r4, 0x02
        sym.mem->write_buffer(0x1014,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,5);
        //TODO ADD RET

        return ret_value;
    }

    unsigned int storeword_loadword()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);

        code = string("\x39\x20\x10\x00",4); //  li r9,0x1000
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x1000,"R9 is not equal to 0x1000");

        code = string("\x91\x3f\x00\x08",4); //stw     r9,8(r31)
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,2);

        code = string("\x39\x20\x20\x00",4); //  li r9,0x2000
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x2000,"R9 is not equal to 0x2000");

        code = string("\x91\x3f\x00\x0c",4); //stw     r9,12(r31)
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,4);

        code = string("\x81\x5f\x00\x08",4); //lwz r10, 8(r31)
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,5);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R10).as_uint()==0x1000,"R10 is not equal to 0x1000");

        code = string("\x80\x7f\x00\x0c",4); //lwz r9, 12(r31)
        sym.mem->write_buffer(0x1014, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,6);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x2000,"R9 is not equal to 0x2000");

        return ret_value;
    }

    // UNFINISHED UNIT TEST
    unsigned int for_loop()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);

        unsigned int test_reg_val = 0;

        code = string("\x39\x20\x00\x00",4); //  li r9,0x0
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==0x00,"R9 is not equal to 0x0");

        code = string("\x91\x3f\x00\x0c",4); //  stw r9,12(r31)
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);

        cout<<"before b:"<<sym.cpu.ctx().get(PPC32::PC)<<endl;
        code = string("\x48\x00\x00\x1c",4); //  b 
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        cout<<"after b:"<<sym.cpu.ctx().get(PPC32::PC)<<endl;

        code = string("\x81\x3f\x00\x08",4); //  lwz r9,8(r31)
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,4);
        cout<<"what is in r9 offset 8: "<<sym.cpu.ctx().get(PPC32::R9).as_uint()<<endl;
        test_reg_val= sym.cpu.ctx().get(PPC32::R9).as_uint();
        //test 

        code = string("\x39\x29\x00\x01",4); //  addi r9 r9 1
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,5);
        //test
        test_reg_val;
        // ret_value += _assert(sym.cpu.ctx().get(PPC32::R9).as_uint()==(test_reg_val+1),"R9 didn't get plus 1");

        code = string("\x91\x3f\x00\x0c",4); //  stw r9,8(r31)
        sym.mem->write_buffer(0x1014, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,6);

        code = string("\x81\x3f\x00\x0c",4);// lwz r9,12(r31)
        sym.mem->write_buffer(0x1018, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,7);
        cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC32::R9).as_uint()<<endl;

        code = string("\x39\x29\x00\x01",4);// addi r9,r9,1
        sym.mem->write_buffer(0x101c, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,8);
        cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC32::R9).as_uint()<<endl;

        code = string("\x91\x3f\x00\x0c",4);// stw r9,12(r31)
        sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,9);
        // cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC32::r9).as_uint()<<endl;

        code = string("\x81\x3f\x00\x0c",4);// lwz r9,12(r31)
        sym.mem->write_buffer(0x1024, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,10);
        cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC32::R9).as_uint()<<endl;

        code = string("\x2c\x09\x00\x09",4);// cmpwi r9,9
        sym.mem->write_buffer(0x1028, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,11);
        cout<<"what is inside cmp register: "<<sym.cpu.ctx().get(PPC32::CR).as_uint()<<endl;

        code = string("\x40\x81\xff\xe0",4);// ble 1000046c
        sym.mem->write_buffer(0x102c, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,12);

        return ret_value;
    }
    
    unsigned int disass_bne()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x40\x82\x00\x20", 4); // bne 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "1: ArchPPC32: failed to disassembly and/or execute BNE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "2: ArchPPC32: failed to disassembly and/or execute BNE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,1));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "3: ArchPPC32: failed to disassembly and/or execute BNE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "4: ArchPPC32: failed to disassembly and/or execute BNE");

        return ret_value;
    }

    unsigned int disass_ble()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x40\x81\x00\x20", 4); // ble 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "1: ArchPPC32: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,10));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "2: ArchPPC32: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "3: ArchPPC32: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "4: ArchPPC32: failed to disassembly and/or execute BLE");

        
        return ret_value;
    }

    unsigned int disass_blt()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;
        
        code = string("\x41\x80\x00\x20", 4); // blt 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "1: ArchPPC32: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "2: ArchPPC32: failed to disassembly and/or execute BLE");
        
        return ret_value;
    }
    
    unsigned int disass_bge()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;
        
        code = string("\x40\x80\x00\x20", 4); // bge 0x12
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,6));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "1: ArchPPC32: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "2: ArchPPC32: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "3: ArchPPC32: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,9));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "4: ArchPPC32: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "5: ArchPPC32: failed to disassembly and/or execute BGE");

        return ret_value;
    }

    unsigned int disass_bgt()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x41\x81\x00\x20", 4); // bgt 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,6));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "1: ArchPPC32: failed to disassembly and/or execute BGT");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1020, "2: ArchPPC32: failed to disassembly and/or execute BGT");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,9));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "3: ArchPPC32: failed to disassembly and/or execute BGT");

        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "4: ArchPPC32: failed to disassembly and/or execute BGT");
        
        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "5: ArchPPC32: failed to disassembly and/or execute BGT");
        
        return ret_value;
    }

    unsigned int disass_cntlzw()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC32::R3, exprcst(32,0x1234));
        sym.cpu.ctx().set(PPC32::R5, exprcst(32,0x5));
        code = string("\x7c\x65\x00\x34", 4); // cntlzw r5,r3
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "1: ArchPPC32: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R5).as_uint() == 19, "1: ArchPPC32: R5 not equal to 19");


        sym.cpu.ctx().set(PPC32::R8, exprcst(32,0x674321));
        sym.cpu.ctx().set(PPC32::R10, exprcst(32,0x5));
        code = string("\x7d\x0a\x00\x34", 4); // cntlzw r10,r8
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "2: ArchPPC32: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R10).as_uint() == 9, "2: ArchPPC32: R10 not equal to 9");

        sym.cpu.ctx().set(PPC32::R8, exprcst(32,0x1));
        sym.cpu.ctx().set(PPC32::CR0, exprcst(8,0x0));
        code = string("\x7d\x0a\x00\x35", 4); // cntlzw. r10,r8
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004, "3: ArchPPC32: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R10).as_uint() == 31, "3: ArchPPC32: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::CR0).as_uint() == 4, "3: ArchPPC32: failed to disassembly and/or execute cntlzw");

        return ret_value;
    }

        unsigned int disass_subf()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC32::R3, exprcst(32,10000));
        sym.cpu.ctx().set(PPC32::R4, exprcst(32,5000));
        code = string("\x7c\x44\x18\x50", 4); // subf r2, r4, r3
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R2).as_uint() == 5000, "1: ArchPPC32: failed to disassembly and/or execute subf");

        code = string("\x7c\x44\x18\x51", 4); // subf. r2, r4, r3
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R2).as_uint() == 5000, "2: ArchPPC32: failed to disassembly and/or execute subf.");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::CR0).as_uint() == 4, "3: ArchPPC32: R3 is not greater than R4");

        return ret_value;
    }

    unsigned int disass_mulli()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC32::R4, exprcst(32,0x3000));
        code = string("\x1c\xc4\x00\x0a", 4); // mulli r6, r4, 10 
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R6).as_uint() == 0x1e000, "ArchPPC32: failed to disassembly and/or execute mulli");

        return ret_value;
    }

    unsigned int disass_mtspr()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC32::R5, exprcst(32,0x50));
        code = string("\x7c\xa8\x03\xa6", 4); // mtspr LR,r5
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::LR).as_uint() == 0x50, "1: ArchPPC32: failed to disassembly and/or execute mtspr");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R2).as_uint() == 0x1000, "2: ArchPPC32: failed to disassembly and/or execute mtspr");

        sym.cpu.ctx().set(PPC32::R0, exprcst(32,0x50));
        code = string("\x7c\x08\x03\xa6", 4); // mtspr LR,r0
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x11\x11", 4).c_str(), 4); // li r2,0x1111
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::LR).as_uint() == 0x50, "3: ArchPPC32: failed to disassembly and/or execute mtspr");

        return ret_value;
    }

    unsigned int disass_bl()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x48\x00\x00\x21", 4); // bl 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::LR).as_uint()  == 0x1004, "1: ArchPPC32: failed to disassemble and/or execute BL");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint()  == 0x1024, "2: ArchPPC32: failed to disassemble and/or execute BL");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R2).as_uint()  == 0x1000, "3: ArchPPC32: failed to disassemble and/or execute BL");

        return ret_value;
    }

    unsigned int disass_bctr()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x4e\x80\x04\x20", 4); // bctr
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.cpu.ctx().set(PPC32::CTR, exprcst(32,0x1500));
        sym.mem->write_buffer(0x1500, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R2).as_uint() == 0x1000,"1: ArchPPC32: failed to disassembly and/or execute BCTR");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1504,"2: ArchPPC32: failed to disassembly and/or execute BCTR");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::CTR).as_uint() == 0x1500,"3: ArchPPC32: failed to disassembly and/or execute BCTR");

        return ret_value;
    }

    unsigned int disass_bctrl()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x4e\x80\x04\x21", 4); // bctrl
        sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), code.size());
        sym.cpu.ctx().set(PPC32::CTR, exprcst(32,0x1500));
        sym.mem->write_buffer(0x1500, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1200,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1500,"1: ArchPPC32: failed to disassembly and/or execute BCTRL");

        sym.run_from(0x1200,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R2).as_uint() == 0x1000,"2: ArchPPC32: failed to disassembly and/or execute BCTRL");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1504,"3: ArchPPC32: failed to disassembly and/or execute BCTRL");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::CTR).as_uint() == 0x1500,"4: ArchPPC32: failed to disassembly and/or execute BCTRL");

        return ret_value;
    }

    unsigned int disass_dcbt()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x7c\x02\x52\x2c", 4); // dcbt r2 r10
        sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1200,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1204,"1: ArchPPC32: failed to disassembly and/or execute dcbt");

        return ret_value;
    }

    unsigned int disass_sc()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32, env::OS::LINUX);
        sym.mem->map(0x10000,0x10000);
        sym.mem->map(0x0,0x0);

        string code;


        sym.cpu.ctx().set(PPC32::R0, exprcst(32,5));
        code = string("\x44\x00\x00\x02", 4); // sc 0x0
        sym.mem->write_buffer(0x10000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x10000,1);
        
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004,"1: ArchPPC32: failed to disassembly and/or execute sc");

        return ret_value;
    }

    unsigned int disass_lbz()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC32, maat::env::OS::LINUX);
        sym.mem->map(0x1000,0x2000);
        string code;

        sym.cpu.ctx().set(PPC32::R10, exprcst(32,0x1500));    
        sym.cpu.ctx().set(PPC32::R9, exprcst(32,0x1234)); 
        sym.mem->write(0x1234,exprcst(32,0x12345678));
        code = string("\x89\x49\x00\x00", 4); // lbz r10,0x0(r9)
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);       
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R10).as_uint() == 0x12, "1: ArchPPC32: failed to disassembly and/or execute lbz");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::PC).as_uint() == 0x1004,"2: ArchPPC32: failed to disassembly and/or execute lbz");
        ret_value += _assert( sym.cpu.ctx().get(PPC32::R9).as_uint() == 0x1234,"3: ArchPPC32: failed to disassembly and/or execute lbz");
        ret_value += _assert( sym.mem->read(0x1234,4).as_uint() == 0x12345678, "4: ArchPPC32: failed to disassembly and/or execute lbz");

        return ret_value;
    }

}// Namespace PPC32
}// Namespace Test
using namespace test::archPPC32;

void test_archPPC32() {
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";

    // Start testing
    std::cout << bold << "[" << green << "+" 
         << def << bold << "]" << def << std::left << std::setw(34)
         << " Testing Arch PPC32 support... " << std::flush;
    total += simple_move();
    total += simple_branch();
    total += simple_addition();
    total += addition_16bits();
    total += addition_overflow();
    total += compare_default();
    total += compare_CR3();
    total += bge_branch(); 
    total += storeword_loadword();
    total += disass_bne();
    total += disass_ble();
    total += disass_blt();
    total += disass_bge();
    total += disass_bgt();
    total += disass_cntlzw(); 
    total += disass_subf();
    total += disass_mulli();
    total += disass_mtspr();
    total += disass_bl();  
    total += disass_bctrl();
    // total += disass_dcbt();
    // total += disass_sc(); ///< TODO write a better syscall test...
    // total += disass_lbz();
    // total += for_loop();

    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}