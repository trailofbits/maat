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
namespace archPPC64
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
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        // write to mem map
        sym.mem->map(0x1000,0x2000);
        code = string("\x38\x80\x00\x03",4); // assembly code = li r4 0x03
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        unsigned int ret_value =0;
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R4).as_uint() == 0x03, "R4 is not equal to 0x3");

        return ret_value;        
    }

    unsigned int simple_branch()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");
        
        code = string("\x7c\x05\x48\x00",4); // cpmw r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        code = string("\x48\x00\x00\x08",4); //b skip 1 instruction?
        sym.mem->write_buffer(0x100c,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,4);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::PC).as_uint()==0x01014,"PC didn't increment by 8");

        code = string("\x38\x80\x00\x01",4); // li r4, 0x01
        sym.mem->write_buffer(0x1010,(uint8_t*)code.c_str(), code.size());
        code = string("\x38\xa0\x00\x03",4); //li r5, 0x02
        sym.mem->write_buffer(0x1014,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,5);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R4).as_uint()!=0x01,"R4 not equal to 2");    

        return ret_value;
    }

        unsigned int disass_cmpw()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.cpu.ctx().set(PPC64::R5, exprcst(64, 0x1111));
        sym.cpu.ctx().set(PPC64::R9, exprcst(64, 0xf00001111));


        code = string("\x7c\x05\x48\x00",4); // cpmw r5,r9
        sym.mem->write_buffer(0x1000,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);

        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR0).as_uint() == 0x2, "1:  ArchPPC64: failed to disassembly and/or execute cmpw");

        return ret_value;
    }

    unsigned int simple_addition()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");

        code = string("\x7c\x65\x4a\x14",4); // add r3 r5 r9 
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R3).as_uint()==0x0f,"R3 is not equal to 0x0F");
        
        return ret_value;
    }

    unsigned int addition_16bits()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x00",4); //  li r9,0x00 ori r9, r9, 60000
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x0,"R9 is not equal to 0x0");

        code = string("\x61\x29\xea\x60",4); // ori r9 r9 0xea60
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0xea60,"R9 is not equal to 0xEA60");

        code = string("\x38\xa0\x00\x00",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0x0,"R5 is not equal to 0x0");

        code = string("\x60\xa5\xea\x60",4); // ori r5 r5 0xea60
        sym.mem->write_buffer(0x100c,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,4);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0xea60,"R5 is not equal to 0x0");

        code = string("\x7c\x65\x4a\x15",4); // addc r3 r5 r9 
        sym.mem->write_buffer(0x1010,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,5);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R3).as_uint()==0x1D4C0,"R3 is not equal to 0x1FE");
        
        return ret_value;
    }

    unsigned int addition_Test_Flags()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);

        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0xffffffffabcd1234));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x7fffffffabcd1234));
         
        code = string("\x7c\x64\x2c\x15",4); // addco. r3, r4, r5
        sym.mem->write_buffer(0x1000,(uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R3).as_uint() == 0x7fffffff579a2468, "1. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint() == 0xffffffffabcd1234, "2. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R4).as_uint() == 0x7fffffffabcd1234, "3. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR0).as_uint() == 0x04, "4. Addition test flag failed to disassemble. Result is not positive.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_SO).as_uint() == 0x0, "5. Addition test flag failed to disassemble. Summary overflow flag set.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_OV).as_uint() == 0x0, "6. Addition test flag failed to disassemble. Overflow flag set");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_CA).as_uint() == 0x1, "7. Addition test flag failed to disassemble. Carry flag not Set");

        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0x7fffffffffffffff));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x1));

        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R3).as_uint() == 0x8000000000000000, "8. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint() == 0x7fffffffffffffff, "9. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R4).as_uint() == 0x1, "10. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR0).as_uint() == 9, "11. Addition test flag failed to disassemble. Result is not negative or SO bit not set.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_SO).as_uint() == 0x1, "12. Addition test flag failed to disassemble. Summary overflow flag not set.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_OV).as_uint() == 0x1, "13. Addition test flag failed to disassemble. Overflow flag not set");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_CA).as_uint() == 0x0, "14. Addition test flag failed to disassemble. Carry flag Set");

        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0x8000000000000000));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x8000000000000000));
        
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R3).as_uint() == 0, "15. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint() == 0x8000000000000000, "16. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R4).as_uint() == 0x8000000000000000, "17. Addition test flag failed to disassemble");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR0).as_uint() == 3, "18. Addition test flag failed to disassemble. Result is not equal/zero or SO bit not set.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_SO).as_uint() == 0x1, "19. Addition test flag failed to disassemble. Summary overflow flag not set.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_OV).as_uint() == 0x1, "20. Addition test flag failed to disassemble. Overflow flag not set");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::XER_CA).as_uint() == 0x1, "21. Addition test flag failed to disassemble. Carry flag not set");

        return ret_value;
    }

    unsigned int compare_default()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");

        code = string("\x7c\x05\x48\x00",4); // cmpw r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR0).as_uint()==0x04, "CR0 isn't set to 4 meaning r5 not greater than r9");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR).as_uint()==1073741824, "CR0 isn't set in the right spot of in CR");

        return ret_value;
    }

    unsigned int storeword_loadword()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0xffffff);
        sym.mem->map(0x0,0);
        sym.cpu.ctx().set(PPC64::R3, exprcst(64,0xDEADBEEF));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x110000));

        code = string("\x90\x64\x00\x00",4); // stw r3,0(r4)
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); 
        code = string("\x80\xa4\x00\x00",4); // lwz r5,0(r4) 
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size()); 

        sym.run_from(0x1000,2);
        ret_value += _assert((uint32_t)sym.mem->read(0x110000, 4).as_uint() == 0xDEADBEEF, "1: Failed to disassemble store and load instructions.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint() == 0xDEADBEEF, "2: Failed to disassemble store and load instructions.");
        
        sym.cpu.ctx().set(PPC64::R3, exprcst(64,0x12345678DEADBEEF));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x110000));
        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0));

        sym.run_from(0x1000,2);
        ret_value += _assert(sym.mem->read(0x110000, 4).as_uint() == 0xDEADBEEF, "3: Failed to disassemble store and load instructions.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint() == 0xDEADBEEF, "4: Failed to disassemble store and load instructions.");

        sym.cpu.ctx().set(PPC64::R3, exprcst(64,0x12345678));
        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0));

        sym.cpu.ctx().set(PPC64::R3, exprcst(64,0xBADC0FFEE0DDF00D));
        code = string("\xf8\x64\x00\x00",4); // std r3,0(r4) 
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); 
        code = string("\xE8\xA4\x00\x00",4); // ld r5,0(r4) 
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,2);

        ret_value += _assert(sym.mem->read(0x110000, 8).as_uint() == 0xBADC0FFEE0DDF00D, "5: Failed to disassemble store and load instructions.");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint() == 0xBADC0FFEE0DDF00D, "6: Failed to disassemble store and load instructions.");

        return ret_value;
    }

        unsigned int mullw_disass()
    {
        // mullw = Multiply Low Word
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0xffffff);
        sym.mem->map(0x0,0);

        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0x12345678));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x100000001));
        sym.cpu.ctx().set(PPC64::R3, exprcst(64,0));
        code = string("\x7c\x64\x29\xd6",4); // mullw r3, r4, r5 
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); 

        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R3).as_uint() == 0x12345678, "1: Failed to disassemble multiply low word.");


        return ret_value;
    }

    unsigned int compare_CR3()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x05",4); // li r5, 0x05
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0x05,"R5 is not equal to 0x0A");

        code = string("\x7d\x85\x48\x00",4); // cmpw cr3, r5,r9
        sym.mem->write_buffer(0x1008,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR3).as_uint()==0x02, "CR3 isn't set to 1 meaning r5 not equal to r9");
        ret_value += _assert(sym.cpu.ctx().get(PPC64::CR).as_uint()==131072, "CR3 isn't set in the right spot of in CR");

        return ret_value;
    }

    unsigned int bge_branch()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);

        code = string("\x39\x20\x00\x05",4); //  li r9,0x05
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x05,"R9 is not equal to 0x05");

        code = string("\x38\xa0\x00\x0a",4); // li r5, 0x0a
        sym.mem->write_buffer(0x1004,(uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R5).as_uint()==0x0a,"R5 is not equal to 0x0A");

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

    // UNFINISHED UNIT TEST
    unsigned int for_loop()
    {
        string code;
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);

        unsigned int test_reg_val = 0;

        code = string("\x39\x20\x00\x00",4); //  li r9,0x0
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==0x00,"R9 is not equal to 0x0");

        code = string("\x91\x3f\x00\x0c",4); //  stw r9,12(r31)
        sym.mem->write_buffer(0x1004, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);

        cout<<"before b:"<<sym.cpu.ctx().get(PPC64::PC)<<endl;
        code = string("\x48\x00\x00\x1c",4); //  b 
        sym.mem->write_buffer(0x1008, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,3);
        cout<<"after b:"<<sym.cpu.ctx().get(PPC64::PC)<<endl;

        code = string("\x81\x3f\x00\x08",4); //  lwz r9,8(r31)
        sym.mem->write_buffer(0x100c, (uint8_t*)code.c_str(), code.size()); 
        sym.run_from(0x1000,4);
        cout<<"what is in r9 offset 8: "<<sym.cpu.ctx().get(PPC64::R9).as_uint()<<endl;
        test_reg_val= sym.cpu.ctx().get(PPC64::R9).as_uint();
        //test 

        code = string("\x39\x29\x00\x01",4); //  addi r9 r9 1
        sym.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,5);
        //test
        test_reg_val;
        // ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint()==(test_reg_val+1),"R9 didn't get plus 1");

        code = string("\x91\x3f\x00\x0c",4); //  stw r9,8(r31)
        sym.mem->write_buffer(0x1014, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,6);

        code = string("\x81\x3f\x00\x0c",4);// lwz r9,12(r31)
        sym.mem->write_buffer(0x1018, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,7);
        cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC64::R9).as_uint()<<endl;

        code = string("\x39\x29\x00\x01",4);// addi r9,r9,1
        sym.mem->write_buffer(0x101c, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,8);
        cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC64::R9).as_uint()<<endl;

        code = string("\x91\x3f\x00\x0c",4);// stw r9,12(r31)
        sym.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,9);
        // cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC64::r9).as_uint()<<endl;

        code = string("\x81\x3f\x00\x0c",4);// lwz r9,12(r31)
        sym.mem->write_buffer(0x1024, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,10);
        cout<<"what is in r9 offset 12: "<<sym.cpu.ctx().get(PPC64::R9).as_uint()<<endl;

        code = string("\x2c\x09\x00\x09",4);// cmpwi r9,9
        sym.mem->write_buffer(0x1028, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,11);
        cout<<"what is inside cmp register: "<<sym.cpu.ctx().get(PPC64::CR).as_uint()<<endl;

        code = string("\x40\x81\xff\xe0",4);// ble 1000046c
        sym.mem->write_buffer(0x102c, (uint8_t*)code.c_str(), code.size()); // code.size() = 4
        sym.run_from(0x1000,12);

        return ret_value;
    }
    
    unsigned int disass_bne()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x40\x82\x00\x20", 4); // bne 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "1: ArchPPC64: failed to disassembly and/or execute BNE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "2: ArchPPC64: failed to disassembly and/or execute BNE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,1));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "3: ArchPPC64: failed to disassembly and/or execute BNE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "4: ArchPPC64: failed to disassembly and/or execute BNE");

        return ret_value;
    }

    unsigned int disass_ble()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x40\x81\x00\x20", 4); // ble 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "1: ArchPPC64: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,10));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "2: ArchPPC64: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "3: ArchPPC64: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "4: ArchPPC64: failed to disassembly and/or execute BLE");

        
        return ret_value;
    }

    unsigned int disass_blt()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;
        
        code = string("\x41\x80\x00\x20", 4); // blt 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "1: ArchPPC64: failed to disassembly and/or execute BLE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "2: ArchPPC64: failed to disassembly and/or execute BLE");
        
        return ret_value;
    }
    
    unsigned int disass_bge()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;
        
        code = string("\x40\x80\x00\x20", 4); // bge 0x12
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,6));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "1: ArchPPC64: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "2: ArchPPC64: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "3: ArchPPC64: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,9));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "4: ArchPPC64: failed to disassembly and/or execute BGE");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "5: ArchPPC64: failed to disassembly and/or execute BGE");

        return ret_value;
    }

    unsigned int disass_bgt()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x41\x81\x00\x20", 4); // bgt 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,6));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "1: ArchPPC64: failed to disassembly and/or execute BGT");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,4));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1020, "2: ArchPPC64: failed to disassembly and/or execute BGT");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,9));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "3: ArchPPC64: failed to disassembly and/or execute BGT");

        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,8));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "4: ArchPPC64: failed to disassembly and/or execute BGT");
        
        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,2));
        sym.run_from(0x1000, 1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "5: ArchPPC64: failed to disassembly and/or execute BGT");
        
        return ret_value;
    }

    unsigned int disass_cntlzw()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC64::R3, exprcst(64,0x1234));
        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0x5));
        code = string("\x7c\x65\x00\x34", 4); // cntlzw r5,r3
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "1: ArchPPC64: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R5).as_uint() == 51, "1: ArchPPC64: R5 not equal to 51");


        sym.cpu.ctx().set(PPC64::R8, exprcst(64,0x674321));
        sym.cpu.ctx().set(PPC64::R10, exprcst(64,0x5));
        code = string("\x7d\x0a\x00\x34", 4); // cntlzw r10,r8
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "2: ArchPPC64: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R10).as_uint() == 41, "2: ArchPPC64: R10 not equal to 41");

        sym.cpu.ctx().set(PPC64::R8, exprcst(64,0x1));
        sym.cpu.ctx().set(PPC64::CR0, exprcst(8,0x0));
        code = string("\x7d\x0a\x00\x35", 4); // cntlzw. r10,r8
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004, "3: ArchPPC64: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R10).as_uint() == 63, "3: ArchPPC64: failed to disassembly and/or execute cntlzw");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::CR0).as_uint() == 4, "3: ArchPPC64: failed to disassembly and/or execute cntlzw");

        return ret_value;
    }

        unsigned int disass_subf()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC64::R3, exprcst(64,10000));
        sym.cpu.ctx().set(PPC64::R4, exprcst(64,5000));
        code = string("\x7c\x44\x18\x50", 4); // subf r2, r4, r3
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 5000, "1: ArchPPC64: failed to disassembly and/or execute subf");

        code = string("\x7c\x44\x18\x51", 4); // subf. r2, r4, r3
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 5000, "2: ArchPPC64: failed to disassembly and/or execute subf.");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::CR0).as_uint() == 4, "3: ArchPPC64: R3 is not greater than R4");

        return ret_value;
    }

    unsigned int disass_mulli()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC64::R4, exprcst(64,0x3000));
        code = string("\x1c\xc4\x00\x0a", 4); // mulli r6, r4, 10 
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R6).as_uint() == 0x1e000, "ArchPPC64: failed to disassembly and/or execute mulli");

        return ret_value;
    }

    unsigned int disass_mtspr()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC64::R5, exprcst(64,0x50));
        code = string("\x7c\xa8\x03\xa6", 4); // mtspr LR,r5
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::LR).as_uint() == 0x50, "1: ArchPPC64: failed to disassembly and/or execute mtspr");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 0x1000, "2: ArchPPC64: failed to disassembly and/or execute mtspr");

        sym.cpu.ctx().set(PPC64::R0, exprcst(64,0x50));
        code = string("\x7c\x08\x03\xa6", 4); // mtspr LR,r0
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x11\x11", 4).c_str(), 4); // li r2,0x1111
        sym.run_from(0x1000,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::LR).as_uint() == 0x50, "3: ArchPPC64: failed to disassembly and/or execute mtspr");

        return ret_value;
    }

    unsigned int test_r0()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        sym.cpu.ctx().set(PPC64::R7, exprcst(64,0x1234));
        sym.cpu.ctx().set(PPC64::R0, exprcst(64,0x1234));
        code = string("\x7c\xa7\x02\x14", 4); // add r5, r7, r0
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1004, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R5).as_uint() == 0x2468, "1: ArchPPC64: failed to disassembly and/or execute test_r0");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 0x1000, "1: ArchPPC64: failed to disassembly and/or execute test_r0");

        code = string("\x38\x60\x01\x00", 4); // addi r3, r0, 256
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R0).as_uint() == 0x1234,"2: ArchPPC64: failed to disassembly and/or execute test_r0");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R3).as_uint() == 0x100, "2: ArchPPC64: failed to disassembly and/or execute test_r0");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 0x1000, "2: ArchPPC64: failed to disassembly and/or execute test_r0");

        return ret_value;
    }

    unsigned int disass_bl()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x48\x00\x00\x21", 4); // bl 0x20
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.mem->write_buffer(0x1020, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::LR).as_uint()  == 0x1004, "1: ArchPPC64: failed to disassemble and/or execute BL");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint()  == 0x1024, "2: ArchPPC64: failed to disassemble and/or execute BL");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint()  == 0x1000, "3: ArchPPC64: failed to disassemble and/or execute BL");

        return ret_value;
    }

    unsigned int disass_bctr()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x4e\x80\x04\x20", 4); // bctr
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
        sym.cpu.ctx().set(PPC64::CTR, exprcst(32,0x1500));
        sym.mem->write_buffer(0x1500, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1000,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 0x1000,"1: ArchPPC64: failed to disassembly and/or execute BCTR");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1504,"2: ArchPPC64: failed to disassembly and/or execute BCTR");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::CTR).as_uint() == 0x1500,"3: ArchPPC64: failed to disassembly and/or execute BCTR");

        return ret_value;
    }

    unsigned int disass_bctrl()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64);
        sym.mem->map(0x1000,0x2000);
        sym.mem->map(0x0,0x1000);
        string code;

        code = string("\x4e\x80\x04\x21", 4); // bctrl
        sym.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), code.size());
        sym.cpu.ctx().set(PPC64::CTR, exprcst(64,0x1500));
        sym.mem->write_buffer(0x1500, (uint8_t*)string("\x38\x40\x10\x00", 4).c_str(), 4); // li r2,0x1000
        sym.run_from(0x1200,1);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1500,"1: ArchPPC64: failed to disassembly and/or execute BCTRL");

        sym.run_from(0x1200,2);
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R2).as_uint() == 0x1000,"2: ArchPPC64: failed to disassembly and/or execute BCTRL");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1504,"3: ArchPPC64: failed to disassembly and/or execute BCTRL");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::CTR).as_uint() == 0x1500,"4: ArchPPC64: failed to disassembly and/or execute BCTRL");

        return ret_value;
    }

    unsigned int disass_sc()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64, env::OS::LINUX);
        sym.mem->map(0x10000,0x10000);
        sym.mem->map(0x0,0x0);

        string code;


        sym.cpu.ctx().set(PPC64::R0, exprcst(32,5));
        code = string("\x44\x00\x00\x02", 4); // sc 0x0
        sym.mem->write_buffer(0x10000, (uint8_t*)code.c_str(), code.size());
        sym.run_from(0x10000,1);
        
        ret_value += _assert( sym.cpu.ctx().get(PPC64::PC).as_uint() == 0x1004,"1: ArchPPC64: failed to disassembly and/or execute sc");

        return ret_value;
    }

    unsigned int disass_lbz()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64, maat::env::OS::LINUX);
        sym.mem->map(0x1000,0x2000);
        string code;

        sym.cpu.ctx().set(PPC64::R10, exprcst(64,0x1500));    
        sym.cpu.ctx().set(PPC64::R9, exprcst(64,0x1234)); 
        sym.mem->write(0x1234,exprcst(64,0x1abc2def12345678));

        code = string("\x89\x49\x00\x00", 4); // lbz r10,0x0(r9)

        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());

        sym.run_from(0x1000,1);      
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R10).as_uint() == 0x1a, "1: ArchPPC64: failed to disassembly and/or execute lbz");
        ret_value += _assert( sym.cpu.ctx().get(PPC64::R9).as_uint() == 0x1234,"3: ArchPPC64: failed to disassembly and/or execute lbz");
        ret_value += _assert( sym.mem->read(0x1234,4).as_uint() == 0x1abc2def, "4: ArchPPC64: failed to disassembly and/or execute lbz");

        return ret_value;
    }

    unsigned int disass_extsw()
    {
        unsigned int ret_value = 0;
        MaatEngine sym = MaatEngine(Arch::Type::PPC64, maat::env::OS::LINUX);
        sym.mem->map(0x1000,0x2000);
        string code;
        
        sym.cpu.ctx().set(PPC64::R9, exprcst(64,0x12345678abcdef12));
        code = string("\x7d\x29\x07\xb4",4 ); // extsw r9,r9
        sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(),code.size());

        sym.run_from(0x1000,1);
        ret_value += _assert(sym.cpu.ctx().get(PPC64::R9).as_uint() == 0xffffffffabcdef12, "1: ArchPPC64: Failed to disassemble extend signed word");
        return ret_value;
    }

}// Namespace PPC64
}// Namespace Test
using namespace test::archPPC64;

void test_archPPC64() {
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";

    // Start testing
    std::cout << bold << "[" << green << "+" 
         << def << bold << "]" << def << std::left << std::setw(34)
         << " Testing Arch PPC64 support... " << std::flush;

    /* 
    commented out code so its faster to run, 
    you can make it faster if you pass a 
    reference to an already existing maatEngine like you did in your previous test casses
    */
    total += simple_move();
    total += simple_branch();
    total += disass_cmpw();
    total += simple_addition();
    total += addition_16bits();
    total += addition_Test_Flags();
    total += storeword_loadword();
    total += mullw_disass();
    total += compare_default();
    total += compare_CR3();
    total += bge_branch(); 
    total += disass_bne();
    total += disass_ble();
    total += disass_blt();
    total += disass_bge();
    total += disass_bgt();
    total += disass_cntlzw(); 
    total += disass_subf();
    total += disass_mulli();
    total += disass_mtspr();
    total += test_r0();
    total += disass_bl();  
    total += disass_bctrl();
    total += disass_lbz();
    total += disass_extsw();
    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}