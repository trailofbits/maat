#include "maat/arch.hpp"
#include "maat/engine.hpp"
#include "maat/exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>

using std::string;

namespace test{
    namespace archX64{
        
        using namespace maat;
        
        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl << std::flush; 
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
         
        unsigned int reg_translation()
        {
            unsigned int nb = 0;
            reg_t reg;
            X64::ArchX64 arch = X64::ArchX64();
            for (reg = 0; reg < X64::NB_REGS; reg++)
            {
                nb += _assert( arch.reg_num(arch.reg_name(reg)) == reg , "ArchX64: translation reg_num <-> reg_name failed");
            }
            nb += _assert(arch.sp() == X64::RSP, "ArchX64: translation reg_num <-> reg_name failed");
            nb += _assert(arch.pc() == X64::RIP, "ArchX64: translation reg_num <-> reg_name failed");
            return nb;
        }
        
        unsigned int disass_blsmsk(MaatEngine& engine){
            unsigned int nb = 0;
            std::string code;
            
            
            
            code = std::string("\xC4\xE2\x78\xF3\xD3", 5); // blsmsk eax, ebx
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x123400001010 : 0x00001010
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400001010));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x00001010));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x001f)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            
            // 0x00001010 : 0xaaaa00100000
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x00001010));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0xaaaa00100000));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x001fffff)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
                        
            // On 64 bits
            code = std::string("\xc4\xe2\xf8\xf3\xd3", 5); // blsmsk eax, ebx
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // 0 : 0
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0xffffffffffffffff)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
                            
            // 0xffffffffffffffff : 0x0020000000000000
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xffffffffffffffff));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0x0020000000000000));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x003fffffffffffff)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSMSK");
            return nb;
        }
        
        unsigned int disass_blsr(MaatEngine& engine){
            unsigned int nb = 0;
            std::string code;
            
            
            
            code = std::string("\xC4\xE2\x78\xF3\xCB", 5); // blsr eax, ebx
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 5);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x000000f0
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x000000f0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0xe0)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            
            // 0x00100000
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x00100000));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            
            // On 64 bits
            code = std::string("\xc4\xe2\xf8\xf3\xcb", 5); // blsr rax, rbx
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);            
            
            // 0
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x12340000abcd));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");

            // 0xffffffffffffffff
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0xffffffffffffffff));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0xfffffffffffffffe)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BLSR");
            return nb;
        }

        unsigned int disass_bsf(MaatEngine& engine){
            unsigned int nb = 0;
            std::string code;
            
            /* On 16 bits */
            code = std::string("\x66\x0F\xBC\xC3", 4); // bsf ax, bx
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            engine.cpu.ctx().set(X64::RAX, 0);
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x00001100));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 8)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSF");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSF");
            // bsf 0x0
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BSF");
            // bsf 0x8000
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x8000));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 15)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSF");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSF");
            
            // bsf 0x10000
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x10000));
            engine.cpu.ctx().set(X64::ZF, exprcst(8,0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BSF");
            
            /* On 32 bits */
            code = std::string("\x0F\xBC\xC3", 3); // bsf eax, ebx
            engine.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1200+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123456786465112));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x00010000));
            engine.run_from(0x1200, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 16)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSF");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSF");
                            
            /* On 64 bits */
            code = std::string("\x48\x0f\xbc\xc3", 4); // bsf rax, rbx
            engine.mem->write_buffer(0x1300, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1300+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x80000000
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x80000000));
            engine.run_from(0x1300, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 31)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSF");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSF");
                            
            // bsf 0x200000000
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x200000000));
            engine.run_from(0x1300, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 33)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSF");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSF");                
            
            // bsf 0
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0));
            engine.run_from(0x1300, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BSF");      
            return nb;
        }
        
        unsigned int disass_bsr(MaatEngine& engine){
            unsigned int nb = 0;
            std::string code;
            
            
            
            /* On 16 bits */
            code = std::string("\x66\x0F\xBD\xC3", 4); // bsr ax, bx
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bsr 0x1100
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400001100));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x00001100));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x123400000000+ 12)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSR");
            // bsr 0x0
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BSR");
            // bsr 0x8000
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x8000));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x123400000000+15)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSR");
            
            // bsr 0x10000
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x10000));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BSR");
            
            /* On 32 bits */
            code = std::string("\x0F\xBD\xC3", 3); // bsr eax, ebx
            engine.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1200+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            // bsr 0x1100
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1234567800000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x00001100));
            engine.run_from(0x1200, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 12)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSR");
                            
            // On 64 bits 
            code = std::string("\x48\x0f\xbd\xc3", 4); // bsr rax, rbx
            engine.mem->write_buffer(0x1300, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1300+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            // bsr 0x80000000
            engine.cpu.ctx().set(X64::RAX, exprcst(64,456864));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x80000001));
            engine.run_from(0x1300, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 31)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSR");
                 
            // bsr 0x300000000
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x300000001));
            engine.run_from(0x1300, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 33)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSR");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BSR");
                            
            // bsr 0
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0));
            engine.run_from(0x1300, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BSR");         
            return nb;
        }
        
        unsigned int disass_bswap(MaatEngine& engine){
            unsigned int nb = 0;
            std::string code;
            
            
            
            /* On 32 bits */
            code = std::string("\x0F\xC8", 2); // bswap eax
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bswap 0x1111000012345678
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1111000012345678));
            engine.run_from(0x1160, 1);
            
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x78563412)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSWAP");
                            
            // bswap 0x100111100
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x100111100));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x00111100)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSWAP");
             
            /* On 64 bits */
            code = std::string("\x48\x0f\xc8", 3); // bswap rax
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bswap 0x1111000012345678
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1111000012345678));
            engine.run_from(0x1170, 1);
            
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x7856341200001111)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSWAP");
                            
            // bswap 0x100111100
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x100111100));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint(*engine.vars) == exprcst(64, 0x0011110001000000)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BSWAP");

            return nb;
        }
        
        unsigned int disass_bt(MaatEngine& engine){
            unsigned int nb = 0;
            std::string code;
            
            
            
            /* On 16 bits */
            code = std::string("\x66\x0F\xA3\xD8", 4); // bt ax, bx
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x8, 3)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x8));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,3));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == exprcst(64, 1)->as_uint(*engine.vars),
                            "ArchX64: failed to disassembly and/or execute BT");

            // bit(0x8, 4)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x8));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,4));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            // bit(0x8, 19) --> 19 = 3%16
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x8));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,19));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
            
            // from memory
            code = std::string("\x66\x0F\xA3\x18", 4); // bt word ptr [rax], bx
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1700, exprcst(32, 0xffffffff));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1701));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,8));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            /* On 32 bits */
            code = std::string("\x0F\xA3\xD8", 3); // bt eax, ebx
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x10000000, 28)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,28));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            // bit(0x10000000, 29)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123410000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,29));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            // bit(0x10000000, 60)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1234567810000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,60));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            /* With an imm */
            code = std::string("\x0F\xBA\xE0\x0D", 4); // bt eax, 13
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x2000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,13));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            code = std::string("\x0F\xBA\xE0\x0C", 4); // bt eax, 12
            engine.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1200+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x2000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,13));
            engine.run_from(0x1200, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BT");
            
            // On 64 bits
            code = std::string("\x48\x0f\xa3\xd8", 4); // bt rax, rbx
            engine.mem->write_buffer(0x1210, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1210+code.size(), (uint8_t*)std::string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x100000001234, 44)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x100000001234));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,44));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x1210, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            // bit(0x400000001234, 45)
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x400000001234));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,45));
            engine.run_from(0x1210, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 0,
                            "ArchX64: failed to disassembly and/or execute BT");
                            
            // bit(0x100000000, (64+32))
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x100000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,96));
            engine.run_from(0x1210, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint(*engine.vars) == 1,
                            "ArchX64: failed to disassembly and/or execute BT");
            
            return nb;
        }
        
        
        
        unsigned int disass_cmp(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            /* cmp reg, imm */
            code = string("\x3C\x0f", 2); // cmp al(ff), f
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xff));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10ff));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
                            
            code = string("\x3C\x81", 2); // cmp al(0x80), 0x81
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x80));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            
            
            code = string("\x66\x3d\xff\x00", 4); // cmp ax, ff
            engine.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1ffff));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
                            
            code = string("\x66\x83\xF8\x01", 4); // cmp ax, 1
            engine.mem->write_buffer(0x1200, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xfa000009));
            engine.run_from(0x1200, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            
            
            code = string("\x83\xF8\x48", 3); // cmp eax, 0x48
            engine.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xff000000));
            engine.run_from(0x1010, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            
            
            code = string("\x3D\x34\x12\x00\x00", 5); // cmp eax, 0x1234
            engine.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 5);
            engine.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10001235));
            engine.run_from(0x1020, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            
            
            code = string("\x3D\x00\x00\x00\xFF", 5); // cmp eax, 0xff000000
            engine.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 5);
            engine.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xffff0000));
            engine.run_from(0x1030, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
                            
            code = string("\x3D\x00\x00\xFF\xFF", 5); // cmp eax, 0xffff0000
            engine.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 5);
            engine.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xff000000));
            engine.run_from(0x1040, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");

            code = string("\x48\x3D\x00\xF0\xFF\xFF", 6); // cmp rax, -0x1000
            engine.mem->write_buffer(0x1100, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1100+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xf0000000));
            engine.run_from(0x1100, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");

            /* cmp reg,reg */
            code = string("\x38\xFC", 2); // cmp ah, bh
            engine.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xf800));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x7900));
            engine.run_from(0x1050, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");

            code = string("\x48\x39\xd8", 3); // cmp rax, rbx
            engine.mem->write_buffer(0x1090, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1090+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xf800000000001234));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x7900000000001234));
            engine.run_from(0x1090, 1);
            
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");    

            /* cmp imm, mem */
            code = string("\x80\x3C\x25\x00\x17\x00\x00\x03", 8); // cmp byte ptr [0x1700], 0x3 
            engine.mem->write_buffer(0x1080, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1080+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.mem->write(0x1700, exprcst(64, 0x01f62303));
            engine.run_from(0x1080, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");

            /* cmp reg,mem */
            code = string("\x3B\x03", 2); // cmp eax, dword ptr [ebx] 
            engine.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.mem->write(0x1700, exprcst(64, 0xAAAA));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xAAAA));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x1700));
            engine.run_from(0x1060, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");

            /* cmp mem,reg */
            code = string("\x48\x39\x18", 3); // cmp qword ptr [rax], rbx 
            engine.mem->write_buffer(0x1070, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1070+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.mem->write(0x123400000010, exprcst(64, 0xffffffffffffffff));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000010));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0xffffffffffffffff));
            engine.run_from(0x1070, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMP");

            return nb;
        }
        
        unsigned int disass_cmpsb(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            code = string("\xA6", 1); // cmpsb
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1000, exprcst(8, 0xff));
            engine.mem->write(0x1500, exprcst(8, 0xf));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == exprcst(64, 0xfff)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == exprcst(64, 0x14ff)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            
            engine.mem->write(0x1000, exprcst(8, 0x1));
            engine.mem->write(0x1500, exprcst(8, 0xff));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == exprcst(64, 0x1001)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == exprcst(64, 0x1501)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSB");
            
            return nb;
        }
        
        unsigned int disass_cmpsd(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\xA7", 1); // cmpsd
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1000, exprcst(64, 0xAAAA));
            engine.mem->write(0x1500, exprcst(64, 0xAAAA));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == exprcst(64, 0xffc)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == exprcst(64, 0x14fc)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            
            engine.mem->write(0x1000, exprcst(64, 0x1234));
            engine.mem->write(0x1500, exprcst(64, 0x1235));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == exprcst(64, 0x1004)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == exprcst(64, 0x1504)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSD");
            
            return nb;
        }
        
        unsigned int disass_cmpsq(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            code = string("\x48\xA7", 2); // cmpsq
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1000, exprcst(16, 0xAAAA000011110001));
            engine.mem->write(0x1500, exprcst(16, 0xAAAA000011110000));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == 0xff8,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == 0x14f8,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            
            engine.mem->write(0x1000, exprcst(64, 0x1000000000001234));
            engine.mem->write(0x1500, exprcst(64, 0x1000000000001235));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == 0x1008,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == 0x1508,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSQ");
            
            return nb;
        }
        
        unsigned int disass_cmpsw(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xA7", 2); // cmpsw
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1000, exprcst(16, 0xAAAA));
            engine.mem->write(0x1500, exprcst(16, 0xAAAA));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == exprcst(64, 0xffe)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == exprcst(64, 0x14fe)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSW");

            engine.mem->write(0x1000, exprcst(64, 0x1234));
            engine.mem->write(0x1500, exprcst(64, 0x1235));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RSI, exprcst(64,0x1000));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSI).as_uint() == exprcst(64, 0x1002)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == exprcst(64, 0x1502)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPSW");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPSW");

            return nb;
        }
        
        unsigned int disass_cmpxchg(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            /* On 8 bits */
            code = string("\x0F\xB0\xEF", 3); // cmpxchg bh, ch
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1234000021));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x2100));
            engine.cpu.ctx().set(X64::RCX, exprcst(64,0x4200));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x1234000021)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == exprcst(64, 0x4200)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::RCX).as_uint() == exprcst(64, 0x4200)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            
            /* On 16 bits */
            code = string("\x66\x0F\xB1\x0B", 4); // cmpxchg word ptr [rbx], cx
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
        
            engine.mem->write(0x1700, exprcst(16, 0x1111));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x4321));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x1700));
            engine.cpu.ctx().set(X64::RCX, exprcst(64,0x1000BBBB));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x1111)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == exprcst(64, 0x1700)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::RCX).as_uint() == exprcst(64, 0x1000BBBB)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            
            /* On 32 bits */
            code = string("\x0f\xb1\xcb", 3); // cmpxchg ebx, ecx
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaaaa000000004321));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x0));
            engine.cpu.ctx().set(X64::RCX, exprcst(64,0x1000BBBB));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x0)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == exprcst(64, 0x0)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::RCX).as_uint() == exprcst(64, 0x1000BBBB)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CMPXCHG");
            
            return nb;
        }
        
        unsigned int disass_cqo(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x48\x99", 2); // cqo
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x12345678deadcafe));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10,
                            "ArchX64: failed to disassembly and/or execute CQO");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CQO");

            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x7f98000000000000));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x888812345678));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x7f98000000000000,
                            "ArchX64: failed to disassembly and/or execute CQO");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CQO");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x8000000000000001));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0xdeadbeef12345678));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x8000000000000001,
                            "ArchX64: failed to disassembly and/or execute CQO");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0xffffffffffffffff,
                            "ArchX64: failed to disassembly and/or execute CQO");

            return nb;
        }
        
        unsigned int disass_cwd(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x66\x99", 2); // cwd
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x1234));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x10)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0x0)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");

            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x7f98));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x1234));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x7f98)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0x0)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x8000));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x123400001234));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x8000)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0x12340000ffff)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10000106));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x1234));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x10000106)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWD");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute CWD");

            return nb;
        }
        
        unsigned int disass_cwde(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            
            
            
            code = string("\x98", 1); // cwde
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x10)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWDE");

            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x7f98));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x7f98)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWDE");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400008000));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0xffff8000)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWDE");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaaa000010000106));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x00000106)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute CWDE");

            return nb;
        }
        
        unsigned int disass_dec(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            
            
            
            
            code = string("\xff\xc8", 2); // dec eax
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000021));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x20)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::AF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            
            
            
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1111ffffff01));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0xffffff00)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::AF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            return nb;
            
            code = string("\x48\xff\xc8", 3); // dec rax
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000022));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x123400000021)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            nb += _assert(  engine.cpu.ctx().get(X64::AF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute DEC");
            return nb;
        }
     
        unsigned int disass_div(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            
            
            
            /* On 8 bits */
            code = string("\xF6\xF3", 2); // div bl
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123410000015));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x4));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x123410000105)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DIV");
            
            
            /* On 16 bits */
            code = string("\x66\xF7\xF3", 3); // div bx
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
			engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123410000015));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x4));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x10000000));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x123410000005)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DIV");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0x10000001)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DIV");
                            
            /* On 32 bits */
            code = string("\xF7\x33", 2); // div dword ptr [rbx]
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1700, exprcst(32, 0x24));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000243));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x1700));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x1234000011111000));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x8e38e39e)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DIV");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0xb)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DIV");

            /* On 64 bits */
            code = string("\x48\xF7\x33", 3); // div qword ptr [rbx]
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1700, exprcst(64, 0x111100000000));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaaaa00000000));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x1700));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x1234000011111000));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x110e110e010e0118)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute DIV");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0x1200000000,
                            "ArchX64: failed to disassembly and/or execute DIV");

            return nb;
        }

        unsigned int disass_idiv(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            /* On 8 bits */
            code = string("\xF6\xFB", 2); // idiv bl
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xfe\xff\xff", 3).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10000015));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,-4));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x100001fb)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute IDIV");
            
            
            /* On 16 bits */
            code = string("\x66\xF7\xFB", 3); // idiv bx
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,-21));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x4));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x10000000));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0xffffffffffff3ffa)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute IDIV");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0x10000003)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute IDIV");

            engine.cpu.ctx().set(X64::RAX, exprcst(64,-24));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,0x67));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x10000000));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0xffffffffffff027c)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute IDIV");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == exprcst(64, 0x10000004)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute IDIV");
            
            /* On 64 bits */
            code = string("\x48\xf7\xfb", 3); // idiv rbx
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);

            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x4400000001));
            engine.cpu.ctx().set(X64::RBX, exprcst(64,-2));
            engine.cpu.ctx().set(X64::RDX, exprcst(64,0x1004641651));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x7fffffddffffffff)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute IDIV");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0xffffffffffffffff,
                            "ArchX64: failed to disassembly and/or execute IDIV");

            return nb;
        }
        
        
        unsigned int disass_imul(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            /* One-operand */
            code = string("\xF6\xEB", 2); // imul bl 
            engine.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,48));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 4));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x00C0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 4, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1002, "ArchX64: failed to disassembly and/or execute IMUL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x4200fc));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 4));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x42fff0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 4, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1002, "ArchX64: failed to disassembly and/or execute IMUL");
            
            code = string("\x66\xF7\xEB", 3); // imul bx
            engine.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,48));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 4));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RDX, exprcst(64, 0x11001234));
            engine.run_from(0x1010, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xC0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 4, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0x11000000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1013, "ArchX64: failed to disassembly and/or execute IMUL");
            
            code = string("\xF7\xEB", 2); // imul ebx
            engine.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1230000000000+ 4823424));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, -423));
            engine.cpu.ctx().set(X64::RDX, exprcst(64, 0x11001234));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1020, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x86635d80, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == -423, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == 0xffffffff, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1022, "ArchX64: failed to disassembly and/or execute IMUL");

            code = string("\x48\xF7\xEB", 3); // imul rbx
            engine.mem->write_buffer(0x2020, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x2020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,-2));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0x3300000000));
            engine.cpu.ctx().set(X64::RDX, exprcst(64, 0x11001234));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x2020, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == -0x6600000000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x3300000000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RDX).as_uint() == -1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            
            /* Two-operands */
            code = string("\x66\x0F\xAF\xC3", 4); // imul ax, bx
            engine.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123410000002)); // 2 * -2 
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0x1000fffe));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1030, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x12341000fffc, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x1000fffe, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1034, "ArchX64: failed to disassembly and/or execute IMUL");
            
            code = string("\x0F\xAF\xC3", 3); // imul eax, ebx
            engine.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x2));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0x80000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1040, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x00000002, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1043, "ArchX64: failed to disassembly and/or execute IMUL");
            
            code = string("\x48\x0f\xaf\xc3", 4); // imul rax, rbx
            engine.mem->write_buffer(0x2040, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x2040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x200000000)); // 0x200000000 * -2 
            engine.cpu.ctx().set(X64::RBX, exprcst(64, -0x2));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x2040, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == -0x400000000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            
            
            /* Three-operands */
            code = string("\x6B\xC3\x07", 3); // imul eax, ebx, 7
            engine.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaaaa12345678));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0x00100000));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1050, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x00700000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x00100000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1053, "ArchX64: failed to disassembly and/or execute IMUL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x12345678));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0xffffffff));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1050, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xfffffff9, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0xffffffff, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1053, "ArchX64: failed to disassembly and/or execute IMUL");
            
            code = string("\x69\xC3\x00\x00\x00\x10", 6); // imul eax, ebx, 0x10000000
            engine.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 6);
            engine.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaaaa12345678));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 17));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1060, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10000000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 17, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1066, "ArchX64: failed to disassembly and/or execute IMUL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123412345678));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, -1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1060, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf0000000, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == -1, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1066, "ArchX64: failed to disassembly and/or execute IMUL");
            
            code = string("\x48\x6b\xc3\x03", 4); // imul rax, rbx, 3
            engine.mem->write_buffer(0x2060, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x2060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaaaa12345678));
            engine.cpu.ctx().set(X64::RBX, exprcst(64, 0x33000000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x2060, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x99000000003, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x33000000001, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute IMUL");
            
            return nb;
        }
        
        unsigned int disass_inc(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            code = string("\xff\xc0", 2); // inc eax
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000022));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x23)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xaa00ffffff01));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0xffffff02)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute INC");
            
            code = string("\x48\xff\xc0", 3); // inc rax
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x123400000022));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == exprcst(64, 0x123400000023)->as_uint(),
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute INC");

            return nb;
        }
        
        unsigned int disass_ja(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x77\x10", 2); // ja 0x12
            engine.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.mem->write_buffer(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,0));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1012, "ArchX64: failed to disassembly and/or execute JA");
            
            /* Not taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,1));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1002, "ArchX64: failed to disassembly and/or execute JA");
            
            /* Not taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,0));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1002, "ArchX64: failed to disassembly and/or execute JA");
            
            /* Not taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,1));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x1002, "ArchX64: failed to disassembly and/or execute JA");


            code = string("\x0f\x87\x50\x34\x12\x00", 6 ); // ja 0x123456
            engine.mem->write_buffer(0x2000, (uint8_t*)code.c_str(), 6);
            engine.mem->write_buffer(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.mem->write_buffer(0x2006, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,0));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x2000, 1);
            nb += _assert( engine.cpu.ctx().get(X64::RIP).as_uint() == 0x125456, "ArchX64: failed to disassembly and/or execute JA");
            
            /* Not taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,1));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0));
            engine.run_from(0x2000, 1);
            nb += _assert( engine.cpu.ctx().get(X64::RIP).as_uint() == 0x2006, "ArchX64: failed to disassembly and/or execute JA");
            
            /* Not taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,0));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x2000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x2006, "ArchX64: failed to disassembly and/or execute JA");
            
            /* Not taken */
            engine.cpu.ctx().set(X64::ZF, exprcst(8,1));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x2000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x2006, "ArchX64: failed to disassembly and/or execute JA");
            
            return nb;
        }


        unsigned int disass_punpcklwd(MaatEngine& engine)
        {
            unsigned int nb = 0;
            string code;

            code = string("\x66\x0F\x61\xC1", 4); // punpcklwd xmm0, xmm1
            engine.mem->write_buffer(0x1020, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::ZMM0, exprcst(512, "1234deadbeef12121212"));
            engine.cpu.ctx().set(X64::ZMM1, exprcst(512, "123412345678cafebabe"));
            engine.run_from(0x1020, 1);
            nb += _assert_bignum_eq( engine.cpu.ctx().get(X64::ZMM0), "0x1234dead5678beefcafe1212babe1212", "ArchX64: failed to disassembly and/or execute PUNPCKLWD");   
            nb += _assert_bignum_eq( engine.cpu.ctx().get(X64::ZMM1), "0x123412345678cafebabe", "ArchX64: failed to disassembly and/or execute PUNPCKLWD");

            code = string("\x66\x0F\x61\x00", 4); // punpcklwd xmm0, [rax]
            engine.mem->write_buffer(0x1030, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::ZMM0, exprcst(512, "1234deadbeef12121212"));
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1900));
            engine.mem->write(0x1900, 0xab001200ffffffff, 8);
            engine.mem->write(0x1908, 0xffffffffffffffff, 8);
            engine.run_from(0x1030, 1);
            nb += _assert_bignum_eq( engine.cpu.ctx().get(X64::ZMM0), "0xab00dead1200beefffff1212ffff1212", "ArchX64: failed to disassembly and/or execute PUNPCKLWD");

            code = string("\x0F\x61\xC1", 3); // punpcklwd mm0, mm1
            engine.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::MM0, exprcst(64, 0xdeadbeef12121212));
            engine.cpu.ctx().set(X64::MM1, exprcst(64, 0x12345678cafebabe));
            engine.run_from(0x1040, 1);
            nb += _assert( engine.cpu.ctx().get(X64::MM0).as_uint() == 0xcafe1212babe1212, "ArchX64: failed to disassembly and/or execute PUNPCKLWD");
            
            code = string("\x0F\x61\x00", 3); // punpcklwd mm0, [rax]
            engine.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::MM0, exprcst(64, 0xdeadbeef12121212));
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1900));
            engine.mem->write(0x1900, 0xab001200abababab, 8);
            engine.run_from(0x1050, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::MM0).as_uint() == 0xabab1212abab1212, "ArchX64: failed to disassembly and/or execute PUNPCKLWD");

            return nb;
        }

        unsigned int disass_push(MaatEngine& engine)
        {
            unsigned int nb = 0;
            string code;

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xffffffff12345678));
            engine.cpu.ctx().set(X64::RSP, exprcst(64, 0x1808));
            code = string("\x50", 1); // push rax
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 1);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSP).as_uint() == 0x1800,
                            "ArchX64: failed to disassembly and/or execute PUSH");
            nb += _assert(  engine.mem->read(0x1800, 8).as_uint() == 0xffffffff12345678,
                            "ArchX64: failed to disassembly and/or execute PUSH");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x123400001900));
            engine.cpu.ctx().set(X64::RSP, exprcst(64, 0x123400001808));
            code = string("\x66\xFF\x30", 3); // push word ptr [rax]
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.mem->write(0x123400001900, exprcst(16, 0xdead));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSP).as_uint() == 0x123400001806,
                            "ArchX64: failed to disassembly and/or execute PUSH");
            nb += _assert(  engine.mem->read(0x123400001806, 2).as_uint() == 0xdead,
                            "ArchX64: failed to disassembly and/or execute PUSH");

            return nb;
        }

        unsigned int disass_pushfq(MaatEngine& sym){
            unsigned int nb = 0;
            string code("\x9C", 1); // pushfd
            sym.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.cpu.ctx().set(X64::RFLAGS, 13);
            sym.cpu.ctx().set(X64::RSP, 0x1908);

            sym.run_from(0x1000, 1);
            nb += _assert(
                sym.cpu.ctx().get(X64::RSP).as_uint() == 0x1900,
                "ArchX64: failed to disassembly and/or execute PUSHFQ"
            );
            nb += _assert(
                sym.mem->read(0x1900, 8).as_uint() == sym.cpu.ctx().get(X64::RFLAGS).as_uint(),
                "ArchX64: failed to disassembly and/or execute PUSHFQ"
            );

            return nb;
        }
        
        unsigned int disass_pxor(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x0F\xEF\xC1", 3); // pxor mm0, mm1
            engine.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::MM0, exprcst(64, 0xffff0000));
            engine.cpu.ctx().set(X64::MM1, exprcst(64, 0xffff0000ffff0000));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::MM0).as_uint() == 0xffff000000000000, "ArchX64: failed to disassembly and/or execute PXOR");   
            
            code = string("\x0F\xEF\x00", 3); // pxor mm0, [rax]
            engine.mem->write_buffer(0x1010, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.cpu.ctx().set(X64::MM0, exprcst(64, 1));
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1900));
            engine.mem->write(0x1900, 0xdeadbeef12340000, 8);
            engine.run_from(0x1010, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::MM0).as_uint() == 0xdeadbeef12340001, "ArchX64: failed to disassembly and/or execute PXOR");

            return nb;
        }
        
        unsigned int disass_rcl(MaatEngine& engine)
        {
            unsigned int nb = 0;
            string code;

            code = string("\x66\xC1\xD0\x07", 4); // rcl ax, 7
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1234000010201));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x12340000100c0, "ArchX64: failed to disassembly and/or execute RCL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10010));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10800, "ArchX64: failed to disassembly and/or execute RCL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCL");

            code = string("\xD1\x10", 2); // rcl dword ptr [rax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x22222222));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x44444445, "ArchX64: failed to disassembly and/or execute RCL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x80000000));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCL");

            // On 64 bits
            code = string("\x48\xd3\xd0", 3); // rcl rax, cl
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x3f));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xc000000000000000, "ArchX64: failed to disassembly and/or execute RCL");
            // Sleigh error on 64 bits in ia.sinc, they have a typo (zero missing in final 0x1000000000.....) nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x4000000000000001));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert( engine.cpu.ctx().get(X64::RAX).as_uint() == 0x8000000000000003, "ArchX64: failed to disassembly and/or execute RCL");
            // Sleigh bug  nb += _assert( engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x12345678deadbeef));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x0));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x12345678deadbeef, "ArchX64: failed to disassembly and/or execute RCL");
            // Sleigh bug  nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCL");

            return nb;
        }

        unsigned int disass_rcr(MaatEngine& engine)
        {
            unsigned int nb = 0;
            string code;

            code = string("\x66\xc1\xd8\x07", 4); // rcr ax, 7
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x11200));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10224, "ArchX64: failed to disassembly and/or execute RCR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCR");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x11240));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10024, "ArchX64: failed to disassembly and/or execute RCR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCR");
            
            code = string("\xD1\x18", 2); // rcr dword ptr [eax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);   
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x22222222));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x91111111, "ArchX64: failed to disassembly and/or execute RCR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x10000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x08000000, "ArchX64: failed to disassembly and/or execute RCR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCR");

            // On 64 bits
            code = string("\x48\xd3\xd8", 3); // rcr rax, cl
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), 3);
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000000));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x3f));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x3, "ArchX64: failed to disassembly and/or execute RCR");
            // Sleigh bug, see RCL nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute RCR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000001));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x4000000000000000, "ArchX64: failed to disassembly and/or execute RCR");
            // Sleigh bug nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf2345678deadbeef));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x0));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf2345678deadbeef, "ArchX64: failed to disassembly and/or execute RCR");
            // Sleigh bug  nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute RCR");

            return nb;
        }

        unsigned int disass_ret(MaatEngine& engine)
        {
            unsigned int nb = 0;
            string code;

            code = string("\xC3", 1); // ret
            engine.cpu.ctx().set(X64::RSP, exprcst(64, 0x123400001800));
            engine.mem->write_buffer(0x123400001160, (uint8_t*)code.c_str(), 1);
            engine.mem->write_buffer(0x123400001700, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.mem->write(0x123400001800, exprcst(64, 0x123400001700));

            engine.run_from(0x123400001160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSP).as_uint() == 0x123400001808,
                            "ArchX64: failed to disassembly and/or execute RET");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x123400001700,
                            "ArchX64: failed to disassembly and/or execute RET");

            code = string("\xc2\x30\x00", 3); // ret 0x30
            engine.cpu.ctx().set(X64::RSP, exprcst(64, 0x123400001800));
            engine.mem->write_buffer(0x123400001170, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x123400001700, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            engine.mem->write(0x123400001800, exprcst(64, 0x123400001700));

            engine.run_from(0x123400001170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RSP).as_uint() == 0x123400001838,
                            "ArchX64: failed to disassembly and/or execute RET");
            nb += _assert(  engine.cpu.ctx().get(X64::RIP).as_uint() == 0x123400001700,
                            "ArchX64: failed to disassembly and/or execute RET");

            return nb;
        }
        
        unsigned int disass_rol(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xC1\xC0\x07", 4); // rol ax, 7
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10201));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10081, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10010));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10800, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");
            
            code = string("\xD1\x00", 2); // rol dword ptr [eax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x22222222));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x44444444, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x80000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 3, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROL");

            code = string("\xd3\xc0", 2); // rol eax, cl
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x123400001111));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x123400000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x2222, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");
            
            // On 64 bits
            code = string("\x48\xd3\xc0", 3); // rol rax, cl
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000000));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x3f));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x4000000000000000, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000001));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x3, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf2345678deadbeef));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x0));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf2345678deadbeef, "ArchX64: failed to disassembly and/or execute ROL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROL");

            return nb;
        }
        
        unsigned int disass_ror(MaatEngine& engine){
            unsigned int nb = 0;
            string code;

            code = string("\x66\xC1\xC8\x07", 4); // ror ax, 7
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10201));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10204, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10018));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x13000, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");
            
            code = string("\xD1\x08", 2); // ror dword ptr [eax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);   

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x22222222));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x11111111, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x80000000));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x40000000, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROR");

            code = string("\xd3\xc8", 2); // ror eax, cl
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x123400001111));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x123400000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x80000888, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROR");
            
            // On 64 bits
            code = string("\x48\xd3\xc8", 3); // ror rax, cl
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000000));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x3f));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x1, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000001));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xc000000000000000, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute ROR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf2345678deadbeef));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x0));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf2345678deadbeef, "ArchX64: failed to disassembly and/or execute ROR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute ROR");

            return nb;
        }
        
        unsigned int disass_rorx(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            

            

            // On 32 bits
            code = string("\xC4\xE3\x7B\xF0\x18\x01", 6); // rorx ebx, dword ptr [rax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2); 

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(32, 0x22222222));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x11111111, "ArchX64: failed to disassembly and/or execute RORX");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(32, 0x80000000));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x40000000, "ArchX64: failed to disassembly and/or execute RORX");

            // On 64 bits
            code = string("\xC4\xE3\xFB\xF0\xD8\x3F", 6); // rorx rbx, rax, 0x3f
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2); 

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000000));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x1, "ArchX64: failed to disassembly and/or execute RORX");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x8000000000000001));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0x3, "ArchX64: failed to disassembly and/or execute RORX");

            code = string("\xC4\xE3\xFB\xF0\xD8\x00", 6); // rorx rbx, rax, 0x0
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2); 
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf2345678deadbeef));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RBX).as_uint() == 0xf2345678deadbeef, "ArchX64: failed to disassembly and/or execute RORX");

            return nb;
        }
        
        unsigned int disass_sal(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            code = string("\x66\xc1\xe0\x04", 4); // sal ax, 4
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10201));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x12010, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x11010));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10100, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");
            
            code = string("\xd1\x20", 2); // sal dword ptr [rax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x22222222));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x44444444, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x80000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 2, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");
            
            code = string("\xc1\xe0\x0c", 3); // sal eax, 12
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1234dead00000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x1000, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");
            
            // On 64 bits
            code = string("\x48\xd3\xe0", 3); // sal rax, cl
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf000000000000000));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x2));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xc000000000000000, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xc000000000000001));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x8000000000000002, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf2345678deadbeef));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x0));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 0));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf2345678deadbeef, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAL");
            
            return nb;
        }
        
        unsigned int disass_sar(MaatEngine& engine){
            unsigned int nb = 0;
            string code;
            
            code = string("\x66\xc1\xf8\x04", 4); // sar ax, 4
            engine.mem->write_buffer(0x1160, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x10201));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10020, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1f008));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.run_from(0x1160, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x1ff00, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAR");
            
            code = string("\xd1\x38", 2); // sar dword ptr [rax], 1
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x22222222));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0x11111111, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0x1700));
            engine.mem->write(0x1700, exprcst(64, 0x80000001));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.mem->read(0x1700, 4).as_uint() == 0xc0000000, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");

            // On 64 bits
            code = string("\x48\xd3\xf8", 3); // sar rax, cl
            engine.mem->write_buffer(0x1180, (uint8_t*)code.c_str(), code.size());
            engine.mem->write_buffer(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf000000000000000));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x2));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xfc00000000000000, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xc000000000000001));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x1));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xe000000000000000, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");

            engine.cpu.ctx().set(X64::RAX, exprcst(64, 0xf2345678deadbeef));
            engine.cpu.ctx().set(X64::RCX, exprcst(64, 0x0));
            engine.cpu.ctx().set(X64::CF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::OF, exprcst(8, 1));
            engine.run_from(0x1180, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf2345678deadbeef, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0, "ArchX64: failed to disassembly and/or execute SAR");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 1, "ArchX64: failed to disassembly and/or execute SAR");
            
            return nb;
        }
        
        unsigned int disass_sbb(MaatEngine& engine){
            unsigned int nb = 0;
            string code; 
            
            /* sbb reg, imm */
            code = string("\x1c\x0e", 2); // sbb al(ff), e
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xff));
            engine.cpu.ctx().set(X64::CF, exprcst(8,0x1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xf0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::AF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
                            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x10ff));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x10f0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::AF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
                            
            code = string("\x1c\x80", 2); // sbb al(0x80), 0x80
            engine.mem->write_buffer(0x1190, (uint8_t*)code.c_str(), 2);
            engine.mem->write_buffer(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x80));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x1190, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0xff,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            
            
            code = string("\x66\x1D\xFE\x00", 4); // sbb ax, fe
            engine.mem->write_buffer(0x1000, (uint8_t*)code.c_str(), 4);
            engine.mem->write_buffer(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1ffff));
            engine.cpu.ctx().set(X64::CF, exprcst(8,1));
            engine.run_from(0x1000, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RAX).as_uint() == 0x1ff00,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SBB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SBB");

            return nb;
        }
        
        unsigned int disass_scasb(MaatEngine& engine){
        
            unsigned int nb = 0;
            string code;
            code = string("\xae", 1); // scasb
            engine.mem->write_buffer(0x1170, (uint8_t*)code.c_str(), 1);
            engine.mem->write_buffer(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            engine.mem->write(0x1500, exprcst(8, 0xf));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 1));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0xff));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == 0x14ff,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            
            engine.mem->write(0x1500, exprcst(8, 0xff));
            engine.cpu.ctx().set(X64::DF, exprcst(8, 0));
            engine.cpu.ctx().set(X64::RAX, exprcst(64,0x1));
            engine.cpu.ctx().set(X64::RDI, exprcst(64,0x1500));
            engine.run_from(0x1170, 1);
            
            nb += _assert(  engine.cpu.ctx().get(X64::RDI).as_uint() == 0x1501,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::ZF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::CF).as_uint() == 1,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::PF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::OF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");
            nb += _assert(  engine.cpu.ctx().get(X64::SF).as_uint() == 0,
                            "ArchX64: failed to disassembly and/or execute SCASB");

            return nb;
        }


        unsigned int disass_xchg(MaatEngine& sym)
        {
            unsigned int nb = 0;
            string code;

            // xchg al,bl
            code = string("\x86\xd8",2);
            sym.cpu.ctx().set(X64::RAX, exprcst(64, 0x23));
            sym.cpu.ctx().set(X64::RBX, exprcst(64, 0x1));
            sym.mem->write_buffer(0x1040, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1040, 1);
            nb += _assert(  sym.cpu.ctx().get(X64::RAX).as_uint() ==  0x1, "ArchX64: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X64::RBX).as_uint() ==  0x23, "ArchX64: failed to disassembly and/or execute XCHG");

            // xchg bx, ax
            code = string("\x66\x93",2);
            sym.cpu.ctx().set(X64::RAX, exprcst(64, 0xaa23));
            sym.cpu.ctx().set(X64::RBX, exprcst(64, 0xbb01));
            sym.mem->write_buffer(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write_buffer(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1050, 1);
            nb += _assert(  sym.cpu.ctx().get(X64::RAX).as_uint() ==  0xbb01, "ArchX64: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X64::RBX).as_uint() ==  0xaa23, "ArchX64: failed to disassembly and/or execute XCHG"); 

            // xchg r8w, bx
            code = string("\x66\x41\x87\xD8",4);
            sym.cpu.ctx().set(X64::RBX, exprcst(64, 0xaa23));
            sym.cpu.ctx().set(X64::R8, exprcst(64, 0xbb01));
            sym.mem->write_buffer(0x1070, (uint8_t*)code.c_str(), 4);
            sym.mem->write_buffer(0x1070+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1070, 1);
            nb += _assert(  sym.cpu.ctx().get(X64::RBX).as_uint() ==  0xbb01, "ArchX64: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X64::R8).as_uint() ==  0xaa23, "ArchX64: failed to disassembly and/or execute XCHG"); 

            // xchg r8w, ax
            code = string("\x66\x41\x90",3);
            sym.cpu.ctx().set(X64::RAX, exprcst(64, 0xaa23));
            sym.cpu.ctx().set(X64::R8, exprcst(64, 0xbb01));
            sym.mem->write_buffer(0x1060, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.run_from(0x1060, 1);
            nb += _assert(  sym.cpu.ctx().get(X64::RAX).as_uint() ==  0xbb01, "ArchX64: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X64::R8).as_uint() ==  0xaa23, "ArchX64: failed to disassembly and/or execute XCHG"); 

            // xchg DWORD PTR [ecx], ecx 
            code = string("\x67\x87\x09", 3);
            sym.mem->write_buffer(0x1100, (uint8_t*)code.c_str(), 3);
            sym.mem->write_buffer(0x1100+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x12345678));
            sym.cpu.ctx().set(X64::RCX, exprcst(64, 0x1700));
            sym.run_from(0x1100, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4).as_uint() ==  0x1700, "ArchX86: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.cpu.ctx().get(X64::RCX).as_uint() ==  0x12345678, "ArchX86: failed to disassembly and/or execute XCHG"); 

            /*
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
            */
            return nb;
        }
    }
}

using namespace test::archX64; 
// All unit tests 
void test_archX64(){
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";
    
    // Start testing
    std::cout << bold << "[" << green << "+" 
         << def << bold << "]" << def << std::left << std::setw(34)
         << " Testing arch X64 support... " << std::flush;

    MaatEngine engine(Arch::Type::X64);
    engine.mem->map(0x0, 0x11000);
    engine.mem->map(0x110000, 0x130000);
    engine.mem->map(0x123400000000, 0x123400003000);

    total += reg_translation();
    /* 
    total += disass_adc(engine);
    total += disass_adcx(engine);
    total += disass_add(engine);
    total += disass_and(engine);
    total += disass_andn(engine);
    total += disass_blsi(engine);
    */
    total += disass_blsmsk(engine);
    total += disass_blsr(engine);
    total += disass_bsf(engine);
    total += disass_bsr(engine);
    total += disass_bswap(engine);
    total += disass_bt(engine);
    /*
    total += disass_btc(engine);
    total += disass_btr(engine);
    total += disass_bts(engine);
    total += disass_bzhi(engine);
    total += disass_call(engine);
    total += disass_cbw(engine);
    total += disass_cdq(engine);
    total += disass_cdqe(engine);
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
    */
    total += disass_cmp(engine);
    total += disass_cmpsb(engine);
    total += disass_cmpsd(engine);
    total += disass_cmpsq(engine);
    total += disass_cmpsw(engine);
    total += disass_cmpxchg(engine);
    total += disass_cqo(engine);
    total += disass_cwd(engine);
    total += disass_cwde(engine);
    total += disass_dec(engine);
    total += disass_div(engine);
    total += disass_idiv(engine);
    total += disass_imul(engine);
    total += disass_inc(engine);
    total += disass_ja(engine);
    /*
    total += disass_jae(engine);
    total += disass_jb(engine);
    total += disass_jbe(engine);
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
    total += disass_jrcxz(engine);
    total += disass_js(engine);
    total += disass_lahf(engine);
    total += disass_lea(engine);
    total += disass_leave(engine);
    total += disass_lodsb(engine);
    total += disass_lodsd(engine);
    total += disass_lodsq(engine);
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
    total += disass_movsq(engine);
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
    total += disass_pextrb(engine);
    total += disass_pminub(engine);
    total += disass_pmovmskb(engine);
    total += disass_pop(engine);
    total += disass_por(engine);
    total += disass_pshufd(engine);
    total += disass_pslld(engine);
    total += disass_pslldq(engine);
    total += disass_psllq(engine);
    total += disass_psubb(engine);
    total += disass_punpckhdq(engine);
    total += disass_punpckhqdq(engine);
    total += disass_punpcklbw(engine);
    total += disass_punpckldq(engine);
    total += disass_punpcklqdq(engine);
    */
    total += disass_punpcklwd(engine);
    total += disass_push(engine);
    total += disass_pushfq(engine);
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
    /*
    total += disass_scasd(engine);
    total += disass_scasq(engine);
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
    total += disass_stosq(engine);
    total += disass_stosw(engine);
    total += disass_sub(engine);
    total += disass_test(engine);
    total += disass_ucomisd(engine);
    total += disass_vmovd(engine);
    total += disass_vmovdqu(engine);
    total += disass_vpaddd(engine);
    total += disass_vpand(engine);
    total += disass_vpmulld(engine);
    total += disass_vpsubb(engine);
    total += disass_xadd(engine);
    */
    total += disass_xchg(engine);
    /*
    total += disass_xor(engine);
    total += disass_xorpd(engine); */
    
    /* Prefixes */
    // total += disass_rep(engine);

    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}
