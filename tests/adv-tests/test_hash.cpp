#include "engine.hpp"
#include "memory.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>

using std::cout;
using std::endl; 
using std::string;
using std::strlen;

namespace test
{
namespace hash
{
        
    using namespace maat;
    
    unsigned int _assert(bool val, const string& msg)
    {
        if( !val){
            cout << "\nFail: " << msg << endl << std::flush; 
            throw test_exception();
        }
        return 1; 
    }

    unsigned int _x86_assert_algo_1(MaatEngine& engine, uint32_t in, uint32_t out)
    {
        /* Init stack */
        engine.cpu.ctx().set(X86::ESP, 0x9000);
        engine.cpu.ctx().set(X86::EBP, 0x9000);
        /* Set input at esp + 0x4 */
        engine.mem->write(engine.cpu.ctx().get(X86::ESP)->as_uint()+4, exprcst(32, in));

        engine.bp_manager.add_addr_bp(0x5a6, "end");

        // Execute
        engine.run_from(0x56d);
        engine.bp_manager.remove_all();
        
        // Check res in eax
        return _assert(engine.cpu.ctx().get(X86::EAX)->as_uint() == out, "Hash emulation test: X86: simple_algo_1: failed");
    }
    
    
    unsigned int x86_simple_algo_1()
    {
        unsigned int nb = 0;
        MaatEngine engine = MaatEngine(Arch::Type::X86);
        // hash function: 
        uint8_t code[] = {0x55,0x89,0xe5,0x83,0xec,0x10,0xc7,0x45,0xfc,0x0,0x0,0x0,0x0,0xeb,0x20,0x81,0x75,0x8,0x1,0x1,0x1,0x11,0x8b,0x45,0x8,0x8d,0x14,0xc5,0x0,0x0,0x0,0x0,0x8b,0x45,0x8,0xc1,0xe8,0x2,0x31,0xd0,0x89,0x45,0x8,0x83,0x45,0xfc,0x1,0x83,0x7d,0xfc,0x63,0x7e,0xda,0x8b,0x45,0x8,0xc9,0xc3};
        /* Argument is a uint32_t in [esp + 4]  
         * Res in eax 
         *         0x0000056d <+0>:	    push   %ebp
                   0x0000056e <+1>:	    mov    %esp,%ebp
                   0x00000570 <+3>:	    sub    $0x10,%esp
                   0x00000573 <+6>:	    movl   $0x0,-0x4(%ebp)
                   0x0000057a <+13>:	jmp    0x59c <transform+47>
                   0x0000057c <+15>:	xorl   $0x11010101,0x8(%ebp)
                   0x00000583 <+22>:	mov    0x8(%ebp),%eax
                   0x00000586 <+25>:	lea    0x0(,%eax,8),%edx
                   0x0000058d <+32>:	mov    0x8(%ebp),%eax
                   0x00000590 <+35>:	shr    $0x2,%eax
                   0x00000593 <+38>:	xor    %edx,%eax
                   0x00000595 <+40>:	mov    %eax,0x8(%ebp)
                   0x00000598 <+43>:	addl   $0x1,-0x4(%ebp)
                   0x0000059c <+47>:	cmpl   $0x63,-0x4(%ebp)
                   0x000005a0 <+51>:	jle    0x57c <transform+15>
                   0x000005a2 <+53>:	mov    0x8(%ebp),%eax
                   0x000005a5 <+56>:	leave
                   0x000005a6 <+57>:	ret
        */
        
        // code
        engine.mem->new_segment(0x0, 0xfff);
        engine.mem->write_buffer(0x56d, code, 58);
        // stack
        engine.mem->new_segment(0x3000, 0xffff);

        nb += _x86_assert_algo_1(engine, 0, 0x219e5c12);
        nb += _x86_assert_algo_1(engine, 100, 0x6f8cdcd6);
        nb += _x86_assert_algo_1(engine, 200, 0x2d9c7d5e);
        nb += _x86_assert_algo_1(engine, 300, 0x6b8cfc96);
        nb += _x86_assert_algo_1(engine, 400, 0x08941f1e);
        nb += _x86_assert_algo_1(engine, 500, 0x46869fda);
        nb += _x86_assert_algo_1(engine, 600, 0x049e7f4a);
        nb += _x86_assert_algo_1(engine, 700, 0x428eff8a);
        nb += _x86_assert_algo_1(engine, 800, 0x63869d0a);
        nb += _x86_assert_algo_1(engine, 900, 0x21961d8a);
        nb += _x86_assert_algo_1(engine, 1000, 0x6f84bc46);
        nb += _x86_assert_algo_1(engine, 1100, 0x2d9c7dff);
        nb += _x86_assert_algo_1(engine, 1200, 0x4a849e37);
        nb += _x86_assert_algo_1(engine, 1300, 0x08941fbf);
        nb += _x86_assert_algo_1(engine, 1400, 0x4686be73);
        nb += _x86_assert_algo_1(engine, 1500, 0x04963ef3);
        nb += _x86_assert_algo_1(engine, 1600, 0x25961c63);
        nb += _x86_assert_algo_1(engine, 1700, 0x63869ca3);
        nb += _x86_assert_algo_1(engine, 1800, 0x21963c23);
        nb += _x86_assert_algo_1(engine, 1900, 0x6f84bce7);
        nb += _x86_assert_algo_1(engine, 2000, 0x0c9c5f6f);
        nb += _x86_assert_algo_1(engine, 2100, 0x4e8496d4);
        nb += _x86_assert_algo_1(engine, 2200, 0x0c94375c);
        nb += _x86_assert_algo_1(engine, 2300, 0x4286b798);
        nb += _x86_assert_algo_1(engine, 2400, 0x638ed518);
        nb += _x86_assert_algo_1(engine, 2500, 0x219e5598);
        nb += _x86_assert_algo_1(engine, 2600, 0x6786b548);
        nb += _x86_assert_algo_1(engine, 2700, 0x259635c8);
        nb += _x86_assert_algo_1(engine, 2800, 0x4a8cd604);
        nb += _x86_assert_algo_1(engine, 2900, 0x089c578c);
        nb += _x86_assert_algo_1(engine, 3000, 0x4e8cf644);
        nb += _x86_assert_algo_1(engine, 3100, 0x0c9437fd);
        nb += _x86_assert_algo_1(engine, 3200, 0x2d9c5475);
        nb += _x86_assert_algo_1(engine, 3300, 0x638ed4b1);
        nb += _x86_assert_algo_1(engine, 3400, 0x219e7431);
        nb += _x86_assert_algo_1(engine, 3500, 0x678ef4f1);
        nb += _x86_assert_algo_1(engine, 3600, 0x049e5661);
        nb += _x86_assert_algo_1(engine, 3700, 0x4a8cd6a5);
        nb += _x86_assert_algo_1(engine, 3800, 0x089c772d);
        nb += _x86_assert_algo_1(engine, 3900, 0x4e8cf6e5);
        nb += _x86_assert_algo_1(engine, 4000, 0x6f84956d);
        nb += _x86_assert_algo_1(engine, 4100, 0x21de4c16);
        nb += _x86_assert_algo_1(engine, 4200, 0x6fccedda);
        nb += _x86_assert_algo_1(engine, 4300, 0x2ddc6d5a);
        nb += _x86_assert_algo_1(engine, 4400, 0x4ac48f9a);
        nb += _x86_assert_algo_1(engine, 4500, 0x08d40f1a);
        nb += _x86_assert_algo_1(engine, 4600, 0x46c6aed6);
        nb += _x86_assert_algo_1(engine, 4700, 0x04de6f4e);
        nb += _x86_assert_algo_1(engine, 4800, 0x25d60cc6);
        nb += _x86_assert_algo_1(engine, 4900, 0x63c68d0e);
        nb += _x86_assert_algo_1(engine, 5000, 0x21d62c86);
        nb += _x86_assert_algo_1(engine, 5100, 0x6fc4ac42);
        nb += _x86_assert_algo_1(engine, 5200, 0x0cd40ef3);
        nb += _x86_assert_algo_1(engine, 5300, 0x4ac48e33);
        nb += _x86_assert_algo_1(engine, 5400, 0x08d42eb3);
        nb += _x86_assert_algo_1(engine, 5500, 0x46c6ae77);
        nb += _x86_assert_algo_1(engine, 5600, 0x67cecdff);
        nb += _x86_assert_algo_1(engine, 5700, 0x25d60c67);
        nb += _x86_assert_algo_1(engine, 5800, 0x63c6adaf);
        nb += _x86_assert_algo_1(engine, 5900, 0x21d62c27);
        nb += _x86_assert_algo_1(engine, 6000, 0x4ecccfeb);
        nb += _x86_assert_algo_1(engine, 6100, 0x0cdc4f6b);
        nb += _x86_assert_algo_1(engine, 6200, 0x4ec4a7d8);
        nb += _x86_assert_algo_1(engine, 6300, 0x0cd42758);
        nb += _x86_assert_algo_1(engine, 6400, 0x2ddc45d8);
        nb += _x86_assert_algo_1(engine, 6500, 0x63cec51c);
        nb += _x86_assert_algo_1(engine, 6600, 0x21de6494);
        nb += _x86_assert_algo_1(engine, 6700, 0x67c6a54c);
        nb += _x86_assert_algo_1(engine, 6800, 0x04de46c4);
        nb += _x86_assert_algo_1(engine, 6900, 0x4accc600);
        nb += _x86_assert_algo_1(engine, 7000, 0x08dc6680);
        nb += _x86_assert_algo_1(engine, 7100, 0x4ecce640);
        nb += _x86_assert_algo_1(engine, 7200, 0x6fccc4f1);
        nb += _x86_assert_algo_1(engine, 7300, 0x2ddc4471);
        nb += _x86_assert_algo_1(engine, 7400, 0x63cee5bd);
        nb += _x86_assert_algo_1(engine, 7500, 0x21de6435);
        nb += _x86_assert_algo_1(engine, 7600, 0x46c687fd);
        nb += _x86_assert_algo_1(engine, 7700, 0x04de4665);
        nb += _x86_assert_algo_1(engine, 7800, 0x4acce7a9);
        nb += _x86_assert_algo_1(engine, 7900, 0x08dc6729);
        nb += _x86_assert_algo_1(engine, 8000, 0x29d405a9);
        nb += _x86_assert_algo_1(engine, 8100, 0x6fc48569);
        nb += _x86_assert_algo_1(engine, 8200, 0x219e7d12);
        nb += _x86_assert_algo_1(engine, 8300, 0x6f8cfdd6);
        nb += _x86_assert_algo_1(engine, 8400, 0x0c941e5e);
        nb += _x86_assert_algo_1(engine, 8500, 0x4a849f96);
        nb += _x86_assert_algo_1(engine, 8600, 0x08943e1e);
        nb += _x86_assert_algo_1(engine, 8700, 0x4686beda);
        nb += _x86_assert_algo_1(engine, 8800, 0x67869c4a);
        nb += _x86_assert_algo_1(engine, 8900, 0x25961cca);
        nb += _x86_assert_algo_1(engine, 9000, 0x6386bc0a);
        nb += _x86_assert_algo_1(engine, 9100, 0x21963c8a);
        nb += _x86_assert_algo_1(engine, 9200, 0x4e8cdf46);
        nb += _x86_assert_algo_1(engine, 9300, 0x0c941eff);
        nb += _x86_assert_algo_1(engine, 9400, 0x4a84bf37);
        nb += _x86_assert_algo_1(engine, 9500, 0x08943ebf);
        nb += _x86_assert_algo_1(engine, 9600, 0x299c5d37);
        nb += _x86_assert_algo_1(engine, 9700, 0x678eddf3);
        nb += _x86_assert_algo_1(engine, 9800, 0x25963d63);
        nb += _x86_assert_algo_1(engine, 9900, 0x6386bda3);
        
        return nb;
    }
            
    unsigned int _x86_assert_md5(MaatEngine& engine, char*in, uint32_t out0, uint32_t out1, uint32_t out2, uint32_t out3)
    {
        // engine.settings.optimise_ir = true;

        // Init stack
        engine.cpu.ctx().set(X86::ESP, exprcst(32, 0xffffd15c));
        engine.cpu.ctx().set(X86::EBP, exprcst(32, 0xffffd15c));
        // Set input string at esp+4 and length at esp+8
        engine.mem->write_buffer(0x11000, (uint8_t*)in, strlen(in));
        engine.mem->write(engine.cpu.ctx().get(X86::ESP)->as_uint()+4, exprcst(32, 0x11000));
        engine.mem->write(engine.cpu.ctx().get(X86::ESP)->as_uint()+8, exprcst(32, strlen(in)));

        engine.bp_manager.add_addr_bp(0x8048b81, "end");

        // Execute
        engine.run_from(0x8048960);
        engine.bp_manager.remove_all();

        // Check res at 0x80dbca4
        return _assert( engine.mem->read(0x80dbcac, 4)->as_uint() == out0 &&
                        engine.mem->read(0x80dbca4, 4)->as_uint() == out1 &&
                        engine.mem->read(0x80dbca8, 4)->as_uint() == out2 &&
                        engine.mem->read(0x80dbcb0, 4)->as_uint() == out3
                        , "Hash emulation test: md5: failed");
    }

    unsigned int x86_md5()
    {
        // md5 binary compiled with:
        // gcc -m32 -fno-pie -mno-mmx -mno-sse -mno-sse2 -O2 -fno-stack-protector md5.c -o md5

        unsigned int nb = 0;
        MaatEngine engine = MaatEngine(Arch::Type::X86);

        // map md5 function at address 0x08048960
        std::ifstream file("tests/ressources/md5/md5_0x08048960_546.bin", std::ios::binary | std::ios::ate);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<char> buffer(size);
        if( ! file.read(buffer.data(), size)){
            cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
            throw test_exception();
        }
        
        engine.mem->new_segment(0x8048950, 0x8050000);
        engine.mem->write_buffer(0x8048960, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);

        // memcpy function at address 0x806ae50
        std::ifstream file2("tests/ressources/md5/memcpy_0x0806ae50_115.bin", std::ios::binary | std::ios::ate);
        size = file2.tellg();
        file2.seekg(0, std::ios::beg);
        
        buffer = std::vector<char>(size);
        if( ! file2.read(buffer.data(), size)){
            cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
            throw test_exception();
        }

        engine.mem->new_segment(0x806ae50, 0x8070000);
        engine.mem->write_buffer(0x806ae50, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);

        // many data sections
        std::ifstream file3("tests/ressources/md5/rodata_0x80ab000_0x2fff.bin", std::ios::binary | std::ios::ate);
        size = file3.tellg();
        file3.seekg(0, std::ios::beg);

        buffer = std::vector<char>(size);
        if( ! file3.read(buffer.data(), size))
        {
            cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
            throw test_exception(); 
        }
        engine.mem->new_segment(0x80a0000, 0x80df000);
        engine.mem->write_buffer(0x80ab000, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);

        // stack
        engine.mem->new_segment(0xffff0000, 0xffffe000);
        // argument to hash
        engine.mem->new_segment(0x11000, 0x12000);

        nb += _x86_assert_md5(engine, (char*)"msul", 0xec04d6b3, 0xf4d9196c, 0x9015e930, 0xbb668ece);
        nb += _x86_assert_md5(engine, (char*)"ixtykuaw", 0xfadace91, 0x86a333a8, 0xce0cc2f0, 0x97524cdc);
        nb += _x86_assert_md5(engine, (char*)"hzgvwzbumqca", 0xff70d0f1, 0x0c08605c, 0xe0b1bc1a, 0x3db4837b);
        nb += _x86_assert_md5(engine, (char*)"ulfqvcfosnzuzrhf", 0x352d0acc, 0x2b1f2cec, 0x07654b0c, 0x193e2328);
        nb += _x86_assert_md5(engine, (char*)"fieuoqwdnazaeqelxawe", 0x1848c685, 0x02fc8360, 0x31812820, 0x37721897);
        nb += _x86_assert_md5(engine, (char*)"bsezeoggylqoxdujjyktqvrb", 0x65e1e27e, 0x7844616d, 0xb70e1400, 0x9708798f);
        nb += _x86_assert_md5(engine, (char*)"dznkzisambwwhieughjmuvegbtyj", 0x81cac364, 0xd0f5575c, 0xfb9be7c0, 0x1b3b761a);
        nb += _x86_assert_md5(engine, (char*)"qcsikxrystkgqwuacwlgaqzcqqdsvqdo", 0x2375a159, 0xe4a7510d, 0x9ef8afb0, 0xf89d0483);
        nb += _x86_assert_md5(engine, (char*)"wrosmjwowzzktacowgcjunnhgvhhfqqxwnwm", 0x69e78e84, 0xbc36bf0d, 0x12643cde, 0xc4b7808e);
        nb += _x86_assert_md5(engine, (char*)"kbhczluprlqjviquiqqguoxdohyuswnnueelijoe", 0xa5197bd1, 0xda7493c5, 0xdfc4ab3f, 0xa3833f8f);
        nb += _x86_assert_md5(engine, (char*)"howutpbbdrvokubqfczqpfspgsxnynsdmgeybdwltgjd", 0x2fb4e535, 0x78bf0624, 0xbb865b55, 0x3dfbf6c7);
        nb += _x86_assert_md5(engine, (char*)"qovjjukmucykhyglreiejjlaqfcyfjufmgbwffnlqbiycguu", 0x68757050, 0xc0de7040, 0x634128a4, 0x1a1e4f72);
        nb += _x86_assert_md5(engine, (char*)"vleuoyfqkczxzcxsdnfbukqnxkbdlxdfziaaffmittomfxiahaxd", 0xdfc57543, 0xc3ef028c, 0xa5f8b207, 0x2fe0558e);
        nb += _x86_assert_md5(engine, (char*)"afuismarynwhfenbhqgvwuakhmivrtozjqhodfsjfknrslmkgappeyiz", 0xaadee9ed, 0xd6f18088, 0x4bad2e63, 0x125a8bf9);
        nb += _x86_assert_md5(engine, (char*)"lutimgtisetqpsyjuactstgtayqyldjifmoegkbobixbllspwkhuqtmmsyuh", 0xeca24a93, 0x98a52ec1, 0xcdb7843e, 0x5a0d3e7c);
        nb += _x86_assert_md5(engine, (char*)"uhwdudmkfwtpiinkysbpithjjwajdjoizgujcdibtmujvcyzumisejcrxmkzompj", 0x1808705a, 0x0f8eb710, 0xb8cfcdcc, 0xdc991b7a);
        nb += _x86_assert_md5(engine, (char*)"czhpnrgyogstuxihwxaxrfnnnhaijeamnaqsurketpzhylktnmrenbbukzswvtmakrno", 0x88942048, 0x2ac69f81, 0x6a863a05, 0xd030616d);
        nb += _x86_assert_md5(engine, (char*)"znocaqtxynsifzvujjjbabtkbbvqmfntgxtfmdzkgnghquguaqwqondhcpvkbtoxzfunmdoq", 0xa8dae03d, 0x073da867, 0x92e2279f, 0xbcfd11cc);
        nb += _x86_assert_md5(engine, (char*)"zeflsjrhdluymxroaxbnyotchfmcroaawhiraveavvsopgqnpbbjjpipuppuibmbasxyffekotez", 0x147137e7, 0x69a38149, 0x4d7c3a4f, 0xb0a0394e);
        nb += _x86_assert_md5(engine, (char*)"wuzqhuprrwdlflysnqekmlmnzecohjfrjrvvjxenmrhzsewkduzhzesahwvyckbownqzmbccykqlhktz", 0xe506a6be, 0xd10b3111, 0xb112d311, 0x177946a2);
        nb += _x86_assert_md5(engine, (char*)"ughtvwpsarhhcwshtudlofzkngrzdcnakfczkobykojbsvwqqyhmnkndqgkytcmgmbwwyatghefobkblaxti", 0x0f5881d8, 0xc7bfb729, 0x1c80eae5, 0x69685dd4);
        nb += _x86_assert_md5(engine, (char*)"lzxwrihlhxcvdowajorjthxhwprepbsqdlyzdfcwpqnuyyscpuavavczxxfpgnzkpxltnneptvrqbqwkeqfhmjxi", 0x979a7cc2, 0x7d0a94f0, 0x00cc5ccb, 0x64cb42c9);
        nb += _x86_assert_md5(engine, (char*)"anistqsfqyovheyggdlzrxssgoheqomjeukfbwdqqdrptmlaidglzvvuqowzvljwjdvfaylinwonnkbnenursnifpsfn", 0x4be34004, 0x7447c735, 0xac23e502, 0xb752723a);
        nb += _x86_assert_md5(engine, (char*)"haxhplsdizyeprwvwifzhmchgxkcgebvdptlzahorytwymnpbkpponzsnivxifntatksgmsqhthoviepqiajuqkbbqrzjqcn", 0xf0d1b693, 0x7b04af02, 0x68a8a9d3, 0x00bff087);

        return nb;

    }

    /*
    // =============================================================
    // Simple algo in X64
    
    unsigned int _x64_assert_algo_3(MaatEngine& sym, uint64_t in, uint64_t out){
        // Init stack
        sym.regs->set(X64_RSP, exprcst(64, 0xfff0000000009000));
        sym.regs->set(X64_RBP, exprcst(64, 0xfff0000000009000));
        // Set input in rdi
        sym.regs->set(X64_RDI, exprcst(64, in));

        sym.breakpoint.add(BreakpointType::ADDR, "end", 0x6d3);

        // Execute
        sym.run_from(0x68a);
        sym.breakpoint.remove_all();
        
        // Check res in rax
        return _assert(sym.regs->concretize(X64_RAX) == out, "Hash emulation test: X64: simple_algo_3: failed");
    }


    unsigned int x64_simple_algo_3(){
        unsigned int nb = 0;
        MaatEngine sym = MaatEngine(ArchType::X64);
        // hash function: 
        uint8_t code[] = {0x55,0x48,0x89,0xe5,0x48,0x89,0x7d,0xe8,0xc7,0x45,0xfc,
                          0x0,0x0,0x0,0x0,0xeb,0x2d,0x48,0xb8,0x0,0x11,0x1,0x10,0x1,
                          0x1,0x1,0x11,0x48,0x31,0x45,0xe8,0x48,0x8b,0x45,0xe8,0x48,
                          0x8d,0x14,0xc5,0x0,0x0,0x0,0x0,0x48,0x8b,0x45,0xe8,0x48,0xc1
                          ,0xe8,0x2,0x48,0x1,0xd0,0x48,0x89,0x45,0xe8,0x83,0x45,0xfc,0x1
                          ,0x83,0x7d,0xfc,0x63,0x7e,0xcd,0x48,0x8b,0x45,0xe8,0x5d, 0xc3}
;
        /* Argument is a uint64_t in rdi
         * Res in rax 
         *         0x000000000000068a <+0>:	    push   %rbp
                   0x000000000000068b <+1>:	    mov    %rsp,%rbp
                   0x000000000000068e <+4>:	    mov    %rdi,-0x18(%rbp)
                   0x0000000000000692 <+8>:	    movl   $0x0,-0x4(%rbp)
                   0x0000000000000699 <+15>:	jmp    0x6c8 <transform+62>
                   0x000000000000069b <+17>:	movabs $0x1101010110011100,%rax
                   0x00000000000006a5 <+27>:	xor    %rax,-0x18(%rbp)
                   0x00000000000006a9 <+31>:	mov    -0x18(%rbp),%rax
                   0x00000000000006ad <+35>:	lea    0x0(,%rax,8),%rdx
                   0x00000000000006b5 <+43>:	mov    -0x18(%rbp),%rax
                   0x00000000000006b9 <+47>:	shr    $0x2,%rax
                   0x00000000000006bd <+51>:	add    %rdx,%rax
                   0x00000000000006c0 <+54>:	mov    %rax,-0x18(%rbp)
                   0x00000000000006c4 <+58>:	addl   $0x1,-0x4(%rbp)
                   0x00000000000006c8 <+62>:	cmpl   $0x63,-0x4(%rbp)
                   0x00000000000006cc <+66>:	jle    0x69b <transform+17>
                   0x00000000000006ce <+68>:	mov    -0x18(%rbp),%rax
                   0x00000000000006d2 <+72>:	pop    %rbp
                   0x00000000000006d3 <+73>:	retq 
        */
        
        
        /*

        // code
        sym.mem->new_segment(0x0, 0x1000, MEM_FLAG_RWX);
        sym.mem->write_buffer(0x68a, code, 74);
        // stack
        sym.mem->new_segment(0xfff0000000003000, 0xfff0000000010000, MEM_FLAG_RW);

        // Do test
        nb += _x64_assert_algo_3(sym, 100, 0xdd2f8d0fbfacdd87);
        nb += _x64_assert_algo_3(sym, 200, 0xa506f580b10e6709);
        nb += _x64_assert_algo_3(sym, 300, 0x9722edc8699ba729);
        nb += _x64_assert_algo_3(sym, 400, 0xc3010fcbdb25007e);
        nb += _x64_assert_algo_3(sym, 10000000, 0xe33817cc83291e93);
        nb += _x64_assert_algo_3(sym, 20000000, 0xbafe98c99f3856e8);
        nb += _x64_assert_algo_3(sym, 0x1cbe9486c1, 0xdabe0951b8168955);
        nb += _x64_assert_algo_3(sym, 0x1cbe9486c1, 0xdabe0951b8168955);
        nb += _x64_assert_algo_3(sym, 0x24c00db4ae803, 0x3ffd53cdbbcea604);
        nb += _x64_assert_algo_3(sym, 0xffffffffffffffff, 0xeb3a57a134f3040d);

        return nb;
    }
    */
}
}

using namespace test::hash;
// All unit tests 
void test_hash()
{
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing hash algos emulation... " << std::flush;  
    total += x86_simple_algo_1();
    total += x86_md5();
    /*
    total += x64_simple_algo_3();
    */
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
