#include "maat/engine.hpp"
#include "maat/varcontext.hpp"
#include "maat/exception.hpp"
#include "maat/solver.hpp"
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

namespace test{
namespace solve_hash{

    using namespace maat;
    using namespace maat::event;

#ifdef HAS_SOLVER_BACKEND
    unsigned int _assert(bool val, const string& msg){
        if( !val){
            cout << "\nFail: " << msg << endl << std::flush; 
            throw test_exception();
        }
        return 1; 
    }

    unsigned int _x86_assert_algo_2(MaatEngine& engine, uint32_t in, uint32_t out)
    {
        // Init stack
        engine.cpu.ctx().set(X86::ESP, 0x9000);
        engine.cpu.ctx().set(X86::EBP, 0x9000);
        // Set input at esp + 0x4
        engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint()+4, exprcst(32, in));

        engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x597));
        // Execute
        engine.run_from(0x56d);
        engine.hooks.disable_all();

        // Check res in eax
        return _assert((uint32_t)engine.cpu.ctx().get(X86::EAX).as_uint() == out, "Hash solving: simple_algo_2: failed");
    }

    uint32_t _x86_revert_hash_algo_2(MaatEngine& engine, uint32_t out)
    {    
        // Init stack
        engine.cpu.ctx().set(X86::ESP, 0x9000);
        engine.cpu.ctx().set(X86::EBP, 0x9000);
        // Set input at esp + 0x4
        engine.mem->write(0x9004, exprvar(32, "input"));
        engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x597));

        // Execute
        engine.run_from(0x56d);
        engine.hooks.disable_all();

        // Check res in eax
        std::unique_ptr<solver::Solver> sol = solver::new_solver();
        sol->add(engine.cpu.ctx().get(X86::EAX).as_expr() == exprcst(32, out)  &&
                exprvar(32, "input") > exprcst(32, 0));
        _assert(sol->check(), "x86_revert_hash: didn't find model for computed hash");
        auto model = sol->get_model();
        uint32_t res = model->get("input");
        return res;
    }
    
    unsigned int x86_simple_algo_2()
    {
        unsigned int nb = 0;
        MaatEngine engine(Arch::Type::X86);
        engine.log.set_level(Log::ERROR);
        // hash function: 
        uint8_t code[] = {0x55,0x89,0xe5,0x81,0x75,0x8,0x1,0x1,0x1,0x11,0x8b,0x45,0x8,0x8d,0x14,0xc5,0x0,0x0,0x0,0x0,0x8b,0x45,0x8,0xc1,0xe8,0x2,0x31,0xd0,0x89,0x45,0x8,0x81,0x75,0x8,0x1,0x0,0x11,0x10,0x8b,0x45,0x8,0x5d,0xc3};
        /* Argument is a uint32_t in [esp + 4]
         * Res in eax 
         *             0x0000056d <+0>:	    push   %ebp
                       0x0000056e <+1>:	    mov    %esp,%ebp
                       0x00000570 <+3>:	    xorl   $0x11010101,0x8(%ebp)
                       0x00000577 <+10>:	mov    0x8(%ebp),%eax
                       0x0000057a <+13>:	lea    0x0(,%eax,8),%edx
                       0x00000581 <+20>:	mov    0x8(%ebp),%eax
                       0x00000584 <+23>:	shr    $0x2,%eax
                       0x00000587 <+26>:	xor    %edx,%eax
                       0x00000589 <+28>:	mov    %eax,0x8(%ebp)
                       0x0000058c <+31>:	xorl   $0x10110001,0x8(%ebp)
                       0x00000593 <+38>:	mov    0x8(%ebp),%eax
                       0x00000596 <+41>:	pop    %ebp
                       0x00000597 <+42>:	ret
        */
        
        // code
        engine.mem->new_segment(0x0, 0x1000);
        engine.mem->write_buffer(0x56d, code, 43);
        // stack
        engine.mem->new_segment(0x3000, 0x10000);
        
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9c594849), 0x9c594849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9cdd4849), 0x9cdd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9d514849), 0x9d514849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9dd54849), 0x9dd54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9e494849), 0x9e494849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9ecd4849), 0x9ecd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9f414849), 0x9f414849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9fc54849), 0x9fc54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x98794849), 0x98794849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x98fd4849), 0x98fd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x99714849), 0x99714849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x99f54849), 0x99f54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9a694849), 0x9a694849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9aed4849), 0x9aed4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9b614849), 0x9b614849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x9be54849), 0x9be54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x94194849), 0x94194849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x949d4849), 0x949d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x95114849), 0x95114849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x95954849), 0x95954849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x96094849), 0x96094849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x968d4849), 0x968d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x97014849), 0x97014849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x97854849), 0x97854849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x90394849), 0x90394849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x90bd4849), 0x90bd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x91314849), 0x91314849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x91b54849), 0x91b54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x92294849), 0x92294849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x92ad4849), 0x92ad4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x93214849), 0x93214849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x93a54849), 0x93a54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8cd94849), 0x8cd94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8c5d4849), 0x8c5d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8dd14849), 0x8dd14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8d554849), 0x8d554849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8ec94849), 0x8ec94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8e4d4849), 0x8e4d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8fc14849), 0x8fc14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8f454849), 0x8f454849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x88f94849), 0x88f94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x887d4849), 0x887d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x89f14849), 0x89f14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x89754849), 0x89754849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8ae94849), 0x8ae94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8a6d4849), 0x8a6d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8be14849), 0x8be14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x8b654849), 0x8b654849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x84994849), 0x84994849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x841d4849), 0x841d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x85914849), 0x85914849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x85154849), 0x85154849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x86894849), 0x86894849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x860d4849), 0x860d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x87814849), 0x87814849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x87054849), 0x87054849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x80b94849), 0x80b94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x803d4849), 0x803d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x81b14849), 0x81b14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x81354849), 0x81354849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x82a94849), 0x82a94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x822d4849), 0x822d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x83a14849), 0x83a14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0x83254849), 0x83254849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbd594849), 0xbd594849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbddd4849), 0xbddd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbc514849), 0xbc514849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbcd54849), 0xbcd54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbf494849), 0xbf494849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbfcd4849), 0xbfcd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbe414849), 0xbe414849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbec54849), 0xbec54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb9794849), 0xb9794849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb9fd4849), 0xb9fd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb8714849), 0xb8714849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb8f54849), 0xb8f54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbb694849), 0xbb694849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbbed4849), 0xbbed4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xba614849), 0xba614849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xbae54849), 0xbae54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb5194849), 0xb5194849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb59d4849), 0xb59d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb4114849), 0xb4114849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb4954849), 0xb4954849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb7094849), 0xb7094849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb78d4849), 0xb78d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb6014849), 0xb6014849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb6854849), 0xb6854849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb1394849), 0xb1394849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb1bd4849), 0xb1bd4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb0314849), 0xb0314849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb0b54849), 0xb0b54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb3294849), 0xb3294849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb3ad4849), 0xb3ad4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb2214849), 0xb2214849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xb2a54849), 0xb2a54849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xadd94849), 0xadd94849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xad5d4849), 0xad5d4849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xacd14849), 0xacd14849);
        nb += _x86_assert_algo_2(engine, _x86_revert_hash_algo_2(engine, 0xac554849), 0xac554849);

        return nb;
        
    }
#endif
}
}

using namespace test::solve_hash; 
// All unit tests 
void test_solve_hash()
{
#ifdef HAS_SOLVER_BACKEND    
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing symbolic hash solving... " << std::flush;
    total += x86_simple_algo_2();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}
