#include "ir.hpp"
#include "exception.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

using std::cout;
using std::endl; 
using std::string;

namespace test
{
    namespace test_ir
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

        /* TODO, add this text when implementing IR Context
        unsigned int ir_context()
        {
            VarContext varctx = VarContext(0);
            IRContext ctx = IRContext(4, &varctx);
            Expr    e1 = exprcst(32, 56),
                    e2 = exprvar(64, "var1"),
                    e3 = exprvar(16, "var2");
            unsigned int nb = 0;
            ctx.set(0, e1);
            ctx.set(1, e1);
            ctx.set(2, e2);
            ctx.set(3, e3);
            nb += _assert(ctx.get(0)->eq(e1), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(1)->eq(e1), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(2)->eq(e2), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(3)->eq(e3), "IRContext failed to update then get variable");
            return nb; 
        } */

        // unsigned int block_map(){
        //     unsigned int nb = 0;
        //     ir::BlockMap blocks;
        //     auto    b1 = std::make_shared<ir::Block>("test", 0, 0x20),
        //             b2 = std::make_shared<ir::Block>("test", 0x30, 0x3f),
        //             b3 = std::make_shared<ir::Block>("test", 0x40, 0x6789);

        //     blocks.add(b1);
        //     blocks.add(b2);
        //     blocks.add(b3);

        //     std::string error_msg("BlockMap::get() didn't return the right Block ");

        //     nb += _assert(!blocks.get_blocks_containing(0x0).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x0)[0] == b1, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x1).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x1)[0] == b1, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x18).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x18)[0] == b1, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x19).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x19)[0] == b1, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x30).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x30)[0] == b2, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x3e).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x3e)[0] == b2, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x40).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x40)[0] == b3, error_msg);
        //     nb += _assert(!blocks.get_blocks_containing(0x6788).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x6788)[0] == b3, error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x6799).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x21).empty(), error_msg);
        //     nb += _assert(blocks.get_blocks_containing(0x29).empty(), error_msg);

        //     return nb;
        // }

    }
    
    
}

using namespace test::test_ir; 
// All unit tests 
void test_ir(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing ir module... " << std::flush;  
    // TODO: total += ir_context();
    // total += block_map();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
