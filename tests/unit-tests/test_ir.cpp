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

        unsigned int block_map(){
            unsigned int nb = 0;
            ir::BlockMap blocks;
            auto    b1 = std::make_shared<ir::Block>("test", 0, 0x20),
                    b2 = std::make_shared<ir::Block>("test", 0x30, 0x3f),
                    b3 = std::make_shared<ir::Block>("test", 0x40, 0x6789);

            blocks.add(b1);
            blocks.add(b2);
            blocks.add(b3);

            std::string error_msg("BlockMap::get() didn't return the right Block ");

            nb += _assert(!blocks.get_blocks_containing(0x0).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x0)[0] == b1, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x1).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x1)[0] == b1, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x18).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x18)[0] == b1, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x19).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x19)[0] == b1, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x30).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x30)[0] == b2, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x3e).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x3e)[0] == b2, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x40).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x40)[0] == b3, error_msg);
            nb += _assert(!blocks.get_blocks_containing(0x6788).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x6788)[0] == b3, error_msg);
            nb += _assert(blocks.get_blocks_containing(0x6799).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x21).empty(), error_msg);
            nb += _assert(blocks.get_blocks_containing(0x29).empty(), error_msg);

            return nb;
        }

        unsigned int optimize_ir()
        {
            unsigned int nb = 0;

            ir::Block block;
            ir::Block empty_block;
            for (int i = 0; i < 4; i++)
                empty_block.new_tmp(); // Create temporaries

            // -------
            block = empty_block;
            block.add_inst(ir::Inst(0x0, ir::Op::INT_ADD, ir::Reg(2,1), ir::Reg(1,1), ir::Reg(0,1)));
            block.add_inst(ir::Inst(0x1, ir::Op::INT_SUB, ir::Tmp(3,1), ir::Reg(1,1), ir::Reg(0,1)));
            block.add_inst(ir::Inst(0x2, ir::Op::COPY, ir::Reg(2,1), ir::Tmp(3,1)));
            block.optimise(4);
            nb += _assert(block.instructions()[0].addr == 0x1, "Block::optimise() failed");
            nb += _assert(block.instructions()[1].addr == 0x2, "Block::optimise() failed");

            // -------
            block = empty_block;
            block.add_inst(ir::Inst(0x0, ir::Op::INT_ADD, ir::Reg(2, 0, 0), ir::Reg(1, 0, 0), ir::Reg(0, 0, 0))); 
            block.add_inst(ir::Inst(0x1, ir::Op::INT_SUB, ir::Tmp(3, 0, 0), ir::Reg(1, 0, 0), ir::Reg(2, 0, 0)));
            block.add_inst(ir::Inst(0x2, ir::Op::COPY, ir::Tmp(3, 0, 0), ir::Cst(0, 0, 0)));
            block.add_inst(ir::Inst(0x3, ir::Op::COPY, ir::Reg(2, 0, 0), ir::Cst(1, 0, 0))); 
            block.optimise(4);
            nb += _assert(block.instructions()[0].addr == 0x3, "Block::optimise() failed");
            
            // -------
            block = empty_block;
            block.add_inst(ir::Inst(0x0, ir::Op::INT_ADD, ir::Tmp(3, 0, 0), ir::Reg(1, 0, 0), ir::Reg(0, 0, 0))); 
            block.add_inst(ir::Inst(0x1, ir::Op::INT_ADD, ir::Tmp(3, 0, 0), ir::Tmp(3, 0, 0), ir::Reg(0, 0, 0)));
            block.add_inst(ir::Inst(0x2, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Tmp(3, 0, 0), ir::Reg(1, 0, 0))); 
            block.optimise(4);
            nb += _assert(block.nb_ir_inst() == 3, "Block::optimise() failed");

            // -------
            block = empty_block;
            block.add_inst(ir::Inst(0x0, ir::Op::INT_ADD, ir::Reg(2, 0, 0), ir::Reg(1, 0, 0), ir::Reg(0, 0, 0))); 
            block.add_inst(ir::Inst(0x1, ir::Op::INT_ADD, ir::Reg(2, 0, 0), ir::Reg(1, 0, 0), ir::Cst(0, 0, 0)));
            block.add_inst(ir::Inst(0x2, ir::Op::STORE, ir::Param::None(), ir::Param::None(), ir::Reg(1, 0, 0), ir::Reg(2, 0, 0)));
            block.add_inst(ir::Inst(0x3, ir::Op::INT_ADD, ir::Reg(2, 0, 0), ir::Reg(1, 0, 0), ir::Cst(1, 0, 0))); 
            block.add_inst(ir::Inst(0x4, ir::Op::INT_SUB, ir::Reg(2, 0, 0), ir::Reg(1, 0, 0), ir::Cst(0, 0, 0)));
            block.add_inst(ir::Inst(0x5, ir::Op::COPY, ir::Tmp(2, 0, 0), ir::Reg(2, 0, 0))); 
            block.optimise(4);
            nb += _assert(block.nb_ir_inst() == 3, "Block::optimise() failed");
            nb += _assert(block.instructions()[0].addr == 0x1, "Block::optimise() failed");
            nb += _assert(block.instructions()[1].addr == 0x2, "Block::optimise() failed");
            nb += _assert(block.instructions()[2].addr == 0x4, "Block::optimise() failed");

            // -------
            block = empty_block;
            block.add_inst(ir::Inst(0x0, ir::Op::INT_ADD, ir::Reg(2, 31, 0), ir::Reg(1, 31, 0), ir::Reg(0, 31, 0))); 
            block.add_inst(ir::Inst(0x1, ir::Op::INT_ADD, ir::Reg(2, 17, 2), ir::Reg(1, 16, 1), ir::Cst(0, 15, 0)));
            block.optimise(4);
            
            nb += _assert(block.instructions()[0].addr == 0x0, "Block::optimise() failed");
            nb += _assert(block.instructions()[1].addr == 0x1, "Block::optimise() failed");
            
            // -------
            block = empty_block;
            block.add_inst(ir::Inst(0x0, ir::Op::INT_ADD, ir::Reg(2, 31, 0), ir::Reg(1, 31, 0), ir::Reg(0, 31, 0))); 
            block.add_inst(ir::Inst(0x1, ir::Op::INT_ADD, ir::Reg(2, 63, 0), ir::Reg(1, 63, 0), ir::Cst(0, 63, 0)));
            block.add_inst(ir::Inst(0x2, ir::Op::STORE, ir::Reg(2, 63, 0), ir::Cst(1, 0, 0)));
            block.add_inst(ir::Inst(0x3, ir::Op::COPY, ir::Reg(2, 0, 0), ir::Cst(0, 0, 0)));

            block.optimise(4);

            nb += _assert(block.instructions()[0].addr == 0x1, "Block::optimise() failed");
            nb += _assert(block.instructions()[1].addr == 0x2, "Block::optimise() failed");
            nb += _assert(block.instructions()[2].addr == 0x3, "Block::optimise() failed");            

            return nb;
        }

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
    total += block_map();
    total += optimize_ir();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
