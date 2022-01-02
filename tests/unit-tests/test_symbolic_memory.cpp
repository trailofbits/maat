#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "memory.hpp"
#include "exception.hpp"
#include "simplification.hpp"
#include "engine.hpp"
#include "varcontext.hpp"

using std::cout;
using std::endl; 
using std::string;
using std::stringstream;
using std::list;

namespace test{
    namespace symbolic_memory{

        using namespace maat;
        
        unsigned int _assert(bool val, const string& msg)
        {
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int interval_tree()
        {
            unsigned int nb = 0;

            IntervalTree tree(0, 0x00020000);

            nb += _assert(tree.center == 0x10000, "Error in interval tree");

            tree.add_interval(0x100, 0x00020000, 1);

            nb += _assert(tree.contains_addr(0x100), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x200), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x20000), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x1ffff), "Error in interval tree");
            nb += _assert(tree.contains_interval(0x1ffff, 0x1000000), "Error in interval tree");
            nb += _assert(tree.contains_interval(0x9, 0x101), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x20001), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0xff), "Error in interval tree");

            tree.add_interval(0x1, 0x6, 2);
            
            nb += _assert(tree.contains_addr(0x6), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x1), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x4), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x7), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x0), "Error in interval tree");

            tree.add_interval(0x12, 0x67, 3);
            
            nb += _assert(tree.contains_addr(0x16), "Error in interval tree");
            nb += _assert(tree.contains_interval(0x6, 0x17), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x67), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x68), "Error in interval tree");
            nb += _assert(! tree.contains_interval(0x10, 0x11), "Error in interval tree");

            // Restoring
            tree.restore(1);

            nb += _assert(! tree.contains_addr(0x67), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x12), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x1), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x4), "Error in interval tree");
            nb += _assert(! tree.contains_addr(0x6), "Error in interval tree");
            nb += _assert(tree.contains_addr(0x104), "Error in interval tree");

            // Internal sorting and non-duplication
            tree.restore(0);
            tree.add_interval(0xf000, 0x11000, 1);
            tree.add_interval(0xffff, 0x20000, 2);
            tree.add_interval(0xf123, 0x20001, 3);

            list<SimpleInterval>::iterator lit;

            lit = tree.match_min.begin();
            std::advance(lit, 0);
            nb += _assert(lit->min == 0xf000, "Error in interval tree internals");
            lit = tree.match_min.begin();
            std::advance(lit, 1);
            nb += _assert(lit->min == 0xf123, "Error in interval tree internals");
            lit = tree.match_min.begin();
            std::advance(lit, 2);
            nb += _assert(lit->min == 0xffff, "Error in interval tree internals");

            lit = tree.match_max.begin();
            std::advance(lit, 0);
            nb += _assert(lit->max == 0x20001, "Error in interval tree internals");
            lit = tree.match_max.begin();
            std::advance(lit, 1);
            nb += _assert(lit->max == 0x20000, "Error in interval tree internals");
            lit = tree.match_max.begin();
            std::advance(lit, 2);
            nb += _assert(lit->max == 0x11000, "Error in interval tree internals");

            return nb;
        }
            
        unsigned int basic_symbolic_ptr()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>();
            Settings settings;
            MemEngine mem(varctx, 32);
            mem.new_segment(0x0, 0x20000, maat::mem_flag_rwx);
            Expr addr1 = exprvar(32, "var_0") & 0xffff,
                 addr2 = exprvar(32, "var_1") | 0x00000100;
            Expr val1 = exprcst(32, 0x12345678);

            mem.symbolic_ptr_write(addr1, addr1->value_set(), val1, settings);

            nb += _assert(!mem.read(0x10003, 4).is_symbolic(*varctx),"Failed to read at concrete address within symbolic memory range");
            nb += _assert(mem.read(0x10002, 4).is_symbolic(*varctx),"Failed to read at concrete address within symbolic memory range");
            nb += _assert(mem.read(0x0, 1).is_symbolic(*varctx),"Failed to read at concrete address within symbolic memory range");

            mem.symbolic_ptr_write(addr2, addr2->value_set(), val1, settings);
            nb += _assert(mem.read(0x10003, 4).is_symbolic(*varctx),"Failed to read at concrete address within symbolic memory range");

            // Restore snapshot ?
            mem.symbolic_mem_engine.restore_snapshot(1);
            nb += _assert(!mem.read(0x10003, 4).is_symbolic(*varctx),"Failed to read at concrete address within symbolic memory range");

            return nb;
        }
        
        unsigned int basic_symbolic_write()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>();
            MemEngine mem(varctx, 32);
            Settings settings;
            mem.new_segment(0x0, 0x100000, maat::mem_flag_rwx);

            Expr addr1 = exprvar(32, "var_0") & 0x0000ff00,
                 addr2 = exprvar(32, "var_1") | 0x00001100;
            Expr e, ite, ite2;
            Expr val1 = exprcst(32, 0x12345678);
            std::unique_ptr<ExprSimplifier> simp = NewDefaultExprSimplifier();

            mem.symbolic_ptr_write(addr1, addr1->value_set(), val1, settings);

            nb += _assert(!mem.read(0x10000, 4).is_symbolic(*varctx),"Concrete read in symbolic memory failed");
            nb += _assert(mem.read(0x10000, 4).as_uint(*varctx) == 0,"Concrete read in symbolic memory failed");

            ite = mem.read(0xf000, 4).as_expr(); // Read in symbolic area
            nb += _assert(ite->is_symbolic(*varctx),"Concrete read in symbolic memory failed");

            mem.symbolic_ptr_write(addr2, addr2->value_set(), val1, settings);

            // e = mem.read(0xf000, 4); // Read in symbolic area
            // ite2 = mem.unfold_exprmem(e);
            // TODO nb += _assert(ite2->neq(ite),"Concrete read in symbolic memory failed");

            // Restore snapshot ?
            /* TODO later
            mem.symbolic_mem_engine.restore_snapshot(1);
            e = mem.read(0xf000, 4); // Read in symbolic area
            ite2 = mem.unfold_exprmem(e);
            // std::cout << "Test ITE2: " << ite2 << std::endl;
            nb += _assert(ite2->eq(ite),"Concrete read in symbolic memory failed");
            */

            // Make concrete ptr write in symbolic memory
            mem.write(0xf008, exprcst(64, 0xdeadbeefcafebabe));
            e = mem.read(0xf008, 4).as_expr();
            nb += _assert(e->size == 32,"Concrete read in symbolic memory failed");
            nb += _assert(e->type != ExprType::ITE,"Concrete read in symbolic memory failed");
            nb += _assert(e->as_uint(*varctx) == 0xcafebabe,"Concrete read in symbolic memory failed");

            // Test all ptr write overwriting with another concrete one
            mem.write(0xf010, exprcst(64, 0x4142434445464748));
            
            ite2 = mem.read(0xf00d, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x48deadbe,"Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf00e, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x4748dead,"Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf00f, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x464748de, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf010, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x45464748, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf011, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x44454647, "Concrete read in symbolic memory failed");
            
            ite2 = mem.read(0xf012, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x43444546, "Concrete read in symbolic memory failed");
            
            ite2 = mem.read(0xf013, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x42434445, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf014, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x41424344, "Concrete read in symbolic memory failed");

            // With overwrite in middle
            mem.write(0xf011, exprcst(8, 0xaa));

            ite2 = mem.read(0xf010, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x4546aa48, "Concrete read in symbolic memory failed");
            
            ite2 = mem.read(0xf00f, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x46aa48de, "Concrete read in symbolic memory failed");

            return nb;
        }
        
        unsigned int basic_symbolic_read()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>(0);
            MemEngine mem(varctx, 64);
            Settings settings;
            mem.new_segment(0x0, 0x100000, maat::mem_flag_rwx);
            Expr addr1 = exprvar(64, "var_0") & 0x000001f,
                 addr2 = exprvar(64, "var_1") | 0x00001100;
            Expr e, ite, ite2;
            Value val;
            Expr val1 = exprcst(64, 0x12345678deadbeef);
            std::unique_ptr<ExprSimplifier> simp = NewDefaultExprSimplifier();

            mem.write(0x10, val1);
            varctx->set("var_0", 0x11);

            mem.symbolic_ptr_read(val, addr1, addr1->value_set(), 4, settings); // Read from symbolic ptr
            e = val.as_expr();
            nb += _assert(!e->is_symbolic(*varctx), "Read from concolic pointer failed");
            nb += _assert(e->type == ExprType::ITE, "Read from concolic pointer failed");
            nb += _assert(e->as_uint(*varctx) == 0x78deadbe, "Read from concolic pointer failed");

            mem.symbolic_ptr_read(val, addr1, addr1->value_set(), 8, settings); // Read from symbolic ptr
            e = val.as_expr();
            nb += _assert(!e->is_symbolic(*varctx), "Read from concolic pointer failed");
            nb += _assert(e->type == ExprType::ITE, "Read from concolic pointer failed");
            nb += _assert(e->as_uint(*varctx) == 0x12345678deadbe, "Read from concolic pointer failed");

            return nb;
        }

        unsigned int refine_value_set()
        {
            unsigned int nb = 0;

            MaatEngine engine(Arch::Type::NONE);
            engine.settings.symptr_refine_timeout = 30000;
            Expr e1 = exprvar(64, "var1"),
                 e2 = exprvar(64, "var2"),
                 c1 = exprcst(64, 0x00ff00),
                 c2 = exprcst(64, 6);

            ValueSet range;
            
            range = engine.refine_value_set(e1 & c1);
            nb += _assert(range.min == 0, "Failed to refine value set with solver");
            nb += _assert(range.max == 0xff00, "Failed to refine value set with solver");

            range = engine.refine_value_set((e1 & c1)*6  - 4);
            nb += _assert(range.min == 0x5fc, "Failed to refine value set with solver");
            nb += _assert(range.max == 0xfffffffffffffffc, "Failed to refine value set with solver");

            range = engine.refine_value_set((e2 ^ c1)*6 | 0x1234);
            nb += _assert(range.min == 0x1234, "Failed to refine value set with solver");
            nb += _assert(range.max == 0xfffffffffffffffe, "Failed to refine value set with solver");

            return nb;
        }
    }
}

using namespace test::symbolic_memory; 
// All unit tests 
void test_symbolic_memory(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";

    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def 
         << std::left << std::setw(34) << " Testing symbolic memory... "
         << std::flush;  
    total += interval_tree();
    total += basic_symbolic_ptr();
    total += basic_symbolic_write();
    total += basic_symbolic_read();
#ifdef HAS_SOLVER_BACKEND
    total += refine_value_set();
#endif
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
