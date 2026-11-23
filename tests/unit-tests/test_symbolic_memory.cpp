#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "maat/memory.hpp"
#include "maat/exception.hpp"
#include "maat/simplification.hpp"
#include "maat/engine.hpp"
#include "maat/varcontext.hpp"

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
            mem.map(0x0, 0x20000, maat::mem_flag_rwx);
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

        unsigned int basic_symbolic_ptr_big_endian()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>();
            Settings settings;
            MemEngine mem(varctx, 32, nullptr, Endian::BIG);
            mem.map(0x0, 0x20000, maat::mem_flag_rwx);
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
            mem.map(0x0, 0x100000, maat::mem_flag_rwx);

            Expr addr1 = exprvar(32, "var_0") & 0x0000ff00,
                 addr2 = exprvar(32, "var_1") | 0x00001100;
            Expr e, ite, ite2;
            Expr val1 = exprcst(32, 0x12345678);
            auto simp = NewDefaultExprSimplifier();

            mem.symbolic_ptr_write(addr1, addr1->value_set(), val1, settings);

            nb += _assert(!mem.read(0x10000, 4).is_symbolic(*varctx),"Concrete read in symbolic memory failed");
            nb += _assert(mem.read(0x10000, 4).as_uint(*varctx) == 0,"Concrete read in symbolic memory failed");

            ite = mem.read(0xf000, 4).as_expr(); // Read in symbolic area
            nb += _assert(ite->is_symbolic(*varctx),"Concrete read in symbolic memory failed");

            mem.symbolic_ptr_write(addr2, addr2->value_set(), val1, settings);

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

        unsigned int basic_symbolic_write_big_endian()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>();
            MemEngine mem(varctx, 32, nullptr, Endian::BIG);
            Settings settings;
            mem.map(0x0, 0x100000, maat::mem_flag_rwx);

            Expr addr1 = exprvar(32, "var_0") & 0x0000ff00,
                 addr2 = exprvar(32, "var_1") | 0x00001100;
            Expr e, ite, ite2;
            Expr val1 = exprcst(32, 0x12345678);
            auto simp = NewDefaultExprSimplifier();

            mem.symbolic_ptr_write(addr1, addr1->value_set(), val1, settings);

            nb += _assert(!mem.read(0x10000, 4).is_symbolic(*varctx),"Concrete read in symbolic memory failed");
            nb += _assert(mem.read(0x10000, 4).as_uint(*varctx) == 0,"Concrete read in symbolic memory failed");

            ite = mem.read(0xf000, 4).as_expr(); // Read in symbolic area
            nb += _assert(ite->is_symbolic(*varctx),"Concrete read in symbolic memory failed");

            mem.symbolic_ptr_write(addr2, addr2->value_set(), val1, settings);

            // Make concrete ptr write in symbolic memory
            mem.write(0xf008, exprcst(64, 0xdeadbeefcafebabe));
            e = mem.read(0xf008, 4).as_expr();
            nb += _assert(e->size == 32,"Concrete read in symbolic memory failed");
            nb += _assert(e->type != ExprType::ITE,"Concrete read in symbolic memory failed");
            nb += _assert(e->as_uint(*varctx) == 0xdeadbeef,"Concrete read in symbolic memory failed");

            // Test all ptr write overwriting with another concrete one
            mem.write(0xf010, exprcst(64, 0x4142434445464748));
            
            ite2 = mem.read(0xf00d, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0xfebabe41,"Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf00e, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0xbabe4142,"Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf00f, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0xbe414243, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf010, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x41424344, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf011, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x42434445, "Concrete read in symbolic memory failed");
            
            ite2 = mem.read(0xf012, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x43444546, "Concrete read in symbolic memory failed");
            
            ite2 = mem.read(0xf013, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x44454647, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf014, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x45464748, "Concrete read in symbolic memory failed");

            // With overwrite in middle
            mem.write(0xf011, exprcst(8, 0xaa));

            ite2 = mem.read(0xf010, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0x41aa4344, "Concrete read in symbolic memory failed");

            ite2 = mem.read(0xf00f, 4).as_expr();
            ite2 = simp->simplify(ite2);
            nb += _assert(ite2->size == 32, "Concrete read in symbolic memory failed");
            nb += _assert(!ite2->is_symbolic(*varctx), "Concrete read in symbolic mempry failed");
            nb += _assert(ite2->as_uint(*varctx) == 0xbe41aa43, "Concrete read in symbolic memory failed");

            return nb;
        }
        
        unsigned int limit_strided_pointer_range()
        {
            auto ctx = std::make_shared<VarContext>(0);
            MemEngine mem(ctx, 64);
            Expr addr = exprvar(64, "addr");
            Settings settings;
            unsigned int nb = 0;
            for (addr_t base : {addr_t(1), UINT64_MAX - 30})
            {
                ValueSet range(64, base, base + 30, 2);
                for (unsigned int limit : {0, 1, 7, 8, 64})
                {
                    settings.symptr_max_range = limit;
                    for (unsigned int i = 0; i < 16; ++i)
                    {
                        addr_t model = base + 2 * i;
                        ctx->set("addr", model);
                        ValueSet window = mem.limit_symptr_range(addr, range, settings);
                        nb += _assert(range.contains(window.min) && range.contains(window.max) &&
                            window.stride == range.stride && window.contains(model),
                            "Limited range lost the model or changed its stride");
                        nb += _assert(window.max - window.min == std::min(limit, 30u) / 2 * 2,
                            "Limited range has the wrong span");
                    }
                }
            }
            ValueSet singleton(64, 5, 5, 0);
            auto window = mem.limit_symptr_range(addr, singleton, settings);
            nb += _assert(window.min == 5 && window.max == 5 && window.stride == 0,
                "Limiting a singleton changed its range");
            return nb;
        }

        unsigned int limit_wide_pointer_range()
        {
            auto ctx = std::make_shared<VarContext>();
            MemEngine mem(ctx, 64);
            mem.map(0x1000, 0x1fff);
            mem.write(0x1040, 0x5a, 1);
            Expr addr = exprvar(256, "addr");
            ctx->set("addr", Number(256, 0x1040));
            ValueSet range(256, 0x1000, 0x10ff, 1);
            Settings settings;
            settings.symptr_limit_range = true;
            settings.symptr_max_range = 8;

            Value value;
            mem.symbolic_ptr_read(value, addr, range, 1, settings);
            unsigned int nb = _assert(value.as_uint(*ctx) == 0x5a,
                "Limited read through a 256-bit pointer missed the modeled address");
            mem.symbolic_ptr_write(addr, range, exprcst(8, 0xa5), settings);
            mem.symbolic_ptr_read(value, addr, range, 1, settings);
            nb += _assert(value.as_uint(*ctx) == 0xa5,
                "Limited write through a 256-bit pointer missed the modeled address");
            return nb;
        }

        unsigned int basic_symbolic_read()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>(0);
            MemEngine mem(varctx, 64);
            Settings settings;
            mem.map(0x0, 0x100000, maat::mem_flag_rwx);
            Expr addr1 = exprvar(64, "var_0") & 0x000001f,
                 addr2 = exprvar(64, "var_1") | 0x00001100;
            Expr e, ite, ite2;
            Value val;
            Expr val1 = exprcst(64, 0x12345678deadbeef);
            auto simp = NewDefaultExprSimplifier();

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

        unsigned int basic_symbolic_read_big_endian()
        {
            unsigned int nb = 0;

            auto varctx = std::make_shared<VarContext>(0);
            MemEngine mem(varctx, 64, nullptr, Endian::BIG);
            Settings settings;
            mem.map(0x0, 0x100000, maat::mem_flag_rwx);
            Expr addr1 = exprvar(64, "var_0") & 0x000001f,
                 addr2 = exprvar(64, "var_1") | 0x00001100;
            Expr e, ite, ite2;
            Value val;
            Expr val1 = exprcst(64, 0x12345678deadbeef);
            auto simp = NewDefaultExprSimplifier();

            mem.write(0x10, val1);
            varctx->set("var_0", 0x11);

            mem.symbolic_ptr_read(val, addr1, addr1->value_set(), 4, settings); // Read from symbolic ptr
            e = val.as_expr();
            nb += _assert(!e->is_symbolic(*varctx), "Read from concolic pointer failed");
            nb += _assert(e->type == ExprType::ITE, "Read from concolic pointer failed");
            nb += _assert(e->as_uint(*varctx) == 0x345678de, "Read from concolic pointer failed");

            mem.symbolic_ptr_read(val, addr1, addr1->value_set(), 8, settings); // Read from symbolic ptr
            e = val.as_expr();
            nb += _assert(!e->is_symbolic(*varctx), "Read from concolic pointer failed");
            nb += _assert(e->type == ExprType::ITE, "Read from concolic pointer failed");
            nb += _assert(e->as_uint(*varctx) == 0x345678deadbeef00, "Read from concolic pointer failed");

            return nb;
        }

        unsigned int strided_table_read()
        {
            auto varctx = std::make_shared<VarContext>(0);
            MemEngine mem(varctx, 64);
            mem.map(0x1000, 0x1fff);
            // Three distinct halfwords, then an odd-length run of equal bytes.
            uint8_t table[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x77, 0x77,
                               0x77, 0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x99};
            mem.write_buffer(0x1000, table, sizeof(table));
            unsigned int nb = 0;
            // The second range enters the segment at 0x1001.
            for (addr_t base : {0x1000, 0x0fff})
            {
                Expr addr = base + (exprvar(64, "index") & 7) * 2;
                for (unsigned int width : {2, 1, 4})
                {
                    Value selected;
                    mem.symbolic_ptr_read(selected, addr, addr->value_set(), width, Settings());
                    for (int index = 0; index < 8; ++index)
                    {
                        addr_t candidate = base + 2 * index;
                        if (candidate < 0x1000)
                            continue;
                        varctx->set("index", index);
                        auto expected = mem.read(candidate, width).as_uint();
                        nb += _assert(selected.as_uint(*varctx) == expected,
                            "Strided read of " + std::to_string(width) +
                            " bytes disagrees at index " + std::to_string(index));
                    }
                }
            }

            MemSegment segment(0x1000, 0x1001);
            Value selected;
            Expr addr = exprvar(64, "addr");
            ValueSet range(64, 0x0fff, 0x1001, 2);
            segment.symbolic_ptr_read(selected, addr, range, 2, nullptr);
            nb += _assert(selected.is_none(), "No complete halfword on this stride");
            range.set_cst(0x1000);
            segment.symbolic_ptr_read(selected, addr, range, 2, nullptr);
            nb += _assert(selected.as_uint() == 0, "Missed the sole candidate on stride zero");
            nb += _assert(segment.is_identical_until(0x1000, 0) == 0x1002,
                "Identical-byte scan exceeded the short segment");
            return nb;
        }

        unsigned int symbolic_read_permission_override()
        {
            auto ctx = std::make_shared<VarContext>(0);
            MemEngine mem(ctx, 64);
            mem.map(0x1000, 0x1fff, mem_flag_w);
            mem.write(0x1000, exprcst(8, 0x34));
            mem.write(0x1001, exprcst(8, 0x56));
            const Value addr = 0x1000 + (exprvar(64, "index") & 1);

            auto read_is_denied = [&](const Value& pointer, bool ignore_mem_permissions) {
                try
                {
                    mem.read(pointer, 1, ignore_mem_permissions);
                    return false;
                }
                catch (const mem_exception&)
                {
                    return true;
                }
            };
            unsigned int nb = _assert(read_is_denied(addr, false), "Symbolic read ignored write-only permissions");
            Value value = mem.read(addr, 1, true);
            ctx->set("index", 0);
            nb += _assert(value.as_uint(*ctx) == 0x34, "Permission override lost the first byte");
            ctx->set("index", 1);
            nb += _assert(value.as_uint(*ctx) == 0x56, "Permission override lost the second byte");

            mem.write(0x1fff, exprcst(8, 0x78));
            mem.new_segment(0x2000, 0x2fff, mem_flag_w);
            mem.write(0x2000, exprcst(8, 0x9a));
            mem.map(0x1000, 0x1fff, mem_flag_none);
            nb += _assert(mem.read(addr, 1, true).as_uint(*ctx) == 0x56,
                "Permission override skipped a mapped page with no access bits");
            const Value boundary = addr + 0xffe;
            nb += _assert(mem.read(boundary, 2, true).as_uint(*ctx) == 0x9a78,
                "Permission override missed a read spanning a mapping and an adjacent segment");
            mem.unmap(0x1000, 0x1fff);
            nb += _assert(read_is_denied(addr, true), "Permission override read an unmapped page");
            mem.new_segment(0x3000, 0x4fff, mem_flag_none);
            mem.write(0x3000, 0x12, 1, true);
            mem.write(0x3001, 0x34, 1, true);
            mem.write(0x4000, 0x56, 1, true);
            mem.write(0x4001, 0x78, 1, true);
            const Value direct = 0x3000 + (exprvar(64, "index") & 1);
            nb += _assert(read_is_denied(direct, false), "Direct no-access segment allowed a symbolic read");
            value = mem.read(direct, 1, true);
            for (unsigned int index : {0, 1})
            {
                ctx->set("index", index);
                nb += _assert(value.as_uint(*ctx) == (index == 0 ? 0x12 : 0x34),
                    "Permission override skipped a byte in a direct no-access segment");
            }
            mem.unmap(0x3000, 0x3fff);
            nb += _assert(read_is_denied(direct, true), "Permission override read an unmapped direct segment");
            const Value remaining = direct + 0x1000;
            value = mem.read(remaining, 1, true);
            for (unsigned int index : {0, 1})
            {
                ctx->set("index", index);
                nb += _assert(value.as_uint(*ctx) == (index == 0 ? 0x56 : 0x78),
                    "Unmapping the first page hid a byte in the second page");
            }
            return nb;
        }

        unsigned int symbolic_read_after_first_no_access_segment()
        {
            auto ctx = std::make_shared<VarContext>();
            MemEngine mem(ctx, 64);
            mem.new_segment(0x3000, 0x3fff, mem_flag_none);
            mem.write(0x3000, 0x31, 1, true);
            mem.write(0x3001, 0x32, 1, true);
            mem.unmap(0x3000, 0x3fff);
            mem.map(0x3000, 0x3fff, mem_flag_r);

            const Value addr = 0x3000 + (exprvar(64, "index") & 1);
            Value value = mem.read(addr, 1);
            unsigned int nb = 0;
            for (unsigned int index : {0, 1})
            {
                ctx->set("index", index);
                nb += _assert(value.as_uint(*ctx) == 0x31 + index,
                    "Symbolic read missed a byte after the first no-access segment became readable");
            }
            return nb;
        }

        unsigned int read_across_short_segments(Endian endian)
        {
            auto ctx = std::make_shared<VarContext>(0);
            MemEngine mem(ctx, 64, nullptr, endian);
            mem.new_segment(0x1000, 0x1001);
            mem.new_segment(0x1002, 0x1002);
            mem.new_segment(0x1003, 0x1005);
            for (addr_t a = 0x1000; a <= 0x1005; ++a)
                mem.write(a, exprcst(8, a - 0x1000));
            mem.write(0x1002, exprvar(8, "byte"));

            const Value addr = 0x1000 + (exprvar(64, "index") & 1) * 2;
            Value selected = mem.read(addr, 4);
            // The two four-byte windows contain [00 01 xx 03] and [xx 03 04 05].
            struct {
                int index, byte;
                uint32_t little, big;
            } const cases[] = {
                {0, 0x12, 0x03120100, 0x00011203},
                {0, 0xab, 0x03ab0100, 0x0001ab03},
                {1, 0x12, 0x05040312, 0x12030405},
                {1, 0xab, 0x050403ab, 0xab030405},
            };
            unsigned int nb = 0;
            for (const auto& item : cases)
            {
                ctx->set("index", item.index);
                ctx->set("byte", item.byte);
                auto expected = endian == Endian::LITTLE ? item.little : item.big;
                nb += _assert(selected.as_uint(*ctx) == expected,
                    "Incorrect strided read across short segments at index " + std::to_string(item.index));
            }
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
    total += basic_symbolic_ptr_big_endian();
    total += basic_symbolic_write();
    total += basic_symbolic_write_big_endian();
    total += limit_strided_pointer_range();
    total += limit_wide_pointer_range();
    total += basic_symbolic_read();
    total += basic_symbolic_read_big_endian();
    total += strided_table_read();
    total += symbolic_read_permission_override();
    total += symbolic_read_after_first_no_access_segment();
    total += read_across_short_segments(maat::Endian::LITTLE);
    total += read_across_short_segments(maat::Endian::BIG);
#ifdef MAAT_HAS_SOLVER_BACKEND
    total += refine_value_set();
#endif
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
