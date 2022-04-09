#include "maat/serializer.hpp"
#include "maat/maat.hpp"
#include <fstream>
#include <string>
#include <iomanip>

namespace test
{
    
    namespace serialization
    {
        using namespace maat;
        using namespace maat::serial;

        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }

        template <typename T, typename U>
        void _dump_and_load(const T& src, U& dst)
        {
            std::string serial_file("/tmp/test_serialization");
            std::ofstream out(serial_file, std::ios_base::binary);
            Serializer s(out);
            s.serialize(src);
            out.close();
        
            std::ifstream in(serial_file, std::ios_base::binary);
            Deserializer d(in);
            d.deserialize(dst);
            in.close();
        }

        unsigned int _test_expr(Expr e)
        {
            Expr e2;
            _dump_and_load(e, e2);
            return _assert(e->eq(e2), "Serializer: failed to dump then load Expr");
        }

        unsigned int serialize_expr()
        {
            unsigned int res = 0;
            Expr    var1 = exprvar(32, "var1"),
                    var2 = exprvar(32, "var2");
            Expr    e1 = extract(~(var1 + 4), 25, 0);
            Expr    e2 = ITE(var1, ITECond::EQ, exprcst(32,65), concat(var1, var2), exprcst(64, 9090));

            res += _test_expr(e1);
            res += _test_expr(e2);

            return res;
        }

        unsigned int serialize_value()
        {
            unsigned int res = 0;
            Expr    var1 = exprvar(32, "var1"),
                    var2 = exprvar(32, "var2");
            Expr    e1 = extract(~(var1 + 4), 25, 0);
            Value   v1(e1);
            Value   v2(Number(32, 123456));
            std::unique_ptr<Value>   tmp;

            _dump_and_load(v1, tmp);
            res += _assert(tmp != nullptr, "Serializer: failed to deserialize Value into unique_ptr");
            res += _assert(tmp->is_abstract(), "Serializer: failed to dump and load abstract Value");
            res += _assert(tmp->expr()->eq(e1), "Serializer: failed to dump and load abstract Value");
        
            _dump_and_load(v2, tmp);
            res += _assert(tmp != nullptr, "Serializer: failed to deserialize Value into unique_ptr");
            res += _assert(not tmp->is_abstract(), "Serializer: failed to dump and load concrete Value");
            res += _assert(tmp->as_uint(123456), "Serializer: failed to dump and load concrete Value");
        
            return res;
        }

        unsigned int serialize_mem_status_bitmap()
        {
            unsigned int res = 0;
            MemStatusBitmap b1(1000);
            std::unique_ptr<MemStatusBitmap> b2;

            b1.mark_as_abstract(10, 12);
            b1.mark_as_abstract(101, 396);
            b1.mark_as_abstract(999);

            _dump_and_load(b1, b2);
            res += _assert(b2->is_abstract_until(10, 100) == 13, "Serializer: failed to dump and load MemStatusBitmap");
            res += _assert(b2->is_abstract_until(101, 500) == 397, "Serializer: failed to dump and load MemStatusBitmap");
            res += _assert(b2->is_abstract_until(999, 100) == 1000, "Serializer: failed to dump and load MemStatusBitmap");
            res += _assert(b2->is_concrete_until(0, 100) == 10, "Serializer: failed to dump and load MemStatusBitmap");
            res += _assert(b2->is_concrete_until(999, 100) == 999, "Serializer: failed to dump and load MemStatusBitmap");

            return res;
        }

        unsigned int serialize_mem_concrete_buffer()
        {
            unsigned int res = 0;
            MemConcreteBuffer b1(1000);
            std::unique_ptr<MemConcreteBuffer> b2;

            b1.write(10, 1236456, 8);
            b1.write(101, 64651132, 4);
            b1.write(999, 7, 1);

            _dump_and_load(b1, b2);
            res += _assert(b2->read(10, 8) == 1236456, "Serializer: failed to dump and load MemConcreteBuffer");
            res += _assert(b2->read(101, 4) == 64651132, "Serializer: failed to dump and load MemConcreteBuffer");
            res += _assert(b2->read(999, 1) == 7, "Serializer: failed to dump and load MemConcreteBuffer");

            return res;
        }

        unsigned int serialize_mem_abstract_buffer()
        {
            unsigned int res = 0;
            MemAbstractBuffer b1;
            std::unique_ptr<MemAbstractBuffer> b2;

            Expr    e1 = exprcst(32, 0xaaaa),
                    e2 = exprvar(64, "A");
            
            b1.write(0x12345678, e1);
            b1.write(101, e2);

            _dump_and_load(b1, b2);
            res += _assert(b2->read(0x12345678, 4)->eq(e1), "Serializer: failed to dump and load MemAbstractBuffer");
            res += _assert(b2->read(101, 8)->eq(e2), "Serializer: failed to dump and load MemAbstractBuffer");

            return res;
        }

        unsigned int serialize_mem_segment()
        {
            unsigned int res = 0;
            MemSegment s1(10, 0x3fff, "mysegment");
            std::unique_ptr<MemSegment> s2;
            VarContext ctx;

            Expr    e1 = exprcst(32, 0xaaaa),
                    e2 = exprvar(64, "A");
            
            s1.write(12, 123456, 4);
            s1.write(101, Value(e1), ctx);
            s1.write(0x1000, Value(e2), ctx);

            _dump_and_load(s1, s2);
            res += _assert(s2->start == 10, "Serializer: failed to dump and load MemSegment");
            res += _assert(s2->end == 0x3fff, "Serializer: failed to dump and load MemSegment");
            res += _assert(s2->name == "mysegment", "Serializer: failed to dump and load MemSegment");
            res += _assert(s2->read(0x1000, 8).as_expr()->eq(e2), "Serializer: failed to dump and load MemSegment");
            res += _assert(s2->read(101, 4).as_expr()->eq(e1), "Serializer: failed to dump and load MemSegment");
            res += _assert(s2->read(12, 4).as_uint() == 123456, "Serializer: failed to dump and load MemSegment");

            return res;
        }

        unsigned int serialize_var_context()
        {
            unsigned int res = 0;
            VarContext v1;
            std::unique_ptr<VarContext> v2;

            v1.set("a", 123456);
            v1.set("b", 0xaaaaaaaabbbbbbbb);

            _dump_and_load(v1, v2);
            res += _assert(v2->get("a") == 123456, "Serializer: failed to dump and load VarContext");
            res += _assert(v2->get("b") == 0xaaaaaaaabbbbbbbb, "Serializer: failed to dump and load VarContext");

            return res;
        }

        unsigned int serialize_symbolic_mem_engine()
        {
            unsigned int res = 0;
            auto ctx = std::make_shared<VarContext>();
            SymbolicMemEngine e1(64, ctx);
            std::unique_ptr<SymbolicMemEngine> e2;

            ctx->set("a", 123456);
            ctx->set("b", 0xaaaaaaaabbbbbbbb);

            e1.concrete_ptr_write(exprcst(64, 10), Value(32, 1234));
            e1.concrete_ptr_write(exprcst(64, 100000000), Value(3, 1));
            e1.symbolic_ptr_write(exprvar(64, "c"), Value(64, 0xaaaaaaaaaa), 0, 0xffffffffffff);

            _dump_and_load(e1, e2);
            
            res += _assert(e2->concrete_ptr_read(exprcst(64, 10), 4, exprcst(32, 0xabcd))->eq(
                    e1.concrete_ptr_read(exprcst(64, 10), 4, exprcst(32, 0xabcd))
                ),
                "Serializer: failed to dump and load SymbolicMemEngine"
            );

            return res;
        }

        unsigned int serialize_mem_engine()
        {
            unsigned int res = 0;
            std::unique_ptr<MemEngine> engine2;
            auto snap = std::make_shared<SnapshotManager<Snapshot>>();
            auto ctx = std::make_shared<VarContext>();
            MemEngine engine1(ctx, 64, snap);

            Expr    e1 = exprcst(32, 0xaaaa),
                    e2 = exprvar(64, "A");
            
            engine1.map(0, 0xfffff, maat::mem_flag_rw, "map1");
            engine1.map(0x10000000, 0x10010000, maat::mem_flag_rw, "map2");
            engine1.write(12, 123456, 4);
            engine1.write(101, Value(e1));
            engine1.write(0x10000000, Value(e2));

            _dump_and_load(engine1, engine2);
            res += _assert(engine2->read(0x10000000, 8).as_expr()->eq(e2), "Serializer: failed to dump and load MemSegment");
            res += _assert(engine2->read(101, 4).as_expr()->eq(e1), "Serializer: failed to dump and load MemSegment");
            res += _assert(engine2->read(12, 4).as_uint() == 123456, "Serializer: failed to dump and load MemSegment");

            return res;
        }

        unsigned int serialize_cpu()
        {
            unsigned int res = 0;
            ir::CPU cpu1(100);
            std::unique_ptr<ir::CPU> cpu2;

            for (reg_t i = 0; i < 100; i++)
                cpu1.ctx().set(i, exprcst(32, (cst_t)i));

            _dump_and_load(cpu1, cpu2);
            for (reg_t i = 0; i < 100; i++)
                res += _assert(cpu2->ctx().get(i).as_uint() == (cst_t)i, "Serializer: failed to dump and load CPU");

            return res;
        }

        unsigned int serialize_maat_engine()
        {
            unsigned int res = 0;
            MaatEngine engine1(Arch::Type::X86, env::OS::LINUX);
            MaatEngine engine2(Arch::Type::NONE);

            // Just check that dump & load engine doesn't raise errors
            _dump_and_load(engine1, engine2);

            return res+1;
        }
    }
}

using namespace test::serialization;
// All unit tests
void test_serialization()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing serializer... " << std::flush;

    total += serialize_expr();
    total += serialize_value();
    total += serialize_mem_status_bitmap();
    total += serialize_mem_concrete_buffer();
    total += serialize_mem_abstract_buffer();
    total += serialize_mem_segment();
    total += serialize_var_context();
    total += serialize_symbolic_mem_engine();
    total += serialize_mem_engine();
    total += serialize_cpu();
    total += serialize_maat_engine();

    std::cout   << "\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;

}
