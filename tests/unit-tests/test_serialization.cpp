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

    std::cout   << "\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;

}
