#include "maat/serializer.hpp"
#include "maat/expression.hpp"
#include "maat/exception.hpp"
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

        template <typename T>
        void _dump_and_load(const T& src, T& dst)
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

    std::cout   << "\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;

}
