#include "maat/memory.hpp"
#include "maat/exception.hpp"
#include "maat/varcontext.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

using std::string;
using std::endl;
using std::cout;

namespace test{
    namespace memory{

        using namespace maat;

        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl; 
                throw test_exception();
            }
            return 1; 
        }
        
        /* Test memory status bitmap (symbolic/concrete) */
        unsigned int memory_bitmap()
        {
            unsigned int nb = 0;
            MemStatusBitmap map = MemStatusBitmap(0x2000);
            // Default values
            nb += _assert(map.is_concrete(0x0),"MemStatusBitmap not concrete by default");
            nb += _assert(map.is_concrete(0x1),"MemStatusBitmap not concrete by default");
            nb += _assert(map.is_concrete(0x78),"MemStatusBitmap not concrete by default");
            nb += _assert(map.is_concrete(0x789),"MemStatusBitmap not concrete by default");
            nb += _assert(map.is_concrete(0x1999),"MemStatusBitmap not concrete by default");
            // Symbolize
            map.mark_as_abstract(0x4);
            nb += _assert(map.is_abstract(0x4), "MemStatusBitmap symbolic marking failed");
            nb += _assert(map.is_concrete(0x3), "MemStatusBitmap symbolic marking spreaded too much");
            nb += _assert(map.is_concrete(0x5), "MemStatusBitmap symbolic marking spreaded too much");
            map.mark_as_abstract(0x200, 0x2ff);
            nb += _assert(map.is_abstract(0x200), "MemStatusBitmap range symbolic marking failed");
            nb += _assert(map.is_abstract(0x2ff), "MemStatusBitmap range symbolic marking failed");
            nb += _assert(map.is_abstract(0x201), "MemStatusBitmap range symbolic marking failed");
            nb += _assert(map.is_abstract(0x209), "MemStatusBitmap range symbolic marking failed");
            nb += _assert(map.is_abstract(0x278), "MemStatusBitmap range symbolic marking failed");
            nb += _assert(map.is_concrete(0x199), "MemStatusBitmap range symbolic marking spreaded too much");
            nb += _assert(map.is_concrete(0x300), "MemStatusBitmap range symbolic marking spreaded too much");
            nb += _assert(map.is_concrete(0x305), "MemStatusBitmap range symbolic marking spreaded too much");
            // Symbolize -> re-concretize
            map.mark_as_concrete(0x210);
            map.mark_as_concrete(0x220,0x220);
            map.mark_as_concrete(0x230,0x240);
            nb += _assert(map.is_concrete(0x210), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(map.is_concrete(0x220), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(map.is_concrete(0x231), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(map.is_concrete(0x240), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(map.is_concrete(0x237), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(!map.is_abstract(0x210), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(!map.is_abstract(0x220), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(!map.is_abstract(0x231), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(!map.is_abstract(0x240), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(!map.is_abstract(0x237), "MemStatusBitmap re-concretize memory failed");
            nb += _assert(map.is_concrete(0x209), "MemStatusBitmap re-concretize memory spreaded too much");
            nb += _assert(map.is_concrete(0x211), "MemStatusBitmap re-concretize memory spreaded too much");
            nb += _assert(map.is_concrete(0x219), "MemStatusBitmap re-concretize memory spreaded too much");
            nb += _assert(map.is_concrete(0x221), "MemStatusBitmap re-concretize memory spreaded too much");
            nb += _assert(map.is_concrete(0x229), "MemStatusBitmap re-concretize memory spreaded too much");
            nb += _assert(map.is_concrete(0x241), "MemStatusBitmap re-concretize memory spreaded too much");
            nb += _assert(map.is_concrete(0x243), "MemStatusBitmap re-concretize memory spreaded too much");
            // Scan for symbolized/concrete ranges
            map.mark_as_abstract(0x200, 0x250);
            map.mark_as_concrete(0x210);
            map.mark_as_concrete(0x220,0x220);
            map.mark_as_concrete(0x230,0x240);
            map.mark_as_concrete(0x250, 0x270);
            map.mark_as_abstract(0x250, 0x255);
            map.mark_as_abstract(0x237);
            nb += _assert(map.is_concrete_until(0x210) == 0x211, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_concrete_until(0x220) == 0x221, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_concrete_until(0x230) == 0x237, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_concrete_until(0x236) == 0x237, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_concrete_until(0x237) == 0x237, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_abstract_until(0x250) == 0x256, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_abstract_until(0x253) == 0x256, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_abstract_until(0x255) == 0x256, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_abstract_until(0x256) == 0x256, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_abstract_until(0x237) == 0x238, "MemStatusBitmap status scan returned wrong offset");
            
            map.mark_as_abstract(0x700, 0x707);
            nb += _assert(map.is_concrete_until(0x6ff) == 0x700, "MemStatusBitmap status scan returned wrong offset");
            nb += _assert(map.is_abstract_until(0x700) == 0x708, "MemStatusBitmap status scan returned wrong offset");
            
            return nb;
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
        
        /* Test concrete memory emulation buffer */
        unsigned int mem_concrete_buffer()
        {
            unsigned int nb = 0;
            MemConcreteBuffer buf = MemConcreteBuffer(0x10000);
            // Initialized to 0
            nb += _assert(buf.read(0x0, 1) == 0, "MemConcreteBuffer not initialized with 0's");
            nb += _assert(buf.read(0x3, 2) == 0, "MemConcreteBuffer not initialized with 0's");
            nb += _assert(buf.read(0x45, 4) == 0, "MemConcreteBuffer not initialized with 0's");
            nb += _assert(buf.read(0x4684, 8) == 0, "MemConcreteBuffer not initialized with 0's");
            // Write and read back
            buf.write(0x10, 0x12, 1);
            buf.write(0x20, 0x1234, 2); 
            buf.write(0x30, 0x12345678, 4); 
            buf.write(0x40, 0x1234567812345678, 8);
            nb += _assert(buf.read(0x10, 1) == 0x12, "MemConcreteBuffer <write then read> error");
            nb += _assert(buf.read(0x20, 2) == 0x1234, "MemConcreteBuffer <write then read> error");
            nb += _assert(buf.read(0x30, 4) == 0x12345678, "MemConcreteBuffer <write then read> error");
            nb += _assert(buf.read(0x40, 8) == 0x1234567812345678, "MemConcreteBuffer <write then read> error");
            // ! Below tests assume little endian storage
            nb += _assert(buf.read(0x21, 1) == 0x12, "MemConcreteBuffer <write then read> error");
            nb += _assert(buf.read(0x31, 2) == 0x3456, "MemConcreteBuffer <write then read> error");
            nb += _assert(buf.read(0x43, 4) == 0x34567812, "MemConcreteBuffer <write then read> error");
         
            return nb; 
        }

        /* Test concrete memory segments resizing */
        unsigned int mem_resize()
        {
            unsigned int nb = 0;
            Expr e = exprvar(8, "somevar");
            Value val = e;

            VarContext ctx = VarContext();
            MemSegment seg1 = MemSegment(0x1000, 0x1fff);
            seg1.write(0x1000, val, ctx);
            seg1.write(0x1009, val, ctx);
            seg1.write(0x1012, val, ctx);
            seg1.write(0x101b, val, ctx);
            seg1.write(0x1024, val, ctx);
            seg1.write(0x102d, val, ctx);
            seg1.write(0x1036, val, ctx);
            seg1.write(0x103f, val, ctx);
            seg1.write(0x1040, 0x1234, 2);

            nb += _assert(seg1.is_abstract_until(0x1000, 0x2000) == 0x1001, "Failed to mark memory as symbolic");
            nb += _assert(seg1.is_abstract_until(0x1009, 0x2000) == 0x100a, "Failed to mark memory as symbolic");
            nb += _assert(seg1.is_abstract_until(0x1012, 0x2000) == 0x1013, "Failed to mark memory as symbolic");
            nb += _assert(seg1.is_abstract_until(0x101b, 0x2000) == 0x101c, "Failed to mark memory as symbolic");
            nb += _assert(seg1.is_concrete_until(0x1024, 0x2000) == 0x1024, "Failed to mark memory as symbolic");
            nb += _assert(seg1.is_concrete_until(0x102e, 0x2000) == 0x1036, "Failed to mark memory as symbolic");
            
            seg1.extend_after(0x81);
            
            nb += _assert(seg1.is_abstract_until(0x1000, 0x2000) == 0x1001, "extend_after() failed");
            nb += _assert(seg1.is_abstract_until(0x1009, 0x2000) == 0x100a, "extend_after() failed");
            nb += _assert(seg1.is_abstract_until(0x1012, 0x2000) == 0x1013, "extend_after() failed");
            nb += _assert(seg1.is_abstract_until(0x101b, 0x2000) == 0x101c, "extend_after() failed");
            nb += _assert(seg1.is_concrete_until(0x1024, 0x2000) == 0x1024, "extend_after() failed");
            nb += _assert(seg1.is_concrete_until(0x102e, 0x2000) == 0x1036, "extend_after() failed");
            nb += _assert(seg1.read(0x1000, 1).as_expr()->eq(e), "extend_after() failed");
            nb += _assert(seg1.read(0x1001, 4).as_uint() == 0, "extend_after() failed");
            nb += _assert(seg1.read(0x1009, 1).as_expr()->eq(e), "extend_after() failed");
            nb += _assert(seg1.read(0x1024, 1).as_expr()->eq(e), "extend_after() failed");
            nb += _assert(seg1.read(0x1040, 2).as_uint() == 0x1234, "extend_after() failed");

            seg1.extend_before(0x1);
            
            nb += _assert(seg1.is_abstract_until(0x1000, 0x2000) == 0x1001, "extend_before() failed");
            nb += _assert(seg1.is_abstract_until(0x1009, 0x2000) == 0x100a, "extend_before() failed");
            nb += _assert(seg1.is_abstract_until(0x1012, 0x2000) == 0x1013, "extend_before() failed");
            nb += _assert(seg1.is_abstract_until(0x101b, 0x2000) == 0x101c, "extend_before() failed");
            nb += _assert(seg1.is_concrete_until(0x1024, 0x2000) == 0x1024, "extend_before() failed");
            nb += _assert(seg1.is_concrete_until(0x102e, 0x2000) == 0x1036, "extend_before() failed");
            nb += _assert(seg1.read(0x1000, 1).as_expr()->eq(e), "extend_before() failed");
            nb += _assert(seg1.read(0x1001, 4).as_uint() == 0, "extend_before() failed");
            nb += _assert(seg1.read(0x1009, 1).as_expr()->eq(e), "extend_before() failed");
            nb += _assert(seg1.read(0x1024, 1).as_expr()->eq(e), "extend_before() failed");
            nb += _assert(seg1.read(0x1040, 2).as_uint() == 0x1234, "extend_before() failed");

            return nb; 
        }

        /* Test MemSegment concrete-only read/write operations */
        unsigned int mem_concrete_rw()
        {
            unsigned int nb = 0; 
            MemSegment mem(0x1000, 0x2000);
            VarContext ctx(0); 
            Expr    c1 = exprcst(8, 1),
                    c2 = exprcst(8, 0xff),
                    c3 = exprcst(16, 42), 
                    c4 = exprcst(16, -42),
                    c5 = exprcst(32, 0x0f0f0f0f),
                    c6 = exprcst(32, 0xfeedbeef),
                    c7 = exprcst(64, 1), 
                    c8 = exprcst(64, 0xffffffffffffffff);
            uint8_t buff[128];
            for( int i = 0; i < sizeof(buff); i++){
                buff[i] = i;
            }
                    
            /* Normal write */
            mem.write(0x1000, c1, ctx);
            nb += _assert(mem.read(0x1000, 1).as_expr()->eq(c1), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1001, c2, ctx);
            nb += _assert(mem.read(0x1001, 1).as_expr()->eq(c2), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1002, c3, ctx);
            nb += _assert(mem.read(0x1002, 2).as_expr()->eq(c3), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1003, c4, ctx);
            nb += _assert(mem.read(0x1003, 2).as_expr()->eq(c4), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1004, c5, ctx);
            nb += _assert(mem.read(0x1004, 4).as_expr()->eq(c5), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1005, c6, ctx);
            nb += _assert(mem.read(0x1005, 4).as_expr()->eq(c6), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1006, c7, ctx);
            nb += _assert(mem.read(0x1006, 8).as_expr()->eq(c7), "MemSegment failed to write a constant expression then read it back");
            mem.write(0x1007, c8, ctx);
            nb += _assert(mem.read(0x1007, 8).as_expr()->eq(c8), "MemSegment failed to write a constant expression then read it back");
            
            /* Overlapping write (assuming little endian) */
            mem.write(0x1100, c8, ctx);
            mem.write(0x1104, c5, ctx);
            nb += _assert(mem.read(0x1100, 8).as_expr()->eq(exprcst(64, 0x0f0f0f0fffffffff)), "MemSegment failed to manage overlapping memory writes");
            mem.write(0x1100, c8, ctx);
            mem.write(0x1100, c6, ctx);
            nb += _assert(mem.read(0x1100, 8).as_expr()->eq(exprcst(64, 0xfffffffffeedbeef)), "MemSegment failed to manage overlapping memory writes");
            mem.write(0x1100, c7, ctx);
            mem.write(0x1100, c2, ctx);
            nb += _assert(mem.read(0x1100, 4).as_expr()->eq(exprcst(32, 0xff)), "MemSegment failed to manage overlapping memory writes");
            mem.write(0x1100, c5, ctx);
            mem.write(0x1104, c6, ctx);
            nb += _assert(mem.read(0x1100, 8).as_expr()->eq(exprcst(64, 0xfeedbeef0f0f0f0f)), "MemSegment failed to manage overlapping memory writes");
            mem.write(0x1100, c3, ctx);
            mem.write(0x1101, c6, ctx);
            nb += _assert(mem.read(0x1100, 4).as_expr()->eq(exprcst(32, 0xedbeef2a)), "MemSegment failed to manage overlapping memory writes");
            
            /* Memcpy */
            mem.write(0x1600, buff, 128);
            nb += _assert(mem.read(0x1600, 1).as_expr()->eq(exprcst(8, 0)), "MemSegment failed to write then read buffer source");
            nb += _assert(mem.read(0x1600 + 10, 1).as_expr()->eq(exprcst(8, 10)), "MemSegment failed to write then read buffer source");
            nb += _assert(mem.read(0x1600 + 127, 1).as_expr()->eq(exprcst(8, 127)),  "MemSegment failed to write then read buffer source");
            
            /* Big numbers */
            Expr big = exprcst(128, "12345678abcdabcd0000000022223333");
            mem.write(0x1100, big, ctx);
            _assert_bignum_eq(mem.read(0x1100, 16), "0x12345678abcdabcd0000000022223333", "MemSegment failed to read then write big number"); 
            mem.write(0x1110, c6, ctx);
            _assert_bignum_eq(mem.read(0x1100, 20), "0xfeedbeef12345678abcdabcd0000000022223333", "MemSegment failed to read then write big number");

            return nb;
        }
        
        /* Test MemSegment symbolic-only read/write operations */
        unsigned int mem_symbolic_rw(){
            unsigned int nb = 0; 
            Expr    e1 = exprvar(8, "var1", Taint::TAINTED),
                    e2 = exprvar(8, "var2", Taint::TAINTED),
                    e3 = exprvar(16, "var3", Taint::TAINTED),
                    e4 = exprvar(16, "var4", Taint::TAINTED),
                    e5 = exprvar(32, "var5", Taint::TAINTED),
                    e6 = exprvar(32, "var6", Taint::TAINTED),
                    e7 = exprvar(64, "var7", Taint::TAINTED);
                    
            MemSegment mem = MemSegment(0x10000, 0x10200);
            VarContext ctx = VarContext(0);
            
            /* Normal write */
            mem.write(0x10000, e1, ctx); 
            nb += _assert(mem.read(0x10000, 1).as_expr()->eq(e1), "MemSegment failed to write a symbolic epression then read it back" );
            mem.write(0x10001, e3, ctx);
            nb += _assert(mem.read(0x10001, 2).as_expr()->eq(e3), "MemSegment failed to write a symbolic epression then read it back" );
            mem.write(0x10003, e5, ctx); 
            nb += _assert(mem.read(0x10003, 4).as_expr()->eq(e5), "MemSegment failed to write a symbolic epression then read it back" );
            mem.write(0x10007, e7, ctx); 
            nb += _assert(mem.read(0x10007, 8).as_expr()->eq(e7), "MemSegment failed to write a symbolic epression then read it back" );
            
            /* Partial read */
            nb += _assert(mem.read(0x10001, 1).as_expr()->eq(extract(e3, 7, 0)), "MemSegment symbolic partial read failed");
            nb += _assert(mem.read(0x10002, 1).as_expr()->eq(extract(e3, 15, 8)), "MemSegment symbolic partial read failed");
            nb += _assert(mem.read(0x10003, 2).as_expr()->eq(extract(e5, 15, 0)), "MemSegment symbolic partial read failed");
            nb += _assert(mem.read(0x10004, 2).as_expr()->eq(extract(e5, 23, 8)), "MemSegment symbolic partial read failed");
            nb += _assert(mem.read(0x10009, 2).as_expr()->eq(extract(e7, 31, 16)), "MemSegment symbolic partial read failed");
            nb += _assert(mem.read(0x1000b, 4).as_expr()->eq(extract(e7, 63, 32)), "MemSegment symbolic partial read failed");
            
            /* Overlapping read */
            nb += _assert(mem.read(0x10000, 2).as_expr()->eq(concat(extract(e3, 7, 0), e1)), "MemSegment symbolic simple overlapping read failed");
            nb += _assert(mem.read(0x10000, 4).as_expr()->eq(concat(concat(extract(e5, 7, 0), e3), e1)), "MemSegment symbolic simple overlapping read failed");
            nb += _assert(mem.read(0x10001, 4).as_expr()->eq(concat(extract(e5, 15, 0), e3)), "MemSegment symbolic simple overlapping read failed");
            nb += _assert(mem.read(0x10006, 8).as_expr()->eq(concat(extract(e7, 55, 0), extract(e5, 31, 24))), "MemSegment symbolic simple overlapping read failed");
            
            /* Overwrite */ 
            mem.write(0x10100, e7, ctx);
            mem.write(0x10104, e6, ctx);
            nb += _assert(mem.read(0x10100, 8).as_expr()->eq(concat(e6, extract(e7, 31,0))), "MemSegment symbolic overwrite read failed");
            mem.write(0x10106, e4, ctx); 
            nb += _assert(mem.read(0x10100, 8).as_expr()->eq(concat(concat(e4, extract(e6,15, 0)), extract(e7, 31,0))), "MemSegment symbolic overwrite read failed");
            mem.write(0x10110, e7, ctx);
            mem.write(0x10112, e3, ctx);
            mem.write(0x10114, e4, ctx);
            nb += _assert(mem.read(0x10110, 8).as_expr()->eq(concat(concat(concat(extract(e7, 63, 48), e4), e3), extract(e7, 15,0))), "MemSegment symbolic overwrite read failed");
            mem.write(0x1010f, e3, ctx); 
            nb += _assert(mem.read(0x10110, 8).as_expr()->eq(concat(concat(concat(concat(extract(e7, 63, 48), e4), e3), extract(e7, 15,8)), extract(e3, 15, 8))), "MemSegment symbolic overwrite read failed");
            return nb; 
        }
        
        unsigned int mix_concrete_symbolic_rw(){
            unsigned int nb = 0; 
            Expr    e1 = exprvar(8, "var1", Taint::TAINTED),
                    e2 = exprvar(16, "var2", Taint::TAINTED),
                    e3 = exprvar(32, "var3", Taint::TAINTED),
                    e4 = exprvar(64, "var4", Taint::TAINTED),
                    c1 = exprcst(8, 0x12), 
                    c2 = exprcst(16, 0x1234), 
                    c3 = exprcst(32, 0x12345678 ),
                    c4 = exprcst(64, 0x12345678deadbabe);

            MemSegment mem = MemSegment(0x1000, 0x30ff);
            VarContext ctx = VarContext(0);
            
            /* Juxtapose concrete and symbolic */
            mem.write(0x1000, c1, ctx);
            mem.write(0x1001, e1, ctx);
            nb += _assert(mem.read(0x1000, 2).as_expr()->eq(concat(e1, c1)), "MemSegment: concrete/symbolic juxtaposition failed");
            
            mem.write(0x1001, e2, ctx);
            nb += _assert(mem.read(0x1000, 2).as_expr()->eq(concat(extract(e2, 7, 0), c1)), "MemSegment: concrete/symbolic juxtaposition failed");
            mem.write(0x1000, e1, ctx);
            mem.write(0x1001, c2, ctx);
            nb += _assert(mem.read(0x1000, 2).as_expr()->eq(concat(exprcst(8, 0x34), e1)), "MemSegment: concrete/symbolic juxtaposition failed");
            mem.write(0x1001, c4, ctx);
            nb += _assert(mem.read(0x1000, 2).as_expr()->eq(concat(exprcst(8, 0xbe), e1)), "MemSegment: concrete/symbolic juxtaposition failed");
            
            /* Overwrite concrete with symbolic and vice versa */
            mem.write(0x1100, c3, ctx);
            mem.write(0x1102, e4, ctx);
            nb += _assert(mem.read(0x1100, 4).as_expr()->eq(concat(extract(e4, 15,0), exprcst(16, 0x5678))), "MemSegment: concrete/symbolic juxtaposition failed");
            mem.write(0x10ff, e2, ctx);
            nb += _assert(mem.read(0x1100, 4).as_expr()->eq(concat(extract(e4, 15,0), concat(exprcst(8, 0x56), extract(e2, 15, 8)))), "MemSegment: concrete/symbolic juxtaposition failed");
            
            mem.write(0x1200, c4, ctx);
            mem.write(0x1204, e2, ctx);
            nb += _assert(mem.read(0x1200, 8).as_expr()->eq(concat(exprcst(16,0x1234), concat(e2, exprcst(32, 0xdeadbabe)))), "MemSegment: concrete/symbolic juxtaposition failed");
            mem.write(0x11fb, e4, ctx);
            mem.write(0x1200, c2, ctx);
            nb += _assert( mem.read(0x1200, 8).as_expr()->eq(concat( exprcst(16, 0x1234), concat( e2, concat( exprcst(8, 0xde), concat(extract(e4, 63, 56) ,c2))))), 
                    "MemSegment: concrete/symbolic juxtaposition failed");
            return nb; 
        }


        unsigned int mem_engine()
        {
            std::shared_ptr<VarContext> ctx = std::make_shared<VarContext>(0);
            MemEngine mem(ctx, 64);

            mem.map(0x1000, 0x1fff, maat::mem_flag_rw);
            mem.map(0x3000, 0x5fff, maat::mem_flag_rwx);

            mem_alert_t alert;
            Expr    e1 = exprvar(8, "var1", Taint::TAINTED),
                    e2 = exprvar(16, "var2", Taint::TAINTED),
                    e3 = exprvar(32, "var3", Taint::TAINTED),
                    e4 = exprvar(64, "var4", Taint::TAINTED),
                    e5 = exprvar(8, "var5"), 
                    c1 = exprcst(8, 0x12), 
                    c2 = exprcst(16, 0x1234), 
                    c3 = exprcst(32, 0x12345678 ),
                    c4 = exprcst(64, 0x12345678deadbabe);
            unsigned int nb = 0;
            /* Test read/write */
            mem.write(0x1002, e3, &alert);
            nb += _assert(mem.read(0x1002, 4, &alert).as_expr()->eq(e3), "MemEngine: failed to write and read back");
            mem.write(0x1002, c4, &alert);
            nb += _assert(mem.read(0x1002, 8, &alert).as_expr()->eq(c4), "MemEngine: failed to write and read back");
            nb += _assert(alert == 0, "MemEngine: didn't update the alert variable correctly");
            mem.write(0x3100, c2, &alert);
            nb += _assert((alert & maat::mem_alert_x_overwrite) != 0, "MemEngine: didn't update the alert variable correctly");
            nb += _assert(mem.read(0x3100, 2, &alert).as_expr()->eq(c2), "MemEngine: failed to write and read back");

            /* Test the status check */
            bool is_symbolic, is_tainted;
            mem.write(0x3201, e1); // 8 bits
            
            is_symbolic = false; is_tainted = false;
            mem.check_status(0x3200, 0x3207, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == true, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == true, "MemEngine: failed to check memory status");
            
            is_symbolic = false; is_tainted = false;
            mem.check_status(0x3200, 0x3201, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == true, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == true, "MemEngine: failed to check memory status");
            
            is_symbolic = false; is_tainted = false;
            mem.check_status(0x3201, 0x3201, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == true, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == true, "MemEngine: failed to check memory status");
            
            is_symbolic = true; is_tainted = true;
            mem.check_status(0x3200, 0x3200, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == false, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == false, "MemEngine: failed to check memory status");
            
            mem.write(0x3206, e5); // 8 bits
            
            is_symbolic = false; is_tainted = true;
            mem.check_status(0x3204, 0x320f, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == true, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == false, "MemEngine: failed to check memory status");
            
            is_symbolic = false; is_tainted = true;
            mem.check_status(0x3206, 0x3206, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == true, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == false, "MemEngine: failed to check memory status");
            
            is_symbolic = false; is_tainted = true;
            mem.check_status(0x3205, 0x3206, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == true, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == false, "MemEngine: failed to check memory status");
            
            is_symbolic = true; is_tainted = true;
            mem.check_status(0x3205, 0x3205, is_symbolic, is_tainted);
            nb += _assert(is_symbolic == false, "MemEngine: failed to check memory status");
            nb += _assert(is_tainted == false, "MemEngine: failed to check memory status");
            
            
            
            /* Test the make_symbolic, make_tainted interface */
            std::string name;
            std::stringstream ss;
            mem.map(0x6000, 0x7000);
            
            // Make symbolic
            name = mem.make_symbolic(0x6000, 4, 4, "buffer0");
            ss.str(""); ss.clear(); ss << name << "_0"; 
            nb += _assert(mem.read(0x6000, 4).as_expr()->eq(exprvar(32, ss.str())), "MemEngine: make_symbolic() failed");
            nb += _assert(mem.read(0x6000, 4).is_symbolic(*ctx), "MemEngine: make_symbolic() failed");
            ss.str(""); ss.clear(); ss << name << "_1"; 
            nb += _assert(mem.read(0x6004, 4).as_expr()->eq(exprvar(32, ss.str())), "MemEngine: make_symbolic() failed");
            nb += _assert(mem.read(0x6004, 4).is_symbolic(*ctx), "MemEngine: make_symbolic() failed");
            
            // Overwrite by making symbolic
            mem.write(0x6010, e4);
            name = mem.make_symbolic(0x6012, 1, 2, "symvar");
            nb += _assert(mem.read(0x6012, 4).is_symbolic(*ctx), "MemEngine: make_symbolic() failed");

            // Make tainted with renaming
            name = mem.make_tainted(0x6020, 10, 1, "var");
            ss.str(""); ss.clear(); ss << name << "_0";
            nb += _assert(mem.read(0x6020, 1).as_expr()->eq(exprvar(8, ss.str())), "MemEngine: make_tainted() failed");
            ss.str(""); ss.clear(); ss << name << "_1";
            nb += _assert(mem.read(0x6021, 1).as_expr()->eq(exprvar(8, ss.str())), "MemEngine: make_tainted() failed");
            /*
            nb += _assert(mem.read(0x6021, 1).is_tainted(), "MemEngine: make_tainted() failed");
            nb += _assert(mem.read(0x601f, 4).is_tainted(), "MemEngine: make_tainted() failed");
            */
            // Make tainted without renaming
            /*
            mem.make_tainted(0x6030, 8, 2);
            nb += _assert(!mem.read(0x6040, 1).is_tainted(), "MemEngine: make_tainted() failed");
            nb += _assert(mem.read(0x6039, 2).is_tainted(), "MemEngine: make_tainted() failed");
            nb += _assert(mem.read(0x602f, 2).is_tainted(), "MemEngine: make_tainted() failed");
            */
            return nb;
        }
        
        unsigned int mem_buffer_rw()
        {
            unsigned int nb = 0;
            std::shared_ptr<VarContext> ctx = std::make_shared<VarContext>(0);
            MemEngine mem(ctx, 64);

            mem.map(0x1000, 0x1fff, maat::mem_flag_rw);
            mem.write(0x1000, 0x12345678deadbeef, 8);
            mem.write(0x1008, 0xaaaabbbbccccdddd, 8);
            
            // Read buffer of bytes
            std::vector<Value> buf = mem.read_buffer(0x1000, 20);
            nb += _assert( buf[0].as_uint() == 0xef, "read_buffer() failed");
            nb += _assert( buf[1].as_uint() == 0xbe, "read_buffer() failed");
            nb += _assert( buf[7].as_uint() == 0x12, "read_buffer() failed");
            nb += _assert( buf[18].as_uint() == 0x0, "read_buffer() failed");
            
            // Read buffer of words
            buf = mem.read_buffer(0x1000, 10, 2);
            nb += _assert( buf[0].as_uint() == 0xbeef, "read_buffer() failed");
            nb += _assert( buf[1].as_uint() == 0xdead, "read_buffer() failed");
            nb += _assert( buf[7].as_uint() == 0xaaaa, "read_buffer() failed");
            nb += _assert( buf[9].as_uint() == 0x0, "read_buffer() failed");
            
            // Read buffer of qwords
            buf = mem.read_buffer(0x1000, 3, 8);
            nb += _assert( buf[0].as_uint() == 0x12345678deadbeef, "read_buffer() failed");
            nb += _assert( buf[1].as_uint() == 0xaaaabbbbccccdddd, "read_buffer() failed");
            nb += _assert( buf[2].as_uint() == 0x0, "read_buffer() failed");

            
            // Read string
            string str = mem.read_string(0x1009, 3);
            nb += _assert( str == "\xdd\xcc\xcc", "read_string() failed");
            
            str = mem.read_string(0x100e, 0);
            nb += _assert( str == "\xaa\xaa", "read_string() failed");            

            
            mem.write(0x1010, 0x41424344, 4);
            str = mem.read_string(0x1010, 0);
            nb += _assert( str == "DCBA", "read_string() failed");
            
            return nb; 
        
        }
     
        /* Test read/writes that overlap segments */
        unsigned int mem_rw_accross_segments()
        {
            unsigned int nb = 0; 
            Expr e = exprvar(64, "var1"), e2;
            std::shared_ptr<VarContext> ctx = std::make_shared<VarContext>(0);
            MemEngine mem(ctx, 64);

            mem.map(0x1000, 0x1fff, maat::mem_flag_rwx);
            mem.map(0x2000, 0x2fff, maat::mem_flag_rwx);

            // With concrete write
            mem.write(0x1ffe, 0x12345678deadbeef, 8);
            nb += _assert(mem.read(0x1ffe, 8).as_uint(*ctx) == 0x12345678deadbeef, "MemEngine: read/write accross segments failed");

            // With symbolic/concolic write
            mem.write(0x1ffe, e);
            e2 = mem.read(0x1ffe, 8).as_expr();
            ctx->set("var1", 0x12345678abababab);
            nb += _assert(e2->as_uint(*ctx) == 0x12345678abababab, "MemEngine: read/write accross segments failed");

            return nb; 
        }
    }
}

using namespace test::memory; 
// All unit tests 
void test_memory()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing memory engine... " << std::flush;  
    total += memory_bitmap();
    total += mem_concrete_buffer();
    // total += mem_resize(); TODO: IMPLEMENTATION OF extend_before/after() NOT DONE FOR SYMBOLIC MEMORY
    total += mem_concrete_rw();
    total += mem_symbolic_rw();
    total += mix_concrete_symbolic_rw();
    total += mem_buffer_rw();
    total += mem_engine();
    total += mem_rw_accross_segments();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}

