#include "maat/expression.hpp"
#include "maat/varcontext.hpp"
#include "maat/exception.hpp"
#include "maat/constraint.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>

namespace test
{
    namespace expression
    {   
        using namespace maat;

        // Individual unit tests
        unsigned int basic()
        {
            Expr e1, e2, e3, e4, e5, e6, e7, e8; 
            for( int i = 0; i < 10; i++){
                e1 = exprcst(32, -1);
                e2 = exprcst(32, 1048567);
                e3 = exprmem(32, e2);
                e4 = -e1;
                e5 = e2 - e1;
                e6 = extract(e1, 31, 23);
                e7 = e6;
            }
            return 0;
        }

        /* Expression hashing */
        unsigned int _assert_hash_eq(Expr e1, Expr e2)
        {
            if( e1->hash() != e2->hash() ){
                std::cout << "\nFail: _assert_hash_eq: " << e1 << " == " << e2 << std::endl;
                throw test_exception();  
            }
            return 1; 
        }
        
        unsigned int _assert_hash_neq(Expr e1, Expr e2)
        {
            if( e1->hash() == e2->hash() ){
                std::cout << "\nFail: _assert_hash_eq: " << e1 << " == " << e2 << std::endl;
                throw test_exception();  
            }
            return 1; 
        }
        
        unsigned hashing()
        {
            Expr    e1 = exprcst(32,1),
                    e2 = exprvar(32, "var1"),
                    e3 = exprmem(32, e2),
                    e4 = -e1,
                    e5 = e2 & e3,
                    e6 = exprmem(32, e5),
                    e7 = exprmem(32, e6),
                    e9 = e3 % e5,
                    e10 = ITE(e1, ITECond::EQ, e2, e6, e7);

            Constraint c1 = e2 != e1;

            Expr    e11 = ITE(c1, e6, e7);

            unsigned int nb = 0;
            // Hash equality 
            nb += _assert_hash_eq(e1, exprcst(32,1));
            nb += _assert_hash_eq(e2, exprvar(32, "var1"));
            nb += _assert_hash_eq(e3, exprmem(32, e2));
            nb += _assert_hash_eq(e4, (-e1));
            nb += _assert_hash_eq(e5, (e2 & e3));
            nb += _assert_hash_eq(e6, exprmem(32, e5));
            nb += _assert_hash_eq(e7, exprmem(32,e6));
            nb += _assert_hash_eq(e9, e3%e5);
            nb += _assert_hash_eq(e10, ITE(e1, ITECond::EQ, e2, e6, e7));
            nb += _assert_hash_eq(e11, ITE(c1, e6, e7));

            // Hash inequality
            nb += _assert_hash_neq(e1, e2);
            nb += _assert_hash_neq(e2,e3);
            nb += _assert_hash_neq(e3,e4);
            nb += _assert_hash_neq(e4,e5);
            nb += _assert_hash_neq(e5,e6);
            nb += _assert_hash_neq(e6,e7);
            nb += _assert_hash_neq(e9, e5%e3);
            nb += _assert_hash_neq(e10, ITE(e1, ITECond::EQ, e2, e7, e6));
            nb += _assert_hash_neq(e11, ITE(c1, e7, e6));
            return nb;
        }

        /* Expression Canonization */
        unsigned int _assert_canonize_eq(Expr e1, Expr e2 )
        {
            Expr tmp1 = expr_canonize(e1), tmp2 = expr_canonize(e2);
            if(!(tmp1->eq(tmp2)))
            {
                std::cout << "\nFail:  _assert_canonize_eq: " << e1 << " <==> " << e2
                << "\nNote: canonized as : " << tmp1 << " <==> " << tmp2 << std::endl;
                throw test_exception();
            }
            return 1;
        }
        
        unsigned int _assert_canonize_neq(Expr e1, Expr e2 )
        {
            Expr tmp1 = expr_canonize(e1), tmp2 = expr_canonize(e2);
            if(!tmp1->neq(tmp2))
            {
                std::cout << "\nFail:  _assert_canonize_neq: " << e1 << " <=/=> " << e2 
                << "\nNote: canonized as : " << tmp1 << " <==> " << tmp2 << std::endl;
                throw test_exception(); 
            }
            return 1;
        }
        
        unsigned int canonize()
        {
            Expr    cst1 = exprcst(32, 1),
                    cst2 = exprcst(32, 567),
                    var1 = exprvar(32, "var1"),
                    var2 = exprvar(32, "var2"),
                    var3 = exprvar(32, "var3"),
                    un1 = -var2,
                    bin1 = var1+var2,
                    bin2 = var3/var2,
                    bin3 = sdiv(var3,var2); 
            unsigned int nb = 0;
            // a+b == b+a 
            nb += _assert_canonize_eq((cst1+cst2), (cst2+cst1));
            nb += _assert_canonize_eq((cst1+var1), (var1+cst1));
            nb += _assert_canonize_eq((bin3+var1), (var1+bin3));
            nb += _assert_canonize_eq((bin1+bin2), (bin2+bin1));
            nb += _assert_canonize_eq((bin1+bin1), (bin1+bin1)); 
            // a*b == b*a
            nb += _assert_canonize_eq((cst1*cst2), (cst2*cst1));
            nb += _assert_canonize_eq((cst1*var1), (var1*cst1));
            // (a^b)^c == (c^b)^a
            nb += _assert_canonize_eq( cst1^var1^bin3, cst1^bin3^var1);
            // a/b/c == a/c/b
            nb += _assert_canonize_eq( var2/var3/un1, var2/un1/var3);
            // a/b != b/a 
            nb += _assert_canonize_neq(var3/cst1, cst1/var3);
            // a<<b != b<<a
            nb += _assert_canonize_neq(shl(bin1,bin2), shl(bin2, bin1));
            // a-b-c == a-c-b
            nb += _assert_canonize_eq(cst1-var1-bin3, cst1-bin3-var1);
            // a-b != b-a
            nb += _assert_canonize_neq(cst2-un1, un1-cst2);
            // Concat reordering
            nb += _assert_canonize_eq(concat(var1, concat(var2, var3)), concat(concat(var1, var2), var3));
            // ITE
            nb += _assert_canonize_eq(ITE(var1, ITECond::EQ, var2, var3, var3), ITE(var2, ITECond::EQ, var1, var3, var3));
            nb += _assert_canonize_eq(ITE(var1, ITECond::FEQ, var2, var3, var3), ITE(var2, ITECond::FEQ, var1, var3, var3));
            return nb;  
        };
        
        /* Taint propagation */ 
        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int taint()
        {
            unsigned int nb = 0; 
            Expr    e1 = exprvar(32, "var1"),
                    e2 = exprvar(32, "var2", Taint::TAINTED),
                    e3 = exprvar(32, "var3");
            Constraint c1 = e2 < e1;
            // Taint propagation basic
            nb += _assert(e2->is_tainted(), "Taint didn't propagate when it should ");
            nb += _assert((e1/e2)->is_tainted(), "Taint didn't propagate when it should ");
            nb += _assert((extract(e2, 31, 17)->is_tainted()), "Taint didn't propagate when it should ");
            nb += _assert((e1*(e2-e3))->is_tainted(), "Taint didn't propagate when it should ");
            nb += _assert((concat(e1,e2))->is_tainted(), "Taint didn't propagate when it should ");
            //nb += _assert((exprmem(16, e2))->is_tainted(), "Taint didn't propagate when it should ");
            //nb += _assert((exprmem(16, e2^e1))->is_tainted(), "Taint didn't propagate when it should ");
            nb += _assert(ITE(e1, ITECond::LT, e1, e2, e3)->is_tainted(), "Taint didn't propagate when it should ");
            nb += _assert((-e2)->is_tainted(), "Taint didn't propagate when it should ");
            nb += _assert(!(e1)->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!(e3)->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!(e1+e3)->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!(e1+exprcst(32,789))->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!(extract(e3+e1, 20, 20))->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!(concat(e3,e1))->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!(~e3)->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!ITE(e2, ITECond::LT, e1, e1, e3)->is_tainted(), "Taint did propagate when it shouldn't ");
            nb += _assert(!ITE(c1, e1, e3)->is_tainted(), "Taint did propagate when it shouldn't ");

            // Taint mask propagation
            e1->make_tainted(0x0000f0f0);
            e3->make_tainted(0x001000f1);
            
            nb += _assert(e1->is_tainted(0x0000f0d0), "Error in taint mask propagation");
            nb += _assert(e3->is_tainted(0x00000011), "Error in taint mask propagation");
            nb += _assert(!e1->is_tainted(0x10000902), "Error in taint mask propagation");
            nb += _assert(!e3->is_tainted(0xff0fff00), "Error in taint mask propagation");
            nb += _assert(e2->is_tainted(0x00100000), "Error in taint mask propagation");

            nb += _assert((e1+e3)->is_tainted(0x0031f1f3), "Error in taint mask propagation");
            nb += _assert(!(e1+e3)->is_tainted(0xffce0e0c), "Error in taint mask propagation");
            nb += _assert((e1&e3)->is_tainted(0x0010f0f1), "Error in taint mask propagation");
            nb += _assert(!(e1^e3)->is_tainted(0xffef0f0e), "Error in taint mask propagation");
            
            nb += _assert(extract(e1, 15, 4)->is_tainted(0xf0d), "Error in taint mask propagation");
            nb += _assert(!extract(e1, 15, 4)->is_tainted(0x0f0), "Error in taint mask propagation");
            
            nb += _assert( concat(e1,e3)->is_tainted(0x0000f0f0001000c1), "Error in taint mask propagation");
            nb += _assert(!concat(e1,e3)->is_tainted(0xffff0f0fffefff0e), "Error in taint mask propagation");

            nb += _assert( ITE(e1, ITECond::EQ, e2, e1, e3)->is_tainted(0x0010f0f1), "Error in taint mask propagation");
            nb += _assert(!ITE(e1, ITECond::LT, e2, e1, e3)->is_tainted(0xffef0f0e), "Error in taint mask propagation");

            return nb;
        }

        /* Concretization */
        unsigned int concretization()
        {
            unsigned int nb = 0; 
            VarContext ctx = VarContext();
            VarContext ctx2 = VarContext();
            Expr    v1 = exprvar(32, "var1" ),
                    v2 = exprvar(32, "var2"),
                    v3 = exprvar(64, "var3"),
                    v4 = exprvar(64, "var4"),
                    e1 = v1|v2, 
                    e2 = v3+v4,
                    e3 = extract(v1, 8, 1),
                    e4 = concat(v2,v1),
                    e5 = ITE(v1, ITECond::LE, v2, v3, v4);
            Constraint c1 = v1 == v2,
                    c2 = v1 > v2,
                    c3 = c1 || c2;
            Expr    e6 = ITE(c3, v3, v4);
            
            ctx.set("var1", 10);
            ctx.set("var2", -2);
            ctx.set("var3", 0xffff000000000000);
            ctx.set("var4", 0x0000ffffffffffff);
            
            ctx2.set("var1", 7);
            ctx2.set("var2", -1);
            ctx2.set("var3", 0xeeee000000000000);
            ctx2.set("var4", 0x0000eeeeeeeeeeee);

            nb += _assert( v1->as_int(ctx) == 10, "Concretization gave wrong result");
            nb += _assert( v2->as_int(ctx) == -2, "Concretization gave wrong result"); 
            nb += _assert( v3->as_int(ctx) == 0xffff000000000000, "Concretization gave wrong result"); 
            nb += _assert( v4->as_int(ctx) == 0x0000ffffffffffff, "Concretization gave wrong result"); 
            nb += _assert( e5->as_int(ctx) == 0xffff000000000000, "Concretization gave wrong result");

            nb += _assert( (v1+v2)->as_int(ctx) == exprcst(32, 8)->as_int(ctx), "Concretization gave wrong result"); 
            nb += _assert( (v1*v2)->as_int(ctx) == exprcst(32, -20)->as_int(ctx), "Concretization gave wrong result"); 
            nb += _assert( (v1/v2)->as_int(ctx) == exprcst(32, 0)->as_int(ctx), "Concretization gave wrong result"); 
            nb += _assert( sdiv(v1,v2)->as_int(ctx) == exprcst(32, -5)->as_int(ctx), "Concretization gave wrong result"); 
            nb += _assert( (v1^v2)->as_int(ctx) == exprcst(32, 10^-2)->as_int(ctx), "Concretization gave wrong result");
            nb += _assert( (v1|v2)->as_int(ctx) == exprcst(32, 10|-2)->as_int(ctx), "Concretization gave wrong result");
            nb += _assert( extract(v2,31,24)->as_int(ctx) == exprcst(8, 0xff)->as_int(ctx), "Concretization gave wrong result");
            nb += _assert( shr(v1,exprcst(32, 2))->as_int(ctx) == 2, "Concretization gave wrong result");
            nb += _assert( shl(exprcst(32, 0x800000001),exprcst(32, 2))->as_int(ctx) == 4, "Concretization gave wrong result");

            nb += _assert( sar(exprcst(32, 0x80000001), exprcst(32, 4))->as_uint(ctx) == 0xf8000000, "Concretization gave wrong result");
            nb += _assert( sar(exprcst(64, 0xfedcba9800000000), exprcst(64, 8))->as_uint(ctx) == 0xfffedcba98000000, "Concretization gave wrong result");            
            nb += _assert( sar(exprcst(32, 0x40000001), exprcst(32, 4))->as_uint(ctx) == 0x04000000, "Concretization gave wrong result");
            nb += _assert( sar(exprcst(64, 0x8080808080808080), exprcst(64, 2))->as_uint(ctx) == 0xe020202020202020, "Concretization gave wrong result");
            nb += _assert( concat(v1,v2)->as_int(ctx) == 0x0000000afffffffe, "Concretization gave wrong result");
            /* TODO remove those when we switch to REM instead of MOD
            nb += _assert( smod(exprcst(32, -6), exprcst(32, 5))->as_int(ctx) == -1, "Concretization gave wrong result");
            nb += _assert( smod(exprcst(32, -10), exprcst(32,3))->as_int(ctx) == -1, "Concretization gave wrong result");
            nb += _assert( smod(exprcst(32, 10), exprcst(32,-3))->as_int(ctx) == 1, "Concretization gave wrong result");
            */

            // multiplications
            /* TODO, is MULH still relevant ? 
            nb += _assert( mulh(exprcst(64, 0xbbf543), exprcst(64, 0xfffffabc7865))->as_int(ctx) == 0xbb, "Concretization gave wrong result");
            nb += _assert( mulh(exprcst(32, 0xbbf543), exprcst(32, 0xc7865))->as_int(ctx) == 0x927, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(8, 48), exprcst(8, 4))->as_int(ctx) == 0xffffffffffffffc0, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(8, 48), exprcst(8, 4))->as_int(ctx) == 0, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(8, -4), exprcst(8, 4))->as_int(ctx) == 0xfffffffffffffff0, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(8, -4), exprcst(8, 4))->as_int(ctx) == 0xffffffffffffffff, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(16, 48), exprcst(16, 4))->as_int(ctx) == 0xc0, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(16, 48), exprcst(16, 4))->as_int(ctx) == 0, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(32, 4823424), exprcst(32, -423))->as_int(ctx) == 0xffffffff86635D80, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(32, 4823424), exprcst(32, -423))->as_int(ctx) == 0xffffffffffffffff, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(32, -1), exprcst(32, -1))->as_int(ctx) == 1, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(32, -1), exprcst(32, -1))->as_int(ctx) == 0, "Concretization gave wrong result");
            */
            
            nb += _assert( (-v3)->as_int(ctx) == 0x0001000000000000, "Concretization gave wrong result");
            nb += _assert( (~v4)->as_int(ctx) == 0xffff000000000000, "Concretization gave wrong result");  
            nb += _assert( (v3^v4)->as_int(ctx) == -1, "Concretization gave wrong result");
            nb += _assert( (v4&v3)->as_int(ctx) == 0, "Concretization gave wrong result");
            nb += _assert( (v3|v4)->as_int(ctx) == -1, "Concretization gave wrong result");
            nb += _assert( (v3*v4)->as_int(ctx) == 0xffff000000000000*0x0000ffffffffffff, "Concretization gave wrong result");
            //nb += _assert(( exprcst(32, 23)%exprcst(32, 2))->as_int(ctx) == 1, "Concretization gave wrong result");
            //nb += _assert(( exprcst(32, 20)%exprcst(32, 27))->as_int(ctx) == 20, "Concretization gave wrong result");
            //nb += _assert(( exprcst(32, 0xffffffff)%exprcst(32, 4))->as_int(ctx) == 
            //              ( exprcst(32, -1)%exprcst(32, 4))->as_int(ctx), "Concretization gave wrong result");

            nb += _assert( v1->as_int(ctx) != v1->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( v2->as_int(ctx) != v2->as_int(ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( v3->as_int(ctx) != v3->as_int(ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( v4->as_int(ctx) != v4->as_int(ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( (v1|v2)->as_int(ctx) != (v1|v2)->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e1->as_int(ctx) != e1->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e2->as_int(ctx) != e2->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e3->as_int(ctx) != e3->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e4->as_int(ctx) != e4->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e5->as_int(ctx) != e5->as_int(ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e6->as_int(ctx) != e6->as_int(ctx2), "Concretization with different contexts gave same result");

            // as unsigned
            nb += _assert( exprcst(7, 0xfffff)->as_uint() == 0x7f, "Interpretation as unsigned failed");
            nb += _assert( exprcst(64, 0xffff0000ffff0000)->as_uint() == 0xffff0000ffff0000, "Interpretation as unsigned failed");
            nb += _assert( exprcst(16, 0xffff0000)->as_uint() == 0, "Interpretation as unsigned failed");
            nb += _assert( extract(exprcst(64, 0xffffffffffffffff), 63, 63)->as_uint() == 1, "Interpretation as unsigned failed");
            
            nb += _assert( (exprcst(64, 0x12345678deadbeef) >> exprcst(64, 64))->as_uint() == 0, "Concretization gave wrong result");
            nb += _assert( (exprcst(64, 0x12345678deadbeef) << exprcst(64, 67))->as_uint() == 0, "Concretization gave wrong result");

            // bugs
            nb += _assert( extract(exprcst(64, 0xfffffffffffff000), 63, 63)->as_uint() == 1, "Concretization failed");

            return nb;
        }

        /* Concretization to floating-pointe */
        unsigned int floating_point()
        {
            unsigned int nb = 0; 
            VarContext ctx = VarContext(0);
            Expr    v1 = exprvar(32, "var1" ),
                    v2 = exprvar(64, "var2");
            
            ctx.set("var1", 0xc8765432);
            nb += _assert( v1->as_float(ctx) == -252240.781250, "Float concretization gave wrong result");
            ctx.set("var1", 0xffff0000c8765432); // With extra stuff above
            nb += _assert( v1->as_float(ctx) == -252240.781250, "Float concretization gave wrong result");

            ctx.set("var2", 0xf1230000c8765432);
            nb += _assert( v2->as_float(ctx) == -966585951975641604397878987804619433003308310484078397905302386511390726917574461359137175674715653924206207181532446082758966450448501976002331945223078365978066319133670017617475516268254192629748638403125320961327323445882106295615488.000000, "Float concretization gave wrong result");
            ctx.set("var2", 0xc400111111111111);
            nb += _assert( v2->as_float(ctx) == -37047211014700015616.000000, "Float concretization gave wrong result");

            return nb;
        }

    
        unsigned int _assert_bignum_eq(
                        VarContext& ctx,
                        Expr var,
                        std::string expected_value,
                        std::string error_msg
                    )
        {
            const Number& number = var->as_number(ctx);
            std::stringstream ss;
            ss << number;
            if (ss.str() != expected_value)
            {
                std::cout << "\nFail: _assert_bignum_eq: " << ss.str() << " is not " << expected_value << std::endl;
                throw test_exception(); 
            }
            return 1; 
        }

        unsigned int big_numbers()
        {
            unsigned int nb = 0;
            VarContext ctx = VarContext();
            Expr    v1 = exprvar(32, "var1" ),
                    v2 = exprvar(64, "var2"),
                    v3 = exprvar(128, "var3"),
                    v4 = exprvar(128, "var4"),
                    e1 = v3|v4,
                    e2 = v3+v4,
                    e3 = extract(v4, 8, 1),
                    e4 = concat(v2,v3),
                    e5 = ITE(v1, ITECond::LE, extract(v4, 95, 64), v3, v4);
            Number n1, n2, n3;

            // Set context
            n1 = Number(32); n1.set_cst(10);
            ctx.set("var1", 10);

            n2 = Number(64); n2.set_cst(-2);
            ctx.set("var2", -2);

            n1 = Number(64); n1.set_cst(0xffff0000ff0f00ef);
            n2 = Number(64); n2.set_cst(0xffff000000000000);
            n3.set_concat(n1, n2);
            ctx.set("var3", n3);

            n1 = Number(64); n1.set_cst(0x12340000ffff0000);
            n2 = Number(64); n2.set_cst(0x0f0f000000ff0002);
            n3.set_concat(n1, n2);
            ctx.set("var4", n3);

            nb += _assert_bignum_eq(ctx, v3, "0xffff0000ff0f00efffff000000000000", "Error when creating big numbers"); 
            nb += _assert_bignum_eq(ctx, v4, "0x12340000ffff00000f0f000000ff0002", "Error when creating big numbers");

            nb += _assert( v1->as_int(ctx) == 10, "Concretization gave wrong result");
            nb += _assert( v2->as_int(ctx) == -2, "Concretization gave wrong result");
            nb += _assert( e3->as_uint(ctx) == 1, "Concretization gave wrong result");

            nb += _assert_bignum_eq(ctx, (v3+v4), "0x12330001ff0e00f00f0e000000ff0002", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, (v3*v4), "0x1f0c00e4ed2e00e0fffe000000000000", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, (v3^v4), "0xedcb000000f000eff0f0000000ff0002", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, (v3|v4), "0xffff0000ffff00efffff000000ff0002", "Error when creating big numbers");

            nb += _assert(extract(v3, 127, 120)->as_uint(ctx) == 0xff, "Error when using big number");
            nb += _assert_bignum_eq(ctx, v4 >> 64, "0x12340000ffff0000", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, shl(exprcst(128, 0x80000001), 64), "0x800000010000000000000000", "Error when creating big numbers");

            nb += _assert_bignum_eq(ctx, sar(v3, 64), "0xffffffffffffffffffff0000ff0f00ef", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, sar(v4, 8), "0x12340000ffff00000f0f000000ff00", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, concat(v3,v4), "0xffff0000ff0f00efffff00000000000012340000ffff00000f0f000000ff0002", "Error when creating big numbers");

            nb += _assert_bignum_eq(ctx, -v3, "0xffff00f0ff100001000000000000", "Error when creating big numbers");
            nb += _assert_bignum_eq(ctx, ~v4, "0xedcbffff0000fffff0f0ffffff00fffd", "Error when creating big numbers");

            nb += _assert_bignum_eq(ctx, exprcst(128, "12345678123456781234567812345678"), "0x12345678123456781234567812345678", "Error when creating big constant");
            nb += _assert_bignum_eq(ctx, exprcst(128, "AAEAEAA12345678123456781234567812345678"), "0x12345678123456781234567812345678", "Error when creating big constant");

            return nb;
        }
        
        unsigned int change_varctx()
        {
            unsigned int nb = 0; 
            VarContext ctx = VarContext(0);
            Expr    v1 = exprvar(32, "var1" ),
                    v2 = exprvar(32, "var2"),
                    v3 = exprvar(64, "var3"),
                    v4 = exprvar(64, "var4"),
                    e1 = v1+v2, 
                    e2 = v3|v4;
            ctx.set("var1", 100);
            ctx.set("var2", -2);
            
            nb += _assert( v1->as_int(ctx) == 100, "Concretization gave wrong result");
            nb += _assert( v2->as_int(ctx) == -2, "Concretization gave wrong result"); 
            
            ctx.set("var1", 10);
            ctx.set("var3", 0xffff000000000000);
            ctx.set("var4", 0x0000ffffffffffff);
            
            nb += _assert( v1->as_int(ctx) == 10, "Concretization gave wrong result");
            nb += _assert( v2->as_int(ctx) == -2, "Concretization gave wrong result"); 
            nb += _assert( v3->as_int(ctx) == 0xffff000000000000, "Concretization gave wrong result"); 
            nb += _assert( v4->as_int(ctx) == 0x0000ffffffffffff, "Concretization gave wrong result"); 
            
            
            nb += _assert( e1->as_int(ctx) == exprcst(32, 8)->as_int(ctx), "Concretization gave wrong result"); 
            nb += _assert( e2->as_int(ctx) == exprcst(64, -1)->as_int(ctx), "Concretization gave wrong result"); 
            
            ctx.set("var2", -3);
            ctx.set("var4", 0xffff000000000000);
            
            nb += _assert( e1->as_int(ctx) == exprcst(32, 7)->as_int(ctx), "Concretization gave wrong result"); 
            nb += _assert( e2->as_int(ctx) == exprcst(64, 0xffff000000000000)->as_int(ctx), "Concretization gave wrong result");

            return nb;
        }
        
        unsigned int strided_interval()
        {
            unsigned int nb = 0;
            ValueSet vs1(32), vs2(32), vs3(32);
            
            // Or
            vs1.set(0xab000000, 0xffedcba9, 4);
            vs2.set_cst(0x00123456);
            vs3.set_or(vs1, vs2);
            nb += _assert( vs3.min == 0xab123456, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xffffffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation"); 
            
            vs1 = ValueSet(64, 0x1200000034000000, 0xff000000350000ff, 8);
            vs2 = ValueSet(64, 0x1234, 0xffff, 8);
            vs3.set_or(vs1, vs2);
            nb += _assert( vs3.min == 0x1200000034001234, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xff0000003500ffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation"); 

            // Xor
            vs1 = ValueSet(64, 0x1200000034000000, 0xff000000350000ff, 8);
            vs2 = ValueSet(64, 0x1234, 0xffff, 8);
            vs3.set_xor(vs1, vs2);
            nb += _assert( vs3.min == 0x1200000034000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xff0000003500ffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation"); 

            // Add
            // Add Without overflow
            vs1 = ValueSet(32, 0x300, 0x400, 4);
            vs2 = ValueSet(32, 0x1000, 0x2004, 6);
            vs3.set_add(vs1, vs2);
            nb += _assert( vs3.min == 0x1300, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x2404, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 2, "Wrong strided interval computation"); 
            nb += _assert( vs3.contains(0x100c  + 0x340), "Wrong strided interval computation");

            // Add With upper bound overflow
            vs1 = ValueSet(32, 0x300, 0xffff11ff, 4);
            vs2 = ValueSet(32, 0x1000, 0x0000f000, 6);
            vs3.set_add(vs1, vs2);
            nb += _assert( vs3.min == 0, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xffffffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Add With both bounds overflow
            vs1 = ValueSet(32, 0xffff1100, 0xffff11ff, 1);
            vs2 = ValueSet(32, 0x0000f000, 0x0000f100, 2);
            vs3.set_add(vs1, vs2);
            nb += _assert( vs3.min == 0x100, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x2ff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Add With both bounds overflow 64 bits 
            vs1 = ValueSet(64, 0xffffffffffff1100, 0xffffffffffff1102, 1);
            vs2 = ValueSet(64, 0xffffffff0000f000, 0xffffffff0000f100, 2);
            vs3.set_add(vs1, vs2);
            nb += _assert( vs3.min == 0x100, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x202, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Neg 32 bits
            vs1 = ValueSet(32, 0xfff00000, 0xfffaaaaa, 0xa);
            vs3.set_neg(vs1);
            nb += _assert( vs3.min == 0x00055556, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x00100000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 0xa, "Wrong strided interval computation");
                
            // Not 64 bits
            vs1 = ValueSet(64, 0xffff0000fff00000, 0xffff0000fffaaaaa, 0xa);
            vs3 = ValueSet(64);
            vs3.set_not(vs1);
            nb += _assert( vs3.min == 0xffff00055555, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xffff000fffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 0xa, "Wrong strided interval computation");

            // Shl 32 bits with bits shifted out
            vs1 = ValueSet(32, 0x00f00000, 0x00f000ac, 2);
            vs2 = ValueSet(32, 1, 9, 1);
            vs3 = ValueSet(32);
            vs3.set_shl(vs1, vs2);
            nb += _assert( vs3.min == 0, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xfffffffe, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Shl 32 bits with no bits shifted out
            vs1 = ValueSet(32, 0x00800000, 0x00800008, 2);
            vs2 = ValueSet(32, 1, 4, 1);
            vs3 = ValueSet(32);
            vs3.set_shl(vs1, vs2);
            nb += _assert( vs3.min == 0x01000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x08000080, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Shl 32 bits with constant shift
            vs1 = ValueSet(32, 0x00800000, 0x00800008, 2);
            vs2.set_cst(0x3);
            vs3 = ValueSet(32);
            vs3.set_shl(vs1, vs2);
            nb += _assert( vs3.min == 0x04000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x04000040, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 2<<3, "Wrong strided interval computation");

            // Shr 32 bits with no bits shifted out
            vs1 = ValueSet(32, 0x00800000, 0x00800008, 2);
            vs2 = ValueSet(32, 1, 4, 1);
            vs3 = ValueSet(32);
            vs3.set_shr(vs1, vs2);
            nb += _assert( vs3.min == 0x00080000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x00400004, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Shr 64 bits with constant shift
            vs1 = ValueSet(64, 0x0080000000000000, 0x0080000800000000, 0x2000);
            vs2 = ValueSet(64);
            vs2.set_cst(0x3);
            vs3 = ValueSet(64);
            vs3.set_shr(vs1, vs2);
            nb += _assert( vs3.min == 0x0010000000000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x0010000100000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 0x400, "Wrong strided interval computation");

            // Sar 64 bits with constant shift
            vs1 = ValueSet(64, 0xf000000000000000, 0xff00000000000000, 0x2000);
            vs2 = ValueSet(64);
            vs2.set_cst(0x4);
            vs3 = ValueSet(64);
            vs3.set_sar(vs1, vs2);
            nb += _assert( vs3.min == 0x0f00000000000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xfff0000000000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 0x200, "Wrong strided interval computation");

            // Sar 32 bits everything shifted out
            vs1 = ValueSet(32, 0x00f00000, 0xf0f000ac, 2);
            vs2 = ValueSet(32, 100, 200, 10);
            vs3 = ValueSet(32);
            vs3.set_sar(vs1, vs2);
            nb += _assert( vs3.min == 0, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xffffffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Sar 32 bits
            vs1 = ValueSet(32, 0x00f00000, 0xf0000004, 4);
            vs2 = ValueSet(32, 0x1, 0x8, 1);
            vs3 = ValueSet(32);
            vs3.set_sar(vs1, vs2);
            nb += _assert( vs3.min == 0x0000f000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xf8000002, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Mul on 32 bits without overflow
            vs1 = ValueSet(32, 0x00121212, 0x00242424, 2);
            vs2 = ValueSet(32, 2, 3, 1);
            vs3 = ValueSet(32);
            vs3.set_mul(vs1, vs2);
            nb += _assert( vs3.min == 0x00242424, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x006c6c6c, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Mul on 32 bits with overflow
            vs1 = ValueSet(32, 0x00121212, 0x00242424, 2);
            vs2 = ValueSet(32, 2, 0x1000, 1);
            vs3 = ValueSet(32);
            vs3.set_mul(vs1, vs2);
            nb += _assert( vs3.min == 0, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xffffffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");
            
            // Mul on 32 bits with constant
            vs1 = ValueSet(32, 0x00121212, 0x00242424, 2);
            vs2 = ValueSet(32, 3, 3, 0);
            vs3 = ValueSet(32);
            vs3.set_mul(vs1, vs2);
            nb += _assert( vs3.min == 0x00363636, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x006c6c6c, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 6, "Wrong strided interval computation");
            
            // Mul on 64 bits without overflow
            vs1 = ValueSet(64, 0x0012121200000000, 0x0024242400000000, 0x2000);
            vs2 = ValueSet(64, 2, 3, 1);
            vs3 = ValueSet(64);
            vs3.set_mul(vs1, vs2);
            nb += _assert( vs3.min == 0x0024242400000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x006c6c6c00000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Mul on 64 bits with overflow
            vs1 = ValueSet(64, 0x0012121200000000, 0x0024242400000000, 2);
            vs2 = ValueSet(64, 2, 0x1000, 1);
            vs3 = ValueSet(64);
            vs3.set_mul(vs1, vs2);
            nb += _assert( vs3.min == 0, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0xffffffffffffffff, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");
            
            // Mul on 64 bits with constant
            vs1 = ValueSet(64, 0x0012121200000000, 0x0024242400000000, 0x2000);
            vs2 = ValueSet(64, 3, 3, 0);
            vs3 = ValueSet(64);
            vs3.set_mul(vs1, vs2);
            nb += _assert( vs3.min == 0x0036363600000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x006c6c6c00000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 0x6000, "Wrong strided interval computation");

            // Mulh on 32 bits
            vs1 = ValueSet(32, 0x00121212, 0x00242424, 2);
            vs2 = ValueSet(32, 0x1000, 0x2000, 0x1000);
            vs3 = ValueSet(32);
            vs3.set_mulh(vs1, vs2);
            nb += _assert( vs3.min == 0x1, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x4, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Mulh on 64 bits
            vs1 = ValueSet(64, 0x0012121200000000, 0x0024242400000000, 2);
            vs2 = ValueSet(64, 0x1000, 0x2000, 1);
            vs3 = ValueSet(64);
            vs3.set_mulh(vs1, vs2);
            nb += _assert( vs3.min == 0x1, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x4, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");
            
            vs1 = ValueSet(64, 0x0012121200000000, 0x0024242400000000, 2);
            vs2 = ValueSet(64, 0x1000000000000000, 0x2000000000000000, 1);
            vs3 = ValueSet(64);
            vs3.set_mulh(vs1, vs2);
            nb += _assert( vs3.min == 0x1212120000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x4848480000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");
            
            // Div on 32 bits
            vs1 = ValueSet(32, 0x1234, 0x40000, 4);
            vs2 = ValueSet(32, 0x4, 0x200, 2);
            vs3 = ValueSet(32);
            vs3.set_div(vs1, vs2);
            nb += _assert( vs3.min == 0x9, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x10000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 1, "Wrong strided interval computation");

            // Div on 64 bits by constant
            vs1 = ValueSet(64, 0x123400000000, 0x4000000000000, 0x4000);
            vs2 = ValueSet(64, 0x20, 0x20, 0);
            vs3 = ValueSet(64);
            vs3.set_div(vs1, vs2);
            nb += _assert( vs3.min == 0x91a0000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.max == 0x200000000000, "Wrong strided interval computation"); 
            nb += _assert( vs3.stride == 0x200, "Wrong strided interval computation");

            return nb;
        }
        
        
        unsigned int value_set()
        {
            unsigned int nb = 0; 
            Expr    v1 = exprvar(64, "var1" ),
                    v2 = exprcst(32, 0x123456),
                    e1 = v1 | exprcst(64, 0x0000ffffffff0000),
                    e2 = v1 & exprcst(64, 0x0000ffffffff0000),
                    e3 = v2 | exprcst(32, 0xab000000);


            // Variables strided intervals
            nb += _assert( v1->value_set().min == 0, "Wrong value set for expression"); 
            nb += _assert( v1->value_set().max == 0xffffffffffffffff, "Wrong value set for expression"); 
            nb += _assert( v1->value_set().stride == 1, "Wrong value set for expression"); 
            nb += _assert( !v1->value_set().is_cst(), "Wrong value set for expression"); 

            nb += _assert( v2->value_set().min == 0x123456, "Wrong value set for expression"); 
            nb += _assert( v2->value_set().max == 0x123456, "Wrong value set for expression"); 
            nb += _assert( v2->value_set().stride == 0, "Wrong value set for expression"); 
            nb += _assert( v2->value_set().is_cst(), "Wrong value set for expression"); 

            // Or
            nb += _assert( e1->value_set().min == 0x0000ffffffff0000, "Wrong value set for expression"); 
            nb += _assert( e1->value_set().max == 0xffffffffffffffff, "Wrong value set for expression"); 
            nb += _assert( e1->value_set().stride == 1, "Wrong value set for expression");  
            nb += _assert( e3->value_set().min == 0xab123456, "Wrong value set for expression"); 
            nb += _assert( e3->value_set().max == 0xab123456, "Wrong value set for expression"); 
            nb += _assert( e3->value_set().is_cst(), "Wrong value set for expression");

            // And
            nb += _assert( e2->value_set().min == 0, "Wrong value set for expression"); 
            nb += _assert( e2->value_set().max == 0x0000ffffffff0000, "Wrong value set for expression"); 
            nb += _assert( e2->value_set().stride == 1, "Wrong value set for expression");

            return nb;
        }
    } // namespace expression
} // namespace test

using namespace test::expression; 

// All unit tests 
void test_expression()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";
    
    // Start testing 
    std::cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing expression module... " << std::flush;  
    total += basic();
    total += canonize();
    total += hashing();
    total += taint();
    total += concretization();
    total += floating_point();
    total += big_numbers();
    total += change_varctx();
    total += strided_interval();
    total += value_set();

    // Return res
    std::cout << "\t" << total << "/" << total << green << "\t\tOK" << def << std::endl;
}
