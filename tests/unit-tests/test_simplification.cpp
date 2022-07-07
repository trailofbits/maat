#include "maat/expression.hpp"
#include "maat/simplification.hpp"
#include "maat/exception.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

namespace test
{
    namespace simplification
    {        
        using namespace maat;

        unsigned int _assert_simplify(Expr e1, Expr e2, ExprSimplifier& simp)
        {
            Expr tmp1 = simp.simplify(e1);
            Expr tmp2 = simp.simplify(e2);
            if( tmp1->neq(tmp2) ){
                std::cout << "\nFail: _assert_simplify: " << e1 << " => " << e2 << "\n"
                << "Note: instead simplified into " << tmp1 << " => " << tmp2 << std::endl; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int basic(ExprSimplifier& s)
        {
            Expr e1 = exprvar(32,"varA");
            return 0;
        }
        
        unsigned int const_folding(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e1 = exprcst(32,-1), e2 =exprcst(32, 1048567);
            nb += _assert_simplify(exprcst(16,2)+exprcst(16,4), exprcst(16,6), s);
            nb += _assert_simplify(exprcst(4,3)*exprcst(4,7),  exprcst(4, 5), s);
            nb += _assert_simplify(exprcst(8,0xc3)/exprcst(8,0x40),  exprcst(8, 3), s);
            nb += _assert_simplify(exprcst(16, 321)/exprcst(16, 40), exprcst(16, 321U/40U), s);
            nb += _assert_simplify(sdiv(exprcst(16, 567),exprcst(16, 56)), exprcst(16, 567/56), s);
            nb += _assert_simplify(exprcst(16, 0x2)&exprcst(16, 0x1234), exprcst(16, 0x2&0x1234), s);
            nb += _assert_simplify(exprcst(16, 0x2)|exprcst(16, 0x1234), exprcst(16, 0x2|0x1234), s);
            nb += _assert_simplify(exprcst(16, 0x2)^exprcst(16, 0x1234), exprcst(16, 0x2^0x1234), s);
            nb += _assert_simplify(shl(exprcst(16, 1),exprcst(16, 4)), exprcst(16, 16), s);
            nb += _assert_simplify(shr(exprcst(16, 16),exprcst(16, 4)), exprcst(16, 1), s);
            nb += _assert_simplify(shl(exprcst(16, 1), exprcst(16, 16)), exprcst(16,0), s);
            
            nb += _assert_simplify(extract(exprcst(8, 20), 4, 2), exprcst(3, 5), s);
            nb += _assert_simplify(concat(exprcst(8, 1), exprcst(4, -1)), exprcst(12, 0x1f), s);
            
            nb += _assert_simplify(-exprcst(7,3),  exprcst(7, -3), s);
            nb += _assert_simplify(~exprcst(7,3),  exprcst(7, ~3), s);
            
            nb += _assert_simplify(e2+e1-e1, e2, s);

            return nb; 
        }

        unsigned int neutral_elems(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            nb += _assert_simplify(exprvar(32,"var1")+exprcst(32, 0), exprvar(32, "var1"), s);
            nb += _assert_simplify(exprvar(32,"var1")*exprcst(32, 1), exprvar(32, "var1"), s);
            nb += _assert_simplify(exprvar(32,"var1")/exprcst(32, 1), exprvar(32, "var1"), s);
            nb += _assert_simplify(sdiv(exprvar(32,"var1"),exprcst(32, 1)), exprvar(32, "var1"), s);
            nb += _assert_simplify(exprvar(7,"var1")&exprcst(7, 0b1111111), exprvar(7, "var1"), s);
            nb += _assert_simplify(exprvar(6,"var1")|exprcst(6, 0), exprvar(6, "var1"), s);
            nb += _assert_simplify(exprvar(32,"var1")^exprcst(32, 0), exprvar(32, "var1"), s);
            nb += _assert_simplify(extract(exprvar(32,"var1"), 31, 0), exprvar(32, "var1"), s);
            return nb; 
        }
        
        unsigned int absorbing_elems(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            nb += _assert_simplify(exprvar(33,"var1")*exprcst(33,0), exprcst(33,0), s);
            nb += _assert_simplify(exprvar(6, "var1")|exprcst(6,0b111111), exprcst(6,0b111111), s);
            nb += _assert_simplify(exprvar(5,"var1")&exprcst(5,0), exprcst(5,0), s);
            nb += _assert_simplify(shl(exprvar(32,"var1"),exprcst(32, 50)), exprcst(32,0), s);
            nb += _assert_simplify(shr(exprvar(32,"var1"),exprcst(32, 32)), exprcst(32,0), s);
            return nb; 
        }
        
        unsigned int arithmetic_properties(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr    e1 = exprvar(64, "var1"),
                    e2 = exprvar(64, "var2"),
                    e3 = exprvar(64, "var3"),
                    e4 = e1/e2,
                    c1 = exprcst(64, 1);
            nb += _assert_simplify( e1+(e1*e2), (e2+c1)*e1, s);
            nb += _assert_simplify( (e2*e1)+e1, (e2+c1)*e1, s);
            nb += _assert_simplify( (e1*e2)-e1, (e2-c1)*e1, s);
            nb += _assert_simplify( (e2*e1)-e1, (e2-c1)*e1, s);
            nb += _assert_simplify( (e1*e3)+(e2*e3), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e3*e1)+(e2*e3), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e1*e3)+(e3*e2), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e3*e1)+(e3*e2), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e4+(e4*e3)), (e3+c1)*e4, s);
            nb += _assert_simplify( (e4+(e3*e4)), (e3+c1)*e4, s);
            nb += _assert_simplify( (-e4+(e4*e3)), (e3-c1)*e4, s);
            nb += _assert_simplify( (-e4+(e3*e4)), (e3-c1)*e4, s);
            nb += _assert_simplify( (e4+e4) , e4*exprcst(64, 2), s); 
            nb += _assert_simplify( e4-e4, exprcst(64,0), s);
            nb += _assert_simplify( -e3+e3, exprcst(64,0), s);
            return nb; 
        }
        
        unsigned int involution(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            nb += _assert_simplify( -(-exprvar(64, "var1")), exprvar(64, "var1"), s);
            nb += _assert_simplify( ~~exprvar(64, "var1"), exprvar(64, "var1"), s);
            return nb; 
        }
        
        unsigned int extract_patterns(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e1 = exprvar(32,"var1"), e2 = exprvar(14, "var2"); 
            Expr e = concat(e1, e2);
            Expr e3 = concat(exprvar(8, "varD"), concat(exprvar(8, "varC"),  concat(exprvar(8, "varB"), exprvar(8, "varA")))); 
            nb += _assert_simplify(extract(e, 45, 40), extract(e1, 31, 26), s);
            nb += _assert_simplify(extract(e, 8, 1), extract(e2, 8, 1), s);
            nb += _assert_simplify(extract(extract(e1, 28,10),8,1), extract(e1, 18,11), s);
            nb += _assert_simplify(extract(extract(exprcst(64,0xffffff), 31,0),10,10), 
                                   extract(exprcst(64,0xffffff), 10,10), s);
            nb += _assert_simplify(extract(e3, 31, 24), (exprvar(8, "varD")), s);
            nb += _assert_simplify(extract(e3, 7, 0), (exprvar(8, "varA")), s);
            return nb; 
        }
        
        unsigned int basic_transform(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e1 = exprvar(56, "var1");
            Expr e2 = exprmem(56, e1); 
            nb += _assert_simplify(shl(e1, exprcst(56, 3)), e1*exprcst(56, 8), s);
            nb += _assert_simplify(shr(e1, exprcst(56, 4)), e1/exprcst(56, 16), s);
            nb += _assert_simplify(exprcst(56, -1)*e1, -e1, s);
            nb += _assert_simplify((~e1)+exprcst(56,1), -e1, s);
            nb += _assert_simplify((~(-e1))+exprcst(56,1), e1, s);
            nb += _assert_simplify(e1*(-e2), -(e2*e1), s);
            nb += _assert_simplify((-e1)*e2, -(e2*e1), s);
            return nb; 
        }
        
        unsigned int logical_properties(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e = exprvar(64, "var1");
            Expr e2 = exprvar(64, "var2");
            nb += _assert_simplify(e&e, e, s);
            nb += _assert_simplify(e|e, e, s);
            nb += _assert_simplify(e&(~e), exprcst(64,0), s);
            nb += _assert_simplify((~e)&e, exprcst(64,0), s);
            nb += _assert_simplify((~e)^e, exprcst(64,-1), s);
            nb += _assert_simplify(e^(~e), exprcst(64,-1), s);
            nb += _assert_simplify((~e)|e, exprcst(64,-1), s);
            nb += _assert_simplify(e|(~e), exprcst(64,-1), s);
            nb += _assert_simplify(e^e, exprcst(64,0), s);
            return nb;
        }

        unsigned int concat_patterns(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e = exprvar(64, "var1"),
                 e2 = exprvar(64, "var2");
            Expr    v1 = exprvar(8, "a"),
                    v2 = exprvar(8, "b"),
                    c1 = exprcst(24, 0x100c3);
            Expr e1 = concat(v1, c1);
            nb += _assert_simplify(concat(extract(e, 63,10), extract(e,9,0)), e, s);
            nb += _assert_simplify(extract( concat(extract(e1, 31, 8), extract(e1, 7, 0)>>6), 7, 0) - 3,   (extract(e1, 7, 0)>>6)-3, s);
            
            e1 = exprcst(32, 0x00ffffff) & concat(v1, c1);
            nb += _assert_simplify(e1, concat(exprcst(8, 0), c1), s);
            
            e1 = exprcst(32, 0xff000000) & concat(v1, c1);
            nb += _assert_simplify(e1, concat(v1, exprcst(24, 0)), s);

            e1 = exprcst(64, 0xffffffff) & concat(exprvar(32, "blabla"), exprcst(32, 0));
            nb += _assert_simplify(e1, exprcst(64, 0), s);

            e1 = exprcst(64, 0xffffffff00000000) & concat(exprcst(32, 0), exprvar(32, "blu"));
            nb += _assert_simplify(e1, exprcst(64, 0), s);

            e1 = concat(exprcst(32, 0), ITE(v1, ITECond::EQ, v2, e, e2));
            nb += _assert_simplify(
                e1, ITE(
                        v1, ITECond::EQ, v2, 
                        concat(exprcst(32, 0),e),
                        concat(exprcst(32, 0),e2)
                    ),
                s
            );

            e1 = concat(e, e2) >> 64;
            nb += _assert_simplify(e1, concat(exprcst(64, 0), e), s);
            return nb; 
        }
        
        unsigned int basic_ite_condition(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e1 = exprvar(64, "var1"), e2 = exprvar(64, "var2"), e3 = exprvar(64, "var3");
            Expr    v1 = exprvar(8, "a"),
                    c1 = exprcst(24, 0x100c3), 
                    c2 = exprcst(24, 0xff000);
            
            nb += _assert_simplify(ITE(e1, ITECond::EQ, e1, e2, e3), e2, s);
            nb += _assert_simplify(ITE(e1, ITECond::LE, e1, e2, e3), e2, s);

            nb += _assert_simplify(ITE(c1, ITECond::EQ, c1, e2, e3), e2, s);
            nb += _assert_simplify(ITE(c1, ITECond::LE, c1, e2, e3), e2, s);
            nb += _assert_simplify(ITE(c1, ITECond::LT, c1, e2, e3), e3, s);
            nb += _assert_simplify(ITE(c1, ITECond::LE, c2, e2, e3), e2, s);
            nb += _assert_simplify(ITE(c1, ITECond::LT, c2, e2, e3), e2, s);
            
            nb += _assert_simplify(ITE(c2, ITECond::EQ, c1, e2, e3), e3, s);
            nb += _assert_simplify(ITE(c2, ITECond::LE, c1, e2, e3), e3, s);
            nb += _assert_simplify(ITE(c2, ITECond::LT, c1, e2, e3), e3, s);

            return nb; 
        }

        unsigned int ite_patterns(ExprSimplifier& s)
        {
            unsigned int nb = 0;
            Expr e1 = exprvar(32, "var1"), e2 = exprvar(32, "var2"), e3 = exprvar(32, "var3");
            Expr    zero = exprcst(32, 0), 
                    one = exprcst(32, 1);
            
            Expr e = ITE(
                zero,
                ITECond::EQ,
                ITE(e1, ITECond::LT, e2, zero, one),
                e1, e2
            );
            nb += _assert_simplify(
                e,
                ITE(e1, ITECond::LT, e2, e1, e2),
                s
            );

            return nb; 
        }
        
        unsigned int advanced(ExprSimplifier& s)
        {
            unsigned int nb = 0; 
            Expr    e1 = exprvar(32,"varA"),
                    e2 = exprvar(32,"varB"),
                    e3 = exprcst(32, -1), 
                    e4 = exprcst(32, 0xffff7),
                    e5 = e3+e4, 
                    e6 = e4/e1,
                    e7 = shr(e5,exprcst(32, 1)),
                    e8 = exprmem(32, e3),
                    e9 = concat(extract(e1, 31, 16), extract(e4, 15, 0));
            
            Expr v1 = exprvar(8, "var1"), v2 = exprvar(8, "var2");
            Expr e10 = concat(v1, concat(v1, concat(v1, concat(v1, concat(v1, concat(v1, concat(v1, v2))))))); 
            e10 = ITE(extract(e10, 7, 0), ITECond::EQ, exprcst(8, 0), e1, e2);
            Expr e10_simp = ITE(v2, ITECond::EQ, exprcst(8, 0), e1, e2);
            
            nb += _assert_simplify(((e1-e2)*e6)^e8, e8^((e1-e2+e2-e2)*(e6&e6)), s);
            nb += _assert_simplify(e1+e2+e3-e1+e4-e2-e3, e4, s);
            nb += _assert_simplify(e3*e4, exprcst(32, 0xfffffffffff00009), s);
            nb += _assert_simplify(e4*e4, exprcst(32, 0xfffee00051), s);
            nb += _assert_simplify(exprcst(32, 0xfffee00051)*e3, exprcst(32, 0xffffff00011fffaf), s);
            nb += _assert_simplify(e4*(e3-e3+e4)*e3, e4*e3*e4, s);
            nb += _assert_simplify(e3*e4*(e1+e2+e3-e1+e4-e2-e3), e4*e4*e3, s);
            nb += _assert_simplify(e2/(e1+e1-e1), e2/e1, s);
            nb += _assert_simplify(e8, e8+e5-e5, s);
            nb += _assert_simplify((e6/e1/e8), (e6/(e8+e5-e5)/e1), s);
            nb += _assert_simplify((e6/e7/e8), (e6/(e8+e5-e5)/e7), s);
            nb += _assert_simplify(e9|e9, e9, s);
            nb += _assert_simplify((e2&(~e1))&e1, exprcst(32,0), s);
            nb += _assert_simplify(e10, e10_simp, s);
            //nb += _assert_simplify(extract(e8^(e9^~e8), 31, 0), e8&(-e6+(e9|e9)+e6) , s);
            /*nb += _assert_simplify(, , s);
            nb += _assert_simplify(, , s);
            nb += _assert_simplify(, , s);
            nb += _assert_simplify(, , s);*/
            //nb += _assert_simplify(, , s);
            return nb; 
        }
    }
}

using namespace test::simplification;
// All unit tests 
void test_simplification(){
    ExprSimplifier simp = ExprSimplifier();
    simp.add(es_constant_folding);
    simp.add(es_neutral_elements);
    simp.add(es_absorbing_elements);
    simp.add(es_arithmetic_properties);
    simp.add(es_involution);
    simp.add(es_extract_patterns);
    simp.add(es_basic_transform);
    simp.add(es_logical_properties);
    simp.add(es_concat_patterns);
    simp.add(es_arithmetic_factorize);
    simp.add(es_basic_ite);
    simp.add(es_ite_patterns);
    //simp.add(es_generic_distribute);
    simp.add(es_generic_factorize);
    simp.add(es_deep_associative);
    
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing simplification module... " << std::flush;

    total += basic(simp);
    total += const_folding(simp);
    total += neutral_elems(simp);
    total += absorbing_elems(simp);
    total += arithmetic_properties(simp);
    total += involution(simp);
    total += extract_patterns(simp);
    total += basic_transform(simp);
    total += logical_properties(simp);
    total += concat_patterns(simp);
    total += basic_ite_condition(simp);
    total += ite_patterns(simp);
    total += advanced(simp);

    std::cout   << "\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
}
