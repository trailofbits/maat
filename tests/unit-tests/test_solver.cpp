#include "expression.hpp"
#include "solver.hpp"
#include "exception.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

namespace test
{
    namespace solver
    {
        using namespace maat;
        using namespace maat::solver;

        unsigned int _assert(bool val, const std::string& msg)
        {
            if( !val){
                std::cout << "\nFail: " << msg << std::endl; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int unsat_constraints(Solver& s)
        {
            unsigned int nb = 0;
            Expr e1, e2, e3, e4;
            e1 = exprvar(64, "var1");
            e2 = exprvar(64, "var2");
            e3 = exprvar(64, "var3");
            e4 = exprvar(64, "var4");
            
            s.reset();
            s.add(e1 == e2 && e2 == e3 && e3 == e4 && e1 != e4);
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add(e1 == exprcst(64, 1) && e2 == e1 && e2 != exprcst(64, 1));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add(e1 > exprcst(64, 3) && e2 == e1 && e2 < exprcst(64, -10));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add(e1 + e2 > e3 && e1 + e2 < e3);
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( e1 + exprcst(64, 2) < exprcst(64, 10) && ( e1 + exprcst(64, 4) > exprcst(64, 16)));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( e1 == exprcst(64, 0) && extract(e1, 15, 0) != exprcst(16, 0));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( shl(e1, e2) != exprcst(64, 0) );
            s.add( e2 >= exprcst(64, 64) );
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            
            s.reset();
            s.add( (exprcst(64, 0x8000) << e1) < (exprcst(64, 0x8000) >> e2 ) );
            s.add( e1 < exprcst(64, 8) && (e1 > exprcst(64, 0)));
            s.add( e2 < exprcst(64, 9) && (e2 > exprcst(64, 0)));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( ITE( e1, ITECond::LT, e1, exprcst(64,42), exprcst(64,1)) ==  42);
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( ITE( e1, ITECond::EQ, e2, exprcst(64,42), exprcst(64,1)) ==  42);
            s.add(e1 < e3);
            s.add(e3 <= e2);

            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");

            return nb;
        }

        unsigned int sat_constraints(Solver& s)
        {
            unsigned int nb = 0;
            std::shared_ptr<VarContext> model;
            Expr e1, e2, e3, e4;
            e1 = exprvar(32, "var1");
            e2 = exprvar(32, "var2");
            e3 = exprvar(32, "var3");
            e4 = exprvar(32, "var4");
            
            s.reset();
            s.add(e1 * e2 == exprcst(32, 0x78945));
            s.add(e1 - e3 == exprcst(32, 0x2));
            s.add(e3 > e4 );
            s.add(e3 / exprcst(32, 10) < e4);
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((e1*e2)->as_uint(*model) == 0x78945, "Solver: got wrong model ! "); 
            nb += _assert((e1-e3)->as_uint(*model) == 2, "Solver: got wrong model ! ");
            nb += _assert((e3)->as_int(*model) > e4->as_int(*model), "Solver: got wrong model ! ");
            nb += _assert((e3->as_int(*model))/10 < e4->as_int(*model), "Solver: got wrong model ! ");
            
            s.reset();
            s.add(e1 << e2 == exprcst(32, 0x789000));
            s.add(e2 >> e3 == exprcst(32, 11));
            s.add(e1 * e4 == exprcst(32, 0x789000));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((e1<<e2)->as_int(*model) == 0x789000, "Solver: got wrong model ! "); 
            nb += _assert((e2>>e3)->as_int(*model) == 11, "Solver: got wrong model ! ");
            nb += _assert((e1*e4)->as_int(*model) == 0x789000, "Solver: got wrong model ! ");

            /* Comment it because too slow
            s.reset();
            s.add(smulh(e1,e2) == exprcst(32, 0x1234));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((uint32_t)smulh(e1,e2)->concretize(model) == 0x1234, "Solver: got wrong model ! ");
            delete model; */
            
            s.reset();
            s.add(smod(e1,e2) == exprcst(32, -8));
            s.add((e2*e3) == exprcst(32, 10));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(smod(e1, e2)->as_int(*model) == -8, "Solver: got wrong model ! "); 
            nb += _assert((e3*e2)->as_int(*model) == 10 , "Solver: got wrong model ! ");
            
            s.reset();
            s.add(e1 == (e2^exprcst(32, 0x11010101))
            );
            s.add((e1 * exprcst(32, 8) ^ (e1 >> exprcst(32, 2))) == e3);
            s.add((e3 ^ exprcst(32, 0x10110001)) == exprcst(32, 0x853ea65f));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(e1->as_int(*model) == (e2^exprcst(32, 0x11010101))->as_int(*model), "Solver: got wrong model ! "); 
            nb += _assert((uint32_t)(e3^exprcst(32, 0x10110001))->as_int(*model) == 0x853ea65f , "Solver: got wrong model ! ");
            
            s.reset();
            s.add( ITE( e1, ITECond::EQ, e1, exprcst(64,42), exprcst(64,1)) ==  42);
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            
            s.reset();
            s.add( ITE( e1, ITECond::EQ, e2, exprcst(64,42), exprcst(64,1)) ==  42);
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(e1->as_int(*model) == e2->as_int(*model), "Solver: got wrong model ! "); 

            s.reset();
            s.add( ITE( e1, ITECond::LE, e2, exprcst(64,42), exprcst(64,1)) ==  42);
            s.add( e2 < e3 );
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(e1->as_uint(*model) <= e2->as_uint(*model), "Solver: got wrong model ! "); 
            nb += _assert(e2->as_uint(*model) < e3->as_uint(*model), "Solver: got wrong model ! "); 

            s.reset();
            s.add( ITE( e1, ITECond::LT, e2, exprcst(64,42), exprcst(64,1)) ==  42);
            s.add( e2 == e3 );
            s.add( e3 == 0xabcd );
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(e1->as_uint(*model) < e2->as_uint(*model), "Solver: got wrong model ! "); 
            nb += _assert(e2->as_uint(*model) == e3->as_uint(*model), "Solver: got wrong model ! "); 
            nb += _assert(e2->as_uint(*model) == 0xabcd, "Solver: got wrong model ! "); 

            return nb;
        }
    }
}

using namespace test::solver;
// All unit tests
void test_solver()
{
    unsigned int total = 0;
    std::string green = "\033[1;32m";
    std::string def = "\033[0m";
    std::string bold = "\033[1m";

#ifdef HAS_SOLVER_BACKEND
    std::cout   << bold << "[" << green << "+" 
                << def << bold << "]" << def 
                << " Testing solver interface... " << std::flush;

#ifdef Z3_BACKEND
    SolverZ3 solver_z3;
    total += sat_constraints(solver_z3);
    total += unsat_constraints(solver_z3);
#endif

    std::cout   << "\t" << total << "/" << total << green << "\t\tOK" 
                << def << std::endl;
#endif
}
