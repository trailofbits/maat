#include "memory.hpp"
#include "engine.hpp"
#include "exception.hpp"
#include "solver.hpp"
#include "loader.hpp"
#include "varcontext.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>

using std::cout;
using std::endl; 
using std::string;
using std::strlen;

namespace test{
namespace solve_symbolic_ptr{

#if defined(HAS_SOLVER_BACKEND) and defined(HAS_LOADER_BACKEND)

        using namespace maat;
        using namespace maat::event;

        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }

        // Try to solve a simple symbolic pointer write
        unsigned int x86_symbolic_index_write()
        {
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86);
            Expr symarg = exprvar(32, "symarg");
            engine.vars->set("symarg", 1234);
            std::unique_ptr<solver::Solver> sol = solver::new_solver();

            engine.load(
                "tests/ressources/symbolic_ptr_binaries/sym_write_1",
                loader::Format::ELF32,
                0,
                {},
                {},
                "",
                {},
                {}
            );

            // Set EIP at beginning of func
            engine.cpu.ctx().set(X86::EIP, 0x52d);
            // Put argument at esp+4
            engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_uint() - 0x40);
            engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint() + 4, symarg);
            // Breakpoint at the end of func
            engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x588));

            // Run function until the end
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to run the target function ");

            // Check if there is a value for the index so that we write at the right address :)
            sol->reset();
            sol->add(engine.cpu.ctx().get(X86::EAX).as_expr() == 42);
            sol->add(0 <= symarg && symarg < 6);
            nb += _assert(sol->check(), "Couldn't find model to solve symbolic pointer");
            auto model = sol->get_model();

            nb += _assert(model->get("symarg") == 5, "Got wrong model when solving symbolic pointer");

            return nb;
        }


        // Try to solve a simple symbolic pointer write but by obtaining
        // the symbolic pointer using the atoi() function  
        unsigned int x86_symbolic_index_write_atoi()
        {
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86, env::OS::LINUX);
            std::unique_ptr<solver::Solver> sol = solver::new_solver();

            std::vector<loader::CmdlineArg> args = {loader::CmdlineArg(engine.vars->new_concolic_buffer("arg", "abcdefghijklm"))};
            engine.load(
                "tests/ressources/symbolic_ptr_binaries/sym_write_1",
                loader::Format::ELF32,
                0, 
                args, {},
                "", {}, {}
            );

            // Breakpoint at the end of func
            engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x588));
            // Take snapshot
            engine.take_snapshot();
            // Run function until the end
            engine.settings.symptr_limit_range = true;
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to run the target program ");

            // Check if there is a value for the index so that we write at the right address :)
            sol->reset();
            sol->add(engine.cpu.ctx().get(X86::EAX).as_expr() == 42);

            nb += _assert(sol->check(), "Couldn't find model to solve symbolic pointer");
            auto model = sol->get_model();
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_uint(*model) == 42, 
                "Re-evaluating result with new VarContext gives wrong value");

            // Try to restore model and run the program again with the solved solution
            engine.restore_last_snapshot();
            engine.vars->update_from(*model);

            // Re-run program
            engine.settings.symptr_refine_timeout = 0; // Don't loose time to refine symbolic accesses, we just want a concrete run
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to re-run the target program to check solution ");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_uint(*engine.vars) == 42, "Re-running program with the solution didn't produce the right result ");

            return nb;
        }


        // Solve a problem where the symbolic pointer is used to read an 
        // index to read in another array
        unsigned int x86_double_indirection()
        {
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86, env::OS::LINUX);
            engine.settings.symptr_refine_range = true;
            engine.settings.symptr_limit_range = true;
            engine.settings.symptr_max_range = 100;

            std::unique_ptr<solver::Solver> sol = solver::new_solver();

            std::vector<loader::CmdlineArg> args = {loader::CmdlineArg(engine.vars->new_concolic_buffer("argv1", "abcdefghijklm"))};
            engine.load(
                "tests/ressources/symbolic_ptr_binaries/sym_write_2",
                loader::Format::ELF32,
                0,
                args, {},
                "",
                {},
                {}
            );

            // Breakpoint at the end of func
            engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x593));
            // Take snapshot
            engine.take_snapshot();
            // Run function until the end
            engine.settings.record_path_constraints = true;
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to run the target program ");

            // Check if there is a value for the argument so that we return '1' (SUCCESS)
            sol->reset();
            for (auto& constraint : engine.path.constraints())
                sol->add(constraint);
            sol->add(engine.cpu.ctx().get(X86::EAX).as_expr() == 42);

            nb += _assert(sol->check(), "Couldn't find model to solve symbolic pointer");
            auto model = sol->get_model();
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_uint(*model) == 42,
                "Re-evaluating result with new VarContext gives wrong value");

            // Try to restore model and run the program again with the solved solution
            engine.restore_last_snapshot();
            engine.vars->update_from(*model);

            // Re-run program
            engine.settings.symptr_refine_range = false; // Don't loose time to refine symbolic accesses, we just want a concrete run
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to re-run the target program to check solution ");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_int(*engine.vars) == 42, "Re-running program with the solution didn't produce the right result ");

            return nb;
        }

        // Try to solve a simple symbolic pointer read
        unsigned int x86_symbolic_index_read()
        {
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86, env::OS::LINUX);
            Expr symarg = exprvar(32, "symarg");
            engine.vars->set("symarg", 1234);
            std::unique_ptr<solver::Solver> sol = solver::new_solver();
            engine.load(
                "tests/ressources/symbolic_ptr_binaries/sym_read_1",
                loader::Format::ELF32,
                0, {}, {}, "", {}, {}
            );
            
            // Set EIP at beginning of func
            engine.cpu.ctx().set(X86::EIP, exprcst(32, 0x52d));
            // Put argument at esp+4
            engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_expr() - 0x40);
            engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint() + 4, symarg);
            // Breakpoint at the end of func
            engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x57d));

            // Run function until the end
            engine.settings.symptr_limit_range = true;
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to run the target function ");

            // Check if there is a value for the index so that we write at the right address :)
            sol->reset();
            sol->add( engine.cpu.ctx().get(X86::EAX).as_expr() == 42);
            sol->add( symarg <= 6 && symarg >= 0);

            nb += _assert(sol->check(), "Couldn't find model to solve symbolic pointer");
            auto model = sol->get_model();
            nb += _assert(model->get("symarg") == 2, "Got wrong model when solving symbolic pointer");

            return nb;
        }

        // Try to solve a simple symbolic pointer read but by obtaining
        // the symbolic pointer using the atoi() function  
        unsigned int x86_symbolic_index_read_atoi(){
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86, env::OS::LINUX);

            engine.settings.symptr_limit_range = true;

            std::unique_ptr<solver::Solver> sol = solver::new_solver();
            std::vector<loader::CmdlineArg> args = {loader::CmdlineArg(engine.vars->new_concolic_buffer("arg", "abcdefghi"))};
            engine.load(
                "tests/ressources/symbolic_ptr_binaries/sym_read_1",
                loader::Format::ELF32,
                0,
                args, {}, "", {}, {}
            );

            // Breakpoint at the end of func
            engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x57d));
            // Take snapshot
            engine.take_snapshot();
            // Run function until the end
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to run the target program ");

            // Check if there is a value for the index so that we write at the right address :)
            sol->reset();
            sol->add( engine.cpu.ctx().get(X86::EAX).as_expr() == 42);

            nb += _assert(sol->check(), "Couldn't find model to solve symbolic pointer");
            auto model = sol->get_model();
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_uint(*model) == 42, 
                "Re-evaluating result with new VarContext gives wrong value");

            // Try to restore model and run the program again with the solved solution
            engine.restore_last_snapshot();
            engine.vars->update_from(*model);

            // Re-run program
            engine.settings.symptr_refine_timeout = 0; // Don't loose time to refine symbolic accesses, we just want a concrete run
            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to re-run the target program to check solution ");
            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_uint(*engine.vars) == 42, "Re-running program with the solution didn't produce the right result ");

            return nb;
        }

        unsigned int x86_symbolic_index_rw()
        {
            unsigned int nb = 0;
            MaatEngine engine = MaatEngine(Arch::Type::X86, env::OS::LINUX);
            Expr idx1 = exprvar(32, "idx1"), idx2 = exprvar(32, "idx2");
            engine.vars->set("idx1", 1);
            engine.vars->set("idx2", 19);

            auto sol = solver::new_solver();
            engine.load(
                "tests/ressources/symbolic_ptr_binaries/sym_rw_1",
                loader::Format::ELF32,
                0, {}, {}, "", {}, {}
            );

            // Set EIP at beginning of func
            engine.cpu.ctx().set(X86::EIP, exprcst(32, 0x52d));
            // Put argument at esp+4
            engine.cpu.ctx().set(X86::ESP, engine.cpu.ctx().get(X86::ESP).as_expr() - 0x40);
            engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint() + 4, idx2);
            engine.mem->write(engine.cpu.ctx().get(X86::ESP).as_uint() + 8, idx1);

            // Breakpoint at the end of func
            engine.hooks.add(Event::EXEC, When::BEFORE, "", AddrFilter(0x5cc));

            // Run function until the end
            engine.settings.symptr_refine_range = false;
            engine.settings.symptr_limit_range = true;

            engine.run();

            nb += _assert(engine.info.stop == info::Stop::HOOK, "Failed to run the target function ");

            // Check if there is a value for the index so that we write at the right address :)
            sol->reset();
            sol->add(engine.cpu.ctx().get(X86::EAX).as_expr() == 42);
            sol->add(idx1 >= 0);
            sol->add(idx2 >= 0);

            nb += _assert(sol->check(), "Couldn't find model to solve symbolic pointer");
            auto model = sol->get_model();
            engine.vars->update_from(*model);

            nb += _assert(engine.cpu.ctx().get(X86::EAX).as_uint(*engine.vars) == 42, "Got wrong model when solving symbolic pointer");
            nb += _assert(engine.vars->get("idx1")%10 == engine.vars->get("idx2")%10, "Got wrong model when solving symbolic pointer");

            return nb;
        }

#endif
    }
}

using namespace test::solve_symbolic_ptr; 
// All unit tests 
void test_solve_symbolic_ptr()
{
#if defined(HAS_SOLVER_BACKEND) && defined(HAS_LOADER_BACKEND) 
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    // Start testing
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing symbolic pointer solving... " << std::flush;
    total += x86_symbolic_index_write();
    total += x86_double_indirection();
    total += x86_symbolic_index_write_atoi();
    total += x86_symbolic_index_read();
    total += x86_symbolic_index_read_atoi();
    total += x86_symbolic_index_rw();
    // Return res
    cout << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}
