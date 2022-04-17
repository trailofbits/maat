#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "maat/exception.hpp"
#include "maat/solver.hpp"
#include "maat/engine.hpp"
#include "maat/varcontext.hpp"
#include "maat/env/env_EVM.hpp"
#include <fstream>

using std::cout;
using std::endl; 
using std::string;

namespace test{
namespace adv_evm{
#ifdef MAAT_HAS_SOLVER_BACKEND        

using namespace maat;


unsigned int _assert(bool val, const string& msg)
{
    if( !val)
    {
        cout << "\nFail: " << msg << endl << std::flush; 
        throw test_exception();
    }
    return 1; 
}

int solve_symbolic_storage()
{
    int nb = 0;
    MaatEngine engine(Arch::Type::EVM);
    env::EVM::Contract contract(engine, Value(256, "123456"));
    Settings s;
    Value v;
    std::unique_ptr<solver::Solver> sol = solver::new_solver();

    // Read/write symbolic
    contract.storage.write(Value(exprvar(256, "a")), Value(256, 1), s);
    contract.storage.write(Value(exprvar(256, "b")), Value(256, 2), s);
    contract.storage.write(Value(exprvar(256, "c")), Value(256, 3), s);
    v = contract.storage.read(Value(exprvar(256, "d")));
    sol->reset();
    sol->add(v == 2);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    auto model = sol->get_model();
    nb += _assert(model->get_as_number("b").equal_to(model->get_as_number("d")), "Got wrong model when solving symbolic storage");
    nb += _assert(not model->get_as_number("c").equal_to(model->get_as_number("d")), "Got wrong model when solving symbolic storage");

    // Write concrete, read symbolic
    contract.storage.write(Value(256, 0xaaaa), Value(256, 5), s);
    contract.storage.write(Value(256, 0xbbbb), Value(256, 6), s);
    contract.storage.write(Value(256, 0xcccc), Value(256, 7), s);
    v = contract.storage.read(Value(exprvar(256, "d")));
    sol->reset();
    sol->add(v == 6);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    model = sol->get_model();
    nb += _assert(model->get_as_number("d").equal_to(Number(256, 0xbbbb)), "Got wrong model when solving symbolic storage");

    // Write symbolic, read concrete
    v = contract.storage.read(Value(256, 0xdedede));
    sol->reset();
    sol->add(v == 1);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    model = sol->get_model();
    nb += _assert(model->get_as_number("a").equal_to(Number(256, 0xdedede)), "Got wrong model when solving symbolic storage");
    nb += _assert(not model->get_as_number("b").equal_to(Number(256, 0xdedede)), "Got wrong model when solving symbolic storage");
    nb += _assert(not model->get_as_number("c").equal_to(Number(256, 0xdedede)), "Got wrong model when solving symbolic storage");

    // Overwrite symbolic address
    contract.storage.write(Value(exprvar(256, "a")), Value(256, 15), s);
    contract.storage.write(Value(exprvar(256, "a")), Value(256, 16), s);
    contract.storage.write(Value(exprvar(256, "b")), Value(256, 17), s);
    contract.storage.write(Value(exprvar(256, "a")), Value(256, 18), s);
    v = contract.storage.read(Value(exprvar(256, "a")));
    sol->reset();
    sol->add(v != 18);
    nb += _assert(not sol->check(), "Found model for unsolvable symbolic storage read");
    sol->reset();
    sol->add(v == 18);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");

    // Overwrite concrete address
    contract.storage.write(Value(256, 0x50), Value(256, 100), s);
    contract.storage.write(Value(256, 0x51), Value(256, 101), s);
    contract.storage.write(Value(256, 0x50), Value(256, 102), s);
    contract.storage.write(Value(256, 0x52), Value(256, 103), s);
    v = contract.storage.read(Value(exprvar(256, "blu")));
    sol->reset();
    sol->add(v == 100);
    nb += _assert(not sol->check(), "Found model for unsolvable symbolic storage read");
    sol->reset();
    sol->add(v == 102);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    model = sol->get_model();
    nb += _assert(model->get_as_number("blu").equal_to(Number(256, 0x50)), "Got wrong model when solving symbolic storage");

    return nb;
}

#endif // ifdef MAAT_HAS_SOLVER_BACKEND
    }
}

using namespace test::adv_evm;
 
void test_adv_evm()
{
#ifdef MAAT_HAS_SOLVER_BACKEND
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing Ethereum environement... " << std::flush;

    total += solve_symbolic_storage();

    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}