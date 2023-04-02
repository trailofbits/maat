#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "maat/exception.hpp"
#include "maat/solver.hpp"
#include "maat/engine.hpp"
#include "maat/varcontext.hpp"
#include "maat/env/env_EVM.hpp"
#include "maat/event.hpp"
#include <fstream>

using std::cout;
using std::endl; 
using std::string;

namespace test{
namespace adv_evm{
#ifdef MAAT_HAS_SOLVER_BACKEND        

using namespace maat;
using namespace maat::event;

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
    contract.storage->write(Value(exprvar(256, "a")), Value(256, 1), s);
    contract.storage->write(Value(exprvar(256, "b")), Value(256, 2), s);
    contract.storage->write(Value(exprvar(256, "c")), Value(256, 3), s);
    v = contract.storage->read(Value(exprvar(256, "d")));
    sol->reset();
    sol->add(v == 2);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    auto model = sol->get_model();
    nb += _assert(not model->contains("a") or not model->get_as_number("a").equal_to(model->get_as_number("d")), "Got wrong model when solving symbolic storage a == d");
    nb += _assert(model->get_as_number("b").equal_to(model->get_as_number("d")), "Got wrong model when solving symbolic storage b != d");
    nb += _assert(not model->contains("c") or not model->get_as_number("c").equal_to(model->get_as_number("d")), "Got wrong model when solving symbolic storage c == d");

    // Write concrete, read symbolic
    contract.storage->write(Value(256, 0xaaaa), Value(256, 5), s);
    contract.storage->write(Value(256, 0xbbbb), Value(256, 6), s);
    contract.storage->write(Value(256, 0xcccc), Value(256, 7), s);
    v = contract.storage->read(Value(exprvar(256, "d")));
    sol->reset();
    sol->add(v == 6);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    model = sol->get_model();
    nb += _assert(model->get_as_number("d").equal_to(Number(256, 0xbbbb)), "Got wrong model when solving symbolic storage");

    // Write symbolic, read concrete
    v = contract.storage->read(Value(256, 0xdedede));
    sol->reset();
    sol->add(v == 1);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");
    model = sol->get_model();
    nb += _assert(model->get_as_number("a").equal_to(Number(256, 0xdedede)), "Got wrong model when solving symbolic storage");
    nb += _assert(not model->contains("b") or not model->get_as_number("b").equal_to(Number(256, 0xdedede)), "Got wrong model when solving symbolic storage");
    nb += _assert(not model->contains("c") or not model->get_as_number("c").equal_to(Number(256, 0xdedede)), "Got wrong model when solving symbolic storage");

    // Overwrite symbolic address
    contract.storage->write(Value(exprvar(256, "a")), Value(256, 15), s);
    contract.storage->write(Value(exprvar(256, "a")), Value(256, 16), s);
    contract.storage->write(Value(exprvar(256, "b")), Value(256, 17), s);
    contract.storage->write(Value(exprvar(256, "a")), Value(256, 18), s);
    v = contract.storage->read(Value(exprvar(256, "a")));
    sol->reset();
    sol->add(v != 18);
    nb += _assert(not sol->check(), "Found model for unsolvable symbolic storage read");
    sol->reset();
    sol->add(v == 18);
    nb += _assert(sol->check(), "Couldn't find model to solve symbolic storage read");

    // Overwrite concrete address
    contract.storage->write(Value(256, 0x50), Value(256, 100), s);
    contract.storage->write(Value(256, 0x51), Value(256, 101), s);
    contract.storage->write(Value(256, 0x50), Value(256, 102), s);
    contract.storage->write(Value(256, 0x52), Value(256, 103), s);
    v = contract.storage->read(Value(exprvar(256, "blu")));
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


int execute_simple_transaction()
{
    int nb = 0;
    MaatEngine engine(Arch::Type::EVM);
    // Manually encode input data to call update("lala..... ") in the contract
    std::string str_tx_data("3d7403a30000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003a226c616c616c616c616c616c616c616c616c616c616c616c616c6161616161616161616161616161616161616161616161616161616161616122000000000000");
    std::vector<char> hex_tx_data(str_tx_data.begin(), str_tx_data.end());
    std::vector<uint8_t> raw_tx_data = env::EVM::hex_string_to_bytes(hex_tx_data);
    std::vector<Value> tx_data;
    for (auto b : raw_tx_data)
        tx_data.push_back(Value(8, b));

    engine.load(
        "tests/resources/smart_contracts/HelloWorld.bin",
        loader::Format::NONE,
        0,
        {}, 
        {{"address","1234568"}, {"deployer","AAABBBCFF0000000000000454F"}}, 
        {}, {}, {}
    );
    
    // Send transaction
    env::EVM::get_contract_for_engine(engine)->transaction = env::EVM::Transaction(
        Value(160, 1), // origin
        Value(160, 1), // sender
        Number(160, 2), // recipient
        Value(256, 0), // value
        tx_data, // data
        Value(256, 50), // gas_price
        Value(256, 46546516351) // gas_limit
    );

    // Execute transaction
    engine.run();
    nb += _assert(
        engine.info.exit_status.has_value()
        and engine.info.exit_status->as_uint() == (int)env::EVM::TransactionResult::Type::STOP,
        "Transaction exited incorrectly"
    );
    return nb;
}

// Deploy a contract whose constructor takes arguments
int contract_with_constructor_arguments()
{
    int nb = 0;
    MaatEngine engine(Arch::Type::EVM);
    // 256 bits for both because values the ABI pads values to 32 bytes
    Value a(exprvar(256, "a")), b(exprcst(256, "-1"));
    // Arguments to constructor
    std::vector<loader::CmdlineArg> constructor_data
    {
        loader::CmdlineArg(a),
        loader::CmdlineArg(b) 
    };

    engine.load(
        "tests/resources/smart_contracts/SimpleConstructor.bin",
        loader::Format::NONE,
        0,
        constructor_data, // args 
        {{"address","1234568"}, {"deployer","AAABBBCFF0000000000000454F"}},
        {}, {}, {}
    );

    nb += _assert(
        engine.info.exit_status.has_value()
        and engine.info.exit_status->as_uint() == (int)env::EVM::TransactionResult::Type::RETURN,
        "Constructor exited incorrectly"
    );
    
    nb += _assert(
        env::EVM::get_contract_for_engine(engine)->storage->read(Value(256, 0)).expr()->eq(a.expr()),
        "Constructor failed to initialise contract state"
    );

    nb += _assert(
        env::EVM::get_contract_for_engine(engine)->storage->read(Value(256, 1)).as_number().equal_to(Number(248, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)),
        "Constructor failed to initialise contract state"
    );

    return nb;
}

// Explore all states without checking constraints at each branch
bool _explore_all_states_no_check(MaatEngine& engine)
{
    bool snapshot_next = true;
    // Path constraint callback
    EventCallback path_cb = EventCallback(
        [&snapshot_next](MaatEngine& engine, void* data)
        {
            if (snapshot_next)
            {
                engine.take_snapshot();
                engine.info.branch->taken = true;
            }
            else
                engine.info.branch->taken = false;
            snapshot_next = true;
            return Action::CONTINUE;
        }
    );

    // Set breakpoints and handlers
    engine.hooks.add(Event::PATH, When::BEFORE, EventCallback(path_cb), "path");

    // Do code coverage
    bool success = false;
    bool cont = true;
    engine.settings.record_path_constraints = true;
    solver::SolverZ3 sol;
    while (true)
    {
        engine.run();

        // Try to solve sqrt(x) == 4
        if (engine.info.exit_status->as_uint() == (int)env::EVM::TransactionResult::Type::RETURN)
        {
            sol.reset();
            const Value& result = env::EVM::get_contract_for_engine(engine)->transaction->result->return_data()[0]; 
            sol.add(result == 2);
            for (auto c : engine.path->get_related_constraints(result))
                sol.add(c);

            if (sol.check())
            {
                // Get new input
                auto model = sol.get_model();
                engine.vars->update_from(*model);
                success = true;
                break;
            }
        }

        // Else go back to previous snapshot and invert condition
        engine.restore_last_snapshot(true);
        snapshot_next = false;
    }
    return success;
}

int explore_sqrt()
{
    int nb = 0;
    MaatEngine engine(Arch::Type::EVM);
    // Manually encode input data to call sqrt() in the contract
    std::vector<Value> tx_data{
        Value(32, 0x677342ce), // sqrt(uint256)
        Value(exprvar(256, "input"))
    };

    engine.load(
        "tests/resources/smart_contracts/Sqrt.bin",
        loader::Format::NONE,
        0,
        {}, 
        {{"address","12345678"}, {"deployer","123456789"}},
        {}, {}, {}
    );

    // Send transaction
    env::EVM::get_contract_for_engine(engine)->transaction = env::EVM::Transaction(
        Value(160, 1), // origin
        Value(160, 1), // sender
        Number(160, 2), // recipient
        Value(256, 0), // value
        tx_data, // data
        Value(256, 50), // gas_price
        Value(256, 46546516351) // gas_limit
    );

    // Execute transaction and find input who's square root is 2
    _explore_all_states_no_check(engine);
    nb += _assert(
        engine.info.exit_status.has_value()
        and engine.info.exit_status->as_uint() == (int)env::EVM::TransactionResult::Type::RETURN,
        "Transaction exited incorrectly"
    );
    
    nb += _assert(
        Number(256, 4).lessequal_than(engine.vars->get_as_number("input")),
        "Found wrong model for sqrt"
    );

    nb += _assert(
        engine.vars->get_as_number("input").less_than(Number(256, 9)),
        "Found wrong model for sqrt"
    );

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
    total += execute_simple_transaction();
    total += contract_with_constructor_arguments();
    total += explore_sqrt();

    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}