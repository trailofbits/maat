#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "maat/exception.hpp"
#include "maat/expression.hpp"
#include "maat/solver.hpp"
#include "maat/engine.hpp"
#include "maat/varcontext.hpp"
#include <fstream>

using std::cout;
using std::endl; 
using std::string;

namespace test{
namespace adv_serialization{
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

class StateManager
{
private:
    static std::string states_dir;
    static std::string base_name;
    int state_cnt;
    std::queue<std::string> pending_states;
public:
    StateManager(): state_cnt(0){}
    void store_state(MaatEngine& engine)
    {
        std::string filename = states_dir + base_name + std::to_string(state_cnt++);
        std::ofstream out(filename, std::ios_base::binary);
        Serializer s(out);
        s.serialize(engine);
        out.close();
        pending_states.push(filename);
    }

    bool load_next_state(MaatEngine& engine)
    {
        if (empty())
            return false;

        std::string filename = pending_states.front();
        pending_states.pop();

        std::ifstream in(filename, std::ios_base::binary);
        Deserializer d(in);
        d.deserialize(engine);
        in.close();
        std::cout << "DEBUG loaded engine hooks: \n" << engine.hooks;
        return true;
    }

    bool empty() const 
    {
        return pending_states.empty();
    }
};

std::string StateManager::states_dir = "./";
std::string StateManager::base_name = "_maat_state";

StateManager state_manager;

// Path constraint callback
static bool snapshot_next = true;
EventCallback path_cb = EventCallback(
    [](MaatEngine& engine)
    {
        std::shared_ptr<VarContext> model;
        if (snapshot_next)
        {
            solver::SolverZ3 sol;
            // Find model that inverts that branch
            for (auto c : engine.path.constraints())
            {
                sol.add(c);
            }
            _assert(engine.info.branch->taken.has_value(), "do_code_coverage_serialization(): got invalid branch info on path constraint breakpoint");
            if (*engine.info.branch->taken)
                sol.add(engine.info.branch->cond->invert());
            else
                sol.add(engine.info.branch->cond);
            if (sol.check())
            {
                // Get new input
                model = sol.get_model();
                // Serialize current branch
                state_manager.store_state(engine);
                // Update context and explore the other branch
                engine.vars->update_from(*model);
            }
        }
        snapshot_next = true;
        return Action::CONTINUE;
    }
);

// Code coverage with BFS algorithm using deserialization
// Return engine state that finds the correct password or nullptr on failure
bool do_code_coverage_serialization(MaatEngine& engine, addr_t start, addr_t end)
{
    // Set EIP at starting point
    engine.cpu.ctx().set(X86::EIP, start);

    // Do code coverage
    bool success = false;
    bool cont = true;
    engine.settings.record_path_constraints = true;
    
    // Set hooks
    engine.hooks.add(Event::EXEC, When::BEFORE, "end", AddrFilter(end));
    engine.hooks.add(Event::PATH, When::BEFORE, EventCallback(path_cb), "path");

    while (engine.run() == info::Stop::HOOK)
    {
        solver::SolverZ3 sol;
        // First try to find a model for EAX == 1
        for (auto c : engine.path.constraints())
            sol.add(c);
        sol.add(engine.cpu.ctx().get(X86::EAX).as_expr() != 0);
        if (sol.check())
        {
            success = true;
            auto model = sol.get_model();
            // Update context and continue from here with new values
            engine.vars->update_from(*model);
            return true; // Success
        }
        else
        {
            // Pull new state
            if (not state_manager.load_next_state(engine))
                break;
            snapshot_next = false; // Don't retake a snapshot on branch where we forked
        }
    }
    return false; // Failure
}

unsigned int plaintext_pwd()
{
    unsigned int nb = 0;
    MaatEngine engine(Arch::Type::X86);
    engine.log.set_level(Log::ERROR);
    engine.mem->map(0x0, 0xfff, maat::mem_flag_rwx, "code");
    engine.mem->map(0x4000, 0x5fff, maat::mem_flag_rw, "stack"); // stack
    engine.cpu.ctx().set(X86::ESP, 0x5000);
    engine.mem->write(0x5004, 0x6000, 4); // argument of the function pushed on the stack
    engine.cpu.ctx().set(X86::EAX, 0x6000);
    engine.mem->map(0x6000, 0x6100, maat::mem_flag_rw, "input_password"); // The input password

    // Make user supplied password symbolic
    engine.mem->write(0x6000, exprvar(8, "char0"));
    engine.mem->write(0x6001, exprvar(8, "char1"));
    engine.mem->write(0x6002, exprvar(8, "char2"));
    engine.mem->write(0x6003, exprvar(8, "char3"));
    engine.mem->write(0x6004, exprvar(8, "char4"));
    // First try to run
    std::string initial_try = "araca";
    engine.vars->set("char0", initial_try[0]);
    engine.vars->set("char1", initial_try[1]);
    engine.vars->set("char2", initial_try[2]);
    engine.vars->set("char3", initial_try[3]);
    engine.vars->set("char4", initial_try[4]);

    // Write the code of the function in memory
    // map function at address 0x4ed
    std::string file1_path("tests/resources/plaintext_pwd/check.bin");
    std::ifstream file(file1_path, std::ios::binary | std::ios::ate);
    if (not file.is_open())
    {
        cout << "Failed to open file " << file1_path;
        throw test_exception();
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if( ! file.read(buffer.data(), size)){
        cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
        throw test_exception();
    }
    engine.mem->write_buffer(0x4ed, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);

    // Do code coverage
    bool success = do_code_coverage_serialization(engine, 0x4ed, 0x568);

    nb += _assert(success, "plaintext_pwd(): failed to find the correct input");
    nb += _assert((char)engine.vars->get("char0") == 't', "plaintext_pwd(): failed to find the correct input");
    nb += _assert((char)engine.vars->get("char1") == 'r', "plaintext_pwd(): failed to find the correct input");
    nb += _assert((char)engine.vars->get("char2") == 'u', "plaintext_pwd(): failed to find the correct input");
    nb += _assert((char)engine.vars->get("char3") == 'c', "plaintext_pwd(): failed to find the correct input");
    nb += _assert((char)engine.vars->get("char4") == 0, "plaintext_pwd(): failed to find the correct input");

    return nb;
}

#endif // ifdef MAAT_HAS_SOLVER_BACKEND
}
}

using namespace test::adv_serialization;
// All unit tests 
void test_adv_serialization()
{
#ifdef MAAT_HAS_SOLVER_BACKEND
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing serialization... " << std::flush;
    total += plaintext_pwd();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}