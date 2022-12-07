#include "maat/loader.hpp"
#include "maat/env/env_EVM.hpp"
#include "maat/engine.hpp"
#include <fstream>
#include <vector>

namespace maat{
namespace loader{

using namespace env::EVM;

void LoaderEVM::load(
    MaatEngine* engine,
    const std::string& filename,
    const std::vector<CmdlineArg>& args,
    const environ_t& env
){
    std::vector<uint8_t> contents; // raw init bytecode

    // Parse deployment info
    if (env.find("address") == env.end())
        throw loader_exception(
            "LoaderEVM::load() : Please specify contract deployment address." 
            " Use the 'address' key in the environment"
        );
    if (env.find("deployer") == env.end())
        throw loader_exception(
            "LoaderEVM::load() : Please specify the deployer address." 
            " Use the 'deployer' key in the environment"
        );
    Value address(160, env.at("address"), 16);
    Value deployer(160, env.at("deployer"), 16);
    bool run_init_bytecode = (env.find("no_run_init_bytecode") == env.end());

    // If no file was specified, we don't load the bytecode from a file,
    // and assume it is included in the args array !
    if (not filename.empty())
    {
        // Read file content
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> buffer(size); // ASCII encoded
        file.read(buffer.data(), size);

        if (not file.good())
        {
            throw env_exception(
                Fmt() << "Error reading contents of '" << filename << "'"
                >> Fmt::to_str
            );
        }
        else
        {
            // Convert ASCII encoded bytes to real bytes
            contents = env::EVM::hex_string_to_bytes(buffer);
        }
    }

    // Create contract object
    engine->process->pid = get_ethereum(*engine)->add_contract(
        std::make_shared<Contract>(
            *engine,
            address
        )
    );
    
    // Write bytecode in memory
    env::EVM::_set_EVM_code(*engine, contents.data(), contents.size());

    // Write constructor data after the bytecode
    for (auto arg : args)
    {
        if (arg.is_concrete())
            env::EVM::_append_EVM_code(
                *engine,
                (uint8_t*)arg.string().data(),
                arg.len()
            );
        else
            env::EVM::_append_EVM_code(*engine, arg.buffer());
    }

    // Reset PC to zero
    engine->cpu.ctx().set(EVM::PC, 0x0);

    env::EVM::contract_t contract = get_contract_for_engine(*engine);
    contract->transaction = env::EVM::Transaction(
        deployer, // origin
        deployer, // sender
        address.as_number(), // recipient
        Value(256, 0), // value
        {}, // data (for deployment, args are appended after the bytecode)
        Value(256, 50), // gas_price
        Value(256, 123456) // gas_limit
    );

    // Users can prevent Maat from automatically running the init bytecode by
    // specifying "no_run_init_bytecode" in the envp parameter
    if (run_init_bytecode)
    {
        // Execute init bytecode
        engine->run();
        // Check that the transaction returned properly
        if (not contract->transaction->result.has_value())
        {
            throw loader_exception("LoaderEVM::load(): init code didn't return any result");
        }

        // Setup proper runtime byte-code
        const std::vector<Value>& return_data = contract->transaction->result->return_data();
        // Erase previous code
        engine->mem->write_buffer(0x0, std::vector<uint8_t>(contents.size(), 0x0).data(), contents.size());
        // Write new one
        env::EVM::_set_EVM_code(*engine, return_data);

        // Reset transaction
        contract->transaction = std::nullopt;

        // Reset memory
        // TODO(boyan)

        // Reset PC at zero
        engine->cpu.ctx().set(EVM::PC, 0x0);
        engine->process->terminated = false;
    }
}

} // namespace loader
} // namespace maat