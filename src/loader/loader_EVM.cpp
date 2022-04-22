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
    Value address
)
{
    // Read file content
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size); // ASCII encoded
    std::vector<uint8_t> contents; // raw bytes
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

    // Create contract object
    engine->process->pid = get_ethereum(*engine)->add_contract(
        std::make_shared<Contract>(
            *engine,
            address
        )
    );
    
    // Write bytecode in memory
    env::EVM::_set_EVM_code(*engine, contents.data(), contents.size());
    // TODO: write constructor data after the bytecode
    engine->cpu.ctx().set(EVM::PC, 0x0);

    env::EVM::contract_t contract = get_contract_for_engine(*engine);
    contract->transaction = Transaction();

    // Execute init bytecode
    engine->run();

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
    engine->info.reset();
    engine->process->terminated = false;
}

} // namespace loader
} // namespace maat