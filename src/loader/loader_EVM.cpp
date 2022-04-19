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
        for(int i = 0; i < size; i+=2)
        {
            uint8_t val = std::stoul(std::string(buffer.data()+i, 2), nullptr, 16);
            contents.push_back(val);
        }
    }

    // Create contract object
    engine->process->pid = get_ethereum(*engine)->add_contract(
        std::make_shared<Contract>(
            *engine,
            address
        )
    );
    
    // Write bytecode in memory AFTER creating contract
    env::EVM::_set_EVM_code(*engine, contents.data(), contents.size());
    engine->cpu.ctx().set(EVM::PC, 0x0);
    
    env::EVM::contract_t contract = get_contract_for_engine(*engine);
    contract->transaction = Transaction();


    // Execute init bytecode
    engine->run();

    // Setup proper runtime byte-code
    std::vector<Value>& return_data = contract->transaction->return_data;
    // Erase previous code
    engine->mem->write_buffer(0x0, std::vector<uint8_t>(contents.size(), 0x0).data(), contents.size());
    // Write new one
    env::EVM::_set_EVM_code(*engine, return_data);

    // Reset transaction
    contract->transaction = std::nullopt;

    // Reset PC at zero
    engine->cpu.ctx().set(EVM::PC, 0x0);
}

} // namespace loader
} // namespace maat