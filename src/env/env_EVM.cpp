#include "maat/env/env_EVM.hpp"

namespace maat{
namespace env{
namespace EVM{

EthereumEmulator::EthereumEmulator(): EnvEmulator(Arch::Type::EVM, OS::NONE)
{
    _init();
}

void EthereumEmulator::_init()
{
    EnvEmulator::_init(Arch::Type::NONE, OS::NONE);
}

uid_t EthereumEmulator::class_uid() const
{
    return serial::ClassId::ENV_ETHEREUM_EMULATOR;
}

void EthereumEmulator::dump(serial::Serializer& s) const
{
    // TODO 
}

void EthereumEmulator::load(serial::Deserializer& d)
{
   // TODO
}

} // namespace EVM
} // namespace env
} // namespace maat