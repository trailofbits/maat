#include "python_bindings.hpp"

namespace maat::py
{
void bind_constants(nb::module_& m)
{
    auto type = nb::module_::import_("builtins").attr("type");
    auto define = [&](const char* name, std::initializer_list<std::pair<const char*, int>> members)
    {
        nb::dict values;
        for (auto [key, value] : members)
            values[key] = value;
        values["__module__"] = m.attr("__name__");
        m.attr(name) = type(name, nb::tuple(), values);
    };
    define("PERM", {
        {"R", static_cast<int>(maat::mem_flag_r)},
        {"W", static_cast<int>(maat::mem_flag_w)},
        {"X", static_cast<int>(maat::mem_flag_x)},
        {"RW", static_cast<int>(maat::mem_flag_rw)},
        {"RX", static_cast<int>(maat::mem_flag_rx)},
        {"WX", static_cast<int>(maat::mem_flag_wx)},
        {"RWX", static_cast<int>(maat::mem_flag_rwx)}});
    define("OS", {
        {"LINUX", static_cast<int>(env::OS::LINUX)},
        {"NONE", static_cast<int>(env::OS::NONE)}});
    define("ARCH", {
        {"X86", static_cast<int>(Arch::Type::X86)},
        {"X64", static_cast<int>(Arch::Type::X64)},
        {"EVM", static_cast<int>(Arch::Type::EVM)}});
    define("STOP", {
        {"HOOK", static_cast<int>(info::Stop::HOOK)},
        {"SYMBOLIC_PC", static_cast<int>(info::Stop::SYMBOLIC_PC)},
        {"SYMBOLIC_CODE", static_cast<int>(info::Stop::SYMBOLIC_CODE)},
        {"MISSING_FUNCTION", static_cast<int>(info::Stop::MISSING_FUNCTION)},
        {"MISSING_SYSCALL", static_cast<int>(info::Stop::MISSING_SYSCALL)},
        {"EXIT", static_cast<int>(info::Stop::EXIT)},
        {"INST_COUNT", static_cast<int>(info::Stop::INST_COUNT)},
        {"ILLEGAL_INST", static_cast<int>(info::Stop::ILLEGAL_INST)},
        {"UNSUPPORTED_INST", static_cast<int>(info::Stop::UNSUPPORTED_INST)},
        {"ARITHMETIC_ERROR", static_cast<int>(info::Stop::ARITHMETIC_ERROR)},
        {"ERROR", static_cast<int>(info::Stop::ERROR)},
        {"FATAL", static_cast<int>(info::Stop::FATAL)},
        {"NONE", static_cast<int>(info::Stop::NONE)}});
    define("BIN", {
        {"ELF32", static_cast<int>(loader::Format::ELF32)},
        {"ELF64", static_cast<int>(loader::Format::ELF64)}});
    define("TX_RES", {
        {"RETURN", static_cast<int>(env::EVM::TransactionResult::Type::RETURN)},
        {"REVERT", static_cast<int>(env::EVM::TransactionResult::Type::REVERT)},
        {"STOP", static_cast<int>(env::EVM::TransactionResult::Type::STOP)},
        {"INVALID", static_cast<int>(env::EVM::TransactionResult::Type::INVALID)},
        {"NONE", static_cast<int>(env::EVM::TransactionResult::Type::NONE)}});
    define("TX", {
        {"CALL", static_cast<int>(env::EVM::Transaction::Type::CALL)},
        {"CALLCODE", static_cast<int>(env::EVM::Transaction::Type::CALLCODE)},
        {"DELEGATECALL", static_cast<int>(env::EVM::Transaction::Type::DELEGATECALL)},
        {"STATICCALL", static_cast<int>(env::EVM::Transaction::Type::STATICCALL)},
        {"EOA", static_cast<int>(env::EVM::Transaction::Type::EOA)},
        {"NONE", static_cast<int>(env::EVM::Transaction::Type::NONE)},
        {"CREATE", static_cast<int>(env::EVM::Transaction::Type::CREATE)},
        {"CREATE2", static_cast<int>(env::EVM::Transaction::Type::CREATE2)}});
    define("EVENT", {
        {"EXEC", static_cast<int>(event::Event::EXEC)},
        {"BRANCH", static_cast<int>(event::Event::BRANCH)},
        {"MEM_R", static_cast<int>(event::Event::MEM_R)},
        {"MEM_W", static_cast<int>(event::Event::MEM_W)},
        {"MEM_RW", static_cast<int>(event::Event::MEM_RW)},
        {"PATH", static_cast<int>(event::Event::PATH)},
        {"REG_R", static_cast<int>(event::Event::REG_R)},
        {"REG_W", static_cast<int>(event::Event::REG_W)},
        {"REG_RW", static_cast<int>(event::Event::REG_RW)}});
    define("ACTION", {
        {"CONTINUE", static_cast<int>(event::Action::CONTINUE)},
        {"HALT", static_cast<int>(event::Action::HALT)},
        {"ERROR", static_cast<int>(event::Action::ERROR)}});
    define("WHEN", {
        {"BEFORE", static_cast<int>(event::When::BEFORE)},
        {"AFTER", static_cast<int>(event::When::AFTER)}});
}
} // namespace maat::py
