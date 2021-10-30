#include "settings.hpp"

namespace maat
{

Settings::Settings():
    optimise_ir(false),
    force_simplify(true),
    ignore_missing_imports(false),
    ignore_missing_syscalls(false),
    record_path_constraints(true),
    symptr_read(true),
    symptr_write(true),
    symptr_assume_aligned(false),
    symptr_limit_range(false),
    symptr_max_range(0x200),
    symptr_refine_range(true),
    symptr_refine_timeout(10000), // in milliseconds
    log_insts(false),
    log_calls(false)
{}

std::string bool_to_string(bool val)
{
    return val ? "yes" : "no";
}

std::ostream& operator<<(std::ostream& os, const Settings& s)
{
    os << "optimise_ir: " << bool_to_string(s.optimise_ir) << "\n";
    os << "force_simplify: " << bool_to_string(s.force_simplify) << "\n";
    os << "ignore_missing_imports: " << bool_to_string(s.ignore_missing_imports) << "\n";
    os << "ignore_missing_syscalls: " << bool_to_string(s.ignore_missing_syscalls) << "\n";
    os << "record_path_constraints: " << bool_to_string(s.record_path_constraints) << "\n";
    os << "symptr_read: " << bool_to_string(s.symptr_read) << "\n";
    os << "symptr_write: " << bool_to_string(s.symptr_write) << "\n";
    os << "symptr_assume_aligned: " << bool_to_string(s.symptr_assume_aligned) << "\n";
    os << "symptr_limit_range: " << bool_to_string(s.symptr_limit_range) << "\n";
    os << "symptr_max_range: " << s.symptr_max_range << "\n";
    os << "symptr_refine_range: " << bool_to_string(s.symptr_refine_range) << "\n";
    os << "symptr_refine_timeout: " << std::dec << s.symptr_refine_timeout << " ms\n";
    os << "log_insts: " << bool_to_string(s.log_insts) << "\n";
    os << "log_calls: " << bool_to_string(s.log_calls) << "\n";
    return os;
}

} // namespace maat
