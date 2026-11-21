#include "python_bindings.hpp"

namespace maat::py
{
static void bool_setting(nb::class_<Settings>& cls, const char* name, bool Settings::* member,
                         const char* doc)
{
    cls.def_prop_rw(
        name, [member](Settings& s) { return s.*member; }, [member](Settings& s, nb::object input)
        { s.*member = truth(input); }, nb::for_setter(nb::arg().none()), doc);
}

void bind_settings(nb::module_& m)
{
    nb::class_<Settings> settings(m, "_Settings", nb::is_final(), "Engine settings and options");
    settings
        .def_prop_rw(
            "symptr_refine_timeout", [](const Settings& s) { return s.symptr_refine_timeout; },
            [](Settings& s, UnsignedSetting n) { s.symptr_refine_timeout = n.value; },
            "Maximum time to spend on symbolic pointer range refinement (in milliseconds, per "
            "pointer)")
        .def_prop_rw(
            "symptr_max_range", [](const Settings& s) { return s.symptr_max_range; },
            [](Settings& s, UnsignedSetting n) { s.symptr_max_range = n.value; },
            "Maximum range of possible values for symbolic pointers")
        .def("__repr__", &format<Settings>)
        .def("__str__", &format<Settings>);
    bool_setting(settings, "force_simplify", &Settings::force_simplify,
                 "Systematically simplify newly created symbolic expressions");
    bool_setting(settings, "symptr_read", &Settings::symptr_read,
                 "Allow reading from symbolic pointers");
    bool_setting(settings, "symptr_write", &Settings::symptr_write,
                 "Allow writing to symbolic pointers");
    bool_setting(settings, "ignore_missing_imports", &Settings::ignore_missing_imports,
                 "Ignore calls to functions that are neither loaded nor emulated");
    bool_setting(settings, "ignore_missing_syscalls", &Settings::ignore_missing_syscalls,
                 "Ignore syscalls that can not be emulated");
    bool_setting(settings, "record_path_constraints", &Settings::record_path_constraints,
                 "Record symbolic constraints associated with the current execution path");
    bool_setting(settings, "symptr_assume_aligned", &Settings::symptr_assume_aligned,
                 "Assume that symbolic pointers are aligned on the default "
                 "architecture address size");
    bool_setting(settings, "symptr_limit_range", &Settings::symptr_limit_range,
                 "Arbitrary limit the maximal range of symbolic pointers");
    bool_setting(settings, "symptr_refine_range", &Settings::symptr_refine_range,
                 "Refine the range of symbolic pointers using the SMT solver");
    bool_setting(settings, "log_insts", &Settings::log_insts, "Log every executed instruction");
    bool_setting(settings, "log_calls", &Settings::log_calls,
                 "Log calls to functions and system calls");
}
} // namespace maat::py
