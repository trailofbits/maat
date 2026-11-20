#include "python_bindings.hpp"

namespace maat::py
{
// Resolve optional event records on each access. Running the engine can replace
// them while Python code still holds a reference to the view.
struct RegView : InfoView
{
};
struct MemView : InfoView
{
};
struct BranchView : InfoView
{
};

template <class T> static T& present(std::optional<T>& value)
{
    if (!value)
        throw nb::attribute_error("Event information is unavailable");
    return *value;
}
static Value present(const Value& value)
{
    if (value.is_none())
        throw nb::attribute_error("Event value is unavailable");
    return value;
}

static std::string format_regview(RegView& v)
{
    std::ostringstream s;
    present(v.engine->info.reg_access).print(s, *v.engine->arch);
    return s.str();
}

static std::string format_memview(MemView& v)
{
    return format(present(v.engine->info.mem_access));
}

static std::string format_branchview(BranchView& v)
{
    return format(present(v.engine->info.branch));
}

static std::string format_infoview(InfoView& v)
{
    std::ostringstream s;
    v.engine->info.print(s, *v.engine->arch);
    return s.str();
}

void bind_info(nb::module_& m)
{
    nb::class_<RegView>(m, "_RegAccess", nb::is_final(), "Register access info")
        .def_prop_ro(
            "reg", [](RegView& v)
            { return v.engine->arch->reg_name(present(v.engine->info.reg_access).reg); },
            "Register being accessed")
        .def_prop_ro(
            "read", [](RegView& v) { return present(v.engine->info.reg_access).read; },
            "Is the register being read")
        .def_prop_ro(
            "written", [](RegView& v) { return present(v.engine->info.reg_access).written; },
            "Is the register being written")
        .def_prop_ro(
            "value", [](RegView& v) { return present(present(v.engine->info.reg_access).value); },
            "Current value of the register")
        .def_prop_ro(
            "new_value",
            [](RegView& v) { return present(present(v.engine->info.reg_access).new_value); },
            "Value that is written to the register")
        .def("__str__", &format_regview)
        .def("__repr__", &format_regview);
    nb::class_<MemView>(m, "_MemAccess", nb::is_final(), "Memory Access Info")
        .def_prop_ro(
            "addr", [](MemView& v) { return present(present(v.engine->info.mem_access).addr); },
            "Expression of the address where the memory is accessed")
        .def_prop_ro(
            "value", [](MemView& v) { return present(present(v.engine->info.mem_access).value); },
            "Value read/written from/to memory")
        .def_prop_ro(
            "read", [](MemView& v) { return present(v.engine->info.mem_access).read; },
            "Is the memory being read")
        .def_prop_ro(
            "written", [](MemView& v) { return present(v.engine->info.mem_access).written; },
            "Is the memory being written")
        .def_prop_ro(
            "size", [](MemView& v) { return present(v.engine->info.mem_access).size; },
            "Number of bytes accessed")
        .def("__str__", &format_memview)
        .def("__repr__", &format_memview);
    nb::class_<BranchView>(m, "_Branch", nb::is_final(), "Branch operation info")
        .def_prop_ro(
            "cond",
            [](BranchView& v)
            {
                auto cond = present(v.engine->info.branch).cond;
                if (!cond)
                    throw nb::attribute_error("No branch condition");
                return cond;
            },
            "Branch condition (if applicable)")
        .def_prop_ro(
            "target", [](BranchView& v) { return present(present(v.engine->info.branch).target); },
            "Target instruction if branch is taken")
        .def_prop_ro(
            "next", [](BranchView& v) { return present(present(v.engine->info.branch).next); },
            "Next instruction if branch is not taken")
        .def_prop_rw(
            "taken", [](BranchView& v) { return present(present(v.engine->info.branch).taken); },
            [](BranchView& v, nb::object taken)
            {
                present(v.engine->info.branch).taken =
                    taken.is_none() ? std::nullopt : std::optional<bool>(truth(taken));
            },
            nb::for_setter(nb::arg().none()), "Is the branch taken or not")
        .def("__str__", &format_branchview)
        .def("__repr__", &format_branchview);
    nb::class_<InfoView>(m, "Info", nb::is_final(), "Symbolic Engine Info")
        .def_prop_ro(
            "stop", [](InfoView& v) { return int(v.engine->info.stop); },
            "Reason why emulation stopped")
        .def_prop_rw(
            "addr", [](InfoView& v) { return present(v.engine->info.addr); },
            [](InfoView& v, addr_t addr) { v.engine->info.addr = addr; },
            "Address of the instruction where the engine stopped")
        .def_prop_ro(
            "exit_status", [](InfoView& v) { return present(v.engine->info.exit_status); },
            "Exit value of the program")
        .def_prop_ro(
            "branch",
            [](InfoView& v)
            {
                present(v.engine->info.branch);
                return BranchView{v};
            },
            nb::keep_alive<0, 1>(), "Branch operation info")
        .def_prop_ro(
            "reg_access",
            [](InfoView& v)
            {
                present(v.engine->info.reg_access);
                return RegView{v};
            },
            nb::keep_alive<0, 1>(), "Register access info")
        .def_prop_ro(
            "mem_access",
            [](InfoView& v)
            {
                present(v.engine->info.mem_access);
                return MemView{v};
            },
            nb::keep_alive<0, 1>(), "Memory access info")
        .def("__str__", &format_infoview)
        .def("__repr__", &format_infoview);
}
} // namespace maat::py
