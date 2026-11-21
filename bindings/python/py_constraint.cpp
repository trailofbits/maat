#include "python_bindings.hpp"

// These overloads raise ValueError for all-integer operands.
// Their uninhabited return type identifies them as error paths to stub generation.
namespace maat::py
{
struct InvalidOperands
{
    InvalidOperands() = delete;
};
} // namespace maat::py
namespace nanobind::detail
{
template <> struct type_caster<maat::py::InvalidOperands>
{
    static constexpr auto Name = const_name("typing.Never");
    static handle from_cpp(const maat::py::InvalidOperands&, rv_policy, cleanup_list*)
    {
        std::terminate();
    }
};
} // namespace nanobind::detail
namespace maat::py
{
void bind_constraints(nb::module_& m)
{
    nb::class_<ConstraintObject>(m, "Constraint", nb::is_final(),
                                 "Constraint on abstract expressions")
        .def("invert", &ConstraintObject::invert, "Returns the invert of the condition")
        .def(
            "contained_vars",
            [](ConstraintObject& c)
            {
                auto& vars = c.contained_vars();
                return std::vector<std::string>(vars.begin(), vars.end());
            },
            "Returns a list of involved symbolic variables")
        .def("__repr__", [](Constraint c) { return format(c); })
        .def("__str__", [](Constraint c) { return format(c); })
        .def("__and__", [](Constraint l, Constraint r) { return l && r; })
        .def("__rand__", [](Constraint l, Constraint r) { return r && l; })
        .def("__or__", [](Constraint l, Constraint r) { return l || r; })
        .def("__ror__", [](Constraint l, Constraint r) { return r || l; })
        .def("__invert__", [](Constraint c) { return c->invert(); });
    m.def(
        "ULE", [](nb::int_, nb::int_) -> InvalidOperands
        { throw nb::value_error("Expected at least one Value"); },
        "Unsigned less-equal constraint on abstract values");
    m.def(
        "ULE", [](const Value& l, const Value& r) { return ULE(l.as_expr(), r.as_expr()); },
        "Unsigned less-equal constraint on abstract values");
    m.def(
        "ULE", [](const Value& l, cst_t r) { return ULE(l.as_expr(), r); },
        "Unsigned less-equal constraint on abstract values");
    m.def(
        "ULE", [](cst_t l, const Value& r) { return ULE(l, r.as_expr()); },
        "Unsigned less-equal constraint on abstract values");
    m.def(
        "ULT", [](nb::int_, nb::int_) -> InvalidOperands
        { throw nb::value_error("Expected at least one Value"); },
        "Unsigned less-than constraint on abstract values");
    m.def(
        "ULT", [](const Value& l, const Value& r) { return ULT(l.as_expr(), r.as_expr()); },
        "Unsigned less-than constraint on abstract values");
    m.def(
        "ULT", [](const Value& l, cst_t r) { return ULT(l.as_expr(), r); },
        "Unsigned less-than constraint on abstract values");
    m.def(
        "ULT", [](cst_t l, const Value& r) { return ULT(l, r.as_expr()); },
        "Unsigned less-than constraint on abstract values");
    m.def(
        "ITE", [](Constraint, nb::int_, nb::int_) -> InvalidOperands
        { throw nb::value_error("Expected at least one Value"); },
        "Create an If-Then-Else expression from a Constraint and two abstract expressions");
    m.def(
        "ITE", [](Constraint c, const Value& l, const Value& r)
        { return Value(ITE(c, l.as_expr(), r.as_expr())); },
        "Create an If-Then-Else expression from a Constraint and two abstract expressions");
    m.def(
        "ITE", [](Constraint c, cst_t l, const Value& r)
        { return Value(ITE(c, exprcst(r.size(), l), r.as_expr())); },
        "Create an If-Then-Else expression from a Constraint and two abstract expressions");
    m.def(
        "ITE", [](Constraint c, const Value& l, cst_t r)
        { return Value(ITE(c, l.as_expr(), exprcst(l.size(), r))); },
        "Create an If-Then-Else expression from a Constraint and two abstract expressions");
}
} // namespace maat::py
