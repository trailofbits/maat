#include "python_bindings.hpp"

#ifdef MAAT_HAS_SOLVER_BACKEND
namespace maat::py
{
void bind_solver(nb::module_& m)
{
    using solver::Solver;
    nb::class_<Solver>(m, "Solver", nb::is_final(), "Constraint solver")
        .def(nb::new_(&solver::_new_solver_raw), nb::rv_policy::take_ownership)
        .def("reset", &Solver::reset, "Remove all constraints from the solver")
        .def("add", &Solver::add, "Add a constraint to the solver")
        .def("check", &Solver::check, "Check if a model exists for the current constraints")
        .def(
            "get_model",
            [](Solver& s) -> std::optional<std::shared_ptr<VarContext>>
            {
                if (auto model = s.get_model())
                    return model;
                return std::nullopt;
            },
            "If a model exists, return the model as a 'VarContext' instance")
        .def_prop_rw(
            "timeout", [](const Solver& s) { return s.timeout; },
            [](Solver& s, UnsignedSetting n) { s.timeout = n.value; },
            "Maximum time to spend to solve a constraint (in milliseconds)")
        .def_prop_ro("did_time_out", &Solver::did_time_out,
                     "True if the last call to check() timed out");
}
} // namespace maat::py
#endif
