#include "python_bindings.hpp"

namespace maat::py
{
void bind_stats(nb::module_& m)
{
    nb::class_<MaatStats>(m, "_MaatStats", nb::is_final(), "Maat statistics")
        .def_static(
            "reset", [] { MaatStats::instance().reset(); }, "Reset statistics")
        .def_prop_ro("symptr_read_total_time", &MaatStats::symptr_read_total_time,
                     "Total time spent solving symbolic pointer reads (in milliseconds)")
        .def_prop_ro("symptr_read_average_time", &MaatStats::symptr_read_average_time,
                     "Average time spent solving symbolic pointer reads (in milliseconds)")
        .def_prop_ro("symptr_read_average_range", &MaatStats::symptr_read_average_range,
                     "Average range of symbolic pointer reads")
        .def_prop_ro("symptr_read_count", &MaatStats::symptr_read_count,
                     "Total number of symbolic pointer reads")
        .def_prop_ro("symptr_write_total_time", &MaatStats::symptr_write_total_time,
                     "Total time spent solving symbolic pointer writes (in milliseconds)")
        .def_prop_ro("symptr_write_average_time", &MaatStats::symptr_write_average_time,
                     "Average time spent solving symbolic pointer rwrites (in milliseconds)")
        .def_prop_ro("symptr_write_average_range", &MaatStats::symptr_write_average_range,
                     "Average range of symbolic pointer writes")
        .def_prop_ro("symptr_write_count", &MaatStats::symptr_write_count,
                     "Total number of symbolic pointer writes")
        .def_prop_ro("executed_insts", &MaatStats::executed_insts,
                     "Total number of assembly instructions symbolically executed")
        .def_prop_ro("lifted_insts", &MaatStats::lifted_insts,
                     "Total number of assembly instructions lifted to IR")
        .def_prop_ro("executed_ir_insts", &MaatStats::executed_ir_insts,
                     "Total number of IR instructions executed")
        .def_prop_ro("solver_total_time", &MaatStats::solver_total_time,
                     "Total time spend solving symbolic constraints (in milliseconds)")
        .def_prop_ro("solver_average_time", &MaatStats::solver_average_time,
                     "Average time spend solving symbolic constraints (in milliseconds)")
        .def_prop_ro("solver_calls_count", &MaatStats::solver_calls_count,
                     "Total number of calls to the solver")
        .def("__repr__", &format<MaatStats>)
        .def("__str__", &format<MaatStats>);
    m.attr("MaatStats") = nb::cast(&MaatStats::instance(), nb::rv_policy::reference);
}
} // namespace maat::py
