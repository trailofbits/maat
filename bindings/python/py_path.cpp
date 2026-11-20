#include "python_bindings.hpp"

namespace maat::py
{
struct PathIterator
{
    PathManager::IteratorWrapper range;
    PathManager::iterator current;
    PathManager::iterator end;
    explicit PathIterator(PathManager::IteratorWrapper items)
        : range(items), current(range.begin()), end(range.end())
    {
    }
    PathIterator(const PathIterator&) = delete;
};

void bind_path(nb::module_& m)
{
    nb::class_<PathIterator>(m, "_PathIterator", nb::is_final(), "Path constraints custom iterator")
        .def(
            "__iter__", [](PathIterator& it) -> PathIterator& { return it; },
            nb::rv_policy::reference)
        .def("__next__",
             [](PathIterator& it)
             {
                 if (it.current == it.end)
                     throw nb::stop_iteration();
                 return *it.current++;
             });
    nb::class_<PathManager>(m, "_PathManager", nb::is_final(), "Path Manager")
        .def("add", &PathManager::add, "Add a path constraint")
        .def(
            "constraints",
            [](PathManager& path) { return new PathIterator(path._constraints_iterator()); },
            nb::rv_policy::take_ownership, nb::keep_alive<0, 1>(), "Get current path constraints")
        .def(
            "get_constraints_containing",
            [](PathManager& path, StringSet names)
            {
                auto vars = string_set_items(names, "Failed to translate set of variables to native std::set");
                return new PathIterator(path.get_constraints_containing(vars));
            },
            nb::rv_policy::take_ownership, nb::keep_alive<0, 1>(),
            "Get current path constraints containing at least one variable from a given set")
        .def(
            "get_related_constraints",
            [](PathManager& path, const std::variant<Constraint, Value>& input)
            {
                auto result = std::visit([&](const auto& v)
                                         { return path.get_related_constraints(v); }, input);
                return std::vector<Constraint>(result.begin(), result.end());
            },
            "Get all path constraints related to a constraint or expression");
}
} // namespace maat::py
