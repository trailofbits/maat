#include "python_bindings.hpp"
#include <nanobind/stl/pair.h>

namespace maat::py
{
static event::EventCallback python_callback(nb::callable callback, nb::object data)
{
    using event::Action;
    return event::EventCallback(
        [callback = std::move(callback), data = std::move(data)](MaatEngine& engine, void*)
        {
            nb::gil_scoped_acquire gil;
            auto wrapper = nb::find(&engine);
            if (!wrapper.is_valid())
                throw runtime_exception("Missing Python engine for callback");
            try
            {
                nb::object result = data.is_valid() ? callback(wrapper, data) : callback(wrapper);
                if (result.is_none())
                    return Action::CONTINUE;
                if (!nb::isinstance<nb::int_>(result))
                {
                    engine.log.fatal("Python callback didn't return a valid action (wrong object type)");
                    return Action::ERROR;
                }
                auto value = PyLong_AsLong(result.ptr());
                if (PyErr_Occurred())
                    throw nb::python_error();
                auto action = static_cast<Action>(static_cast<int>(value));
                if (action == Action::CONTINUE || action == Action::HALT || action == Action::ERROR)
                    return action;
                engine.log.fatal("Python callback didn't return a valid action");
            }
            catch (nb::python_error& error)
            {
                std::cout << "Error in python callback: " << std::flush;
                error.restore();
                PyErr_Print();
            }
            return Action::ERROR;
        });
}

void bind_events(nb::module_& m)
{
    using namespace event;
    using Range = nb::typed<nb::sequence, addr_t>;
    using Filter = std::variant<addr_t, Range>;
    using Callbacks = nb::typed<nb::list, nb::callable>;
    // Explicit data=None passes a second callback argument. Omission passes one.
    auto omitted = nb::module_::import_("builtins").attr("object")();
    nb::class_<EventManager>(m, "_EventManager", nb::is_final(), "Event hooks manager")
        .def(
            "add",
            [omitted](EventManager& mgr, int kind, int when, const std::string& name, Filter filter,
                      Callbacks callbacks, nb::object data, const std::string& group)
            {
                std::vector<EventCallback> handlers;
                nb::object callback_data = data.is(omitted) ? nb::object() : data;
                for (auto f : callbacks)
                {
                    if (!nb::isinstance<nb::callable>(f))
                        throw nb::type_error("Expected a callable");
                    handlers.push_back(python_callback(nb::borrow<nb::callable>(f), callback_data));
                }
                AddrFilter addresses;
                if (auto addr = std::get_if<addr_t>(&filter))
                    addresses = AddrFilter(*addr);
                else
                {
                    std::pair<addr_t, addr_t> limits;
                    if (!nb::try_cast(std::get<Range>(filter), limits))
                        throw nb::type_error("Expected an address or a pair of addresses");
                    if (limits.first != 0 || limits.second != UINT64_MAX)
                        addresses = AddrFilter(limits.first, limits.second);
                }
                mgr.add(static_cast<Event>(kind), static_cast<When>(when), handlers, name,
                        addresses, group);
            },
            nb::arg(), nb::arg(), "name"_a = "", "filter"_a = nb::make_tuple(0, UINT64_MAX),
            "callbacks"_a = nb::list(), nb::arg("data").none().sig("...") = omitted, "group"_a = "",
            "Add a hook")
        .def("disable", nb::overload_cast<std::string>(&EventManager::disable),
             "Disable a given hook")
        .def("enable", nb::overload_cast<std::string>(&EventManager::enable), "Enable a given hook")
        .def("disable_group", &EventManager::disable_group, "Disable a group of hooks")
        .def("enable_group", &EventManager::enable_group, "Enable a group of hooks")
        .def("disable_all", &EventManager::disable_all, "Disable all hooks")
        .def("__repr__", &format<EventManager>)
        .def("__str__", &format<EventManager>);
}
} // namespace maat::py
