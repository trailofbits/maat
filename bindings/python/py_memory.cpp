#include "python_bindings.hpp"

namespace maat::py
{
using Address = std::variant<addr_t, Value>;
class Index : public nb::object
{
    NB_OBJECT(Index, nb::object, "typing.SupportsIndex", PyIndex_Check)
};

void bind_memory(nb::module_& m)
{
    nb::class_<MemEngine>(m, "_MemEngine", nb::is_final(), "Memory engine")
        .def(
            "map",
            [](MemEngine& mem, addr_t first, addr_t last, Index flags,
               const std::string& name)
            {
                auto bits = PyLong_AsUnsignedLongMask(flags.ptr());
                if (PyErr_Occurred())
                    throw nb::python_error();
                mem.map(first, last, static_cast<unsigned short>(bits), name);
            },
            nb::arg(), nb::arg(), "flags"_a = mem_flag_rwx, "name"_a = "", "Map a memory region")
        .def(
            "read",
            [](MemEngine& mem, const Address& addr, unsigned size)
            {
                if (auto v = std::get_if<Value>(&addr))
                    return mem.read(*v, size);
                Value result;
                mem.read(result, std::get<addr_t>(addr), size);
                return result;
            },
            "Reads memory into an expression")
        .def(
            "read_buffer",
            [](MemEngine& mem, const Address& addr, unsigned count, unsigned width)
            {
                return std::visit([&](const auto& a) { return mem.read_buffer(a, count, width); },
                                  addr);
            },
            nb::arg(), nb::arg(), nb::arg() = 1, "Reads a buffer in memory")
        .def(
            "read_str",
            [](MemEngine& mem, const Address& addr, unsigned size)
            {
                auto s = std::visit([&](const auto& a) { return mem.read_string(a, size); }, addr);
                return nb::bytes(s.data(), s.size());
            },
            nb::arg(), nb::arg() = 0, "Reads a concrete string in memory")
        .def(
            "write",
            [](MemEngine& mem, const Address& addr, const Value& v, nb::object, nb::object ignore)
            {
                if (auto symbolic = std::get_if<Value>(&addr))
                    mem.write(*symbolic, v, truth(ignore));
                else
                    mem.write(std::get<addr_t>(addr), v, nullptr, false, truth(ignore));
            },
            nb::arg(), nb::arg(), nb::arg().none() = nb::none(),
            nb::arg("ignore_flags").none() = false, "Write a value/expression/buffer into memory")
        .def(
            "write",
            [](MemEngine& mem, const Address& addr, cst_t v, unsigned width, nb::object ignore)
            { std::visit([&](const auto& a) { mem.write(a, v, width, truth(ignore)); }, addr); },
            nb::arg(), nb::arg(), nb::arg(), nb::arg("ignore_flags").none() = false,
            "Write a value/expression/buffer into memory")
        .def(
            "write",
            [](MemEngine& mem, const Address& addr, nb::bytes data, size_t length,
               nb::object ignore)
            {
                auto size = std::min<size_t>(length, data.size());
                std::visit([&](const auto& a)
                           { mem.write_buffer(a, (uint8_t*)data.c_str(), size, truth(ignore)); },
                           addr);
            },
            nb::arg(), nb::arg(), nb::arg().sig("...") = SIZE_MAX,
            nb::arg("ignore_flags").none() = false, "Write a value/expression/buffer into memory")
        .def(
            "make_concolic",
            [](MemEngine& m, addr_t a, unsigned n, unsigned w, const std::string& name)
            { return m.make_concolic(a, n, w, name); }, "Make a memory area concolic")
        .def(
            "make_symbolic",
            [](MemEngine& m, addr_t a, unsigned n, unsigned w, const std::string& name)
            { return m.make_symbolic(a, n, w, name); }, "Make a memory area purely symbolic")
        .def("__repr__", &format<MemEngine>)
        .def("__str__", &format<MemEngine>);
}
} // namespace maat::py
