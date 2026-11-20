#include "python_bindings.hpp"

namespace maat::py
{
static ir::reg_t lookup(const CpuView& cpu, const std::string& name)
{
    try
    {
        return cpu.engine->arch->reg_num(name);
    }
    catch (const ir_exception& e)
    {
        throw nb::attribute_error(e.what());
    }
}

static std::string format_cpu(const CpuView& cpu)
{
    std::ostringstream s;
    cpu.engine->cpu.ctx().print(s, *cpu.engine->arch);
    return s.str();
}

void bind_cpu(nb::module_& m)
{
    nb::class_<CpuView>(m, "_CPU", nb::is_final(), "Emulated CPU")
        .def("__getattr__", [](const CpuView& cpu, const std::string& name)
             { return BoundValue{cpu.engine->cpu.ctx().get(lookup(cpu, name)), cpu.engine->vars}; })
        .def("__setattr__",
             [](CpuView& cpu, const std::string& name, std::variant<Value, nb::int_> value)
             {
                 auto reg = lookup(cpu, name);
                 if (auto v = std::get_if<Value>(&value))
                     cpu.engine->cpu.ctx().set(reg, *v);
                 else
                     cpu.engine->cpu.ctx().set(
                         reg, bigint(cpu.engine->arch->reg_size(reg), std::get<1>(value)));
             })
        .def("__str__", &format_cpu)
        .def("__repr__", &format_cpu);
}
} // namespace maat::py
