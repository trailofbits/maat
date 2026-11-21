#include "python_bindings.hpp"
#include <climits>

namespace maat::py
{
static const std::string& variable_name(const std::string& name)
{
    if (name.find('\0') != std::string::npos)
        throw nb::value_error("embedded null character");
    return name;
}

using ConcolicInput = std::variant<ByteString, nb::typed<nb::list, cst_t>>;

static std::vector<Value> concolic(VarContext& ctx, const std::string& name, ConcolicInput input,
                                   int count, int width, std::optional<cst_t> trailing)
{
    if (name.find('\0') != std::string::npos)
        throw nb::type_error("Invalid concolic buffer name");
    if (width <= 0)
        throw nb::value_error("Element size must be positive");
    std::vector<cst_t> data;
    if (auto p = std::get_if<ByteString>(&input))
    {
        const auto buffer = p->as_bytes();
        const auto size = buffer.size();
        if (count == -1 && size % width)
            throw nb::value_error("Incomplete buffer element");
        const auto available = size / width;
        if (count == -1)
        {
            if (available > INT_MAX)
                throw std::overflow_error("Buffer is too large");
            count = static_cast<int>(available);
        }
        if (count < 0 || size_t(count) > available)
            throw nb::value_error("Buffer too short");
        const auto* bytes = reinterpret_cast<const uint8_t*>(buffer.c_str());
        for (int i = 0; i < count; ++i)
        {
            ucst_t value = 0;
            for (int j = width; j-- > 0;)
            {
                const size_t offset = size_t(i) * width + j;
                if (ctx.endianness() == Endian::LITTLE)
                    value = (value << 8) | bytes[offset];
                else
                    // Big-endian buffers shift the promoted char by its byte index in bits.
                    value |= static_cast<ucst_t>(buffer.c_str()[offset]) << (j % 64);
            }
            data.push_back(static_cast<cst_t>(value));
        }
    }
    else
    {
        auto items = std::get<1>(input);
        if (count == -1)
            count = static_cast<int>(nb::len(items));
        if (count < 0 || size_t(count) > nb::len(items))
            throw nb::type_error("Buffer too short");
        for (int i = 0; i < count; ++i)
            data.push_back(nb::cast<cst_t>(items[i]));
    }
    return ctx.new_concolic_buffer(name, data, count, width, trailing);
}

void bind_varcontext(nb::module_& m)
{
    nb::class_<VarContext>(m, "VarContext", nb::is_final(),
                           "Concrete context for abstract variables")
        .def(nb::init<>())
        .def(
            "set", [](VarContext& ctx, const std::string& name, nb::int_ n, int bits)
            { ctx.set(variable_name(name), bigint(bits, n)); }, nb::arg(), nb::arg(), nb::arg() = 64,
            "Give a concrete value to a symbolic variable")
        .def(
            "get",
            [](VarContext& ctx, const std::string& name)
            {
                if (!ctx.contains(variable_name(name)))
                    throw nb::key_error(name.c_str());
                return integer(ctx.get_as_number(name));
            },
            "Give the concrete value associated with a symbolic variable")
        .def("remove", [](VarContext& ctx, const std::string& name) { return ctx.remove(variable_name(name)); },
             "Remove the concrete value associated with a symbolic variable")
        .def("contains", [](VarContext& ctx, const std::string& name) { return ctx.contains(variable_name(name)); },
             "Check if a given symbolic variable has an associated concrete value")
        .def(
            "contained_vars",
            [](VarContext& ctx)
            {
                auto vars = ctx.contained_vars();
                return std::vector<std::string>(vars.begin(), vars.end());
            },
            "Get the list of contained symbolic variables")
        .def("update_from", &VarContext::update_from,
             "Update concrete values associated with symbolic variables according to another "
             "VarContext")
        .def(
            "get_as_buffer",
            [](VarContext& ctx, const std::string& name, unsigned width)
            {
                auto bytes = ctx.get_as_buffer(variable_name(name), width);
                if (bytes.size() > 4096)
                    throw std::runtime_error("Buffer is too big!");
                return nb::bytes(bytes.data(), bytes.size());
            },
            nb::arg(), nb::arg() = 1,
            "Give the buffer associated with a certain symbolic variable prefix")
        .def(
            "get_as_str",
            [](VarContext& ctx, const std::string& name)
            {
                try
                {
                    return nb::bytes(ctx.get_as_string(variable_name(name)).c_str());
                }
                catch (const std::exception& e)
                {
                    throw nb::value_error(e.what());
                }
            },
            "Give the string associated with a certain symbolic variable prefix")
        .def(
            "new_concolic_buffer",
            [](VarContext& ctx, const std::string& name, ConcolicInput input, int count, int width)
            { return concolic(ctx, name, input, count, width, std::nullopt); }, nb::arg(),
            nb::arg(), "nb_elems"_a = -1, "elem_size"_a = 1,
            "Create a new buffer of concolic variables")
        .def(
            "new_concolic_buffer",
            [](VarContext& ctx, const std::string& name, ConcolicInput input, int count, int width,
               cst_t trailing) { return concolic(ctx, name, input, count, width, trailing); },
            nb::arg(), nb::arg(), "nb_elems"_a, "elem_size"_a, "trailing_value"_a,
            "Create a new buffer of concolic variables")
        .def(
            "new_concolic_buffer",
            [](VarContext& ctx, const std::string& name, ConcolicInput input, int count, int width,
               cst_t trailing) { return concolic(ctx, name, input, count, width, trailing); },
            nb::arg(), nb::arg(), "nb_elems"_a = -1, "elem_size"_a = 1, nb::kw_only(),
            "trailing_value"_a, "Create a new buffer of concolic variables")
        .def(
            "new_symbolic_buffer",
            [](VarContext& ctx, const std::string& name, int count, int width)
            { return ctx.new_symbolic_buffer(variable_name(name), count, width, std::nullopt); }, nb::arg(),
            "nb_elems"_a, "elem_size"_a = 1, "Create a new buffer of symbolic variables")
        .def(
            "new_symbolic_buffer",
            [](VarContext& ctx, const std::string& name, int count, int width, cst_t trailing)
            { return ctx.new_symbolic_buffer(variable_name(name), count, width, trailing); }, nb::arg(),
            "nb_elems"_a, "elem_size"_a, "trailing_value"_a,
            "Create a new buffer of symbolic variables")
        .def(
            "new_symbolic_buffer",
            [](VarContext& ctx, const std::string& name, int count, int width, cst_t trailing)
            { return ctx.new_symbolic_buffer(variable_name(name), count, width, trailing); }, nb::arg(),
            "nb_elems"_a, "elem_size"_a = 1, nb::kw_only(), "trailing_value"_a,
            "Create a new buffer of symbolic variables")
        .def("__str__", &format<VarContext>)
        .def("__repr__", &format<VarContext>);
}
} // namespace maat::py
