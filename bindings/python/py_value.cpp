#include "python_bindings.hpp"

namespace maat::py
{
using Operand = std::variant<Value, cst_t>;
static Value operand(const Operand& rhs, const Value& lhs)
{
    if (auto v = std::get_if<Value>(&rhs))
        return *v;
    return Value(lhs.size(), std::get<cst_t>(rhs));
}

using ComparisonOperand = std::variant<Value, nb::int_>;
static Value comparison_operand(const ComparisonOperand& rhs, const Value& lhs)
{
    if (auto v = std::get_if<Value>(&rhs))
        return *v;
    auto raw = PyLong_AsUnsignedLongLong(std::get<nb::int_>(rhs).ptr());
    if (PyErr_Occurred())
        throw nb::python_error();
    return Value(exprcst(lhs.size(), static_cast<cst_t>(raw)));
}

// Omission uses the value's bound context. An explicit argument must be a context.
template <class Function>
static void bind_context_method(nb::class_<BoundValue>& cls, const char* name, const char* doc,
                                Function fn)
{
    auto call = [fn](const BoundValue& value, VarContext* ctx)
    {
        try
        {
            return fn(value, ctx);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(e.what());
        }
    };
    cls.def(name, [call](const BoundValue& v) { return call(v, v.context.get()); }, doc);
    cls.def(name, [call](const BoundValue& v, VarContext& ctx) { return call(v, &ctx); }, doc);
}

void bind_values(nb::module_& m)
{
    nb::class_<BoundValue> value(m, "Value", nb::is_final(), "Abstract expression");
    value
        .def_prop_ro(
            "size", [](const BoundValue& v) { return v.value.size(); }, "Value size in bits")
        .def_prop_ro(
            "name",
            [](const BoundValue& v)
            {
                if (!v.value.is_abstract() || !v.value.expr()->is_type(ExprType::VAR))
                    throw nb::attribute_error("Expected a symbolic variable");
                return v.value.expr()->name();
            },
            "Variable name (throws AttributeError if the value is not a symbolic variable)")
        .def("__str__", [](const BoundValue& v) { return format(v.value); })
        .def("__repr__", [](const BoundValue& v) { return format(v.value); })
        .def("__hash__", [](const BoundValue& v) { return v.value.as_expr()->hash(); })
        .def(
            "eq", [](const BoundValue& v, const Value& o) { return v.value.eq(o); },
            "Return True if two values are identical (same abstract syntax tree)")
        .def("__neg__", [](const BoundValue& v) { return -v.value; })
        .def("__invert__", [](const BoundValue& v) { return ~v.value; });
    bind_context_method(value, "is_concrete", "Check whether the value is concrete",
                        [](const BoundValue& v, VarContext* ctx)
                        {
                            if (!ctx)
                                throw std::runtime_error("Value isn't bound to a VarContext");
                            return v.value.is_concrete(*ctx);
                        });
    bind_context_method(value, "is_concolic", "Check whether the value is concolic",
                        [](const BoundValue& v, VarContext* ctx)
                        {
                            if (!ctx)
                                throw std::runtime_error("Value isn't bound to a VarContext");
                            return v.value.is_concolic(*ctx);
                        });
    bind_context_method(value, "is_symbolic", "Check whether the value is symbolic",
                        [](const BoundValue& v, VarContext* ctx)
                        {
                            if (!ctx)
                                throw std::runtime_error("Value isn't bound to a VarContext");
                            return v.value.is_symbolic(*ctx);
                        });
    bind_context_method(value, "as_uint", "Concretize the value interpreted as an unsigned value",
                        [](const BoundValue& v, VarContext* ctx)
                        {
                            if (v.value.size() > 64)
                                return integer(ctx ? v.value.as_number(*ctx) : v.value.as_number());
                            return nb::int_(ctx ? v.value.as_uint(*ctx) : v.value.as_uint());
                        });
    bind_context_method(value, "as_int", "Concretize the value interpreted as a signed value",
                        [](const BoundValue& v, VarContext* ctx)
                        {
                            if (v.value.size() > 64)
                                return integer(ctx ? v.value.as_number(*ctx) : v.value.as_number());
                            return nb::int_(ctx ? v.value.as_int(*ctx) : v.value.as_int());
                        });
    bind_context_method(
        value, "as_float", "Concretize the value interpreted as a floating point value",
        [](const BoundValue& v, VarContext* ctx)
        {
            if (v.value.size() > 64)
                throw std::runtime_error("as_float requires at most 64 bits");
            return nb::int_(static_cast<ucst_t>(ctx ? v.value.as_float(*ctx) : v.value.as_float()));
        });
    value.def("__add__", [](const BoundValue& v, const Operand& other)
              { return v.value + operand(other, v.value); });
    value.def("__radd__", [](const BoundValue& v, cst_t other) { return other + v.value; });
    value.def("__sub__", [](const BoundValue& v, const Operand& other)
              { return v.value - operand(other, v.value); });
    value.def("__rsub__", [](const BoundValue& v, cst_t other) { return other - v.value; });
    value.def("__mul__", [](const BoundValue& v, const Operand& other)
              { return v.value * operand(other, v.value); });
    value.def("__rmul__", [](const BoundValue& v, cst_t other) { return other * v.value; });
    value.def("__floordiv__", [](const BoundValue& v, const Operand& other)
              { return v.value / operand(other, v.value); });
    value.def("__rfloordiv__", [](const BoundValue& v, cst_t other) { return other / v.value; });
    value.def("__truediv__", [](const BoundValue& v, const Operand& other)
              { return v.value / operand(other, v.value); });
    value.def("__rtruediv__", [](const BoundValue& v, cst_t other) { return other / v.value; });
    value.def("__mod__", [](const BoundValue& v, const Operand& other)
              { return v.value % operand(other, v.value); });
    value.def("__rmod__", [](const BoundValue& v, cst_t other) { return other % v.value; });
    value.def("__and__", [](const BoundValue& v, const Operand& other)
              { return v.value & operand(other, v.value); });
    value.def("__rand__", [](const BoundValue& v, cst_t other) { return other & v.value; });
    value.def("__or__", [](const BoundValue& v, const Operand& other)
              { return v.value | operand(other, v.value); });
    value.def("__ror__", [](const BoundValue& v, cst_t other) { return other | v.value; });
    value.def("__xor__", [](const BoundValue& v, const Operand& other)
              { return v.value ^ operand(other, v.value); });
    value.def("__rxor__", [](const BoundValue& v, cst_t other) { return other ^ v.value; });
    value.def("__lshift__", [](const BoundValue& v, const Operand& other)
              { return v.value << operand(other, v.value); });
    value.def("__rlshift__", [](const BoundValue& v, cst_t other) { return other << v.value; });
    value.def("__rshift__", [](const BoundValue& v, const Operand& other)
              { return v.value >> operand(other, v.value); });
    value.def("__rrshift__", [](const BoundValue& v, cst_t other) { return other >> v.value; });
    value.def("__eq__", [](const BoundValue& v, const ComparisonOperand& other)
              { return v.value == comparison_operand(other, v.value); });
    value.def("__ne__", [](const BoundValue& v, const ComparisonOperand& other)
              { return v.value != comparison_operand(other, v.value); });
    value.def("__lt__", [](const BoundValue& v, const ComparisonOperand& other)
              { return v.value < comparison_operand(other, v.value); });
    value.def("__le__", [](const BoundValue& v, const ComparisonOperand& other)
              { return v.value <= comparison_operand(other, v.value); });
    value.def("__gt__", [](const BoundValue& v, const ComparisonOperand& other)
              { return v.value > comparison_operand(other, v.value); });
    value.def("__ge__", [](const BoundValue& v, const ComparisonOperand& other)
              { return v.value >= comparison_operand(other, v.value); });
    m.def(
        "Cst", [](int size, nb::int_ n, int) { return Value(bigint(size, n)); }, "size"_a,
        "value"_a, "base"_a = 16, "Create a constant abstract expression");
    m.def(
        "Cst", [](int size, const std::string& n, int base)
        { return Value(exprcst(size, std::string(n), base)); }, "size"_a, "value"_a, "base"_a = 16,
        "Create a constant abstract expression");
    m.def(
        "Var",
        [](int size, ByteString name)
        {
            if (name.bytes.size() > 255)
                throw nb::type_error("Variable name is too long");
            return Value(exprvar(size, name.bytes.c_str()));
        },
        "size"_a, "name"_a, "Create an abstract variable expression");
    m.def("Concat", nb::overload_cast<const Value&, const Value&>(&concat),
          "Concatenate two abstract expressions");
    m.def("Extract", nb::overload_cast<const Value&, unsigned long, unsigned long>(&extract),
          "Bitfield extract from an abstract expression");
    m.def("Sext", nb::overload_cast<int, const Value&>(&sext), "Sign-extend an abstract value");
    m.def("Zext", nb::overload_cast<int, const Value&>(&zext), "Zero-extend an abstract value");
}
} // namespace maat::py
