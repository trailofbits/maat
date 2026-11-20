#include "python_bindings.hpp"

namespace maat::py
{
std::set<std::string> string_set_items(const StringSet& items, const char* error)
{
    std::set<std::string> result;
    for (auto item : items)
    {
        const char* text = PyUnicode_AsUTF8AndSize(item.ptr(), nullptr);
        if (!text)
        {
            PyErr_Clear();
            throw std::runtime_error(error);
        }
        result.emplace(text);
    }
    return result;
}

Number bigint(unsigned bits, const nb::int_& value)
{
    if (bits <= 64)
    {
        int overflow = 0;
        auto raw = PyLong_AsLongLongAndOverflow(value.ptr(), &overflow);
        if (overflow)
            raw = static_cast<cst_t>(PyLong_AsUnsignedLongLong(value.ptr()));
        if (PyErr_Occurred())
            throw nb::python_error();
        return Number(bits, static_cast<cst_t>(raw));
    }
    return Number(bits, nb::cast<std::string>(nb::str(value)), 10);
}

nb::int_ integer(const Number& value)
{
    std::ostringstream stream;
    stream << std::hex << value;
    auto result = nb::steal<nb::int_>(PyLong_FromString(stream.str().c_str(), nullptr, 16));
    if (!result.is_valid())
        throw nb::python_error();
    return result;
}
} // namespace maat::py
