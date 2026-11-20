#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>
#include "maat/maat.hpp"

namespace maat::py
{
namespace nb = nanobind;
using namespace nb::literals;

// A register value remembers the context used for implicit concretization.
struct BoundValue
{
    Value value;
    std::shared_ptr<VarContext> context;
};

struct CpuView
{
    MaatEngine* engine;
};
struct InfoView
{
    MaatEngine* engine;
};
// Python lists are invariant. An input list can contain either alternative alone
// or elements of both types. All three call forms use the same element converter.
template <class A, class B> struct MixedList
{
    using Items = nb::typed<nb::list, std::variant<A, B>>;
    Items items;
};

// The property setters accept an unsigned long before storing it in
// Maat's narrower unsigned fields (timeouts and symbolic pointer limits).
struct UnsignedSetting
{
    unsigned int value;
};

struct ByteString
{
    nb::bytes bytes;
};

inline bool truth(nb::handle input)
{
    int result = PyObject_IsTrue(input.ptr());
    if (result < 0)
        throw nb::python_error();
    return result != 0;
}
using StringSet = nb::typed<nb::set, std::string>;
std::set<std::string> string_set_items(const StringSet& items, const char* error);

Number bigint(unsigned bits, const nb::int_& value);
nb::int_ integer(const Number& value);
template <class T> std::string format(T& value)
{
    std::ostringstream stream;
    stream << value;
    return stream.str();
}
template <class T> std::vector<T> list_items(nb::typed<nb::list, T> items)
{
    std::vector<T> result;
    result.reserve(nb::len(items));
    for (auto item : items)
    {
        T value;
        if (!nb::try_cast(item, value))
            throw nb::type_error("Invalid list element");
        result.push_back(std::move(value));
    }
    return result;
}

void bind_cpu(nb::module_&);
void bind_varcontext(nb::module_&);
void bind_values(nb::module_&);
void bind_constraints(nb::module_&);
void bind_engine(nb::module_&);
void bind_memory(nb::module_&);
void bind_environment(nb::module_&);
void bind_events(nb::module_&);
void bind_info(nb::module_&);
void bind_evm(nb::module_&);
void bind_solver(nb::module_&);
void bind_path(nb::module_&);
void bind_settings(nb::module_&);
void bind_stats(nb::module_&);
void bind_constants(nb::module_&);
} // namespace maat::py

namespace nanobind::detail
{
template <class A, class B> struct type_caster<maat::py::MixedList<A, B>>
{
    using Input = maat::py::MixedList<A, B>;
    using Items = typename Input::Items;
    using Forms = std::variant<typed<list, A>, typed<list, B>, Items>;
    NB_TYPE_CASTER(Input, make_caster<Forms>::Name)
    bool from_python(handle src, uint32_t, cleanup_list*)
    {
        if (!PyList_Check(src.ptr()))
            return false;
        value.items = borrow<Items>(src);
        return true;
    }
};
template <> struct type_caster<maat::py::UnsignedSetting>
{
    NB_TYPE_CASTER(maat::py::UnsignedSetting, const_name("int"))
    bool from_python(handle src, uint32_t, cleanup_list*)
    {
        if (!PyLong_Check(src.ptr()))
            throw std::runtime_error("Expected an integer");
        auto raw = PyLong_AsUnsignedLong(src.ptr());
        if (PyErr_Occurred())
            throw python_error();
        value.value = static_cast<unsigned int>(raw);
        return true;
    }
};

// Use the same Python class wherever the native API passes Value by value.
template <> struct type_caster<maat::Value>
{
    using Bound = maat::py::BoundValue;
    NB_TYPE_CASTER(maat::Value, const_name<Bound>())
    bool from_python(handle src, uint32_t flags, cleanup_list* cleanup)
    {
        make_caster<Bound> caster;
        if (!caster.from_python(src, flags, cleanup) || !caster.can_cast<Bound&>())
            return false;
        value = static_cast<Bound&>(caster).value;
        return true;
    }
    static handle from_cpp(const maat::Value& value, rv_policy, cleanup_list* cleanup)
    {
        return make_caster<Bound>::from_cpp(Bound{value, {}}, rv_policy::move, cleanup);
    }
};

template <> struct type_caster<maat::py::ByteString>
{
    NB_TYPE_CASTER(maat::py::ByteString, const_name("str | collections.abc.Buffer"))
    bool from_python(handle src, uint32_t, cleanup_list*)
    {
        PyObject* bytes;
        if (PyUnicode_Check(src.ptr()))
            bytes = PyUnicode_AsUTF8String(src.ptr());
        else if (PyBytes_Check(src.ptr()))
            bytes = Py_NewRef(src.ptr());
        else if (PyObject_CheckBuffer(src.ptr()))
        {
            auto view = steal<object>(PyMemoryView_FromObject(src.ptr()));
            bytes = view.is_valid() ? PyBytes_FromObject(view.ptr()) : nullptr;
        }
        else
            return false;
        if (!bytes)
            throw python_error();
        value.bytes = steal<nanobind::bytes>(bytes);
        return true;
    }
};
} // namespace nanobind::detail
