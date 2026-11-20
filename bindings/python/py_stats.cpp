#include "python_bindings.hpp"
#include "maat/stats.hpp"

namespace maat{
namespace py{
    
static void Stats_dealloc(PyObject* self){
    free_binding_object(self);
};

static PyObject* Stats_str(PyObject* self)
{
    std::stringstream res;
    res << MaatStats::instance();
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Stats_repr(PyObject* self)
{
    return Stats_str(self);
}

static PyObject* Stats_reset(PyObject* self)
{
    maat::MaatStats::instance().reset();
    Py_RETURN_NONE;
}


static PyMethodDef Stats_methods[] = {
    {"reset", (PyCFunction)Stats_reset, METH_NOARGS | METH_CLASS, "Reset statistics"},
    {NULL, NULL, 0, NULL}
};

// MACROs for generic getter bindings for MaatStats
#define MAAT_DEFINE_STATS_GETTER(property_name) \
static PyObject* Stats_get_##property_name(PyObject* self, void* closure){ \
   return PyLong_FromUnsignedLongLong( \
       MaatStats::instance().property_name() \
   ); \
}

#define MAAT_GETDEF(property_name, docstr) \
{#property_name, Stats_get_##property_name, NULL, docstr, NULL}

MAAT_DEFINE_STATS_GETTER(symptr_read_total_time)
MAAT_DEFINE_STATS_GETTER(symptr_read_average_time)
MAAT_DEFINE_STATS_GETTER(symptr_read_average_range)
MAAT_DEFINE_STATS_GETTER(symptr_read_count)
MAAT_DEFINE_STATS_GETTER(symptr_write_total_time)
MAAT_DEFINE_STATS_GETTER(symptr_write_average_time)
MAAT_DEFINE_STATS_GETTER(symptr_write_average_range)
MAAT_DEFINE_STATS_GETTER(symptr_write_count)
MAAT_DEFINE_STATS_GETTER(executed_insts)
MAAT_DEFINE_STATS_GETTER(executed_ir_insts)
MAAT_DEFINE_STATS_GETTER(lifted_insts)
MAAT_DEFINE_STATS_GETTER(created_exprs)
MAAT_DEFINE_STATS_GETTER(solver_total_time)
MAAT_DEFINE_STATS_GETTER(solver_average_time)
MAAT_DEFINE_STATS_GETTER(solver_calls_count)

static PyGetSetDef Stats_getset[] = {
    MAAT_GETDEF(symptr_read_total_time, "Total time spent solving symbolic pointer reads (in milliseconds)"),
    MAAT_GETDEF(symptr_read_average_time, "Average time spent solving symbolic pointer reads (in milliseconds)"),
    MAAT_GETDEF(symptr_read_average_range, "Average range of symbolic pointer reads"),
    MAAT_GETDEF(symptr_read_count, "Total number of symbolic pointer reads"),
    MAAT_GETDEF(symptr_write_total_time, "Total time spent solving symbolic pointer writes (in milliseconds)"),
    MAAT_GETDEF(symptr_write_average_time, "Average time spent solving symbolic pointer rwrites (in milliseconds)"),
    MAAT_GETDEF(symptr_write_average_range, "Average range of symbolic pointer writes"),
    MAAT_GETDEF(symptr_write_count, "Total number of symbolic pointer writes"),
    MAAT_GETDEF(executed_insts, "Total number of assembly instructions symbolically executed"),
    MAAT_GETDEF(lifted_insts, "Total number of assembly instructions lifted to IR"),
    MAAT_GETDEF(executed_ir_insts, "Total number of IR instructions executed"),
    MAAT_GETDEF(solver_total_time, "Total time spend solving symbolic constraints (in milliseconds)"),
    MAAT_GETDEF(solver_average_time, "Average time spend solving symbolic constraints (in milliseconds)"),
    MAAT_GETDEF(solver_calls_count, "Total number of calls to the solver"),
    {NULL}
};


static PyType_Slot Stats_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Stats_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(Stats_repr)},
    {Py_tp_str, reinterpret_cast<void*>(Stats_str)},
    {Py_tp_doc, const_cast<char*>("Maat statistics")},
    {Py_tp_methods, Stats_methods},
    {Py_tp_getset, Stats_getset},
    {0, nullptr}
};

PyType_Spec BindingTypes::Stats_spec = {
    "maat.MaatStats", sizeof(Stats_Object), 0, binding_type_flags, Stats_slots
};

void init_stats(PyObject* module, PyTypeObject* type)
{
    // HACK: We create an instance instead of exposing the class directly
    // because setting class-level properties from the Python C API is
    // just too cumbersome. With an instance we can use the regular tp_getset
    // field to get the various stats.
    auto* object = PyObject_New(Stats_Object, type);
    if (!object)
        return;
    if (PyModule_AddObject(module, "MaatStats", (PyObject*)object) < 0)
        Py_DECREF(object);
}

} // namespace py
} // namespace maat