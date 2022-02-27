#include "python_bindings.hpp"
#include "maat/stats.hpp"

namespace maat{
namespace py{
    
static void Stats_dealloc(PyObject* self){
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int Stats_print(PyObject* self, void * io, int s)
{
    std::cout << MaatStats::instance() << std::flush;
    return 0;
}

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


/* Type description for python Expr objects */
PyTypeObject Stats_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "MaatStats",                                   /* tp_name */
    sizeof(Stats_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Stats_dealloc,            /* tp_dealloc */
    (printfunc)Stats_print,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Stats_repr,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Stats_str,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Maat statistics",             /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Stats_methods,                                        /* tp_methods */
    0,                                        /* tp_members */
    Stats_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_Stats_Type()
{
    return (PyObject*)&Stats_Type;
}

// Constructor
PyObject* maat_Stats()
{
    // Create object
    PyType_Ready(&Stats_Type);
    Stats_Object* object = PyObject_New(Stats_Object, &Stats_Type);
    return (PyObject*)object;
}

void init_stats(PyObject* module)
{
    // HACK: We create an instance instead of exposing the class directly
    // because setting class-level properties from the Python C API is
    // just too cumbersome. With an instance we can use the regular tp_getset
    // field to get the various stats.
    Stats_Object *object = nullptr;
    PyType_Ready(&Stats_Type);
    object = PyObject_New(Stats_Object, &Stats_Type);
    if (!object)
        return;
    if (PyModule_AddObject(module, "MaatStats", (PyObject*)object) < 0)
        Py_DECREF(object);
}

} // namespace py
} // namespace maat