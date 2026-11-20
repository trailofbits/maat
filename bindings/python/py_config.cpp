#include "python_bindings.hpp"

namespace maat{
namespace py{
    
static void Config_dealloc(PyObject* self){
    free_binding_object(self);
};


static PyObject* Config_add_explicit_sleigh_dir(PyObject* self, PyObject* args)
{
    const char* dir = nullptr;
    if (!PyArg_ParseTuple(args, "s", &dir))
    {
        return NULL;
    }
    maat::MaatConfig::instance().add_explicit_sleigh_dir(std::string(dir));
    Py_RETURN_NONE;
}

static PyObject* Config_add_explicit_sleigh_file(PyObject* self, PyObject* args)
{
    const char* filepath = nullptr;
    if (!PyArg_ParseTuple(args, "s", &filepath))
    {
        return NULL;
    }
    maat::MaatConfig::instance().add_explicit_sleigh_file(std::string(filepath));
    Py_RETURN_NONE;
}

static PyMethodDef Config_methods[] = {
    {"add_explicit_sleigh_file", (PyCFunction)Config_add_explicit_sleigh_file, METH_VARARGS | METH_CLASS, "Add an explicit path to a sleigh specification file"},
    {"add_explicit_sleigh_dir", (PyCFunction)Config_add_explicit_sleigh_dir, METH_VARARGS | METH_CLASS, "Add an explicit directory where to look for sleigh specification files"},
    {NULL, NULL, 0, NULL}
};


static PyType_Slot Config_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(Config_dealloc)},
    {Py_tp_doc, const_cast<char*>("Maat global configuration")},
    {Py_tp_methods, Config_methods},
    {0, nullptr}
};

PyType_Spec BindingTypes::Config_spec = {
    "maat.MaatConfig", sizeof(Config_Object), 0, binding_type_flags, Config_slots
};


} // namespace py
} // namespace maat