#include "python_bindings.hpp"

namespace maat{
namespace py{

void init_env(PyObject* module)
{
    // OS enum
    PyObject* os_enum = PyDict_New();
    PyDict_SetItemString(os_enum, "LINUX", PyLong_FromLong((int)env::OS::LINUX));
    PyDict_SetItemString(os_enum, "NONE", PyLong_FromLong((int)env::OS::NONE));
    PyObject* os_class = create_class(PyUnicode_FromString("OS"), PyTuple_New(0), os_enum);
    PyModule_AddObject(module, "OS", os_class);
};

}
}
