#include "python_bindings.hpp"

namespace maat{
namespace py{

// ============= MaatEngine ==================

static void MaatEngine_dealloc(PyObject* self)
{
    delete ((MaatEngine_Object*)self)->engine;  ((MaatEngine_Object*)self)->engine = nullptr;
    Py_DECREF(as_engine_object(self).mem);
    Py_DECREF(as_engine_object(self).info);
    Py_DECREF(as_engine_object(self).cpu);
    Py_DECREF(as_engine_object(self).vars);    
    Py_DECREF(as_engine_object(self).hooks);    
    Py_DECREF(as_engine_object(self).path);
    Py_DECREF(as_engine_object(self).env);

    /* TODO deref stats, logger */
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* MaatEngine_run(PyObject* self, PyObject* args){
    unsigned int max_instr = 0;
    info::Stop res;
    
    if( ! PyArg_ParseTuple(args, "|I", &max_instr) ){
        return NULL;
    }
    try{
        res = as_engine_object(self).engine->run(max_instr);
    }catch(symbolic_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "Fatal error: Maat failed with the following error: %s\n ", e.what());
    }
    return PyLong_FromLong((int)res);
};

static PyObject* MaatEngine_run_from(PyObject* self, PyObject* args){
    unsigned long long addr;
    unsigned int max_instr = 0;
    info::Stop res;
    
    if( ! PyArg_ParseTuple(args, "K|I", &addr, &max_instr) ){
        return NULL;
    }
    try{ 
        res = as_engine_object(self).engine->run_from(addr, max_instr);
    }catch(symbolic_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "Fatal error: Maat failed with the following error: %s\n ", e.what());
    }
    return PyLong_FromLong((int)res);
};


static PyObject* MaatEngine_take_snapshot(PyObject* self){
    unsigned int snap_id;
    
    snap_id = as_engine_object(self).engine->take_snapshot();
    return PyLong_FromLong(snap_id);
};

static PyObject* MaatEngine_restore_snapshot(PyObject* self, PyObject* args, PyObject* keywords){
    int id = -1;
    int remove = 0;
    static char *kwlist[] = {"", "remove", NULL};

    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "|ip", kwlist, &id, &remove) ){
        return NULL;
    }

    try{
        if (id == -1)
        {
            as_engine_object(self).engine->restore_last_snapshot((bool)remove);
        }
        else
        {
            as_engine_object(self).engine->restore_snapshot((MaatEngine::snapshot_t)id, (bool)remove);
        }
    }catch(snapshot_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    
    Py_RETURN_NONE;
};

static PyObject* MaatEngine_load(PyObject* self, PyObject* args, PyObject* keywords){
    char * name;
    int bin_type;
    unsigned long long base = 0;
    PyObject* py_cmdline_args = nullptr, *arg = nullptr;
    PyObject *py_envp = nullptr;
    PyObject* py_libs = nullptr, *lib = nullptr;
    PyObject* py_ignore_libs = nullptr;
    std::vector<loader::CmdlineArg> cmdline_args;
    std::list<std::string> lib_paths, ignore_libs;
    loader::environ_t envp;
    char *virtual_path = "";
    int load_interp = 1; // True by default
    Py_ssize_t i;

    // TODO ADD envp argument as option
    char* keywd[] = {"", "", "base", "args", "envp", "libdirs", "ignore_libs", "virtual_path", "load_interp", NULL};

    if( !PyArg_ParseTupleAndKeywords(
            args, keywords, "si|KOOOOsp", keywd,
            &name, &bin_type, &base, 
            &py_cmdline_args, &py_envp,
            &py_libs, &py_ignore_libs,
            &virtual_path, &load_interp
        )
    )
    {
        return NULL;
    }

    // Build args vector
    if (py_cmdline_args != nullptr)
    {
        // Check if it's a list
        if (!PyList_Check(py_cmdline_args))
        {
            return PyErr_Format(PyExc_TypeError, "'args' parameter must be a list");
        }
        for (i = 0; i < PyList_Size(py_cmdline_args); i++)
        {
            arg = PyList_GetItem(py_cmdline_args, i);
            if(!PyObject_TypeCheck(arg, (PyTypeObject*)get_CmdlineArg_Type()))
            {
                return PyErr_Format(PyExc_TypeError, "Wrong type for command line argument %d", i);
            }
            cmdline_args.push_back(*(as_arg_object(arg).arg));
        }
    }

    // Build lib paths list
    if (py_libs != nullptr)
    {
        // Check if it's a list
        if( !PyList_Check(py_libs) )
        {
            return PyErr_Format(PyExc_TypeError, "'libs' parameter must be a list");
        }
        for( i = 0; i < PyList_Size(py_libs); i++)
        {
            lib = PyList_GetItem(py_libs, i);
            if(!PyUnicode_Check(lib))
            {
                return PyErr_Format(PyExc_TypeError, "'libs' parameter contains a non-'str' element");
            }
            lib_paths.push_back(std::string(PyUnicode_AsUTF8(lib)));
        }
    }

    // Build ignore_libs list
    if (py_ignore_libs != nullptr)
    {
        // Check if it's a list
        if( !PyList_Check(py_ignore_libs) )
        {
            return PyErr_Format(PyExc_TypeError, "'ignore_libs' parameter must be a list");
        }
        for( i = 0; i < PyList_Size(py_ignore_libs); i++)
        {
            lib = PyList_GetItem(py_ignore_libs, i);
            if(!PyUnicode_Check(lib))
            {
                return PyErr_Format(PyExc_TypeError, "'ignore_libs' parameter contains a non-'str' element");
            }
            ignore_libs.push_back(std::string(PyUnicode_AsUTF8(lib)));
        }
    }

    // Build envp map
    if (py_envp != nullptr)
    {
        // Check if it's a dict
        if( !PyDict_Check(py_envp) )
        {
            return PyErr_Format(PyExc_TypeError, "'envp' parameter must be a dict");
        }
        PyObject *key, *value;
        Py_ssize_t pos = 0;
        while (PyDict_Next(py_envp, &pos, &key, &value))
        {
            if (not PyUnicode_Check(key))
            {
                return PyErr_Format(PyExc_TypeError, "'envp' keys must be str");
            }
            if (not PyUnicode_Check(value))
            {
                return PyErr_Format(PyExc_TypeError, "'envp' values must be str");
            }
            const char *key_str, *value_str;
            key_str = PyUnicode_AsUTF8(key);
            value_str = PyUnicode_AsUTF8(value);
            envp[std::string(key_str)] = std::string(value_str);
        }
    }

    try
    {
        as_engine_object(self).engine->load(
            name,
            (loader::Format)bin_type,
            (addr_t)base,
            cmdline_args,
            envp,
            std::string(virtual_path),
            lib_paths,
            ignore_libs,
            load_interp
        );
    }
    catch(std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }

    Py_RETURN_NONE;
};


static PyMethodDef MaatEngine_methods[] = {
    {"run", (PyCFunction)MaatEngine_run, METH_VARARGS, "Continue to run code from current location"},
    {"run_from", (PyCFunction)MaatEngine_run_from, METH_VARARGS, "Run code from a given address"},
    {"take_snapshot", (PyCFunction)MaatEngine_take_snapshot, METH_NOARGS, "Take a snapshot of the symbolic engine"},
    {"restore_snapshot", (PyCFunction)MaatEngine_restore_snapshot, METH_VARARGS | METH_KEYWORDS, "Restore a snapshot of the symbolic engine"},
    {"load", (PyCFunction)MaatEngine_load, METH_VARARGS | METH_KEYWORDS, "Load an executable"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef MaatEngine_members[] = {
    {"vars", T_OBJECT_EX, offsetof(MaatEngine_Object, vars), READONLY, "Symbolic Variables Context"},
    {"cpu", T_OBJECT_EX, offsetof(MaatEngine_Object, cpu), READONLY, "Emulated CPU"},
    {"mem", T_OBJECT_EX, offsetof(MaatEngine_Object, mem), READONLY, "Memory Engine"},
    {"hooks", T_OBJECT_EX, offsetof(MaatEngine_Object, hooks), READONLY, "Event Hooks Manager"},
    {"info", T_OBJECT_EX, offsetof(MaatEngine_Object, info), READONLY, "Symbolic Engine Info"},
    {"path", T_OBJECT_EX, offsetof(MaatEngine_Object, path), READONLY, "Path Manager"},
    {"env", T_OBJECT_EX, offsetof(MaatEngine_Object, env), READONLY, "Environment Manager"},
    //{"stats", T_OBJECT_EX, offsetof(MaatEngine_Object, stats), READONLY, "Runtime statistics"},
    {"settings", T_OBJECT_EX, offsetof(MaatEngine_Object, settings), READONLY, "Symbolic Engine Settings"},
    {"process", T_OBJECT_EX, offsetof(MaatEngine_Object, process), READONLY, "Process Info"},
    {NULL}
};

PyTypeObject MaatEngine_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "MaatEngine",                         /* tp_name */
    sizeof(MaatEngine_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)MaatEngine_dealloc,       /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Dynamic Symbolic Execution Engine",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    MaatEngine_methods,                   /* tp_methods */
    MaatEngine_members,                   /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_MaatEngine_Type(){
    return (PyObject*)&MaatEngine_Type;
};

/* Constructor */
PyObject* maat_MaatEngine(PyObject* self, PyObject* args){
    MaatEngine_Object* object;
    int arch;
    int system = (int)env::OS::NONE;

    // Parse arguments
    if( ! PyArg_ParseTuple(args, "i|i", &arch, &system) ){
        return NULL;
    }

    // Create object
    try
    {
        PyType_Ready(&MaatEngine_Type);
        object = PyObject_New(MaatEngine_Object, &MaatEngine_Type);
        if (object != nullptr)
        {
            object->engine = new MaatEngine((Arch::Type)arch, (env::OS)system);
            object->engine->self_python_wrapper_object = (PyObject*)object;
            // Create wrappers with references to members
            object->vars = PyVarContext_FromVarContext(object->engine->vars.get(), true);
            object->cpu = PyCPU_FromCPUAndArchAndVarContext(
                &object->engine->cpu,
                true,
                object->engine->arch.get(),
                object->engine->vars
            );
            object->mem = PyMemEngine_FromMemEngine(object->engine->mem.get(), true);
            object->hooks = PyEventManager_FromEventManager(&(object->engine->hooks), true);
            object->info = PyInfo_FromInfoAndArch(&(object->engine->info), true, &(*object->engine->arch));
            object->path = PyPath_FromPath(&(object->engine->path), true);
            object->env = PyEnv_FromEnvEmulator(object->engine->env.get(), true);
            // TODO object->stats = PyStats_FromMaatEngineStats(&(object->engine->stats), true);
            // TODO: object->log ....
            object->settings = PySettings_FromSettings(&(object->engine->settings), true);
            object->process = PyProcessInfo_FromProcessInfo(object->engine->process.get(), true);
        }
    }
    catch(std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return (PyObject*)object;
}


/* ------------------------------------
 *          Init function
 * ------------------------------------ */
void init_engine(PyObject* module)
{
    /* STOP enum */
    PyObject* stop_enum = PyDict_New();
    PyDict_SetItemString(stop_enum, "HOOK", PyLong_FromLong((int)info::Stop::HOOK));
    PyDict_SetItemString(stop_enum, "SYMBOLIC_PC", PyLong_FromLong((int)info::Stop::SYMBOLIC_PC));
    PyDict_SetItemString(stop_enum, "SYMBOLIC_CODE", PyLong_FromLong((int)info::Stop::SYMBOLIC_CODE));
    PyDict_SetItemString(stop_enum, "MISSING_FUNCTION", PyLong_FromLong((int)info::Stop::MISSING_FUNCTION));
    PyDict_SetItemString(stop_enum, "MISSING_SYSCALL", PyLong_FromLong((int)info::Stop::MISSING_SYSCALL));
    PyDict_SetItemString(stop_enum, "EXIT", PyLong_FromLong((int)info::Stop::EXIT));
    PyDict_SetItemString(stop_enum, "INST_COUNT", PyLong_FromLong((int)info::Stop::INST_COUNT));
    PyDict_SetItemString(stop_enum, "ILLEGAL_INST", PyLong_FromLong((int)info::Stop::ILLEGAL_INST));
    PyDict_SetItemString(stop_enum, "UNSUPPORTED_INST", PyLong_FromLong((int)info::Stop::UNSUPPORTED_INST));
    PyDict_SetItemString(stop_enum, "ARITHMETIC_ERROR", PyLong_FromLong((int)info::Stop::ARITHMETIC_ERROR));
    PyDict_SetItemString(stop_enum, "ERROR", PyLong_FromLong((int)info::Stop::ERROR));
    PyDict_SetItemString(stop_enum, "FATAL", PyLong_FromLong((int)info::Stop::FATAL));
    PyDict_SetItemString(stop_enum, "NONE", PyLong_FromLong((int)info::Stop::NONE));
    PyObject* stop_class = create_class(PyUnicode_FromString("STOP"), PyTuple_New(0), stop_enum);
    PyModule_AddObject(module, "STOP", stop_class);
};
    
} // namespace py
} // namespace maat
