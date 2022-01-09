#include "python_bindings.hpp"

namespace maat{
namespace py{

// ============== FileSystem =================
static void FileSystem_dealloc(PyObject* self)
{
    if (! as_fs_object(self).is_ref)
        delete ((FileSystem_Object*)self)->fs;
    ((FileSystem_Object*)self)->fs = nullptr;

    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* FileSystem_str(PyObject* self){
    std::stringstream res;
    res << *((FileSystem_Object*) self)->fs;
    return PyUnicode_FromString(res.str().c_str());
}

static int FileSystem_print(PyObject* self, void * io, int s){
    std::cout << *((FileSystem_Object*) self)->fs << std::flush;
    return 0;
}

static PyObject* FileSystem_repr(PyObject* self) {
    return FileSystem_str(self);
}

static PyObject* FileSystem_new_fa(PyObject* self, PyObject *args)
{
    const char* file;
    
    if( !PyArg_ParseTuple(args, "s", &file) ){
        return NULL;
    }
    try
    {
        env::filehandle_t handle = as_fs_object(self).fs->new_fa(std::string(file));
        return PyLong_FromLong((int)handle);
    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
};

static PyObject* FileSystem_get_fa_by_handle(PyObject* self, PyObject *args)
{
    int handle;
    
    if( !PyArg_ParseTuple(args, "i", &handle) )
    {
        return NULL;
    }
    try
    {
        env::FileAccessor& fa = as_fs_object(self).fs->get_fa_by_handle(handle);
        return PyFileAccessor_FromFileAccessor(&fa, true);
    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
};

static PyObject* FileSystem_delete_fa(PyObject* self, PyObject*args, PyObject* keywords)
{
    int handle;
    int weak = 0; // False by default

    char* keywd[] = {"", "weak", NULL};

    if( !PyArg_ParseTupleAndKeywords(args, keywords, "i|p", keywd, &handle, &weak))
    {
        return NULL;
    }
    try
    {
        as_fs_object(self).fs->delete_fa((env::filehandle_t)handle);
        Py_RETURN_NONE;
    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* FileSystem_get_file(PyObject* self, PyObject*args, PyObject* keywords)
{
    const char* filename;
    int follow_symlink = 1; // True by default

    char* keywd[] = {"", "follow_symlink", NULL};

    if( !PyArg_ParseTupleAndKeywords(args, keywords, "s|p", keywd, &filename, &follow_symlink))
    {
        return NULL;
    }
    try
    {
        env::physical_file_t file = as_fs_object(self).fs->get_file(
            std::string(filename),
            (bool)follow_symlink
        );
        if (file == nullptr)
        {
            return PyErr_Format(PyExc_RuntimeError, "Internal error getting physical file (got nullptr)");
        }
        return PyFile_FromPhysicalFile(file.get(), true);
    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
}

static PyObject* FileSystem_get_stdin_for_pid(PyObject* self, PyObject *args)
{
    int pid;
    
    if( !PyArg_ParseTuple(args, "i", &pid) )
    {
        return NULL;
    }
    try
    {
        std::string filename = as_fs_object(self).fs->get_stdin_for_pid(pid);
        return PyUnicode_FromString(filename.c_str());
    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
};

static PyMethodDef FileSystem_methods[] = {
    {"new_fa", (PyCFunction)FileSystem_new_fa, METH_VARARGS, "Create a new file accessor for a file"},
    {"get_fa_by_handle", (PyCFunction)FileSystem_get_fa_by_handle, METH_VARARGS, "Get a file accessor by handle"},
    {"delete_fa", (PyCFunction)FileSystem_delete_fa, METH_VARARGS | METH_KEYWORDS, "Remove a file accessor"},
    {"get_file", (PyCFunction)FileSystem_get_file, METH_VARARGS | METH_KEYWORDS, "Get a physical file"},
    {"get_stdin_for_pid", (PyCFunction)FileSystem_get_stdin_for_pid, METH_VARARGS, "Get the name of the stdin file for a given process"},
    {NULL, NULL, 0, NULL}
};

PyTypeObject FileSystem_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "FileSystem",                         /* tp_name */
    sizeof(FileSystem_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)FileSystem_dealloc,       /* tp_dealloc */
    (printfunc)FileSystem_print,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    FileSystem_repr,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    FileSystem_str,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Symbolic file-system emulator",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    FileSystem_methods,                      /* tp_methods */
    0,                                       /* tp_members */
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

// Constructor
PyObject* PyFileSystem_FromFileSystem(maat::env::FileSystem* fs, bool is_ref)
{
    FileSystem_Object* object;

    // Create object
    PyType_Ready(&FileSystem_Type);
    object = PyObject_New(FileSystem_Object, &FileSystem_Type);
    if (object != nullptr)
    {
        object->fs = fs;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}


// ============== FileAccessor =================
static void FileAccessor_dealloc(PyObject* self)
{
    if (! as_fileaccessor_object(self).is_ref)
        delete ((FileAccessor_Object*)self)->fa;
    ((FileAccessor_Object*)self)->fa = nullptr;

    Py_TYPE(self)->tp_free((PyObject *)self);
};

// buf must be list, returns NULL on success
PyObject* generic_buffer_translate(std::vector<Value>& native_buf, PyObject* buf)
{
    size_t val_size_hint = 8; // Size hint in bits for int values, to allow mixing Expr and int
    for (int i = 0; i < PyList_Size(buf); i++)
    {
        PyObject* val = PyList_GetItem(buf, i);
        if (PyObject_TypeCheck(val, (PyTypeObject*)get_Value_Type()))
        {
            native_buf.push_back(*as_value_object(val).value);
            val_size_hint = (*as_value_object(val).value).size();
        }
        else if (PyLong_Check(val))
        {
            native_buf.push_back(Value(val_size_hint, PyLong_AsLongLong(val)));
        }
        else
        {
            return PyErr_Format(PyExc_TypeError, "Buffer element %d is not an Expr not an int", i);
        }
    }
    return NULL;
}


static PyObject* FileAccessor_write_buffer(PyObject* self, PyObject *args)
{
    PyObject* buf;
    std::vector<Value> native_buf;
    const char* bytes;
    Py_ssize_t bytes_len = 0; 
    int len = -1;

    try
    {
        if (PyArg_ParseTuple(args, "s#|i", &bytes, &bytes_len, &len))
        {
            len = (len < 0)? bytes_len : len;
            return PyLong_FromLong(as_fileaccessor_object(self).fa->write_buffer((uint8_t*)bytes, len));
        }
        else if (PyArg_ParseTuple(args, "O!", &PyList_Type, &buf))
        {
            PyErr_Clear();
            PyObject* error = generic_buffer_translate(native_buf, buf);
            if (error != NULL)
                return error;
            return PyLong_FromLong(as_fileaccessor_object(self).fa->write_buffer(native_buf));
        }
        else
        {
            return PyErr_Format(PyExc_TypeError, "write_buffer(): parameters have wrong type");
        }
    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
};

static PyObject* FileAccessor_read_buffer(PyObject* self, PyObject* args)
{
    unsigned int nb_elems, elem_size=1;
    std::vector<Value> res;
    PyObject* list;

    if( !PyArg_ParseTuple(args, "I|I", &nb_elems, &elem_size)){
        return NULL;
    }

    try
    {
        as_fileaccessor_object(self).fa->read_buffer(res, nb_elems, elem_size);
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    // Translate expressions list into python list
    list = PyList_New(0);
    if( list == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const Value& val : res)
    {
        if( PyList_Append(list, PyValue_FromValue(val)) == -1)
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add expression to python list");
        }
    }
    return list;
}

static PyMethodDef FileAccessor_methods[] = {
    {"write_buffer", (PyCFunction)FileAccessor_write_buffer, METH_VARARGS, "Write a buffer to a file"},
    {"read_buffer", (PyCFunction)FileAccessor_read_buffer, METH_VARARGS | METH_KEYWORDS, "Read a buffer from a file"},
    {NULL, NULL, 0, NULL}
};

PyTypeObject FileAccessor_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "FileAccessor",                         /* tp_name */
    sizeof(FileAccessor_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)FileAccessor_dealloc,       /* tp_dealloc */
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
    "Wrapper to read/write emulated files",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    FileAccessor_methods,                      /* tp_methods */
    0,                                       /* tp_members */
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

// Constructor
PyObject* PyFileAccessor_FromFileAccessor(maat::env::FileAccessor* fa, bool is_ref)
{
    FileAccessor_Object* object;

    // Create object
    PyType_Ready(&FileAccessor_Type);
    object = PyObject_New(FileAccessor_Object, &FileAccessor_Type);
    if (object != nullptr)
    {
        object->fa = fa;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}


// ============== PhysicalFile =================
static void File_dealloc(PyObject* self)
{
    if (! as_file_object(self).is_ref)
        delete ((File_Object*)self)->file;
    ((File_Object*)self)->file = nullptr;

    Py_TYPE(self)->tp_free((PyObject *)self);
};


static PyObject* File_write_buffer(PyObject* self, PyObject *args)
{
    PyObject* buf;
    std::vector<Value> native_buf;
    addr_t offset = 0;
    const char* bytes;
    Py_ssize_t bytes_len = 0;
    int len = -1;

    try
    {
        if (PyArg_ParseTuple(args, "s#K|i", &bytes, &bytes_len, &offset, &len))
        {
            PyErr_Clear();
            len = (len < 0)? bytes_len : len;
            return PyLong_FromLong(as_file_object(self).file->write_buffer((uint8_t*)bytes, offset, len));
        }
        else if (PyArg_ParseTuple(args, "O!K", &PyList_Type, &buf, &offset))
        {
            PyErr_Clear();
            PyObject* error = generic_buffer_translate(native_buf, buf);
            if (error != NULL)
                return error;
            return PyLong_FromLong(as_file_object(self).file->write_buffer(native_buf, offset));
        }
        else
        {
            return PyErr_Format(PyExc_TypeError, "write_buffer(): parameters have wrong type");
        }

    }
    catch (const env_exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
};

static PyObject* File_read_buffer(PyObject* self, PyObject* args)
{
    unsigned int nb_elems, elem_size=1;
    std::vector<Value> res;
    PyObject* list;
    addr_t offset = 0;

    if( !PyArg_ParseTuple(args, "KI|I", &offset, &nb_elems, &elem_size))
    {
        return NULL;
    }

    try
    {
        as_file_object(self).file->read_buffer(res, offset, nb_elems, elem_size);
    }
    catch(const std::exception& e)
    {
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    // Translate expressions list into python list
    list = PyList_New(0);
    if( list == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to create new python list");
    }
    for (const Value& val : res)
    {
        if( PyList_Append(list, PyValue_FromValue(val)) == -1)
        {
            return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to add expression to python list");
        }
    }
    return list;
}

static PyMethodDef File_methods[] = {
    {"write_buffer", (PyCFunction)File_write_buffer, METH_VARARGS, "Write a buffer to a file"},
    {"read_buffer", (PyCFunction)File_read_buffer, METH_VARARGS | METH_KEYWORDS, "Read a buffer from a file"},
    {NULL, NULL, 0, NULL}
};

PyTypeObject File_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "File",                         /* tp_name */
    sizeof(File_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)File_dealloc,       /* tp_dealloc */
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
    "Physical emulated file",                 /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    File_methods,                      /* tp_methods */
    0,                                       /* tp_members */
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

// Constructor
PyObject* PyFile_FromPhysicalFile(maat::env::PhysicalFile* file, bool is_ref)
{
    File_Object* object;

    // Create object
    PyType_Ready(&File_Type);
    object = PyObject_New(File_Object, &File_Type);
    if (object != nullptr)
    {
        object->file = file;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

}
}
