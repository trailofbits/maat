#include "python_bindings.hpp"

namespace maat{
namespace py{
    
// ============= MemEngine ===============

static void MemEngine_dealloc(PyObject* self){
    if( ! as_mem_object(self).is_ref){
        delete ((MemEngine_Object*)self)->mem;
    }
    as_mem_object(self).mem = nullptr;
    free_binding_object(self);
};

static PyObject* MemEngine_str(PyObject* self){
    std::stringstream res;
    res << *((MemEngine_Object*) self)->mem;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* MemEngine_repr(PyObject* self) {
    return MemEngine_str(self);
}

static PyObject* MemEngine_map(PyObject* self, PyObject* args, PyObject* keywords) {
    unsigned long long start, end;
    unsigned short flags = maat::mem_flag_rwx;
    char* name = NULL;
    std::string name_str;

    char* keywds[] = {"", "", "flags", "name", NULL};
    
    if( !PyArg_ParseTupleAndKeywords(args, keywords, "KK|Hs", keywds, &start, &end, &flags, &name)){
        return NULL;
    }

    if( name != NULL){
        name_str = std::string(name);
    }

    try{
        as_mem_object(self).mem->map(start, end, flags, name_str);
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    Py_RETURN_NONE;
}

static PyObject* MemEngine_read(PyObject* self, PyObject* args) {
    unsigned int nb_bytes;
    Value res;
    PyObject* addr = nullptr;
    
    if(PyArg_ParseTuple(args, "OI", &addr, &nb_bytes)){
        if( PyObject_TypeCheck(addr, binding_types().Value) ){
            try{
                // Handles both symbolic and concrete addresses
                res = as_mem_object(self).mem->read(*(as_value_object(addr).value), nb_bytes);
            }catch(const mem_exception& e){
                return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
            }
        }else if(PyLong_Check(addr)){
            try{
                as_mem_object(self).mem->read(res, PyLong_AsUnsignedLongLong(addr), nb_bytes);
            }catch(const mem_exception& e){
                return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
            }
        }else{
            return PyErr_Format(PyExc_TypeError, "%s", "read(): first argument must be int or Expr");
        }
    }else{
        return NULL;
    }
    return PyValue_FromValue(res);
}


static PyObject* MemEngine_read_buffer(PyObject* self, PyObject* args) {
    PyObject* addr;
    unsigned int nb_elems, elem_size=1;
    std::vector<Value> res;

    if( !PyArg_ParseTuple(args, "OI|I", &addr, &nb_elems, &elem_size)){
        return NULL;
    }

    if( PyObject_TypeCheck(addr, binding_types().Value) ){
        try{
            res = as_mem_object(self).mem->read_buffer(*(as_value_object(addr).value), nb_elems, elem_size);
        }catch(mem_exception e){
            return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
        }
    }else if(PyLong_Check(addr)){
        try{
            res = as_mem_object(self).mem->read_buffer(PyLong_AsUnsignedLongLong(addr), nb_elems, elem_size);
        }catch(mem_exception e){
            return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
        }
    }else{
        return PyErr_Format(PyExc_TypeError, "%s", "read_buffer(): first argument must be int or Expr");
    }

    return native_to_py(res);
}

static PyObject* MemEngine_read_str(PyObject* self, PyObject* args) {
    PyObject* addr;
    unsigned int len=0;
    std::string res;
    PyObject* bytes;
    
    if( !PyArg_ParseTuple(args, "O|I", &addr, &len)){
        return NULL;
    }

    if( PyObject_TypeCheck(addr, binding_types().Value) ){
        try{
            res = as_mem_object(self).mem->read_string(*(as_value_object(addr).value), len );
        }catch(const mem_exception& e){
            return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
        }
    }else if(PyLong_Check(addr)){
        try{
            res = as_mem_object(self).mem->read_string(PyLong_AsUnsignedLongLong(addr), len);
        }catch(const mem_exception& e){
            return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
        }
    }else{
        return PyErr_Format(PyExc_TypeError, "%s", "read_string(): first argument must be int or Expr");
    }

    // Translate string into python bytes
    bytes = PyBytes_FromStringAndSize(res.c_str(), res.size());
    if( bytes == NULL ){
        return PyErr_Format(PyExc_RuntimeError, "%s", "Failed to translate string to python bytes");
    }

    return bytes;
}


static PyObject* MemEngine_write(PyObject* self, PyObject* args, PyObject* keywords)
{
    addr_t concrete_addr;
    PyObject* addr = nullptr;
    Value val_addr;
    Expr e = nullptr;
    char * data = nullptr;
    Py_ssize_t data_len;
    PyObject* arg2 = nullptr;
    PyObject* arg3 = nullptr;
    int ignore_flags = 0; // Default False 

    char * keywds[] = {"", "", "", "ignore_flags", NULL};

    if( !PyArg_ParseTupleAndKeywords(args, keywords, "OO|Op", keywds, &addr, &arg2, &arg3, &ignore_flags)){
        return NULL;
    }

    // Check addr first
    if( PyLong_Check(addr)){
        concrete_addr = PyLong_AsUnsignedLongLong(addr);
    }else if( PyObject_TypeCheck(addr, binding_types().Value)){
        val_addr = *(as_value_object(addr).value);
    }else{
        return PyErr_Format(PyExc_TypeError, "MemEngine.write(): address must be 'int' or 'Expr'"); 
    }

    try{
        // Check arguments types, function is overloaded
        // (addr, expr)
        if( PyObject_TypeCheck(arg2, binding_types().Value) ){
            if (not val_addr.is_none())
                as_mem_object(self).mem->write(val_addr, *(as_value_object(arg2).value), (bool)ignore_flags);
            else
                as_mem_object(self).mem->write(concrete_addr, *(as_value_object(arg2).value), nullptr, false, (bool)ignore_flags);
        // (addr, cst, nb_bytes)
        }else if(arg3 != nullptr && PyLong_Check(arg2) && PyLong_Check(arg3)){
            if (not val_addr.is_none())
                as_mem_object(self).mem->write(
                    val_addr,
                    PyLong_AsLongLong(arg2),
                    PyLong_AsUnsignedLong(arg3),
                    (bool)ignore_flags
                );
            else
                as_mem_object(self).mem->write(
                    concrete_addr,
                    PyLong_AsLongLong(arg2),
                    PyLong_AsUnsignedLong(arg3),
                    (bool)ignore_flags
                );
        // (addr, buffer, nb_bytes)
        }else if( PyBytes_Check(arg2) ){
            PyBytes_AsStringAndSize(arg2, &data, &data_len);
            if( arg3 != nullptr){
                if( !PyLong_Check(arg3)){
                    return PyErr_Format(PyExc_TypeError, "MemEngine.write(): 3rd argument must be int");
                }
                // Optional length argument, parse it
                if(PyLong_AsSsize_t(arg3) < data_len){
                    data_len = PyLong_AsSsize_t(arg3);
                }
            }
            if (not val_addr.is_none())
                as_mem_object(self).mem->write_buffer(
                    val_addr,
                    (uint8_t*)data,
                    (unsigned int)data_len,
                    (bool)ignore_flags
                );
            else
                as_mem_object(self).mem->write_buffer(
                    concrete_addr,
                    (uint8_t*)data,
                    (unsigned int)data_len,
                    (bool)ignore_flags
                );
        }else{
            return PyErr_Format(PyExc_TypeError, "MemEngine.write(): got wrong types for arguments");
        }
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    Py_RETURN_NONE;
}

PyObject* MemEngine_make_concolic(PyObject* self, PyObject* args){
    unsigned long long addr;
    unsigned int nb_elems, elem_size;
    char * name = "";
    std::string res_name;
    
    if( ! PyArg_ParseTuple(args, "KIIs", &addr, &nb_elems, &elem_size, &name)){
        return NULL;
    }

    try{
        res_name = as_mem_object(self).mem->make_concolic(addr, nb_elems, elem_size, std::string(name));
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    return PyUnicode_FromString(res_name.c_str());
}


PyObject* MemEngine_make_symbolic(PyObject* self, PyObject* args){
    unsigned long long addr;
    unsigned int nb_elems, elem_size;
    char * name = "";
    std::string res_name;
    
    if( ! PyArg_ParseTuple(args, "KIIs", &addr, &nb_elems, &elem_size, &name)){
        return NULL;
    }

    try{
        res_name = as_mem_object(self).mem->make_symbolic(addr, nb_elems, elem_size, std::string(name));
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    return PyUnicode_FromString(res_name.c_str());
}


static PyMethodDef MemEngine_methods[] = {
    {"map", (PyCFunction)MemEngine_map, METH_VARARGS | METH_KEYWORDS, "Map a memory region"},
    {"read", (PyCFunction)MemEngine_read, METH_VARARGS, "Reads memory into an expression"},
    {"read_buffer", (PyCFunction)MemEngine_read_buffer, METH_VARARGS, "Reads a buffer in memory"},
    {"read_str", (PyCFunction)MemEngine_read_str, METH_VARARGS, "Reads a concrete string in memory"},
    {"write", (PyCFunction)MemEngine_write, METH_VARARGS | METH_KEYWORDS, "Write a value/expression/buffer into memory"},
    {"make_concolic", (PyCFunction)MemEngine_make_concolic, METH_VARARGS, "Make a memory area concolic"},
    {"make_symbolic", (PyCFunction)MemEngine_make_symbolic, METH_VARARGS, "Make a memory area purely symbolic"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef MemEngine_members[] = {
    {NULL}
};

static PyType_Slot MemEngine_slots[] = {
    {Py_tp_dealloc, reinterpret_cast<void*>(MemEngine_dealloc)},
    {Py_tp_repr, reinterpret_cast<void*>(MemEngine_repr)},
    {Py_tp_str, reinterpret_cast<void*>(MemEngine_str)},
    {Py_tp_doc, const_cast<char*>("Memory engine")},
    {Py_tp_methods, MemEngine_methods},
    {Py_tp_members, MemEngine_members},
    {0, nullptr}
};

PyType_Spec BindingTypes::MemEngine_spec = {
    "maat.MemEngine", sizeof(MemEngine_Object), 0, binding_type_flags, MemEngine_slots
};

/* Constructors */
PyObject* PyMemEngine_FromMemEngine(MemEngine* mem, bool is_ref)
{
    MemEngine_Object* object;
    
    // Create object
    object = PyObject_New(MemEngine_Object, binding_types().MemEngine);
    if( object != nullptr ){
        object->mem = mem;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

void init_memory(PyObject* module)
{
    /* MEM enum */
    PyObject* mem_enum = PyDict_New();
    PyDict_SetItemString(mem_enum, "R", PyLong_FromLong(maat::mem_flag_r));
    PyDict_SetItemString(mem_enum, "W", PyLong_FromLong(maat::mem_flag_w));
    PyDict_SetItemString(mem_enum, "X", PyLong_FromLong(maat::mem_flag_x));
    PyDict_SetItemString(mem_enum, "RW", PyLong_FromLong(maat::mem_flag_rw));
    PyDict_SetItemString(mem_enum, "RX", PyLong_FromLong(maat::mem_flag_rx));
    PyDict_SetItemString(mem_enum, "WX", PyLong_FromLong(maat::mem_flag_wx));
    PyDict_SetItemString(mem_enum, "RWX", PyLong_FromLong(maat::mem_flag_rwx));
    PyObject* perm_class = create_class(PyUnicode_FromString("PERM"), PyTuple_New(0), mem_enum);
    PyModule_AddObject(module, "PERM", perm_class);
};

} // namespace py
} // namespace maat
