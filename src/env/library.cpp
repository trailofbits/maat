#include "env/library.hpp"
#include "engine.hpp"

namespace maat
{
namespace env
{

FunctionCallback::FunctionCallback()
{
    // TODO python callback = nullptr;
}

FunctionCallback::FunctionCallback(const args_spec_t& args, FunctionCallback::native_cb_t callback)
:native_callback(callback), args_spec(args) // TODO python_callback = nullptr
{}

FunctionCallback::~FunctionCallback()
{
    // TODO PyDecREF Python callback if any
}

Action FunctionCallback::execute(MaatEngine& engine, const abi::ABI& abi) const
{
    if (native_callback != nullptr)
        return _execute_native(engine, abi);
    else
        return _execute_python(engine, abi);
}

Action FunctionCallback::_execute_native(MaatEngine& engine, const abi::ABI& abi) const
{
    std::vector<Expr> args;
    try
    {
        abi.get_args(engine, args_spec, args);
        return_t ret_value = native_callback(engine, args);
        abi.set_ret_value(engine, ret_value);
        abi.ret(engine);
        return Action::CONTINUE;
    }
    catch(const std::exception& e)
    {
        engine.log.error("Error executing emulation callback: ", e.what());
        return Action::ERROR;
    }
}

Action FunctionCallback::_execute_python(MaatEngine& engine, const abi::ABI& abi) const
{
    throw runtime_exception("FunctionCallback::_execute_python(): not implemented!");
}

Function::Function():
_callback(std::nullopt),
_names{},
_ir_block(nullptr),
_raw{}
{}

Function::Function(const std::string& name, const FunctionCallback& callback)
: _type(Function::Type::CALLBACK), _callback(callback),
_ir_block(std::nullopt), _raw(std::nullopt)
{
    _names = std::vector<std::string>{name};
}

Function::Function(const Function::names_t& n, const FunctionCallback& callback)
:_type(Function::Type::CALLBACK), _callback(callback), _names(n),
_ir_block(std::nullopt), _raw(std::nullopt)
{}

Function::Function(const Function::names_t& n, std::shared_ptr<ir::AsmInst> block)
:_type(Function::Type::IR), _ir_block(block), _names(n),
_callback(std::nullopt), _raw(std::nullopt)
{}

Function::Function(const Function::names_t& n, const std::vector<uint8_t>& raw)
:_type(Function::Type::RAW), _raw(raw), _names(n),
_callback(std::nullopt), _ir_block(std::nullopt)
{}

Function::Function(const Function& other):
_type(other._type),
_callback(other._callback),
_names(other._names),
_ir_block(other._ir_block),
_raw(other._raw)
{
}

Function& Function::operator=(const Function& other)
{
    _type = other._type;
    _callback = other._callback;
    _names = other._names;
    _ir_block = other._ir_block;
    _raw = other._raw;
    return *this;
}


Function::Type Function::type() const
{
    return _type;
}

const FunctionCallback& Function::callback() const
{
    if (_type == Function::Type::CALLBACK and _callback.has_value())
        return _callback.value();
    else
        throw env_exception("Function::callback() called on function that has no callback!");
}

const std::shared_ptr<ir::AsmInst>& Function::ir() const
{
    if (_type == Function::Type::IR and _ir_block.has_value())
        return _ir_block.value();
    else
        throw env_exception("Function::ir() called on function that has no IR block!");
}

const std::vector<std::string>& Function::names() const
{
    return _names;
}

const std::string& Function::name() const
{
    return _names.at(0);
}

const bool Function::has_name(const std::string& name) const
{
    return std::find(_names.begin(), _names.end(), name) != _names.end();
}



Data::Data(std::string name, const std::vector<uint8_t>& data):
_data(data), _names{name}
{}

const std::vector<std::string>& Data::names() const
{
    return _names;
}

const std::vector<uint8_t>& Data::data() const
{
    return _data;
}

const std::string& Data::name() const
{
    return _names.at(0); // at() will check for OOB access
}

const bool Data::has_name(const std::string& name) const
{
    for (const auto& n : _names)
        if (n == name)
            return true;
    return false;
}





Library::Library(const std::string& name): _name(name) {}

Library::Library(
    const std::string& name,
    const std::vector<Function>& functions,
    const std::vector<Data>& exported_data
)
: _name(name), _functions(functions), _data(exported_data)
{}

Library::Library(Library&& other)
{
    _name = other._name;
    _functions = std::move(other._functions);
    _data = std::move(other._data);
}

const std::string& Library::name() const
{
    return _name;
}

void Library::add_function(const Function& function)
{
    for (auto& func : _functions)
        if (func.has_name(function.name()))
        {
            func = function;
            return;
        }
    _functions.push_back(function);
}

void Library::add_data(const Data& data)
{
    for (auto& d : _data)
        if (d.has_name(data.name()))
        {
            d = data;
            return;
        }
    _data.push_back(data);
}

const Function& Library::get_function_by_name(const std::string& name) const
{
    for (auto& func : _functions)
        if (func.has_name(name))
        {
            return func;
        }
    throw env_exception(
        Fmt() << "Library::get_function_by_name(): no function named " << name
        >> Fmt::to_str
    );
}

const Function& Library::get_function_by_num(int num) const
{
    if (num < 0 or num >= _functions.size())
        throw env_exception("Library::get_function_by_num(): called with invalid function num!");
    return _functions.at(num);
}

const std::vector<Function>& Library::functions() const
{
    return _functions;
}

const std::vector<Data>& Library::data() const
{
    return _data;
}

const Data& Library::get_data_by_name(const std::string& name) const
{
    for (auto& d : _data)
        if (d.has_name(name))
        {
            return d;
        }
    throw env_exception(
        Fmt() << "Library::get_data_by_name(): no exported data named " << name
        >> Fmt::to_str
    );
}

size_t Library::total_data_size() const
{
    size_t res = 0;
    for (auto& d : _data)
        res += d.data().size();
    return res;
}

} // namespace env
} // namespace maat
