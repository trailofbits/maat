#include "varcontext.hpp"
#include "expression.hpp"
#include "value.hpp"

namespace maat
{

// Var Context implementation
/* ====================================== */
unsigned int VarContext::_id_cnt = 0;

VarContext::VarContext(unsigned int i): id(i)
{
    if(id == 0)
        id = ++(VarContext::_id_cnt);
}

void VarContext::set(const std::string& name, cst_t value)
{
    varmap[name] = Number(64);
    varmap[name].set_cst(value);
    id = ++(VarContext::_id_cnt);
}

void VarContext::set(const std::string& name, const Number& number)
{
    varmap[name] = number;
    id = ++(VarContext::_id_cnt);
}

cst_t VarContext::get(const std::string& name) const
{
    std::map<std::string, maat::Number>::const_iterator it;
    if((it = varmap.find(name)) == varmap.end())
    {
        throw var_context_exception(Fmt()
            << "Trying to access variable '" 
            << name << "' which is unknown in context"
            >> Fmt::to_str);
    }
    if (it->second.size > 64)
    {
        throw var_context_exception(Fmt()
            << "Trying to get variable '" 
            << name << "' as native integer but its value is on more than 64 bits"
            >> Fmt::to_str);
    }

    return it->second.cst_;
}

const maat::Number& VarContext::get_as_number(const std::string& name) const
{
    std::map<std::string, maat::Number>::const_iterator it;
    if((it = varmap.find(name)) == varmap.end())
    {
        throw var_context_exception(Fmt()
            << "Trying to access variable '" 
            << name << "' which is unknown in context"
            >> Fmt::to_str);
    }
    return it->second;
}

std::vector<uint8_t> VarContext::get_as_buffer(std::string name, unsigned int elem_size) const
{
    int i = 0;
    bool stop = false;
    std::string var_name;
    std::vector<uint8_t> res;
    while( !stop )
    {
        std::stringstream ss;
        ss << name << "_" << std::dec << i;
        var_name = ss.str();
        if( ! contains(var_name))
        {
            stop = true;
        }
        else
        {
            for( ucst_t j = 0; j < elem_size; j++ )
            {
                // Assume little endian
                res.push_back((uint8_t)((get(var_name) >> (j*8)) & 0xff));
            }
            i++;
        }
    }
    return res;
}

std::string VarContext::get_as_string(std::string name) const
{
    int i = 0;
    bool stop = false;
    std::string var_name;
    std::string res;
    ucst_t c;
    while( !stop )
    {
        std::stringstream ss;
        ss << name << "_" << std::dec << i;
        var_name = ss.str();
        if( ! contains(var_name))
        {
            stop = true;
        }
        else
        {
            c = (ucst_t)get(var_name) & 0xff;
            res += (char)c;
            if( c == 0 )
                stop = true;
            i++;
        }
    }
    return res;
}

bool VarContext::contains(const std::string& name) const
{
    return varmap.find(name) != varmap.end(); 
}

std::string VarContext::new_name_from(const std::string& name) const
{
    std::stringstream ss;
    if( name.empty() )
    {
        throw var_context_exception(Fmt()
            << "VarContext::new_name_from(): Got empty name "
            << name
            >> Fmt::to_str);
    }

    // If name available return it
    if( !contains(name))
    {
        std::string res = name;
        return res; // Return rvalue reference
    }
    // If not, add some _1, _2, _3, ... after it
    for( int i = 1; i < 10000; i++ )
    {
        ss.str(""); ss.clear();
        ss << name << "(" << std::dec << i << ")";
        if( ! contains(ss.str()))
        {
            return ss.str();
        }
    }
    throw var_context_exception(Fmt()
        << "VarContext::new_name_from(): Failed to create new variable name from string: "
        << name
        >> Fmt::to_str);
}

std::vector<Value> VarContext::new_symbolic_buffer(
    const std::string& name,
    int nb_elems,
    int elem_size,
    std::optional<cst_t> trailing_value
)
{
    std::vector<Value> res;
    std::stringstream ss;
    for (int i = 0; i < nb_elems; i++)
    {
        ss.str("");
        ss << name << "_" << i;
        res.push_back(Value(exprvar(elem_size*8, ss.str())));
    }
    if (trailing_value)
        res.push_back(Value(exprcst(elem_size*8, *trailing_value)));
    return res;
}

std::vector<Value> VarContext::new_concolic_buffer(
    const std::string& name,
    const std::vector<cst_t>& concrete_buffer,
    int nb_elems,
    int elem_size,
    std::optional<cst_t> trailing_value
)
{
    std::vector<Value> res;
    std::stringstream ss;
    if (nb_elems > concrete_buffer.size())
        throw var_context_exception(
            "VarContext::new_concolic_buffer(): 'nb_elems' is bigger than the concrete buffer size"
        );

    for (int i = 0; i <  nb_elems; i++)
    {
        ss.str("");
        ss << name << "_" << i;
        std::string var_name = ss.str();
        if (contains(var_name))
        {
            throw var_context_exception(
                Fmt() << "VarContext::new_concolic_buffer(): variable named "
                << var_name << " already exists! " >> Fmt::to_str
            );
        }
        res.push_back(Value(exprvar(elem_size*8, var_name)));
        set(var_name, concrete_buffer[i]);
    }
    if (trailing_value)
        res.push_back(Value(exprcst(elem_size*8, *trailing_value)));
    return res;
}

void VarContext::remove(const std::string& name)
{
    varmap.erase(name);
    id = ++(VarContext::_id_cnt);
}

void VarContext::update_from(VarContext& other)
{
    std::map<std::string, maat::Number>::iterator it; 
    for( it = other.varmap.begin(); it != other.varmap.end(); it++)
    {
        varmap[it->first] = it->second;
    }
    id = ++(VarContext::_id_cnt);
}

void VarContext::print(std::ostream& os ) const
{
    os << "\n";
    for( auto var : varmap )
    {
        if (var.second.is_mpz())
        {
            char str[500];  // Enough to store the string representation
                            // of a number on 512 bits
            mpz_get_str(str, 16, var.second.mpz_.get_mpz_t()); // Base 36 to be quicker
            os << var.first << " : 0x" << std::string(str) << std::endl;
        }
        else
            os << var.first << " : " << std::hex << "0x" << var.second.cst_ << std::dec << std::endl;
    }
}

std::ostream& operator<<(std::ostream& os, const VarContext& c)
{
    c.print(os);
    return os;
}

} // namespace maat