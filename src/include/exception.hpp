#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <sstream>
#include <string>
#include <exception>

/** \defgroup exception Exceptions
 * \brief Custom Maat exceptions.
 * 
 * This module contains all custom exceptions types used within Maat
 * to handle different types of errors that can occur.
 * */

namespace maat
{

/* Taken from github */
class Fmt
{
    public:
    Fmt() {}
    ~Fmt() {}

    template <typename Type>
    Fmt& operator<< (const Type & value)
    {
        stream_ << value;
        return *this;
    }

    std::string str() const         { return stream_.str(); }
    operator std::string () const   { return stream_.str(); }

    enum ConvertToString
    {
        to_str
    };
    std::string operator >> (ConvertToString) { return stream_.str(); }

    private:
    std::stringstream stream_;

    Fmt(const Fmt &);
    Fmt& operator = (Fmt &);
};

/**  \addtogroup exception
 * \{ */

/** Generic base exception class */
class generic_exception: public std::exception {
public:
    std::string _msg;
    explicit generic_exception(std::string msg): _msg(msg){};
    const char * what () const throw () {
      return _msg.c_str();
   }
};

/** Runtime exception.
 * This exception is thrown when an unexpected error or inconsistency occurs
 * and execution should not continue. It indicates a fatal error */
class runtime_exception: public generic_exception {
public:
    explicit runtime_exception(std::string msg): generic_exception(msg){};
};

/** Memory engine exception */ 
class mem_exception: public generic_exception {
public:
    explicit mem_exception(std::string msg): generic_exception(msg){};
};

/** Expression exception */
class expression_exception: public generic_exception {
public:
    explicit expression_exception(std::string msg): generic_exception(msg){};
};

/** Var context exception */
class var_context_exception: public generic_exception {
public:
    explicit var_context_exception(std::string msg): generic_exception(msg){};
};

/** Constraint exception */
class constraint_exception: public generic_exception {
public:
    explicit constraint_exception(std::string msg): generic_exception(msg){};
};

/** Loader Exception */
class loader_exception: public generic_exception {
public:
    explicit loader_exception(std::string msg): generic_exception(msg){};
}; 

/** Breakpoint exception */
class bp_exception: public generic_exception {
public:
    explicit bp_exception(std::string msg): generic_exception(msg){};
}; 

/** IR exception */
class ir_exception: public generic_exception {
public:
    explicit ir_exception(std::string msg): generic_exception(msg){};
};

/** Symbolic engine exception */
class symbolic_exception: public generic_exception {
public:
    explicit symbolic_exception(std::string msg): generic_exception(msg){};
}; 

/** Snapshot exception */
class snapshot_exception: public generic_exception {
public:
    explicit snapshot_exception(std::string msg): generic_exception(msg){};
};

/** Instruction unsupported by disassembler exception */
class unsupported_instruction_exception: public generic_exception {
public:
    explicit unsupported_instruction_exception(std::string msg): generic_exception(msg){};
}; 

/** Illegal instruction exception */
class illegal_instruction_exception: public generic_exception {
public:
    explicit illegal_instruction_exception(std::string msg): generic_exception(msg){};
};

/** Environment exception */
class env_exception: public generic_exception {
public:
    explicit env_exception(std::string msg): generic_exception(msg){};
}; 

/** Disassembler exception */
class lifter_exception: public generic_exception {
public:
    explicit lifter_exception(std::string msg): generic_exception(msg){};
};

/** Symbol exception */
class symbol_exception: public generic_exception {
public:
    explicit symbol_exception(std::string msg): generic_exception(msg){};
};

/** Test exception */ 
class test_exception : public std::exception {
   const char * what () const throw () {
      return "Unit test failure";
   }
};

/** \} */

} // namespace maat



#endif
