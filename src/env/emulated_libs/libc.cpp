#include "maat/env/library.hpp"
#include "maat/engine.hpp"
#include <cstdlib>

namespace maat
{
namespace env
{
namespace emulated
{

// ================= Utils ===================
/* Read a concrete C string into buffer 
   - addr is the address of the string
   - max_len is the length of 'buffer' where to put the concrete string
   - len is set to the length of the string 
   The function throws an env_exception on error
 */
void _mem_read_c_string(MaatEngine& engine, addr_t addr, char* buffer, int& len, unsigned int max_len)
{
    Value val;
    char c = 0xff;
    len = 0;
    while (c != 0 && len < max_len )
    {
        val = engine.mem->read(addr+len, 1);
        if (val.is_symbolic(*engine.vars))
        {
            throw env_exception("_mem_read_c_string(): tries to read concrete C string but got symbolic data");
        }
        c = (uint8_t)(val.as_uint(*engine.vars));
        buffer[len++] = c;
    }
    if (len == max_len)
    {
        throw env_exception("_mem_read_c_string(): C string is too long to fit into buffer !");
    }
}

// Supported format specifiers
static constexpr int SPEC_NONE = 0;
static constexpr int SPEC_UNSUPPORTED = 1;
static constexpr int SPEC_INT32 = 2;
static constexpr int SPEC_STRING = 3;
static constexpr int SPEC_CHAR = 4;
static constexpr int SPEC_HEX32 = 5; // Int on hex format


/* input: size of expressions must be 8 (a byte) */
bool _is_whitespace(char c)
{
    return  c == 0x20 ||
            c == 0x9 ||
            c == 0xa ||
            c == 0xb ||
            c == 0xc ||
            c == 0xd ||
            c == 0;
}

bool _is_terminating(char c)
{
    return  c == 0 ||
            c == '\n';
}

/* Tries to parse a format specifier in string format at index 'index'.
 * If successful, index is modified to the last char of the specifier
 */
int _get_specifier(char* format, int format_len, int& index, char* spec, int spec_max_len ){
    int i = index;
    int res;
    // % marker
    if( format[i] != '%' )
        return SPEC_NONE;
    spec[i-index] = format[i];
    // width
    for( i = i +1; i < format_len; i++){
        if( i > spec_max_len-3 )
            return SPEC_UNSUPPORTED;
        // Check if number
        if( format[i] >= '0' && format[i] <= '9' )
            spec[i-index] = format[i];
        else
            break;
    }
    if( i ==  format_len )
        return false;

    // Precision 
    if( format[i] == '.' ){
        spec[i-index] = format[i];
        for( i = i +1; i < format_len; i++){
            if( i > spec_max_len-3 )
                return SPEC_UNSUPPORTED;
            // Check if number
            if( format[i] >= '0' && format[i] <= '9' )
                spec[i-index] = format[i];
            else
                break;
        }
    }
    
    // specifier
    spec[i-index] = format[i];
    if(     format[i] == 'd' || format[i] == 'u' ){
        res = SPEC_INT32; 
    }else if( format[i] == 'x' ){
        res = SPEC_HEX32;
    }else if( format[i] == 's' ){
        res = SPEC_STRING;
    }else if( format[i] == 'c' ){
        res = SPEC_CHAR;
    }else{
        res = SPEC_UNSUPPORTED;
    }
    // Check res
    if( res != SPEC_UNSUPPORTED ){
        spec[i-index+1] = '\0';
        index = i;
    }
    return res;
}


// from_arg: marks the first argument that starts the varargs, for example in 
// printf(char* format, ...) from_arg must be 1
void _get_format_string(MaatEngine& engine, char* format, int len, std::string& res, int from_arg=0){
    int vararg_cnt = from_arg;
    std::stringstream ss;
    int val;
    addr_t addr;
    char buffer[2048], specifier[128], formatted_arg[256];
    int buffer_len;
    const maat::env::abi::ABI& abi = *engine.env->default_abi;
    size_t arg_size = engine.arch->octets();

    int spec;
    for( int i = 0; i < len; i++ ){
        spec = _get_specifier(format, len, i, specifier, sizeof(specifier));
        if (spec ==  SPEC_INT32 || spec == SPEC_HEX32)
        {
            val = (int)abi.get_arg(engine, vararg_cnt++, arg_size).as_uint(*engine.vars);
            // Use snprintf that does the formatting for us :)
            snprintf(formatted_arg, sizeof(formatted_arg), specifier, val);
            ss << std::string(formatted_arg);
        }
        else if( spec == SPEC_STRING )
        {
            addr = (addr_t)abi.get_arg(engine, vararg_cnt++, arg_size).as_uint(*engine.vars);
            _mem_read_c_string(engine,  addr, buffer, buffer_len, sizeof(buffer)); // Ignore if we exceed sizeof(buffer)
            ss << std::string(buffer, buffer_len);
        }
        else if( spec == SPEC_CHAR)
        {
            val = (char)abi.get_arg(engine, vararg_cnt++, arg_size).as_uint(*engine.vars);
            // Use snprintf that does the formatting for us :)
            snprintf(formatted_arg, sizeof(formatted_arg), specifier, (char)val);
            ss << std::string(formatted_arg);
        }
        else if( spec == SPEC_UNSUPPORTED)
        {
            engine.log.fatal(
                "Error in emulation callback: _get_format_string():", 
                " Unsupported format: ", std::string(specifier), " in ", std::string(format)
            );
            throw env_exception("Error in emulation callback: couldn't process format string");
        }
        else
        {
            ss << format[i];
        }
    }
    res = ss.str();
}

// ================= Emulated functions ================
// Callback that does nothing
FunctionCallback::return_t do_nothing_callback(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    return std::monostate();
}

// __libc_exit
FunctionCallback::return_t libc_exit_callback(
    MaatEngine& engine, 
    const std::vector<Value>& args
)
{
    
    Value status;
    switch (engine.arch->type)
    {
        case Arch::Type::X86:
            status = engine.cpu.ctx().get(X86::EAX);
            break;
        case Arch::Type::X64:
            status = engine.cpu.ctx().get(X64::RAX);
            break;
        default:
            throw env_exception("Emulated __libc_exit(): not supported for this architecture");
    }
    // Exit process in the engine
    engine.terminate_process(status);
    return status;
}

// ============ atoi =============== 
// int atoi (const char * str);
Expr _atoi_parse_digits(MaatEngine& engine, addr_t addr)
{
    // Get int
    Expr c;
    Expr res = exprcst(engine.arch->bits(), 0);
    Expr error_too_big = exprcst(engine.arch->bits(), (1ULL << (engine.arch->bits()-1)) - 1); // MAX_INT
    Expr error_invalid = exprcst(engine.arch->bits(), 0);
    bool char_was_enginebolic[11]; // tells if str[i] was enginebolic/concolic (false if concrete)
    Expr tmp_res[11]; // tmp_res[i] = atoi(str) if char number i is null
                      // BUT tmp_res[10] is the real last possible value
    Expr char_expressions[11]; // str[i]

    int i;
    for (i = 0; i < 11; i++)
    { // 11 because nb_digits of MAX_INT is 10
        // Read next char
        c = engine.mem->read(addr++, 1).as_expr();
        char_was_enginebolic[i] = not c->is_concrete(*engine.vars);
        char_expressions[i] = c;
        if (i == 10){ // Check the eleventh char
            // String is too long? 
            if (c->is_concrete(*engine.vars))
            {
                if (c->as_uint(*engine.vars) == 0)
                    tmp_res[i] = res;
                else
                    tmp_res[i] = error_too_big;
            }
            else
            {
                // Eleventh char not concrete: if zero then result is OK, else
                // string is too mong and result is ERROR
                tmp_res[i] = ITE(c, ITECond::EQ, exprcst(8, 0), res, error_too_big);
            }
            break;
        }
        else // Read next integer char
        {
            if (c->is_concrete(*engine.vars) and c->as_uint() == 0)
            {
                // Concrete '\0'
                tmp_res[i] = res;
                break;
            }
            else if (c->is_concrete(*engine.vars))
            {
                // Update res if concrete
                res = res*10 + exprcst(res->size, c->as_uint() - 0x30);
                tmp_res[i] = nullptr; // no tmp_res because concrete != null
            }
            else
            {
                // Update if enginebolic/concolic, 2 possibilities:
                //   - char is digit so add it
                //   - char is invalid so return error
                // Note: 3rd possibility is when the char is null, but this is handled
                // later when recombining the tmp_res
                // Note2: we currently don't support invalid enginebolic digits
                tmp_res[i] = res; // If null, tmp_res is the current res
                res = res*10 + concat(exprcst(engine.arch->bits() - c->size, 0), c - 0x30);
            }
        }
    }

    // Here i = the index of the last char processed
    // Test if string was empty
    if( i == 0 )
    {
        return error_invalid;
    }

    // Build the final ITE expression by combining all possibilities
    res = tmp_res[i--];
    // Go through all possibilities in reverse
    for (; i >= 0; i--)
    {
        if( char_was_enginebolic[i] )
        {
            c = char_expressions[i];
            Expr if_invalid_inf = ITE(c, ITECond::LT, exprcst(c->size, 0x30), error_invalid, res);
            Expr if_invalid_sup = ITE(exprcst(c->size, 0x39), ITECond::LT, c, error_invalid, if_invalid_inf);
            res = ITE(c, ITECond::EQ, exprcst(c->size, 0), tmp_res[i], if_invalid_sup);
        }
    }
    return res;
}

FunctionCallback::return_t libc_atoi_callback(MaatEngine& engine, const std::vector<Value>& args)
{
    addr_t str = args[0].as_uint(*engine.vars);
    Expr c;
    Expr    sign = nullptr,
            res = nullptr,
            sign_expr = nullptr,
            int_from_first_char = nullptr,
            int_from_second_char = nullptr;
    bool enginebolic_sign = false;

    // Skip whitespaces
    c = engine.mem->read(str, 1).as_expr();
    while( c->is_concrete(*engine.vars) and c->as_uint(*engine.vars) != 0)
    {
        if(!isspace((char)(c->as_uint(*engine.vars))))
        {
            break;
        }else{
            c = engine.mem->read(++str, 1).as_expr();
        }
    }

    // Check sign char
    if (c->is_concrete(*engine.vars))
    {
        // If first char is concrete we know the sign
        if (c->as_uint() == 0x2b) // 0x2b == '+'
        { 
            sign = exprcst(engine.arch->bits(), 1);
            c = engine.mem->read(++str, 1).as_expr();
        }
        else if (c->as_uint() == 0x2d)
        {
            sign = exprcst(engine.arch->bits(), -1);
            c = engine.mem->read(++str, 1).as_expr();
        }
        else
        {
            sign = exprcst(engine.arch->bits(), 1);
        }
    }
    else
    {
        enginebolic_sign = true;
        sign_expr = c;
        // Parse digits from second char (because first char might be '+' or '-' )
        int_from_second_char = _atoi_parse_digits(engine, str+1);
    }

    // Parse digits from first char
    int_from_first_char = _atoi_parse_digits(engine, str);

    // Adjust result with sign
    if (enginebolic_sign)
    {
        Expr if_plus = ITE( sign_expr, ITECond::EQ, exprcst(8, 0x2b), int_from_second_char, int_from_first_char);
        Expr if_minus = ITE( sign_expr, ITECond::EQ, exprcst(8, 0x2d), exprcst(engine.arch->bits(), -1)*int_from_second_char, if_plus);
        res = if_minus;
    }
    else
    {
        res = sign * int_from_first_char;
    }

    return Value(res); 
}

// int fflush ( FILE * stream );
FunctionCallback::return_t libc_fflush_callback(MaatEngine& engine, const std::vector<Value>& args)
{
    // We don't need to flush because emulated functions don't do buffering...
    // Return zero for success
    return 0; 
}


// FILE * fopen ( const char * filename, const char * mode );
// We return the FILE* as an opaque filehandle_t in the emulated file system
FunctionCallback::return_t libc_fopen_callback(MaatEngine& engine, const std::vector<Value>& args)
{
    std::string mode; 
    std::string filename;

    // Get args
    try
    {
        mode = engine.mem->read_string(args[1].as_uint(*engine.vars));
        filename = engine.mem->read_string(args[0].as_uint(*engine.vars));
    }
    catch (std::exception& e)
    {
        engine.log.error("Emulated fopen(), error when reading arguments: ", e.what());
        throw env_exception("Fatal error in emulated fopen()");
    }

    // TODO Support append modes !!!
    if (filename == "-") // stdio
    {
        try
        {
            if(
                mode.find("w") != std::string::npos
                or mode.find("a") != std::string::npos
            )
            {
                // Write, return stdout
                return engine.env->fs.new_fa(
                    engine.env->fs.get_stdout_for_pid(engine.process->pid)
                );
            }
            else if (mode.find("r") != std::string::npos)
            {
                // Read, return stdin
                return engine.env->fs.new_fa(
                    engine.env->fs.get_stdin_for_pid(engine.process->pid)
                );
            }
            else
            {
                // Error null res
                engine.log.warning("Emulated fopen(), unsupported mode: ", mode);
                return 0;
            }
        }
        catch(const env_exception& e)
        {
            engine.log.error("Emulated fopen(): ", e.what());
            throw env_exception("Fatal error in emulated fopen()");
        }

    }
    else // Regular file
    {
        std::string full_path = engine.env->fs.path_from_relative_path(filename, engine.process->pwd);
        // Check if file exists
        node_status_t status = engine.env->fs.get_node_status(full_path);
        if (not env::node::check_is_file(status))
        {
            // fopen failed (NULL)
            engine.log.warning("Emulated fopen(): ", full_path, "doesn't exist or is not a file '");
            return 0;
        }

        // Get new FILE*
        try
        {
            filehandle_t handle = engine.env->fs.new_fa(full_path);
            return handle;
        }
        catch(const env_exception& e)
        {
            engine.log.warning("Emulated fopen(), error opening file '", full_path, "': ", e.what());
            return 0; // fopen() returns NULL on error
        }
    }
}


// size_t fwrite (const void * ptr, size_t size, size_t count, FILE * stream);
FunctionCallback::return_t libc_fwrite_callback(MaatEngine& engine, const std::vector<Value>& args)
{
    filehandle_t handle = args[3].as_uint(*engine.vars);
    Value buf = args[0]; // It can be enginebolic
    size_t size = args[1].as_uint(*engine.vars);
    size_t count = args[2].as_uint(*engine.vars);
    size_t total_size =  size * count;
    int res=0;
    std::vector<Value> buffer;

    FileAccessor& fa = engine.env->fs.get_fa_by_handle(handle);
    // Read buffer of bytes
    buffer = engine.mem->read_buffer(buf, total_size, 1);
    // Write it to file
    res = fa.write_buffer(buffer);
    res /= size; // Transform bytes count in element count

    // Return number of elements written
    return res;
}


// int printf ( const char * format, ... );
FunctionCallback::return_t libc_printf_callback(MaatEngine& engine, const std::vector<Value>& args)
{
    addr_t format = args[0].as_uint(*engine.vars);
    char str[2048];
    int len;
    std::string to_print;

    try
    {
        // Read first argument (format string) into a buffer
        _mem_read_c_string(engine, format, str, len, sizeof(str));
        
        // Try to interpret the format and get the correct string
        _get_format_string(engine, str, len, to_print, 1);
        
        // Print to stdout
        addr_t offset = 0;
        env::physical_file_t out = engine.env->fs.get_file(
            engine.env->fs.get_stdout_for_pid(engine.process->pid)
        );
        out->write_buffer((uint8_t*)to_print.c_str(), offset, to_print.size()+1); // +1 for terminating null byte
    }
    catch(const env_exception& e)
    {
        engine.log.fatal("Emulated printf(): ", e.what());
        throw env_exception("Emulated printf(): fatal error during emulation");
    }

    // Return value is the number of bytes written
    return (cst_t)to_print.size(); 
}

// =============== Arch specific functions ====================
// int __libc_start_main(int *(main) (int, char **, char **), int argc, 
//                       char ** ubp_av, void (*init) (void), void (*fini) (void),
//                       void (*rtld_fini) (void), void (* stack_end));
FunctionCallback::return_t linux_x86_libc_start_main_callback(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    // With cdecl ABI
    addr_t main = (args[0].as_uint(*engine.vars));
    addr_t argc = (args[1].as_uint(*engine.vars));
    addr_t argv = (args[2].as_uint(*engine.vars));
    addr_t init = (args[3].as_uint(*engine.vars)); // pointer to __libc_csu_init
    //addr_t fini = (args[4].as_uint(*engine.vars)); // 
    //addr_t rtld_fini = (args[5].as_uint(*engine.vars));
    //addr_t end_stack = (args[6].as_uint(engine.vars));

    addr_t stack = engine.cpu.ctx().get(X86::ESP).as_uint(*engine.vars);

    // Push argc, argv
    stack -= 4;
    engine.mem->write(stack, argv, 4);
    stack -= 4;
    engine.mem->write(stack, argc, 4);

    // Push return address after main
    stack -= 4;
    engine.mem->write(stack, engine.symbols->addr("__libc_exit"), 4);

    // Push return address after init() (address of main!)
    stack -= 4;
    engine.mem->write(stack, main, 4);

    // HACK: set return address of __libc_start_main to init() so that when we 
    // return from the callback we go to the init function :)
    stack -= 4;
    engine.mem->write(stack, init, 4);

    engine.cpu.ctx().set(X86::ESP, stack); // Update stack pointer

    return std::monostate();
}

/* int __libc_start_main(int *(main) (int, char **, char **), int argc,
                        char ** ubp_av, void (*init) (void), void (*fini) (void),
                        void (*rtld_fini) (void), void (* stack_end)); */
// First part of __libc_start_main: call init() then go to second part
FunctionCallback::return_t linux_x64_libc_start_main_callback_part1(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    // With system V ABI
    addr_t main = (args[0].as_uint());
    addr_t argc = (args[1].as_uint());
    addr_t argv = (args[2].as_uint());
    addr_t init = (args[3].as_uint());
    //addr_t fini = (args[4]->as_unsigned(engine.vars));
    //addr_t rtld_fini = (args[5]->as_unsigned(engine.vars));
    //addr_t end_stack = (args[6]->as_unsigned(engine.vars));

    // Push (main, argc, argv) as args to part2
    addr_t stack = engine.cpu.ctx().get(X64::RSP).as_uint() - 24;
    engine.mem->write(stack, main, 8);
    engine.mem->write(stack+8, argc, 8);
    engine.mem->write(stack+16, argv, 8);

    // Push return address after init() (address of part2)
    engine.mem->write(stack-8, engine.symbols->addr("__libc_start_main_part2"), 8);

    // HACK: set return address of __libc_start_main to init() so that when we 
    // execute _abi_return we go to init() :)
    engine.cpu.ctx().set(X64::RSP, stack-16);
    engine.mem->write(stack-16, init, 8);
    
    return std::monostate(); 
}

// Part2 of __libc_start_main, executed after init(), it just calls main()
FunctionCallback::return_t linux_x64_libc_start_main_callback_part2(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    // Get args manually on stack, cdecl-style
    Value stack = engine.cpu.ctx().get(X64::RSP);
    Value main = engine.mem->read(stack, 8);
    Value argc = engine.mem->read(stack+8, 8);
    Value argv = engine.mem->read(stack+16, 8);

    // Set argc, argv
    engine.cpu.ctx().set(X64::RDI, argc);
    engine.cpu.ctx().set(X64::RSI, argv);

    // Push return address after main
    engine.mem->write(stack-8, engine.symbols->addr("__libc_exit"), 8);

    // Push main address
    engine.mem->write(stack-16, main);
    engine.cpu.ctx().set(X64::RSP, stack-16);

    return std::monostate();
}

// All common libc functions (cross platform)
std::vector<Function> libc_common_functions
{
    Function("atoi", FunctionCallback({env::abi::auto_argsize}, libc_atoi_callback)),
    Function("fflush", FunctionCallback({env::abi::auto_argsize}, libc_fflush_callback)),
    Function("fopen", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, libc_fopen_callback)),
    Function("fwrite", FunctionCallback({env::abi::auto_argsize, 2, 2, env::abi::auto_argsize}, libc_fwrite_callback)),
    Function("printf", FunctionCallback({env::abi::auto_argsize}, libc_printf_callback)),
    Function("__libc_exit", FunctionCallback({}, libc_exit_callback))
};

// All common libc exported data (cross platform)
std::vector<Data> libc_common_data
{
    Data("__gmon_start__", std::vector<uint8_t>{8, 0}) // On 8 bytes so it works for both 32 and 64 bit platforms
};

// For Linux X86
Library linux_x86_libc()
{
    Library lib("libc", libc_common_functions, libc_common_data);
    // Arch specific functions...
    lib.add_function(Function("__libc_start_main",
        FunctionCallback({4,4,4,4,4,4,4}, linux_x86_libc_start_main_callback)
    ));
    return lib;
}

// For Linux X64
Library linux_x64_libc()
{
    Library lib("libc", libc_common_functions, libc_common_data);
    // Arch specific functions...
    lib.add_function(Function("__libc_start_main",
        FunctionCallback({8,8,8,8,8,8,8}, linux_x64_libc_start_main_callback_part1)
    ));
    lib.add_function(Function("__libc_start_main_part2",
        FunctionCallback({}, linux_x64_libc_start_main_callback_part2)
    ));
    return lib;
}

// For Linux ARM32
Library linux_ARM32_libc()
{
    Library lib("libc", libc_common_functions, libc_common_data);
    // Arch specific functions...
    //TODO Find functions to use
    lib.add_function(Function("__libc_start_main",
        FunctionCallback({8,8,8,8,8,8,8}, linux_x64_libc_start_main_callback_part1)
    ));
    lib.add_function(Function("__libc_start_main_part2",
        FunctionCallback({}, linux_x64_libc_start_main_callback_part2)
    ));
    return lib;
}

} // namespace emulated
} // namespace env
} // namespace maat
