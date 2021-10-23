#include "env/library.hpp"
#include "engine.hpp"
#include "env/library.hpp"

namespace maat
{
namespace env
{
namespace emulated
{

// __libc_exit
FunctionCallback::return_t libc_exit_callback(
    MaatEngine& engine, 
    const std::vector<Expr>& args
)
{
    // TODO set exit in engine
    switch (engine.arch->type)
    {
        case Arch::Type::X86:
            return engine.cpu.ctx().get(X86::EAX);
        case Arch::Type::X64:
            return engine.cpu.ctx().get(X64::RAX);
        default:
            throw env_exception("Emulated __libc_exit(): not supported for this architecture");
    }
}

// ============ atoi =============== 
// int atoi (const char * str);
Expr _atoi_parse_digits(MaatEngine& engine, addr_t addr)
{
    // Get int
    Expr c;
    Expr res = exprcst(engine.arch->bits(), 0);
    Expr error_too_big = exprcst(engine.arch->bits(), (1 << (engine.arch->bits()-1)) - 1); // MAX_INT
    Expr error_invalid = exprcst(engine.arch->bits(), 0);
    bool char_was_enginebolic[11]; // tells if str[i] was enginebolic/concolic (false if concrete)
    Expr tmp_res[11]; // tmp_res[i] = atoi(str) if char number i is null
                      // BUT tmp_res[10] is the real last possible value
    Expr char_expressions[11]; // str[i]

    int i;
    for (i = 0; i < 11; i++)
    { // 11 because nb_digits of MAX_INT is 10
        // Read next char
        c = engine.mem->read(addr++, 1);
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

FunctionCallback::return_t libc_atoi_callback(MaatEngine& engine, const std::vector<Expr>& args)
{
    addr_t str = args[0]->as_uint(*engine.vars);
    Expr c;
    Expr    sign = nullptr,
            res = nullptr,
            sign_expr = nullptr,
            int_from_first_char = nullptr,
            int_from_second_char = nullptr;
    bool enginebolic_sign = false;

    // Skip whitespaces
    c = engine.mem->read(str, 1);
    while( c->is_concrete(*engine.vars) and c->as_uint(*engine.vars) != 0)
    {
        if(!isspace((char)(c->as_uint(*engine.vars))))
        {
            break;
        }else{
            c = engine.mem->read(++str, 1);
        }
    }

    // Check sign char
    if (c->is_concrete(*engine.vars))
    {
        // If first char is concrete we know the sign
        if (c->as_uint() == 0x2b) // 0x2b == '+'
        { 
            sign = exprcst(engine.arch->bits(), 1);
            c = engine.mem->read(++str, 1);
        }
        else if (c->as_uint() == 0x2d)
        {
            sign = exprcst(engine.arch->bits(), -1);
            c = engine.mem->read(++str, 1);
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

    return res; 
}

// int fflush ( FILE * stream );
FunctionCallback::return_t libc_fflush_callback(MaatEngine& engine, const std::vector<Expr>& args)
{
    // We don't need to flush because emulated functions don't do buffering...
    // Return zero for success
    return 0; 
}


// FILE * fopen ( const char * filename, const char * mode );
// We return the FILE* as an opaque filehandle_t in the emulated file system
FunctionCallback::return_t libc_fopen_callback(MaatEngine& engine, const std::vector<Expr>& args)
{
    std::string mode; 
    std::string filename;

    // Get args
    try
    {
        mode = engine.mem->read_string(args[1]->as_uint(*engine.vars));
        filename = engine.mem->read_string(args[0]->as_uint(*engine.vars));
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
                return engine.env->fs.new_fa("#stdout");
            }
            else if (mode.find("r") != std::string::npos)
            {
                // Read, return stdin
                return engine.env->fs.new_fa("#stdin");
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
FunctionCallback::return_t libc_fwrite_callback(MaatEngine& engine, const std::vector<Expr>& args)
{
    filehandle_t handle = args[3]->as_uint(*engine.vars);
    Expr buf = args[0]; // It can be enginebolic
    size_t size = args[1]->as_uint(*engine.vars);
    size_t count = args[2]->as_uint(*engine.vars);
    size_t total_size =  size * count;
    int res=0;
    std::vector<Expr> buffer;

    FileAccessor& fa = engine.env->fs.get_fa_by_handle(handle);
    // Read buffer of bytes
    buffer = engine.mem->read_buffer(buf, total_size, 1);
    // Write it to file
    res = fa.write_buffer(buffer);
    res /= size; // Transform bytes count in element count

    // Return number of elements written
    return res;
}

// =============== Arch specific functions ====================
// int __libc_start_main(int *(main) (int, char **, char **), int argc, 
//                       char ** ubp_av, void (*init) (void), void (*fini) (void),
//                       void (*rtld_fini) (void), void (* stack_end));
FunctionCallback::return_t linux_x86_libc_start_main_callback(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    // With cdecl ABI
    addr_t main = (args[0]->as_uint(*engine.vars));
    addr_t argc = (args[1]->as_uint(*engine.vars));
    addr_t argv = (args[2]->as_uint(*engine.vars));
    addr_t init = (args[3]->as_uint(*engine.vars)); // pointer to __libc_csu_init
    //addr_t fini = (args[4]->as_uint(*engine.vars)); // 
    //addr_t rtld_fini = (args[5]->as_uint(*engine.vars));
    //addr_t end_stack = (args[6]->as_uint(engine.vars));

    addr_t stack = engine.cpu.ctx().get(X86::ESP)->as_uint(*engine.vars);

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
    const std::vector<Expr>& args
)
{
    // With system V ABI
    addr_t main = (args[0]->as_uint());
    addr_t argc = (args[1]->as_uint());
    addr_t argv = (args[2]->as_uint());
    addr_t init = (args[3]->as_uint());
    //addr_t fini = (args[4]->as_unsigned(engine.vars));
    //addr_t rtld_fini = (args[5]->as_unsigned(engine.vars));
    //addr_t end_stack = (args[6]->as_unsigned(engine.vars));

    // Push (main, argc, argv) as args to part2
    addr_t stack = engine.cpu.ctx().get(X64::RSP)->as_uint() - 24;
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
    const std::vector<Expr>& args
)
{
    // Get args manually on stack, cdecl-style
    Expr stack = engine.cpu.ctx().get(X64::RSP);
    Expr main = engine.mem->read(stack, 8);
    Expr argc = engine.mem->read(stack+8, 8);
    Expr argv = engine.mem->read(stack+16, 8);

    // Set argc, argv
    engine.cpu.ctx().set(X64::RDI, argc);
    engine.cpu.ctx().set(X64::RSI, argv);

    // Push return address after main
    engine.cpu.ctx().set(X64::RSP, stack-8);
    engine.mem->write(stack-8, engine.symbols->addr("__libc_exit"), 8);

    // Set program counter to main and return (because ABI none)
    engine.cpu.ctx().set(X64::RIP, main);

    return std::monostate();
}

// All common libc functions (cross platform)
std::vector<Function> libc_common_functions
{
    Function("atoi", FunctionCallback({env::abi::auto_argsize}, libc_atoi_callback)),
    Function("fflush", FunctionCallback({env::abi::auto_argsize}, libc_fflush_callback)),
    Function("fopen", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, libc_fopen_callback)),
    Function("fwrite", FunctionCallback({env::abi::auto_argsize, 2, 2, env::abi::auto_argsize}, libc_fwrite_callback)),
    Function("__libc_exit", FunctionCallback({}, libc_exit_callback))
};

// For Linux X86
Library linux_x86_libc()
{
    Library lib("libc", libc_common_functions);
    // Arch specific functions...
    lib.add_function(Function("__libc_start_main",
        FunctionCallback({4,4,4,4,4,4,4}, linux_x86_libc_start_main_callback)
    ));
    return lib;
}

// For Linux X64
Library linux_x64_libc()
{
    Library lib("libc", libc_common_functions);
    // Arch specific functions...
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