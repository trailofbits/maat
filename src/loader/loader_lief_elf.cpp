#ifdef LIEF_BACKEND

#include "loader.hpp"
#include "engine.hpp"
#include <sys/stat.h>

namespace maat
{
namespace loader
{

std::string get_symbol_name(LIEF::ELF::Symbol& symbol)
{
    try
    {
        return symbol.demangled_name();
    }
    catch(const LIEF::not_supported& e)
    {
        return symbol.name();
    }
}

void LoaderLIEF::load_elf(
    MaatEngine* engine,
    const std::string& binary,
    addr_t base,
    std::vector<CmdlineArg> args,
    const std::string& virtual_path,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs
)
{
    addr_t stack_base, stack_size, heap_base, heap_size, kernel_stack_size, kernel_stack_base;
    addr_t gs, fs;
    std::list<std::string> loaded_libs;
    reg_t reg_sp = -1;
    reg_t reg_bp = -1;
    reg_t reg_gs = -1;
    reg_t reg_fs = -1;
    reg_t reg_pc = -1;
    int arch_bytes = engine->arch->octets();

    // Parse binary with LIEF
    parse_binary(binary, Format::ELF32);

    // Get particular registers
    get_arch_special_registers(*engine->arch, reg_pc, reg_sp, reg_bp, reg_gs, reg_fs);

    // Map and copy segments to memory
    map_elf_segments(engine, base);

    // Add symbols to symbol manager
    add_elf_symbols(engine, base);

    // Setup process stack
    stack_size = 0x04000000;
    stack_base = alloc_segment(engine, 0x2000000, stack_size, maat::mem_flag_rw, "Stack");
    engine->cpu.ctx().set(reg_sp, stack_base+stack_size-0x400); // - 0x400 to leave some space in memory
    engine->cpu.ctx().set(reg_bp, stack_base+stack_size-0x400); 

    // Setup kernel stack
    kernel_stack_size = 0x000c000;
    kernel_stack_base = alloc_segment(engine, 0x4000, kernel_stack_size, maat::mem_flag_rw, "Kernel Stack", true);
    // TODO engine->env->kernel_stack = kernel_stack_base + kernel_stack_size;

    // Setup heap
    heap_size = 0x06000000;
    heap_base = alloc_segment(engine, 0x09000000, heap_size, maat::mem_flag_rw, "Heap");
    // engine->env->init_mem_allocator(heap_base, heap_base+heap_size-1);

    // Allocate some segments for GS and FS segment selectors (stack canary stuff)
    if (reg_gs != -1)
    {
        gs = alloc_segment(engine, 0x00aa0000, 0x1000, maat::mem_flag_rw, "Fake GS: segment");
        fs = alloc_segment(engine, 0x00aa0000, 0x1000, maat::mem_flag_rw, "Fake FS: segment");
        engine->cpu.ctx().set(reg_gs, gs);
        engine->cpu.ctx().set(reg_fs, fs);
    }

    // Load misc. things
    // TODO auto load everything from Env !!
    /* 
    _load_ctype_tables(sym);
    _load_stdio(sym);
    _load_kernel_data(sym);
    */

    // Initialize default signal handlers
    // TODO Do that in Env directly
    // _init_signal_handlers(sym);

    // Preload emulated libraries. We do it before loading dependencies
    // because dependencies themselves might need functions from emulated libs...
    // For this to work, the dependencies are expected to overwrite emulated
    // symbols if the "real" library is loaded instead of the emulated one
    load_emulated_libs(engine);

    // Load all shared libraries
    load_elf_dependencies(engine, libdirs, ignore_libs, loaded_libs, *this);

    // Perform relocations
    perform_elf_relocations(engine, base);

    // Setup args, env, auxilliary vector, etc in memory
    // 1 ---------------- Write Args to memory -----------------
    std::vector<addr_t> argv_addresses;

    // First add the binary name to the args
    args.insert(args.begin(), CmdlineArg(binary_name));
    int argc = 0;
    // Then load the args in memory
    load_cmdline_args(engine, args, argc, argv_addresses);

    // 2 ---------------- Write env to memory -----------------
    /* TODO get env from env ;)
    std::vector<addr_t> env_addresses;
    std::string var;
    addr_t mem_arg_addr;
    for( i = 0; i < env_variables.size(); i++ )
    {
        var = env_variables[i];
        // Decrease esp of its size + 1 for null byte
        mem_arg_addr = (uint32_t)engine->cpu.ctx().concretize(X86_ESP) - var.size() - 1;
        engine->cpu.ctx().set(X86_ESP, exprcst(32, mem_arg_addr));
        engine->mem->write_buffer(mem_arg_addr, (uint8_t*)var.c_str(), var.size()+1);
        env_addresses.insert(env_addresses.begin(), mem_arg_addr);
    } */

    // 3 ---------------- Generate auxilliary vector -----------------
    // This updates the stack (writing random bytes, etc)
    std::vector<std::pair<uint64_t, uint64_t>> aux_vector = generate_aux_vector(engine, base, argv_addresses[0]);

    /* When calling _start the memory must be environment variables, then
     * program arguments, then argument count 
     Low Addr.
                argc      <--- esp
                &argv[0]
                &argv[1]
                ...
                0
                &env[0]
                &env[1]
                ...
                0
     High Addr.
    */

    // Setup auxilliary vector
    // At the end of aux add two null pointers (termination key/value)
    addr_t tmp_sp = engine->cpu.ctx().get(reg_sp)->as_uint() - (arch_bytes*2);
    engine->cpu.ctx().set(reg_sp,  - arch_bytes*2);
    engine->mem->write(tmp_sp, 0, arch_bytes);
    engine->mem->write(tmp_sp+arch_bytes, 0, arch_bytes);
    for (auto it = aux_vector.rbegin(); it != aux_vector.rend(); it++)
    {
        tmp_sp -= arch_bytes*2;
        engine->mem->write(tmp_sp, it->first, arch_bytes);
        engine->mem->write(tmp_sp+arch_bytes, it->second, arch_bytes);
    }

    // Setup env
    // TODO GET ENV FROM ENV :) 
    /* 
    tmp_sp -= arch_bytes;
    engine->mem->write(tmp_sp, 0, arch_bytes); // At the end of env variables add a null pointer
    for (auto it = env_addresses.rbegin(); it != env_addresses.rend(); it++)
    {
        tmp_sp -= arch_bytes;
        engine->mem->write(tmp_sp, *it, arch_bytes);
    } */
    // TODO: Setup env pointer in environment ? 
    // engine->env->env_array = engine->cpu.ctx().as_unsigned(X86_ESP); // Set env[] pointer in environment :)

    // Setup argv
    tmp_sp -= arch_bytes;
    engine->mem->write(tmp_sp, 0, arch_bytes); // At the end of argv add a null pointer
    for (auto it = argv_addresses.rbegin(); it != argv_addresses.rend(); it++)
    {
        tmp_sp -= arch_bytes;
        engine->mem->write(tmp_sp, *it, arch_bytes);
    }
    // Setup argc
    tmp_sp -= arch_bytes;
    engine->mem->write(tmp_sp, argc, arch_bytes);
    engine->cpu.ctx().set(reg_sp, tmp_sp);
    
    // Point PC to entrypoint
    std::cout << "DEBUG finish, inter entry ? " << interpreter_entry.value() << std::endl;
    addr_t real_entry = interpreter_entry.has_value() ?
        interpreter_entry.value() : _elf->entrypoint() + base;
    engine->cpu.ctx().set(reg_pc, real_entry);

}

void LoaderLIEF::map_elf_segments(MaatEngine* engine, addr_t base_address)
{
    uint64_t addr;
    mem_flag_t flags;
    int i;
    uint8_t* data;
    unsigned int virtual_size, physical_size;

    for (LIEF::ELF::Segment& segment: _elf->segments())
    {
        if( segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_LOAD )
        {
            if( segment.content().size() != segment.physical_size() )
            {
                throw loader_exception("LoaderLIEF::map_elf_segments(): Inconsistent sizes for segment content and its physical size!");
            }

            // Copy segment content (vector<uint8_t>) into a buffer
            data = new uint8_t[segment.physical_size()]; // FIXME, use std::array...
            i = 0;
            for( auto b : segment.content())
            {
                data[i++] = b;
            }
            virtual_size = segment.virtual_size();
            // Aligne virtual size
            if( virtual_size % engine->mem->page_manager.page_size() != 0)
            {
                virtual_size += engine->mem->page_manager.page_size() - (virtual_size % engine->mem->page_manager.page_size());
            }
            physical_size = segment.physical_size();
            addr = segment.virtual_address() + base_address;
            flags = get_segment_flags(segment);
            // Create new segment
            std::stringstream ss;
            ss << "[" << _elf->name() << "]";
            engine->mem->new_segment(addr, addr+virtual_size-1, flags, ss.str());
            // Write content
            engine->mem->write_buffer(addr, data, physical_size, true);
            delete [] data; data = nullptr;
        }
    }
}

// Remove prefixes like /lib64/... on interpreter name
std::string _clean_interpreter_name(const std::string& name)
{
    size_t idx = name.find_last_of("/");
    if (idx != std::string::npos)
        return name.substr(idx+1);
    else
        return name;
}

void LoaderLIEF::load_elf_dependencies(
    MaatEngine* engine,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    std::list<std::string>& loaded_libs,
    LoaderLIEF& top_loader
)
{
    LoaderLIEF lib_loader;
    std::string lib_path;
    struct stat path_stat;
    bool found = false;
    for (const std::string& lib_name : _elf->imported_libraries())
    {
        if( std::find(ignore_libs.begin(), ignore_libs.end(), lib_name) != ignore_libs.end())
        {
            continue;
        }
        if( std::find(loaded_libs.begin(), loaded_libs.end(), lib_name) != loaded_libs.end())
        {
            continue;
        }
        found = false;
        // Add lib to list of loaded libs (no matter if success or not)
        loaded_libs.push_back(lib_name);
        // Search candidate file 
        for (const std::string& path : libdirs)
        {
            // Check if file or directory
            if( stat(path.c_str(), &path_stat) )
            {
                continue; // Error in stat, skip this file
            }
            // Create cnadidate filename
            if( S_ISREG(path_stat.st_mode))
            {
                // Regular file
                // DO nothing
                lib_path = path;
            }else if( S_ISDIR(path_stat.st_mode)){
                // Directory
                lib_path = path + "/" + lib_name;
            }else{
                continue;
            }

            // Check if file exists
            if( stat(lib_path.c_str(), &path_stat) != 0 )
            {    
                continue;
            }

            // Check if same name as requested lib
            if( lib_path.size()+1 < lib_name.size() )
                continue;
            if( lib_path.substr(lib_path.size()- lib_name.size()-1, lib_path.size()) == (std::string("/") + lib_name) ){
                found = true;
                break;
            }
        }
        
        if( ! found )
        {
            engine->log.warning("LIEFLoader: Couldn't find library '", lib_name, "': skipping import");
            continue;
        }

        // Load the library !
        addr_t lib_base = 0;
        try
        {
            switch (_elf->type())
            {
                case LIEF::ELF::ELF_CLASS::ELFCLASS64: 
                    lib_base = lib_loader.load_elf_library(
                        engine,
                        Format::ELF64, 
                        lib_path, 
                        libdirs, 
                        ignore_libs, 
                        loaded_libs,
                        top_loader
                    );
                    break;
                case LIEF::ELF::ELF_CLASS::ELFCLASS32:
                    lib_base = lib_loader.load_elf_library(
                        engine,
                        Format::ELF32,
                        lib_path,
                        libdirs,
                        ignore_libs,
                        loaded_libs,
                        top_loader
                    ); 
                    break;
                default: throw loader_exception("LoaderLIEF::load_elf_dependencies(): Unsupported ELFCLASS!");
            }
        }
        catch(loader_exception& e)
        {
            throw loader_exception(
                Fmt() << "Error loading library " << lib_name << ": "
                << " (path: " << lib_path << ") \n" << e.what()
                >> Fmt::to_str
            );
        }
        // If this was the interpreter, record its entry point
        std::cout << "DEBUG loaded dep: " << lib_name << std::endl;
        std::cout << "debug interp " << _clean_interpreter_name(_elf->interpreter());
        if (
            top_loader._elf->has_interpreter() and
            _clean_interpreter_name(top_loader._elf->interpreter()) == lib_name
        )
        {
            top_loader.interpreter_entry = 
                (addr_t)lib_loader._elf->entrypoint() + lib_base;
        }
    }
}

addr_t LoaderLIEF::load_elf_library(
    MaatEngine* engine,
    loader::Format type,
    const std::string& lib,
    const std::list<std::string>& libdirs,
    const std::list<std::string>& ignore_libs,
    std::list<std::string>& loaded_libs,
    LoaderLIEF& top_loader
)
{
    // Parse binary with LIEF
    parse_binary(lib, type);

    // Find available base address
    uint64_t vsize = _elf->virtual_size();
    addr_t base_address = find_free_space(engine, 0x1000, vsize);
    if (base_address == 0)
    {
        throw loader_exception(
            Fmt() << "LIEFLoader::_load_elf32_x86_library(): couldn't allocate "
            << std::hex << "0x" << vsize << " bytes to load library '" << lib << "'"
            >> Fmt::to_str
        );
    }

    // Load segments
    map_elf_segments(engine, base_address);

    // Add symbols to symbol manager
    add_elf_symbols(engine, base_address);

    // Load dependent libraries (recursively)
    load_elf_dependencies(engine, libdirs, ignore_libs, loaded_libs, top_loader);

    // Perform relocations
    perform_elf_relocations(engine, base_address);

    return base_address;
}

std::vector<std::pair<uint64_t, uint64_t>> LoaderLIEF::generate_aux_vector(
    MaatEngine* engine,
    addr_t base_segment,
    addr_t argv_0
)
{
    /* // Symbolic values for the entries in the auxiliary table
    //  put on the initial stack 
    #define AT_NULL   0	// end of vector 
    #define AT_IGNORE 1	// entry should be ignored 
    #define AT_EXECFD 2	// file descriptor of program 
    #define AT_PHDR   3	// program headers for program 
    #define AT_PHENT  4	// size of program header entry 
    #define AT_PHNUM  5	// number of program headers 
    #define AT_PAGESZ 6	// system page size 
    #define AT_BASE   7	// base address of interpreter 
    #define AT_FLAGS  8	// flags 
    #define AT_ENTRY  9	// entry point of program 
    #define AT_NOTELF 10	// program is not ELF 
    #define AT_UID    11	// real uid 
    #define AT_EUID   12	// effective uid 
    #define AT_GID    13	// real gid 
    #define AT_EGID   14	// effective gid 
    #define AT_PLATFORM 15  // string identifying CPU for optimizations 
    #define AT_HWCAP  16    // arch dependent hints at CPU capabilities 
    #define AT_CLKTCK 17	// frequency at which times() increments 
    // AT_* values 18 through 22 are reserved 
    #define AT_SECURE 23   // secure mode boolean 
    #define AT_BASE_PLATFORM 24	// string identifying real platform, may
                     * differ from AT_PLATFORM. 
    #define AT_RANDOM 25	// address of 16 random bytes 
    #define AT_HWCAP2 26	// extension of AT_HWCAP 
    #define AT_EXECFN  31	// filename of program 
    */

    reg_t sp = engine->arch->sp();
    std::string platform;

    if (engine->arch->type == Arch::Type::X86)
        platform = "x86";
    else if (engine->arch->type == Arch::Type::X64)
        platform = "x86_64";
    else if (engine->arch->type == Arch::Type::ARM64)
        platform = "arm64";
    else
        throw loader_exception("LIEFLoader::_generate_aux_vector(): got unsupported architecture");

    std::vector<std::pair<uint64_t, uint64_t>> aux_vector;
    aux_vector.push_back(std::make_pair(3, base_segment + _elf->imagebase() + 
            _elf->header().program_headers_offset())); // Address of program table (just after header)
                                                       // imagebase() in LIEF is @header - header_offset
    aux_vector.push_back(std::make_pair(4, _elf->header().program_header_size())); // Size of program table (just after header)
    aux_vector.push_back(std::make_pair(5, _elf->header().numberof_segments())); // Number of segments in program header
    aux_vector.push_back(std::make_pair(6, 0x1000)); // Default page size at 0x1000
    aux_vector.push_back(std::make_pair(7, 0)); // Base address of interpreter, we don't specify it 
    aux_vector.push_back(std::make_pair(8, 0)); // Set flags to 0 (I don't know what they do ...)
    aux_vector.push_back(std::make_pair(9, base_segment + _elf->entrypoint())); // Program entry point
    aux_vector.push_back(std::make_pair(11, 1000)); // uid
    aux_vector.push_back(std::make_pair(12, 1000)); // euid
    aux_vector.push_back(std::make_pair(13, 1000)); // gid
    aux_vector.push_back(std::make_pair(14, 1000)); // egid

    // Put platform string in memory
    engine->cpu.ctx().set(sp, engine->cpu.ctx().get(sp) - (platform.size()+1));
    engine->mem->write_buffer(engine->cpu.ctx().get(sp)->as_uint(), (uint8_t*)platform.c_str(), platform.size()+1);
    aux_vector.push_back(std::make_pair(15, engine->cpu.ctx().get(sp)->as_uint())); // Address of platform identifier string

    aux_vector.push_back(std::make_pair(16, 0x00000000bfebfbff));   // HWCAP : just ripped from my own machine, no idea what bit 
                                                                    // encodes what information

    aux_vector.push_back(std::make_pair(17, 0x64)); // times() frequency (just ripped from my own machine also)
    aux_vector.push_back(std::make_pair(23, 0)); // no secure mode boolean (I don't know what this does)

    // Generate 64 ""random"" bytes on stack
    std::vector<uint8_t> random_bytes = {0x5e,0xfb,0xa8,0x6f,0x37,0xe4,0xfc,0xde,0x45,0x79,0xdc,0x84,0x1b,0x3c,0x39,0x6a,0xad,0xd5,0xef,0x56,
        0x8d,0xe5,0x3a,0x95,0x22,0xa9,0x89,0x78,0xe8,0x5,0xfc,0x5d,0x9c,0x86,0x8f,0x7a,0xe2,0xa,0xad,0x4,0x2e,0x7a,0x8e,0xf4,0xa6,0xf7,
        0xf2,0xbe,0x10,0x13,0x1a,0x86,0x78,0x75,0x53,0x2f,0xde,0xad,0x47,0xa7,0x5e,0x8c,0xed,0xbb };
    addr_t random_bytes_addr = engine->cpu.ctx().get(sp)->as_uint() - random_bytes.size();
    engine->cpu.ctx().set(sp, random_bytes_addr);
    engine->mem->write_buffer(random_bytes_addr, (uint8_t*)&random_bytes[0], random_bytes.size());
    aux_vector.push_back(std::make_pair(25, random_bytes_addr)); // Address of random bytes

    aux_vector.push_back(std::make_pair(26, 0)); // Don't specify HWCAP extension
    aux_vector.push_back(std::make_pair(31, argv_0)); // Address of argv[0] which is the name of the program ;)

    return aux_vector; // should be ret-value-optimised by compiler
}


/*    X86 Relocations 
     ---------------
        Name 	 	        Calculation
        R_386_NONE 	        None
        R_386_32 	        S + A
        R_386_PC32 		    S + A – P
        R_386_GOT32 	    G + A
        R_386_PLT32 	    L + A – P
        R_386_COPY 	        Value is copied directly from shared object
        R_386_GLOB_DAT 	    S
        R_386_JMP_SLOT 	    S
        R_386_RELATIVE 	    B + A
        R_386_GOTOFF 	    S + A – GOT
        R_386_GOTPC 	    GOT + A – P
        R_386_32PLT 	    L + A
        R_386_16 	        S + A       (word)
        R_386_PC16          S + A – P   (word)
        R_386_8 	        S + A       (byte)
        R_386_PC8 	        S + A – P   (byte)
        R_386_SIZE32        Z + A
        R_386_IRELATIVE     The value (B+A) points to a resolver function which must be executed 
                            by the loader and returns in EAX the address of the choosen implementation
 
     X64 Relocations 
     ---------------
        Name 	 	        Size        Calculation
        --- R_AMD64_NONE        None        None
        R_AMD64_64          word64      S + A
        R_AMD64_PC32        word32      S + A - P
        --- R_AMD64_GOT32       word32      G + A
        --- R_AMD64_PLT32       word32      L + A - P
        R_AMD64_COPY        None        --- 
        R_AMD64_GLOB_DAT    word64      S
        R_AMD64_JUMP_SLOT   word64      S
        R_AMD64_RELATIVE    word64      B + A
        --- R_AMD64_GOTPCREL    word32      G + GOT + A - P
        R_AMD64_32          word32      S + A
        R_AMD64_32S         word32      S + A
        R_AMD64_16          word16      S + A
        R_AMD64_PC16        word16      S + A - P
        R_AMD64_8           word8       S + A
        R_AMD64_PC8         word8       S + A - P
        R_AMD64_PC64        word64      S + A - P
        --- R_AMD64_GOTOFF64    word64      S + A - GOT
        --- R_AMD64_GOTPC32     word32      GOT + A + P
        R_AMD64_SIZE32      word32      Z + A
        R_AMD64_SIZE64      word64      Z + A
        R_AMD64_IRELATIVE   word64      Ifunc resolver like in x86

*/
void LoaderLIEF::perform_elf_relocations(MaatEngine* engine, addr_t base_address)
{
    int arch_bytes = engine->arch->octets();
    
    // Create segment for missing imported functions
    addr_t emu = engine->mem->allocate_segment(
        0xaaab0000, 0x1000, 0x1000,
        maat::mem_flag_r,
        "Missing functions",
        true // is_special_segment
    );
    addr_t unsupported_idx = 0;

    uint64_t B, A, P, S, reloc_addr, reloc_new_value, simu_data_symbol_addr, symbol_size;
    std::string symbol_name = "";
    for (LIEF::ELF::Relocation& reloc : _elf->relocations())
    {
        B = base_address;
        A = reloc.is_rela() ? reloc.addend() : 0;
        P = reloc.address() + base_address; // Address of the relocation (virtual address) (+base_address)
        reloc_addr = reloc.address() + base_address;
        reloc_new_value;
        simu_data_symbol_addr = 0; // Address where we load imported data if any

        if (reloc.has_symbol())
        {
            symbol_name = get_symbol_name(reloc.symbol());
            S = reloc.symbol().value() + base_address; // Value of the symbol (its virtual address) (+ base_address)
            symbol_size = reloc.symbol().size();
        }
        else
        {
            symbol_name = "";
            S = 0;
            symbol_size = 0;
        }

        // Check if the symbol is imported
        if (reloc.has_symbol() and reloc.symbol().is_imported())
        {
            // std::cout << "DEBUG imported function " << symbol_name << std::endl;
            // Check if function
            if (reloc.symbol().is_function())
            {
                try
                {
                    const Symbol& sym = engine->symbols->get_by_name(symbol_name);
                    S = sym.addr; // Update symbol address for relocation
                }
                catch (const symbol_exception& e)
                {
                    engine->log.warning("Missing function: ", symbol_name);
                    // Add missing import
                    S = emu + unsupported_idx++;
                    std::cout << "DEBUG, addr of symbol is " << std::hex << S << std::endl;
                    std::cout << "DEBUG, reloc addr " << std::hex << reloc_addr << std::endl;
                    engine->symbols->add_symbol(Symbol(
                        Symbol::FunctionStatus::MISSING,
                        S,
                        symbol_name
                    ));
                }
            }
            // TODO check and import if data
        }


        if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_32
            or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_64)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, arch_bytes)->as_uint();
            reloc_new_value +=  S + A;
            engine->mem->write(reloc_addr, reloc_new_value, arch_bytes, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_32
            or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_32S)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 4)->as_uint(); 
            reloc_new_value += S + A;
            engine->mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_PC64)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 8)->as_uint();
            reloc_new_value +=  S + A - P;
            engine->mem->write(reloc_addr, reloc_new_value, 8, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_PC32
                or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_PC32)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 4)->as_uint();
            reloc_new_value +=  S + A - P;
            engine->mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_PC16)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 2)->as_uint();
            reloc_new_value +=  S + A - P;
            engine->mem->write(reloc_addr, reloc_new_value, 2, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_PC8)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 1)->as_uint();
            reloc_new_value +=  S + A - P;
            engine->mem->write(reloc_addr, reloc_new_value, 1, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_GLOB_DAT
                or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_GLOB_DAT)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, arch_bytes)->as_uint();
            reloc_new_value +=  S;
            engine->mem->write(reloc_addr, reloc_new_value, arch_bytes, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_RELATIVE
                or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_RELATIVE)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, arch_bytes)->as_uint();
            reloc_new_value +=  B + A;
            engine->mem->write(reloc_addr, reloc_new_value, arch_bytes, true); // Ignore memory flags
        }
        else if(reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_JUMP_SLOT
                or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_JUMP_SLOT)
        {
            std::cout << "DEBUG, jump slot S = 0x" << std::hex << S << std::endl;
            reloc_new_value =  S;
            engine->mem->write(reloc_addr, reloc_new_value, arch_bytes, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_COPY
                or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_COPY)
        {
            if( simu_data_symbol_addr != 0 ){
                engine->mem->write_buffer(P, engine->mem->raw_mem_at(simu_data_symbol_addr), reloc.symbol().size(), true ); // Ignore memory flags
            }
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_i386::R_386_IRELATIVE
                or reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_IRELATIVE)
        {
            //reloc_new_value = _call_ifunc_resolver(sym, (uint32_t)engine->mem->read(reloc_addr, 4)->concretize() + B + A);
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 4)->as_uint();
            reloc_new_value +=  B + A;
            engine->mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_16)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 2)->as_uint();
            reloc_new_value +=  S + A;
            engine->mem->write(reloc_addr, reloc_new_value, 2, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_8)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 1)->as_uint();
            reloc_new_value +=  S + A;
            engine->mem->write(reloc_addr, reloc_new_value, 1, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_SIZE32)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 4)->as_uint();
            reloc_new_value +=  symbol_size + A;
            engine->mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }
        else if (reloc.type() == (uint32_t)LIEF::ELF::RELOC_x86_64::R_X86_64_SIZE64)
        {
            reloc_new_value = reloc.is_rela()? 0 : engine->mem->read(reloc_addr, 8)->as_uint();
            reloc_new_value +=  symbol_size + A;
            engine->mem->write(reloc_addr, reloc_new_value, 8, true); // Ignore memory flags
        }
        else
        {
            engine->log.warning(
                "LoaderLIEF: unsupported X86 relocation type: ",
                reloc.type(),
                " for symbol '",
                symbol_name,
                "'"
            );
        }
    }
}


void LoaderLIEF::add_elf_symbols(MaatEngine* engine, uint64_t base)
{
    for (auto& symbol : _elf->symbols())
    {
        // Add internal function symbols
        if( symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_FUNC && symbol.value() != 0)
        {
            engine->symbols->add_symbol(Symbol(
                Symbol::FunctionStatus::LOADED,
                base + symbol.value(), // addr
                get_symbol_name(symbol)
            ));
        }
        // TODO data symbols
    }
}


} // namespace loader
} // namespace maat
#endif
