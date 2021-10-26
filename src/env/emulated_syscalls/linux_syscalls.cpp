#include "env/syscall.hpp"
#include "engine.hpp"


namespace maat{
namespace env{
namespace emulated{

// ================= Syscall functions ==================

// ssize_t read(int fd, void *buf, size_t count);
FunctionCallback::return_t sys_linux_read(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    int fd = args[0]->as_uint(*engine.vars);
    size_t count = args[2]->as_uint(*engine.vars);

    // Get file accessor and read file
    env::FileAccessor& fa = engine.env->fs.get_fa_by_handle(fd);
    std::vector<Expr> content;
    cst_t res = fa.read_buffer(content, count, 1);
    // Write to buffer in memory
    engine.mem->write_buffer(args[1], content);
    // Return number of bytes read
    return res;
}

// ssize_t read(int fd, void *buf, size_t count, off_t offset);
FunctionCallback::return_t sys_linux_pread(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    int fd = args[0]->as_uint(*engine.vars);
    size_t count = args[2]->as_uint(*engine.vars);
    offset_t offset = args[3]->as_uint(*engine.vars);

    // pread() reads from an arbitrary offset in the file and
    // doesn't change the offset, so directly read from the
    // PhysicalFile
    physical_file_t file = engine.env->fs.get_file_by_handle(fd);
    std::vector<Expr> content;
    cst_t res = file->read_buffer(content, offset, count, 1);
    // Write to buffer in memory
    engine.mem->write_buffer(args[1], content);
    // Return number of bytes read
    return res;
}

// int stat(const char *restrict pathname,struct stat *restrict statbuf);
FunctionCallback::return_t sys_linux_stat(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    /* struct stat {
               dev_t     st_dev;         // ID of device containing file 
               ino_t     st_ino;         // Inode number 
               mode_t    st_mode;        // File type and mode 
               nlink_t   st_nlink;       // Number of hard links 
               uid_t     st_uid;         // User ID of owner 
               gid_t     st_gid;         // Group ID of owner 
               dev_t     st_rdev;        // Device ID (if special file) 
               off_t     st_size;        // Total size, in bytes 
               blksize_t st_blksize;     // Block size for filesystem I/O 
               blkcnt_t  st_blocks;      // Number of 512B blocks allocated 

               // Since Linux 2.6, the kernel supports nanosecond
                  precision for the following timestamp fields.
                  For the details before Linux 2.6, see NOTES.

               struct timespec st_atim;  // Time of last access 
               struct timespec st_mtim;  // Time of last modification 
               struct timespec st_ctim;  // Time of last status change 

           #define st_atime st_atim.tv_sec      // Backward compatibility 
           #define st_mtime st_mtim.tv_sec
           #define st_ctime st_ctim.tv_sec
           }; 
    */

    // stmode_t stuff 
    ucst_t xS_IFMT =   0170000; //  bit mask for the file type bit field

    ucst_t xS_IFSOCK = 0140000; //   socket
    ucst_t xS_IFLNK = 0120000;  // symbolic link
    ucst_t xS_IFREG = 0100000;  // regular file
    ucst_t xS_IFBLK = 0060000;  //  block device
    ucst_t xS_IFDIR = 0040000;  // directory
    ucst_t xS_IFCHR = 0020000;  // character device
    ucst_t xS_IFIFO = 0010000;  //  FIFO

    std::string filepath = engine.mem->read_string(args[0]);
    addr_t statbuf = args[1]->as_uint(*engine.vars);
    addr_t long_size = engine.arch->octets(); // Size for long unsigned int / long int fields

    if (engine.env->fs.is_relative_path(filepath))
        filepath = engine.env->fs.path_from_relative_path(filepath, engine.process->pwd);
    
    // Check file info
    env::node_status_t status = engine.env->fs.get_node_status(filepath);
    ucst_t st_mode = 0;
    ucst_t st_size = 0;
    if (env::node::check_is_file(status))
    {
        st_size = engine.env->fs.get_file(filepath)->size();
        st_mode |= xS_IFREG;
    }
    if (env::node::check_is_dir(status))
    {
        st_mode |= xS_IFDIR;
    }
    if (env::node::check_is_symlink(status))
    {
        st_mode |= xS_IFLNK;
    }
    // TODO FIFO, socket...

    // Most of the values are ripped from experiments on my own machine
    // Order of the fields in the stat struct also come from the reverse on my own machine
    engine.mem->write(statbuf, 0x16, long_size); // st_dev
    statbuf += long_size;
    engine.mem->write(statbuf, 0x4, long_size); // st_ino
    statbuf += long_size;
    engine.mem->write(statbuf, 0x1, long_size); // st_nlink
    statbuf += long_size;
    engine.mem->write(statbuf, st_mode, 4); // st_mode
    statbuf += 4;
    engine.mem->write(statbuf, 1000, 4); // st_uid
    statbuf += 4;
    engine.mem->write(statbuf, 1000, 4); // st_gid
    statbuf += 4;
    if (engine.arch->octets() == 8)
        statbuf += 4; // To align on 8 bits if 64 bits
    engine.mem->write(statbuf, 0x8804, long_size); // st_rdev
    statbuf += long_size;
    engine.mem->write(statbuf, st_size, long_size); // st_size
    statbuf += long_size;
    engine.mem->write(statbuf, 2048, long_size); // st_blksize
    statbuf += long_size;
    engine.mem->write(statbuf, st_size/512, long_size); // st_blocks
    statbuf += long_size;

    // timespec structures
    std::time_t curr_time = std::time(nullptr);
    // atime (last access)
    engine.mem->write(statbuf, curr_time, long_size); // timestamp in seconds
    engine.mem->write(statbuf+long_size, 0, long_size); // we don't care about nanoseconds
    statbuf += long_size*2;
    // mtime (last modification)
    engine.mem->write(statbuf, curr_time-5, long_size); // timestamp in seconds
    engine.mem->write(statbuf+long_size, 0, long_size); // we don't care about nanoseconds
    statbuf += long_size*2;
    // ctime (last status change)
    engine.mem->write(statbuf, curr_time-20, long_size); // timestamp in seconds
    engine.mem->write(statbuf+long_size, 0, long_size); // we don't care about nanoseconds
    statbuf += long_size*2;

    return 0; // Success
}

// int brk(void* addr)
FunctionCallback::return_t sys_linux_brk(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    addr_t addr = args[0]->as_uint(*engine.vars);
    addr_t end_heap, prev_end;
    addr_t extend_bytes = 0;

    std::cout << "DEBUG BRK address " << addr << std::endl;
    // throw std::exception();

    // Find the heap's end address
    auto heap = engine.mem->get_segment_by_name("Heap");
    if (heap == nullptr)
    {
        throw env_exception("Emulated brk(): didn't find 'Heap' segment!");
    }
    end_heap = heap->end+1;
    // Special behaviour for brk(NULL), return end of Heap
    if (addr == 0)
    {
        return (cst_t)(heap->end+1);
    }
    // Try to resize this segment
    else if (addr > heap->end +1)
    {
        // First check if memory is free for extending
        extend_bytes = addr - heap->end -1;
        if (not engine.mem->is_free(heap->end+1, heap->end+1+extend_bytes))
        {
            return -1; // Memory not free
        }
        // Then extend
        prev_end = heap->end+1;
        heap->extend_after(extend_bytes);
        end_heap = heap->end+1;
        // Mark new memory as RW
        engine.mem->page_manager.set_flags(prev_end, end_heap, maat::mem_flag_rw);
        return 0; // Success
    }

    return 0; // Success
}

// int access(const char *pathname, int mode);
FunctionCallback::return_t sys_linux_access(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    ucst_t  R = 4,
            W = 2,
            X = 1,
            F = 0;
    ucst_t mode = args[1]->as_uint(*engine.vars);
    std::string file = engine.mem->read_string(args[0]);
    std::cout << "debug filename " << file << std::endl;
    // Get file
    env::node_status_t status = engine.env->fs.get_node_status(file);
    // Test if file exists 
    if (not env::node::check_is_file(status))
        return -1;
    // TODO: check for RWX perms once they are supported in the filesystem
    return 0;
}

// int uname(struct utsname *buf);
FunctionCallback::return_t sys_linux_newuname(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    /*
     * buf is of following type:
    struct utsname {
               char sysname[];    // Operating system name (e.g., "Linux")
               char nodename[];   // Name within "some implementation-defined
                                     network"
               char release[];    // Operating system release (e.g., "2.6.28")
               char version[];    // Operating system version
               char machine[];    // Hardware identifier 
           #ifdef _GNU_SOURCE
               char domainname[]; // NIS or YP domain name
           #endif
           };
        
        Note: Each array is actually of size 65 !
    */


    addr_t utsname = args[0]->as_uint(*engine.vars);
    std::string sysname = "Linux\x00";
    std::string nodename = "\x00"; // Not supported
    std::string release = "4.15.0-88-generic\x00";
    std::string version = "#88-Ubuntu SMP Tue Feb 11 20:11:34 UTC 2020\x00";
    std::string machine = "x86_64\x00";
    std::string domainname = "\x00"; // Not supported

    // Write OS name
    engine.mem->write_buffer(utsname, (uint8_t*)sysname.c_str(), sysname.size()+1);
    // nodename ?
    engine.mem->write_buffer(utsname + 65, (uint8_t*)nodename.c_str(), nodename.size()+1);
    // Write OS release and version
    engine.mem->write_buffer(utsname + 65*2, (uint8_t*)release.c_str(), release.size()+1);
    engine.mem->write_buffer(utsname + 65*3, (uint8_t*)version.c_str(), version.size()+1);
    // Write hardware id
    engine.mem->write_buffer(utsname + 65*4, (uint8_t*)machine.c_str(), machine.size()+1);
    // Write domain name
    engine.mem->write_buffer(utsname + 65*5, (uint8_t*)domainname.c_str(), domainname.size()+1);
    
    // On success return zero
    return 0;
}

// int arch_prctl(struct task_struct *task, int code, unsigned long* addr)
FunctionCallback::return_t sys_linux_arch_prctl(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    /* Function codes
        #define ARCH_SET_GS		0x1001
        #define ARCH_SET_FS		0x1002
        #define ARCH_GET_FS		0x1003
        #define ARCH_GET_GS		0x1004

        #define ARCH_GET_CPUID		0x1011
        #define ARCH_SET_CPUID		0x1012

        #define ARCH_CET_STATUS		0x3001
        #define ARCH_CET_DISABLE	0x3002
        #define ARCH_CET_LOCK		0x3003
        #define ARCH_CET_EXEC		0x3004
        #define ARCH_CET_ALLOC_SHSTK	0x3005
        #define ARCH_CET_PUSH_SHSTK	0x3006
    */
    ucst_t code = args[0]->as_uint(*engine.vars);
    if (code == 0x1002) // Set FS
    {
        // HACK: in Maat we don't distinguish between segment selector
        // and the address their entry points to 
        engine.cpu.ctx().set(X64::FS, args[1]);
    }
    else if (code >= 0x3001 and code <= 0x3006)
    {
        // CET stuff, not supported but pretend everything went fine
        return 0; // Success
    }
    else
    {
        throw env_exception(
            Fmt() << "Emulated arch_prctl(): unsupported subfunction code: 0x"
            << std::hex << code
            >> Fmt::to_str
        );
    }

    return 0; // Success
}

// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
FunctionCallback::return_t sys_linux_openat(
    MaatEngine& engine,
    const std::vector<Expr>& args
)
{
    cst_t AT_FDCWD = -100; 
    std::string pathname = engine.mem->read_string(args[1]);
    int dirfd = args[0]->as_int(*engine.vars);
    int flags = args[2]->as_int(*engine.vars);
    bool absolute_path = pathname[0] == '/';
    std::string filepath = "";
    // Get filepath
    if (absolute_path)
    {
        filepath = pathname;
    }
    else
    {
        if (dirfd == AT_FDCWD) // Relative to current dir
        {
            filepath = engine.env->fs.path_from_relative_path(pathname, engine.process->pwd);
        }
        else // Relative to dirfd
        {
            throw env_exception("Emulated openat(): not supported for arbitrary dirfd");
        }
    }
    // Open file 
    // Flags in octal
    int O_CREAT = 00000100;
    int O_APPEND = 00002000;
    int O_EXCL = 00000200;
    int O_TRUNC = 00001000;

    if (flags & O_EXCL)
        throw env_exception("Emulated openat(): O_EXCL flag not supported");
    if (flags & O_TRUNC)
        throw env_exception("Emulated openat(): O_TRUNC flag not supported");
    if (flags & O_APPEND)
        throw env_exception("Emulated openat(): O_APPEND flag not supported");

    std::cout << "DEBUG openat filepath " << filepath << "\n\n\n\n\n";
    try
    {
        // Check if file exists
        if (not engine.env->fs.file_exists(filepath))
        {
            if (flags & O_CREAT)
                engine.env->fs.create_file(filepath);
            else // Failure, return -1
                return -1;
        }
        env::filehandle_t handle = engine.env->fs.new_fa(filepath);
        return handle; // Success
    }
    catch(const env_exception& e)
    {
        // If file doesn't exist, we just emit a warning and emulate syscall failure
        engine.log.warning("Emulated openat() failed: ", e.what());
        return -1; // Failure
    }
}

// ================= Build the syscall maps =================
syscall_func_map_t linux_x86_syscall_map()
{
    syscall_func_map_t res
    {
        {3, Function("sys_read", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_read))},
        {18, Function("sys_stat", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_stat))},
        {33, Function("sys_access", FunctionCallback({env::abi::auto_argsize, 4}, sys_linux_access))},
        {45, Function("sys_brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))},
        {122, Function("sys_newuname", FunctionCallback({env::abi::auto_argsize}, sys_linux_newuname))},
        {180, Function("sys_pread", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_pread))}
    };
    return res;
}

syscall_func_map_t linux_x64_syscall_map()
{
    syscall_func_map_t res
    {
        {0, Function("sys_read", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_read))},
        {4, Function("sys_stat", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_stat))},
        {12, Function("sys_brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))},
        {17, Function("sys_pread64", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_pread))},
        {21, Function("sys_access", FunctionCallback({env::abi::auto_argsize, 4}, sys_linux_access))},
        {63, Function("sys_newuname", FunctionCallback({env::abi::auto_argsize}, sys_linux_newuname))},
        {158, Function("sys_arch_prctl", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_arch_prctl))},
        {257, Function("sys_openat", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_openat))}
    
    };
    return res;
}

} // namespace emulated
} // namespace env
} // namespace maat