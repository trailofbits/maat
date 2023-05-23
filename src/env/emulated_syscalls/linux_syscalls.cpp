#include "maat/env/syscall.hpp"
#include "maat/engine.hpp"


namespace maat{
namespace env{
namespace emulated{

// ================= Syscall functions ==================

// ssize_t read(int fd, void *buf, size_t count);
FunctionCallback::return_t sys_linux_read(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    int fd = args[0].as_uint(*engine.vars);
    size_t count = args[2].as_uint(*engine.vars);
    // Get file accessor and read file
    env::FileAccessor& fa = engine.env->fs.get_fa_by_handle(fd);
    std::vector<Value> content;
    cst_t res = fa.read_buffer(content, count, 1);
    // Write to buffer in memory
    engine.mem->write_buffer(args[1], content);
    // Return number of bytes read
    return res;
}

// ssize_t read(int fd, void *buf, size_t count, off_t offset);
FunctionCallback::return_t sys_linux_pread(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    int fd = args[0].as_uint(*engine.vars);
    size_t count = args[2].as_uint(*engine.vars);
    offset_t offset = args[3].as_uint(*engine.vars);

    // pread() reads from an arbitrary offset in the file and
    // doesn't change the offset, so directly read from the
    // PhysicalFile
    physical_file_t file = engine.env->fs.get_file_by_handle(fd);
    std::vector<Value> content;
    cst_t res = file->read_buffer(content, offset, count, 1);
    // Write to buffer in memory
    engine.mem->write_buffer(args[1], content);
    // Return number of bytes read
    return res;
}

// ssize_t write(int fd, const void *buf, size_t count);
FunctionCallback::return_t sys_linux_write(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    int fd = args[0].as_uint(*engine.vars);
    cst_t count = args[2].as_uint(*engine.vars);
    Value buf = args[1];
    cst_t res;

    try
    {
        env::FileAccessor& fa = engine.env->fs.get_fa_by_handle(fd);
        // Read buffer of bytes
        std::vector<Value> buffer;
        engine.mem->read_buffer(buffer, buf, count, 1);
        // Write it to file
        res = fa.write_buffer(buffer);
    }
    catch(const env_exception& e)
    {
        engine.log.warning("Emulated write(): failed because of env exception: ", e.what());
        return -1; // Failure
    }

    // Return number of bytes written
    return res;
}

// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
// struct iovec {
//     void  *iov_base;    /* Starting address */
//     size_t iov_len;     /* Number of bytes to transfer */
// };
FunctionCallback::return_t sys_linux_writev(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    int fd = args[0].as_uint(*engine.vars);
    cst_t count = args[2].as_uint(*engine.vars);
    Value iov = args[1];
    cst_t res = 0;
    Value iov_len, iov_base;
    ucst_t ptr_size = engine.arch->octets();
    ucst_t struct_size = ptr_size*2;
    // Write all iov buffers
    for (cst_t i = 0; i < count; i++)
    {
        // Read iovec struct
        iov_base = engine.mem->read(iov.as_uint(*engine.vars) + i*struct_size, ptr_size);
        iov_len = engine.mem->read(iov.as_uint(*engine.vars) + i*struct_size + ptr_size, ptr_size);
        res += iov_len.as_uint(*engine.vars);
        // Perform write() syscall
        std::vector<Value> write_args = {args[0], iov_base, iov_len};
        sys_linux_write(engine, write_args);
    }
    return res;
}

// Generic helper for stat, fstat
FunctionCallback::return_t _stat(
    MaatEngine& engine,
    env::physical_file_t file,
    addr_t statbuf
)
{
    /* struct stat {
               dev_t     st_dev;         // ID of device containing file 
               ino_t     st_ino;         // Inode number 
               mode_t    st_mode;        // File type and mode 
               nlink_t   st_nlink;       // Number of hard links 
               uuid_t     st_uid;         // User ID of owner 
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

    addr_t long_size = engine.arch->octets(); // Size for long unsigned int / long int fields

    ucst_t st_mode = 0;
    ucst_t st_size = 0;
    node_status_t status = file->status();
    if (env::node::check_is_file(status))
    {
        st_size = file->size();
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
    engine.mem->write(statbuf, file->uid(), long_size); // st_ino
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

// int stat(const char *restrict pathname, struct stat *restrict statbuf);
FunctionCallback::return_t sys_linux_stat(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    std::string filepath = engine.mem->read_string(args[0]);
    addr_t statbuf = args[1].as_uint(*engine.vars);

    if (engine.env->fs.is_relative_path(filepath))
        filepath = engine.env->fs.path_from_relative_path(filepath, engine.process->pwd);

    // Check if file exists
    if (not engine.env->fs.file_exists(filepath))
        return -1; // Error
    // Fill the statbuf struct
    env::physical_file_t file = engine.env->fs.get_file(filepath);
    return _stat(engine, file, statbuf);
}

// int close(int fd);
FunctionCallback::return_t sys_linux_close(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    int fd = args[0].as_uint(*engine.vars);

    try
    {
        engine.env->fs.delete_fa(fd);
        return 0;
    }
    catch(const env_exception& e)
    {
        engine.log.warning("Emulated close(): catched error from filesystem: ", e.what());
        return -1; // Failure
    }
}

// int fstat(int fd, struct stat *restrict statbuf);
FunctionCallback::return_t sys_linux_fstat(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    int fd = args[0].as_uint(*engine.vars);
    addr_t statbuf = args[1].as_uint(*engine.vars);

    env::physical_file_t file = engine.env->fs.get_file_by_handle(fd);
    return _stat(engine, file, statbuf);
}


// int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
FunctionCallback::return_t sys_linux_fstatat(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    cst_t AT_FDCWD = -100;
    cst_t AT_EMPTY_PATH = 0x1000;
    cst_t ERR_ENOENT = 3025;
    std::string pathname = engine.mem->read_string(args[1]);
    addr_t statbuf = args[2].as_uint(*engine.vars);
    int dirfd = args[0].as_int(*engine.vars);
    int flags = args[3].as_int(*engine.vars);
    bool absolute_path = pathname[0] == '/';
    std::string filepath = "";
    physical_file_t file = nullptr;

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
        else if (flags & AT_EMPTY_PATH) // dirfd points to the file, ignore pathname
        {
            file = engine.env->fs.get_file_by_handle(dirfd);
        }
        else // Relative to dirfd
        {
            throw env_exception("Emulated fstatat(): not supported for arbitrary dirfd");
        }
    }
    if (file == nullptr)
    {
        // Check if file exists
        if (not engine.env->fs.file_exists(filepath))
            return -ERR_ENOENT; // Error: No such path or directory
        file = engine.env->fs.get_file(filepath);
    }
    return _stat(engine, file, statbuf);
}

// void *mmap(void *addr, size_t length, int prot, int flags,
//            int fd, off_t offset);
// TODO: make this generic to support the old_mmap() syscall on X86 
// where arguments are passed in a struct pointer :/
FunctionCallback::return_t sys_linux_mmap(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    addr_t addr = args[0].as_uint(*engine.vars);
    cst_t length = args[1].as_uint(*engine.vars);
    int prot = args[2].as_uint(*engine.vars);
    ucst_t flags = args[3].as_uint(*engine.vars);
    cst_t fd = args[4].as_uint(*engine.vars);
    offset_t offset  = args[5].as_uint(*engine.vars);
    mem_flag_t mflags = 0;
    addr_t res = -1;
    cst_t aligned_length;
    ucst_t MAP_ANONYMOUS = 0x20, MAP_FIXED=0x10;
    int PROT_EXEC = 0x4, PROT_READ = 0x1, PROT_WRITE = 0x2;
    std::string map_name = "";

    // Mode
    if (prot & PROT_EXEC)
        mflags |= maat::mem_flag_x;
    if (prot & PROT_READ)
        mflags |= maat::mem_flag_r;
    if (prot & PROT_WRITE)
        mflags |= maat::mem_flag_w;

    // Adjust addr
    if (addr % 0x1000 != 0)
    {
        if (!(flags & MAP_FIXED))
            addr = addr + (0x1000 - (addr % 0x1000));
        else
        {
            engine.log.warning(
                "Emulated mmap(): called with MAP_FIXED but address isn't aligned on page size"
            );
            return -1;
        }
    }
    // Adjust length to be a multiple 
    if( length % 0x1000 != 0)
        aligned_length = length + (0x1000 - (length % 0x1000));
    else
        aligned_length = length;

    // If not ANONYMOUS, get the file
    physical_file_t file = nullptr;
    if (not (flags & MAP_ANONYMOUS))
    {
        try
        {
            file = engine.env->fs.get_file_by_handle(fd);
            FileAccessor& fa = engine.env->fs.get_fa_by_handle(fd);
            if (not fa.filename().empty())
                map_name = fa.filename(); 
        }
        catch(const env_exception& e)
        {
            engine.log.warning("Emulated mmap(): couldn't get file for fd: ", fd);
            return -1;
        }
    }

    // Allocate memory
    if (flags & MAP_FIXED)
    {
        // Find where to allocate new memory
        addr_t prev_end = 0;
        addr_t map_end_addr = addr + aligned_length -1;
        engine.mem->map(addr, map_end_addr, mflags, map_name);
        res = addr;
    }
    else
    {
        // Try to allocate memory wherever possible
        try
        {
            res = engine.mem->allocate(addr == 0 ? 0x4000000: addr, aligned_length, 0x1000, mflags, map_name);
        }
        catch(const mem_exception& e)
        {
            // Return error
            engine.log.warning("Emulated mmap(): memory engine failed to allocate requested memory");
            return -1;
        }
    }

    // Fill mapping with zeros
    std::vector<uint8_t> zeros(aligned_length, 0);
    engine.mem->write_buffer(res, zeros.data(), aligned_length, true);

    // Complete with file content
    if (not (flags & MAP_ANONYMOUS))
    {
        // Read the file content as a buffer
        if (offset + length > file->size())
        {
            // If requesting too many bytes, adjust to real file size
            length = file->size() - offset;
        }
        std::vector<Value> content;
        file->read_buffer(content, offset, length, 1); // Read file content into buffer
        // Write the file content in allocated memory
        engine.mem->write_buffer(res, content, true); // Ignore flags when mapping file
    }

    return (cst_t)res;
}

// Similar to mmap except the last argument specifies the offset
// into the file in 4096-byte units (instead of bytes, as is done by mmap(2))
FunctionCallback::return_t sys_linux_mmap2(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    std::vector<Value> new_args = args;
    new_args[5] = new_args[5]*4096;
    return sys_linux_mmap(engine, new_args);
}


FunctionCallback::return_t sys_linux_munmap(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    addr_t addr = args[0].as_uint(*engine.vars);
    cst_t length = args[1].as_uint(*engine.vars);

    // Adjust addr and length
    if (addr % 0x1000 != 0)
        addr = addr + (0x1000 - (addr % 0x1000));
    // Adjust length to be a multiple 
    if( length % 0x1000 != 0)
        length = length + (0x1000 - (length % 0x1000));
    engine.mem->unmap(addr, addr+length-1);
    return 0;
}

// int mprotect(void *addr, size_t len, int prot);
FunctionCallback::return_t sys_linux_mprotect(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    addr_t addr = args[0].as_uint(*engine.vars);
    cst_t length = args[1].as_uint(*engine.vars);
    int prot = args[2].as_int(*engine.vars);
    mem_flag_t flags = 0;
    int PROT_EXEC = 0x4, PROT_READ = 0x1, PROT_WRITE = 0x2;

    // Check addr
    if (addr % 0x1000 != 0)
    {
        engine.log.warning("Emulated mprotect(): address not multiple of page size (0x1000)");
        return -1; // Error
    }

    // Mode
    if (prot & PROT_EXEC)
        flags |= maat::mem_flag_x;
    if (prot & PROT_READ)
        flags |= maat::mem_flag_r;
    if (prot & PROT_WRITE)
        flags |= maat::mem_flag_w;

    // Change memory mode/flags
    engine.mem->page_manager.set_flags(addr, addr+length-1, flags);
    return 0; // Success
}

// int brk(void* addr)
FunctionCallback::return_t sys_linux_brk(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    addr_t addr = args[0].as_uint(*engine.vars);
    addr_t end_heap, prev_end;
    addr_t extend_bytes = 0;

    // Find the heap's end address
    const auto& heap = engine.mem->mappings.get_map_by_name("Heap");

    end_heap = heap.end+1;
    // Special behaviour for brk(NULL), return end of Heap
    if (addr == 0)
    {
        return (cst_t)(end_heap);
    }
    // Try to resize this segment
    else if (addr > end_heap)
    {
        // First check if memory is free for extending
        if (not engine.mem->is_free(end_heap, addr-1))
        {
            return -1; // Memory not free
        }
        // Extend map by remapping
        engine.mem->map(heap.start, addr-1, maat::mem_flag_rw, "Heap");
        return 0; // Success
    }

    return 0; // Success
}

// int access(const char *pathname, int mode);
FunctionCallback::return_t sys_linux_access(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    ucst_t  R = 4,
            W = 2,
            X = 1,
            F = 0;
    ucst_t mode = args[1].as_uint(*engine.vars);
    std::string file = engine.mem->read_string(args[0]);
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
    const std::vector<Value>& args
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


    addr_t utsname = args[0].as_uint(*engine.vars);
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
    const std::vector<Value>& args
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
    ucst_t code = args[0].as_uint(*engine.vars);
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

FunctionCallback::return_t linux_generic_open(MaatEngine& engine, const std::string& filepath, int flags)
{
    // Open file 
    // Flags in octal
    int O_CREAT = 00000100;
    int O_APPEND = 00002000;
    int O_EXCL = 00000200;
    int O_TRUNC = 00001000;

    if (flags & O_EXCL)
        throw env_exception("Emulated open(): O_EXCL flag not supported");
    if (flags & O_TRUNC)
        throw env_exception("Emulated open(): O_TRUNC flag not supported");
    if (flags & O_APPEND)
        throw env_exception("Emulated open(): O_APPEND flag not supported");

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
        engine.log.warning("Emulated open() failed: ", e.what());
        return -1; // Failure
    }
}

// int open(const char *pathname, int flags, mode_t mode);
FunctionCallback::return_t sys_linux_open(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    std::string pathname = engine.mem->read_string(args[0]);
    int flags = args[1].as_int(*engine.vars);
    bool absolute_path = pathname[0] == '/';
    std::string filepath = "";
    // Get filepath
    if (absolute_path)
    {
        filepath = pathname;
    }
    else
    {
        filepath = engine.env->fs.path_from_relative_path(pathname, engine.process->pwd);
    }
    return linux_generic_open(engine, filepath, flags);
}

// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
FunctionCallback::return_t sys_linux_openat(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    cst_t AT_FDCWD = -100; 
    std::string pathname = engine.mem->read_string(args[1]);
    int dirfd = args[0].as_int(*engine.vars);
    int flags = args[2].as_int(*engine.vars);
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

    return linux_generic_open(engine, filepath, flags);
}

//--------------------------------------------------------------------
FunctionCallback::return_t sys_linux_getpid(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    return engine.process->pid;
}

FunctionCallback::return_t sys_linux_gettid(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    // In a single-threaded process, the thread ID is equal to the process ID
    return sys_linux_getpid(engine, args);
}

FunctionCallback::return_t sys_linux_set_tid_address(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    //pretend everything went fine
    engine.log.warning("Emulated set_tid_address(): faking success");
    // Always return the caller's thread ID
    return sys_linux_gettid(engine, args);
}

//--------------------------------------------------------------------
// ssize_t readlink(const char *path, char *buf, size_t bufsiz);
FunctionCallback::return_t sys_linux_readlink(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    addr_t path = args[0].as_uint(*engine.vars);
    addr_t buf = args[1].as_uint(*engine.vars);
    size_t bufsiz = args[2].as_uint(*engine.vars);
    cst_t res;

    // Get file
    std::string filepath = engine.mem->read_string(path);
    env::node_status_t status = engine.env->fs.get_node_status(filepath);
    if (not env::node::check_is_symlink(status))
    {
        // Not a symbolic link, return error
        engine.log.warning("Emulated readlink(): called on '", filepath, "' which isn't a symbolic link");
        return -1;
    }
    std::string pointed_file = engine.env->fs.pointed_path_from_symlink(filepath);

    // Write pointed file to buffer
    res = pointed_file.size(); // not +1 because readlink() doesn't append null byte to buffer
    if (res > bufsiz)
        res = bufsiz;
    engine.mem->write_buffer(buf, (uint8_t*)pointed_file.c_str(), res);

    // Return number of bytes written
    return res;
}

// void exit(int status);
FunctionCallback::return_t sys_linux_exit(
    MaatEngine& engine,
    const std::vector<Value>& args
)
{
    engine.terminate_process(args[0]);
    return std::monostate();
}

// ================= Build the syscall maps =================
syscall_func_map_t linux_x86_syscall_map()
{
    syscall_func_map_t res
    {
        {3, Function("sys_read", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_read))},
        {4, Function("sys_write", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_write))},
        {5, Function("sys_open", FunctionCallback({env::abi::auto_argsize, 4, 4}, sys_linux_open))},
        {6, Function("sys_close", FunctionCallback({4}, sys_linux_close))},
        {18, Function("sys_stat", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_stat))},
        {28, Function("sys_fstat", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_fstat))},
        {33, Function("sys_access", FunctionCallback({env::abi::auto_argsize, 4}, sys_linux_access))},
        {45, Function("sys_brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))},
        {56, Function("sys_exit", FunctionCallback({4}, sys_linux_exit))},
        {85, Function("sys_readlink", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_readlink))},
        {91, Function("sys_munmap", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_munmap))},
        {122, Function("sys_newuname", FunctionCallback({env::abi::auto_argsize}, sys_linux_newuname))},
        {125, Function("sys_mprotect", FunctionCallback({env::abi::auto_argsize, 4, 4}, sys_linux_mprotect))},
        {146, Function("sys_writev", FunctionCallback({4, env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_writev))},
        {180, Function("sys_pread", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_pread))},
        {192, Function("sys_mmap2", FunctionCallback({env::abi::auto_argsize, 4, 4, 4, 4, 4}, sys_linux_mmap2))},
        {195, Function("sys_stat64", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_stat))},
        {197, Function("sys_fstat64", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_fstat))}, 
        {212, Function("sys_exit_group", FunctionCallback({4}, sys_linux_exit))},
        {295, Function("sys_openat", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_openat))}
    };
    return res;
}

syscall_func_map_t linux_x64_syscall_map()
{
    syscall_func_map_t res
    {        
        {0, Function("sys_read", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_read))},
        {1, Function("sys_write", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_write))},
        {2, Function("sys_open", FunctionCallback({env::abi::auto_argsize, 4, 4}, sys_linux_open))},
        {3, Function("sys_close", FunctionCallback({4}, sys_linux_close))},
        {4, Function("sys_stat", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_stat))},
        {5, Function("sys_fstat", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_fstat))},
        {9, Function("sys_mmap", FunctionCallback({env::abi::auto_argsize, 4, 4, 4, 4, 4}, sys_linux_mmap))},
        {11, Function("sys_munmap", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_munmap))},
        {10, Function("sys_mprotect", FunctionCallback({env::abi::auto_argsize, 4, 4}, sys_linux_mprotect))},
        {12, Function("sys_brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))},
        {17, Function("sys_pread64", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_pread))},
        {20, Function("sys_writev", FunctionCallback({4, env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_writev))},
        {21, Function("sys_access", FunctionCallback({env::abi::auto_argsize, 4}, sys_linux_access))},
        {39, Function("sys_linux_getpid", FunctionCallback({},sys_linux_getpid))},   // nathan edit
        {60, Function("sys_exit", FunctionCallback({4}, sys_linux_exit))},
        {63, Function("sys_newuname", FunctionCallback({env::abi::auto_argsize}, sys_linux_newuname))},
        {89, Function("sys_readlink", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_readlink))},
        {158, Function("sys_arch_prctl", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_arch_prctl))},
        {218, Function("sys_set_tid_address", FunctionCallback({},sys_linux_gettid))},  //nathan edit plz
        {231, Function("sys_exit_group", FunctionCallback({4}, sys_linux_exit))},
        {257, Function("sys_openat", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_openat))},
        {262, Function("sys_newfstatat", FunctionCallback({4, env::abi::auto_argsize, env::abi::auto_argsize, 4}, sys_linux_fstatat))}
    };
    return res;
}

syscall_func_map_t linux_ppc32_syscall_map()
{
    syscall_func_map_t res
    {        
        {1, Function("sys_exit", FunctionCallback({4}, sys_linux_exit))},
        {3, Function("sys_read", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_read))},
        {4, Function("sys_write", FunctionCallback({4, env::abi::auto_argsize, 4}, sys_linux_write))},
        {5, Function("sys_open", FunctionCallback({env::abi::auto_argsize, 4, 4}, sys_linux_open))},
        {6, Function("sys_close", FunctionCallback({4}, sys_linux_close))},
        {18, Function("sys_stat", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_stat))},
        {28, Function("sys_fstat", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_fstat))},
        {33, Function("sys_access", FunctionCallback({env::abi::auto_argsize, 4}, sys_linux_access))},
        {45, Function("sys_brk", FunctionCallback({env::abi::auto_argsize}, sys_linux_brk))},
        {85, Function("sys_readlink", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_readlink))},
        {90, Function("sys_mmap", FunctionCallback({env::abi::auto_argsize, 4, 4, 4, 4, 4}, sys_linux_mmap))},
        {91, Function("sys_munmap", FunctionCallback({env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_munmap))},
        {122, Function("sys_newuname", FunctionCallback({env::abi::auto_argsize}, sys_linux_newuname))},
        {125, Function("sys_mprotect", FunctionCallback({env::abi::auto_argsize, 4, 4}, sys_linux_mprotect))},
        {146, Function("sys_writev", FunctionCallback({4, env::abi::auto_argsize, env::abi::auto_argsize}, sys_linux_writev))},
        {171, Function("sys_arch_prctl", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_arch_prctl))},
        {179, Function("sys_pread64", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_pread))},
        {197, Function("sys_fstat64", FunctionCallback({4, env::abi::auto_argsize}, sys_linux_fstat))}, 
        {234, Function("sys_exit_group", FunctionCallback({4}, sys_linux_exit))},
        {286, Function("sys_openat", FunctionCallback({4, env::abi::auto_argsize, 4, 4}, sys_linux_openat))},
    };
    return res;
}
} // namespace emulated
} // namespace env
} // namespace maat
