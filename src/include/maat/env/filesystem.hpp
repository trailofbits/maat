#ifndef MAAT_FS_HPP
#define MAAT_FS_HPP

#include <memory>
#include "maat/memory.hpp"
#include "maat/env/os.hpp"
#include "maat/snapshot.hpp"
#include "maat/varcontext.hpp"

namespace maat
{
namespace env
{

/** \addtogroup env
 * \{ */

class PhysicalFile;
typedef std::shared_ptr<PhysicalFile> physical_file_t;

/// Opaque handle to a file (equivalent of file descriptors on Linux)
typedef int filehandle_t;

/** This class mimics a basic FILE* like structure used to read/write from a file */
class FileAccessor
{
friend class FileSystem;
public:
    struct State
    {
        addr_t read_ptr; /// Current read offset in file
        addr_t write_ptr; ///  Current write offset in file
    };
protected:
    filehandle_t _handle;
    int flags; // TODO ? 
    physical_file_t physical_file;
    addr_t _alloc_addr; // Address where the EnvFile's fileno has been allocated in memory ??? TODO
    State state;
    std::string _filename;
public:
    bool deleted; /// If file accessor was deleted by the emulated program
public:
    /// Create a new file 
    FileAccessor(physical_file_t physical_file, filehandle_t handle, const std::string& filename="");
    /// Write abstract buffer to the file. Return the number of bytes written
    unsigned int write_buffer(const std::vector<Value>& buffer);
    /// Write concrete buffer to the file. Return the number of bytes written
    unsigned int write_buffer(uint8_t* buffer, int len);
    /// Read abstract buffer from the file. Return the number of bytes read
    unsigned int read_buffer(std::vector<Value>& buffer, unsigned int nb_elems, unsigned int elem_size);
public:
    filehandle_t handle() const;
    const std::string& filename() const;
};


/// Actions modifying the filesystem layout
enum class FileSystemAction
{
    CREATE_FILE, ///< Creating a new physical file
    DELETE_FILE, ///< Deleting a physical file
    CREATE_DIR, ///< Creating a new directory
    DELETE_DIR ///< Deleting a directory
};

// Env Snapshot
class Snapshot
{
public:
    std::list<std::pair<std::shared_ptr<PhysicalFile>, SavedMemState>> saved_file_contents;
    // <path, action>
    std::list<std::pair<std::string, FileSystemAction>> fs_actions;
    std::list<env::FileAccessor> file_accessors;
public:
    Snapshot() = default;
    Snapshot(const Snapshot& other) = delete;
    Snapshot& operator=(const Snapshot& other) = delete;
public:
    void add_saved_file_content(std::shared_ptr<PhysicalFile> file, SavedMemState&& content);
    void add_filesystem_action(std::string path, FileSystemAction action);
};



typedef unsigned node_status_t;
namespace node
{
    static constexpr node_status_t none = 0;

    static constexpr node_status_t exists = 1 << 0;
    static constexpr node_status_t is_file = 1 << 1;
    static constexpr node_status_t is_symlink = 1 << 2;
    static constexpr node_status_t is_dir = 1 << 3;

    bool check_is_file(node_status_t s);
    bool check_is_symlink(node_status_t s);
    bool check_is_dir(node_status_t s);
}

/// Absolute path to a file or directory node in the virtual file system
typedef std::vector<std::string> fspath_t;

/** This class represents a physical file on the disk */
class PhysicalFile: public std::enable_shared_from_this<PhysicalFile>
{
friend class FileSystem;
public:
    /// Types of files
    enum class Type
    {
        REGULAR, ///< Regular file supporting arbitrary read write
        IOSTREAM, ///< Stream (reads consume data from the beginning, writes append data at the end)
        SYMLINK ///< Symbolic link to another file
    };
private:
    static unsigned int _uuid_cnt;
    unsigned int _uuid;
protected:
    std::shared_ptr<MemSegment> data;
    int flags;
    bool deleted; ///< 'True' if the file was deleted by the emulated program
    addr_t _size; ///< Size in bytes
    std::string _symlink; ///< Path if this file is a symlink
    Type type;
private:
    addr_t istream_read_offset; ///< Used by IOSTREAM files
private:
    SnapshotManager<env::Snapshot>* snapshots; ///< Snapshot manager to record writes
public:
    /** \brief If this field is set, flush every write to the file in the
     * stream as well. This is mostly used for stdout/stderr emulated files */
    std::optional<std::reference_wrapper<std::ostream>> flush_stream;
public:
    /// Create a new physical file
    PhysicalFile(SnapshotManager<env::Snapshot>* snapshots, Type type = Type::REGULAR);
    /// Write abstract buffer to the file. Return the number of bytes written
    unsigned int write_buffer(const std::vector<Value>& buffer, addr_t& offset);
    /// Write concrete buffer to the file. Return the number of bytes written
    unsigned int write_buffer(uint8_t* buffer, addr_t& offset, int len);
    /// Read abstract buffer from file. Return the number of elements read
    unsigned int read_buffer(std::vector<Value>& buffer, addr_t& offset, unsigned int nb_elems, unsigned int elem_size);
    /// Return the total size of the physical file content in bytes
    unsigned int size();
    /// Fill the emulated file with concrete content from a real file. Return the size of 'filename'
    unsigned int copy_real_file(const std::string& filename);
public:
    /// Return the file status
    node_status_t status();
public:
    /// Set the deleted status of the file
    void set_deleted(bool deleted);
    /// Return 'True' if the file has been deleted by the emulated program
    bool is_deleted();
    /// Return 'True' if the file is a symbolic link
    bool is_symlink();
    /// If symlink, returns the file it points to
    const std::string& symlink();
public:
    /// Return the file uuid
    unsigned int uuid();
private:
    // Used by streams
    void _adjust_read_offset(addr_t& offset);
    void _adjust_write_offset(addr_t& offset);

private:
    // Snapshoting
    void record_write(addr_t offset, int nb_bytes);

protected:
    void _set_symlink(const std::string& target);
};



class Directory;
typedef std::shared_ptr<Directory> directory_t;

class Directory
{
friend class FileSystem;
protected:
    bool deleted;
private:
    std::map<std::string, physical_file_t> files;
    std::map<std::string, directory_t> subdirs;
    std::map<std::string, fspath_t> symlinks;
private:
    SnapshotManager<env::Snapshot>* snapshots; ///< Snapshot manager to record writes
private:
    // Return True if 'name' is an existing file or subdir or symlink
    bool _contains_name(const std::string& name);
public:
    Directory(SnapshotManager<env::Snapshot>* snapshots); ///< Create a new empty directory
    /// Create new file
    bool create_file(fspath_t path, bool create_path = false); // TODO snapshot manager ?
    /// Get physical file object. Throws exception if the file doesn't exist
    physical_file_t get_file(fspath_t path);
    /// Delete physical file
    bool delete_file(fspath_t path, bool weak=true);
    /// Create new sub-directory
    bool create_dir(fspath_t path);
    /// Get directory object. Throws exception if the directory doesn't exist
    directory_t get_dir(fspath_t path);
    /// Delete sub directory
    bool delete_dir(fspath_t path, bool weak=true);
    /// Get status of node
    node_status_t get_node_status(fspath_t path);
    /// Delete the directory
    void delete_self(bool recursive=true, bool weak=true); // TODO Snapshot, FileSystem, not used anymore?
public:
    /// Print directory to output stream
    void print(std::ostream& os, const std::string& indent) const;
};



class FileSystem
{
friend class EnvEmulator;
friend class LinuxEmulator;

private:
    filehandle_t _handle_cnt;
    std::string path_separator;
    std::string rootdir_prefix;
    char orphan_file_wildcard;
    Directory root;
    Directory orphan_files; // Stdin, stdout, stderr, network streams, ...
    // TODO: returning references to FAs in this list is 
    // probably not safe if the list is modified before they
    // are used....
    std::list<FileAccessor> fa_list;
    std::vector<filehandle_t> reserved_handles;
private:
    SnapshotManager<env::Snapshot> snapshots;
public:
    /// Create a new filesystem for OS 'system'
    FileSystem(OS system);

public:
    // Physical files
    // get_fa_by_* functions don't check whether the path is marked as 'deleted' !

    /** \brief Get a file in the file system
     * @param path Absolute path of the file
     * @param follow_symlink If set to 'true', resolve potential symbolic links to get the actual file */ 
    physical_file_t get_file(const std::string& path, bool follow_symlink=true);
    /** \brief Convenience function to get a physical file by handle.
     * @param handle The handle of the file */
     physical_file_t get_file_by_handle(filehandle_t handle);
    /** \brief Create a file specified by its absolute path. 
     * Returns 'true' on success and 'false' on failure.
     * @param path Absolute path of the file
     * @param create_path If set to 'true', any missing directories in 'link' will be automatically created */
    bool create_file(const std::string& path, bool create_path=false);
    /** \brief Delete a file
     * Returns 'true' on success and 'false' on failure
     * @param path Absolute path of the file
     * @param weak If set to 'true', the file is virtually deleted from the emulated
     * filesystem, but its contents are preserved internally and will be restored if a
     * snapshot rewinds back to before the deletion. If set to 'false' the file object
     * is completely deleted internally */
    bool delete_file(const std::string& path, bool weak=true);
    /** \brief Check if a file exists in the filesystem */
    bool file_exists(const std::string& path);

    // Symlinks
    /** \brief Create a symbolic link
     * @param link The absolute path of the symbolic link
     * @param pointed_file The file pointed to by the symbolic link
     * @param create_path If set to 'true', any missing directories in 'link' will be automatically created */
    bool create_symlink(const std::string& link, const std::string& pointed_file, bool create_path=false);

    // Handles (FILE*)
    /** \brief Create a new file accessor
     * @param path Absolute path of the file to access */
    filehandle_t new_fa(const std::string& path);
    /** \brief Get a file accessor by handle */
    FileAccessor& get_fa_by_handle(filehandle_t handle);
    /** \brief Delete a file accessor 
     * @param handle Unique handle of the file accessor to delete
     * @param weak If set to 'true', the file accessor is virtually deleted
     * , but its contents are preserved internally and will be restored if a
     * snapshot rewinds back to before the deletion. If set to 'false' the object
     * is completely deleted internally */
    void delete_fa(filehandle_t handle, bool weak=true);

    // Dir
    /// Create a directory in the filesystem. Returns 'true' on success, 'false' on failure
    bool create_dir(const std::string& path);
    /// Get directory by absolute path. This function doesn't check wheter the dir was deleted or not!
    directory_t get_dir(const std::string& path);
    /** \brief Delete a directory
     * @param path Absolute path of the directory
     * @param weak If set to 'true', the directory is virtually deleted from the emulated
     * filesystem, but its contents are preserved internally and will be restored if a
     * snapshot rewinds back to before the deletion. If set to 'false' the file object
     * is completely deleted internally */
    bool delete_dir(const std::string& path, bool weak=true);

    // Utils
    std::string path_from_fspath(const fspath_t& path);
    fspath_t fspath_from_path(const std::string& path);
    fspath_t fspath_from_path_relative_to(std::string rel_path, fspath_t path_base);
    std::string path_from_relative_path(std::string rel_path, std::string path_base);
    std::string pointed_path_from_symlink(std::string symlink_file);
    bool is_relative_path(const std::string& path);

    node_status_t get_node_status(const std::string& path);

public:
    /// Return the stdin file for process with PID 'pid'
    std::string get_stdin_for_pid(int pid);
    /// Return the stdout file for process with PID 'pid'
    std::string get_stdout_for_pid(int pid);
    /// Return the stderr file for process with PID 'pid'
    std::string get_stderr_for_pid(int pid);

public:
    friend std::ostream& operator<<(std::ostream& os, const FileSystem& fs);

private:
    /// Get a new, free handle value
    filehandle_t get_free_handle();
    /// Arbitrary creation of file accessor with specific handle (for stdin, stdout, ...)
    void _new_fa(const std::string& path, filehandle_t handle);

public:
    using snapshot_t = int;
    /// Take a snapshot of the filesystem
    snapshot_t take_snapshot();
    /// Restore a snapshot of the filesystem
    void restore_snapshot(snapshot_t snapshot, bool remove=false);
    /// Restore latests snapshot
    void restore_last_snapshot(bool remove=false);
};



/** \} */ // Doxygen group env
    
} // namespace env
} // namespace maat

#endif
