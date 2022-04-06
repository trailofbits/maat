#ifndef MAAT_FS_INTERNAL_HPP
#define MAAT_FS_INTERNAL_HPP

#include <memory>
#include <list>
#include "maat/env/os.hpp"
#include "maat/varcontext.hpp"
#include "maat/serializer.hpp"
#include "maat/saved_mem_state.hpp"
#include "maat/memory.hpp"
#include "maat/snapshot.hpp"

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
class FileAccessor: public serial::Serializable
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
    /// Dummy constructor used by deserializer
    FileAccessor();
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
public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};


/// Actions modifying the filesystem layout
enum class FileSystemAction: uint8_t
{
    CREATE_FILE, ///< Creating a new physical file
    DELETE_FILE, ///< Deleting a physical file
    CREATE_DIR, ///< Creating a new directory
    DELETE_DIR ///< Deleting a directory
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

// Env Snapshot
class PhysialFile; // Forward decl
class Snapshot: public serial::Serializable
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
public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};

/** This class represents a physical file on the disk */
class PhysicalFile: public std::enable_shared_from_this<PhysicalFile>,
                    public serial::Serializable
{
friend class FileSystem;
public:
    /// Types of files
    enum class Type
    {
        REGULAR, ///< Regular file supporting arbitrary read write
        IOSTREAM, ///< Stream (reads consume data from the beginning, writes append data at the end)
        SYMLINK, ///< Symbolic link to another file
        INVALID
    };
private:
    static unsigned int _uid_cnt;
    unsigned int _uid;
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
    std::shared_ptr<SnapshotManager<env::Snapshot>> snapshots; ///< Snapshot manager to record writes
public:
    /** \brief If this field is set, flush every write to the file in the
     * stream as well. This is mostly used for stdout/stderr emulated files */
    std::optional<std::reference_wrapper<std::ostream>> flush_stream;
public:
    /// Create a new physical file
    PhysicalFile(std::shared_ptr<SnapshotManager<env::Snapshot>> snapshots=nullptr, Type type = Type::REGULAR);
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
    /// Return the file uid
    unsigned int uid();
private:
    // Used by streams
    void _adjust_read_offset(addr_t& offset);
    void _adjust_write_offset(addr_t& offset);

private:
    // Snapshoting
    void record_write(addr_t offset, int nb_bytes);

protected:
    void _set_symlink(const std::string& target);

public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};



class Directory;
typedef std::shared_ptr<Directory> directory_t;

class Directory: public serial::Serializable
{
friend class FileSystem;
protected:
    bool deleted;
private:
    std::map<std::string, physical_file_t> files;
    std::map<std::string, directory_t> subdirs;
    std::map<std::string, fspath_t> symlinks;
private:
    std::shared_ptr<SnapshotManager<env::Snapshot>> snapshots; ///< Snapshot manager to record writes
private:
    // Return True if 'name' is an existing file or subdir or symlink
    bool _contains_name(const std::string& name);
public:
    Directory(std::shared_ptr<SnapshotManager<env::Snapshot>> snapshots=nullptr); ///< Create a new empty directory
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
public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);
};


/** \} */ // Doxygen group env
    
} // namespace env
} // namespace maat

#endif
