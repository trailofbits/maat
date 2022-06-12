#ifndef MAAT_FS_HPP
#define MAAT_FS_HPP

#include <memory>
#include "maat/env/filesystem_internal.hpp"
#include "maat/snapshot.hpp"
#include "maat/serializer.hpp"

namespace maat
{
namespace env
{

class FileSystem: public maat::serial::Serializable
{
friend class EnvEmulator;
friend class LinuxEmulator;

private:
    filehandle_t _handle_cnt;
    std::string _path_separator;
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
    std::shared_ptr<maat::SnapshotManager<env::Snapshot>> snapshots;
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
    /** \brief Create a file and initialize its content from a real file on
    * the host system that runs Maat. 
    * Returns 'true' on success and 'false' on failure.
    * @param real_file_path Path to the real file on the host system
    * @param virtual_file_path Full path where to create the virtual file in
    * the symbolic filesystem
    * @param create_path If set to 'false', any missing directory in 'virtual_file_path'
    * will result in a failure */
    bool add_real_file(
        const std::string& real_file_path,
        const std::string& virtual_file_path,
        bool create_path=true
    );
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

    const std::string& path_separator(void) const;

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

public:
    virtual maat::serial::uid_t class_uid() const;
    virtual void dump(maat::serial::Serializer& s) const;
    virtual void load(maat::serial::Deserializer& d);
};



/** \} */ // Doxygen group env
    
} // namespace env
} // namespace maat

#endif
