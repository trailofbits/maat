#ifndef MAAT_CONFIG_H
#define MAAT_CONFIG_H

// TODO(ekilmer) static constexpr char* maat_specfile_dir_prefix = CMAKE_SPECFILE_DIR_PREFIX;
static constexpr char* maat_specfile_dir_prefix = "/etc/maat/processors/";

#include <filesystem>
#include <list>
#include <optional>

namespace maat
{

/// Config interface to find sleigh spec files at runtime
class MaatConfig
{
public:
    using path_t = std::filesystem::path;
private:
    std::list<path_t> standard_locations;
    std::list<path_t> explicit_directories;
    std::list<path_t> explicit_files;

public:
    MaatConfig()
    {
        std::string prefix(maat_specfile_dir_prefix); 
        standard_locations = {
            "/usr/local/"+prefix,
            "/usr/"+prefix
        };
    }

    /// Get the global config
    static MaatConfig& instance()
    {
        static MaatConfig config;
        return config;
    }

private:
    // Search for file 'filename' in directory 'dir'
    std::optional<std::filesystem::path> find_sleigh_file_in_dir(
        const std::string& filename,
        const path_t& dir
    )
    {
        if (not std::filesystem::is_directory(dir))
        {
            return std::nullopt;
        }
        for (const auto& entry: std::filesystem::directory_iterator(dir))
        {
            if (entry.path().filename() == filename)
                return entry.path();
        }
        return std::nullopt;
    }

public:
    /// Add an explicit directory where to search for sleigh files
    void add_explicit_sleigh_dir(const std::string& dir)
    {
        explicit_directories.push_front(std::filesystem::path(dir));
    }

    /// Add an explicit path for an arbitrary sleigh file
    void add_explicit_sleigh_file(const std::string& dir)
    {
        explicit_files.push_front(std::filesystem::path(dir));
    }

    /** Find sleigh file on the current machine.
     *
     * This method searches for sleigh in various locations, in the following
     * order:
     *     1. Explicit files added with 'add_explicit_sleigh_file'
     *     2. Explicit directories added with 'add_explicit_sleigh_dir'
     *     3. Maat install directory, specified with `MAAT_INSTALL_DIR` env variable
     *     4. Standard locations such as '/usr/local/', '/usr/', ...
     *
     * @param filename Name of the file to find (e.g, 'x86.sla')
     * @param only_explicit_paths If set to 'True', searches for 'filename'
       only in locations specified with 'add_explicit_sleigh_dir' and
       'add_explicit_sleigh_file' */
    std::optional<std::filesystem::path> find_sleigh_file(
        const std::string& filename,
        bool only_explicit_paths=false
    )
    {
        // 1. First search in explicit files
        for (const auto& file : explicit_files)
        {
            if (file.filename() == filename and std::filesystem::exists(file))
                return file;
        }

        // 2. Then search in explicit dirs
        for (const auto& dir : explicit_directories)
        {
            if (auto res = find_sleigh_file_in_dir(filename, dir))
                return res;
        }

        if(only_explicit_paths)
            return std::nullopt;

        // 3. Known absolute installation path with env variable
        char* install_dir = std::getenv("MAAT_INSTALL_DIR");
        if (install_dir)
        {
            if (
                auto res = find_sleigh_file_in_dir(
                    filename, 
                    std::filesystem::path(std::string(install_dir)+maat_specfile_dir_prefix)
                )
            )
                return res;
        }

        // 4. Known relative paths
        // TODO(boyan)

        // 5. Standard locations
        for (const auto& dir : standard_locations)
        {
            if (auto res = find_sleigh_file_in_dir(filename, dir))
                return res;
        }

        // Failed to find the file
        return std::nullopt;
    }
};

} // namespace maat

#endif
