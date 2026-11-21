#include "python_bindings.hpp"

namespace maat::py
{
using BufferList = MixedList<Value, cst_t>;
static std::vector<Value> file_values(BufferList items)
{
    std::vector<Value> result;
    result.reserve(nb::len(items.items));
    size_t bits = 8;
    for (auto item : items.items)
    {
        const BoundValue* bound;
        cst_t integer;
        if (nb::try_cast(item, bound, false) && bound)
        {
            bits = bound->value.size();
            result.push_back(bound->value);
        }
        else if (nb::try_cast(item, integer))
            result.emplace_back(bits, integer);
        else
            throw nb::type_error("Invalid list element");
    }
    return result;
}

static int byte_count(const nb::bytes& input, int count)
{
    if (count < 0)
    {
        if (input.size() > INT_MAX)
            throw std::overflow_error("Buffer is too large");
        return static_cast<int>(input.size());
    }
    if (size_t(count) > input.size())
        throw nb::value_error("Length exceeds the buffer size");
    return count;
}

// Restoring a filesystem snapshot can replace its entire accessor list.
struct FileHandle
{
    env::FileSystem* fs;
    env::filehandle_t handle;
    env::FileAccessor& get() const
    {
        return fs->get_fa_by_handle(handle);
    }
};

void bind_environment(nb::module_& m)
{
    using namespace env;
    nb::class_<ProcessInfo>(m, "_ProcessInfo", nb::is_final(), "Process Info")
        .def_ro("pid", &ProcessInfo::pid, "Process PID");
    nb::class_<EnvEmulator>(m, "_EnvEmulator", nb::is_final(), "Process environment emulator")
        .def_ro("fs", &EnvEmulator::fs, "Emulated symbolic file-system");
    nb::class_<FileSystem>(m, "_FileSystem", nb::is_final(), "Symbolic file-system emulator")
        .def(
            "add_real_file",
            [](FileSystem& fs, const std::string& src, const std::string& dst, nb::object create)
            { return fs.add_real_file(src, dst, truth(create)); }, nb::arg(), nb::arg(),
            nb::arg().none() = true, "Map a real file in the virtual file system")
        .def(
            "new_fa", [](FileSystem& fs, const std::string& path) { return fs.new_fa(path); },
            "Create a new file accessor for a file")
        .def(
            "delete_fa",
            [](FileSystem& fs, filehandle_t fd, nb::object weak)
            {
                truth(weak);
                fs.delete_fa(fd);
            },
            nb::arg(), nb::arg("weak").none() = false, "Remove a file accessor")
        .def(
            "get_fa_by_handle",
            [](FileSystem& fs, filehandle_t handle)
            {
                fs.get_fa_by_handle(handle);
                return FileHandle{&fs, handle};
            },
            nb::keep_alive<0, 1>(), "Get a file accessor by handle")
        .def("get_stdin_for_pid", &FileSystem::get_stdin_for_pid,
             "Get the name of the stdin file for a given process")
        .def(
            "get_file",
            [](FileSystem& fs, const std::string& name, nb::object follow)
            {
                auto file = fs.get_file(name, truth(follow));
                if (!file)
                    throw std::runtime_error("Could not get the physical file");
                return file;
            },
            nb::arg(), nb::arg("follow_symlink").none() = true, "Get a physical file")
        .def("__repr__", &format<FileSystem>)
        .def("__str__", &format<FileSystem>);
    nb::class_<FileHandle>(m, "_FileAccessor", nb::is_final(),
                           "Wrapper to read/write emulated files")
        .def(
            "write_buffer",
            [](FileHandle& file, ByteString input, int count)
            {
                auto bytes = input.as_bytes();
                return file.get().write_buffer((uint8_t*)bytes.c_str(), byte_count(bytes, count));
            },
            nb::arg(), nb::arg() = -1, "Write a buffer to a file")
        .def(
            "write_buffer", [](FileHandle& file, BufferList input)
            { return file.get().write_buffer(file_values(input)); }, "Write a buffer to a file")
        .def(
            "read_buffer",
            [](FileHandle& file, unsigned count, unsigned width)
            {
                std::vector<Value> values;
                file.get().read_buffer(values, count, width);
                return values;
            },
            nb::arg(), nb::arg() = 1, "Read a buffer from a file");
    nb::class_<PhysicalFile>(m, "_File", nb::is_final(), "Physical emulated file")
        .def(
            "write_buffer",
            [](PhysicalFile& file, ByteString input, addr_t offset, int count)
            {
                auto bytes = input.as_bytes();
                return file.write_buffer((uint8_t*)bytes.c_str(), offset, byte_count(bytes, count));
            },
            nb::arg(), nb::arg(), nb::arg() = -1, "Write a buffer to a file")
        .def(
            "write_buffer", [](PhysicalFile& file, BufferList input, addr_t offset)
            { return file.write_buffer(file_values(input), offset); }, "Write a buffer to a file")
        .def(
            "read_buffer",
            [](PhysicalFile& file, addr_t offset, unsigned count, unsigned width)
            {
                std::vector<Value> values;
                file.read_buffer(values, offset, count, width);
                return values;
            },
            nb::arg(), nb::arg(), nb::arg() = 1, "Read a buffer from a file");
}
} // namespace maat::py
