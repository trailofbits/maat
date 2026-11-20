#include "python_bindings.hpp"
#include <nanobind/stl/list.h>

namespace maat::py
{
// The nanobind instance registry keys borrowed children by address. Keeping
// these two views inside the engine preserves their identity and lets
// reference_internal keep the engine alive when a script retains a child.
class PythonEngine final : public MaatEngine
{
  public:
    using MaatEngine::MaatEngine;
    CpuView cpu_view{this};
    InfoView info_view{this};
};

using ArgBuffer = nb::typed<nb::list, Value>;
using CommandArgs = MixedList<nb::bytes, ArgBuffer>;
using StringDict = nb::typed<nb::dict, std::string, std::string>;
using StringList = nb::typed<nb::list, std::string>;

static std::unordered_map<std::string, std::string> string_map(const StringDict& items)
{
    std::unordered_map<std::string, std::string> result;
    for (auto [key, value] : items)
    {
        if (!nb::isinstance<nb::str>(key) || !nb::isinstance<nb::str>(value))
            throw nb::type_error("Expected string keys and values");
        const char* k = nb::borrow<nb::str>(key).c_str();
        const char* v = nb::borrow<nb::str>(value).c_str();
        if (!k || !v)
            throw nb::python_error();
        result[k] = v;
    }
    return result;
}

static std::list<std::string> string_list(const StringList& items)
{
    std::list<std::string> result;
    if (!nb::try_cast(items, result))
        throw nb::type_error("Expected a list of strings");
    return result;
}

static void load(MaatEngine& engine, const std::string& filename, int format, addr_t base,
                 CommandArgs args, const StringDict& envp, const StringList& libdirs,
                 const StringList& ignore_libs, const StringDict& virtual_fs,
                 nb::object load_interp)
{
    std::vector<loader::CmdlineArg> argv;
    for (auto item : args.items)
    {
        if (nb::isinstance<nb::bytes>(item))
        {
            auto bytes = nb::borrow<nb::bytes>(item);
            argv.emplace_back(std::string(bytes.c_str(), bytes.size()));
        }
        else if (nb::isinstance<nb::list>(item))
        {
            argv.emplace_back(list_items(nb::borrow<ArgBuffer>(item)));
        }
        else
            throw nb::type_error("Expected bytes or a list of Value objects");
    }
    engine.load(filename, static_cast<loader::Format>(format), base, argv,
                string_map(envp), string_map(virtual_fs), string_list(libdirs),
                string_list(ignore_libs), truth(load_interp));
}

void bind_engine(nb::module_& m)
{
    nb::class_<MaatEngine>(m, "_MaatEngine", nb::is_final(), "Dynamic Symbolic Execution Engine")
        .def_prop_ro("uid", &MaatEngine::uid, "Unique ID for this MaatEngine instance")
        .def_prop_ro(
            "vars", [](MaatEngine& e) { return e.vars; }, "Symbolic Variables Context")
        .def_prop_ro(
            "mem", [](MaatEngine& e) { return e.mem; }, "Memory Engine")
        .def_prop_ro(
            "env", [](MaatEngine& e) { return e.env; }, "Environment Manager")
        .def_prop_ro(
            "path", [](MaatEngine& e) { return e.path; }, "Path Manager")
        .def_prop_ro(
            "process", [](MaatEngine& e) { return e.process; }, "Process Info")
        .def_ro("hooks", &MaatEngine::hooks, "Event Hooks Manager")
        .def_ro("settings", &MaatEngine::settings, "Symbolic Engine Settings")
        .def_prop_ro(
            "cpu", [](MaatEngine& e) -> CpuView& { return static_cast<PythonEngine&>(e).cpu_view; },
            nb::rv_policy::reference_internal, "Emulated CPU")
        .def_prop_ro(
            "info",
            [](MaatEngine& e) -> InfoView& { return static_cast<PythonEngine&>(e).info_view; },
            nb::rv_policy::reference_internal, "Symbolic Engine Info")
        .def(
            "run", [](MaatEngine& e, unsigned limit) { return int(e.run(limit)); }, nb::arg() = 0,
            "Continue to run code from current location")
        .def(
            "run_from",
            [](MaatEngine& e, addr_t addr, unsigned limit) { return int(e.run_from(addr, limit)); },
            nb::arg(), nb::arg() = 0, "Run code from a given address")
        .def(
            "restore_snapshot",
            [](MaatEngine& e, int id, nb::object remove)
            {
                if (id == -1)
                    e.restore_last_snapshot(truth(remove));
                else
                    e.restore_snapshot(id, truth(remove));
            },
            nb::arg() = -1, nb::arg("remove").none() = false,
            "Restore a snapshot of the symbolic engine")
        .def("take_snapshot", &MaatEngine::take_snapshot, "Take a snapshot of the symbolic engine")
        .def("get_inst_asm", &MaatEngine::get_inst_asm, "Get assembly code of an instruction")
        .def(
            "get_inst_bytes",
            [](MaatEngine& e, addr_t addr)
            {
                auto bytes = e.get_inst_bytes(addr);
                return nb::bytes(bytes.data(), bytes.size());
            },
            "Get raw bytes of an instruction")
        .def(
            "_duplicate",
            [](MaatEngine& e, StringSet copy_names, StringSet share_names)
            {
                auto duplicate =
                    string_set_items(copy_names, "Failed to process 'duplicate' argument");
                auto share = string_set_items(share_names, "Failed to process 'share' argument");
                return std::shared_ptr<MaatEngine>(
                    std::make_shared<PythonEngine>(e, duplicate, share));
            },
            "duplicate"_a = nb::set(), "share"_a = nb::set(), "Duplicate a symbolic engine")
        .def("load", &load, nb::arg(), nb::arg() = int(loader::Format::NONE), "base"_a = 0,
             "args"_a = nb::list(), "envp"_a = nb::dict(), "libdirs"_a = nb::list(),
             "ignore_libs"_a = nb::list(), "virtual_fs"_a = nb::dict(),
             nb::arg("load_interp").none() = true, "Load an executable");
    m.def(
        "MaatEngine",
        [](int arch, int os)
        {
            return std::shared_ptr<MaatEngine>(std::make_shared<PythonEngine>(
                static_cast<Arch::Type>(arch), static_cast<env::OS>(os)));
        },
        nb::arg(), nb::arg() = int(env::OS::NONE), "Create a new DSE engine");
    nb::class_<serial::SimpleStateManager>(m, "_SimpleStateManager", nb::is_final())
        .def("enqueue_state", &serial::SimpleStateManager::enqueue_state)
        .def("dequeue_state", &serial::SimpleStateManager::dequeue_state);
    m.def(
        "SimpleStateManager",
        [](const std::string& dir, std::string name, nb::object remove)
        {
            return new serial::SimpleStateManager(dir, name.empty() ? "maat_state" : name,
                                                  truth(remove));
        },
        nb::arg(), nb::arg() = "maat_state", nb::arg().none() = true, nb::rv_policy::take_ownership,
        "Create a new helper for serializing/deserializing engine states");
}
} // namespace maat::py
