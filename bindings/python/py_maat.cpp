#include "python_bindings.hpp"

namespace maat::py
{
std::optional<std::filesystem::path> get_maat_module_directory()
{
    auto module = nb::module_::import_("maat._native");
    return std::filesystem::path(nb::cast<std::string>(module.attr("__file__"))).parent_path();
}

NB_MODULE(_native, m)
{
    nb::register_exception_translator(
        [](const std::exception_ptr& error, void*)
        {
            try
            {
                std::rethrow_exception(error);
            }
            catch (const event_exception& e)
            {
                PyErr_SetString(PyExc_ValueError, e.what());
            }
            catch (const constraint_exception& e)
            {
                PyErr_SetString(PyExc_ValueError, e.what());
            }
            catch (const expression_exception& e)
            {
                PyErr_SetString(PyExc_ValueError, e.what());
            }
            catch (const var_context_exception& e)
            {
                PyErr_SetString(PyExc_ValueError, e.what());
            }
        });
    nb::class_<MaatConfig>(m, "MaatConfig", nb::is_final(), "Maat global configuration")
        .def_static(
            "add_explicit_sleigh_file",
            [](const std::string& file) { MaatConfig::instance().add_explicit_sleigh_file(file); },
            "Add an explicit path to a sleigh specification file")
        .def_static(
            "add_explicit_sleigh_dir",
            [](const std::string& dir) { MaatConfig::instance().add_explicit_sleigh_dir(dir); },
            "Add an explicit directory where to look for sleigh specification files");
    bind_constants(m);
    bind_constraints(m);
    bind_varcontext(m);
    bind_values(m);
    bind_environment(m);
    bind_events(m);
    bind_info(m);
    bind_memory(m);
    bind_path(m);
    bind_settings(m);
    bind_stats(m);
#ifdef MAAT_HAS_SOLVER_BACKEND
    bind_solver(m);
#endif
    bind_cpu(m);
    bind_engine(m);
    bind_evm(m);
}
} // namespace maat::py
