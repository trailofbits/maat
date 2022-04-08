#include "maat/serializer.hpp"
#include "maat/engine.hpp"
#include <filesystem>

namespace maat{
namespace serial{


/** \addtogroup serial
 * \{ */

/// Helper class for dynamically saving and loading states into a single MaatEngine
class SimpleEngineSerializer
{
private:
    std::filesystem::path states_dir;
    std::string base_filename;
    int state_cnt;
    std::queue<std::filesystem::path> pending_states;
    bool delete_on_load;
public:
    /** \brief Constructor
     * 
     * @param dir Directory where to store serialized states
     * @param base_filname Base name to use to name the files containing serialized states
     * @param delete_on_load If set to true, delete the serialization files when loading a state */
    SimpleEngineSerializer(
        std::filesystem::path dir,
        std::string base_filename = "maat_state",
        bool delete_on_load=true
    );
    /// Add engine's current state to the state queue 
    void enqueue_state(MaatEngine& engine);
    /// Load next pending state into engine. Returns 'true' on success and 'false' if there are no more states to load
    bool dequeue_state(MaatEngine& engine);
private:
    /// Return filename where to serialize next state
    std::string get_next_state_filename();
};

/** \} */ // Serialization doxygen group

} // namespace serial
} // namespace maat