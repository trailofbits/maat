#ifndef MAAT_PROCESS_H
#define MAAT_PROCESS_H

#include "maat/serializer.hpp"

namespace maat
{

using serial::bits;

/// This class contains information about a process
class ProcessInfo: public serial::Serializable
{
public:
    int pid; ///< Process ID  
    std::string pwd; ///< Current working directory of the running process
    std::string binary_path; ///< Path to the executable in the virtual file system
    bool terminated; ///< 'True' if the process exited or was killed
    std::optional<Value> exit_status; ///< Status with whom process exited
public:
    ProcessInfo(): pid(0), pwd(""), binary_path(""), terminated(false){}
    virtual ~ProcessInfo() = default;

    virtual serial::uid_t class_uid() const
    {
        return serial::ClassId::PROCESS_INFO;
    }

    virtual void dump(serial::Serializer& s) const
    {
        s << bits(pid) << pwd << binary_path << bits(terminated) << exit_status;
    }

    virtual void load(serial::Deserializer& d)
    {
        d >> bits(pid) >> pwd >> binary_path >> bits(terminated) >> exit_status;
    }
};

    
} // namespace maat


#endif

