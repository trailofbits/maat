#ifndef MAAT_PROCESS_H
#define MAAT_PROCESS_H

namespace maat
{
  
/// This class contains information about a process
class ProcessInfo
{
public:
    int pid; ///< Process ID  
    std::string pwd; ///< Current working directory of the running process
    std::string binary_path; ///< Path to the executable in the virtual file system
public:
    ProcessInfo(): pid(0), pwd(""), binary_path(""){}
};

    
} // namespace maat


#endif

