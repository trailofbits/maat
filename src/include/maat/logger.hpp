#ifndef MAAT_LOGGER_H
#define MAAT_LOGGER_H

#include <vector>
#include <utility>
#include <string>
#include <iostream>

namespace maat
{

/// Log levels
enum class Log
{
    DEBUG = 0, ///< Debug
    INFO = 1, ///< Info
    WARNING = 2, ///< Warnings
    ERROR = 3, ///< Errors
    FATAL = 4 /// < Fatal errors
};

extern std::string log_bold;
extern std::string log_def;
extern std::string log_red;
extern std::string log_green;
extern std::string log_yellow;
extern std::string log_orange;

extern std::string debug_str;
extern std::string info_str;
extern std::string warning_str;
extern std::string error_str;
extern std::string fatal_str;
extern std::string empty_str;


/// Maat logger
class Logger
{
private:
    Log min_level;
    std::ostream& out;

public:
    Logger(std::ostream& os=std::cout): out(os), min_level(Log::INFO){}

public:
    void set_ostream(std::ostream& os);

private:
    template<typename T>
    void vararg_log(std::ostream& os, const T& t)
    {
        os << t << std::endl;
    }

    template<typename T, typename ...Args>
    void vararg_log(std::ostream& os, const T& t, const Args&... args)
    {
        os << t;
        vararg_log(os, args...);
    }

    const std::string& level_to_text(Log level)
    {
        switch (level)
        {
            case Log::DEBUG: return debug_str;
            case Log::INFO: return info_str;
            case Log::WARNING: return warning_str;
            case Log::ERROR: return error_str;
            case Log::FATAL: return fatal_str;
            default:
                return empty_str;
        }
    }

    const std::string& level_to_color(Log level)
    {
        switch (level)
        {
            case Log::DEBUG: return log_def;
            case Log::INFO: return log_green;
            case Log::WARNING: return log_yellow;
            case Log::ERROR: return log_orange;
            case Log::FATAL: return log_red;
            default:
                return log_def;
        }
    }

public:
    template<typename ...Args>
    void log(Log level, const Args&... args)
    {
        if (level < min_level)
            return;

        if (out.rdbuf() != std::cout.rdbuf()) // Log to file
        {
            out << level_to_text(level);
            vararg_log(out, args...);
        }
        else // Log to cout
        {
            out  << log_bold << "[" << level_to_color(level) << level_to_text(level)
                << log_def << log_bold << "] " << log_def;
            vararg_log(out, args...);
        }
    }
    
    template<typename ...Args>
    void debug(const Args&... args)
    {
        return log(Log::DEBUG, args...);
    }

    template<typename ...Args>
    void info(const Args&... args)
    {
        return log(Log::INFO, args...);
    }
    
    template<typename ...Args>
    void warning(const Args&... args)
    {
        return log(Log::WARNING, args...);
    }
    
    template<typename ...Args>
    void error(const Args&... args)
    {
        return log(Log::ERROR, args...);
    }
    
    template<typename ...Args>
    void fatal(const Args&... args)
    {
        return log(Log::FATAL, args...);
    }

    void set_level(Log level)
    {
        min_level = level;
    }
};


} // namespace maat


#endif
