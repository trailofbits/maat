#ifndef MAAT_STATS_H
#define MAAT_STATS_H

#include <chrono>
#include <iostream>

namespace maat{

/** \defgroup stats Stats 
 * \brief Statistics and introspection features */

/** \addtogroup stats
 * \{ */

/** Global stats recorded by Maat to be used for introspection
 * and optimisations */
class MaatStats
{
private:
    std::chrono::steady_clock::time_point _time;
private:
    unsigned int _symptr_read_total_time;
    unsigned int _symptr_read_average_range;
    unsigned int _symptr_read_count;
    unsigned int _symptr_write_total_time;
    unsigned int _symptr_write_average_range;
    unsigned int _symptr_write_count;
    unsigned int _executed_inst_count;
    unsigned int _lifted_inst_count;
    unsigned int _executed_ir_inst_count;
    unsigned int _created_expr_count;
    unsigned int _created_abstract_values_count;
    unsigned int _solver_total_time;
    unsigned int _solver_calls_count;
    // TODO(boyan): total/average time spent simplifying symbolic expressions?

public:
    MaatStats()
    {
        _symptr_read_total_time = 0;
        _symptr_read_average_range = 0;
        _symptr_read_count = 0;
        _symptr_write_total_time = 0;
        _symptr_write_average_range = 0;
        _symptr_write_count = 0;
        _executed_inst_count = 0;
        _lifted_inst_count = 0;
        _executed_ir_inst_count = 0;
        _created_expr_count = 0;
        _created_abstract_values_count = 0;
        _solver_total_time = 0;
        _solver_calls_count = 0;
    }

    /// Get the global stats instance
    static MaatStats& instance()
    {
        static MaatStats s;
        return s;
    }

public:
    // Get API
    /// Total time spent refining symbolic pointer reads (in milliseconds)
    unsigned int symptr_read_total_time() const {return _symptr_read_total_time;}
    /// Average time spend refining symbolic pointer reads (in milliseconds)
    unsigned int symptr_read_average_time() const
    {
        if  (_symptr_read_count != 0)
            return _symptr_read_total_time/_symptr_read_count;
        else
            return 0;
    }
    /// Average memory range for symbolic pointer reads 
    unsigned int symptr_read_average_range() const {return _symptr_read_average_range;}
    /// Total number of symbolic pointer reads
    unsigned int symptr_read_count() const {return _symptr_read_count;}

    /// Total time spent refining symbolic pointer writes (in milliseconds)
    unsigned int symptr_write_total_time() const {return _symptr_write_total_time;}
    /// Average time spend refining symbolic pointer writes (in milliseconds)
    unsigned int symptr_write_average_time() const
    {
        if  (_symptr_write_count != 0)
            return _symptr_write_total_time/_symptr_write_count;
        else
            return 0;
    }
    /// Average memory range for symbolic pointer writes
    unsigned int symptr_write_average_range() const {return _symptr_write_average_range;}
    /// Total number of symbolic pointer writes
    unsigned int symptr_write_count() const {return _symptr_write_count;}

    /// Total number of ASM instructions executed
    unsigned int executed_insts() const {return _executed_inst_count;}
    /// Total number of ASM instructions lifted to IR
    unsigned int lifted_insts() const {return _lifted_inst_count;}
    /// Total number of IR instructions executed
    unsigned int executed_ir_insts() const {return _executed_ir_inst_count;}

    /// Total number of Expr instances created
    unsigned int created_exprs() const {return _created_expr_count;}
    /// Total number of Value instances created
    unsigned int created_abstract_values() const {return _created_abstract_values_count;}

    /// Total time spent solving symbolic constraints (in milliseconds)
    unsigned int solver_total_time() const {return _solver_total_time;}
    /// Average time spent per call to the solver (in milliseconds)
    unsigned int solver_average_time() const
    {
        if (_solver_calls_count != 0)
            return _solver_total_time/_solver_calls_count;
        else
            return 0;
    }
    /// Total number of calls to the solver
    unsigned int solver_calls_count() const {return _solver_calls_count;}

public: 
    // Set API
    /// Notify start of refinement for symptr read
    void start_refine_symptr_read()
    {
        _record_current_time();
    }
    /// Notify end of refinement for symptr read and record the refinement time
    void done_refine_symptr_read()
    {
        _symptr_read_total_time += _get_elapsed_time();
    }
    /// Record a symbolic read
    void add_symptr_read(unsigned int range)
    {
        _symptr_read_average_range = 
            (_symptr_read_average_range*_symptr_read_count)+range / 
            (_symptr_read_count+1);
        _symptr_read_count++;
    }

    /// Notify start of refinement for symptr read
    void start_refine_symptr_write()
    {
        _record_current_time();
    }
    /// Notify end of refinement for symptr read and record the refinement time
    void done_refine_symptr_write()
    {
        _symptr_write_total_time += _get_elapsed_time();
    }
    /// Record a symbolic read
    void add_symptr_write(unsigned int range)
    {
        _symptr_write_average_range = 
            (_symptr_write_average_range*_symptr_write_count)+range / 
            (_symptr_write_count+1);
        _symptr_write_count++;
    }

    void inc_executed_insts() {_executed_inst_count++;}
    void inc_lifted_insts() {_lifted_inst_count++;}
    void inc_executed_ir_insts() {_executed_ir_inst_count++;}

    void inc_created_exprs() {_created_expr_count++;}
    void inc_created_absract_values() {_created_abstract_values_count++;}

    /// Add a solving time (in milliseconds) for the solver AND increments the solver calls count
    void add_solver_call(unsigned int time)
    {
        _solver_total_time += time;
        _solver_calls_count++;
    }

private:
    void _record_current_time()
    {
        _time = std::chrono::steady_clock::now();
    }

    /// Return nb of milliseconds elasped since last call to _record_current_time()
    unsigned int _get_elapsed_time()
    {
        std::chrono::steady_clock::time_point curr_time = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(curr_time - _time).count();
    }

public:
    friend std::ostream& operator<<(std::ostream& os, const MaatStats& stats)
    {
        os << std::dec;
        os << "Executed insts: " << stats.executed_insts() << "\n";
        os << "Lifted insts: " << stats.lifted_insts() << "\n"; 
        os << "Executed IR insts: " << stats.executed_ir_insts() << "\n\n";

        os << "Symbolic expr created: " << stats.created_exprs() << "\n";
        os << "Abstract values created: " << stats.created_abstract_values() << "\n\n";

        os << "Solver total time: " << stats.solver_total_time() << " ms \n";
        os << "Solver average time: " << stats.solver_average_time() << " ms \n";
        os << "Calls to solver: " << stats.solver_calls_count() << "\n\n";

        os << "Symptr read total solving time: " << stats.symptr_read_total_time() << " ms \n";
        os << "Symptr read average solving time: " << stats.symptr_read_average_time() << " ms \n";
        os << "Symptr read average range: " << stats.symptr_read_average_range() << "\n";
        os << "Symptr read count: " << stats.symptr_read_count() << "\n\n";

        os << "Symptr write total solving time: " << stats.symptr_write_total_time() << " ms \n";
        os << "Symptr write average solving time: " << stats.symptr_write_average_time() << " ms \n";
        os << "Symptr write average range: " << stats.symptr_write_average_range() << "\n";
        os << "Symptr write count: " << stats.symptr_write_count() << "\n\n";

        return os;
    }
};

/** \} */ // doxygen stats group

} // namespace maat

#endif