#ifndef MAAT_STATS_H
#define MAAT_STATS_H

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
    int _symptr_read_total_time;
    int _symptr_read_average_range;
    int _symptr_read_count;
    int _symptr_write_total_time;
    int _symptr_write_average_range;
    int _symptr_write_count;
    int _executed_inst_count;
    int _lifted_inst_count;
    int _executed_ir_inst_count;
    int _created_expr_count;
    int _created_abstract_values_count;
    int _solver_total_time;
    int _solver_calls_count;
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
    int symptr_read_total_time() const;
    /// Average time spend refining symbolic pointer reads (in milliseconds)
    int symptr_read_average_time() const;
    /// Average memory range for symbolic pointer reads 
    int symptr_read_average_range() const;
    /// Total number of symbolic pointer reads
    int symptr_read_count() const;

    /// Total time spent refining symbolic pointer writes (in milliseconds)
    int symptr_write_total_time() const;
    /// Average time spend refining symbolic pointer writes (in milliseconds)
    int symptr_write_average_time() const;
    /// Average memory range for symbolic pointer writes
    int symptr_write_average_range() const;
    /// Total number of symbolic pointer writes
    int symptr_write_count() const;

    /// Total number of ASM instructions executed
    int executed_insts() const {return _executed_inst_count;}
    /// Total number of ASM instructions lifted to IR
    int lifted_insts() const {return _lifted_inst_count;}
    /// Total number of IR instructions executed
    int executed_ir_insts() const {return _executed_ir_inst_count;}

    /// Total number of Expr instances created
    int created_exprs() const;
    /// Total number of Value instances created
    int created_abstract_values() const; 

    /// Total time spent solving symbolic constraints (in milliseconds)
    int solver_total_time() const;
    /// Average time spent per call to the solver (in milliseconds)
    int solver_average_time() const;
    /// Total number of calls to the solver
    int solver_calls_count() const;

public: 
    // Set API
    /// Record a refinement time for a symbolic read 
    void add_symptr_read_time(int ms);
    /// Record a range for a symbolic read
    void add_symptr_read_range(int range);
    /// Increment number of symbolic reads
    void inc_symptr_read_count();

    /// Record a refinement time for a symbolic write
    void add_symptr_write_time(int ms);
    /// Record a range for a symbolic write
    void add_symptr_write_range(int range);
    /// Increment number of symbolic writes
    void inc_symptr_write_count();

    void inc_executed_insts() {_executed_inst_count++;}
    void inc_lifted_insts() {_lifted_inst_count++;}
    void inc_executed_ir_insts() {_executed_ir_inst_count++;}
    void inc_created_exprs();
    void inc_created_absract_values();

    /// Add a solving time (in milliseconds) for the solver AND increments the solver calls count
    void add_solver_call(int time);

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