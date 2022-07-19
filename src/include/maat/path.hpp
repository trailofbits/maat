#ifndef MAAT_PATH_H
#define MAAT_PATH_H

#include "maat/constraint.hpp"
#include "maat/serializer.hpp"
#include "maat/value.hpp"
#include <unordered_set>

namespace maat
{

/** \addtogroup engine
 * \{ */
 
/// A class recording the constraints associated with the current execution path
class PathManager: public serial::Serializable
{
public:
    using path_snapshot_t = unsigned int;
private:
    std::vector<Constraint> _constraints;
public:
    PathManager() = default;
    virtual ~PathManager() = default;
public:
    void add(Constraint constraint); ///< Add a path constraint
    path_snapshot_t take_snapshot(); ///< Snapshot the current path constraints
    void restore_snapshot(path_snapshot_t snap); ///< Restore snapshot
    const std::vector<Constraint>& constraints(); ///< Get current path constraints
public:
    // Basically taken from https://internalpointers.com/post/writing-custom-iterators-modern-cpp
    /// Custom iterator for path constraints
    struct iterator
    {
        public:
        enum class Type
        {
            REGULAR,
            RELATED,
            RELATED_REVERSE,
            UNINITIALIZED
        };

        public:
        using iterator_category = std::input_iterator_tag;
        using difference_type   = std::ptrdiff_t;
        using value_type        = Constraint;
        using const_pointer     = const Constraint*;  // or also value_type*
        using const_reference   = const Constraint&;  // or also value_type&
        iterator(Type t, std::vector<Constraint>* c, int idx, std::set<std::string>* v): type(t), m_idx(idx), constraints(c), vars(v) {}
        iterator(const iterator& other) = default;
        iterator& operator=(const iterator& other) = default;
        ~iterator() = default;

        private:
        int m_idx;
        // TODO use mutable references
        // Use pointers because iterator can't be copied if they contains const references...
        std::vector<Constraint>* constraints;
        std::set<std::string>* vars;
        Type type;

        public:
        const_reference operator*() const { return (*constraints)[m_idx]; }
        const_pointer operator->() { return &((*constraints)[m_idx]); }

        // Prefix increment
        iterator& operator++()
        {
            if (type == Type::REGULAR)
                m_idx++;
            else if (type == Type::RELATED)
            {
                // Increment until next constraint that contains requested abstract variables 
                do
                {
                    m_idx++;
                } while(
                    m_idx < constraints->size() and
                    not (*constraints)[m_idx]->contains_vars(*vars)
                );
            }
            else
            {
                // TODO REVERSE !!!
            }
            return *this;
        }

        // Postfix increment
        iterator operator++(int) { iterator tmp = *this; ++(*this); return tmp; }

        friend bool operator== (const iterator& a, const iterator& b) { return a.m_idx == b.m_idx; };
        friend bool operator!= (const iterator& a, const iterator& b) { return a.m_idx != b.m_idx; }; 
    };
    
    /** Simple wrapper class used to use the PathManager iterator with syntactic sugar
     * like so:
     * 
     * for (const auto& constraint : get_constraints_containing(c)) {...}
     * 
     * */
    class IteratorWrapper
    {
        private:
        std::set<std::string> vars;
        std::vector<Constraint>* constraints;
        iterator::Type type;

        public:
        IteratorWrapper(iterator::Type t, const std::set<std::string>& v, std::vector<Constraint>* c):
            vars(v), constraints(c), type(t) {}
        IteratorWrapper(const IteratorWrapper& other):
            vars(other.vars), constraints(other.constraints), type(other.type) {}
        IteratorWrapper& operator=(IteratorWrapper&& other) = delete;
        IteratorWrapper& operator=(const IteratorWrapper& other)
        {
            vars = other.vars;
            constraints = other.constraints;
            type = other.type;
            return *this;
        };
        /// Return the initial iterator
        PathManager::iterator begin(){ return iterator(type, constraints, 0, &vars);}
        /// Return the final iterator
        PathManager::iterator end(){return iterator(type, constraints, constraints->size(), &vars);}
    };

    /** Returns the constraints that contain at least one of the variables listed
    in 'vars' */
    IteratorWrapper get_constraints_containing(const std::set<std::string>& vars);
    // Return an iterator for the normal constraint vector, used by python bindings
    IteratorWrapper _constraints_iterator();
public:
    /// Get the minimal set of path constraints that involve variables contained in 'constraint' 
    std::unordered_set<Constraint> get_related_constraints(const Constraint& constraint) const;
    /// Get the minimal set of path constraints that involve variables contained in 'expr'
    std::unordered_set<Constraint> get_related_constraints(const Expr& expr) const;
    /// Get the minimal set of path constraints that involve variables contained in 'val'
    std::unordered_set<Constraint> get_related_constraints(const Value& val) const;
    // Helper function for get_related_constraints overloads
    std::unordered_set<Constraint> _get_related_constraints(std::set<std::string> vars) const;

public:
    virtual serial::uid_t class_uid() const;
    virtual void dump(serial::Serializer& s) const;
    virtual void load(serial::Deserializer& d);

};



/** \} */ // doxygen group engine
}
#endif
