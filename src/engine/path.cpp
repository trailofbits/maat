#include "path.hpp"

namespace maat
{
    
void PathManager::add(Constraint constraint)
{
    _constraints.push_back(constraint);
}

PathManager::path_snapshot_t PathManager::take_snapshot()
{
    return _constraints.size();
}

void PathManager::restore_snapshot(path_snapshot_t snap)
{
    unsigned int idx(snap);
    if (idx < _constraints.size())
        _constraints.resize(idx);
}

const std::vector<Constraint>& PathManager::constraints()
{
    return _constraints;
}

PathManager::IteratorWrapper PathManager::_constraints_iterator()
{
    return PathManager::IteratorWrapper(
                PathManager::iterator::Type::REGULAR,
                std::set<std::string>(),
                &_constraints
            );
}

PathManager::IteratorWrapper PathManager::get_related_constraints(const Constraint& c)
{
    return PathManager::IteratorWrapper(
                PathManager::iterator::Type::RELATED,
                c->contained_vars(), // Converted to rvalue
                &_constraints
            );
}

PathManager::IteratorWrapper PathManager::get_related_constraints(const Expr& e)
{
    std::set<std::string> vars;
    e->get_vars(vars);
    return PathManager::IteratorWrapper(
                PathManager::iterator::Type::RELATED,
                vars, // Compiler should optimise that into move semantics
                &_constraints
            );
}



} // namespace maat
