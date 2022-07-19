#include "maat/path.hpp"

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

PathManager::IteratorWrapper PathManager::get_constraints_containing(
    const std::set<std::string>& vars
){
    return PathManager::IteratorWrapper(
                PathManager::iterator::Type::RELATED,
                vars,
                &_constraints
            );
}

std::unordered_set<Constraint> PathManager::get_related_constraints(
    const Constraint& constraint
) const {
    return _get_related_constraints(constraint->contained_vars());
}

std::unordered_set<Constraint> PathManager::get_related_constraints(
    const Expr& expr
) const {
    std::set<std::string> vars;
    expr->get_vars(vars);
    return _get_related_constraints(vars);
}

std::unordered_set<Constraint> PathManager::get_related_constraints(
    const Value& val
) const {
    return get_related_constraints(val.as_expr());
}

std::unordered_set<Constraint> PathManager::_get_related_constraints(
    std::set<std::string> vars
) const {
    std::unordered_set<Constraint> res;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const auto& constraint : _constraints)
        {
            if (not res.count(constraint)) // ignore constraints already added
            {
                if (constraint->contains_vars(vars))
                {
                    res.insert(constraint);
                    // Add potential new variables to the variables closure
                    for (const auto& v : constraint->contained_vars())
                        vars.insert(v);
                    changed = true;
                }
            }
        }
    }
    return res;
}

uid_t PathManager::class_uid() const
{
    return serial::ClassId::PATH_MANAGER;
}

void PathManager::dump(serial::Serializer& s) const
{
    s << _constraints;
}

void PathManager::load(serial::Deserializer& d)
{
    d >> _constraints;
}


} // namespace maat
