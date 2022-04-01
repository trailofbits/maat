#include "maat/serializer.hpp"
#include "maat/exception.hpp"

namespace maat{
namespace serial{

// uuid 0 is reserved for null pointers
Serializer::Serializer(std::ostream& os): _stream(os), _uuid_cnt(1)
{
    // Reserve space for index info
    int index_pos = 0, index_cnt = 0;
    stream() << bits(index_pos) << bits(index_cnt);
}

Serializer::Stream& Serializer::stream() {return _stream;}

uuid_t Serializer::new_uuid() {return _uuid_cnt++;}

Serializer::IndexEntry& Serializer::get_index_entry(const Serializable* obj_ptr)
{
    const void* p = obj_ptr;
    auto it = object_index.find(p);
    if (it == object_index.end())
        throw serialize_exception("Serializer::get_uuid(): object was not indexed!");
    else
        return it->second;
}

void Serializer::serialize(const Serializable& obj)
{
    uuid_t root_obj_uuid = ptr(&obj); // Add object
    stream() << bits(root_obj_uuid); // Write root object uuid before all data
    while (not serialization_queue.empty())
    {
        const Serializable* next = serialization_queue.front();
        get_index_entry(next).data_pos = stream().current_pos();
        next->dump(*this);
        serialization_queue.pop();
    }
    // Write index
    finalize();
}

void Serializer::serialize(const std::shared_ptr<Serializable>& obj)
{
    return serialize(*obj);
}

uuid_t Serializer::ptr(const Serializable* obj_ptr)
{
    // If nullptr, return null uuid
    if (obj_ptr == nullptr)
        return (uuid_t)0;

    // Get void ptr to object
    const void* p = obj_ptr;
    // Check if ptr already in index
    auto it = object_index.find(p);
    if (it != object_index.end())
    {
        return it->second.obj_uuid;
    }
    else
    {
        // Add a new entry
        uuid_t obj_uuid = new_uuid();
        object_index[p] = IndexEntry{obj_uuid, obj_ptr->class_uuid(), 0};
        serialization_queue.push(obj_ptr);
        return obj_uuid;
    }
}


Serializer& Serializer::operator<<(const std::shared_ptr<Serializable>& s)
{
    stream() << bits(ptr(s.get()));
    return *this;
}

Serializer& Serializer::operator<<(const Serializable* s)
{
    stream() << bits(ptr(s));
    return *this;
}

void Serializer::dump_index()
{
    for (const auto & [p,entry] : object_index)
    {
        stream() << bits(entry.obj_uuid) << bits(entry.class_uuid) << bits(entry.data_pos);
    }
}

void Serializer::finalize()
{
    int index_pos = stream().current_pos();
    int index_cnt = object_index.size();
    dump_index();
    stream().set_pos(0);
    stream() << bits(index_pos) << bits(index_cnt);
}

Serializer::Stream::Stream(std::ostream& _os): os(std::ref(_os)) {}

int Serializer::Stream::current_pos() const
{
    return (int)os.get().tellp();
}

void Serializer::Stream::set_pos(int pos)
{
    os.get().seekp((std::streampos)pos);
}

} // namespace serial
} // namespace maat