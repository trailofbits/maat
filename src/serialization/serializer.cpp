#include "maat/serializer.hpp"
#include "maat/exception.hpp"
#include "maat/types.hpp"

namespace maat{
namespace serial{

Empty _empty_instance;
Empty& empty()
{
    return _empty_instance;
}


// uid 0 is reserved for null pointers
Serializer::Serializer(std::ostream& os): _stream(os), _uid_cnt(1)
{
    // Reserve space for index info
    int index_pos = 0, index_cnt = 0;
    stream() << bits(index_pos) << bits(index_cnt);
}

Serializer::Stream& Serializer::stream() {return _stream;}

uid_t Serializer::new_uid() {return _uid_cnt++;}

Serializer::IndexEntry& Serializer::get_index_entry(const Serializable* obj_ptr)
{
    const void* p = obj_ptr;
    auto it = object_index.find(p);
    if (it == object_index.end())
        throw serialize_exception("Serializer::get_uid(): object was not indexed!");
    else
        return it->second;
}

void Serializer::serialize(const Serializable& obj)
{
    uid_t root_obj_uid = ptr(&obj); // Add object
    stream() << bits(root_obj_uid); // Write root object uid before all data
    while (not serialization_queue.empty())
    {
        const Serializable* next = serialization_queue.front();
        get_index_entry(next).data_pos = stream().current_pos();
        next->dump(*this);
        get_index_entry(next).data_end_pos = stream().current_pos();
        serialization_queue.pop();
    }
    // Write index
    finalize();
}

void Serializer::serialize(const std::shared_ptr<Serializable>& obj)
{
    return serialize(*obj);
}

uid_t Serializer::ptr(const Serializable* obj_ptr)
{
    // If nullptr, return null uid
    if (obj_ptr == nullptr)
        return (uid_t)0;

    // Get void ptr to object
    const void* p = obj_ptr;
    // Check if ptr already in index
    auto it = object_index.find(p);
    if (it != object_index.end())
    {
        return it->second.obj_uid;
    }
    else
    {
        // Add a new entry
        uid_t obj_uid = new_uid();
        object_index[p] = IndexEntry{obj_uid, obj_ptr->class_uid(), 0};
        serialization_queue.push(obj_ptr);
        return obj_uid;
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
        stream() << bits(entry.obj_uid) << bits(entry.class_uid)
                 << bits(entry.data_pos) << bits(entry.data_end_pos);
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




// ========= Cache for sleigh contexts ===========

std::unordered_map<CPUMode, std::shared_ptr<TranslationContext>> __sleigh_ctx_cache;

void cache_sleigh_ctx(CPUMode mode, std::shared_ptr<TranslationContext> sleigh_ctx)
{
    __sleigh_ctx_cache[mode] = sleigh_ctx;
}

std::shared_ptr<TranslationContext> get_cached_sleigh_ctx(CPUMode mode)
{
    const auto& res = __sleigh_ctx_cache.find(mode);
    if (res == __sleigh_ctx_cache.end())
        return nullptr;
    else
        return res->second;
}

} // namespace serial
} // namespace maat