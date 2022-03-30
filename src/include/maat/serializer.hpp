#ifndef MAAT_SERIALIZER_HPP
#define MAAT_SERIALIZER_HPP

#include <unordered_map>
#include <queue>
#include <string>
#include <iostream>
#include <set>
#include "maat/exception.hpp"

namespace maat{

/** \defgroup serial Serialization
 * \brief Maat's serialization utilities
 * */

namespace serial{

/** \addtogroup ir
 * \{ */

/// Unique identifier of a serialized object
typedef uint16_t uuid_t;


/** UUID for Maat classes. The UID is used to store the class of a serialized object
 * and reconstruct the appropriate object when deserializing. NULL UID is reserved 
 * for error detection */
enum ClassId : uuid_t
{
    EXPR_BINOP=1,
    EXPR_CONCAT,
    EXPR_CST,
    EXPR_EXTRACT,
    EXPR_ITE,
    EXPR_UNOP,
    EXPR_VAR,
    MEM_CONCRETE_BUFFER,
    MEM_STATUS_BITMAP,
    NUMBER,
    VALUE
};


// From https://stackoverflow.com/questions/1559254/are-there-binary-memory-streams-in-c
/** Explicit wrapper to dump/load the raw contents of any variable using a serializer stream.
 * Intended to be used for primitive POD types like 'int', 'char', etc  */
template <typename T> struct Bits
{
  T t;
};
/// Wrap a variable for reading from a deserializer stream
template <typename T> static inline Bits<T&> bits(T& t) { return Bits<T&>{t}; }
/// Wrap a variable for writing to a serializer stream
template <typename T> static inline Bits<const T&> bits(const T& t) { return Bits<const T&>{t}; }

/** Explicit wrapper to dump a raw buffer in a serializer stream, intended to be used
 * for char*, uint8_t*, etc  */
template <typename T> struct Buffer
{
    T* buf;
    int cnt;
};
/// Wrap a buffer for reading from a deserializer stream
static inline Buffer<char> buffer(char* buf, int cnt){ return Buffer<char>{buf, cnt}; }
/// Wrap a buffer for writing to a serializer stream
static inline Buffer<const char> buffer(const char* buf, int cnt){ return Buffer<const char>{buf, cnt}; }

// Forward declarations
class Serializer;
class Deserializer;

/// Virtual interface that serializable classes must implement 
class Serializable
{
public:
    /// Return the class uuid (see ClassId enum)
    virtual uuid_t class_uuid() const = 0; 
    /// Dump the object contents in a serializer stream
    virtual void dump(Serializer&) const = 0; 
    /// Restore an object from a deserializer stream
    virtual void load(Deserializer&) = 0; 
};

/// Class that serializes a serializable class into a stream
class Serializer
{
public:
    /// Raw stream to write serialized data to
    class Stream
    {
        std::reference_wrapper<std::ostream> os;
    public:
        /// Constructor. Stream argument MUST be opened in binary mode (ios_base::binary)
        Stream(std::ostream& os);
        /// Dump raw contents of a primitive type
        template <typename T> Stream& operator<<(Bits<T&> b)
        {
            os.get().write(reinterpret_cast<const char *>(&b.t), sizeof(T));
            return *this;
        }
        /// Dump a raw buffer
        template <typename T> Stream& operator<<(Buffer<T> b)
        {
            os.get().write(reinterpret_cast<const char*>(b.buf), b.cnt);
            return *this;
        }
        /// Return current position in stream
        int current_pos() const;
        /// Set position in stream
        void set_pos(int pos);
    };

    /// Index entry used to keep track of an object being serialized
    struct IndexEntry
    {
        uuid_t obj_uuid;
        uuid_t class_uuid;
        int data_pos; // Data position for object in stream
    };

private:
    // Unique object ID counter
    uuid_t _uuid_cnt;
    // Out stream
    Stream _stream;
    // Map objects to their uuid
    std::unordered_map<const void*, IndexEntry> object_index;
    // Objects waiting to be serialized
    std::queue<const Serializable*> serialization_queue;
public:
    Serializer(std::ostream& os); ///< Constructor
protected:
    Stream& stream(); ///< Get data stream
public:
    // Note: the serialize() methods can be called only once
    /// Serialize object
    void serialize(const Serializable& obj);
    /// Serialize object from shared pointer
    void serialize(const std::shared_ptr<Serializable>& obj);
    /** Add an object to the serialization queue and return it's object uuid. This
     * method is intended to be used from within the Serializable::dump() overloads */
    uuid_t ptr(const Serializable* obj);
public:
    /// Dump primitive type by reference
    template <typename T> Serializer& operator<<(Bits<T&> obj)
    {
        stream() << obj;
        return *this;
    }

    /// Dump raw buffer
    template <typename T> Serializer& operator<<(Buffer<T> obj)
    {
        stream() << obj;
        return *this;
    }

    /// Dump string
    Serializer& operator<<(const std::string& str)
    {
        stream() << bits(str.size());
        stream() << buffer(str.data(), str.size());
        return *this;
    }

    /// Dump standard container
    template <typename T, template< typename ELEM, typename ALLOC = std::allocator<ELEM>> class C>
    Serializer& operator<<(const C<T>& container)
    {
        size_t size = container.size();
        stream() << bits(size);
        for (const auto& elem : container)
            *this << elem;
        return *this;
    }

    /// Dump shared_ptr of serializable 
    Serializer& operator<<(const std::shared_ptr<Serializable>& s);

    /// Dump serializable object
    Serializer& operator<<(const Serializable& s)
    {
        s.dump(*this); 
        return *this;
    }

private:
    // Get index entry for object
    IndexEntry& get_index_entry(const Serializable*);
    uuid_t new_uuid();
    // Write index data to stream
    void dump_index();
    // Dump the index, write index info at the beginning of the stream
    void finalize();
};


/// Class that deserializes a serializable class from a stream
class Deserializer
{
public:
    /// Stream to read serialized data from
    class Stream
    {
        std::reference_wrapper<std::istream> in;
    public:
        /// Constructore. Input stream MUST be opened in binary mode (ios_base::binary) and seekable
        Stream(std::istream& in);
        /// Load contents of a primitive type
        template <typename T> Stream& operator>>(Bits<T&> b)
        {
            in.get().read(reinterpret_cast<char *>(&b.t), sizeof(T));
            return *this;
        }
        /// Load contents of a buffer
        template <typename T> Stream& operator>>(Buffer<T> b)
        {
            in.get().read(reinterpret_cast<char*>(b.buf), b.cnt);
            return *this;
        }
        /// Return current position in stream
        int current_pos() const;
        /// Set position in stream
        void set_pos(int pos);
    };

    /// Helper class to reconstruct dynamic objects from serialized data 
    class Factory
    {
    private:
        // Map used for creating new shared pointers for objects which already have
        // a shared pointer to them
        std::unordered_map<Serializable*, std::shared_ptr<Serializable>> obj_to_shared_ptr;
        // Map used to keep track of raw pointers that were used to create a unique_ptr
        std::set<Serializable*> already_has_unique_ptr;
    public:
        /// Allocate new object of a given class
        Serializable* new_object(uuid_t class_uuid);
        /// Create new shared pointer for a given object
        std::shared_ptr<Serializable> new_shared_ptr(Serializable* raw_ptr);
        /// Create new unique_ptr for a given object
        std::unique_ptr<Serializable> new_unique_ptr(Serializable* raw_ptr);
    };

private:
    std::unordered_map<uuid_t, Serializable*> uuid_to_object;
    std::unordered_map<int, Serializable*> data_pos_to_object;
    // In stream
    Stream _stream;
    Factory _factory;
public:
    Deserializer(std::istream&); ///< Constructor
protected:
    Stream& stream();
public:
    // deserialize() methods must be called only once
    /// Deserialize object
    template <typename T> void deserialize(std::unique_ptr<T>& dest)
    {
        dest = std::unique_ptr<T>(reinterpret_cast<T*>(_deserialize()));
    }

    /// Deserialize object into a shared pointer
    template <typename T> void deserialize(std::shared_ptr<T>& dest)
    {
        dest = std::shared_ptr<T>(reinterpret_cast<T*>(_deserialize()));
    }
public:
    /// Load primitive type by reference
    template <typename T> Deserializer& operator>>(Bits<T&> obj)
    {
        stream() >> obj;
        return *this;
    }

    /// Load raw buffer
    template <typename T> Deserializer& operator>>(Buffer<T> obj)
    {
        stream() >> obj;
        return *this;
    }

    /// Load string
    Deserializer& operator>>(std::string& str);

    /// Load shared_ptr of serializable
    template <typename T>
    typename std::enable_if<std::is_base_of<Serializable, T>::value, Deserializer&>::type
    operator>>(std::shared_ptr<T>& s)
    {
        uuid_t obj_uuid = 0;
        stream() >> bits(obj_uuid);
        // if null uuid, null pointer
        if (obj_uuid == 0)
        {
            s = nullptr;
        }
        else
        {
            // Get object for this uuid
            auto it = uuid_to_object.find(obj_uuid);
            if (it == uuid_to_object.end())
                throw serialize_exception("Error deserializing shared_ptr: can't map uuid to object");
            Serializable* obj = it->second;
            // We should be OK forcing the cast to child class T here since
            // the template is enabled only if T derives from Serializable
            s = reinterpret_pointer_cast<T>(
                _factory.new_shared_ptr(obj)
            );
        }
        return *this;
    }

    /// Load standard container
    template <typename T, template< typename ELEM, typename ALLOC = std::allocator<ELEM>> class C>
    Deserializer& operator>>(C<T>& container)
    {
        size_t size = 0;
        stream() >> bits(size);
        for (size_t i = 0; i < size; i++)
        {
            T& t = container.emplace_back();
            *this >> t;
        }
        return *this;
    }

    // Load serializable object
    Deserializer& operator>>(Serializable& s)
    {
        s.load(*this);
        return *this;
    }

private:
    // Read index and initialise all empty objects
    void init();
    Serializable* _deserialize();
};

/** \} */ // Serialization doxygen group

} // namespace serial
} //namespace maat


#endif