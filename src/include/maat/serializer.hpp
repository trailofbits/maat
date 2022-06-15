#ifndef MAAT_SERIALIZER_HPP
#define MAAT_SERIALIZER_HPP

#include <unordered_map>
#include <queue>
#include <string>
#include <iostream>
#include <set>
#include <functional>
#include <memory>
#include <optional>
#include "maat/exception.hpp"

namespace maat{

// Forward declarations
enum class CPUMode;
class TranslationContext;

/** \defgroup serial Serialization
 * \brief Maat's serialization utilities
 * */

namespace serial{

/** \addtogroup serial
 * \{ */

/// Unique identifier of a serialized object
typedef uint16_t uid_t;


/** UID for Maat classes. The UID is used to store the class of a serialized object
 * and reconstruct the appropriate object when deserializing. NULL UID is reserved 
 * for error detection */
enum ClassId : uid_t
{
    ABSTRACT_COUNTER=1,
    ARCH_NONE,
    ARCH_X64,
    ARCH_X86,
    BRANCH,
    CONSTRAINT,
    CPU,
    CPU_CONTEXT,
    ENV_EMULATOR,
    ENV_ETHEREUM_EMULATOR,
    ENV_LINUX_EMULATOR,
    ENV_SNAPSHOT,
    EVM_CONTRACT,
    EVM_KECCAK_HELPER,
    EVM_MEMORY,
    EVM_STACK,
    EVM_STORAGE,
    EVM_TRANSACTION,
    EVM_INTERNAL_TRANSACTION,
    EVM_TRANSACTION_RESULT,
    EXPR_BINOP,
    EXPR_CONCAT,
    EXPR_CST,
    EXPR_EXTRACT,
    EXPR_ITE,
    EXPR_UNOP,
    EXPR_VAR,
    FILE_ACCESSOR,
    FILE_SYSTEM,
    FS_DIRECTORY,
    INFO,
    INST_LOCATION,
    INTERVAL_TREE,
    LIFTER,
    MAAT_ENGINE,
    MEM_ABSTRACT_BUFFER,
    MEM_ACCESS,
    MEM_CONCRETE_BUFFER,
    MEM_ENGINE,
    MEM_MAP,
    MEM_MAP_MANAGER,
    MEM_PAGE_MANAGER,
    MEM_SEGMENT,
    MEM_STATUS_BITMAP,
    NUMBER,
    PAGE_SET,
    PATH_MANAGER,
    PHYSICAL_FILE,
    PROCESS_INFO,
    REG_ACCESS,
    SAVED_MEM_STATE,
    SETTINGS,
    SIMPLE_INTERVAL,
    SNAPSHOT,
    SNAPSHOT_MANAGER,
    SNAPSHOT_MANAGER_ENV,
    SYMBOL,
    SYMBOL_MANAGER,
    SYMBOLIC_MEM_ENGINE,
    SYMBOLIC_MEM_WRITE,
    TMP_CONTEXT,
    VALUE,
    VALUE_SET,
    VAR_CONTEXT
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

/** Explicit wrapper to dump/load the raw contents of std::optional<> variables using a serializer stream.
 * Intended to be used for primitive POD types like 'int', 'char', etc  */
template <typename T> struct OptionalBits
{
    T t;
};
/// Wrap a variable for reading from a deserializer stream
template <typename T> static inline OptionalBits<std::optional<T>&> optional_bits(std::optional<T>& t){
    return OptionalBits<std::optional<T>&>{t};
}

/// Wrap a variable for writing to a deserializer stream
template <typename T> static inline OptionalBits<const std::optional<T>&> optional_bits(const std::optional<T>& t){
    return OptionalBits<const std::optional<T>&>{t};
}

/** Explicit wrapper to dump/load the raw contents of a primitive-type container using a serializer stream.
 * Intended to be used for POD types like 'int', 'char', etc  */
template <typename T> struct ContainerBits
{
    T t;
};
/// Wrap a POD type container for reading from a deserializer stream
template <typename T, template< typename ELEM, typename ALLOC = std::allocator<ELEM>> class C>
static inline ContainerBits<C<T>&> container_bits(C<T>& t){
    return ContainerBits<C<T>&>{t};
}

/// Wrap a POD type container for writing to a deserializer stream
template <typename T, template< typename ELEM, typename ALLOC = std::allocator<ELEM>> class C>
static inline ContainerBits<const C<T>&> container_bits(const C<T>& t){
    return ContainerBits<const C<T>&>{t};
}


// Forward declarations
class Serializer;
class Deserializer;

/// Virtual interface that serializable classes must implement 
class Serializable
{
public:
    virtual ~Serializable() = default;
    /// Return the class uid (see ClassId enum)
    virtual uid_t class_uid() const = 0; 
    /// Dump the object contents in a serializer stream
    virtual void dump(Serializer&) const = 0; 
    /// Restore an object from a deserializer stream
    virtual void load(Deserializer&) = 0; 
};

/// Wrap an empty object for reading/writing to serializer/deserializer
// This needs to be used for objects that have no body to serialize (otherwise
// their position in the stream will be identical to the next object's position,
// which breaks the deserializer)
class Empty
{
public:
    char dummy;
};
Empty& empty();

/** Class that serializes a serializable class into a stream
 *
 * A 'Serializer' instance is intended to be used only once, then deleted. The
 * serialize() method allows to serialize an object on the disk, so that it can 
 * later be reconstructed using the 'Deserializer'.
 * 
 * Objects content can be added to the serialization stream using the '<<' operator. 
 * The serializer accepts 
 * either objects that inherit from the 'Serializable' class, or raw bits.
 * 
 * 'Serializable' objects are serialized automatically using their dump()
 * method. Operator '<<' seemlessly supports smart pointers, containers, std::optional, 
 * raw pointers, and maps of 'Serializable' objects.
 *
 * In order to serialize raw bits (primitive types, buffers, etc), one needs to wrap
 * the variable(s) with one of the following functions available in the serial:: namespace:
 * - bits(): for primitive types (int, char, size_t, etc)
 * - buffer(): for byte buffers with a known size
 * - optional_bits(): for primitive types wrapped in std::optional (e.g optional<bool>)
 * - container_bits(): for primitive types wrapper in std container (e.g vector<int>)
 */
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
        uid_t obj_uid;
        uid_t class_uid;
        int data_pos; // Data position for object in stream
        int data_end_pos; // End of data for object in stream
    };

private:
    // Unique object ID counter
    uid_t _uid_cnt;
    // Out stream
    Stream _stream;
    // Map objects to their uid
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
    /** Add an object to the serialization queue and return it's object uid. This
     * method is intended to be used from within the Serializable::dump() overloads */
    uid_t ptr(const Serializable* obj);
public:
    /// Dump primitive type by reference
    template <typename T> Serializer& operator<<(Bits<T&> obj)
    {
        stream() << obj;
        return *this;
    }

    /// Dump std::optional primitive type by reference
    template <typename T> Serializer& operator<<(OptionalBits<T&> obj)
    {
        bool has_value = obj.t.has_value(); 
        stream() << bits(has_value);
        if (has_value)
            stream() << bits(obj.t.value());
        return *this;
    }

    /// Dump raw buffer
    template <typename T> Serializer& operator<<(Buffer<T> obj)
    {
        stream() << obj;
        return *this;
    }

    /// Dump empty object
    Serializer& operator<<(Empty& obj)
    {
        stream() << bits(obj.dummy);
        return *this;
    }

    /// Dump string
    Serializer& operator<<(const std::string& str)
    {
        stream() << bits(str.size());
        stream() << buffer(str.data(), str.size());
        return *this;
    }

    /// Dump standard container of primitive type
    template <typename T>
    Serializer& operator<<(ContainerBits<T&> container)
    {
        size_t size = container.t.size();
        stream() << bits(size);
        for (const auto& elem : container.t)
            *this << bits(elem);
        return *this;
    }

    /// Dump standard container of non-primitive type
    template <typename T, template< typename ELEM, typename ALLOC = std::allocator<ELEM>> class C>
    Serializer& operator<<(const C<T>& container)
    {
        size_t size = container.size();
        stream() << bits(size);
        for (const auto& elem : container)
            *this << elem;
        return *this;
    }

    /// Dump map non-primitive type
    template<template <typename...> class Map, typename K, typename V, typename H, typename CMP>
    Serializer& operator<<(const Map<K,V,H,CMP>& map)
    {
        stream() << bits(map.size());
        for (const auto& [key,val] : map)
            *this << key << val;
        return *this;
    }

    /// Dump shared_ptr of serializable 
    Serializer& operator<<(const std::shared_ptr<Serializable>& s);

    /// Dump ptr of serializable 
    Serializer& operator<<(const Serializable* s);

    /// Dump serializable object
    Serializer& operator<<(const Serializable& s)
    {
        s.dump(*this); 
        return *this;
    }

    /// Dump optional of non-serializable non-primitive type
    template <typename T>
    Serializer& operator<<(const std::optional<T>& s)
    {
        *this << bits(s.has_value());
        if (s.has_value())
            *this << *s; // Don't use bits() here, we don't want to support primitive types
        return *this;
    }

private:
    // Get index entry for object
    IndexEntry& get_index_entry(const Serializable*);
    uid_t new_uid();
    // Write index data to stream
    void dump_index();
    // Dump the index, write index info at the beginning of the stream
    void finalize();
};


/** Class that deserializes a serializable class from a stream
 *
 * A 'Deserializer' instance is intended to be used only once, then deleted. The
 * deserialize() method allows to deserialize an object that was serialized by the
 * 'Serializer'. There are different signatures for deserialize():
 * deserialize(Serializable&): loads object content in place
 * deserialize(<pointer to Serializable>): loads content in a newly allocated object 
 * 
 * Objects content can be read from the serialization stream using the '>>' operator. 
 * The deserializer accepts 
 * either objects that inherit from the 'Serializable' class, or raw bits.
 * 
 * 'Serializable' objects are loaded automatically using their load()
 * method. Operator '>>' seemlessly supports smart pointers, containers, std::optional, 
 * raw pointers, and maps of 'Serializable' objects.
 *
 * In order to deserialize raw bits (primitive types, buffers, etc), one needs to wrap
 * the variable(s) with the same functions mentioned in the 'Serializer' documentation.
 */
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
        Serializable* new_object(uid_t class_uid);
        /// Create new shared pointer for a given object
        std::shared_ptr<Serializable> new_shared_ptr(Serializable* raw_ptr);
        /// Create new unique_ptr for a given object
        std::unique_ptr<Serializable> new_unique_ptr(Serializable* raw_ptr);
    };

private:
    std::unordered_map<uid_t, Serializable*> uid_to_object;
    std::unordered_map<int, Serializable*> data_pos_to_object;
    int root_obj_data_pos, root_obj_data_end_pos;
    // In stream
    Stream _stream;
    Factory _factory;
public:
    Deserializer(std::istream&); ///< Constructor
protected:
    Stream& stream();
public:
    // WARNING: deserialize() methods must be called only once!
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

    /// Deserialize object into an object reference
    void deserialize(Serializable& dest);

public:
    /// Load primitive type by reference
    template <typename T> Deserializer& operator>>(Bits<T&> obj)
    {
        stream() >> obj;
        return *this;
    }

    /// Load std::optional primitive type by reference
    template <typename T> Deserializer& operator>>(OptionalBits<T&> obj)
    {
        bool has_value = obj.t.has_value();
        stream() >> bits(has_value);
        if (has_value)
            stream() >> bits(obj.t.emplace());
        return *this;
    }

    /// Load map non-primitive type
    template<template <typename...> class Map, typename K, typename V, typename H, typename CMP>
    Deserializer& operator>>(Map<K,V, H, CMP>& map)
    {
        size_t size;
        K key;
        V val;
        stream() >> bits(size);
        for (int i = 0; i < size; i++)
        {
            *this >> key >> val;
            map[key] = val;
        }
        return *this;
    }

    /// Load raw buffer
    template <typename T> Deserializer& operator>>(Buffer<T> obj)
    {
        stream() >> obj;
        return *this;
    }

    /// Load empty object
    Deserializer& operator>>(Empty& obj)
    {
        stream() >> bits(obj.dummy);
        return *this;
    }

    /// Load string
    Deserializer& operator>>(std::string& str);

    /// Load shared_ptr of serializable
    template <typename T>
    typename std::enable_if<std::is_base_of<Serializable, T>::value, Deserializer&>::type
    operator>>(std::shared_ptr<T>& s)
    {
        uid_t obj_uid = 0;
        stream() >> bits(obj_uid);
        // if null uid, null pointer
        if (obj_uid == 0)
        {
            s = nullptr;
        }
        else
        {
            // Get object for this uid
            auto it = uid_to_object.find(obj_uid);
            if (it == uid_to_object.end())
                throw serialize_exception("Error deserializing shared_ptr: can't map uid to object");
            Serializable* obj = it->second;
            // We should be OK forcing the cast to child class T here since
            // the template is enabled only if T derives from Serializable
            s = std::reinterpret_pointer_cast<T>(
                _factory.new_shared_ptr(obj)
            );
        }
        return *this;
    }

    /// Load ptr of serializable
    template <typename T>
    typename std::enable_if<std::is_base_of<Serializable, T>::value, Deserializer&>::type
    operator>>(T*& s)
    {
        uid_t obj_uid = 0;
        stream() >> bits(obj_uid);
        // if null uid, null pointer
        if (obj_uid == 0)
        {
            s = nullptr;
        }
        else
        {
            // Get object for this uid
            auto it = uid_to_object.find(obj_uid);
            if (it == uid_to_object.end())
                throw serialize_exception("Error deserializing ptr: can't map uid to object");
            Serializable* obj = it->second;
            // We should be OK forcing the cast to child class T here since
            // the template is enabled only if T derives from Serializable
            s = reinterpret_cast<T*>(obj);
        }
        return *this;
    }

    /// Load standard container of primitive type
    template <typename T>
    Deserializer& operator>>(ContainerBits<T> container)
    {
        size_t size = 0;
        stream() >> bits(size);
        container.t.clear();
        for (size_t i = 0; i < size; i++)
        {
            auto& t = container.t.emplace_back();
            *this >> bits(t);
        }
        return *this;
    }

    /// Load standard container
    template <typename T, template< typename ELEM, typename ALLOC = std::allocator<ELEM>> class C>
    Deserializer& operator>>(C<T>& container)
    {
        size_t size = 0;
        stream() >> bits(size);
        container.clear();
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

    /// Load optional of non-primitive type
    template <typename T>
    Deserializer& operator>>(std::optional<T>& opt)
    {
        bool has_value;
        *this >> bits(has_value);
        if (has_value)
            *this >> opt.emplace(); // Don't use bits() here, we don't want to support primitive types
        else
            opt = std::nullopt;
        return *this;
    }

private:
    // Read index and initialise all empty objects
    void init();
    /** Deserialize objects and return a pointer to the root object.
      * If skip_root_obj is true, deserializes all objects but the root object,
        and returns a nullptr */
    Serializable* _deserialize(bool skip_root_obj = false);
};

void cache_sleigh_ctx(CPUMode mode, std::shared_ptr<TranslationContext> sleigh_ctx);
std::shared_ptr<TranslationContext> get_cached_sleigh_ctx(CPUMode mode);

/** \} */ // Serialization doxygen group

} // namespace serial
} //namespace maat


#endif