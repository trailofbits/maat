#include "maat/memory.hpp"
#include "maat/exception.hpp"
#include "maat/stats.hpp"
#include "maat/varcontext.hpp"
#include <cassert>
#include <iostream>
#include <sstream>
#include <cstring>

namespace maat
{

using serial::bits;

PageSet::PageSet(): start(0), end(0), flags(maat::mem_flag_none), was_once_executable(false)
{}

PageSet::PageSet(addr_t s, addr_t e, mem_flag_t f, bool was_once_exec): 
    start(s), end(e), flags(f)
{
    was_once_executable = was_once_exec | ( f & maat::mem_flag_x );
}

bool PageSet::intersects_with_range(addr_t min, addr_t max) const
{
    return start <= max && end >= min;
}

bool PageSet::contains(addr_t addr)
{
    return start <= addr && end >= addr;
}

uid_t PageSet::class_uid() const
{
    return serial::ClassId::PAGE_SET;
}

void PageSet::dump(serial::Serializer& s) const
{
    s << bits(start) << bits(end)  << bits(flags) << bits(was_once_executable);
}

void PageSet::load(serial::Deserializer& d)
{
    d >> bits(start) >> bits(end) >> bits(flags) >> bits(was_once_executable);
}


MemPageManager::MemPageManager(size_t ps): _page_size(ps)
{
    // Add one big region with no permissions
    _regions.push_back(PageSet(0x0, 0xffffffffffffffff, 0x0));
}

size_t MemPageManager::page_size()
{
    return _page_size;
}


bool MemPageManager::is_mapped(addr_t start, addr_t end)
{
    for (const auto& r : _regions)
    {
        if (r.intersects_with_range(start, end) and r.flags == mem_flag_none)
            return false;
    }
    return true;
}

bool MemPageManager::is_unmapped(addr_t start, addr_t end)
{
    for (const auto& r : _regions)
    {
        if (r.intersects_with_range(start, end) and r.flags != mem_flag_none)
            return false;
    }
    return true;
}

void MemPageManager::set_flags(addr_t start, addr_t end, mem_flag_t flags)
{
    std::list<PageSet>::iterator it;
    std::list<PageSet> new_regions;
    
    // Adjust start and end
    if( start % _page_size != 0 )
    {
        start -= (start%_page_size);
    }

    if( end+1 % _page_size != 0 )
    {
        end += (_page_size - (end%_page_size));
        end--;
    }

    for( auto& r : _regions)
    {
        if( r.intersects_with_range(start, end))
        {
            if( r.flags != flags )
            {
                // Different flags, we need to split the 
                if( start <= r.start && end >= r.end )
                {
                    // region contained in changing region, so change all flags
                    r.flags = flags;
                    new_regions.push_back(r);
                }
                else if( start <= r.start )
                {
                    // Start at same addr but changing region is smaller
                    new_regions.push_back(PageSet(r.start, end, flags, r.was_once_executable));
                    new_regions.push_back(PageSet(end+1, r.end, r.flags, r.was_once_executable));
                }
                else if( end >= r.end)
                {
                    // End at same addr
                    new_regions.push_back(PageSet(r.start, start-1, r.flags, r.was_once_executable));
                    new_regions.push_back(PageSet(start, r.end, flags, r.was_once_executable));
                }
                else
                {
                    // changing region in the middle of existing region
                    new_regions.push_back(PageSet(r.start, start-1, r.flags, r.was_once_executable));
                    new_regions.push_back(PageSet(start, end, flags, r.was_once_executable));
                    new_regions.push_back(PageSet(end+1, r.end, r.flags, r.was_once_executable));
                }
            }
            else
            {
                new_regions.push_back(r);
            }
        }
        else
        {
            new_regions.push_back(r);
        }
    }
    _regions = new_regions;
    merge_regions(); // Merge contiguous regions with same permissions
}

void MemPageManager::merge_regions()
{
    addr_t prev_start = 0;
    mem_flag_t prev_flags = _regions.front().flags;
    std::list<PageSet>::iterator it = _regions.begin();
    std::list<PageSet> res;
    int i = 1;
    std::advance(it, 1);
    for( ; it != _regions.end(); it++)
    {
        if( it->flags != prev_flags )
        {
            res.push_back(PageSet(prev_start, it->start-1, prev_flags));
            prev_start = it->start;
            prev_flags = it->flags;
        }
        i++;
        if( i == _regions.size() )
        {
            // We reached last region, add it
            res.push_back(PageSet(prev_start, it->end, it->flags));
        }
    }
    _regions = res;
}

mem_flag_t MemPageManager::get_flags(addr_t addr)
{
    for (PageSet& r : _regions)
    {
        if (r.contains(addr))
        {
            return r.flags;
        }
    }
    throw runtime_exception("MemPageManager::get_flags(): didn't find matching map, should not happen!");
}

bool MemPageManager::has_flags(addr_t addr, mem_flag_t flags){
    return (get_flags(addr) & flags);
}

bool MemPageManager::was_once_executable(addr_t addr){
    for( PageSet& r : _regions )
    {
        if( r.contains(addr))
            return r.was_once_executable;
    }
    return false;
}

const std::list<PageSet>& MemPageManager::regions()
{
    return _regions;
}

void MemPageManager::set_regions(std::list<PageSet>&& regions)
{
    _regions = regions;
}

uid_t MemPageManager::class_uid() const
{
    return serial::ClassId::MEM_PAGE_MANAGER;
}

void MemPageManager::dump(serial::Serializer& s) const
{
    s << bits(_page_size) << _regions;
}

void MemPageManager::load(serial::Deserializer& d)
{
    _regions.clear();
    d >> bits(_page_size) >> _regions;
}

std::string _mem_flags_to_string(mem_flag_t flags)
{
    std::stringstream ss;
    if( flags & maat::mem_flag_r )
        ss << "R";
    else
        ss << "-";
        
    if( flags & maat::mem_flag_w )
        ss << "W";
    else
        ss << "-";
    
    if( flags & maat::mem_flag_x )
        ss << "X";
    else
        ss << "-";    
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, MemPageManager& mem)
{
    static unsigned int addr_w = 20;
    os << std::endl << "Page permissions: " << std::endl;
    os << std::endl << std::left << std::setw(addr_w) << "Start" << std::left << std::setw(addr_w) << "End" 
       << std::left << std::setw(8) << "Perm." << std::endl;
    os << std::left << std::setw(addr_w) << "-----" << std::left << std::setw(addr_w) << "---" 
       << std::left << std::setw(8) << "-----" << std::endl;
    
    for( PageSet& r : mem._regions )
    {
        if (r.flags != maat::mem_flag_none)
        {
            os  << std::hex << "0x" << std::left << std::setw(addr_w-2)
                << r.start << "0x" << std::left << std::setw(addr_w-2)
                << r.end << _mem_flags_to_string(r.flags)
                << std::endl;
        }
    }
    return os;
}

MemStatusBitmap::MemStatusBitmap():_bitmap(nullptr), _size(0){}

MemStatusBitmap::MemStatusBitmap(const MemStatusBitmap& other)
:_size(other._size)
{
    try
    {
        _bitmap = new uint8_t[_size]{0};
        memcpy(_bitmap, other._bitmap, _size);
    }
    catch(std::bad_alloc)
    {
        throw mem_exception(Fmt()
            << "Failed to copy MemStatusBitmap of size " << _size
            >> Fmt::to_str );
    }
}

MemStatusBitmap::MemStatusBitmap(offset_t nb_bytes)
{
    // +1 to be sure to not loose bytes if nb_bytes is
    // not a multiple of 8 
    // {0} to initialize everything to concrete by default
    try
    {
        _size = (nb_bytes/8) + 1;
        _bitmap = new uint8_t[_size]{0};
    }
    catch(std::bad_alloc)
    {
        throw mem_exception(Fmt()
            << "Failed to allocate MemStatusBitmap of size " << nb_bytes
            >> Fmt::to_str );
    }
}

void MemStatusBitmap::extend_after(addr_t nb_bytes)
{
    uint8_t* new_bitmap;
    addr_t new_size = _size + (nb_bytes/8)+1;
    try
    {
        new_bitmap = new uint8_t[new_size]{0};
    }
    catch(std::bad_alloc)
    {
        throw mem_exception(Fmt()
            << "MemStatusBitmap::extend_after(): Failed to allocate MemStatusBitmap of size " 
            << new_size 
            >> Fmt::to_str );
    }
    memcpy(new_bitmap, _bitmap, _size);
    delete [] _bitmap;
    _bitmap = new_bitmap;
    _size = new_size;
}

void MemStatusBitmap::extend_before(addr_t nb_bytes)
{
    uint8_t* new_bitmap, *ptr;
    int i = 0;
    uint8_t rshift, lshift;

    addr_t new_size = _size + (nb_bytes/8)+1;
    try
    {
        new_bitmap = new uint8_t[new_size]{0};
    }
    catch(std::bad_alloc)
    {
        throw mem_exception(Fmt()
            << "MemStatusBitmap::extend_after(): Failed to allocate MemStatusBitmap of size " 
            << new_size
            >> Fmt::to_str
        );
    }

    if (nb_bytes % 8 == 0)
    {
        memcpy(new_bitmap+(nb_bytes/8), _bitmap, _size);
    }
    else
    {
        /* Copy the bitmap and shift the bytes if nb_bytes is 
         * not a multiple of 8 */
        lshift = nb_bytes % 8;
        rshift = 8 - lshift;
        ptr = new_bitmap + (nb_bytes/8); // Pointer to the first byte to fill
        for( i = 0; i < _size; i++){
            if( i != 0 ){
                ptr[i] |= (_bitmap[i-1] >> rshift);
            }
            ptr[i] |= (_bitmap[i] << lshift);
        }
    }

    delete [] _bitmap;
    _bitmap = new_bitmap;
    _size = new_size;
}

MemStatusBitmap::~MemStatusBitmap()
{
    if( _bitmap != nullptr )
        delete [] _bitmap;
    _bitmap = nullptr;
}

void MemStatusBitmap::mark_as_abstract(offset_t off)
{
    offset_t qword = off/8;
    uint8_t mask = 1 << (off%8);
    _bitmap[qword] |= mask;
}

void MemStatusBitmap::mark_as_abstract(offset_t start, offset_t end)
{
    offset_t qword = start/8, last_qword=end/8;
    uint8_t final_mask = 0xff >> (8-1-(end%8));
    uint8_t first_mask = (0xff << (start%8));
    if( qword == last_qword ){
        _bitmap[qword] |= (final_mask&first_mask);
        return;
    }
    _bitmap[qword++] |= first_mask;
    while( qword < last_qword ){
        _bitmap[qword++] = 0xff;
    }
    _bitmap[last_qword] |= final_mask;
}

void MemStatusBitmap::mark_as_concrete(offset_t off)
{
    offset_t qword = off/8;
    uint8_t mask = ~(1 << (off%8));
    _bitmap[qword] &= mask;
}

void MemStatusBitmap::mark_as_concrete(offset_t start, offset_t end)
{
    offset_t qword = start/8, last_qword=end/8;
    uint8_t first_mask = 0xff >> (8-(start%8));
    uint8_t final_mask = (0xfe << (end%8));
    if( qword == last_qword )
    {
        _bitmap[qword] &= (first_mask|final_mask);
        return;
    }
    _bitmap[qword++] &= first_mask;
    while( qword < last_qword )
    {
        _bitmap[qword++] = 0x0;
    }
    _bitmap[last_qword] &= final_mask;
}

bool MemStatusBitmap::is_abstract(offset_t off)
{
    offset_t qword = off/8;
    uint8_t mask = 1 << (off%8);
    return _bitmap[qword] & mask;
}

bool MemStatusBitmap::is_concrete(offset_t off)
{
    offset_t qword = off/8;
    uint8_t mask = 1 << (off%8);
    return _bitmap[qword] ^ mask;
}

/* Return the offset of the first byte that is not abstract */
offset_t MemStatusBitmap::is_abstract_until(offset_t off , offset_t max)
{
    offset_t qword = off/8;
    offset_t max_qword = ((max+off-1)/8)+1;
    offset_t res = off;
    uint8_t m;
    // Test the 8 first bytes
    m = (uint8_t)1 << (off%8);
    while( m != 0)
    {
        if( (_bitmap[qword] & m) == 0 )
            return res; 
        res += 1; 
        m = m << 1; 
    }
    qword++; // Continue from next qword

    // Test 8 bytes per 8 bytes
    while( qword < _size && qword < max_qword && _bitmap[qword] == 0xff)
    {
        res += 8;
        qword++;
    }
    // If we reached the end or the max to read return it 
    if( qword == _size)
        return res + 7;
    else if( qword == max_qword )
        return res;
    // Else test the 7 last ones one by one
    m = 1; 
    while( (m != 0) && ((_bitmap[qword] & m) != 0))
    {
        m = m << 1; 
        res++;
    }
    return res;
}

offset_t MemStatusBitmap::is_concrete_until(offset_t off, offset_t max )
{
    offset_t qword = off/8;
    offset_t max_qword = ((off+max-1)/8)+1;
    offset_t res = off;
    uint8_t m;
    // Test the 8 first bytes
    m = (uint8_t)1 << (off%8);
    while( m != 0)
    {
        if( (_bitmap[qword] & m ) != 0 )
            return res;
        res += 1; 
        m = m << 1; 
    }
    qword++; // Continue from next qword
    
    // Test 8 bytes per 8 bytes
    while( qword < _size && qword < max_qword && _bitmap[qword] == 0x0)
    {
        res += 8;
        qword++;
    }
    // If we reached the end return it
    if( qword == _size )
        return res + 7; 
    else if( qword == max_qword )
        return res;
    // Else test the 7 last ones one by one
    m = 1; 
    while( (m != 0) && ((_bitmap[qword] & m) == 0))
    {
        m = m << 1;
        res++;
    }
    return res;
}

uid_t MemStatusBitmap::class_uid() const
{
    return serial::ClassId::MEM_STATUS_BITMAP;
}

void MemStatusBitmap::dump(Serializer& s) const
{
    s << bits(_size);
    s << serial::buffer((char*)_bitmap, _size);
}

void MemStatusBitmap::load(Deserializer& d)
{
    if (_bitmap != nullptr)
        delete [] _bitmap;

    d >> bits(_size);
    _bitmap = new uint8_t[_size];
    d >> serial::buffer((char*)_bitmap, _size);
}

MemConcreteBuffer::MemConcreteBuffer(Endian endian)
:_mem(nullptr), _endianness(endian){}

MemConcreteBuffer::MemConcreteBuffer(const MemConcreteBuffer& other)
:_endianness(other._endianness), _size(other._size)
{
    try
    {
        _mem = new uint8_t[_size]{0};
        memcpy(_mem, other._mem, _size);
    }
    catch(const std::bad_alloc&)
    {
        throw mem_exception(Fmt()
            << "Failed to copy MemConcreteBuffer of size " << _size
            >> Fmt::to_str );
    }
}

MemConcreteBuffer::MemConcreteBuffer(offset_t nb_bytes, Endian endian)
:_endianness(endian)
{
    try
    {
        _size = nb_bytes;
        _mem = new uint8_t[nb_bytes]{0};
    }
    catch(const std::bad_alloc&)
    {
        throw mem_exception(Fmt()
            << "Failed to allocate MemConcreteBuffer of size " << nb_bytes
            >> Fmt::to_str );
    }
}

MemConcreteBuffer::~MemConcreteBuffer()
{
    if( _mem != nullptr )
        delete [] _mem;
    _mem = nullptr;
}

void MemConcreteBuffer::extend_after(addr_t nb_bytes)
{
    uint8_t* new_mem;
    addr_t new_size = _size + nb_bytes;
    try
    {
        new_mem = new uint8_t[new_size]{0};
    }
    catch(std::bad_alloc)
    {
        throw mem_exception(Fmt()
            << "MemConcreteBuffer::extend_after(): Failed to allocate MemConcreteBuffer of size " 
            << new_size
            >> Fmt::to_str );
    }
    memcpy(new_mem, _mem, _size);
    delete [] _mem;
    _mem = new_mem;
    _size = new_size;
}

void MemConcreteBuffer::extend_before(addr_t nb_bytes)
{
    uint8_t* new_mem;
    addr_t new_size = _size + nb_bytes;
    try
    {
        new_mem = new uint8_t[new_size]{0};
    }
    catch(std::bad_alloc)
    {
        throw mem_exception(Fmt()
            << "MemConcreteBuffer::extend_before(): Failed to allocate MemConcreteBuffer of size " 
            << new_size
            >> Fmt::to_str );
    }
    memcpy(new_mem + nb_bytes, _mem, _size);
    delete [] _mem;
    _mem = new_mem;
    _size = new_size;
}

// Return the first offset where the byte is different than 'val'
offset_t MemConcreteBuffer::is_identical_until(offset_t start, offset_t end, uint8_t val)
{
    offset_t tmp = start;

    if (start == end)
        return start;

    while( *(uint8_t*)((uint8_t*)_mem+(tmp)) == val)
    {
        tmp++;
        if (tmp >= end)
            break;
    };
    return tmp;
}

uint64_t MemConcreteBuffer::read(offset_t off, int nb_bytes)
{
    uint64_t res = 0;
    if (_endianness == Endian::LITTLE)
    {
        for (int i = 0; i < nb_bytes; i++)
            res += ((uint64_t)(*(_mem+off+i))) << i*8;
    }
    else
    {
        for (int i = nb_bytes-1; i >= 0; i--)
            res += ((uint64_t)(*(_mem+off+nb_bytes-1-i))) << i*8;
    }
    return res;
}

Value MemConcreteBuffer::read_as_value(offset_t off, int nb_bytes)
{
    uint64_t val = 0;
    Value res;
    while (nb_bytes >= 8)
    {
        // Read val byte per byte to play nice with sanitizers
        val = read(off, 8);
        if (res.is_none())
            res = Value(64, val);
        else
        {
            if (_endianness == Endian::LITTLE)
                res.set_concat(Value(64,val), res);
            else
                res.set_concat(res, Value(64, val));
        }
        nb_bytes -= 8;
        off += 8;
    }
    if (nb_bytes > 0)
    {
        val = read(off, nb_bytes);
        if (res.is_none())
            res = Value(nb_bytes*8, val);
        else
            if (_endianness == Endian::LITTLE)
                res.set_concat(Value(nb_bytes*8,val), res);
            else
                res.set_concat(res, Value(nb_bytes*8,val));
    }
    return res;
}

void MemConcreteBuffer::write(offset_t off, int64_t val, int nb_bytes)
{
    if( nb_bytes > 8 )
    {
        throw mem_exception(Fmt()
            << "Can not write constant on more than 8 bytes with this method (got " 
            << std::dec << nb_bytes << ")"
            >> Fmt::to_str);
    }

    if (_endianness == Endian::LITTLE)
    {
        for( ; nb_bytes > 0; nb_bytes--)
        {
            *(uint8_t*)((uint8_t*)_mem+off) = val & 0xff;
            val = val >> 8;
            off++;
        }
    }
    else
    {
        for( ; nb_bytes > 0; nb_bytes--)
        {
            *(uint8_t*)((uint8_t*)_mem+off) = (val >> ((nb_bytes-1)*8)) & 0xff;
            off++;
        }
    }
}

void MemConcreteBuffer::write(offset_t off, const Number& val, int nb_bytes)
{
    Number tmp = val;
    Number shft;
    while (nb_bytes > 0)
    {
        if (nb_bytes <= 8)
        {
            write(off, tmp.get_cst(), nb_bytes);
            return;
        }
        else
        {
            if (_endianness == Endian::LITTLE)
            {
                write(off, tmp.get_cst(), 8);
                shft = Number(tmp.size, 64);
                tmp.set_shr(tmp, shft); // Should be safe
            }
            else
            {
                Number tmp_val; tmp_val.set_extract(tmp, nb_bytes*8-1, (nb_bytes-8)*8);
                write(off, tmp_val.get_ucst(), 8);
            }
            nb_bytes -= 8;
            off += 8;
        }
    }
}

void MemConcreteBuffer::write_buffer(offset_t off, uint8_t* buff, int nb_bytes)
{
    for( int i = 0; i < nb_bytes; i++)
        _mem[off+i] = buff[i];
}

uint8_t* MemConcreteBuffer::raw_mem_at(offset_t off)
{
    return reinterpret_cast<uint8_t*>(_mem) + off;
}

uid_t MemConcreteBuffer::class_uid() const
{
    return serial::ClassId::MEM_CONCRETE_BUFFER;
}

void MemConcreteBuffer::dump(Serializer& s) const
{
    s << bits(_size);
    s << serial::buffer((char*)_mem, _size);
    s << bits(_endianness);
}

void MemConcreteBuffer::load(Deserializer& d)
{
    if (_mem != nullptr)
        delete [] _mem;

    d >> bits(_size);
    _mem = new uint8_t[_size];
    d >> serial::buffer((char*)_mem, _size);
    d >> bits(_endianness);
}

/* Memory abstract buffer 
   ======================
Abstract expressions are stored in a hashmap <offset : (expr, byte_num)>. 
 - offset: is the offset in the buffer (the address) 
 - expr: expr is the expression written at address addr
 - byte_num: is the number of the particular octet of 'expr' that is at 
        address addr
  For example, assuming little endian,  writing v1 = exprvar(32, "var1")
  at offset 0x100 gives:
    - <0x100: (v1, 0)>
    - <0x101: (v1, 1)>
    - <0x102: (v1, 2)>
    - <0x103: (v1, 3)>

For read operations, if the value read overlaps between two different
expressions stored in memory, the class automatically concatenates/extracts
the corresponding parts.
*/

MemAbstractBuffer::MemAbstractBuffer(Endian endian):_endianness(endian){}


Expr MemAbstractBuffer::_read_little_endian(offset_t off, unsigned int nb_bytes)
{
    int i = nb_bytes-1;
    int off_byte, low_byte; 
    Expr res = nullptr, tmp=nullptr;
    abstract_mem_t::iterator it, it2;
    while( nb_bytes > 0 )
    {
        it = _mem.find(off+nb_bytes-1); // Take next byte 
        tmp = it->second.first; // Get associated expr
        off_byte = it->second.second; // Get associated exproffset
        low_byte = off_byte;
        /* Find until where the same expression is in memory */
        i = nb_bytes-1; 
        while( i >= 0 )
        {
            it2 = _mem.find(off+i); // Get expr
            if( it2->second.first->neq(tmp) )
            {
                /* Found different expr */
                if (res == nullptr)
                {
                    res = extract(tmp, (off_byte*8)+7, low_byte*8);
                }
                else
                {
                    res = concat(res, extract(tmp, (off_byte*8)+7, low_byte*8));
                }
                nb_bytes = i+1; // Updates nb bytes to read 
                break;
            }
            low_byte = it2->second.second; // Same expr, decrememnt exproffset counter
            if( low_byte == 0)
            {
                /* Reached beginning of the memory write */
                if( res == nullptr )
                {
                    // If the size corresponds the the offset_byte, then use the whole expr
                    // Else extract lower bits 
                    res = ( tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0)); 
                }
                else
                {
                    res = concat(res,  ( tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0))); 
                }
                nb_bytes = i;
                break;
            }
            else
            {
                /* Not different expr, not beginning, continue to next */
                i--; // Go to prev offset 
            }
        }
        if( i < 0 )
        {
            /* We reached the requested address, so extract and return */
            if( res == nullptr )
            {
                res = extract(tmp, (off_byte*8)+7, low_byte*8);
            }
            else
            {
                res = concat(res, extract(tmp, (off_byte*8)+7, low_byte*8)); 
            }
            break;
        }
        /* Else just loop back and read next expression */
    }
    return res;
}

Expr MemAbstractBuffer::_read_big_endian(offset_t off, unsigned int nb_bytes)
{
    int i = nb_bytes-1;
    int off_byte, low_byte; 
    Expr res = nullptr, tmp=nullptr;
    abstract_mem_t::iterator it, it2;
    while (nb_bytes > 0)
    {
        it = _mem.find(off); // Take next byte 
        tmp = it->second.first; // Get associated expr
        off_byte = it->second.second; // Get associated exproffset
        low_byte = off_byte;
        /* Find until where the same expression is in memory */
        i = 0;
        while (i < nb_bytes)
        {
            it2 = _mem.find(off+i); // Get expr
            if (it2->second.first->neq(tmp))
            {
                /* Found different expr */
                if (res == nullptr)
                    res = extract(tmp, (off_byte*8)+7, low_byte*8);
                else
                    res = concat(res, extract(tmp, (off_byte*8)+7, low_byte*8));
                i -= 1; // Don't consume this byte
                break;
            }
            low_byte = it2->second.second; // Same expr, decrememnt exproffset counter
            if (low_byte == 0)
            {
                /* Reached beginning of the memory write */
                if (res == nullptr)
                {
                    // If the size corresponds to the offset_byte, then use the whole expr
                    // Else extract lower bits 
                    res = (tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0));
                }
                else
                {
                    res = concat(res,  (tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0))); 
                }
                break;
            }
            else
            {
                /* Not different expr, not beginning, continue to next */
                i++; // Go to next offset 
            }
        }

        // If nb_bytes wasn't reset to zero then we finished while in the middle of
        // an expression
        if (i == nb_bytes and nb_bytes != 0)
        {
            /* We reached the requested address, so extract and return */
            if( res == nullptr )
            {
                res = extract(tmp, (off_byte*8)+7, low_byte*8);
            }
            else
            {
                res = concat(res, extract(tmp, (off_byte*8)+7, low_byte*8)); 
            }
            break;
        }
        /* Else just loop back and read next expression */
        else
        {
            nb_bytes -= i+1; // Updates nb bytes to read
            off += i+1; // Update offset from where to read
        }
    }
    return res;
}

Expr MemAbstractBuffer::read(offset_t off, unsigned int nb_bytes)
{
    if (_endianness == Endian::LITTLE)
        return _read_little_endian(off, nb_bytes);
    else
        return _read_big_endian(off, nb_bytes);
}

void MemAbstractBuffer::_read_optimised_buffer(std::vector<Value>& res, offset_t off, unsigned int nb_bytes)
{
    if (_endianness != Endian::BIG)
        throw mem_exception("MemAbstractBuffer::_read_optimised_buffer(): only implemented for big endian");

    int i = 0;
    int off_byte, low_byte; 
    Expr tmp=nullptr;
    abstract_mem_t::iterator it, it2;
    while (nb_bytes > 0)
    {
        it = _mem.find(off); // Take next byte 
        tmp = it->second.first; // Get associated expr
        off_byte = it->second.second; // Get associated exproffset
        low_byte = off_byte;
        /* Find until where the same expression is in memory */
        i = 0;
        while (i < nb_bytes)
        {
            it2 = _mem.find(off+i); // Get expr
            if (it2->second.first->neq(tmp))
            {
                /* Found different expr */
                res.push_back(Value(extract(tmp, (off_byte*8)+7, low_byte*8)));
                break;
            }
            low_byte = it2->second.second; // Same expr, decrememnt exproffset counter
            if (low_byte == 0)
            {
                // If the size corresponds to the offset_byte, then use the whole expr
                // Else extract lower bits 
                Expr val = (tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0));
                res.push_back(Value(val));
                break;
            }
            else
            {
                /* Not different expr, not beginning, continue to next */
                i++; // Go to next offset 
            }
        }

        // If nb_bytes wasn't reset to zero then we finished while in the middle of
        // an expression
        if (i == nb_bytes and nb_bytes != 0)
        {
            /* We reached the requested address, so extract and return */
            res.push_back(Value(extract(tmp, (off_byte*8)+7, low_byte*8)));
            break;
        }
        /* Else just loop back and read next expression */
        else
        {
            nb_bytes -= i+1; // Updates nb bytes to read
            off += i+1; // Update offset from where to read
        }
    }
}

void MemAbstractBuffer::write(offset_t off, Expr e)
{
    for( offset_t i = 0; i < (e->size/8); i++ )
    {
        if (_endianness == Endian::LITTLE)
            _mem[off+i] = std::make_pair(e, i);
        else
            _mem[off+i] = std::make_pair(e, (e->size/8)-1-i);
    }
}

uid_t MemAbstractBuffer::class_uid() const
{
    return serial::ClassId::MEM_ABSTRACT_BUFFER;
}

void MemAbstractBuffer::dump(Serializer& s) const
{
    s << bits(_endianness);
    s << bits(_mem.size());
    for (auto const& [key, val]: _mem)
    {
        s << bits(key) // offset
          << val.first // expr
          << bits(val.second); // selected byte in expr
    }
}

void MemAbstractBuffer::load(Deserializer& d)
{
    size_t nb_elems;
    offset_t off;
    uint8_t byte;
    Expr expr;
    d >> bits(_endianness);
    _mem.clear();
    d >> bits(nb_elems);
    for (int i = 0; i < nb_elems; i++)
    {
        d >> bits(off) >> expr >> bits(byte);
        _mem[off] = std::make_pair(expr, byte); 
    }
}



MemSegment::MemSegment(addr_t s, addr_t e, const std::string& n, bool special, Endian endian):
    start(s), end(e),
    _bitmap(MemStatusBitmap(e-s+1)), 
    _concrete(MemConcreteBuffer(e-s+1, endian)),
    _abstract(MemAbstractBuffer(endian)), 
    _is_engine_special_segment(special),
    name(n),
    _endianness(endian)
{
    if(start > end){
        throw mem_exception("Cannot create segment with start address bigger than end address");
    }
}

bool MemSegment::is_engine_special_segment()
{
    return _is_engine_special_segment;
}

void MemSegment::extend_after(addr_t nb_bytes)
{
    _bitmap.extend_after(nb_bytes);
    _concrete.extend_after(nb_bytes);
    end = end + nb_bytes;
}

void MemSegment::extend_before(addr_t nb_bytes)
{
    if( nb_bytes > start )
        throw runtime_exception("MemSegment::extend_before() got too many bytes (will go beyond the 0 address)");
    
    _bitmap.extend_before(nb_bytes);
    _concrete.extend_before(nb_bytes);
    start = start - nb_bytes;
}

bool MemSegment::contains(addr_t addr)
{
    return addr >= start && addr <= end;
}

bool MemSegment::intersects_with_range(addr_t addr_min, addr_t addr_max)
{
    return  (addr_min <= start && addr_max >= start)
            || (addr_min <= end && addr_max >= end ) 
            || (addr_min >= start && addr_max <= end);
}

addr_t MemSegment::size()
{
    return end - start + 1;
}

void MemSegment::symbolic_ptr_read(Value& result, const Expr& addr, ValueSet& addr_value_set, unsigned int nb_bytes, const Expr& base)
{
    Expr res = base;
    Expr byte;
    addr_t a2;
    addr_t a = addr_value_set.min;

    // Check if value_set doesn't intersect this segment
    if ((addr_value_set.min + nb_bytes -1 > end)
        || (addr_value_set.max < start))
    {
        result = res;
        return;
    }
    
    if( a < start )
        a = start;
    
    // If base is null, put first possible read in it and increment address
    if( base == nullptr )
    {
        res = read(a, nb_bytes).as_expr();
        a++;
    }

    // Get all other possible values
    for( ; a <= addr_value_set.max and a-1+nb_bytes <= end; a += addr_value_set.stride)
    {
        /* Optimisation to detect huge areas containing only a single byte (typically zeros) */
        if( _bitmap.is_concrete(a-start))
        {
            a2 = is_identical_until(a, _concrete.read(a-start, 1)) -1; // a2 == last address containing the byte "byte"
            if (a2 >= a-1+nb_bytes)
            {
                // Identical memory region bigger than single read so
                // use interval instead
                // Same value for addr >= a
                Expr v = read(a, nb_bytes).as_expr();
                if( !(v->eq(res)) )
                {
                    // Combine with ITE only if new possible value is different than the 
                    // current one. This check is used to avoid having ITE(0x1 <= addr, 0x0, 0x0) as
                    // base expression for the symbolic read
                    res = ITE(exprcst(addr->size, a), ITECond::LE, addr, v, res);
                }
                a = a2+1-nb_bytes;
            }
            else
            {
                /* Add possible concrete value to ITE switch :) */
                res = ITE(addr, ITECond::EQ, exprcst(addr->size, a), read(a, nb_bytes).as_expr(), res);
            }
        }
        else
        {
            /* Add possible concrete value to ITE switch :) */
            res = ITE(addr, ITECond::EQ, exprcst(addr->size, a), read(a, nb_bytes).as_expr(), res);
        }
    }

    result = res;
    return;
}

Value MemSegment::read(addr_t addr, unsigned int nb_bytes)
{
    Value val;
    read(val, addr, nb_bytes);
    return val;
}

// Concatenate two values according to endianness. 
// 'first' is the value at the lower address and 'second'
// the one at the higher address
static inline void concat_endian(
    Value& res,
    const Value& first,
    const Value& second,
    Endian endian
)
{
    if (endian == Endian::LITTLE)
        res.set_concat(second, first);
    else
        res.set_concat(first, second);
}

// Extract bytes to be written according to endianness
// For big endian extract left-most bytes, for little endian
// extract right-most bytes
static inline Value extract_endian(
    const Value& val,
    int high_byte,
    int low_byte,
    Endian endian
)
{
    if (endian == Endian::LITTLE)
        return extract(val, high_byte*8-1, low_byte*8);
    else
        return extract(
            val, 
            val.size()-1-(low_byte*8), 
            val.size()-(high_byte+1)*8
        );
}

void MemSegment::read(Value& res, addr_t addr, unsigned int nb_bytes)
{
    offset_t off = addr - start;
    offset_t from = off, to, bytes_to_read;
    Value tmp1, tmp2, tmp3;
    Value n1, n2, n3, n4;

    res.set_none();

    if( addr+nb_bytes-1 > end )
    {
        throw mem_exception("MemSegment::read(): try to read beyond segment's end");
    }

    do
    {
        /* Try if concrete or symbolic */
        to = _bitmap.is_concrete_until(from, nb_bytes);
        if (to != from)
        {
            /* Concrete */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if (bytes_to_read > nb_bytes) // We don't want more that what's left to read
            { 
                bytes_to_read = nb_bytes; 
            }
            // Max bytes we can read at a time is 32...
            if (bytes_to_read > 32)
                bytes_to_read = 32;
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            if (bytes_to_read <= 8)
                tmp2.set_cst(bytes_to_read*8, _concrete.read(from, bytes_to_read));
            else
                tmp2 = _concrete.read_as_value(from, bytes_to_read);

            /* Update result */
            if (res.is_none())
                res = tmp2;
            else
                concat_endian(res, res, tmp2, _endianness);
        }
        else
        {
            to = _bitmap.is_abstract_until(from, nb_bytes);
            /* Symbolic */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if( bytes_to_read > nb_bytes ) // We don't want more that what's left to read
            {
                bytes_to_read = nb_bytes; 
            }
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            /* Read */
            tmp2 = _abstract.read(from, bytes_to_read);
            /* Update result */
            if (res.is_none())
                res = tmp2;
            else
                concat_endian(res, res, tmp2, _endianness);
        }
        from += bytes_to_read;
    } while(nb_bytes > 0);
}

void MemSegment::_read_optimised_buffer(std::vector<Value>& res, addr_t addr, unsigned int nb_bytes)
{
    offset_t off = addr - start;
    offset_t from = off, to, bytes_to_read;
    Value tmp1, tmp2, tmp3;
    Value n1, n2, n3, n4;

    if( addr+nb_bytes-1 > end )
    {
        throw mem_exception("MemSegment::read(): try to read beyond segment's end");
    }

    do
    {
        /* Try if concrete or symbolic */
        to = _bitmap.is_concrete_until(from, nb_bytes);
        if (to != from)
        {
            /* Concrete */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if (bytes_to_read > nb_bytes) // We don't want more that what's left to read
            { 
                bytes_to_read = nb_bytes; 
            }
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            // Read 1-byte concrete values
            for (int i = 0; i < bytes_to_read; i++)
                res.push_back(Value(8, _concrete.read(from+i, 1)));
        }
        else
        {
            to = _bitmap.is_abstract_until(from, nb_bytes);
            /* Symbolic */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if( bytes_to_read > nb_bytes ) // We don't want more that what's left to read
                bytes_to_read = nb_bytes; 
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            // Read optimised symbolic values
            _abstract._read_optimised_buffer(res, from, bytes_to_read);
        }
        from += bytes_to_read;
    } while(nb_bytes > 0);
}

cst_t MemSegment::concrete_snapshot(addr_t& addr, int& nb_bytes)
{
    offset_t off = addr - start;
    int bytes_to_read = 0;
    ucst_t res = 0;

    // Check if all bytes in the segment or it overlaps with the next one...
    if (addr + nb_bytes -1 > end)
        bytes_to_read = end - addr + 1;
    else
        bytes_to_read = nb_bytes;

    if (bytes_to_read > 8)
        throw runtime_exception("MemSegment::concrete_snapshot() called with wrong nb_bytes. Supports only: 1,2,3,4,5,6,7,8");
    else
        res = _concrete.read(off, bytes_to_read);

    nb_bytes -= bytes_to_read;
    addr += bytes_to_read;
    return (cst_t)res;
}


abstract_mem_chunk_t MemSegment::abstract_snapshot(addr_t addr, int nb_bytes)
{
    abstract_mem_chunk_t res;
    abstract_snapshot(addr, nb_bytes, res);
    return res; // vector has move semantics so optimised by compiler
}

std::pair<Expr, uint8_t>& MemAbstractBuffer::at(offset_t off)
{
    return _mem[off];
}

void MemAbstractBuffer::set(offset_t off, std::pair<Expr, uint8_t>& pair)
{
    _mem[off] = pair;
}

void MemSegment::abstract_snapshot(addr_t& addr, int& nb_bytes, abstract_mem_chunk_t& snap){
    offset_t off = addr - start;
    int i = 0;
    for( ; nb_bytes > 0 && start+i <= end; nb_bytes--)
    {
        if (_bitmap.is_abstract(off+i))
        {
            snap.push_back(_abstract.at(off+i));
        }
        else
        {
            snap.push_back(std::make_pair(nullptr, 0));
        }
        i++;
    }
    addr += i;
}

void MemSegment::write(addr_t addr, const Value& val, VarContext& ctx)
{
    offset_t off = addr - start;
    const Expr& e = val.expr();
    if (val.is_abstract())
    {
        if( (!e->is_concrete(ctx)) || e->is_tainted())
        {
            /* Add symbolic value */
            _abstract.write(off, e);
            /* Update the bitmap */
            _bitmap.mark_as_abstract(off, off+(e->size/8)-1);
        }
        else
        {
            // expression is actually concrete
            _bitmap.mark_as_concrete(off, off+(e->size/8)-1);
        }
    }
    else
    {
        _bitmap.mark_as_concrete(off, off+(val.size()/8)-1);
    }

    /* ALWAYS Add concrete value if possible (even if its tainted
    * in case it is code that'll be disassembled, but DON'T update
    * the bitmap */
    if (not val.is_symbolic(ctx))
    {
        const Number& concrete = val.as_number(ctx);
        _concrete.write(off, concrete, val.size()/8);
    }
}

void MemSegment::write(addr_t addr, const std::vector<Value>& buf, VarContext& ctx)
{
    offset_t off = addr-start;

    for (const Value& val : buf)
    {
        if (addr + val.size()/8 -1 > end)
            throw mem_exception("MemSegment: buffer write: nb_bytes exceeds segment");
        write(addr, val, ctx);
        addr += val.size()/8;
        off += val.size()/8;
    }
}

void MemSegment::write(addr_t addr, uint8_t* src, int nb_bytes)
{
    offset_t off = addr-start;
    if( addr + nb_bytes -1 > end)
    {
        throw mem_exception("MemSegment:: buffer write: nb_bytes exceeds segment");
    }
    _concrete.write_buffer(off, src, nb_bytes);
    _bitmap.mark_as_concrete(off, off+nb_bytes-1);
}

void MemSegment::write(addr_t addr, cst_t val, unsigned int nb_bytes)
{
    offset_t off = addr - start;
    _concrete.write(off, val, nb_bytes);
    _bitmap.mark_as_concrete(off, off+nb_bytes-1);
}

void MemSegment::write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes)
{
    // !! Doesn't update the bitmap !!, it will be updated by write_from_abstract_snapshot
    offset_t off = addr - start;
    _concrete.write(off, val, nb_bytes);
}

void MemSegment::write_from_abstract_snapshot(addr_t addr, abstract_mem_chunk_t& snap)
{
    abstract_mem_chunk_t::iterator it;
    offset_t off = addr - start, i = 0;
    for (it = snap.begin(); it != snap.end() && addr+i <= end; it++)
    {
        if( it->first == nullptr )
            _bitmap.mark_as_concrete(off+i);
        else
        {
            _abstract.set(off+i, *it);
            _bitmap.mark_as_abstract(off+i);
        }
        i++;
    }
    // If we reached end of segment, update snap to contain only the rest of the snapshot
    // Note: not very efficient but this will happen very rarely
    addr += i;
    if (i != snap.size())
    {
        snap.erase(snap.begin(), snap.begin()+i);
    }
    else
    {
        snap.clear();
    }
}

uint8_t* MemSegment::raw_mem_at(addr_t addr)
{
    offset_t off = addr - start;
    return _concrete.raw_mem_at(off);
}

addr_t MemSegment::is_abstract_until(addr_t addr1, addr_t max)
{
    addr_t adjusted_max = (max < end-start)? max: end-start;
    return start + _bitmap.is_abstract_until(addr1-start, adjusted_max);
}

addr_t MemSegment::is_concrete_until(addr_t addr1, addr_t max)
{
    addr_t adjusted_max = (max < end-addr1)? max: end-addr1;
    return start + _bitmap.is_concrete_until(addr1-start, adjusted_max);
}

// Return first address where the byte is different than "byte"
addr_t MemSegment::is_identical_until(addr_t addr, cst_t byte)
{
    addr_t max_addr = is_concrete_until(addr, end-addr+1);
    addr_t offset = _concrete.is_identical_until(addr-start, max_addr-start, (uint8_t)byte);
    return offset + start;
}


uid_t MemSegment::class_uid() const
{
    return serial::ClassId::MEM_SEGMENT;
}

void MemSegment::dump(Serializer& s) const
{
    s << _bitmap << _concrete << _abstract
      << bits(_is_engine_special_segment)
      << bits(start) << bits(end) << name
      << bits(_endianness);
}

void MemSegment::load(Deserializer& d)
{
    d >> _bitmap >> _concrete >> _abstract
      >> bits(_is_engine_special_segment)
      >> bits(start) >> bits(end) >> name
      >> bits(_endianness);
}


// Initialise static engine count
int MemEngine::_uid_cnt = 0;

MemEngine::MemEngine(
    std::shared_ptr<VarContext> varctx,
    size_t arch_bits,
    std::shared_ptr<SnapshotManager<Snapshot>> snap,
    Endian endian
):
_varctx(varctx),
symbolic_mem_engine(arch_bits, varctx, endian),
_arch_bits(arch_bits),
_snapshots(snap),
_endianness(endian)
{
    if(_varctx == nullptr)
        _varctx = std::make_shared<VarContext>(0);
    if(_snapshots == nullptr)
        _snapshots = std::make_shared<SnapshotManager<Snapshot>>();
    _uid = _uid_cnt++;
}

MemEngine::~MemEngine()
{}

void MemEngine::new_segment(addr_t start, addr_t end, mem_flag_t flags, const std::string& name, bool is_special)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;

    if(has_segment_containing(start, end))
        throw mem_exception("Trying to create a segment that overlaps with another segment");

    // Else create entire new segment
    std::shared_ptr<MemSegment> seg = std::make_shared<MemSegment>(
        start,
        end,
        name,
        is_special,
        _endianness
    );
    // Find where to insert new segment
    // TODO: std::lower_bound won't f**** compile and I can't figure out why
    for (it = _segments.begin(); it != _segments.end(); it++)
    {
        if((*it)->start > seg->start)
            break;
    }
    _segments.insert(it, seg);
    page_manager.set_flags(start, end, flags);


    if (_snapshots->active())
    {
        _snapshots->back().add_created_segment(start);
    }
}

void MemEngine::map(addr_t start, addr_t end, mem_flag_t mflags, const std::string& map_name)
{
    addr_t prev_end = 0;
    std::vector<std::tuple<addr_t, addr_t, mem_flag_t>> to_create;

    if (start > end)
        throw mem_exception("MemEngine::map(): 'start' must be lower than 'end'");

    // Adjust map on the page size
    addr_t page_size = page_manager.page_size();
    if (end+1 % page_size != 0)
        end += page_size - (end % page_size) -1;
    if (start % page_size != 0)
        start -= (start % page_size);

    if (
        segments().empty()
        or (segments().front()->start > end)
        or (segments().back()->end < start)
    )
    {
        to_create.push_back(std::make_tuple(start, end, mflags));
    }
    else
    {
        for (auto& seg : segments())
        {
            // Check if there is a space between both segments
            if(prev_end+1 < seg->start)
            {
                // Check if space between segments are contained in the requested mapping
                if (start <= prev_end+1 && end >= seg->start-1)
                    // Space contained in mapping, fill it completely
                    to_create.push_back(std::make_tuple(prev_end+1, seg->start-1, mflags));
                else if (start >= prev_end+1 && end <= seg->start-1)
                {
                    // Space contains mapping
                    to_create.push_back(std::make_tuple(start, end, mflags));
                }
                else if( start <= prev_end+1 && end >= prev_end+1)
                    // Overlap low part of space between segments
                    to_create.push_back(std::make_tuple(prev_end+1, end, mflags));
                else if( start <= seg->start-1 && end >= seg->start-1)
                    // Overlap high part of space between segments
                    to_create.push_back(std::make_tuple(start, seg->start-1, mflags));
                //else
                    // No overlap at all, do nothing

            }
            prev_end = seg->end;
            if (seg->start > end)
                break;
        }
        // When it overlaps the last segment
        if (end > prev_end)
            to_create.push_back(std::make_tuple(prev_end+1, end, mflags));
    }

    for (auto& t : to_create)
    {
        new_segment(std::get<0>(t), std::get<1>(t), std::get<2>(t), map_name);
    }

    // Change memory mapping flags
    page_manager.set_flags(start, end, mflags);
    
    // Update mappings 
    mappings.map(MemMap(start, end, mflags, map_name));
}

addr_t MemEngine::allocate(
    addr_t init_base, addr_t size, addr_t align,
    mem_flag_t flags, const std::string& name
)
{
    addr_t base = init_base;
    addr_t max_addr = 0xffffffffffffffff >> ((_arch_bits-64)*-1);

    // Adjust size to alignment
    if( size % align != 0 )
        size += align - (size % align);

    while (base <= max_addr-size+1)
    {
        if (mappings.is_free(base, base+size-1))
        {
            map(base, base+size-1, flags, name);
            return base;
        }
        base += align;
    }
    throw mem_exception("MemEngine::allocate(): Failed to allocate requested map");
}

void MemEngine::unmap(addr_t start, addr_t end)
{
    if (start > end)
        throw mem_exception("MemEngine::unmap(): 'start' must be lower than 'end'");

    // Adjust map on the page size
    addr_t page_size = page_manager.page_size();
    if (end % page_size != 0)
        end += page_size - (end % page_size);
    if (start % page_size != 0)
        start -= (start % page_size);

    page_manager.set_flags(start, end, mem_flag_none);
    mappings.unmap(start, end);
}

std::shared_ptr<MemSegment> MemEngine::get_segment_containing(addr_t addr)
{
    for (auto& it : _segments)
    {
        if (it->start <= addr && it->end >= addr)
            return it;
    }
    return nullptr;
}

bool MemEngine::is_free(addr_t start, addr_t end)
{
    return mappings.is_free(start, end);
}

addr_t MemEngine::allocate_segment(
    addr_t init_base, addr_t size, addr_t align,
    mem_flag_t flags, const std::string& name, bool is_special)
{
    addr_t base = init_base;
    addr_t max_addr = 0xffffffffffffffff >> ((_arch_bits-64)*-1);

    // Adjust size to alignment
    if( size % align != 0 )
        size += align - (size % align);

    auto it = _segments.begin();
    do
    {
        if (not has_segment_containing(base, base+size-1) and base-1 < max_addr)
        {
            new_segment(base, base+size-1, flags, name, is_special);
            return base;
        }
        if (it == _segments.end())
            break;
        else
        {
            base = (*it)->end;
            // Adjust base to alignment
            if (base%align != 0)
                base = base - (base % align) + align;
            it++;
        }
    } while (base+size-1 < max_addr and it != _segments.end());

    throw mem_exception("Couldn't allocate requested memory segment");

}

void MemEngine::delete_segment(addr_t start)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;
    
    for( it = _segments.begin(); it != _segments.end(); it++)
        if( (*it)->start == start )
            break;

    if( it == _segments.end() )
    {
        throw runtime_exception(Fmt()
            << "MemEngine::delete_segment(): no segment starts at 0x"
            << std::hex << start
            >> Fmt::to_str
        );
    }
    else
    {
        _segments.erase(it);
    }
}

std::list<std::shared_ptr<MemSegment>>& MemEngine::segments()
{
    return _segments;
}

std::shared_ptr<MemSegment> MemEngine::get_segment_by_name(
    const std::string& name
)
{
    auto it = std::find_if(
        _segments.begin(),
        _segments.end(),
        [&name](auto seg){return seg->name == name;}
    );
    if (it != _segments.end())
        return *it;
    else
        return nullptr;
}

bool MemEngine::has_segment_containing(addr_t start, addr_t end)
{
    for( auto& segment : _segments )
    {
        if( segment->start <= end && segment->end >= start )
            return true;
    }
    return false;
}

Value MemEngine::read(const Value& addr, unsigned int nb_bytes, bool ignore_flags)
{
    Value res;
    if( ! addr.is_concrete(*_varctx))
    {
        Settings tmp_settings;
        symbolic_ptr_read(res, addr.expr(), addr.expr()->value_set(), nb_bytes, tmp_settings);
    }
    else
    {
        read(res, addr.as_uint(*_varctx), nb_bytes, nullptr, ignore_flags);
    }
    return res;
}


std::string MemEngine::read_string(const Value& addr, unsigned int len)
{
    // Do the read
    if( addr.is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::read_string(): doesn't support symbolic expression as address");
    }
    else
    {
        return read_string(addr.as_uint(*_varctx), len);
    }
}

// force_concrete_read makes the read concrete even though the memory area has been affected 
// by symbolic pointers write
void MemEngine::read(Value& res, addr_t addr, unsigned int nb_bytes, mem_alert_t* alert, bool force_concrete_read)
{
    Value tmp;
    unsigned int save_nb_bytes = nb_bytes;
    addr_t save_addr = addr;

    res.set_none();

    if( alert != nullptr )
    {
        *alert = 0; // Reset alert
    }

    // Check if the read is within an area where symbolic writes occured
    if(
        !force_concrete_read
        and symbolic_mem_engine.contains_symbolic_write(addr, addr-1+nb_bytes)
    )
    {
        // base_expr is the value if we read from 'normal' memory and
        // assume it hasn't been modified by symbolic writes
        Value base_expr;
        read(base_expr, addr, nb_bytes, alert, true);
        res = symbolic_mem_engine.concrete_ptr_read(
                exprcst(_arch_bits, addr),
                nb_bytes,
                base_expr.as_expr()
              );
        return;
    }

    // Else do a read in the "sure" memory
    // Find the segment we read from
    for (auto& segment : _segments)
    {
        if (segment->intersects_with_range(addr, addr+nb_bytes-1))
        {
            // Check flags
            if( !page_manager.has_flags(addr, maat::mem_flag_r))
            {
                throw mem_exception(Fmt() << "Reading at address 0x" << std::hex << addr << " in segment that doesn't have R flag set" << std::dec >> Fmt::to_str);
            }

            // Check if read exceeds segment
            if( addr + nb_bytes-1 > segment->end)
                // Read overlaps two segments
                segment->read(tmp, addr, segment->end - addr+1);
            else
                segment->read(tmp, addr, nb_bytes);

            // Assign read to result
            if (res.is_none())
                res = tmp;
            else
                concat_endian(res, res, tmp, _endianness);

            nb_bytes -= tmp.size()/8;
            addr += tmp.size()/8;
            if( nb_bytes == 0 )
                return;
        }
    }

    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to read " << std::dec << save_nb_bytes
        << " bytes at address 0x" 
        << std::hex << save_addr << " causing access to non-mapped memory"
        >> Fmt::to_str
    );
}

std::vector<Value> MemEngine::_read_optimised_buffer(addr_t addr, size_t nb_bytes)
{
    std::vector<Value> res;
    size_t save_nb_bytes = nb_bytes;
    // Check if the read is within an area where symbolic writes occured
    if(symbolic_mem_engine.contains_symbolic_write(addr, addr-1+nb_bytes))
    {
       // Not possible to optimise so call regular function
       return read_buffer(addr, nb_bytes, 1);
    }

    // Else do a read in the "sure" memory
    // Find the segment we read from
    for (auto& segment : _segments)
    {
        if (segment->intersects_with_range(addr, addr+nb_bytes-1))
        {
            // Check flags
            if( !page_manager.has_flags(addr, maat::mem_flag_r))
            {
                throw mem_exception(Fmt() << "Reading at address 0x" << std::hex << addr << " in segment that doesn't have R flag set" << std::dec >> Fmt::to_str);
            }

            // Check if read exceeds segment
            if( addr + nb_bytes-1 > segment->end)
            {
                // Read overlaps two segments
                size_t tmp_nb_bytes = segment->end - addr+1;
                segment->_read_optimised_buffer(res, addr, tmp_nb_bytes);
                addr += tmp_nb_bytes;
                nb_bytes -= tmp_nb_bytes;
            }
            else
            {
                segment->_read_optimised_buffer(res, addr, nb_bytes);
                nb_bytes = 0;
            }

            if (nb_bytes == 0)
                return res;
        }
    }

    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to read " << std::dec << save_nb_bytes
        << " bytes at address 0x" 
        << std::hex << addr << " causing access to non-mapped memory"
        >> Fmt::to_str
    );
}

// Not performant at all, legacy method! 
Expr MemEngine::read(Expr addr, unsigned int nb_bytes)
{
    Value addr_val = addr;
    return read(addr_val, nb_bytes).as_expr();
}

// Legacy method
Value MemEngine::read(addr_t addr, unsigned int nb_bytes, mem_alert_t* alert, bool force_concrete_read)
{
    Value res;
    read(res, addr, nb_bytes, alert, force_concrete_read);
    return res;
}


ValueSet MemEngine::limit_symptr_range(Expr addr, const ValueSet& range, const Settings& settings)
{
    addr_t tmp_addr_min, tmp_addr_max;
    ValueSet res(range.size);

    // Adjust the value set min
    tmp_addr_min = addr->as_number(*_varctx).get_ucst() - settings.symptr_max_range/2;
    tmp_addr_min -= tmp_addr_min % range.stride; // Adjust lower bound on stride
    if (tmp_addr_min < range.min)
    {
        tmp_addr_min = range.min; // We have to stay in the original range...
    }
    // Then max
    tmp_addr_max = settings.symptr_max_range - (settings.symptr_max_range % addr->value_set().stride); // Adjuste range on stride
    tmp_addr_max += tmp_addr_min;
    if (tmp_addr_max > range.max)
    {
        // We need to slide the limited range 'down' so that the upper bound
        // stays in the original range
        tmp_addr_min = tmp_addr_max - settings.symptr_max_range;
        tmp_addr_min -= tmp_addr_min % range.stride; // Adjust lower bound on stride
    }
    res.set(tmp_addr_min, tmp_addr_max, range.stride);
    return res;
}


void MemEngine::symbolic_ptr_read(Value& res, Expr addr, const ValueSet& range, unsigned int nb_bytes, const Settings& settings)
{
    ValueSet addr_value_set(range.size);
    res.set_none();

    // Check if we have to limit the pointer range
    if(
        settings.symptr_limit_range and
        addr_value_set.range() > settings.symptr_max_range and 
        addr->is_concolic(*_varctx)
    )
    {
        addr_value_set = limit_symptr_range(addr, range, settings);
    }
    else
    {
        addr_value_set = range;
    }

    // Get the base value if read over concrete writes
    // We consider each possible memory segment
    for( auto& segment: _segments)
    {
        if( segment->is_engine_special_segment())
            continue; // We don't read in special segments
        else if (segment->start >  addr_value_set.max)
            break;
        else if (segment->end < addr_value_set.min)
            continue;
        else{
            segment->symbolic_ptr_read(res, addr, addr_value_set, nb_bytes, nullptr);
        }
    }

    if( res.is_none() )
        throw runtime_exception("Got NULL as base value for symbolic pointer read!");

    if( symbolic_mem_engine.contains_symbolic_write(addr_value_set.min, addr_value_set.max+nb_bytes-1) )
    {
        res = symbolic_mem_engine.symbolic_ptr_read(addr, addr_value_set, nb_bytes, res.as_expr());
    }

    // Record symbolic read in statistics
    MaatStats::instance().add_symptr_read(addr_value_set.range());
}

std::vector<Value> MemEngine::read_buffer(addr_t addr, unsigned int nb_elems, unsigned int elem_size)
{
    Value addr_val(_arch_bits, addr);
    return read_buffer(addr_val, nb_elems, elem_size);
}

std::vector<Value> MemEngine::read_buffer(const Value& addr, unsigned int nb_elems, unsigned int elem_size)
{
    std::vector<Value> res;
    read_buffer(res, addr, nb_elems, elem_size);
    return res;
}

void MemEngine::read_buffer(std::vector<Value>& buffer, const Value& addr, unsigned int nb_elems, unsigned int elem_size)
{
    if (elem_size > 16)
    {
        throw mem_exception(
            "MemEngine::read_buffer(): Buffer element size should not exceed 16 bytes"
        );
    }
    for (int i = 0; i < nb_elems; i++)
    {
        buffer.push_back(read(addr+(i*elem_size), elem_size));
    }
}

void MemEngine::read_buffer(std::vector<Value>& buffer, addr_t addr, unsigned int nb_elems, unsigned int elem_size)
{
    Value addr_val(_arch_bits, addr);
    return read_buffer(buffer, addr_val, nb_elems, elem_size);
}

/* Read a string of size len 
 * If len == 0 then stop at first null byte (C String) */
std::string MemEngine::read_string(addr_t addr, unsigned int len)
{
    std::string res;
    Value val;
    char c;

    for( int i = 0; len == 0 || i < len; i++)
    {
        read(val, addr+i, 1);
        if( val.is_symbolic(*_varctx))
        {
            throw mem_exception("Got purely symbolic char while reading concrete string");
        }
        c = (char)(val.as_uint(*_varctx));
        if( c == 0 && len == 0 )
        {
            return res;
        }
        res += c;
    }
    return res;
}

void MemEngine::write(const Value& addr, const Value& val, bool ignore_flags)
{
    if (addr.is_concrete(*_varctx))
    {
        return write(addr.as_uint(*_varctx), val, nullptr, false, ignore_flags);
    }
    else
    {
        Settings settings; // Dummy settings because symbolic_ptr_write needs it
        return symbolic_ptr_write(addr.expr(), addr.expr()->value_set(), val, settings);
    }
}

void MemEngine::write(addr_t addr, const Value& val, mem_alert_t* alert, bool called_by_engine, bool ignore_flags)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;
    bool finish = false;
    Value tmp_val = val;
    addr_t tmp_addr = addr;
    int bytes_to_write = 0;

    if( alert != nullptr )
    {
        *alert = maat::mem_alert_none; // Reset alert
    }

    /* Find the segment we write to */
    for( it = _segments.begin(); it != _segments.end() && !finish; it++)
    {
        if( (*it)->intersects_with_range(tmp_addr, tmp_addr+(tmp_val.size()/8)-1) )
        {
            // Check flags
            if( 
                not ignore_flags
                and not page_manager.has_flags(tmp_addr, maat::mem_flag_w)
            )
            {
                throw mem_exception(Fmt()
                    << "Writing at address 0x" << std::hex << tmp_addr
                    << " in page that doesn't have W flag set" << std::dec
                    >> Fmt::to_str
                );
            }

            // If executable segment, set alert
            if( page_manager.was_once_executable(tmp_addr))
            {
                if( alert != nullptr )
                {
                    *alert |= maat::mem_alert_x_overwrite;
                }
                // If not called by engine, put him the ovewritten X addresses
                // for it to handle them later 
                if (!called_by_engine)
                {
                    
                    pending_x_mem_overwrites.push_back(
                        std::make_pair(
                            tmp_addr,
                            tmp_addr-1+(tmp_val.size()/8)
                        )
                    );
                }

            }
            /* Perform write*/
            if (tmp_addr + tmp_val.size()/8 -1 > (*it)->end)
            {
                bytes_to_write = (*it)->end-tmp_addr+1;
                // Record write for snapshots
                record_mem_write(tmp_addr, bytes_to_write);
                // Write
                Value extracted;
                if (_endianness == Endian::LITTLE)
                    extracted = extract(tmp_val, (bytes_to_write*8)-1, 0);
                else
                    extracted = extract(
                        tmp_val,
                        tmp_val.size()-1,
                        tmp_val.size()-(bytes_to_write*8)
                    );
                (*it)->write(tmp_addr, extracted, *_varctx);
                tmp_addr += bytes_to_write;
                if (_endianness == Endian::LITTLE)
                    tmp_val.set_extract(tmp_val, tmp_val.size()-1, bytes_to_write*8);
                else
                    tmp_val.set_extract(tmp_val, tmp_val.size()-1-(bytes_to_write*8), 0);
            }
            else
            {
                bytes_to_write = tmp_val.size()/8;
                // Record write for snapshots
                record_mem_write(tmp_addr, bytes_to_write);
                // Write
                (*it)->write(tmp_addr, tmp_val, *_varctx);
                finish = true;
            }
        }
    }
    
    if (finish)
    {
        // Success
        // Record write in symbolic memory engine if needed
        symbolic_mem_engine.concrete_ptr_write(exprcst(_arch_bits,addr), val);
        return;
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to write " << std::dec << val.size()/8
        << " bytes at address 0x" << std::hex << addr
        << " causes access to non-mapped memory"
        >> Fmt::to_str);
}

void MemEngine::symbolic_ptr_write(Expr addr, const ValueSet& range, const Value& val, const Settings& settings, mem_alert_t* alert, bool _called_by_sym)
{
    addr_t addr_min, addr_max;

    // Check if we have to limit the pointer range
    if( 
        settings.symptr_limit_range and
        (range.max - range.min) > settings.symptr_max_range and
        addr->is_concolic(*_varctx)
    )
    {
        ValueSet tmp = limit_symptr_range(addr, range, settings);
        addr_min = tmp.min;
        addr_max = tmp.max;
    }
    else
    {
        addr_min = range.min;
        addr_max = range.max;
    }

    if( alert != nullptr )
    {
        *alert = 0; // Reset alert
    }

    /* Check if possible write on non-mapped memory */
    bool set_alert = false;
    addr_t tmp_addr_min = addr_min;

    for (auto& segment : _segments)
    {
        if( segment->start > tmp_addr_min )
        {
            set_alert = true;
            break;
        }
        else if( segment->end >= addr_max )
            break; // Value set contained in segments, don't set alert
        else
            tmp_addr_min = segment->end + 1;
    }

    if( set_alert )
    {
        *alert |= maat::mem_alert_possible_out_of_bounds;
    }

    // Record the symbolic write
    symbolic_mem_engine.symbolic_ptr_write(addr, val, addr_min, addr_max);
}

// Convenience function, shouldn't be used by the engine!!!
void MemEngine::write(const Value& addr, cst_t val, int nb_bytes, bool ignore_flags)
{
    if (addr.is_concrete(*_varctx))
    {
        return write(addr.as_uint(*_varctx), val, nb_bytes, ignore_flags);
    }
    else
    {
        Settings settings; // Dummy settings because symbolic_ptr_write needs it
        return symbolic_ptr_write(addr.expr(), addr.expr()->value_set(), exprcst(nb_bytes*8, val), settings);
    }
}

void MemEngine::write(addr_t addr, Expr e)
{
    Value val = e;
    return write(addr, val);
}

void MemEngine::write(
    addr_t addr, cst_t val, int nb_bytes, bool ignore_mem_permissions
)
{
    Value as_value = Number(nb_bytes*8, val);
    return write(addr, as_value, nullptr, false, ignore_mem_permissions);
}

void MemEngine::write_buffer(const Value& addr, uint8_t* src, int nb_bytes, bool ignore_flags)
{
    if( addr.is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::write_buffer(): doesn't support symbolic expressions as address");
    }
    else
    {
        return write_buffer(addr.as_uint(*_varctx), src, nb_bytes, ignore_flags);
    }
}

void MemEngine::write_buffer(const Value& addr, const std::vector<Value>& src, bool ignore_flags){
    if( addr.is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::write_buffer(): doesn't support symbolic expressions as address");
    }
    else
    {
        return write_buffer(addr.as_uint(*_varctx), src, ignore_flags);
    }
}

void MemEngine::write_buffer(addr_t addr, uint8_t* src, int nb_bytes, bool ignore_flags)
{
    if( nb_bytes == 0 )
        return;

    /* If breakpoints enabled record the write */
    record_mem_write(addr, nb_bytes);

    for (auto& segment : _segments)
    {
        if( segment->contains(addr) )
        {
            if( 
                not ignore_flags
                and not page_manager.has_flags(addr, maat::mem_flag_w)
            )
            {
                throw mem_exception(Fmt() << "Writing at address 0x" << std::hex << addr << " in page that doesn't have W flag set" << std::dec >> Fmt::to_str);
            }

            // If buffer exceeds segment size, adjust the number of bytes to write
            int tmp_nb_bytes = nb_bytes;
            if (addr + nb_bytes > segment->end)
                tmp_nb_bytes = segment->end - addr+1;

            // FIXME: should check for the whole range, not just 'addr'
            if( page_manager.was_once_executable(addr))
            {
                pending_x_mem_overwrites.push_back(
                    std::make_pair(
                        addr,
                        addr-1+tmp_nb_bytes
                    )
                );
            }
            segment->write(addr, src, tmp_nb_bytes);
            
            // If the buffer exceeded segment size, update buffer and #bytes
            // and go back in the loop
            if (tmp_nb_bytes != nb_bytes)
            {
                nb_bytes -= tmp_nb_bytes;
                addr += tmp_nb_bytes;
                src += tmp_nb_bytes;
            }
            // Else stop (whole buffer written)
            else
                return;
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to write at address 0x" << std::hex << addr
        << std::dec << " not mapped in memory"
        >> Fmt::to_str
    );
}

void MemEngine::write_buffer(addr_t addr, const std::vector<Value>& buf, bool ignore_flags)
{
    int nb_bytes = 0;
    std::vector<Value> tmp_buf;
    std::vector<Value> next_buf;
    std::vector<Value> tmp_buf2;

    if (buf.empty())
        return;

    for (const Value& val : buf)
        nb_bytes += val.size()/8;

    // Record write for snapshots
    record_mem_write(addr, nb_bytes);

    for( auto& segment : _segments)
    {
        if( segment->contains(addr) )
        {
            if(
                not ignore_flags
                and not page_manager.has_flags(addr, maat::mem_flag_w)
            )
            {
                throw mem_exception(Fmt() << "Writing at address 0x" << std::hex << addr << " in page that doesn't have W flag set" << std::dec >> Fmt::to_str);
            }
            if( page_manager.was_once_executable(addr))
            {
                pending_x_mem_overwrites.push_back(
                    std::make_pair(
                        addr,
                        addr-1+nb_bytes
                    )
                );
            }

            // If buffer exceeds segment size, adjust the number of bytes to write
            int tmp_nb_bytes = nb_bytes;
            tmp_buf.clear();
            next_buf.clear();
            if (tmp_buf2.empty())
                tmp_buf2 = buf; // copy buf
            if (addr + nb_bytes > segment->end)
            {
                tmp_nb_bytes = segment->end - addr+1;
                int tmp_size = 0;
                // Truncate the buffer to write
                for (const auto& val : tmp_buf2)
                {
                    if (tmp_size + val.size()/8 <= tmp_nb_bytes)
                    {
                        tmp_buf.push_back(val);
                        tmp_size += val.size()/8;
                    }
                    else if (tmp_size < tmp_nb_bytes)
                    {
                        tmp_buf.push_back(
                            extract_endian(val, tmp_nb_bytes-tmp_size-1, 0, _endianness)
                        );
                        next_buf.push_back(
                            extract_endian(
                                val, val.size()/8 -1, tmp_nb_bytes-tmp_size, _endianness
                            )
                        );
                        tmp_size = tmp_nb_bytes;
                    }
                    else
                    {
                        next_buf.push_back(val);
                        tmp_size += val.size()/8;
                    }
                }
                // Write partial buffer
                segment->write(addr, tmp_buf, *_varctx);
                // Update data to write
                nb_bytes -= tmp_nb_bytes;
                addr += tmp_nb_bytes;
                tmp_buf2 = std::move(next_buf); // OK to move because we clear() we using it
            }
            // Else if buffer fits in the segment, just write everyting
            else
            {
                segment->write(addr, tmp_buf2.empty()? buf : tmp_buf2, *_varctx);
                return;
            }
        }
    }

    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to write at address 0x" << std::hex << addr
        << std::dec << " not mapped int memory"
        >> Fmt::to_str
    );
}

std::string MemEngine::make_symbolic(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& name)
{
    std::stringstream ss;
    std::vector<std::string> res;

    if( nb_elems == 0 )
        return "";

    if( _varctx == nullptr )
    {
        throw runtime_exception("MemEngine::make_symbolic(): called with null context!");
    }

    else if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 )
    {
        throw mem_exception(Fmt()
            << "MemEngine::make_symbolic(): called with unsupported elem_size: "
            << elem_size
            >> Fmt::to_str
        );
    }

    std::string new_name = _varctx->new_name_from(name);
    _varctx->set(new_name, -1); // Just set to say that this buffer name is taken

    for( unsigned int i = 0; i < nb_elems; i++)
    {
        ss.str(""); ss.clear();
        ss << new_name << "_" << std::dec << i;
        write(addr + i*elem_size, exprvar(elem_size*8, ss.str()));
    }
    return new_name;
}

std::string MemEngine::make_concolic(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& name)
{
    std::stringstream ss;
    std::vector<std::string> res;
    Value prev_expr;
    Value addr_val(_arch_bits, addr);

    if( nb_elems == 0 )
        return "";

    if( _varctx == nullptr )
    {
        throw runtime_exception("MemEngine::make_concolic(): called with null context!");
    }
    
    if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 )
    {
        throw mem_exception(Fmt()
            << "MemEngine::make_concolic(): called with unsupported elem_size: "
            << elem_size
            >> Fmt::to_str
        );
    }

    std::string new_name = _varctx->new_name_from(name);

    for( unsigned int i = 0; i < nb_elems; i++)
    {
        ss.str(""); ss.clear();
        ss << new_name << "_" << std::dec << i;
        prev_expr = read(addr_val + i*elem_size, elem_size);
        if (prev_expr.is_symbolic(*_varctx))
        {
            throw mem_exception("MemEngine::make_concolic(): can not be called on memory region that contains full symbolic expressions");
        }
        _varctx->set(
            ss.str(), 
            Number(prev_expr.size(), prev_expr.as_uint(*_varctx))
        );
        write(addr_val + i*elem_size, exprvar(elem_size*8, ss.str()));
    }
    return new_name;
}


std::string MemEngine::make_tainted(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& name){
    if( name.empty())
    {
        make_tainted_no_var(addr, nb_elems, elem_size);
        return "";
    }
    else
    {
        return make_tainted_var(addr, nb_elems, elem_size, name);
    }
}

void MemEngine::make_tainted_no_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size)
{
    Expr e;
    std::vector<std::string> res;
    Value addr_val(_arch_bits, addr);

    if( _varctx == nullptr )
    {
        throw runtime_exception("MemEngine::_make_tainted_no_var(): called with _varctx == NULL!");
    }

    if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 )
    {
        throw mem_exception(Fmt()
            << "MemEngine::_make_tainted_no_var(): called with unsupported elem_size: "
            << elem_size
            >> Fmt::to_str
        );
    }
    for( unsigned int i = 0; i < nb_elems; i++)
    {
        e = read(addr_val + i*elem_size, elem_size).as_expr();
        e->make_tainted();
        write(addr_val + i*elem_size, e);
    }
}

std::string MemEngine::make_tainted_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& name)
{
    Expr e;
    std::stringstream ss;
    std::vector<std::string> res;
    Value addr_val(_arch_bits, addr);

    if( _varctx == nullptr )
    {
        throw runtime_exception("MemEngine::_make_tainted_var(): called with _varctx == NULL!");
    }

    if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 )
    {
        throw mem_exception(Fmt()
            << "MemEngine::_make_tainted_var(): called with unsupported elem_size: "
            << elem_size
            >> Fmt::to_str
        );
    }

    std::string new_name = _varctx->new_name_from(name);
    _varctx->set(new_name, -1); // Just set to say that this buffer name is taken

    for( unsigned int i = 0; i < nb_elems; i++)
    {
        ss.str(""); ss.clear();
        ss << new_name << "_" << std::dec << i;
        e = read(addr_val + i*elem_size, elem_size).as_expr();
        _varctx->set(ss.str(), e->as_int(*_varctx)); // Save the concrete value
        write(addr_val + i*elem_size, exprvar(elem_size*8, ss.str(), Taint::TAINTED)); // Write the new exprvar
    }

    return new_name;
}

cst_t MemEngine::concrete_snapshot(addr_t addr, int nb_bytes)
{
    ucst_t res = 0;
    addr_t tmp_addr = addr;
    int i = 0;
    for (auto& segment : _segments)
    {
        if( segment->contains(tmp_addr) )
        {
            ucst_t tmp = segment->concrete_snapshot(tmp_addr, nb_bytes); // updates addr and nb_bytes
            if (_endianness == Endian::LITTLE)
                res += tmp << ((ucst_t)i*8);
            else
                res |= tmp << ((nb_bytes-i)*8);
            i = tmp_addr - addr;
        }
        if (nb_bytes == 0)
        {
            return (cst_t)res;
        }
    }

    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(Fmt()
        << "Trying to concrete-snapshot address 0x" << std::hex << addr
        << " not mapped int memory"
        >> Fmt::to_str
    );

}

abstract_mem_chunk_t MemEngine::abstract_snapshot(addr_t addr, int nb_bytes)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;
    abstract_mem_chunk_t snap = abstract_mem_chunk_t();
    for( it = _segments.begin(); it != _segments.end() && nb_bytes > 0; it++)
    {
        if( (*it)->intersects_with_range(addr, addr+nb_bytes-1) )
        {
            (*it)->abstract_snapshot(addr, nb_bytes, snap); // Updates addr, nb_bytes, and snap
        }
    }
    if( nb_bytes == 0 )
    {
        return snap;
    }
    else
    {
        /* If addr isn't in any segment, throw exception */
        throw runtime_exception(Fmt()
            << "Trying to symbolic-snapshot address " << std::hex 
            << addr << " not mapped int memory"
            >> Fmt::to_str
        );
    }
}

void MemEngine::write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes, mem_alert_t& alert)
{
    alert = maat::mem_alert_none;
    int bytes_to_write = 0;
    for (auto& segment : _segments)
    {
        if (segment->contains(addr))
        {
            // Check if contains all bytes or just a few
            if (addr + nb_bytes -1 > segment->end)
                bytes_to_write = segment->end - addr + 1;
            else
                bytes_to_write = nb_bytes;

            // Write
            if (page_manager.was_once_executable(addr))
                alert |= maat::mem_alert_x_overwrite;
            

            if (_endianness == Endian::LITTLE)
            {
                segment->write_from_concrete_snapshot(addr, val, bytes_to_write);
                val = val >> (bytes_to_write*8);
            }
            else
            {
                segment->write_from_concrete_snapshot(
                    addr,
                    val >> (nb_bytes-bytes_to_write),
                    bytes_to_write
                );
                // No need to update value for big endian
            }

            nb_bytes -= bytes_to_write;
            if (nb_bytes == 0)
                return;
        }
    }

    // If address is not in any segment, then the segment was deleted by restoring
    // the snapshot and we don't care to write back its contents
    return;
}


void MemEngine::write_from_abstract_snapshot(addr_t addr, abstract_mem_chunk_t& snap, mem_alert_t& alert)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;
    alert = maat::mem_alert_none;
    for( it = _segments.begin(); it != _segments.end() && !snap.empty(); it++)
    {
        if( (*it)->intersects_with_range(addr, addr-1+snap.size()) )
        {
            if( page_manager.was_once_executable(addr))
            {
                alert |= maat::mem_alert_x_overwrite;
            }
            (*it)->write_from_abstract_snapshot(addr, snap); // Updates addr and snap
        }
    }

    // If address is not in any segment, then the segment was deleted by restoring
    // the snapshot and we don't care to write back its contents
    return;
}

uint8_t* MemEngine::raw_mem_at(addr_t addr)
{
    for (auto& segment : _segments)
    {
        if( segment->contains(addr) ){
            return segment->raw_mem_at(addr);
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to get raw pointer of address 0x"
        << std::hex << addr << " not mapped in memory"
        >> Fmt::to_str
    );
}

void MemEngine::check_status(addr_t start, addr_t end, bool& is_symbolic, bool& is_tainted)
{
    if( start > end )
        throw runtime_exception("MemEngine::check_mem_status(): got start bigger than end");

    is_symbolic = false;
    is_tainted = false;
    Value val;
    addr_t start_sym = start;
    /* Find the segment */
    for (auto& segment : _segments)
    {
        if( segment->contains(start) )
        {
            if( (start_sym = segment->is_concrete_until(start, end)) < end+1 )
            {
                // If not full concrete check the not concrete bytes
                while( start_sym <= end )
                {
                    read(val, start_sym, 1);
                    if( val.as_expr()->is_tainted() )
                        is_tainted = true;
                    if( val.is_symbolic(*_varctx))
                    {
                        is_symbolic = true;
                        return; // Break as soon as symbolic code detected
                    }
                    start_sym++;
                }
            }
            return; 
        }
    }
}

std::list<MemEngine::mem_access_t>& MemEngine::_get_pending_x_mem_overwrites()
{
    return pending_x_mem_overwrites;
}

void MemEngine::_clear_pending_x_mem_overwrites()
{
    pending_x_mem_overwrites.clear();
}

std::ostream& operator<<(std::ostream& os, MemEngine& mem)
{
    static unsigned int addr_w = 20;

    os << mem.mappings << "\n" << mem.page_manager << "\n";

    if (
        std::find_if(
            mem._segments.begin(),
            mem._segments.end(),
            [](auto& seg){return seg->is_engine_special_segment();}
        ) != mem._segments.end())
    {
        // Print special segments
        os << std::endl << "Special segments: " << std::endl;
        os << std::endl << std::left << std::setw(addr_w) << "Start" << std::left << std::setw(addr_w) << "End" 
        << std::left << std::setw(8) << "Name" << std::endl;
        os << std::left << std::setw(addr_w) << "-----" << std::left << std::setw(addr_w) << "---" 
        << std::left << std::setw(8) << "----" << std::endl;
        for( auto& segment : mem._segments )
        {
            if (not segment->is_engine_special_segment())
                continue;
            os << std::hex << "0x" << std::left << std::setw(addr_w-2) << segment->start << "0x" << std::left << std::setw(addr_w-2) << segment->end;
            if( !segment->name.empty() )
                os << segment->name;
            os << std::endl;
        }
    }

    return os;
}

void MemEngine::record_mem_write(addr_t addr, int nb_bytes)
{
    size_t bytes_to_write;
 
    /* If snapshots enabled record the write */
    if (_snapshots->active())
    {
        // If we just created a segment and write to it, we don't care about
        // snapshoting its content because it will be deleted when rewinding the
        // last snapshot anyway. It'll be costly to check the segment we're 
        // snapshoting every time, but for big memory writes (like mmaping a file, etc)
        // it's worth doing
        if (nb_bytes > 256)
        {
            for (addr_t segment_start : _snapshots->back().created_segments)
            {
                std::shared_ptr<MemSegment> segment = get_segment_containing(segment_start);
                if (segment == nullptr)
                    throw mem_exception("MemEngine::record_mem_write(): couldn't find created segment!");
                if (segment->contains(addr))
                    // Skip recording this write
                    return;
            }
        }

        
        // Do snapshots by chunks of 8, it's more efficient this way
        // than using a single multi-precision number
        while (nb_bytes > 0)
        {
            bytes_to_write = nb_bytes>8 ? 8 : nb_bytes;
            _snapshots->back().add_saved_mem(SavedMemState{
                bytes_to_write, // size
                addr, // addr
                concrete_snapshot(addr, bytes_to_write), // concrete content
                abstract_snapshot(addr, bytes_to_write) // abstract content
            });
            nb_bytes -= bytes_to_write;
            addr += bytes_to_write;
        }
    }
}

uid_t MemEngine::class_uid() const
{
    return serial::ClassId::MEM_ENGINE;
}

void MemEngine::dump(serial::Serializer& s) const
{
    s << bits(_uid) << bits(_arch_bits) << bits(_endianness) 
      << _segments << _varctx << _snapshots
      << symbolic_mem_engine << page_manager << mappings;
}

void MemEngine::load(serial::Deserializer& d)
{
    d >> bits(_uid) >> bits(_arch_bits) >> bits(_endianness)
      >> _segments >> _varctx >> _snapshots
      >> symbolic_mem_engine >> page_manager >> mappings; 
}

int MemEngine::uid() const
{
    return _uid;
}

Endian MemEngine::endianness() const
{
    return _endianness;
}

addr_t reserved_memory(MemEngine& mem)
{
    auto seg = mem.get_segment_by_name("Reserved");
    if (seg != nullptr)
        return seg->start;
    else
        return mem.allocate_segment(
            0xee0000, 0x1000, 0x1000,
            maat::mem_flag_rwx,
            "Reserved",
            true // is special segment 
        );
}


} // namespace maat
