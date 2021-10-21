#include "memory.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <sstream>

namespace maat
{


PageSet::PageSet(addr_t s, addr_t e, mem_flag_t f, bool was_once_exec): 
    start(s), end(e), flags(f)
{
    was_once_executable = was_once_exec | ( f & maat::mem_flag_x );
}

bool PageSet::intersects_with_range(addr_t min, addr_t max)
{
    return start <= max && end >= min;
}

bool PageSet::contains(addr_t addr)
{
    return start <= addr && end >= addr;
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
    for( PageSet& r : _regions )
    {
        if( r.contains(addr))
            return r.flags;
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
        os  << std::hex << "0x" << std::left << std::setw(addr_w-2)
            << r.start << "0x" << std::left << std::setw(addr_w-2)
            << r.end << _mem_flags_to_string(r.flags)
            << std::endl;
    }
    return os;
}

MemStatusBitmap::MemStatusBitmap():_bitmap(nullptr), _size(0){}

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


MemConcreteBuffer::MemConcreteBuffer():_mem(nullptr){}
MemConcreteBuffer::MemConcreteBuffer(offset_t nb_bytes)
{
    try
    {
        _size = nb_bytes;
        _mem = new uint8_t[nb_bytes]{0};
    }
    catch(std::bad_alloc)
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
    while( *(uint8_t*)((uint8_t*)_mem+(tmp)) == val)
    {
        tmp++;
        if( tmp > end )
            break;
    };
    return tmp;
}

uint8_t MemConcreteBuffer::read_u8(offset_t off){return *(uint8_t*)((uint8_t*)_mem+off);}
uint16_t MemConcreteBuffer::read_u16(offset_t off){return *(uint16_t*)((uint8_t*)_mem+off);}
uint32_t MemConcreteBuffer::read_u32(offset_t off){return *(uint32_t*)((uint8_t*)_mem+off);}
uint64_t MemConcreteBuffer::read_u64(offset_t off){return *(uint64_t*)((uint8_t*)_mem+off);}
int8_t MemConcreteBuffer::read_i8(offset_t off){return *(int8_t*)((uint8_t*)_mem+off);}
int16_t MemConcreteBuffer::read_i16(offset_t off){return *(int16_t*)((uint8_t*)_mem+off);}
int32_t MemConcreteBuffer::read_i32(offset_t off){return *(int32_t*)((uint8_t*)_mem+off);}
int64_t MemConcreteBuffer::read_i64(offset_t off){return *(int64_t*)((uint8_t*)_mem+off);}

void MemConcreteBuffer::write(offset_t off, int64_t val, int nb_bytes)
{
    if( nb_bytes > 8 )
    {
        throw mem_exception(Fmt()
            << "Can not write constant on more than 8 bytes with this method (got " 
            << std::dec << nb_bytes << ")"
            >> Fmt::to_str);
    }

    for( ; nb_bytes > 0; nb_bytes--)
    {
        *(uint8_t*)((uint8_t*)_mem+off) = val & 0xff;
        val = val >> 8;
        off++;
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
            write(off, tmp.get_cst(), 8);
            nb_bytes -= 8;
            off += 8;
            shft = Number(tmp.size, 64);
            tmp.set_shr(tmp, shft); // Should be safe
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

MemAbstractBuffer::MemAbstractBuffer(){}

/* 1°) !! Reading function assumes little endian !!
 *  
 * 2°) !! This code assumes that the MemAbstractBuffer has been used in a 
 * consistent way. In particular, if a read() operation is performed on 
 * an address range that has NOT been written, it will return wrong results
 * or more likely result in a crash. !! 
 * 
 * */
Expr MemAbstractBuffer::read(offset_t off, unsigned int nb_bytes)
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
                if( res == nullptr )
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

void MemAbstractBuffer::write(offset_t off, Expr e)
{
    for( offset_t i = 0; i < (e->size/8); i++ )
        _mem[off+i] = std::make_pair(e, i);
}



MemSegment::MemSegment(addr_t s, addr_t e, const std::string& n, bool special):
    start(s), end(e),
    _bitmap(MemStatusBitmap(e-s+1)), 
    _concrete(MemConcreteBuffer(e-s+1)),
    _abstract(MemAbstractBuffer()), 
    _is_engine_special_segment(special),
    name(n)
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

Expr MemSegment::symbolic_ptr_read(const Expr& addr, ValueSet& addr_value_set, unsigned int nb_bytes, const Expr& base)
{
    Expr res = base;
    Expr byte;
    addr_t a2;

    addr_t a = addr_value_set.min;
    // Check if value_set doesn't intersect this segment
    if ((addr_value_set.min + nb_bytes -1 > end)
        || (addr_value_set.max < start))
    {
        return res;
    }
    
    if( a < start )
        a = start;
    
    // If base is null, put first possible read in it and increment address
    if( base == nullptr )
    {
        res = read(a, nb_bytes);
        a++;
    }

    // Get all other possible values
    for( ; a-1+nb_bytes <= end; a++ )
    {
        if( !addr_value_set.contains(a) )
            break;
            
        /* Optimisation to detect huge areas containing only a single byte (typically zeros) */
        if( _bitmap.is_concrete(a-start))
        {
            a2 = is_identical_until(a, _concrete.read_u8(a-start)) -1; // a2 == last address containing the byte "byte"
            if( a2 >= a-1+nb_bytes )
            {
                // Identical memory region bigger than single read so
                // use interval instead
                // Same value for addr >= a
                Expr v = read(a, nb_bytes);
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
                res = ITE(addr, ITECond::EQ, exprcst(addr->size, a), read(a, nb_bytes), res);
            }
        }
        else
        {
            /* Add possible concrete value to ITE switch :) */
            res = ITE(addr, ITECond::EQ, exprcst(addr->size, a), read(a, nb_bytes), res);
        }
    }
    // Return res
    return res;
}


Expr MemSegment::read(addr_t addr, unsigned int nb_bytes)
{
    offset_t off = addr - start;
    offset_t from = off, to, bytes_to_read;
    Expr tmp = nullptr, tmp2;
    Number number, n1, n2;

    if( addr+nb_bytes-1 > end )
    {
        throw mem_exception("MemSegment::read(): try to read beyond segment's end");
    }

    do
    {
        /* Try if concrete or symbolic */
        to = _bitmap.is_concrete_until(from, nb_bytes);
        if( to != from )
        {
            /* Concrete */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if (bytes_to_read > nb_bytes) // We don't want more that what's left to read
            { 
                bytes_to_read = nb_bytes; 
            }
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            /* Read */
            switch(bytes_to_read)
            {
                case 1: tmp2 = exprcst(8, _concrete.read_i8(from)); break;
                case 2: tmp2 = exprcst(16, _concrete.read_i16(from)); break;
                case 3: tmp2 = exprcst(24, _concrete.read_i32(from) & 0x00ffffff); break; // Assumes little endian
                case 4: tmp2 = exprcst(32, _concrete.read_i32(from)); break;
                case 5: tmp2 = exprcst(40, _concrete.read_i64(from) & 0x000000ffffffffff); break; // Assumes little endian
                case 6: tmp2 = exprcst(48, _concrete.read_i64(from) & 0x0000ffffffffffff); break; // Assumes little endian
                case 7: tmp2 = exprcst(56, _concrete.read_i64(from) & 0x00ffffffffffffff); break;// Assumes little endian
                case 8: tmp2 = exprcst(64, _concrete.read_i64(from)); break;
                case 9: 
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(8, _concrete.read_i8(from+8));
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 10: 
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(16, _concrete.read_i16(from+8));
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 11:
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(24, _concrete.read_i32(from+8) & 0x00ffffff);
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 12:
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(32, _concrete.read_i32(from+8));
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 13:
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(40, _concrete.read_i64(from+8) & 0xffffffffff);
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 14:
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(48, _concrete.read_i64(from+8) & 0xffffffffffff);
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 15:
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(56, _concrete.read_i64(from+8) & 0xffffffffffffff);
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                case 16:
                    n1 = Number(64, _concrete.read_i64(from));
                    n2 = Number(64, _concrete.read_i64(from+8));
                    number.set_concat(n2, n1);
                    tmp2 = exprcst(number);
                    break;
                default: throw mem_exception("MemSegment: should not be reading more than 16 bytes at a time!");
            }
            /* Update result */
            if( tmp == nullptr )
                tmp = tmp2;
            else
                tmp = concat(tmp2, tmp); // Assumes little endian
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
            if( tmp == nullptr )
                tmp = tmp2;
            else
                tmp = concat(tmp2, tmp); // Assumes little endian
        }
        from += bytes_to_read;
    } while(nb_bytes > 0);
    return tmp;
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

    switch(bytes_to_read)
    {
        case 1: res = _concrete.read_u8(off); break;
        case 2: res = _concrete.read_u16(off); break;
        case 3: res = _concrete.read_u32(off) & 0xffffff; break;
        case 4: res = _concrete.read_u32(off); break;
        case 5: res = _concrete.read_u64(off) & 0xffffffffff; break;
        case 6: res = _concrete.read_u64(off) & 0xffffffffffff; break;
        case 7: res = _concrete.read_u64(off) & 0xffffffffffffff; break;
        case 8: res = _concrete.read_u64(off); break;
        default: throw runtime_exception("MemSegment::concrete_snapshot() called with wrong nb_bytes. Supports only: 1,2,3,4,5,6,7,8");
    }

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

void MemSegment::write(addr_t addr, const Expr& e, VarContext& ctx)
{
    offset_t off = addr - start;
    if( (!e->is_concrete(ctx)) || e->is_tainted())
    {
        /* Add symbolic value */
        _abstract.write(off, e);
        /* Update the bitmap */
        _bitmap.mark_as_abstract(off, off+(e->size/8)-1);
    }
    else
    {
        /* Update the bitmap */
        _bitmap.mark_as_concrete(off, off+(e->size/8)-1);
    }

    /* ALWAYS Add concrete value if possible (even if its tainted
     * in case it is code that'll be disassembled, but DON'T update
     * the bitmap */
    if( ! e->is_symbolic(ctx))
    {
        const Number& concrete = e->as_number(ctx);
        _concrete.write(off, concrete, e->size/8);
    }
}

void MemSegment::write(addr_t addr, const std::vector<Expr>& buf, VarContext& ctx)
{
    offset_t off = addr-start;

    for (Expr e : buf)
    {
        if (addr + e->size/8 -1 > end)
            throw mem_exception("MemSegment: buffer copy: nb_bytes exceeds segment");
        write(addr, e, ctx);
        addr += e->size/8;
        off += e->size/8;
    }
}

void MemSegment::write(addr_t addr, uint8_t* src, int nb_bytes)
{
    offset_t off = addr-start;
    if( addr + nb_bytes -1 > end)
    {
        throw mem_exception("MemSegment: buffer copy: nb_bytes exceeds segment");
    }
    _concrete.write_buffer(off, src, nb_bytes);
    _bitmap.mark_as_concrete(off, off+nb_bytes-1);
}

void MemSegment::write(addr_t addr, cst_t val, unsigned int nb_bytes)
{
    offset_t off = addr - start;
    _concrete.write(off, val, nb_bytes);
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
    addr_t adjusted_max = (max < end-start)? max: end-start;
    return start + _bitmap.is_concrete_until(addr1-start, adjusted_max);
}

// Return first address where the byte is different than "byte"
addr_t MemSegment::is_identical_until(addr_t addr, cst_t byte)
{
    addr_t max_addr = is_concrete_until(start, end);
    addr_t res = _concrete.is_identical_until(addr-start, max_addr-start, (uint8_t)byte);
    return res + start;
}



MemEngine::MemEngine(
    std::shared_ptr<VarContext> varctx,
    size_t arch_bits,
    std::shared_ptr<SnapshotManager<Snapshot>> snap
):
_varctx(varctx),
symbolic_mem_engine(arch_bits, varctx),
_arch_bits(arch_bits),
_snapshots(snap)
{
    if(_varctx == nullptr)
        _varctx = std::make_shared<VarContext>(0);
    if(_snapshots == nullptr)
        _snapshots = std::make_shared<SnapshotManager<Snapshot>>();
}

MemEngine::~MemEngine()
{}

void MemEngine::new_segment(addr_t start, addr_t end, mem_flag_t flags, const std::string& name, bool is_special)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;

    if( !is_free(start, end))
        throw mem_exception("Trying to create a segment that overlaps with another segment");

    std::shared_ptr<MemSegment> seg = std::make_shared<MemSegment>(start, end, name, is_special);

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

std::shared_ptr<MemSegment> MemEngine::get_segment_containing(addr_t addr)
{
    for( auto& it : _segments)
    {
        if( it->start <= addr && it->end >= addr )
            return it;
    }
    return nullptr;
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
        if (is_free(base, base+size-1) and base-1 < max_addr)
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

bool MemEngine::is_free(addr_t start, addr_t end)
{
    for( auto& segment : _segments )
    {
        if( segment->start <= end && segment->end >= start )
            return false;
    }
    return true;
}

// Generic read function
// This function is never called by the engine but can be called by the user
Expr MemEngine::read(Expr addr, unsigned int nb_bytes)
{
    // Do the read
    if( ! addr->is_concrete(*_varctx))
    {
        Settings tmp_settings;
        return symbolic_ptr_read(addr, addr->value_set(), nb_bytes, tmp_settings);
    }
    else
    {
        return read(addr->as_uint(*_varctx), nb_bytes);
    }
}

std::vector<Expr> MemEngine::read_buffer(Expr addr, unsigned int nb_elems, unsigned int elem_size)
{
    // Do the read
    if( addr->is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::read_buffer(): doesn't support symbolic expression as address");
    }
    else
    {
        return read_buffer(addr->as_uint(*_varctx), nb_elems, elem_size);
    }
}

std::string MemEngine::read_string(Expr addr, unsigned int len)
{
    // Do the read
    if( addr->is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::read_string(): doesn't support symbolic expression as address");
    }
    else
    {
        return read_string(addr->as_uint(*_varctx), len);
    }
}

// force_concrete_read makes the read concrete even though the memory area has been affected 
// by symbolic pointers write
Expr MemEngine::read(addr_t addr, unsigned int nb_bytes, mem_alert_t* alert, bool force_concrete_read)
{
    Expr res=nullptr, tmp;
    unsigned int save_nb_bytes = nb_bytes;

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
        Expr base_expr = read(addr, nb_bytes, alert, true);
        res = symbolic_mem_engine.concrete_ptr_read(
                exprcst(_arch_bits, addr),
                nb_bytes,
                base_expr
              );
        return res;
    }

    // Else do a read in the "sure" memory
    // Find the segment we read from
    for( auto& segment : _segments)
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
                tmp = segment->read(addr, segment->end - addr+1);
            else
                tmp = segment->read(addr, nb_bytes);

            // Assign read to result
            if( !res )
                res = tmp;
            else
                res = concat(tmp, res);

            nb_bytes -= tmp->size/8;
            addr += tmp->size/8;
            if( nb_bytes == 0 )
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

ValueSet MemEngine::limit_symptr_range(Expr addr, const ValueSet& range, const Settings& settings)
{
    addr_t tmp_addr_min, tmp_addr_max;
    ValueSet res(range.size);

    // Adjust the value set min
    tmp_addr_min = addr->as_uint(*_varctx) - settings.symptr_max_range/2;
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


Expr MemEngine::symbolic_ptr_read(Expr addr, const ValueSet& range, unsigned int nb_bytes, const Settings& settings)
{
    Expr res = nullptr;
    ValueSet addr_value_set(range.size);

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

    // Update average pointer range size
    // TODO ??
    /*
    if( _sym ){
        // Moyenne ponderee
        _sym->stats.symbolic_ptr_read_average_range = ((_sym->stats.symbolic_ptr_read_average_range*_sym->stats.symbolic_ptr_read_count)+addr_value_set.range())/(1+_sym->stats.symbolic_ptr_read_count);
        // Incremente le compteur de lectures symboliques
        _sym->stats.symbolic_ptr_read_count++;
    }
    */

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
        else
            res = segment->symbolic_ptr_read(addr, addr_value_set, nb_bytes, res);
    }

    if( res == nullptr )
        throw runtime_exception("Got NULL as base value for symbolic pointer read!");

    if( symbolic_mem_engine.contains_symbolic_write(addr_value_set.min, addr_value_set.max+nb_bytes-1) )
    {
        res = symbolic_mem_engine.symbolic_ptr_read(addr, addr_value_set, nb_bytes, res);
    }

    return res;
}

std::vector<Expr> MemEngine::read_buffer(addr_t addr, unsigned int nb_elems, unsigned int elem_size)
{
    std::vector<Expr> res;
    read_buffer(res,addr, nb_elems, elem_size);
    return res;
}

void MemEngine::read_buffer(std::vector<Expr>& buffer, addr_t addr, unsigned int nb_elems, unsigned int elem_size)
{
    if( elem_size > 8 )
    {
        throw mem_exception("Buffer element size should not exceed 8 bytes");
    }
    for( int i = 0; i < nb_elems; i++)
    {
        buffer.push_back(read(addr+(i*elem_size), elem_size));
    }
}

/* Read a string of size len 
 * If len == 0 then stop at first null byte (C String) */
std::string MemEngine::read_string(addr_t addr, unsigned int len)
{
    std::string res;
    Expr e;
    char c;

    for( int i = 0; len == 0 || i < len; i++)
    {
        e = read(addr+i, 1);
        if( e->is_symbolic(*_varctx))
        {
            throw mem_exception("Got purely symbolic char while reading concrete string");
        }
        c = (char)(e->as_uint(*_varctx));
        if( c == 0 && len == 0 )
        {
            return res;
        }
        res += c;
    }
    return res;
}

void MemEngine::write(Expr addr, Expr e, bool ignore_flags)
{
    if (addr->is_concrete(*_varctx))
    {
        return write(addr->as_uint(*_varctx), e, nullptr, false, ignore_flags);
    }
    else
    {
        Settings settings; // Dummy settings because symbolic_ptr_write needs it
        return symbolic_ptr_write(addr, addr->value_set(), e, settings);
    }
}

void MemEngine::write(addr_t addr, Expr e, mem_alert_t* alert, bool called_by_engine, bool ignore_flags)
{
    std::list<std::shared_ptr<MemSegment>>::iterator it;
    bool finish = false;
    Expr tmp_e = e;
    addr_t tmp_addr = addr;
    int bytes_to_write = 0;

    if( alert != nullptr )
    {
        *alert = maat::mem_alert_none; // Reset alert
    }

    /* Find the segment we write to */
    for( it = _segments.begin(); it != _segments.end() && !finish; it++)
    {
        if( (*it)->intersects_with_range(tmp_addr, tmp_addr+(tmp_e->size/8)-1) )
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
                            tmp_addr-1+(tmp_e->size/8)
                        )
                    );
                }

            }
            /* Perform write*/
            if( tmp_addr + tmp_e->size/8 -1 > (*it)->end )
            {
                bytes_to_write = (*it)->end-tmp_addr+1;
                // Record write for snapshots
                record_mem_write(tmp_addr, bytes_to_write);
                // Write
                (*it)->write(tmp_addr, extract(tmp_e, (bytes_to_write*8)-1, 0) , *_varctx); // Just write lower bytes
                tmp_addr += bytes_to_write;
                tmp_e = extract(tmp_e, tmp_e->size-1, bytes_to_write*8);
            }
            else
            {
                bytes_to_write = tmp_e->size/8;
                // Record write for snapshots
                record_mem_write(tmp_addr, bytes_to_write);
                // Write
                (*it)->write(tmp_addr, tmp_e, *_varctx);
                finish = true;
            }
        }
    }
    
    if (finish)
    {
        // Success
        // Record write in symbolic memory engine if needed
        symbolic_mem_engine.concrete_ptr_write(exprcst(_arch_bits, addr), e);
        return;
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(Fmt()
        << "Trying to write " << std::dec << e->size/8
        << " bytes at address 0x" << std::hex << addr
        << " causes access to non-mapped memory"
        >> Fmt::to_str);
}

void MemEngine::symbolic_ptr_write(Expr addr, const ValueSet& range, Expr e, const Settings& settings, mem_alert_t* alert, bool _called_by_sym)
{
    addr_t addr_min, addr_max;

    // Check if we have to limit the pointer range
    if( 
        settings.symptr_limit_range and
        (range.max - range.min +1) > settings.symptr_max_range and
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

    // TODO Update average pointer range size
    // TODO in engine ?
    /*
    if (_sym)
    {
        // Moyenne ponderee
        _sym->stats.symbolic_ptr_write_average_range = ((_sym->stats.symbolic_ptr_write_average_range*_sym->stats.symbolic_ptr_write_count)+(addr_max-addr_min+1))/(1+_sym->stats.symbolic_ptr_read_count);
        // Incremente le compteur de lectures symboliques
        _sym->stats.symbolic_ptr_write_count++;
    }
    */

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
    symbolic_mem_engine.symbolic_ptr_write(addr, e, addr_min, addr_max);
}

void MemEngine::write(Expr addr, cst_t val, int nb_bytes, bool ignore_flags)
{
    if (addr->is_concrete(*_varctx))
    {
        return write(addr->as_uint(*_varctx), val, nb_bytes, ignore_flags);
    }
    else
    {
        Settings settings; // Dummy settings because symbolic_ptr_write needs it
        return symbolic_ptr_write(addr, addr->value_set(), exprcst(nb_bytes*8, val), settings);
    }
}

void MemEngine::write(
    addr_t addr, cst_t val, int nb_bytes, bool ignore_mem_permissions,
    mem_alert_t* alert, bool called_by_engine
)
{
    return write(addr, exprcst(nb_bytes*8, val), alert, called_by_engine, ignore_mem_permissions);
}

void MemEngine::write_buffer(Expr addr, uint8_t* src, int nb_bytes, bool ignore_flags)
{
    if( addr->is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::write_buffer(): doesn't support symbolic expressions as address");
    }
    else
    {
        return write_buffer(addr->as_uint(*_varctx), src, nb_bytes, ignore_flags);
    }
}

void MemEngine::write_buffer(Expr addr, const std::vector<Expr>& src, bool ignore_flags){
    if( addr->is_symbolic(*_varctx))
    {
        throw mem_exception("MemEngine::write_buffer(): doesn't support symbolic expressions as address");
    }
    else
    {
        return write_buffer(addr->as_uint(*_varctx), src, ignore_flags);
    }
}

void MemEngine::write_buffer(addr_t addr, uint8_t* src, int nb_bytes, bool ignore_flags)
{
    if( nb_bytes == 0 )
        return;

    /* If breakpoints enabled record the write */
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
            segment->write(addr, src, nb_bytes);
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

void MemEngine::write_buffer(addr_t addr, const std::vector<Expr>& buf, bool ignore_flags)
{
    int nb_bytes = 0;

    for (Expr e : buf)
        nb_bytes += e->size/8;

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
                
            segment->write(addr, buf, *_varctx);
            return;
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
    Expr prev_expr;
    
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
        prev_expr = read(addr + i*elem_size, elem_size);
        if (prev_expr->is_symbolic(*_varctx))
        {
            throw mem_exception("MemEngine::make_concolic(): can not be called on memory region that contains full symbolic expressions");
        }
        _varctx->set(ss.str(), prev_expr->as_uint(*_varctx));
        write(addr + i*elem_size, exprvar(elem_size*8, ss.str()));
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
        e = read(addr + i*elem_size, elem_size);
        e->make_tainted();
        write(addr + i*elem_size, e);
    }
}

std::string MemEngine::make_tainted_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size, const std::string& name)
{
    Expr e;
    std::stringstream ss;
    std::vector<std::string> res;
    

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
        e = read(addr + i*elem_size, elem_size);
        _varctx->set(ss.str(), e->as_int(*_varctx)); // Save the concrete value
        write(addr + i*elem_size, exprvar(elem_size*8, ss.str(), Taint::TAINTED)); // Write the new exprvar
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
            // Assuming little endian
            res += tmp << ((ucst_t)i*8);
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
        if( segment->contains(addr) )
        {
            // Check if contains all bytes or just a few
            if (addr + nb_bytes -1 > segment->end)
                bytes_to_write = segment->end - addr + 1;
            else
                bytes_to_write = nb_bytes;

            // Write
            if (page_manager.was_once_executable(addr))
                alert |= maat::mem_alert_x_overwrite;
            segment->write_from_concrete_snapshot(addr, val, bytes_to_write);

            // Update
            val = val >> (bytes_to_write*8);
            nb_bytes -= bytes_to_write;
            if (nb_bytes == 0)
                return;
        }
    }

    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(Fmt()
        << "Trying to restore from concrete-snapshot at address 0x"
        << std::hex << addr << " not mapped int memory"
        >> Fmt::to_str
    );
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

    if( !snap.empty())
    {
        /* If addr isn't in any segment, throw exception */
        throw runtime_exception(Fmt()
            << "Trying to restore from symbolic-snapshot at address 0x"
            << std::hex << addr << " not mapped int memory"
            >> Fmt::to_str
        );
    }
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
        << std::hex << addr << " not mapped int memory"
        >> Fmt::to_str
    );
}

void MemEngine::check_status(addr_t start, addr_t end, bool& is_symbolic, bool& is_tainted)
{
    if( start > end )
        throw runtime_exception("MemEngine::check_mem_status(): got start bigger than end");

    is_symbolic = false;
    is_tainted = false;
    Expr e;
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
                    e = read(start_sym, 1);
                    if( e->is_tainted() )
                        is_tainted = true;
                    if( e->is_symbolic(*_varctx))
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
    os << std::endl << "Segments: " << std::endl;
    os << std::endl << std::left << std::setw(addr_w) << "Start" << std::left << std::setw(addr_w) << "End" 
       << std::left << std::setw(8) << "Name" << std::endl;
    os << std::left << std::setw(addr_w) << "-----" << std::left << std::setw(addr_w) << "---" 
       << std::left << std::setw(8) << "----" << std::endl;
    for( auto& segment : mem._segments )
    {
        os << std::hex << "0x" << std::left << std::setw(addr_w-2) << segment->start << "0x" << std::left << std::setw(addr_w-2) << segment->end;
        if( !segment->name.empty() )
            os << segment->name;
        os << std::endl;
    }
    
    os << mem.page_manager;

    return os;
}

void MemEngine::record_mem_write(addr_t addr, int nb_bytes)
{
    size_t bytes_to_write;
 
    /* If snapshots enabled record the write */
    if (_snapshots->active())
    {
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

/* TODO
std::string MemEngine::read_instr(addr_t addr, unsigned int nb_instr, CPUMode mode){
    std::stringstream ss;
    std::string res;
    if( _sym == nullptr ){
        return "";
    }
    try{
        vector<pair<addr_t, string>> disassembly = _sym->read_instr(addr, nb_instr, mode);
        for( auto& item: disassembly ){
            ss.str(""); ss.clear();
            ss << "0x" << std::hex << item.first << '\t' << item.second << std::endl;
            res += ss.str();
        }
        return res;
    }catch(generic_exception e){
        throw mem_exception(e.what());
    }
} */


} // namespace maat
