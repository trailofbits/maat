#include "maat/expression.hpp"
#include <algorithm>
#include <iostream>

namespace maat
{
    
ValueSet::ValueSet():size(-1){}
ValueSet::ValueSet(size_t s):size(s), min(ValueSet::vs_min), max(ValueSet::vs_max), stride(1){}
ValueSet::ValueSet(size_t si, ucst_t l, ucst_t h, ucst_t s): size(si), min(l), max(h), stride(s){}

void ValueSet::set(ucst_t l, ucst_t h, ucst_t s)
{
    min = l;
    max = h;
    stride = s;
}

void ValueSet::set_cst(ucst_t val)
{
    min = val;
    max = val;
    stride = 0;
}

bool ValueSet::is_cst()
{
    return stride == 0 || min == max;
}

void ValueSet::set_all()
{
    min = ValueSet::vs_min;
    max = cst_unsign_trunc(size, ValueSet::vs_max);
    stride = 1;
}

ucst_t ValueSet::range()
{
    if (is_cst())
        return 0;
    else
        if (max >= cst_mask(size) and min == 0)
            return max;
        else
            return max-min+1;
}

bool ValueSet::contains(ucst_t val)
{
    if (is_cst() and val == min)
        return true;
    else
        return  val >= min and 
                val <= max and
                ((val-min) % stride) == 0;
}

// Most propagation rules taken from Warren - Hacker's Delight
void ValueSet::set_neg(ValueSet& vs)
{
    // Let A < X < B
    // Then 0 < -X < MAX_INT if A == 0 && B != 0 
    //      -A < -X < -B otherwise
    if( vs.min == 0 && vs.max != 0 ){
        set_all();
    }else{
        set(cst_unsign_trunc(size, -(cst_t)vs.max), cst_unsign_trunc(size, -(cst_t)vs.min), vs.stride);
    }
}

void ValueSet::set_not(ValueSet& vs)
{
    // A < X < B  => ~B < ~X < ~A
    set(cst_unsign_trunc(size, ~vs.max), cst_unsign_trunc(size, ~vs.min), vs.stride);
}

void ValueSet::set_add(ValueSet& vs1, ValueSet& vs2)
{
    // Let A < X < B and C < Y < D
    // Then 0 < X+Y < MAX_INT if A+C < MAX_INT and B+D > MAX_INT (overflow)
    //      A+C < X+Y < B+D otherwise
    // New stride is the gcd of both strides

    // Check if overflow when adding biggest numbers
    if( cst_unsign_trunc(size, vs1.max + vs2.max) < vs1.max ){
        // Overflow, check if overflow with smallest numbers also
        if( cst_unsign_trunc(size, vs1.min + vs2.min) < vs1.min ){
            // The addition always overflows, so the interval is
            // actually preserved :D
            set( cst_unsign_trunc(size, vs1.min + vs2.min), 
                 cst_unsign_trunc(size, vs1.max + vs2.max),
                 cst_gcd(vs1.stride, vs2.stride));
        }else{
            // The addition overflows only sometimes, resulting
            // intervals can not be represented with a strided 
            // interval
            set_all();
        }
        
    }else{
        // No overflow, just set the interval
        set( vs1.min + vs2.min, 
             vs1.max + vs2.max,
             cst_gcd(vs1.stride, vs2.stride));
    }
}

// Compute the maximal value when propagating strided interval on 
// OR operation
inline ucst_t _vs_max_or(ValueSet& vs1, ValueSet& vs2 )
{
    // The idea is to scan bits of the higher bounds left to right.
    // When both bits are 1, try to change one of them into 0 and set
    // all following bits to 1 
    // Example: 
    //   0b100101 --> becomes 0b100111
    //   0b001101
    // new min value is then: 0b101111 (and not 0b101101)
    ucst_t tmp;
    ucst_t m = 1ULL << (vs1.size-1);
    ucst_t max1 = vs1.max, max2 = vs2.max;
    while( m != 0 ){
        if( max1 & max2 & m ){
            tmp = (max1 - m) | (m-1);
            if( vs1.contains(tmp)){
                max1 = tmp; break;
            }
            tmp = (max2 - m ) | (m-1);
            if( vs2.contains(tmp)){
                max2 = tmp; break;
            }
        }
        m >>= 1;
    }
    return max1 | max2;
}

// Compute the minimal value when propagating strided interval on 
// OR operation
inline ucst_t _vs_min_or(ValueSet& vs1, ValueSet& vs2 )
{
    // The idea is to scan bits left to right. When one bit is 0 and the 
    // other is 1, try changing the 0 bit to 1 and set all leading bits 
    // to 0
    // Example: 
    //   0b100101 --> becomes 0b101000
    //   0b001001
    // new min value is then: 0b101001 (and not 0b101101)
    ucst_t tmp;
    ucst_t m = 1ULL << (vs1.size-1);
    ucst_t min1 = vs1.min, min2 = vs2.min;
    while( m != 0 ){
        if( ~min1 & min2 & m ){
            tmp = (min1|m) & (-m); // tmp is the possible new value
            if( vs1.contains(tmp) ){ // if new min valid, break
                min1 = tmp;
                break;
            }
        }else if( min1 & ~min2 & m){
            tmp = (min2|m) & (-m);
            if( vs2.contains(tmp) ){
                min2 = tmp;
                break;
            }
        }
        m >>= 1;
    }
    return min1 | min2;
}

void ValueSet::set_or(ValueSet& vs1, ValueSet& vs2)
{
    set(_vs_min_or(vs1, vs2), _vs_max_or(vs1, vs2), 1);
}

// Compute the maximal value when propagating strided interval on 
// AND operation
inline ucst_t _vs_max_and(ucst_t min1, ucst_t max1, ucst_t min2, ucst_t max2, size_t size )
{
    // Use demorgan law x&y = ~(~x | ~y)
    // So max_and(a, b, c, d) = ~min_or(~b, ~a, ~d, ~c)
    ValueSet new_vs1 = ValueSet(size, ~max1, ~min1, 1);
    ValueSet new_vs2 = ValueSet(size, ~max2, ~min2, 1);
    return ~_vs_min_or(new_vs1, new_vs2);
}

// Compute the minimal value when propagating strided interval on 
// AND operation
inline ucst_t _vs_min_and(ucst_t min1, ucst_t max1, ucst_t min2, ucst_t max2 , size_t size)
{
    // Use demorgan law x&y = ~(~x | ~y)
    // So min_and(a, b, c, d) = ~min_or(~b, ~a, ~d, ~c)
    ValueSet new_vs1 = ValueSet(size, ~max1, ~min1, 1);
    ValueSet new_vs2 = ValueSet(size, ~max2, ~min2, 1);
    return ~_vs_max_or(new_vs1, new_vs2);
}

void ValueSet::set_and(ValueSet& vs1, ValueSet& vs2)
{
    set(_vs_min_and(vs1.min, vs1.max, vs2.min, vs2.max, size), 
        _vs_max_and(vs1.min, vs1.max, vs2.min, vs2.max, size),
        1);
}

// Compute the maximal value when propagating strided interval on 
// XOR operation
inline ucst_t _vs_max_xor(ValueSet& vs1, ValueSet& vs2 )
{
    // Use law x^y = (x & ~y) | (~x & y)
    ValueSet new_vs1 = ValueSet(vs1.size, 0, _vs_max_and(vs1.min, vs1.max, ~vs2.max, ~vs2.min, vs1.size), 1);
    ValueSet new_vs2 = ValueSet(vs2.size, 0, _vs_max_and(~vs1.max, ~vs1.min, vs2.min, vs2.max, vs2.size), 1);
    return _vs_max_or( new_vs1, new_vs2 );
}

// Compute the minimal value when propagating strided interval on 
// XOR operation
inline ucst_t _vs_min_xor(ValueSet& vs1, ValueSet& vs2 )
{
    // Use law x^y = (x & ~y) | (~x & y)
    return _vs_min_and(vs1.min, vs1.max, ~vs2.max, ~vs2.min, vs1.size) 
           | _vs_min_and(~vs1.max, ~vs1.min, vs2.min, vs2.max, vs1.size);
}

void ValueSet::set_xor(ValueSet& vs1, ValueSet& vs2)
{
    set(_vs_min_xor(vs1, vs2), _vs_max_xor(vs1, vs2), 1);
}

void ValueSet::set_mod(ValueSet& vs1, ValueSet& vs2)
{
    set(0, vs2.max, 1);
}

void ValueSet::set_smod(ValueSet& vs1, ValueSet& vs2)
{
    // It should be possible to refine this result by looking
    // at the sign of the operands
    set(-vs2.max, vs2.max, 1);
}

void ValueSet::set_shl(ValueSet& vs1, ValueSet& vs2)
{
    if(  vs2.max >= vs1.size ){
        // Max shift sets the value to zero, all possible values
        // (but max can still be known)
        set(0, cst_unsign_trunc(vs1.size, ValueSet::vs_max << vs2.min), 1);
    }else if( vs2.is_cst() && vs2.max == 0){
        // Shift by zero, we keep the same interval
        set(vs1.min, vs1.max, vs1.stride);
    }else if( vs1.max >> (vs1.size - vs2.max) > 0){
        // Some bits get shifted out, we can't make assumptions
        // on the new min/max value
        // TODO: Refine 'min' if stride and vs1.min enable it
        set(0, cst_unsign_trunc(vs1.size, ValueSet::vs_max << vs2.min), 1);
    }else{
        // No bits get shifted out, we just shift the interval then :)
        min = vs1.min << vs2.min;
        max = vs1.max << vs2.max;
        // If the shift is constant, we can adjust the stride, otherwise
        // set it to 1 :/
        if( vs2.is_cst() ){
            stride = vs1.stride << vs2.min;
        }else{
            stride = 1;
        }
    }
}

void ValueSet::set_shr(ValueSet& vs1, ValueSet& vs2)
{
    if( vs2.max >= vs1.size )
        min = 0;
    else
        min = vs1.min >> vs2.max;
    if( vs2.min >= vs1.size )
        max = 0;
    else
        max = vs1.max >> vs2.min;
    if( vs2.is_cst() && (vs1.stride>>vs2.max) > 0){
        stride = vs1.stride >> vs2.max;
    }else{
        stride = 1;
    }
}

void ValueSet::set_sar(ValueSet& vs1, ValueSet& vs2)
{
    // !! Shifting by more than the size of the integer
    // results in UB in C99 standard... So we need to test
    // the shift values.
    if( vs2.max >= vs1.size )
        min = 0;
    else
        min = (ucst_t)vs1.min >> (ucst_t)vs2.max;
    if( cst_extract(vs1.max, vs1.size-1, vs1.size-1) != 0 ){
        // HSB is 1 so we insert 0xffff... when shifting
        if( vs2.min >= vs1.size )
            max = cst_mask(vs1.size);
        else
            max = cst_sign_trunc( vs1.size, ((ucst_t)cst_mask(64)<<(vs1.size-vs2.min)) | (vs1.max >> vs2.min));
    }else{
        // HSB is 0 so we don't insert 0xffff... when shifting
        if( vs2.min >= vs1.size )
            max = 0;
        else
            max = (vs1.max >> vs2.min);
    }
    if( vs2.is_cst() && (vs1.stride>>vs2.max) > 0){
        stride = vs1.stride >> vs2.max;
    }else{
        stride = 1;
    }
}

void ValueSet::set_mul(ValueSet& vs1, ValueSet& vs2)
{
    
    if( vs1.is_cst() && vs1.max == 0 ){
        set_cst(0);
    
    // Check if overflow when mult by biggest numbers
    }else if( (cst_mask(size)/vs1.max) <= vs2.max ){
        set_all();
    }else{
        // No overflow, adjust
        ucst_t new_stride;
        // If one interval is constant, stride can be deduced
        if( vs1.is_cst() ){
            new_stride = vs2.stride * vs1.min;
        }else if( vs2.is_cst() ){
            new_stride = vs1.stride * vs2.min;
        }else{
            // If none of the intervals is a cst, we don't know 
            // the stride
            new_stride = 1;
        }
        // Set stride
        set( cst_unsign_trunc(size, vs1.min * vs2.min),
             cst_unsign_trunc(size, vs1.max * vs2.max),
             new_stride);
    }
}

void ValueSet::set_mulh(ValueSet& vs1, ValueSet& vs2)
{
    // Simlar to MUL but there can not be an overflow on this one :)
    ucst_t new_min = (ucst_t)(((__uint128_t)vs1.min * (__uint128_t)vs2.min) >> size ); 
    ucst_t new_max = (ucst_t)(((__uint128_t)vs1.max * (__uint128_t)vs2.max) >> size );
    set(new_min, new_max, 1);
}

void ValueSet::set_div(ValueSet& vs1, ValueSet& vs2)
{
    ucst_t new_min = vs1.min / vs2.max;
    ucst_t new_max = vs1.max / vs2.min;
    ucst_t new_stride;
    
    if( vs2.is_cst() && (vs1.stride % vs2.min == 0)){
        new_stride = vs1.stride / vs2.min;
    }else{
        new_stride = 1;
    }
    
    set(new_min, new_max, new_stride);
}

void ValueSet::set_concat(ValueSet& high, ValueSet& low)
{
    ucst_t min = cst_concat(high.min, high.size, low.min, low.size);
    ucst_t max = cst_concat(high.max, high.size, low.max, low.size);
    ucst_t new_stride;
    if( low.is_cst() )
        new_stride = high.stride;
    else if( high.is_cst())
        new_stride = low.stride;
    else
        new_stride = 1;
    set(min, max, new_stride);
}

void ValueSet::set_union(ValueSet& vs1, ValueSet& vs2)
{
    ucst_t min, max;
    min = vs1.min < vs2.min ? vs1.min : vs2.min;
    max = vs1.max > vs2.max ? vs1.max : vs2.max;
    set(min, max, 1); // TODO: properly analyse resulting stride instead of "1"
}

} // namespace maat
