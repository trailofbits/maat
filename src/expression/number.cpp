#include "maat/number.hpp"

namespace maat
{

// Interpret src as a signed mpz value and puts it in res
// src must be more than 64 bits, mpz_t is not initialized
void mpz_init_force_signed(mpz_t& res, const Number& src)
{
    if (not src.is_mpz())
        throw expression_exception("mpz_force_signed(): shouldn't be called with regular Number!");
    
    mpz_init(res);
    int bit = mpz_tstbit(src.mpz_.get_mpz_t(), src.size-1);
    if (bit == 0)
        mpz_set(res, src.mpz_.get_mpz_t()); // Unsigned, keep the same value
    else
    {
        mpz_t tmp;
        mpz_init(tmp);
        mpz_setbit(tmp, src.size);
        mpz_sub(tmp, tmp, src.mpz_.get_mpz_t());
        mpz_neg(res, tmp);
        mpz_clear(tmp);
    }
}

Number::Number(): size(0), cst_(-1), mpz_(0){}

Number::Number(size_t bits): size(bits), cst_(0), mpz_(0){}

Number::~Number(){}

void Number::adjust_mpz()
{
    mpz_t tmp;
    if (!is_mpz())
        return;

    mpz_init_set(tmp, mpz_.get_mpz_t());
    mpz_ = mpz_class(0);

    // Copy bit by bit
    for (unsigned int i = 0; i < size; i++)
    {
        if (mpz_tstbit(tmp, i) == 1)
            mpz_setbit(mpz_.get_mpz_t(), i);
        else
            mpz_clrbit(mpz_.get_mpz_t(), i);
    }
    mpz_clear(tmp);
}

cst_t __number_cst_mask(size_t size)
{
    if( size == sizeof(cst_t)*8 )
        return (cst_t)-1;
    else
        return ((ucst_t)1<<(ucst_t)size)-1; 
}

ucst_t __number_cst_unsign_trunc(size_t size, cst_t c)
{
    if( size == sizeof(cst_t)*8)
    {
        return c;
    }
    return (ucst_t)__number_cst_mask(size) & (ucst_t)c;
}

cst_t __number_cst_sign_extend(size_t size, cst_t val)
{
    if( size == sizeof(cst_t)*8)
    {
        return val;
    }
    if( ((ucst_t)1<<((ucst_t)size-1)) & (ucst_t)val )
    {
        // Negative, set higher bits to 1
        val = ((ucst_t)0xffffffffffffffff<< size) | val;
    }
    else
    {
        // Positive, set higher bits to 0
        val = ((((ucst_t)1<<size)-1) & val);
    }
    return val;
}

Number::Number(size_t bits, cst_t value): size(bits)
{
    if (bits > 64)
        set_mpz(value);
    else
        cst_ = __number_cst_sign_extend(size, value);
}

/// Set the number to simple value 'val'
void Number::set_cst(cst_t val)
{
    // Truncate/extend value if needed
    cst_ = __number_cst_sign_extend(size, val);
}

void Number::set(cst_t val)
{
    cst_ = val;
    if (is_mpz())
    {
        mpz_ = mpz_class((unsigned long int)val);
        adjust_mpz();
    }
}

cst_t Number::get_cst() const
{
    if (!is_mpz())
        return cst_;
    else
    {
        cst_t res = 0;
        for (int i = (sizeof(cst_t)*8) -1; i >= 0; i--)
        {
            res = (res<<1) + mpz_tstbit(mpz_.get_mpz_t(), i);
        }
        return res;
    }
}

ucst_t Number::get_ucst() const
{
    if (!is_mpz())
        return __number_cst_unsign_trunc(size, cst_);
    else
    {
        cst_t res = 0;
        for (int i = (sizeof(cst_t)*8) -1; i >= 0; i--)
        {
            res = (res<<1) + mpz_tstbit(mpz_.get_mpz_t(), i);
        }
        return __number_cst_unsign_trunc(size, res);
    }
}

/// Set the number to multiprecision value 'val'
void Number::set_mpz(cst_t val)
{
    mpz_ = mpz_class((unsigned long int)val);
}

void Number::set_mpz(const std::string& val, int base)
{
    if (base < 2 or base > 62)
        throw expression_exception("Number::set_mpz() needs a base between 2 and 62");
    mpz_ = mpz_class(val, base);
    adjust_mpz();
}

void Number::set_neg(const Number& n)
{
    size = n.size;
    if (n.size <= 64)
        set_cst(-1 * n.cst_);
    else
    {
        mpz_ = - n.mpz_;
        adjust_mpz();
    }
}

void Number::set_not(const Number& n)
{
    size = n.size;
    if (n.size <= 64)
        set_cst(~(ucst_t)(n.cst_));
    else
    {
        mpz_ = ~ n.mpz_;
        adjust_mpz();
    }
}

void Number::set_add(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
        set_cst(n1.cst_ + n2.cst_);
    else
    {
        mpz_ = n1.mpz_ + n2.mpz_;
        adjust_mpz();
    }
}

void Number::set_sub(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
        set_cst(n1.cst_ - n2.cst_);
    else
    {
        mpz_ = n1.mpz_ - n2.mpz_;
        adjust_mpz();
    }
}

void Number::set_and(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
        set_cst((ucst_t)n1.cst_ & (ucst_t)n2.cst_);
    else
    {
        mpz_ = n1.mpz_ & n2.mpz_;
    }
}

void Number::set_mul(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        set_cst(n1.cst_ * n2.cst_);
    }
    else
    {
        mpz_ = n1.mpz_ * n2.mpz_;
        adjust_mpz();
    }
}

void Number::set_xor(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        set_cst(n1.cst_ ^ n2.cst_);
    }
    else
    {
        mpz_ = n1.mpz_ ^ n2.mpz_;
        adjust_mpz();
    }
}

void Number::set_rem(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        set_cst(__number_cst_unsign_trunc(n1.size, n1.cst_) % __number_cst_unsign_trunc(n2.size, n2.cst_));
    }
    else
    {
        mpz_mod(mpz_.get_mpz_t(), n1.mpz_.get_mpz_t(), n2.mpz_.get_mpz_t());
        adjust_mpz();
    }
}

void Number::set_srem(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        set_cst(__number_cst_sign_extend(n1.size, n1.cst_) % __number_cst_sign_extend(n2.size, n2.cst_));
    }
    else
    {
        mpz_t tmp1, tmp2;
        mpz_init_force_signed(tmp1, n1);
        mpz_init_force_signed(tmp2, n2);
        mpz_fdiv_r(mpz_.get_mpz_t(), tmp1, tmp2);
        adjust_mpz();
        mpz_clear(tmp1);
        mpz_clear(tmp2);
    }
}

void Number::set_shl(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        cst_t tmp;
        if (n2.cst_ >= n1.size)
            tmp = 0;
        else
            tmp = ((ucst_t)n1.cst_) << ((ucst_t)n2.cst_);
        set_cst(tmp);
    }
    else
    {
        mpz_mul_2exp(mpz_.get_mpz_t(), n1.mpz_.get_mpz_t(), n2.get_cst());
        adjust_mpz();
    }
}

void Number::set_shr(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        cst_t tmp;
        if (n2.cst_ >= n1.size)
            tmp = 0;
        else
            tmp = n1.get_ucst() >> n2.get_ucst();
        set_cst(tmp);
    }
    else
    {
        mpz_fdiv_q_2exp(mpz_.get_mpz_t(), n1.mpz_.get_mpz_t(), n2.get_cst()); // shr is a div by power of two
        adjust_mpz();
    }
}

void Number::set_sar(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        cst_t tmp;
        if (n2.cst_ >= n1.size)
        {
            if( n1.cst_ & (0x1 << (n1.size-1)))
                tmp = 0xffffffffffffffff;
            else
                tmp = 0;
        }
        else
        {
            tmp = n1.get_cst() >> n2.get_ucst();
        }
        set_cst(tmp);
    }
    else
    {
        mpz_ = 0;
        unsigned int shift = mpz_get_ui(n2.mpz_.get_mpz_t());
        unsigned int i;
        // Copy bits
        for (i = 0; i < size-shift; i++)
        {
            if (mpz_tstbit(n1.mpz_.get_mpz_t(), i + shift) == 1)
                mpz_setbit(mpz_.get_mpz_t(), i);
            else
                mpz_clrbit(mpz_.get_mpz_t(), i);
        }
        // Set the shifted mask to 0 or 0xffff....
        if (mpz_tstbit(n1.mpz_.get_mpz_t(), n1.size-1) == 1)
            for (i = 0; i < shift; i++)
                mpz_setbit(mpz_.get_mpz_t(), size-1-i);
        else 
            for (i = 0; i < shift; i++)
                mpz_clrbit(mpz_.get_mpz_t(), size-1-i);
        // Adjust
        adjust_mpz();
    }
}

void Number::set_or(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        set_cst(n1.cst_ | n2.cst_);
    }
    else
    {
        mpz_ = n1.mpz_ | n2.mpz_;
    }
}

void Number::set_sdiv(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        set_cst(
            __number_cst_sign_extend(n1.size, n1.get_cst()) /
            __number_cst_sign_extend(n2.size, n2.get_cst())
        );
    }
    else
    {
        
        mpz_t tmp1, tmp2;
        mpz_init_force_signed(tmp1, n1);
        mpz_init_force_signed(tmp2, n2); 
        mpz_fdiv_q(mpz_.get_mpz_t(), tmp1, tmp2);
        adjust_mpz();
        mpz_clear(tmp1);
        mpz_clear(tmp2);
    }
}

void Number::set_div(const Number& n1, const Number& n2)
{
    size = n1.size;
    if (size <= 64)
    {
        ucst_t t1 = n1.get_ucst();
        ucst_t t2 = n2.get_ucst();
        set_cst(t1 / t2);
    }
    else
    {
        // TODO: this is signed division, not unsigned ???
        mpz_fdiv_q(mpz_.get_mpz_t(), n1.mpz_.get_mpz_t(), n2.mpz_.get_mpz_t());
        adjust_mpz();
    }
}

void Number::set_extract(const Number& n, unsigned int high, unsigned int low)
{
    cst_t tmp;
    size_t tmp_size = high - low + 1;
    if (n.size <= 64)
    {
        ucst_t mask;
        if( high == 63 )
            mask = 0xffffffffffffffff;
        else
            mask = (((cst_t)1 << (high+1))-1);

        tmp =  ((ucst_t)n.cst_ & mask) >> (ucst_t)low;
        size = tmp_size;
        set_cst(tmp);
    }
    else
    {
        mpz_t tmp;
        mpz_init_set_ui(tmp, 0); // init tmp mpz
        // Copy bit by bit
        for (unsigned int i = 0; i < tmp_size; i++)
        {
            if (mpz_tstbit(n.mpz_.get_mpz_t(), i+low) == 1)
                mpz_setbit(tmp, i);
            else
                mpz_clrbit(tmp, i);
        }

        size = tmp_size;
        mpz_ = mpz_class(tmp);
        mpz_clear(tmp); // clear tmp mpz
        // adjust_mpz(); no need to adjust, we set bits manually
        // If result size on 64 bits or less, transform into cst, not mpz 
        if (this->size <= 64)
        {
            set_cst(mpz_get_ui(mpz_.get_mpz_t()));
        }
    }
}

void Number::set_concat(const Number& n1, const Number& n2)
{
    size_t tmp_size = n1.size + n2.size; // Use tmp size because *this might be n1 or n2
    if (tmp_size <= 64)
    {
        cst_t tmp = n2.cst_;
        // Mask higher bits before doing OR
        tmp &= (((ucst_t)1<<(ucst_t)n2.size)-1);
        // Do OR to set higher part
        tmp |= (ucst_t)n1.cst_ << (ucst_t)n2.size;
        size = tmp_size;
        set_cst(tmp);
    }
    else
    {
        // Set higher (set then shift)
        if (n1.is_mpz())
            mpz_ = n1.mpz_;
        else
            mpz_ = mpz_class((unsigned long int)n1.get_ucst());
        mpz_mul_2exp(mpz_.get_mpz_t(), mpz_.get_mpz_t(), n2.size); // shift left
        // Set lower
        if (n2.is_mpz())
            mpz_ior(mpz_.get_mpz_t(), mpz_.get_mpz_t(), n2.mpz_.get_mpz_t());
        else
        {
            mpz_t t1;
            mpz_init_set_ui(t1, (ucst_t)n2.get_ucst());
            mpz_ior(mpz_.get_mpz_t(), mpz_.get_mpz_t(), t1);
            mpz_clear(t1);
        }
        size = tmp_size;
        adjust_mpz();
    }
}

void Number::set_popcount(int dest_size, const Number& n)
{
    size = dest_size;
    ucst_t res = 0;
    if (n.size <= 64)
    {
        for (int i = 0; i < n.size; i++)
        {
            res += (n.cst_ >> i) & 1;
        }
    }
    else
    {
        for (int i = 0; i < n.size; i++)
        {
            res += mpz_tstbit(n.mpz_.get_mpz_t(), i);
        }
    }

    // Assign res
    if (size <= 64)
        set_cst(res);
    else
        set_mpz(res);
}

void Number::set_zext(int ext_size, const Number& n)
{
    this->size = ext_size;
    if (ext_size <= 64)
    {
        cst_t tmp =  ((ucst_t)__number_cst_unsign_trunc(n.size, n.cst_));
        set_cst(tmp);
    }
    else
    {
        if (n.is_mpz())
            mpz_ = n.mpz_;
        else
            mpz_ = (unsigned long int)n.get_ucst();
        // Extend higher bits to zero
        for (unsigned int i = n.size; i < ext_size; i++)
        {
                mpz_clrbit(mpz_.get_mpz_t(), i);
        }
    }
}

void Number::set_sext(int ext_size, const Number& n)
{
    this->size = ext_size;
    if (ext_size <= 64)
    {
        cst_t tmp =  ((ucst_t)__number_cst_unsign_trunc(n.size, n.cst_));
        if (tmp & (1U << (n.size-1)))
        {
            // hsb is 1 add mask
            tmp |= (__number_cst_mask(ext_size - n.size) << n.size);
        }
        set_cst(tmp);
    }
    else
    {
        if (n.is_mpz())
            mpz_ = n.mpz_;
        else
            mpz_ = (unsigned long int)n.get_ucst();
        // Extend higher bits
        bool hsb_set = mpz_tstbit(mpz_.get_mpz_t(), n.size-1);
        for (unsigned int i = n.size; i < ext_size; i++)
        {
            if (hsb_set)
                mpz_setbit(mpz_.get_mpz_t(), i);
            else
                mpz_clrbit(mpz_.get_mpz_t(), i);
        }
        adjust_mpz();
    }
}

void Number::set_mask(int mask_size)
{
    if (size <= 64)
    {
        set_cst(__number_cst_mask(mask_size));
    }
    else
    {
        for (unsigned int i = 0; i < mask_size; i++)
        {
                mpz_setbit(mpz_.get_mpz_t(), i);
        }
    }
}

void Number::set_overwrite(const Number& n1, const Number& n2, int lb)
{
    ucst_t mask;
    ucst_t res;

    if (n2.size + lb > n1.size)
        throw expression_exception("Number::set_overwrite(): src number is too big to fit in dest!");
    if (n2.size == n1.size)
    {
        *this = n2;
        return;
    }

    if (n1.size <= 64)
    {
        mask = ~ ((ucst_t)__number_cst_mask(n2.size) << (ucst_t)lb);
        res = (n1.cst_ & mask) | (__number_cst_unsign_trunc(n2.size, n2.cst_) << lb);

        // Set size at the end because n2 might be a reference to 'this'
        this->size = n1.size;
        set_cst(res);
    }
    else
    {
        // Make copies in case n1 or n2 is a reference to 'this'
        mpz_class tmp = n1.mpz_;
        mpz_class tmp2 = n2.is_mpz() ? n2.mpz_ : (unsigned long int)n2.get_ucst();
        for (int i = 0; i < n2.size; i++)
        {
            if (mpz_tstbit(tmp2.get_mpz_t(), i) == 1)
            {
                mpz_setbit(tmp.get_mpz_t(), i + lb);
            }
            else
            {
                mpz_clrbit(tmp.get_mpz_t(), i + lb);
            }
        }
        mpz_ = tmp;
        this->size = n1.size;
    }
}

bool Number::sless_than(const Number& other) const
{
    if (size <= 64)
    {
        return (cst_t)cst_ < (cst_t)other.cst_;
    }
    else
    {
        // mpz_cmp returns a positive value if op1 > op2, 
        // zero if op1 = op2, or a negative value if op1 < op2
        return mpz_cmp(mpz_.get_mpz_t(),  other.mpz_.get_mpz_t()) < 0;
    }
}

bool Number::slessequal_than(const Number& other) const
{
    if (size <= 64)
    {
        return (cst_t)cst_ <= (cst_t)other.cst_;
    }
    else
    {
        // mpz_cmp returns a positive value if op1 > op2, 
        // zero if op1 = op2, or a negative value if op1 < op2
        return mpz_cmp(mpz_.get_mpz_t(), other.mpz_.get_mpz_t()) <= 0;
    }
}

bool Number::less_than(const Number& other) const
{
    if (size <= 64)
    {
        return (ucst_t)cst_ < (ucst_t)other.cst_;
    }
    else
    {   
        if (mpz_sgn(mpz_.get_mpz_t()) == -1)
        {
            // this is a negative number
            if (mpz_sgn(other.mpz_.get_mpz_t()) == -1)
            {
                // both are negative, so the bigger one is also
                // the bigger one when interpreted as unsigned
                return mpz_cmp(mpz_.get_mpz_t(), other.mpz_.get_mpz_t()) < 0;
            }
            else
            {
                // other one is positive so this one will be bigger (MSB == 1)
                return false;
            }
        }
        else
        {
            // this is a positive number
            if (mpz_sgn(other.mpz_.get_mpz_t()) == -1)
            {
                // other is negative and will always be bigger (MSB == 1)
                return true;
            }
            else
            {
                // both are positive
                return mpz_cmp(mpz_.get_mpz_t(), other.mpz_.get_mpz_t()) < 0;
            }
        }
    }
}

bool Number::lessequal_than(const Number& other) const
{
    if (size <= 64)
    {
        return (ucst_t)cst_ <= (ucst_t)other.cst_;
    }
    else
    {   
        if (mpz_sgn(mpz_.get_mpz_t()) == -1)
        {
            // this is a negative number
            if (mpz_sgn(other.mpz_.get_mpz_t()) == -1)
            {
                // both are negative, so the bigger one is also
                // the bigger one when interpreted as unsigned
                return mpz_cmp(mpz_.get_mpz_t(), other.mpz_.get_mpz_t()) <= 0;
            }
            else
            {
                // other one is positive so this one will be bigger (MSB == 1)
                return false;
            }
        }
        else
        {
            // this is a positive number
            if (mpz_sgn(other.mpz_.get_mpz_t()) == -1)
            {
                // other is negative and will always be bigger (MSB == 1)
                return true;
            }
            else
            {
                // both are positive
                return mpz_cmp(mpz_.get_mpz_t(), other.mpz_.get_mpz_t()) <= 0;
            }
        }
    }
}


bool Number::equal_to(const Number& other) const
{
    if (size <= 64)
    {
        return (cst_t)cst_ == (cst_t)other.cst_;
    }
    else
    {
        // mpz_cmp returns a positive value if op1 > op2, 
        // zero if op1 = op2, or a negative value if op1 < op2
        return mpz_cmp(mpz_.get_mpz_t(), other.mpz_.get_mpz_t()) == 0;
    }
}



bool Number::is_mpz() const
{
    return size > 64;
}

std::ostream& operator<<(std::ostream& os, const Number& n)
{
    n.print(os);
    return os;
}

const char* __hex_format = "%Zx";
const char* __dec_format = "%Zd";

void Number::print(std::ostream& os, bool decimal) const
{
    if (is_mpz())
    {
        char str[1000];  // Enough to store the string representation
                        // of a number on 512 bits
        //mpz_get_str(str, 16,n. mpz_); // Base 16
        const char* fmt = decimal? __dec_format : __hex_format; 
        gmp_snprintf(str, sizeof(str), fmt, mpz_.get_mpz_t());
        if (not decimal)
            os << "0x";
        os << std::string(str);
    }
    else
        os << std::hex << std::showbase << get_ucst() << std::noshowbase;
}

} // namespace maat
