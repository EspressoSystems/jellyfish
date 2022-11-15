// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#if defined(__CUDA_ARCH__) && !defined(__MONT_T_CUH__)
# define __MONT_T_CUH__

# include <cstddef>
#include <cstdint>

# define inline __device__ __forceinline__
# ifdef __GNUC__
#  define asm __asm__ __volatile__
# else
#  define asm asm volatile
# endif

//
// To instantiate declare modulus as __device__ __constant___ const and
// complement it with its factual bit-length and the corresponding 32-bit
// Motgomery factor. Bit-length has to be such that (N+31)/32 is even
// and not less than 4.
//
// Special note about M0 being declared as uint32_t& [as opposed to just
// uint32_t]. It was noted that if M0 is 0xffffffff, CUDA compiler
// generates suboptimal code for Montgomery reduction. The way to work
// around the problem is to prevent compiler from viewing it as constant.
// For this reason it's suggested to declare the parameter as following:
//
//    __device__ __constant__ /*const*/ my_M0 = <literal>;
//
template<const size_t N, const uint32_t MOD[(N+31)/32], const uint32_t& M0,
         const uint32_t RR[(N+31)/32], const uint32_t ONE[(N+31)/32]>
class mont_t {
public:
    static const size_t nbits = N;
private:
    static const size_t n = (N+31)/32;
    uint32_t even[n];

    static inline void mul_n(uint32_t* acc, const uint32_t* a, uint32_t bi,
                             size_t n=n)
    {
        for (size_t j = 0; j < n; j += 2)
            asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"
                : "=r"(acc[j]), "=r"(acc[j+1])
                : "r"(a[j]), "r"(bi));
    }

    static inline void cmad_n(uint32_t* acc, const uint32_t* a, uint32_t bi,
                              size_t n=n)
    {
        asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"
            : "+r"(acc[0]), "+r"(acc[1])
            : "r"(a[0]), "r"(bi));
        for (size_t j = 2; j < n; j += 2)
            asm("madc.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"
                : "+r"(acc[j]), "+r"(acc[j+1])
                : "r"(a[j]), "r"(bi));
        // return carry flag
    }

    class wide_t {
    private:
        uint32_t even[2*n];

    private:
        static inline void mad_row(uint32_t* odd, uint32_t* even,
                                   const uint32_t* a, uint32_t bi, size_t n=n)
        {
            cmad_n(odd, a+1, bi, n-2);
            asm("madc.lo.cc.u32 %0, %2, %3, 0; madc.hi.u32 %1, %2, %3, 0;"
                : "=r"(odd[n-2]), "=r"(odd[n-1])
                : "r"(a[n-1]), "r"(bi));

            cmad_n(even, a, bi, n);
            asm("addc.u32 %0, %0, 0;" : "+r"(odd[n-1]));
        }

    public:
        inline wide_t(const mont_t& a, const mont_t& b)     //// |a|*|b|
        {
            size_t i = 0;
            uint32_t odd[2*n-2];

            mul_n(even, &a[0], b[0]);
            mul_n(odd,  &a[1], b[0]);
            ++i; mad_row(&even[i+1], &odd[i-1], &a[0], b[i]);

            #pragma unroll
            while (i < n-2) {
                ++i; mad_row(&odd[i],    &even[i],  &a[0], b[i]);
                ++i; mad_row(&even[i+1], &odd[i-1], &a[0], b[i]);
            }

            // merge |even| and |odd|
            asm("add.cc.u32 %0, %0, %1;" : "+r"(even[1]) : "r"(odd[0]));
            for (i = 1; i < 2*n-2; i++)
                asm("addc.cc.u32 %0, %0, %1;" : "+r"(even[i+1]) : "r"(odd[i]));
            asm("addc.u32 %0, %0, 0;" : "+r"(even[i+1]));
        }

    private:
        static inline void qad_row(uint32_t* odd, uint32_t* even,
                                   const uint32_t* a, uint32_t bi, size_t n)
        {
            cmad_n(odd, a, bi, n-2);
            asm("madc.lo.cc.u32 %0, %2, %3, 0; madc.hi.u32 %1, %2, %3, 0;"
                : "=r"(odd[n-2]), "=r"(odd[n-1])
                : "r"(a[n-2]), "r"(bi));

            cmad_n(even, a+1, bi, n-2);
            asm("addc.u32 %0, %0, 0;" : "+r"(odd[n-1]));
        }

    public:
        inline wide_t(const mont_t& a)                      //// |a|**2
        {
            size_t i = 0, j;
            uint32_t odd[2*n-2];

            // perform |a[i]|*|a[j]| for all j>i
            mul_n(even+2, &a[2], a[0], n-2);
            mul_n(odd,    &a[1], a[0], n);

            #pragma unroll
            while (i < n-4) {
                ++i; mad_row(&even[2*i+2], &odd[2*i], &a[i+1], a[i], n-i-1);
                ++i; qad_row(&odd[2*i], &even[2*i+2], &a[i+1], a[i], n-i);
            }

            asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"
                : "=r"(even[2*n-4]), "=r"(even[2*n-3])
                : "r"(a[n-1]), "r"(a[n-3]));
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.cc.u32 %1, %2, %3, %1;"
                : "+r"(odd[2*n-6]), "+r"(odd[2*n-5])
                : "r"(a[n-2]), "r"(a[n-3]));
            asm("addc.u32 %0, %0, 0;" : "+r"(even[2*n-3]));

            asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"
                : "=r"(odd[2*n-4]), "=r"(odd[2*n-3])
                : "r"(a[n-1]), "r"(a[n-2]));

            // merge |even[2:]| and |odd[1:]|
            asm("add.cc.u32 %0, %0, %1;" : "+r"(even[2]) : "r"(odd[1]));
            for (j = 2; j < 2*n-3; j++)
                asm("addc.cc.u32 %0, %0, %1;" : "+r"(even[j+1]) : "r"(odd[j]));
            asm("addc.u32 %0, %1, 0;" : "+r"(even[j+1]) : "r"(odd[j]));

            // double |even|
            even[0] = 0;
            asm("add.cc.u32 %0, %1, %1;" : "=r"(even[1]) : "r"(odd[0]));
            for (j = 2; j < 2*n-1; j++)
                asm("addc.cc.u32 %0, %0, %0;" : "+r"(even[j]));
            asm("addc.u32 %0, 0, 0;" : "=r"(even[j]));

            // accumulate "diagonal" |a[i]|*|a[i]| product
            i = 0;
            asm("mad.lo.cc.u32 %0, %2, %2, %0; madc.hi.cc.u32 %1, %2, %2, %1;"
                : "+r"(even[2*i]), "+r"(even[2*i+1])
                : "r"(a[i]));
            for (++i; i < n; i++)
                asm("madc.lo.cc.u32 %0, %2, %2, %0; madc.hi.cc.u32 %1, %2, %2, %1;"
                    : "+r"(even[2*i]), "+r"(even[2*i+1])
                    : "r"(a[i]));
        }
    };

private:
    inline operator const uint32_t*() const             { return even;    }
    inline operator uint32_t*()                         { return even;    }

public:
    inline uint32_t& operator[](size_t i)               { return even[i]; }
    inline const uint32_t& operator[](size_t i) const   { return even[i]; }
    inline size_t len() const                           { return n;       }

    inline mont_t() {}
    inline mont_t(const uint32_t *p)
    {
        for (size_t i = 0; i < n; i++)
            even[i] = p[i];
    }

    inline void store(uint32_t *p) const
    {
        for (size_t i = 0; i < n; i++)
            p[i] = even[i];
    }

    inline mont_t& operator+=(const mont_t& b)
    {
        size_t i;
        uint32_t tmp[n+1];
        asm("{ .reg.pred %top;");

        asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(b[0]));
        for (i = 1; i < n; i++)
            asm("addc.cc.u32 %0, %0, %1;" : "+r"(even[i]) : "r"(b[i]));
        if (N%32 == 0)
            asm("addc.u32 %0, 0, 0;" : "=r"(tmp[n]));

        asm("sub.cc.u32 %0, %1, %2;" : "=r"(tmp[0]) : "r"(even[0]), "r"(MOD[0]));
        for (i = 1; i < n; i++)
            asm("subc.cc.u32 %0, %1, %2;" : "=r"(tmp[i]) : "r"(even[i]), "r"(MOD[i]));
        if (N%32 == 0)
            asm("subc.u32 %0, %0, 0; setp.eq.u32 %top, %0, 0;" : "+r"(tmp[n]));
        else
            asm("subc.u32 %0, 0, 0; setp.eq.u32 %top, %0, 0;" : "=r"(tmp[n]));

        for (i = 0; i < n; i++)
            asm("@%top mov.b32 %0, %1;" : "+r"(even[i]) : "r"(tmp[i]));

        asm("}");
        return *this;
    }
    friend inline mont_t operator+(mont_t a, const mont_t& b)
    {   return a += b;   }

    inline mont_t& operator<<=(unsigned l)
    {
        size_t i;
        uint32_t tmp[n+1];
        asm("{ .reg.pred %top;");

        while (l--) {
            asm("add.cc.u32 %0, %0, %0;" : "+r"(even[0]));
            for (i = 1; i < n; i++)
                asm("addc.cc.u32 %0, %0, %0;" : "+r"(even[i]));
            if (N%32 == 0)
                asm("addc.u32 %0, 0, 0;" : "=r"(tmp[n]));

            asm("sub.cc.u32 %0, %1, %2;" : "=r"(tmp[0]) : "r"(even[0]), "r"(MOD[0]));
            for (i = 1; i < n; i++)
                asm("subc.cc.u32 %0, %1, %2;" : "=r"(tmp[i]) : "r"(even[i]), "r"(MOD[i]));
            if (N%32 == 0)
                asm("subc.u32 %0, %0, 0; setp.eq.u32 %top, %0, 0;" : "+r"(tmp[n]));
            else
                asm("subc.u32 %0, 0, 0; setp.eq.u32 %top, %0, 0;" : "=r"(tmp[n]));

            for (i = 0; i < n; i++)
                asm("@%top mov.b32 %0, %1;" : "+r"(even[i]) : "r"(tmp[i]));
        }

        asm("}");
        return *this;
    }
    friend inline mont_t operator<<(mont_t a, unsigned l)
    {   return a <<= l;   }

    inline mont_t& operator>>=(unsigned r)
    {
        size_t i;
        uint32_t tmp[n+1];

        while (r--) {
            tmp[n] = 0 - (even[0]&1);
            for (i = 0; i < n; i++)
                tmp[i] = MOD[i] & tmp[n];

            asm("add.cc.u32 %0, %0, %1;" : "+r"(tmp[0]) : "r"(even[0]));
            for (i = 1; i < n; i++)
                asm("addc.cc.u32 %0, %0, %1;" : "+r"(tmp[i]) : "r"(even[i]));
            if (N%32 == 0)
                asm("addc.u32 %0, 0, 0;" : "=r"(tmp[n]));

            for (i = 0; i < n-1; i++)
                asm("shf.r.wrap.b32 %0, %1, %2, 1;"
                    : "=r"(even[i]) : "r"(tmp[i]), "r"(tmp[i+1]));
            if (N%32 == 0)
                asm("shf.r.wrap.b32 %0, %1, %2, 1;"
                    : "=r"(even[i]) : "r"(tmp[i]), "r"(tmp[i+1]));
            else
                even[i] = tmp[i] >> 1;
        }

        return *this;
    }
    friend inline mont_t operator>>(mont_t a, unsigned r)
    {   return a >>= r;   }

    inline mont_t& operator-=(const mont_t& b)
    {
        size_t i;
        uint32_t tmp[n], borrow;

        asm("sub.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(b[0]));
        for (i = 1; i < n; i++)
            asm("subc.cc.u32 %0, %0, %1;" : "+r"(even[i]) : "r"(b[i]));
        asm("subc.u32 %0, 0, 0;" : "=r"(borrow));

        asm("add.cc.u32 %0, %1, %2;" : "=r"(tmp[0]) : "r"(even[0]), "r"(MOD[0]));
        for (i = 1; i < n-1; i++)
            asm("addc.cc.u32 %0, %1, %2;" : "=r"(tmp[i]) : "r"(even[i]), "r"(MOD[i]));
        asm("addc.u32 %0, %1, %2;" : "=r"(tmp[i]) : "r"(even[i]), "r"(MOD[i]));

        asm("{ .reg.pred %top; setp.ne.u32 %top, %0, 0;" :: "r"(borrow));
        for (i = 0; i < n; i++)
            asm("@%top mov.b32 %0, %1;" : "+r"(even[i]) : "r"(tmp[i]));
        asm("}");

        return *this;
    }
    friend inline mont_t operator-(mont_t a, const mont_t& b)
    {   return a -= b;   }

#if 1
    inline mont_t& cneg(bool flag)
    {
        size_t i;
        uint32_t tmp[n], is_zero = even[0];
        asm("{ .reg.pred %flag; setp.ne.u32 %flag, %0, 0;" :: "r"((int)flag));

        asm("sub.cc.u32 %0, %1, %2;" : "=r"(tmp[0]) : "r"(MOD[0]), "r"(even[0]));
        for (i = 1; i < n; i++) {
            asm("subc.cc.u32 %0, %1, %2;" : "=r"(tmp[i]) : "r"(MOD[i]), "r"(even[i]));
            asm("or.b32 %0, %0, %1;" : "+r"(is_zero) : "r"(even[i]));
        }

        asm("@%flag setp.ne.u32 %flag, %0, 0;" :: "r"(is_zero));

        for (i = 0; i < n; i++)
            asm("@%flag mov.b32 %0, %1;" : "+r"(even[i]) : "r"(tmp[i]));

        asm("}");
        return *this;
    }
    friend inline mont_t cneg(mont_t a, bool flag)
    {   return a.cneg(flag);   }
#else
    friend inline mont_t cneg(const mont_t& a, bool flag)
    {
        size_t i;
        uint32_t tmp[n], is_zero = a[0];
        asm("{ .reg.pred %flag; setp.ne.u32 %flag, %0, 0;" :: "r"((int)flag));
        asm("sub.cc.u32 %0, %1, %2;" : "=r"(tmp[0]) : "r"(MOD[0]), "r"(a[0]));
        for (i = 1; i < n; i++) {
            asm("subc.cc.u32 %0, %1, %2;" : "=r"(tmp[i]) : "r"(MOD[i]), "r"(a[i]));
            asm("or.b32 %0, %0, %1;" : "+r"(is_zero) : "r"(a[i]));
        }
        asm("@%flag setp.ne.u32 %flag, %0, 0;" :: "r"(is_zero));
        mont_t ret = a;
        for (i = 0; i < n; i++)
            asm("@%flag mov.b32 %0, %1;" : "+r"(ret[i]) : "r"(tmp[i]));
        asm("}");
        return ret;
    }
#endif
    inline mont_t operator-() const
    {   return cneg(*this, true);   }

private:
    static inline void madc_n_rshift(uint32_t* odd, const uint32_t *a, uint32_t bi)
    {
        for (size_t j = 0; j < n-2; j += 2)
            asm("madc.lo.cc.u32 %0, %2, %3, %4; madc.hi.cc.u32 %1, %2, %3, %5;"
                : "=r"(odd[j]), "=r"(odd[j+1])
                : "r"(a[j]), "r"(bi), "r"(odd[j+2]), "r"(odd[j+3]));
        asm("madc.lo.cc.u32 %0, %2, %3, 0; madc.hi.u32 %1, %2, %3, 0;"
            : "=r"(odd[n-2]), "=r"(odd[n-1])
            : "r"(a[n-2]), "r"(bi));
    }

    static inline void mad_n_redc(uint32_t *even, uint32_t* odd,
                                  const uint32_t *a, uint32_t bi, bool first=false)
    {
        if (first) {
            mul_n(odd, a+1, bi);
            mul_n(even, a,  bi);
        } else {
            asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(odd[1]));
            madc_n_rshift(odd, a+1, bi);
            cmad_n(even, a, bi);
            asm("addc.u32 %0, %0, 0;" : "+r"(odd[n-1]));
        }

        uint32_t mi = even[0] * M0;

        cmad_n(odd, MOD+1, mi);
        cmad_n(even, MOD,  mi);
        asm("addc.u32 %0, %0, 0;" : "+r"(odd[n-1]));
    }

public:
    friend inline mont_t operator*(const mont_t& a, const mont_t& b)
    {
        if (&a == &b && 0) {
            union { wide_t w; mont_t s[2]; } ret = { wide_t(a) };
            ret.s[0].mul_by_1();
            return ret.s[0] += ret.s[1];
        } else if (N%32 == 0) {
            union { wide_t w; mont_t s[2]; } ret = { wide_t(a, b) };
            ret.s[0].mul_by_1();
            return ret.s[0] += ret.s[1];
        } else {
            mont_t even;
            uint32_t odd[n+1];
            size_t i;
            asm("{ .reg.pred %top;");

            #pragma unroll
            for (i = 0; i < n; i += 2) {
                mad_n_redc(&even[0], &odd[0], &a[0], b[i], i==0);
                mad_n_redc(&odd[0], &even[0], &a[0], b[i+1]);
            }

            // merge |even| and |odd|
            asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(odd[1]));
            for (i = 1; i < n-1; i++)
                asm("addc.cc.u32 %0, %0, %1;" : "+r"(even[i]) : "r"(odd[i+1]));
            asm("addc.u32 %0, %0, 0;" : "+r"(even[i]));

            // final subtraction
            asm("sub.cc.u32 %0, %1, %2;" : "=r"(odd[0]) : "r"(even[0]), "r"(MOD[0]));
            for (i = 1; i < n; i++)
                asm("subc.cc.u32 %0, %1, %2;" : "=r"(odd[i]) : "r"(even[i]), "r"(MOD[i]));
            asm("subc.u32 %0, 0, 0; setp.eq.u32 %top, %0, 0;" : "=r"(odd[i]));

            for (i = 0; i < n; i++)
                asm("@%top mov.b32 %0, %1;" : "+r"(even[i]) : "r"(odd[i]));

            asm("}");
            return even;
        }
    }
    inline mont_t& operator*=(const mont_t& a)
    {   return *this = *this * a;   }

    inline mont_t& sqr()
    {
        union { wide_t w; mont_t s[2]; } ret = { wide_t(*this) };
        ret.s[0].mul_by_1();
        return *this = ret.s[0] + ret.s[1];
    }
    // simplified exponentiation, but mind the ^ operator's precedence!
    inline mont_t& operator^=(unsigned p)
    {
        if (p < 2)
            asm("trap;");

        mont_t sqr = *this;
        for (; (p&1) == 0; p >>= 1)
            sqr.sqr();
        *this = sqr;
        for (p >>= 1; p; p >>= 1) {
            sqr.sqr();
            if (p&1)
                *this *= sqr;
        }
        return *this;
    }
    friend inline mont_t operator^(mont_t a, unsigned p)
    {   return a ^= p;   }
    inline mont_t operator()(unsigned p)
    {   return *this^p;   }
    friend inline mont_t sqr(const mont_t& a)
    {   return a^2;   }

    inline void to()    { mont_t t = *this; t *= RR;      *this = t; }
    inline void from()  { mont_t t = *this; t.mul_by_1(); *this = t; }

    static inline const mont_t& one()
    {   return *reinterpret_cast<const mont_t*>(ONE);   }

    inline bool is_zero() const
    {
        size_t i;
        uint32_t is_zero = even[0];

        for (i = 1; i < n; i++)
            asm("or.b32 %0, %0, %1;" : "+r"(is_zero) : "r"(even[i]));

        asm("set.eq.u32.u32 %0, %0, 0;" : "+r"(is_zero));

        return is_zero;
    }

    inline void zero()
    {
        if (n%4 == 0) {
            uint4* p = (uint4*)even;
            for (size_t i=0; i<sizeof(even)/sizeof(*p); i++)
                p[i] = uint4{0, 0, 0, 0};
        } else {
            uint64_t* p = (uint64_t*)even;
            for (size_t i=0; i<sizeof(even)/sizeof(uint64_t); i++)
                p[i] = 0;
        }
    }

    friend inline mont_t czero(const mont_t& a, int set_z)
    {
        mont_t ret;
        asm("{ .reg.pred %set_z;");
        asm("setp.ne.s32 %set_z, %0, 0;" : : "r"(set_z));
        for (size_t i = 0; i < n; i++)
            asm("selp.u32 %0, 0, %1, %set_z;" : "=r"(ret[i]) : "r"(a[i]));
        asm("}");
        return ret;
    }

    static inline mont_t csel(const mont_t& a, const mont_t& b, int sel_a)
    {
        mont_t ret;
        asm("{ .reg.pred %sel_a;");
        asm("setp.ne.s32 %sel_a, %0, 0;" : : "r"(sel_a));
        for (size_t i = 0; i < n; i++)
            asm("selp.u32 %0, %1, %2, %sel_a;" : "=r"(ret[i]) : "r"(a[i]), "r"(b[i]));
        asm("}");
        return ret;
    }

private:
    static inline void mul_by_1_row(uint32_t* even, uint32_t* odd, bool first=false)
    {
        uint32_t mi;

        if (first) {
            mi = even[0] * M0;
            mul_n(odd, MOD+1, mi);
            cmad_n(even, MOD,  mi);
            asm("addc.u32 %0, %0, 0;" : "+r"(odd[n-1]));
        } else {
            asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(odd[1]));
# if 1      // do we trust the compiler to *not* touch the carry flag here?
            mi = even[0] * M0;
# else
            asm("mul.lo.u32 %0, %1, %2;" : "=r"(mi) : "r"(even[0]), "r"(M0));
# endif
            madc_n_rshift(odd, MOD+1, mi);
            cmad_n(even, MOD, mi);
            asm("addc.u32 %0, %0, 0;" : "+r"(odd[n-1]));
        }
    }
    inline void mul_by_1()
    {
        uint32_t odd[n];
        size_t i;

        #pragma unroll
        for (i = 0; i < n; i += 2) {
            mul_by_1_row(&even[0], &odd[0], i==0);
            mul_by_1_row(&odd[0], &even[0]);
        }

        asm("add.cc.u32 %0, %0, %1;" : "+r"(even[0]) : "r"(odd[1]));
        for (i = 1; i < n-1; i++)
            asm("addc.cc.u32 %0, %0, %1;" : "+r"(even[i]) : "r"(odd[i+1]));
        asm("addc.u32 %0, %0, 0;" : "+r"(even[i]));
    }
};

# undef inline
# undef asm
#endif