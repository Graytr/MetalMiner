// NexaPow (Nexa) kernels, part 1 of 4: field arithmetic mod p = 2^256 - 0x1000003D1 (secp256k1).
// The library is nexapow_field, nexapow_sha, nexapow_ec, nexapow (in that order); see nexapow.metal.
//
// Field elements: 8 x 32-bit limbs, little-endian limb order, lazily reduced (any value below 2^256 that is
// congruent mod p). Limb products are ulong(a) * ulong(b) (one 32x32 -> 64 multiply on Apple GPUs);
// 2^256 = 0x1000003D1 (mod p) folds the high half cheaply. Squaring computes the 28 cross products once,
// doubles them, and adds the 8 squares (36 products instead of 64).
// NEXAPOW_FUSED=1 selects the older multiply that folds both adds into one 64-bit expression (slower here).

#ifndef NEXAPOW_W
#define NEXAPOW_W 16
#endif
#ifndef NEXAPOW_WINDOWS
#define NEXAPOW_WINDOWS 17
#endif
#define NEXAPOW_TSIZE (1u << (NEXAPOW_W - 1))
#define NEXAPOW_MASK ((1u << NEXAPOW_W) - 1u)

struct np_fe { uint v[8]; };
struct np_jac { np_fe x, y, z; };

static inline np_fe np_fe_zero() { np_fe r; for (int i = 0; i < 8; i++) r.v[i] = 0; return r; }
static inline np_fe np_fe_one() { np_fe r = np_fe_zero(); r.v[0] = 1; return r; }

// 512-bit t (16 limbs) to a value below 2^256 congruent mod p.
static inline np_fe np_fe_reduce(thread const uint *t)
{
    np_fe r;
    ulong c = (ulong)t[8] * 977ul + (ulong)t[0];
    r.v[0] = (uint)c;
    c >>= 32;
    #pragma unroll
    for (int j = 1; j < 8; j++) {
        c += (ulong)t[8 + j] * 977ul + (ulong)t[j] + (ulong)t[7 + j];
        r.v[j] = (uint)c;
        c >>= 32;
    }
    ulong top = c + (ulong)t[15];   // what's left above 2^256, below 2^33
    c = top * 977ul + (ulong)r.v[0];
    r.v[0] = (uint)c;
    c >>= 32;
    c += top + (ulong)r.v[1];
    r.v[1] = (uint)c;
    c >>= 32;
    #pragma unroll
    for (int j = 2; j < 8; j++) {
        c += (ulong)r.v[j];
        r.v[j] = (uint)c;
        c >>= 32;
    }
    if (c != 0) {   // wrapped past 2^256, so r is now tiny: add 0x1000003D1 once more
        c = (ulong)r.v[0] + 977ul;
        r.v[0] = (uint)c;
        r.v[1] += 1u + (uint)(c >> 32);
    }
    return r;
}

// Full 512-bit product of two 256-bit values (operand scanning, one carry chain per row).
static inline void np_mul_wide(thread const uint *a, thread const uint *b, thread uint *t)
{
#if NEXAPOW_FUSED
    ulong c = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        c = (ulong)a[0] * (ulong)b[j] + (c >> 32);
        t[j] = (uint)c;
    }
    t[8] = (uint)(c >> 32);
    #pragma unroll
    for (int i = 1; i < 8; i++) {
        c = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            c = (ulong)a[i] * (ulong)b[j] + ((ulong)t[i + j] + (c >> 32));
            t[i + j] = (uint)c;
        }
        t[i + 8] = (uint)(c >> 32);
    }
#else
    uint c = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        ulong p = (ulong)a[0] * (ulong)b[j];
        p += (ulong)c;
        t[j] = (uint)p;
        c = (uint)(p >> 32);
    }
    t[8] = c;
    #pragma unroll
    for (int i = 1; i < 8; i++) {
        c = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            ulong p = (ulong)a[i] * (ulong)b[j];
            p += (ulong)t[i + j];
            p += (ulong)c;
            t[i + j] = (uint)p;
            c = (uint)(p >> 32);
        }
        t[i + 8] = c;
    }
#endif
}

// Full 512-bit square: cross products once, doubled, plus the diagonal.
static inline void np_sqr_wide(thread const uint *a, thread uint *t)
{
    t[0] = 0;
    uint c = 0;
    #pragma unroll
    for (int j = 1; j < 8; j++) {          // row 0: a0 * a1..a7 into t1..t7
        ulong p = (ulong)a[0] * (ulong)a[j];
        p += (ulong)c;
        t[j] = (uint)p;
        c = (uint)(p >> 32);
    }
    t[8] = c;
    #pragma unroll
    for (int i = 1; i < 7; i++) {          // row i: a_i * a_(i+1)..a7 into t(2i+1)..t(i+7), carry to t(i+8)
        c = 0;
        #pragma unroll
        for (int j = i + 1; j < 8; j++) {
            ulong p = (ulong)a[i] * (ulong)a[j];
            p += (ulong)t[i + j];
            p += (ulong)c;
            t[i + j] = (uint)p;
            c = (uint)(p >> 32);
        }
        t[i + 8] = c;
    }
    t[15] = 0;
    // double the cross products (they are below 2^511)
    #pragma unroll
    for (int k = 15; k > 0; k--) t[k] = (t[k] << 1) | (t[k - 1] >> 31);
    t[0] = 0;
    // add the squares a_i^2 at limb 2i
    ulong s = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        ulong d = (ulong)a[i] * (ulong)a[i];
        s += (ulong)t[2 * i] + (ulong)(uint)d;
        t[2 * i] = (uint)s;
        s >>= 32;
        s += (ulong)t[2 * i + 1] + (d >> 32);
        t[2 * i + 1] = (uint)s;
        s >>= 32;
    }
}

static inline np_fe np_fe_mul(np_fe a, np_fe b)
{
    uint t[16];
    np_mul_wide(a.v, b.v, t);
    return np_fe_reduce(t);
}

static inline np_fe np_fe_sqr(np_fe a)
{
    uint t[16];
    np_sqr_wide(a.v, t);
    return np_fe_reduce(t);
}

static inline np_fe np_fe_add(np_fe a, np_fe b)
{
    np_fe r;
    ulong c = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        c += (ulong)a.v[j] + (ulong)b.v[j];
        r.v[j] = (uint)c;
        c >>= 32;
    }
    uint m = (uint)c;   // carried out of 2^256: add 0x1000003D1
    c = (ulong)r.v[0] + (ulong)(m * 977u);
    r.v[0] = (uint)c;
    c >>= 32;
    c += (ulong)r.v[1] + (ulong)m;
    r.v[1] = (uint)c;
    c >>= 32;
    #pragma unroll
    for (int j = 2; j < 8; j++) {
        c += (ulong)r.v[j];
        r.v[j] = (uint)c;
        c >>= 32;
    }
    m = (uint)c;        // only after a wrap that left r tiny
    c = (ulong)r.v[0] + (ulong)(m * 977u);
    r.v[0] = (uint)c;
    r.v[1] += m + (uint)(c >> 32);
    return r;
}

// r -= 0x1000003D1 * m (m = 0 or 1) over 256 bits; returns the borrow.
static inline uint np_fe_sub_c(thread np_fe &r, uint m)
{
    ulong d = (ulong)r.v[0] - (ulong)(m * 977u);
    r.v[0] = (uint)d;
    uint borrow = (uint)(d >> 63);
    d = (ulong)r.v[1] - (ulong)m - (ulong)borrow;
    r.v[1] = (uint)d;
    borrow = (uint)(d >> 63);
    #pragma unroll
    for (int j = 2; j < 8; j++) {
        d = (ulong)r.v[j] - (ulong)borrow;
        r.v[j] = (uint)d;
        borrow = (uint)(d >> 63);
    }
    return borrow;
}

static inline np_fe np_fe_sub(np_fe a, np_fe b)
{
    np_fe r;
    uint borrow = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        ulong d = (ulong)a.v[j] - (ulong)b.v[j] - (ulong)borrow;
        r.v[j] = (uint)d;
        borrow = (uint)(d >> 63);
    }
    // a - b went negative: add p, i.e. subtract 0x1000003D1 mod 2^256 (twice if still negative)
    borrow = np_fe_sub_c(r, borrow);
    np_fe_sub_c(r, borrow);
    return r;
}

static inline np_fe np_fe_neg(np_fe a) { return np_fe_sub(np_fe_zero(), a); }

// Canonical value in [0, p).
static inline np_fe np_fe_normalize(np_fe a)
{
    np_fe t;
    ulong c = (ulong)a.v[0] + 977ul;
    t.v[0] = (uint)c;
    c >>= 32;
    c += (ulong)a.v[1] + 1ul;
    t.v[1] = (uint)c;
    c >>= 32;
    #pragma unroll
    for (int j = 2; j < 8; j++) {
        c += (ulong)a.v[j];
        t.v[j] = (uint)c;
        c >>= 32;
    }
    return c != 0 ? t : a;   // a >= p exactly when a + 0x1000003D1 carries out; then a - p = t
}

static inline bool np_fe_is_zero(np_fe a)
{
    np_fe n = np_fe_normalize(a);
    uint z = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) z |= n.v[j];
    return z == 0;
}

static inline bool np_fe_is_one(np_fe a)
{
    np_fe n = np_fe_normalize(a);
    uint z = n.v[0] ^ 1u;
    #pragma unroll
    for (int j = 1; j < 8; j++) z |= n.v[j];
    return z == 0;
}

// a^((p-3)/4) by the libsecp256k1-style addition chain (runs of ones 223, 22, then 0000 1 0 11):
// 253 squarings and 14 multiplications, driven by a small step table so there is one squaring and one
// multiplication site in the code.
constant uchar NP_CHAIN_SQR[14] = {1, 1, 3, 3, 2, 11, 22, 44, 88, 44, 3, 23, 5, 3};
constant uchar NP_CHAIN_MUL[14] = {0, 0, 2, 2, 1, 3, 4, 5, 6, 5, 2, 4, 0, 1};
constant char NP_CHAIN_SAVE[14] = {1, 2, -1, -1, 3, 4, 5, 6, -1, -1, -1, -1, -1, -1};

static inline np_fe np_fe_pow_p34(np_fe a)
{
    np_fe slot[7];
    slot[0] = a;
    np_fe t = a;
    for (int s = 0; s < 14; s++) {
        int n = NP_CHAIN_SQR[s];
        for (int i = 0; i < n; i++) t = np_fe_sqr(t);
        t = np_fe_mul(t, slot[NP_CHAIN_MUL[s]]);
        int save = NP_CHAIN_SAVE[s];
        if (save >= 0) slot[save] = t;
    }
    return t;
}

// a^-1 = (a^((p-3)/4))^4 * a = a^(p-2)
static inline np_fe np_fe_inv(np_fe a)
{
    np_fe t = np_fe_pow_p34(a);
    t = np_fe_sqr(np_fe_sqr(t));
    return np_fe_mul(t, a);
}
