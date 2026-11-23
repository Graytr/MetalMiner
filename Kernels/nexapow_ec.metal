// NexaPow kernels, part 3 of 4: secp256k1 points (Jacobian, a = 0), fixed-base k G from the window table,
// and scalar arithmetic mod the group order n.
//
// Table: signed NEXAPOW_W-bit windows; entry (window i, j) = j 2^(W i) G for j = 1 .. 2^(W-1), affine,
// 64 bytes (x then y, little-endian limbs). k G is then one mixed addition per nonzero window digit.

constant uint NP_N[8] = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
constant uint NP_NC[5] = {0x2FC9BEBF, 0x402DA173, 0x50B75FC4, 0x45512319, 0x00000001};   // 2^256 - n

// dbl-2009-l (a = 0): 2M + 5S. y = 0 never occurs on secp256k1.
static inline np_jac np_dbl(np_jac p)
{
    np_fe a = np_fe_sqr(p.x);
    np_fe b = np_fe_sqr(p.y);
    np_fe c = np_fe_sqr(b);
    np_fe d = np_fe_sub(np_fe_sqr(np_fe_add(p.x, b)), np_fe_add(a, c));
    d = np_fe_add(d, d);
    np_fe e = np_fe_add(np_fe_add(a, a), a);
    np_jac r;
    r.x = np_fe_sub(np_fe_sqr(e), np_fe_add(d, d));
    np_fe c8 = np_fe_add(c, c);
    c8 = np_fe_add(c8, c8);
    c8 = np_fe_add(c8, c8);
    r.y = np_fe_sub(np_fe_mul(e, np_fe_sub(d, r.x)), c8);
    r.z = np_fe_mul(np_fe_add(p.y, p.y), p.z);
    return r;
}

// p += (x2, y2) affine, Jacobian result: 8M + 3S. Equal x: doubles, or sets inf for p = -q.
static inline void np_madd(thread np_jac &p, np_fe x2, np_fe y2, thread bool &inf)
{
    np_fe z1z1 = np_fe_sqr(p.z);
    np_fe u2 = np_fe_mul(x2, z1z1);
    np_fe s2 = np_fe_mul(y2, np_fe_mul(z1z1, p.z));
    np_fe h = np_fe_sub(u2, p.x);
    np_fe r = np_fe_sub(s2, p.y);
    if (np_fe_is_zero(h)) {
        if (np_fe_is_zero(r)) p = np_dbl(p);
        else inf = true;
        return;
    }
    np_fe hh = np_fe_sqr(h);
    np_fe hhh = np_fe_mul(h, hh);
    np_fe v = np_fe_mul(p.x, hh);
    np_fe x3 = np_fe_sub(np_fe_sub(np_fe_sqr(r), hhh), np_fe_add(v, v));
    np_fe y3 = np_fe_sub(np_fe_mul(r, np_fe_sub(v, x3)), np_fe_mul(p.y, hhh));
    p.z = np_fe_mul(p.z, h);
    p.x = x3;
    p.y = y3;
}

static inline void np_load_affine(device const uint4 *e, thread np_fe &x, thread np_fe &y)
{
    uint4 a = e[0], b = e[1], c = e[2], d = e[3];
    x.v[0] = a.x; x.v[1] = a.y; x.v[2] = a.z; x.v[3] = a.w; x.v[4] = b.x; x.v[5] = b.y; x.v[6] = b.z; x.v[7] = b.w;
    y.v[0] = c.x; y.v[1] = c.y; y.v[2] = c.z; y.v[3] = c.w; y.v[4] = d.x; y.v[5] = d.y; y.v[6] = d.z; y.v[7] = d.w;
}

// k G from the signed-window table (0 < k < n). Sets inf only if the sum is the point at infinity.
static inline np_jac np_mul_g(device const uint4 *table, np_fe k, thread bool &inf)
{
    np_jac q;
    q.x = np_fe_zero(); q.y = np_fe_one(); q.z = np_fe_zero();
    inf = true;
    uint s[8];
    #pragma unroll
    for (int l = 0; l < 8; l++) s[l] = k.v[l];
    uint carry = 0;
    for (uint i = 0; i < NEXAPOW_WINDOWS; i++) {
        uint raw = (s[0] & NEXAPOW_MASK) + carry;
        #pragma unroll
        for (int l = 0; l < 7; l++) s[l] = (s[l] >> NEXAPOW_W) | (s[l + 1] << (32 - NEXAPOW_W));
        s[7] >>= NEXAPOW_W;
        carry = raw > NEXAPOW_TSIZE ? 1u : 0u;
        int d = (int)raw - (int)(carry << NEXAPOW_W);   // in [-2^(W-1), 2^(W-1)]
        if (d != 0) {
            np_fe x, y;
            np_load_affine(table + 4 * ((ulong)i * NEXAPOW_TSIZE + (ulong)(abs(d) - 1)), x, y);
            np_fe ny = np_fe_neg(y);
            if (d < 0) y = ny;
            if (inf) {
                q.x = x; q.y = y; q.z = np_fe_one();
                inf = false;
            } else {
                np_madd(q, x, y, inf);
            }
        }
    }
    return q;
}

static inline bool np_scalar_valid(thread const uint *k)   // 0 < k < n
{
    uint z = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) z |= k[j];
    if (z == 0) return false;
    for (int j = 7; j >= 0; j--) {
        if (k[j] < NP_N[j]) return true;
        if (k[j] > NP_N[j]) return false;
    }
    return false;   // k == n
}

// r = a - n over 256 bits; returns the borrow.
static inline uint np_sub_n(thread const uint *a, thread uint *r)
{
    uint borrow = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        ulong d = (ulong)a[j] - (ulong)NP_N[j] - (ulong)borrow;
        r[j] = (uint)d;
        borrow = (uint)(d >> 63);
    }
    return borrow;
}

// k = n - k (0 < k < n)
static inline void np_scalar_negate(thread uint *k)
{
    uint borrow = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        ulong d = (ulong)NP_N[j] - (ulong)k[j] - (ulong)borrow;
        k[j] = (uint)d;
        borrow = (uint)(d >> 63);
    }
}

// (e x + k) mod n, all inputs below n.
static inline void np_scalar_muladd(thread const uint *e, thread const uint *x, thread const uint *k, thread uint *out)
{
    uint t[16];
    np_mul_wide(e, x, t);
    // m = t_lo + t_hi * (2^256 - n): below 2^386, 13 limbs
    uint m[13];
    #pragma unroll
    for (int j = 0; j < 8; j++) m[j] = t[j];
    #pragma unroll
    for (int j = 8; j < 13; j++) m[j] = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        ulong c = 0;
        #pragma unroll
        for (int j = 0; j < 5; j++) {
            c = (ulong)t[8 + i] * (ulong)NP_NC[j] + ((ulong)m[i + j] + (c >> 32));
            m[i + j] = (uint)c;
        }
        c >>= 32;
        #pragma unroll
        for (int j = i + 5; j < 13; j++) {
            c += (ulong)m[j];
            m[j] = (uint)c;
            c >>= 32;
        }
    }
    // r = m_lo + m_hi * (2^256 - n): m_hi below 2^130, r below 2^260, 9 limbs
    uint r[9];
    #pragma unroll
    for (int j = 0; j < 8; j++) r[j] = m[j];
    r[8] = 0;
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        ulong c = 0;
        #pragma unroll
        for (int j = 0; j < 5; j++) {
            if (i + j < 9) {
                c = (ulong)m[8 + i] * (ulong)NP_NC[j] + ((ulong)r[i + j] + (c >> 32));
                r[i + j] = (uint)c;
            }
        }
        c >>= 32;
        #pragma unroll
        for (int j = i + 5; j < 9; j++) {
            c += (ulong)r[j];
            r[j] = (uint)c;
            c >>= 32;
        }
    }
    // fold r[8] (below 16), then any final carry (at most once more)
    uint top = r[8];
    for (int pass = 0; pass < 2; pass++) {
        ulong c = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            c += (ulong)r[j] + (j < 5 ? (ulong)top * (ulong)NP_NC[j] : 0ul);
            r[j] = (uint)c;
            c >>= 32;
        }
        top = (uint)c;
    }
    // r < 2^256 < 2n: subtract n once if r >= n
    uint s[8];
    if (np_sub_n(r, s) == 0) {
        #pragma unroll
        for (int j = 0; j < 8; j++) r[j] = s[j];
    }
    // + k, then reduce again
    ulong c = 0;
    #pragma unroll
    for (int j = 0; j < 8; j++) {
        c += (ulong)r[j] + (ulong)k[j];
        r[j] = (uint)c;
        c >>= 32;
    }
    uint borrow = np_sub_n(r, s);
    bool subtract = (c != 0) || (borrow == 0);
    #pragma unroll
    for (int j = 0; j < 8; j++) out[j] = subtract ? s[j] : r[j];
}
