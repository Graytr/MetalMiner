// ---- XelisHash v3 (XEL) ----
// Mainnet proof of work since block height 3,282,150 (BlockVersion V3, Dec 2025), still current (V7).
// Port of github.com/xelis-project/xelis-hash src/v3.rs (stage 3) + src/v2.rs (stage 1 and stage 4).
//
// One thread computes one hash. Each hash needs a 543,744-byte scratchpad (67,968 u64 words) in
// device memory. Scratchpads of 32 consecutive threads are interleaved word by word, so word w of
// lane L lives at slot[(w * 32) + L]: the sequential passes (ChaCha8 fill, BLAKE3 read-back, the
// `c` stream of stage 3) are coalesced; stage 3's random accesses touch one line per lane anyway.
//
// Two stage-3 variants: `simple` follows the reference line by line; `pipelined` issues the next
// iteration's loads before the current iteration's stores (fixing up the rare aliasing cases) and
// replaces the 16-way divergent switch by one shared u128 division and isqrt pair per iteration.

#ifndef XH_FAST_DIV
#define XH_FAST_DIV 1                // 64/32 divisions inside u128 division via a float reciprocal
#endif

#define XH_MEM_WORDS      67968u     // 531 * 128 u64 words = 543,744 bytes
#define XH_BUF_WORDS      33984u     // MEMORY_SIZE / 2: mem_buffer_a = [0, 33984), mem_buffer_b = [33984, 67968)
#define XH_CHUNK_WORDS    16992u     // stage-1 output per 32-byte input chunk: 135,936 bytes
#define XH_CHACHA_BLOCKS  2124u      // 64-byte ChaCha8 blocks per input chunk
#define XH_LANES          32u        // interleave width
#define XH_B3_CHUNKS      531u       // 1 KiB BLAKE3 chunks in the scratchpad

#define XH_B3_START  1u
#define XH_B3_END    2u
#define XH_B3_PARENT 4u
#define XH_B3_ROOT   8u

#define XH_IV0 0x6A09E667u
#define XH_IV1 0xBB67AE85u
#define XH_IV2 0x3C6EF372u
#define XH_IV3 0xA54FF53Au
#define XH_IV4 0x510E527Fu
#define XH_IV5 0x9B05688Cu
#define XH_IV6 0x1F83D9ABu
#define XH_IV7 0x5BE0CD19u

struct XhParams {
    uint  work[28];     // 112-byte MinerWork as little-endian u32 words; bytes 40..47 (nonce) are replaced
    uint  target[8];    // 256-bit target as big-endian u32 words, target[0] most significant
    ulong startNonce;
    uint  count;
    uint  flags;        // bit 0: also write every hash to `hashes`
};

constant uchar XH_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// ---------------------------------------------------------------------------------------------
// 64/128-bit integer helpers (Apple GPUs emulate 64-bit math with 32-bit pairs; no 128-bit type)

static inline uint xh_clz64(ulong x) {
    uint hi = (uint)(x >> 32);
    return hi != 0u ? clz(hi) : 32u + clz((uint)x);
}

static inline ulong xh_rotl(ulong x, uint n) {
    n &= 63u;
    return n == 0u ? x : ((x << n) | (x >> (64u - n)));
}

static inline ulong xh_rotr(ulong x, uint n) {
    n &= 63u;
    return n == 0u ? x : ((x >> n) | (x << (64u - n)));
}

// High 64 bits of the 128-bit product a * b.
static inline ulong xh_mulhi(ulong a, ulong b) {
    ulong a0 = a & 0xFFFFFFFFul, a1 = a >> 32, b0 = b & 0xFFFFFFFFul, b1 = b >> 32;
    ulong p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    ulong mid = (p00 >> 32) + (p01 & 0xFFFFFFFFul) + (p10 & 0xFFFFFFFFul);
    return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

// floor(u / v) for a normalized 32-bit v (2^31 <= v < 2^32) and a quotient below about 2^33:
// a float estimate (error < 2^12), one float refinement, then exact +-1 fix-ups.
static inline ulong xh_div64_32n(ulong u, ulong v, float rv) {
    float fu = (float)(uint)(u >> 32) * 4294967296.0f + (float)(uint)u;
    ulong q = (ulong)(fu * rv);
    long rem = (long)(u - q * v);
    q = (ulong)((long)q + (long)((float)rem * rv));
    rem = (long)(u - q * v);
    while (rem < 0l) { q -= 1ul; rem += (long)v; }
    while (rem >= (long)v) { q += 1ul; rem -= (long)v; }
    return q;
}

// (u1:u0) / v for u1 < v: 64-bit quotient and remainder. Hacker's Delight divlu2 with 32-bit digits.
static inline ulong xh_divlu(ulong u1, ulong u0, ulong v, thread ulong &rem) {
    const ulong b = 0x100000000ul;
    uint s = xh_clz64(v);
    v <<= s;
    ulong vn1 = v >> 32, vn0 = v & 0xFFFFFFFFul;
    ulong un32 = s != 0u ? ((u1 << s) | (u0 >> (64u - s))) : u1;
    ulong un10 = u0 << s;
    ulong un1 = un10 >> 32, un0 = un10 & 0xFFFFFFFFul;
#if XH_FAST_DIV
    float rv = 1.0f / (float)(uint)vn1;
    ulong q1 = xh_div64_32n(un32, vn1, rv);
#else
    ulong q1 = un32 / vn1;
#endif
    ulong rhat = un32 - q1 * vn1;
    while (q1 >= b || q1 * vn0 > ((rhat << 32) | un1)) {
        q1 -= 1ul;
        rhat += vn1;
        if (rhat >= b) break;
    }
    ulong un21 = (un32 << 32) + un1 - q1 * v;
#if XH_FAST_DIV
    ulong q0 = xh_div64_32n(un21, vn1, rv);
#else
    ulong q0 = un21 / vn1;
#endif
    rhat = un21 - q0 * vn1;
    while (q0 >= b || q0 * vn0 > ((rhat << 32) | un0)) {
        q0 -= 1ul;
        rhat += vn1;
        if (rhat >= b) break;
    }
    rem = ((un21 << 32) + un0 - q0 * v) >> s;
    return (q1 << 32) | q0;
}

// (nh:nl) / (dh:dl), divisor non-zero: low 64 bits of the quotient and of the remainder
// (what Rust's `(u128 / u128) as u64` and `(u128 % u128) as u64` give). Every lane runs the same
// two divlu calls, so a SIMD group with mixed divisor sizes doesn't execute both paths.
static inline void xh_divrem128(ulong nh, ulong nl, ulong dh, ulong dl, thread ulong &q, thread ulong &r) {
    bool wide = dh != 0ul;
    bool below = wide && (nh < dh || (nh == dh && nl < dl));     // N < D
    uint n = xh_clz64(dh) & 63u;
    ulong v1 = n != 0u ? ((dh << n) | (dl >> (64u - n))) : dh;  // top word of the normalized divisor
    // narrow divisor: nh mod d, then (nh mod d : nl) / d.  Wide: (N >> 1) / v1, then fix-ups (Hacker's Delight divdu).
    ulong u1 = wide ? nh >> 1 : 0ul;
    ulong u0 = wide ? ((nh << 63) | (nl >> 1)) : nh;
    ulong dv = wide ? v1 : dl;
    if (below) { u1 = 0ul; u0 = 0ul; dv = 1ul; }
    ulong t;
    ulong q1 = xh_divlu(u1, u0, dv, t);
    ulong r2;
    ulong q2 = xh_divlu(wide ? 0ul : t, wide ? 0ul : nl, wide ? 1ul : dl, r2);
    if (!wide) { q = q2; r = r2; return; }
    if (below) { q = 0ul; r = nl; return; }
    ulong q0 = q1 >> (63u - n);
    if (q0 != 0ul) q0 -= 1ul;
    ulong plo = q0 * dl;
    ulong phi = xh_mulhi(q0, dl) + q0 * dh;
    ulong rl = nl - plo;
    ulong rh = nh - phi - (nl < plo ? 1ul : 0ul);
    if (rh > dh || (rh == dh && rl >= dl)) {
        q0 += 1ul;
        ulong borrow = rl < dl ? 1ul : 0ul;
        rl -= dl;
        rh = rh - dh - borrow;
    }
    q = q0;
    r = rl;
}

// ---------------------------------------------------------------------------------------------
// XelisHash v3 primitives

// v3 isqrt: floor(sqrt(n)) via an f64 estimate in the reference. Reproduces its exact results,
// including the two wrap-around quirks at the top of the range (see docs/specs/xelishash.md).
static inline ulong xh_isqrt(ulong n) {
    if (n < 2ul) return n;
    if (n >= 0xFFFFFFFFFFFFFC00ul) return 0x100000001ul;   // f64(n) rounds to 2^64
    if (n >= 0xFFFFFFFE00000001ul) return 0x100000000ul;   // n >= (2^32 - 1)^2
    float fn = (float)(uint)(n >> 32) * 4294967296.0f + (float)(uint)n;
    ulong x = (ulong)sqrt(fn);
    x = clamp(x, 1ul, 0xFFFFFFFEul);
    long e = (long)(n - x * x);                            // |e| < 2^43, exact as a signed value
    long y = (long)x + (long)rint((float)e / (2.0f * (float)x));   // one Newton step
    x = (ulong)clamp(y, 1l, 0xFFFFFFFEl);
    while (x * x > n) x -= 1ul;
    while ((x + 1ul) * (x + 1ul) <= n) x += 1ul;
    return x;
}

static inline ulong xh_murmur(ulong s) {
    s ^= s >> 55;
    s *= 0xff51afd7ed558ccdul;
    s ^= s >> 32;
    s *= 0xc4ceb9fe1a85ec53ul;
    s ^= s >> 15;
    return s;
}

// MurmurHash3-style mix, then ((x as u128) * BUFFER_SIZE) >> 64.
static inline uint xh_map_index(ulong x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdul;
    ulong p = (x >> 32) * (ulong)XH_BUF_WORDS + (((x & 0xFFFFFFFFul) * (ulong)XH_BUF_WORDS) >> 32);
    return (uint)(p >> 32);
}

static inline bool xh_pick_half(ulong v) {
    return (xh_murmur(v) & (1ul << 58)) != 0ul;
}

static inline ulong xh_mulmod(ulong a, ulong b, ulong m) {
    ulong r;
    xh_divlu(xh_mulhi(a, b), a * b, m, r);
    return r;
}

// Reference: result starts at 1 (not reduced), base %= mod, square-and-multiply with u128 products.
static inline ulong xh_modpow(ulong base, ulong exp, ulong mod) {
    if (mod == 0ul) return 0ul;   // the reference panics here (probability 2^-64)
    ulong result = 1ul;
    xh_divlu(0ul, base, mod, base);
    while (exp > 0ul) {
        if ((exp & 1ul) != 0ul) result = xh_mulmod(result, base, mod);
        base = xh_mulmod(base, base, mod);
        exp >>= 1;
    }
    return result;
}

static inline uint xh_xtime(uint x) {
    return ((x << 1) ^ (((x >> 7) & 1u) * 0x1Bu)) & 0xFFu;
}

// One AES encryption round (SubBytes, ShiftRows, MixColumns, AddRoundKey with "xelishash-pow-v3")
// on the 16-byte block lo (bytes 0..7, LE) || hi (bytes 8..15, LE), like _mm_aesenc_si128.
static inline void xh_aes_round(ulong lo, ulong hi, thread ulong &out_lo, thread ulong &out_hi) {
    uint col[4] = { (uint)lo, (uint)(lo >> 32), (uint)hi, (uint)(hi >> 32) };
    const uint key[4] = { 0x696c6578u, 0x73616873u, 0x6f702d68u, 0x33762d77u };
    uint res[4];
    for (uint c = 0u; c < 4u; c++) {
        uint b0 = XH_SBOX[col[c] & 0xFFu];
        uint b1 = XH_SBOX[(col[(c + 1u) & 3u] >> 8) & 0xFFu];
        uint b2 = XH_SBOX[(col[(c + 2u) & 3u] >> 16) & 0xFFu];
        uint b3 = XH_SBOX[(col[(c + 3u) & 3u] >> 24) & 0xFFu];
        uint x0 = xh_xtime(b0), x1 = xh_xtime(b1), x2 = xh_xtime(b2), x3 = xh_xtime(b3);
        uint m0 = x0 ^ (x1 ^ b1) ^ b2 ^ b3;
        uint m1 = b0 ^ x1 ^ (x2 ^ b2) ^ b3;
        uint m2 = b0 ^ b1 ^ x2 ^ (x3 ^ b3);
        uint m3 = (x0 ^ b0) ^ b1 ^ b2 ^ x3;
        res[c] = (m0 | (m1 << 8) | (m2 << 16) | (m3 << 24)) ^ key[c];
    }
    out_lo = (ulong)res[0] | ((ulong)res[1] << 32);
    out_hi = (ulong)res[2] | ((ulong)res[3] << 32);
}

// ---------------------------------------------------------------------------------------------
// BLAKE3 and ChaCha8

#define XH_G(a, b, c, d, x, y) \
    a = a + b + (x); d = rotr32(d ^ a, 16u); c = c + d; b = rotr32(b ^ c, 12u); \
    a = a + b + (y); d = rotr32(d ^ a, 8u);  c = c + d; b = rotr32(b ^ c, 7u);

#define XH_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
    XH_G(v0, v4, v8,  v12, m[s0],  m[s1]);  \
    XH_G(v1, v5, v9,  v13, m[s2],  m[s3]);  \
    XH_G(v2, v6, v10, v14, m[s4],  m[s5]);  \
    XH_G(v3, v7, v11, v15, m[s6],  m[s7]);  \
    XH_G(v0, v5, v10, v15, m[s8],  m[s9]);  \
    XH_G(v1, v6, v11, v12, m[s10], m[s11]); \
    XH_G(v2, v7, v8,  v13, m[s12], m[s13]); \
    XH_G(v3, v4, v9,  v14, m[s14], m[s15]);

// BLAKE3 compression; cv is replaced by the first 8 output words.
static inline void xh_b3_compress(thread uint *cv, thread const uint *m, ulong counter, uint len, uint flags) {
    uint v0 = cv[0], v1 = cv[1], v2 = cv[2], v3 = cv[3], v4 = cv[4], v5 = cv[5], v6 = cv[6], v7 = cv[7];
    uint v8 = XH_IV0, v9 = XH_IV1, v10 = XH_IV2, v11 = XH_IV3;
    uint v12 = (uint)counter, v13 = (uint)(counter >> 32), v14 = len, v15 = flags;
    XH_ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    XH_ROUND(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
    XH_ROUND(3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1)
    XH_ROUND(10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6)
    XH_ROUND(12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4)
    XH_ROUND(9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7)
    XH_ROUND(11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13)
    cv[0] = v0 ^ v8;  cv[1] = v1 ^ v9;  cv[2] = v2 ^ v10; cv[3] = v3 ^ v11;
    cv[4] = v4 ^ v12; cv[5] = v5 ^ v13; cv[6] = v6 ^ v14; cv[7] = v7 ^ v15;
}

static inline void xh_b3_iv(thread uint *cv) {
    cv[0] = XH_IV0; cv[1] = XH_IV1; cv[2] = XH_IV2; cv[3] = XH_IV3;
    cv[4] = XH_IV4; cv[5] = XH_IV5; cv[6] = XH_IV6; cv[7] = XH_IV7;
}

#define XH_QR(a, b, c, d) \
    a += b; d = rotl32(d ^ a, 16u); c += d; b = rotl32(b ^ c, 12u); \
    a += b; d = rotl32(d ^ a, 8u);  c += d; b = rotl32(b ^ c, 7u);

// ---------------------------------------------------------------------------------------------
// Stage 1: scratchpad = ChaCha8 keystreams. For each 32-byte input chunk (zero-padded), the key is
// BLAKE3(previous hash || chunk); the first nonce is BLAKE3(input)[0..12], later nonces are the
// last 12 bytes of the previous chunk's output.

static void xh_stage1(thread const uint *in, device ulong *sp) {
    uint h[8];
    uint m[16];
    xh_b3_iv(h);
    for (uint k = 0u; k < 16u; k++) m[k] = in[k];
    xh_b3_compress(h, m, 0ul, 64u, XH_B3_START);
    for (uint k = 0u; k < 16u; k++) m[k] = in[16u + k];              // in[28..31] are zero
    xh_b3_compress(h, m, 0ul, 48u, XH_B3_END | XH_B3_ROOT);
    uint n0 = h[0], n1 = h[1], n2 = h[2];

    for (uint chunk = 0u; chunk < 4u; chunk++) {
        for (uint k = 0u; k < 8u; k++) {
            m[k] = h[k];
            m[8u + k] = in[chunk * 8u + k];
        }
        xh_b3_iv(h);
        xh_b3_compress(h, m, 0ul, 64u, XH_B3_START | XH_B3_END | XH_B3_ROOT);

        device ulong *dst = sp + chunk * XH_CHUNK_WORDS * XH_LANES;
        uint o13 = 0u, o14 = 0u, o15 = 0u;
        for (uint blk = 0u; blk < XH_CHACHA_BLOCKS; blk++) {
            uint x0 = 0x61707865u, x1 = 0x3320646eu, x2 = 0x79622d32u, x3 = 0x6b206574u;
            uint x4 = h[0], x5 = h[1], x6 = h[2], x7 = h[3], x8 = h[4], x9 = h[5], x10 = h[6], x11 = h[7];
            uint x12 = blk, x13 = n0, x14 = n1, x15 = n2;
            for (uint dr = 0u; dr < 4u; dr++) {
                XH_QR(x0, x4, x8,  x12); XH_QR(x1, x5, x9,  x13); XH_QR(x2, x6, x10, x14); XH_QR(x3, x7, x11, x15);
                XH_QR(x0, x5, x10, x15); XH_QR(x1, x6, x11, x12); XH_QR(x2, x7, x8,  x13); XH_QR(x3, x4, x9,  x14);
            }
            x0 += 0x61707865u; x1 += 0x3320646eu; x2 += 0x79622d32u; x3 += 0x6b206574u;
            x4 += h[0]; x5 += h[1]; x6 += h[2]; x7 += h[3]; x8 += h[4]; x9 += h[5]; x10 += h[6]; x11 += h[7];
            x12 += blk; x13 += n0; x14 += n1; x15 += n2;
            device ulong *d = dst + blk * 8u * XH_LANES;
            d[0u * XH_LANES] = (ulong)x0  | ((ulong)x1  << 32);
            d[1u * XH_LANES] = (ulong)x2  | ((ulong)x3  << 32);
            d[2u * XH_LANES] = (ulong)x4  | ((ulong)x5  << 32);
            d[3u * XH_LANES] = (ulong)x6  | ((ulong)x7  << 32);
            d[4u * XH_LANES] = (ulong)x8  | ((ulong)x9  << 32);
            d[5u * XH_LANES] = (ulong)x10 | ((ulong)x11 << 32);
            d[6u * XH_LANES] = (ulong)x12 | ((ulong)x13 << 32);
            d[7u * XH_LANES] = (ulong)x14 | ((ulong)x15 << 32);
            o13 = x13; o14 = x14; o15 = x15;
        }
        n0 = o13; n1 = o14; n2 = o15;
    }
}

// ---------------------------------------------------------------------------------------------
// Stage 3 (v3): 2 x 33,984 sequential iterations of random reads, random read-modify-writes and a
// 16-way data-dependent branch with u128 division, isqrt and multiply-high.

#define XH_A(x) sp[(x) * XH_LANES]
#define XH_B(x) sp[(XH_BUF_WORDS + (x)) * XH_LANES]

// The reference's match, case by case (divergent inside a SIMD group).
static inline ulong xh_branch(uint branch, ulong a, ulong b, ulong c, ulong result, uint r, uint i, uint j) {
    ulong iu = (ulong)i, ju = (ulong)j;
    ulong v = 0ul, q, rem;
    switch (branch) {
    case 0u: {
        ulong denom = xh_murmur(c ^ result ^ iu ^ ju) | 1ul;
        xh_divrem128(a + iu, xh_isqrt(b + ju), 0ul, denom, q, rem);
        v = rem;
    } break;
    case 1u: {
        xh_divrem128(0ul, c + iu, 0ul, xh_isqrt(b | 2ul), q, rem);
        v = xh_rotl(rem, i + j) * xh_isqrt(a + ju);
    } break;
    case 2u: v = (xh_isqrt(a + iu) * xh_isqrt(c + ju)) ^ (b + iu + ju); break;
    case 3u: v = (a + b) * c; break;
    case 4u: v = (b - c) * a; break;
    case 5u: v = c - a + b; break;
    case 6u: v = a - b + c; break;
    case 7u: v = b * c + a; break;
    case 8u: v = c * a + b; break;
    case 9u: v = a * b * c; break;
    case 10u: xh_divrem128(a, b, 0ul, c | 1ul, q, rem); v = rem; break;
    case 11u: {
        ulong dh = xh_rotl(result, r), dl = a | 2ul;            // t2 = (dh:dl), t1 = (b:c)
        if (dh > b || (dh == b && dl > c)) { v = c; }
        else { xh_divrem128(b, c, dh, dl, q, rem); v = rem; }
    } break;
    case 12u: xh_divrem128(c, a, 0ul, b | 4ul, q, rem); v = q; break;
    case 13u: {
        ulong nh = xh_rotl(result, r), dl = c | 8ul;            // t1 = (nh:b), t2 = (a:dl)
        if (nh > a || (nh == a && b > dl)) { xh_divrem128(nh, b, a, dl, q, rem); v = q; }
        else { v = a ^ b; }
    } break;
    case 14u: v = b * c + xh_mulhi(a, c); break;
    default:  v = a * b + c * xh_rotr(result, r) + xh_mulhi(c, b); break;
    }
    return v;
}

// The same match with the expensive parts shared by all lanes: two isqrt and one u128 division
// with per-branch operands, then a cheap per-branch combination.
static inline ulong xh_branch_unified(uint br, ulong a, ulong b, ulong c, ulong result, uint r, uint i, uint j) {
    ulong iu = (ulong)i, ju = (ulong)j;
    ulong rl = xh_rotl(result, r);
    ulong s1 = xh_isqrt(br == 0u ? b + ju : (br == 1u ? (b | 2ul) : a + iu));
    ulong s2 = xh_isqrt(br == 1u ? a + ju : c + ju);
    ulong nh = 0ul, nl = 0ul, dh = 0ul, dl = 1ul;
    if (br == 0u)       { nh = a + iu; nl = s1; dl = xh_murmur(c ^ result ^ iu ^ ju) | 1ul; }
    else if (br == 1u)  { nl = c + iu; dl = s1; }
    else if (br == 10u) { nh = a; nl = b; dl = c | 1ul; }
    else if (br == 11u) { nh = b; nl = c; dh = rl; dl = a | 2ul; }    // N < D gives c, as the reference
    else if (br == 12u) { nh = c; nl = a; dl = b | 4ul; }
    else if (br == 13u) { nh = rl; nl = b; dh = a; dl = c | 8ul; }
    ulong q, rem;
    xh_divrem128(nh, nl, dh, dl, q, rem);
    switch (br) {
    case 0u:  return rem;
    case 1u:  return xh_rotl(rem, i + j) * s2;
    case 2u:  return (s1 * s2) ^ (b + iu + ju);
    case 3u:  return (a + b) * c;
    case 4u:  return (b - c) * a;
    case 5u:  return c - a + b;
    case 6u:  return a - b + c;
    case 7u:  return b * c + a;
    case 8u:  return c * a + b;
    case 9u:  return a * b * c;
    case 10u: return rem;
    case 11u: return rem;
    case 12u: return q;
    case 13u: return (nh > dh || (nh == dh && nl > dl)) ? q : a ^ b;
    case 14u: return b * c + xh_mulhi(a, c);
    default:  return a * b + c * xh_rotr(result, r) + xh_mulhi(c, b);
    }
}

static void xh_stage3_simple(device ulong *sp) {
    ulong addr_a = XH_B(XH_BUF_WORDS - 1u);
    ulong addr_b = XH_A(XH_BUF_WORDS - 1u) >> 32;
    uint r = 0u;
    for (uint i = 0u; i < 2u; i++) {
        ulong mem_a = XH_A(xh_map_index(addr_a));
        ulong mem_b = XH_B(xh_map_index(mem_a ^ addr_b));
        ulong h1, h2;
        xh_aes_round(mem_b, mem_a, h1, h2);
        ulong result = ~(h1 ^ h2);

        for (uint j = 0u; j < XH_BUF_WORDS; j++) {
            ulong a = XH_A(xh_map_index(result));
            ulong b = XH_B(xh_map_index(a ^ ~xh_rotr(result, r)));
            ulong c = sp[r * XH_LANES];
            r = r < XH_MEM_WORDS - 1u ? r + 1u : 0u;

            ulong v = xh_branch((uint)xh_rotl(result, (uint)c) & 15u, a, b, c, result, r, i, j);

            ulong seed = v ^ result;
            result = xh_rotl(seed, r);
            uint it = xh_map_index(seed) + (xh_pick_half(v) ? XH_BUF_WORDS : 0u);
            ulong t = sp[it * XH_LANES] ^ result;
            uint ia = xh_map_index(t ^ result ^ 0x9e3779b97f4a7c15ul);
            uint ib = xh_map_index((ulong)ia ^ ~result ^ 0xd2b74407b1ce6e93ul);
            ulong old = XH_A(ia);
            XH_A(ia) = t;
            XH_B(ib) ^= old ^ xh_rotr(t, i + j);
        }
        if (i == 0u) {   // the reference also updates them after the last pass; those values are unused
            addr_a = xh_modpow(addr_a, addr_b, result);
            addr_b = xh_isqrt(result) * ((ulong)r + 1ul) * xh_isqrt(addr_a);
        }
    }
}

// Software-pipelined: the next iteration's a, b and c are loaded before this iteration's two stores
// and patched when they alias them, so each iteration waits on two memory round trips instead of four.
static void xh_stage3_pipelined(device ulong *sp) {
    ulong addr_a = XH_B(XH_BUF_WORDS - 1u);
    ulong addr_b = XH_A(XH_BUF_WORDS - 1u) >> 32;
    uint r = 0u;
    for (uint i = 0u; i < 2u; i++) {
        ulong mem_a = XH_A(xh_map_index(addr_a));
        ulong mem_b = XH_B(xh_map_index(mem_a ^ addr_b));
        ulong h1, h2;
        xh_aes_round(mem_b, mem_a, h1, h2);
        ulong result = ~(h1 ^ h2);
        ulong a = XH_A(xh_map_index(result));
        ulong b = XH_B(xh_map_index(a ^ ~xh_rotr(result, r)));
        ulong c = sp[r * XH_LANES];

        for (uint j = 0u; j < XH_BUF_WORDS; j++) {
            uint r1 = r < XH_MEM_WORDS - 1u ? r + 1u : 0u;
            ulong v = xh_branch_unified((uint)xh_rotl(result, (uint)c) & 15u, a, b, c, result, r1, i, j);
            ulong seed = v ^ result;
            result = xh_rotl(seed, r1);
            uint it = xh_map_index(seed) + (xh_pick_half(v) ? XH_BUF_WORDS : 0u);
            uint na = xh_map_index(result);
            ulong t = sp[it * XH_LANES];
            ulong a_next = XH_A(na);
            ulong c_next = sp[r1 * XH_LANES];
            t ^= result;
            uint ia = xh_map_index(t ^ result ^ 0x9e3779b97f4a7c15ul);
            uint ib = xh_map_index((ulong)ia ^ ~result ^ 0xd2b74407b1ce6e93ul);
            ulong old = XH_A(ia);
            ulong bo = XH_B(ib);
            if (na == ia) a_next = t;
            uint nb = xh_map_index(a_next ^ ~xh_rotr(result, r1));
            ulong b_next = XH_B(nb);
            ulong nbv = bo ^ old ^ xh_rotr(t, i + j);
            XH_A(ia) = t;
            XH_B(ib) = nbv;
            if (nb == ib) b_next = nbv;
            if (r1 == ia) c_next = t;
            if (r1 == XH_BUF_WORDS + ib) c_next = nbv;
            a = a_next;
            b = b_next;
            c = c_next;
            r = r1;
        }
        if (i == 0u) {
            addr_a = xh_modpow(addr_a, addr_b, result);
            addr_b = xh_isqrt(result) * ((ulong)r + 1ul) * xh_isqrt(addr_a);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Stage 4: BLAKE3 of the whole scratchpad (531 chunks). Chunk chaining values are written over the
// first 32 bytes of each chunk once it has been read, then merged as BLAKE3's left-balanced tree:
// root = P(P[0..512), P(P[512..528), P(P(528, 529), 530))).

static inline void xh_slot_load(device const ulong *sp, uint chunk, thread uint *dst) {
    for (uint q = 0u; q < 4u; q++) {
        ulong w = sp[(chunk * 128u + q) * XH_LANES];
        dst[2u * q] = (uint)w;
        dst[2u * q + 1u] = (uint)(w >> 32);
    }
}

static inline void xh_slot_store(device ulong *sp, uint chunk, thread const uint *cv) {
    for (uint q = 0u; q < 4u; q++) {
        sp[(chunk * 128u + q) * XH_LANES] = (ulong)cv[2u * q] | ((ulong)cv[2u * q + 1u] << 32);
    }
}

static inline void xh_parent(device ulong *sp, uint left, uint right, uint flags, thread uint *cv) {
    uint m[16];
    xh_slot_load(sp, left, m);
    xh_slot_load(sp, right, m + 8);
    xh_b3_iv(cv);
    xh_b3_compress(cv, m, 0ul, 64u, XH_B3_PARENT | flags);
}

static inline void xh_merge_perfect(device ulong *sp, uint start, uint len) {
    uint cv[8];
    for (uint step = 1u; step < len; step <<= 1) {
        for (uint k = start; k < start + len; k += 2u * step) {
            xh_parent(sp, k, k + step, 0u, cv);
            xh_slot_store(sp, k, cv);
        }
    }
}

static void xh_stage4(device ulong *sp, thread uint *out) {
    for (uint k = 0u; k < XH_B3_CHUNKS; k++) {
        device const ulong *chunk = sp + k * 128u * XH_LANES;
        uint cv[8];
        uint m[16];
        xh_b3_iv(cv);
        for (uint blk = 0u; blk < 16u; blk++) {
            for (uint q = 0u; q < 8u; q++) {
                ulong w = chunk[(blk * 8u + q) * XH_LANES];
                m[2u * q] = (uint)w;
                m[2u * q + 1u] = (uint)(w >> 32);
            }
            uint flags = (blk == 0u ? XH_B3_START : 0u) | (blk == 15u ? XH_B3_END : 0u);
            xh_b3_compress(cv, m, (ulong)k, 64u, flags);
        }
        xh_slot_store(sp, k, cv);
    }
    uint cv[8];
    xh_merge_perfect(sp, 0u, 512u);
    xh_merge_perfect(sp, 512u, 16u);
    xh_parent(sp, 528u, 529u, 0u, cv);
    xh_slot_store(sp, 528u, cv);
    xh_parent(sp, 528u, 530u, 0u, cv);
    xh_slot_store(sp, 528u, cv);
    xh_parent(sp, 512u, 528u, 0u, cv);
    xh_slot_store(sp, 512u, cv);
    xh_parent(sp, 0u, 512u, XH_B3_ROOT, out);
}

// ---------------------------------------------------------------------------------------------
// Search kernels: one thread per nonce. Thread gid uses scratchpad slot gid (count <= slots).
// The 112-byte MinerWork: header work hash (32) | timestamp ms u64 BE (8) | nonce u64 BE (8) |
// extra nonce (32) | miner public key (32). A hit is hash <= target, both read as big-endian 256-bit.

static inline void xh_search(constant XhParams &p, device ulong *scratch, device SearchOutput *out,
                             device uint *hashes, uint gid, bool pipelined) {
    if (gid >= p.count) return;
    ulong nonce = p.startNonce + (ulong)gid;
    uint in[32];
    for (uint k = 0u; k < 28u; k++) in[k] = p.work[k];
    in[10] = bswap32((uint)(nonce >> 32));
    in[11] = bswap32((uint)nonce);
    in[28] = 0u; in[29] = 0u; in[30] = 0u; in[31] = 0u;

    device ulong *sp = scratch + (ulong)(gid / XH_LANES) * ((ulong)XH_MEM_WORDS * XH_LANES) + (gid % XH_LANES);
    xh_stage1(in, sp);
    if (pipelined) xh_stage3_pipelined(sp);
    else xh_stage3_simple(sp);
    uint h[8];
    xh_stage4(sp, h);

    int cmp = 0;
    for (uint k = 0u; k < 8u; k++) {
        if (cmp == 0) {
            uint hv = bswap32(h[k]);
            uint tv = p.target[k];
            cmp = hv < tv ? -1 : (hv > tv ? 1 : 0);
        }
    }
    if (cmp <= 0) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
    if ((p.flags & 1u) != 0u) {
        for (uint k = 0u; k < 8u; k++) hashes[gid * 8u + k] = h[k];
    }
}

kernel void xelishash_search_simple(constant XhParams &p [[buffer(0)]],
                                    device ulong *scratch [[buffer(1)]],
                                    device SearchOutput *out [[buffer(2)]],
                                    device uint *hashes [[buffer(3)]],
                                    uint gid [[thread_position_in_grid]]) {
    xh_search(p, scratch, out, hashes, gid, false);
}

kernel void xelishash_search_pipelined(constant XhParams &p [[buffer(0)]],
                                       device ulong *scratch [[buffer(1)]],
                                       device SearchOutput *out [[buffer(2)]],
                                       device uint *hashes [[buffer(3)]],
                                       uint gid [[thread_position_in_grid]]) {
    xh_search(p, scratch, out, hashes, gid, true);
}

// Unit tests for the arithmetic primitives against the CPU reference (rare paths that random
// hashes almost never reach: isqrt near 2^64, u128 division corner cases, every S-box entry).
struct XhPrimCase {
    ulong x, y, z, w;
    uint op, pad;
};

kernel void xelishash_primitives(device const XhPrimCase *cases [[buffer(0)]],
                                 device ulong *results [[buffer(1)]],
                                 constant uint &n [[buffer(2)]],
                                 uint gid [[thread_position_in_grid]]) {
    if (gid >= n) return;
    XhPrimCase c = cases[gid];
    ulong r0 = 0ul, r1 = 0ul;
    switch (c.op) {
    case 0u: r0 = xh_isqrt(c.x); break;
    case 1u: xh_divrem128(c.x, c.y, c.z, c.w, r0, r1); break;
    case 2u: xh_aes_round(c.x, c.y, r0, r1); break;
    case 3u: r0 = xh_modpow(c.x, c.y, c.z); break;
    case 4u: r0 = (ulong)xh_map_index(c.x); r1 = xh_murmur(c.x); break;
    case 5u: r0 = xh_mulhi(c.x, c.y); r1 = xh_pick_half(c.x) ? 1ul : 0ul; break;
    default: break;
    }
    results[2u * gid] = r0;
    results[2u * gid + 1u] = r1;
}
