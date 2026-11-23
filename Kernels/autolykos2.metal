// Autolykos v2 (Ergo): table generation, search, and full-hash kernels.
//
// Table: N elements of 32 bytes. Element j is Blake2b256(j || height || M) without its first byte: a 248-bit
// big-endian number, stored as 8 little-endian uint limbs (limb 0 least significant, limb 7 < 2^24).
// Per nonce (one thread): H(msg || nonce) picks element i; H(element i || msg || nonce) yields 32 indexes;
// the 32 elements are summed, and H(sum as 32 big-endian bytes) is the hit, a big-endian number that must
// be below the target. H is BLAKE2b-256; the nonce is 8 big-endian bytes.
//
// Build options (library macros): AL2_U64 runs BLAKE2b on ulong and leaves the 64-bit emulation to the
// compiler; by default it runs on uint2 halves (explicit carries, rotations as 32-bit shifts), and AL2_MIX
// keeps those rotations but does the additions on ulong. AL2_GROUP is the largest threadgroup the
// cooperative kernels accept.

#ifndef AL2_GROUP
#define AL2_GROUP 256
#endif

#define AL2_IV0 0x6A09E667F3BCC908UL
#define AL2_IV1 0xBB67AE8584CAA73BUL
#define AL2_IV2 0x3C6EF372FE94F82BUL
#define AL2_IV3 0xA54FF53A5F1D36F1UL
#define AL2_IV4 0x510E527FADE682D1UL
#define AL2_IV5 0x9B05688C2B3E6C1FUL
#define AL2_IV6 0x1F83D9ABFB41BD6BUL
#define AL2_IV7 0x5BE0CD19137E2179UL
// First state word for an unkeyed 32-byte digest.
#define AL2_H0 (AL2_IV0 ^ 0x01010020UL)

static inline ulong al2_word(uint lo, uint hi) { return (ulong)lo | ((ulong)hi << 32); }

#ifndef AL2_U64
// 64-bit lanes as uint2 (x = low half, y = high half).
#define AL2_T uint2
#define AL2_IN(x) as_type<uint2>(x)
#define AL2_OUT(x) as_type<ulong>(x)
static inline uint2 al2_add(uint2 a, uint2 b)
{
#ifdef AL2_MIX
    return as_type<uint2>(as_type<ulong>(a) + as_type<ulong>(b));
#else
    uint lo = a.x + b.x;
    return uint2(lo, a.y + b.y + (lo < a.x ? 1u : 0u));
#endif
}
static inline uint2 al2_ror24(uint2 a) { return uint2((a.x >> 24) | (a.y << 8), (a.y >> 24) | (a.x << 8)); }
static inline uint2 al2_ror16(uint2 a) { return uint2((a.x >> 16) | (a.y << 16), (a.y >> 16) | (a.x << 16)); }
static inline uint2 al2_ror63(uint2 a) { return uint2((a.x << 1) | (a.y >> 31), (a.y << 1) | (a.x >> 31)); }
#define AL2_G(a, b, c, d, x, y)                                                                     \
    a = al2_add(al2_add(a, b), AL2_IN(x)); d = (d ^ a).yx; c = al2_add(c, d); b = al2_ror24(b ^ c); \
    a = al2_add(al2_add(a, b), AL2_IN(y)); d = al2_ror16(d ^ a); c = al2_add(c, d); b = al2_ror63(b ^ c);
#else
#define AL2_T ulong
#define AL2_IN(x) (x)
#define AL2_OUT(x) (x)
static inline ulong al2_rotr(ulong x, uint n) { return (x >> n) | (x << (64u - n)); }
#define AL2_G(a, b, c, d, x, y)                                                     \
    a = a + b + (x); d = al2_rotr(d ^ a, 32); c = c + d; b = al2_rotr(b ^ c, 24);   \
    a = a + b + (y); d = al2_rotr(d ^ a, 16); c = c + d; b = al2_rotr(b ^ c, 63);
#endif

#define AL2_ROUND(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15) \
    AL2_G(v0, v4, v8,  v12, m[s0],  m[s1])                                              \
    AL2_G(v1, v5, v9,  v13, m[s2],  m[s3])                                              \
    AL2_G(v2, v6, v10, v14, m[s4],  m[s5])                                              \
    AL2_G(v3, v7, v11, v15, m[s6],  m[s7])                                              \
    AL2_G(v0, v5, v10, v15, m[s8],  m[s9])                                              \
    AL2_G(v1, v6, v11, v12, m[s10], m[s11])                                             \
    AL2_G(v2, v7, v8,  v13, m[s12], m[s13])                                             \
    AL2_G(v3, v4, v9,  v14, m[s14], m[s15])

// One BLAKE2b compression: state h absorbs block m (16 little-endian words); t counts the bytes hashed so far.
static inline void al2_compress(thread ulong *h, thread const ulong *m, ulong t, bool last)
{
    AL2_T v0 = AL2_IN(h[0]), v1 = AL2_IN(h[1]), v2 = AL2_IN(h[2]), v3 = AL2_IN(h[3]);
    AL2_T v4 = AL2_IN(h[4]), v5 = AL2_IN(h[5]), v6 = AL2_IN(h[6]), v7 = AL2_IN(h[7]);
    AL2_T v8 = AL2_IN(AL2_IV0), v9 = AL2_IN(AL2_IV1), v10 = AL2_IN(AL2_IV2), v11 = AL2_IN(AL2_IV3);
    AL2_T v12 = AL2_IN(AL2_IV4 ^ t), v13 = AL2_IN(AL2_IV5), v14 = AL2_IN(last ? ~AL2_IV6 : AL2_IV6), v15 = AL2_IN(AL2_IV7);
    AL2_ROUND( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15)
    AL2_ROUND(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3)
    AL2_ROUND(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4)
    AL2_ROUND( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8)
    AL2_ROUND( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13)
    AL2_ROUND( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9)
    AL2_ROUND(12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11)
    AL2_ROUND(13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10)
    AL2_ROUND( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5)
    AL2_ROUND(10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0)
    AL2_ROUND( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15)
    AL2_ROUND(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3)
    h[0] ^= AL2_OUT(v0 ^ v8);  h[1] ^= AL2_OUT(v1 ^ v9);  h[2] ^= AL2_OUT(v2 ^ v10); h[3] ^= AL2_OUT(v3 ^ v11);
    h[4] ^= AL2_OUT(v4 ^ v12); h[5] ^= AL2_OUT(v5 ^ v13); h[6] ^= AL2_OUT(v6 ^ v14); h[7] ^= AL2_OUT(v7 ^ v15);
}

// BLAKE2b-256 of a single block holding len (<= 128) bytes; the digest as 4 little-endian words.
static inline void al2_hash1(thread const ulong *m, ulong len, thread ulong *out)
{
    ulong h[8] = { AL2_H0, AL2_IV1, AL2_IV2, AL2_IV3, AL2_IV4, AL2_IV5, AL2_IV6, AL2_IV7 };
    al2_compress(h, m, len, true);
    out[0] = h[0]; out[1] = h[1]; out[2] = h[2]; out[3] = h[3];
}

// x mod n for n < 2^31, with m = floor((2^32 - 1) / n): the quotient estimate is low by at most 1.
static inline uint al2_mod32(uint x, uint n, uint m)
{
    uint r = x - mulhi(x, m) * n;
    return r >= n ? r - n : r;
}

// x mod n for 64-bit x, with m = floor((2^64 - 1) / n).
static inline uint al2_mod64(ulong x, uint n, ulong m)
{
    ulong r = x - mulhi(x, m) * (ulong)n;
    return (uint)(r >= (ulong)n ? r - (ulong)n : r);
}

// Per-job constants, built on the host.
struct AL2Params {
    ulong msg[4];      // the 32-byte message as little-endian words
    ulong seedMsg[3];  // seed-hash words 4..6: message bytes 1..24, which sit one byte off the word grid
    ulong mod64;       // floor((2^64 - 1) / N)
    uint  n;           // table size N
    uint  mod32;       // floor((2^32 - 1) / N)
};

// First half of an evaluation: i = (last 8 bytes of H(msg || nonce), big-endian) mod N, then the seed hash
// H(element i as 31 bytes || msg || nonce) over 71 bytes, returned as 4 little-endian words.
static inline void al2_seed(device const uint4 *table, constant AL2Params &p, ulong nonce,
                            thread uint &first, thread ulong *seed)
{
    ulong nq = bswap64(nonce);   // the nonce's 8 big-endian bytes, loaded as a little-endian word
    ulong m[16];
    ulong d[4];
    m[0] = p.msg[0]; m[1] = p.msg[1]; m[2] = p.msg[2]; m[3] = p.msg[3]; m[4] = nq;
    #pragma unroll
    for (int j = 5; j < 16; j++) m[j] = 0;
    al2_hash1(m, 40, d);
    uint i = al2_mod64(bswap64(d[3]), p.n, p.mod64);
    first = i;

    // b0..b3: the element's 32 big-endian bytes (byte 0 is the dropped zero) as little-endian words
    uint4 e0 = table[2 * (ulong)i], e1 = table[2 * (ulong)i + 1];
    ulong b0 = bswap64(al2_word(e1.z, e1.w));
    ulong b1 = bswap64(al2_word(e1.x, e1.y));
    ulong b2 = bswap64(al2_word(e0.z, e0.w));
    ulong b3 = bswap64(al2_word(e0.x, e0.y));
    m[0] = (b0 >> 8) | (b1 << 56);
    m[1] = (b1 >> 8) | (b2 << 56);
    m[2] = (b2 >> 8) | (b3 << 56);
    m[3] = (b3 >> 8) | (p.msg[0] << 56);
    m[4] = p.seedMsg[0]; m[5] = p.seedMsg[1]; m[6] = p.seedMsg[2];
    m[7] = (p.msg[3] >> 8) | (nq << 56);
    m[8] = nq >> 8;
    #pragma unroll
    for (int j = 9; j < 16; j++) m[j] = 0;
    al2_hash1(m, 71, seed);
}

// Index k (0..31): the big-endian 4-byte window at byte k of seed || seed[0..2], mod N. w[q] is seed bytes
// 4q..4q+3 read big-endian, with w[8] = w[0].
#define AL2_INDEX(w, k, p) al2_mod32(((k) & 3) == 0 ? w[(k) >> 2]                                         \
                                     : (w[(k) >> 2] << (8 * ((k) & 3))) | (w[((k) >> 2) + 1] >> (32 - 8 * ((k) & 3))), \
                                     p.n, p.mod32)

static inline void al2_windows(thread const ulong *seed, thread uint *w)
{
    #pragma unroll
    for (int q = 0; q < 4; q++) { w[2*q] = bswap32((uint)seed[q]); w[2*q+1] = bswap32((uint)(seed[q] >> 32)); }
    w[8] = w[0];
}

// Second half: hit = H(sum as 32 big-endian bytes) from the 8 limb accumulators (carries not yet propagated),
// as 8 words, most significant first.
static inline void al2_finish(thread ulong *acc, thread uint *hit)
{
    #pragma unroll
    for (int l = 0; l < 7; l++) acc[l + 1] += acc[l] >> 32;   // the low 32 bits of acc[l] are now limb l
    ulong m[16];
    ulong d[4];
    m[0] = bswap64(al2_word((uint)acc[6], (uint)acc[7]));
    m[1] = bswap64(al2_word((uint)acc[4], (uint)acc[5]));
    m[2] = bswap64(al2_word((uint)acc[2], (uint)acc[3]));
    m[3] = bswap64(al2_word((uint)acc[0], (uint)acc[1]));
    #pragma unroll
    for (int j = 4; j < 16; j++) m[j] = 0;
    al2_hash1(m, 32, d);
    #pragma unroll
    for (int q = 0; q < 4; q++) { hit[2*q] = bswap32((uint)d[q]); hit[2*q+1] = bswap32((uint)(d[q] >> 32)); }
}

// Full evaluation for one nonce, each thread on its own: the first index, the seed hash and the hit.
static inline void al2_eval(device const uint4 *table, constant AL2Params &p, ulong nonce,
                            thread uint &first, thread ulong *seed, thread uint *hit)
{
    al2_seed(table, p, nonce, first, seed);
    uint w[9];
    al2_windows(seed, w);
    ulong acc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    #pragma unroll
    for (int k = 0; k < 32; k++) {
        ulong at = 2 * (ulong)AL2_INDEX(w, k, p);
        uint4 a = table[at], b = table[at + 1];
        acc[0] += a.x; acc[1] += a.y; acc[2] += a.z; acc[3] += a.w;
        acc[4] += b.x; acc[5] += b.y; acc[6] += b.z; acc[7] += b.w;
    }
    al2_finish(acc, hit);
}

// Cooperative evaluation: the 8 lanes of a set (lanes 8s..8s+7 of a SIMD group) gather each element together,
// lane t of the set loading limb t, so every load instruction reads 4 whole 32-byte elements. Lane t keeps limb
// t's running sum for each of the set's 8 nonces; threadgroup memory transposes the sums back to their own
// lanes. All 32 lanes of the SIMD group must be running (dispatch a multiple of 32 threads).
static inline void al2_eval_coop(device const uint4 *table, constant AL2Params &p, ulong nonce,
                                 uint lane, uint tid, threadgroup ulong *slots,
                                 thread uint &first, thread ulong *seed, thread uint *hit)
{
    al2_seed(table, p, nonce, first, seed);
    uint w[9];
    al2_windows(seed, w);
    uint idx[32];
    #pragma unroll
    for (int k = 0; k < 32; k++) idx[k] = AL2_INDEX(w, k, p);

    device const uint *limbs = (device const uint *)table;
    uint t = lane & 7u;
    ushort set = (ushort)(lane - t);
    uint last = p.n - 1;
    ulong acc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };   // acc[g]: limb t of the sum for the nonce of lane set + g
    #pragma unroll
    for (int k = 0; k < 32; k++) {
        #pragma unroll
        for (int g = 0; g < 8; g++) {
            uint e = min(simd_shuffle(idx[k], (ushort)(set + g)), last);
            acc[g] += limbs[8 * (ulong)e + t];
        }
    }
    threadgroup ulong *mine = slots + 8 * (tid - t);   // this set's 64 slots: [nonce g][limb t]
    #pragma unroll
    for (int g = 0; g < 8; g++) mine[8 * g + t] = acc[g];
    simdgroup_barrier(mem_flags::mem_threadgroup);
    #pragma unroll
    for (int l = 0; l < 8; l++) acc[l] = mine[8 * t + l];
    al2_finish(acc, hit);
}

// a < b for 256-bit numbers held as 8 words, most significant first.
static inline bool al2_less(thread const uint *a, constant uint *b)
{
    for (int k = 0; k < 8; k++) {
        if (a[k] != b[k]) return a[k] < b[k];
    }
    return false;
}

// One table element per thread: elements [first, first + threads), clipped to n.
kernel void autolykos2_table(device uint4 *table    [[buffer(0)]],
                             constant uint &first   [[buffer(1)]],
                             constant uint &n       [[buffer(2)]],
                             constant uint &height  [[buffer(3)]],
                             uint gid [[thread_position_in_grid]])
{
    uint j = first + gid;
    if (j >= n) return;
    ulong h[8] = { AL2_H0, AL2_IV1, AL2_IV2, AL2_IV3, AL2_IV4, AL2_IV5, AL2_IV6, AL2_IV7 };
    ulong m[16];
    // Input: j (4 bytes, big-endian) || height (4 bytes, big-endian) || M, where M[k] = k as 8 big-endian
    // bytes; as little-endian words, M[k] has only its high half set: bswap32(k) << 32.
    m[0] = al2_word(bswap32(j), bswap32(height));
    #pragma unroll
    for (uint x = 1; x < 16; x++) m[x] = (ulong)bswap32(x - 1) << 32;
    al2_compress(h, m, 128, false);
    for (uint blk = 1; blk < 64; blk++) {          // block blk holds M[16 blk - 1 ... 16 blk + 14]
        uint base = 16 * blk - 1;
        #pragma unroll
        for (uint x = 0; x < 16; x++) m[x] = (ulong)bswap32(base + x) << 32;
        al2_compress(h, m, 128 * (ulong)(blk + 1), false);
    }
    m[0] = (ulong)bswap32(1023u) << 32;            // the last 8 of 8200 bytes
    #pragma unroll
    for (uint x = 1; x < 16; x++) m[x] = 0;
    al2_compress(h, m, 8200, true);
    // limb k is digest bytes 28 - 4k ... 31 - 4k read big-endian; dropping digest byte 0 clears limb 7's top byte
    device uint4 *out = table + 2 * (ulong)j;
    out[0] = uint4(bswap32((uint)(h[3] >> 32)), bswap32((uint)h[3]), bswap32((uint)(h[2] >> 32)), bswap32((uint)h[2]));
    out[1] = uint4(bswap32((uint)(h[1] >> 32)), bswap32((uint)h[1]), bswap32((uint)(h[0] >> 32)),
                   bswap32((uint)h[0]) & 0x00FFFFFFu);
}

static inline void al2_report(thread const uint *hit, constant uint *target, ulong nonce, device SearchOutput *out)
{
    if (al2_less(hit, target)) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
}

static inline void al2_store(device uint *results, uint gid, uint first, thread const ulong *seed, thread const uint *hit)
{
    device uint *r = results + 17 * gid;
    r[0] = first;
    for (int q = 0; q < 4; q++) { r[1 + 2*q] = (uint)seed[q]; r[2 + 2*q] = (uint)(seed[q] >> 32); }
    for (int k = 0; k < 8; k++) r[9 + k] = hit[k];
}

// Search: one nonce per thread from startNonce; hits (hit < target) go to out.
kernel void autolykos2_search(device const uint4 *table   [[buffer(0)]],
                              constant AL2Params &p        [[buffer(1)]],
                              constant ulong &startNonce   [[buffer(2)]],
                              constant uint *target        [[buffer(3)]],
                              device SearchOutput *out     [[buffer(4)]],
                              uint gid [[thread_position_in_grid]])
{
    ulong nonce = startNonce + gid;
    uint first;
    ulong seed[4];
    uint hit[8];
    al2_eval(table, p, nonce, first, seed, hit);
    al2_report(hit, target, nonce, out);
}

// Every intermediate for given nonces (cross-checking), 17 words per nonce: i, the seed hash as 8
// little-endian words (its bytes in order), then the hit as 8 words, most significant first.
kernel void autolykos2_hash(device const uint4 *table   [[buffer(0)]],
                            constant AL2Params &p        [[buffer(1)]],
                            device const ulong *nonces   [[buffer(2)]],
                            device uint *results         [[buffer(3)]],
                            uint gid [[thread_position_in_grid]])
{
    uint first;
    ulong seed[4];
    uint hit[8];
    al2_eval(table, p, nonces[gid], first, seed, hit);
    al2_store(results, gid, first, seed, hit);
}

kernel void autolykos2_search_coop(device const uint4 *table   [[buffer(0)]],
                                   constant AL2Params &p        [[buffer(1)]],
                                   constant ulong &startNonce   [[buffer(2)]],
                                   constant uint *target        [[buffer(3)]],
                                   device SearchOutput *out     [[buffer(4)]],
                                   uint gid  [[thread_position_in_grid]],
                                   uint tid  [[thread_index_in_threadgroup]],
                                   uint lane [[thread_index_in_simdgroup]])
{
    threadgroup ulong slots[AL2_GROUP * 8];
    ulong nonce = startNonce + gid;
    uint first;
    ulong seed[4];
    uint hit[8];
    al2_eval_coop(table, p, nonce, lane, tid, slots, first, seed, hit);
    al2_report(hit, target, nonce, out);
}

kernel void autolykos2_hash_coop(device const uint4 *table   [[buffer(0)]],
                                 constant AL2Params &p        [[buffer(1)]],
                                 device const ulong *nonces   [[buffer(2)]],
                                 device uint *results         [[buffer(3)]],
                                 uint gid  [[thread_position_in_grid]],
                                 uint tid  [[thread_index_in_threadgroup]],
                                 uint lane [[thread_index_in_simdgroup]])
{
    threadgroup ulong slots[AL2_GROUP * 8];
    uint first;
    ulong seed[4];
    uint hit[8];
    al2_eval_coop(table, p, nonces[gid], lane, tid, slots, first, seed, hit);
    al2_store(results, gid, first, seed, hit);
}
