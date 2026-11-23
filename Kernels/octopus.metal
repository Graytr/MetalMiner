// Octopus (Conflux). Per warp of 32 nonces (from a multiple of 32), SipHash chains fill the 1024
// coefficients of a polynomial over F_P, P = 1032193 = 2^20 - 2^14 + 1; each nonce evaluates it at 32 points
// (Horner, 32 x 1024 multiply-adds); the values steer an Ethash-style walk of 32 accesses over 256-byte DAG
// pages; Keccak-256 gives the final hash. Needs ethash.metal first (ethash_keccakf, ethash_fnv; the DAG items
// are Ethash's and EthashDAG builds them). Threadgroups: a multiple of 32 threads, at most OCTOPUS_GROUP, and
// nonces start at a multiple of 32, so SIMD lane == nonce % 32.

#ifndef OCTOPUS_GROUP
#define OCTOPUS_GROUP 128
#endif
#ifndef OCTOPUS_CHAINS
#define OCTOPUS_CHAINS 8       // points evaluated together in one Horner pass (divides 32)
#endif
#ifndef OCTOPUS_PAR
#define OCTOPUS_PAR 2          // hashes in flight per 16-lane group in the cooperative walk
#endif
#ifndef OCTOPUS_MULMOD
#define OCTOPUS_MULMOD 0       // 0: fp32 with exact FMA error term, 1: 32-bit Shoup, 2: 64-bit remainder
#endif
#ifndef OCTOPUS_FASTMOD
#define OCTOPUS_FASTMOD 1      // page index: 1 = float reciprocal and correction, 0 = integer %
#endif
#ifndef OCTOPUS_PHASE
#define OCTOPUS_PHASE 0        // diagnostics: 1 = skip the polynomial, 2 = skip the DAG loads, 3 = skip both
#endif

#define OCTOPUS_P  1032193u
#define OCTOPUS_PF 1032193.0f
#define OCTOPUS_SKIP_POLY (OCTOPUS_PHASE == 1 || OCTOPUS_PHASE == 3)
#define OCTOPUS_SKIP_LOADS (OCTOPUS_PHASE >= 2)

static inline void octopus_sipround(thread ulong &v0, thread ulong &v1, thread ulong &v2, thread ulong &v3) {
    v0 += v1; v2 += v3; v1 = rotl64(v1, 13); v3 = rotl64(v3, 16); v1 ^= v0; v3 ^= v2; v0 = rotl64(v0, 32);
    v2 += v1; v0 += v3; v1 = rotl64(v1, 17); v3 = rotl64(v3, 21); v1 ^= v2; v3 ^= v0; v2 = rotl64(v2, 32);
}

// pv * x + d mod P in fp32, kept as an exact integer in (-P, 2P). ph + pl is the exact product (FMA error
// term), q = round(pv * x / P) is within 1 of the true quotient, and ph - q*P is small, so FMA gives it exactly.
// Seven full-rate fp32 ops; integer Shoup (3 multiplies) measured 3.7x slower on this GPU.
static inline float octopus_mma(float pv, float x, float xinv, float d) {
    float ph = pv * x;
    float pl = fma(pv, x, -ph);
    float q = rint(pv * xinv);
    float r = fma(-q, OCTOPUS_PF, ph);
    return (r + pl) + d;
}

// pv * x + d mod P with Shoup's xs = floor(x * 2^32 / P): any 32-bit pv in, result below 3P.
static inline uint octopus_mma_shoup(uint pv, uint x, uint xs, uint d) {
    uint q = mulhi(pv, xs);
    return pv * x - q * OCTOPUS_P + d;
}

// v mod m for the page index; minv = 1/m. The float quotient is within 1 of floor(v/m), then corrected.
static inline uint octopus_mod(uint v, uint m, float minv) {
#if OCTOPUS_FASTMOD
    uint q = (uint)((float)v * minv);
    int r = (int)(v - q * m);
    r += r < 0 ? (int)m : 0;
    r -= r >= (int)m ? (int)m : 0;
    return (uint)r;
#else
    return v % m;
#endif
}

// The polynomial phase for one nonce. `d` is this SIMD group's 1024 words of threadgroup memory: first the
// warp's coefficients d[32 j + lane], then its values res[32 i + lane]. Returns the FNV-64 fold of the values.
// `points` holds, per k < 1024: x_k as float bits, x_k / P as float bits, x_k, floor(x_k * 2^32 / P).
static inline ulong octopus_poly(constant ulong *header, device const uint4 *points, ulong nonce, uint lane,
                                 threadgroup uint *d)
{
    ulong v0 = header[0], v1 = header[1], v2 = header[2], v3 = header[3];
    v3 ^= nonce;
    octopus_sipround(v0, v1, v2, v3);
    octopus_sipround(v0, v1, v2, v3);
    v0 ^= nonce;
    v2 ^= 0xffUL;
    for (int r = 0; r < 4; r++) octopus_sipround(v0, v1, v2, v3);
    for (uint j = 0; j < 32; j++) {
        octopus_sipround(v0, v1, v2, v3);
        uint c = (uint)(v0 ^ v1 ^ v2 ^ v3) % OCTOPUS_P;
#if OCTOPUS_MULMOD == 0 && !OCTOPUS_SKIP_POLY
        d[j * 32 + lane] = as_type<uint>((float)c);
#else
        d[j * 32 + lane] = c;
#endif
    }
    simdgroup_barrier(mem_flags::mem_threadgroup);

    uint res[32];
#if OCTOPUS_SKIP_POLY
    #pragma unroll
    for (int i = 0; i < 32; i++) res[i] = d[i * 32 + lane];
#else
    #pragma unroll
    for (uint c0 = 0; c0 < 32; c0 += OCTOPUS_CHAINS) {
#if OCTOPUS_MULMOD == 0
        float pv[OCTOPUS_CHAINS], xv[OCTOPUS_CHAINS], xi[OCTOPUS_CHAINS];
        #pragma unroll
        for (int k = 0; k < OCTOPUS_CHAINS; k++) {
            uint4 e = points[lane + 32 * (c0 + k)];
            xv[k] = as_type<float>(e.x);
            xi[k] = as_type<float>(e.y);
            pv[k] = 0.0f;
        }
        for (int j = 1020; j >= 0; j -= 4) {
            float4 dv = as_type<float4>(*(threadgroup const uint4 *)(d + j));
            #pragma unroll
            for (int s = 3; s >= 0; s--) {
                float dj = dv[s];
                #pragma unroll
                for (int k = 0; k < OCTOPUS_CHAINS; k++) pv[k] = octopus_mma(pv[k], xv[k], xi[k], dj);
            }
        }
        #pragma unroll
        for (int k = 0; k < OCTOPUS_CHAINS; k++) {
            float r = pv[k] < 0.0f ? pv[k] + OCTOPUS_PF : pv[k];
            res[c0 + k] = (uint)(r >= OCTOPUS_PF ? r - OCTOPUS_PF : r);
        }
#elif OCTOPUS_MULMOD == 1
        uint pv[OCTOPUS_CHAINS], xv[OCTOPUS_CHAINS], xs[OCTOPUS_CHAINS];
        #pragma unroll
        for (int k = 0; k < OCTOPUS_CHAINS; k++) {
            uint4 e = points[lane + 32 * (c0 + k)];
            xv[k] = e.z;
            xs[k] = e.w;
            pv[k] = 0;
        }
        for (int j = 1020; j >= 0; j -= 4) {
            uint4 dv = *(threadgroup const uint4 *)(d + j);
            #pragma unroll
            for (int s = 3; s >= 0; s--) {
                uint dj = dv[s];
                #pragma unroll
                for (int k = 0; k < OCTOPUS_CHAINS; k++) pv[k] = octopus_mma_shoup(pv[k], xv[k], xs[k], dj);
            }
        }
        #pragma unroll
        for (int k = 0; k < OCTOPUS_CHAINS; k++) {
            uint r = pv[k] >= OCTOPUS_P ? pv[k] - OCTOPUS_P : pv[k];
            res[c0 + k] = r >= OCTOPUS_P ? r - OCTOPUS_P : r;
        }
#else
        uint pv[OCTOPUS_CHAINS], xv[OCTOPUS_CHAINS];
        #pragma unroll
        for (int k = 0; k < OCTOPUS_CHAINS; k++) {
            xv[k] = points[lane + 32 * (c0 + k)].z;
            pv[k] = 0;
        }
        for (int j = 1023; j >= 0; j--) {
            uint dj = d[j];
            #pragma unroll
            for (int k = 0; k < OCTOPUS_CHAINS; k++) pv[k] = (uint)(((ulong)pv[k] * xv[k] + dj) % OCTOPUS_P);
        }
        #pragma unroll
        for (int k = 0; k < OCTOPUS_CHAINS; k++) res[c0 + k] = pv[k];
#endif
    }
#endif
    simdgroup_barrier(mem_flags::mem_threadgroup);
    ulong result = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        d[i * 32 + lane] = res[i];
        result = result * 0x01000193UL ^ (ulong)res[i];
    }
    simdgroup_barrier(mem_flags::mem_threadgroup);
    return result;
}

// seed = keccak512(header || result): 40 bytes, rate 72. Leaves the seed in st[0..7].
static inline void octopus_seed(constant ulong *header, ulong result, thread ulong *st) {
    st[0] = header[0]; st[1] = header[1]; st[2] = header[2]; st[3] = header[3];
    st[4] = result;
    st[5] = 0x01UL;
    #pragma unroll
    for (int i = 6; i < 25; i++) st[i] = 0;
    st[8] = 0x8000000000000000UL;
    ethash_keccakf(st);
}

// final = keccak256(seed || digest): 96 bytes, rate 136. st[0..7] must hold the seed.
static inline void octopus_final(thread ulong *st, thread const uint *digest, thread ulong *final) {
    #pragma unroll
    for (int i = 0; i < 4; i++) st[8 + i] = (ulong)digest[2*i] | ((ulong)digest[2*i+1] << 32);
    st[12] = 0x01UL;
    #pragma unroll
    for (int i = 13; i < 25; i++) st[i] = 0;
    st[16] = 0x8000000000000000UL;
    ethash_keccakf(st);
    #pragma unroll
    for (int i = 0; i < 4; i++) final[i] = st[i];
}

// Strict 256-bit comparison: the hash read big-endian against the boundary (4 limbs, most significant first).
static inline bool octopus_below(thread const ulong *final, constant ulong *target) {
    for (int k = 0; k < 4; k++) {
        ulong h = bswap64(final[k]);
        if (h != target[k]) return h < target[k];
    }
    return false;
}

// One thread walks its own nonce: 64 mix words in registers, 16 uint4 loads per page.
static inline void octopus_simple(device const uint4 *dag, constant ulong *header, device const uint4 *points,
                                  ulong nonce, uint pages, uint lane, threadgroup uint *d,
                                  thread uint *digest, thread ulong *final)
{
    ulong result = octopus_poly(header, points, nonce, lane, d);
    ulong st[25];
    octopus_seed(header, result, st);
    uint s[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { s[2*i] = (uint)st[i]; s[2*i+1] = (uint)(st[i] >> 32); }
    float pinv = 1.0f / (float)pages;
    uint mix[64];
    #pragma unroll
    for (int i = 0; i < 64; i++) mix[i] = s[i & 15];
    #pragma unroll
    for (uint i = 0; i < 32; i++) {
        uint page = octopus_mod(ethash_fnv(s[0] ^ i ^ d[i * 32 + lane], mix[i]), pages, pinv);
        device const uint4 *p = dag + 16 * (ulong)page;
        #pragma unroll
        for (int k = 0; k < 16; k++) {
#if OCTOPUS_SKIP_LOADS
            uint4 v = uint4(page + k);
#else
            uint4 v = p[k];
#endif
            mix[4*k]   = ethash_fnv(mix[4*k],   v.x);
            mix[4*k+1] = ethash_fnv(mix[4*k+1], v.y);
            mix[4*k+2] = ethash_fnv(mix[4*k+2], v.z);
            mix[4*k+3] = ethash_fnv(mix[4*k+3], v.w);
        }
    }
    #pragma unroll
    for (int k = 0; k < 8; k++) {
        uint r1 = ethash_fnv(ethash_fnv(ethash_fnv(mix[4*k], mix[4*k+1]), mix[4*k+2]), mix[4*k+3]);
        uint r2 = ethash_fnv(ethash_fnv(ethash_fnv(mix[32+4*k], mix[33+4*k]), mix[34+4*k]), mix[35+4*k]);
        digest[k] = ethash_fnv(r1, r2);
    }
    octopus_final(st, digest, final);
}

// Cooperative walk: 16 lanes share each hash, so every load fetches a whole 256-byte page (lane t reads
// uint4 t). Lane t holds mix words 4t..4t+3; the index for access i comes from lane i / 4. Each thread still
// owns one nonce; a 16-lane group walks its 16 hashes OCTOPUS_PAR at a time.
static inline void octopus_coop(device const uint4 *dag, constant ulong *header, device const uint4 *points,
                                ulong nonce, uint pages, uint tid, uint lane, threadgroup uint *d,
                                threadgroup uint4 *sharedS, thread uint *digest, thread ulong *final)
{
    ulong result = octopus_poly(header, points, nonce, lane, d);
    ulong st[25];
    octopus_seed(header, result, st);
    #pragma unroll
    for (int k = 0; k < 4; k++) {
        sharedS[tid * 4 + k] = uint4((uint)st[2*k], (uint)(st[2*k] >> 32), (uint)st[2*k+1], (uint)(st[2*k+1] >> 32));
    }
    simdgroup_barrier(mem_flags::mem_threadgroup);

    float pinv = 1.0f / (float)pages;
    uint t = lane & 15u;
    uint first = tid - t;                 // threadgroup index of this group's first thread
    ushort g0 = (ushort)(lane - t);       // and its SIMD lane
    for (uint h = 0; h < 16; h += OCTOPUS_PAR) {
        uint4 mix[OCTOPUS_PAR];
        uint s0[OCTOPUS_PAR];
        #pragma unroll
        for (int p = 0; p < OCTOPUS_PAR; p++) {
            mix[p] = sharedS[(first + h + p) * 4 + (t & 3u)];
            s0[p] = sharedS[(first + h + p) * 4].x;
        }
        for (uint a = 0; a < 32; a += 4) {
            ushort owner = g0 + (ushort)(a >> 2);
            #pragma unroll
            for (uint b = 0; b < 4; b++) {
                #pragma unroll
                for (int p = 0; p < OCTOPUS_PAR; p++) {
                    uint v = simd_shuffle(ethash_fnv(s0[p] ^ (a + b) ^ d[(a + b) * 32 + g0 + h + p], mix[p][b]), owner);
                    uint page = octopus_mod(v, pages, pinv);
#if OCTOPUS_SKIP_LOADS
                    uint4 x = uint4(page + t);
#else
                    uint4 x = dag[(ulong)page * 16 + t];
#endif
                    mix[p] = uint4(ethash_fnv(mix[p].x, x.x), ethash_fnv(mix[p].y, x.y),
                                   ethash_fnv(mix[p].z, x.z), ethash_fnv(mix[p].w, x.w));
                }
            }
        }
        #pragma unroll
        for (int p = 0; p < OCTOPUS_PAR; p++) {
            uint r = ethash_fnv(ethash_fnv(ethash_fnv(mix[p].x, mix[p].y), mix[p].z), mix[p].w);
            uint c = ethash_fnv(r, simd_shuffle_down(r, (ushort)8));   // lanes g0..g0+7: digest words 0..7
            #pragma unroll
            for (ushort k = 0; k < 8; k++) {
                uint w = simd_shuffle(c, (ushort)(g0 + k));
                if (t == h + p) digest[k] = w;
            }
        }
    }
    #pragma unroll
    for (int k = 0; k < 4; k++) {
        uint4 v = sharedS[tid * 4 + k];
        st[2*k] = (ulong)v.x | ((ulong)v.y << 32);
        st[2*k+1] = (ulong)v.z | ((ulong)v.w << 32);
    }
    octopus_final(st, digest, final);
}

static inline void octopus_report(thread const ulong *final, constant ulong *target, ulong nonce,
                                  device SearchOutput *out) {
    if (octopus_below(final, target)) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
}

static inline void octopus_store(thread const uint *digest, thread const ulong *final, device uint *r) {
    for (int i = 0; i < 8; i++) r[i] = digest[i];
    for (int i = 0; i < 4; i++) { r[8 + 2*i] = (uint)final[i]; r[9 + 2*i] = (uint)(final[i] >> 32); }
}

// Search: nonces startNonce + gid (startNonce a multiple of 32); hits are hashes below the boundary.
kernel void octopus_search(device const uint4 *dag     [[buffer(0)]],
                           constant ulong *header       [[buffer(1)]],
                           device const uint4 *points   [[buffer(2)]],
                           constant ulong &startNonce   [[buffer(3)]],
                           constant ulong *target       [[buffer(4)]],
                           constant uint &pages         [[buffer(5)]],
                           device SearchOutput *out     [[buffer(6)]],
                           uint gid  [[thread_position_in_grid]],
                           uint tid  [[thread_index_in_threadgroup]],
                           uint lane [[thread_index_in_simdgroup]],
                           uint sg   [[simdgroup_index_in_threadgroup]])
{
    threadgroup uint4 shared[OCTOPUS_GROUP * 8];
    threadgroup uint4 sharedS[OCTOPUS_GROUP * 4];
    ulong nonce = startNonce + gid;
    uint digest[8];
    ulong final[4];
    octopus_coop(dag, header, points, nonce, pages, tid, lane, (threadgroup uint *)(shared + sg * 256), sharedS,
                 digest, final);
    octopus_report(final, target, nonce, out);
}

kernel void octopus_search_simple(device const uint4 *dag     [[buffer(0)]],
                                  constant ulong *header       [[buffer(1)]],
                                  device const uint4 *points   [[buffer(2)]],
                                  constant ulong &startNonce   [[buffer(3)]],
                                  constant ulong *target       [[buffer(4)]],
                                  constant uint &pages         [[buffer(5)]],
                                  device SearchOutput *out     [[buffer(6)]],
                                  uint gid  [[thread_position_in_grid]],
                                  uint lane [[thread_index_in_simdgroup]],
                                  uint sg   [[simdgroup_index_in_threadgroup]])
{
    threadgroup uint4 shared[OCTOPUS_GROUP * 8];
    ulong nonce = startNonce + gid;
    uint digest[8];
    ulong final[4];
    octopus_simple(dag, header, points, nonce, pages, lane, (threadgroup uint *)(shared + sg * 256), digest, final);
    octopus_report(final, target, nonce, out);
}

// Full hashes for cross-checking: 16 words per nonce (digest, then the final hash's bytes as little-endian words).
kernel void octopus_hash(device const uint4 *dag     [[buffer(0)]],
                         constant ulong *header       [[buffer(1)]],
                         device const uint4 *points   [[buffer(2)]],
                         constant ulong &startNonce   [[buffer(3)]],
                         constant uint &pages         [[buffer(5)]],
                         device uint *results         [[buffer(6)]],
                         uint gid  [[thread_position_in_grid]],
                         uint tid  [[thread_index_in_threadgroup]],
                         uint lane [[thread_index_in_simdgroup]],
                         uint sg   [[simdgroup_index_in_threadgroup]])
{
    threadgroup uint4 shared[OCTOPUS_GROUP * 8];
    threadgroup uint4 sharedS[OCTOPUS_GROUP * 4];
    uint digest[8];
    ulong final[4];
    octopus_coop(dag, header, points, startNonce + gid, pages, tid, lane, (threadgroup uint *)(shared + sg * 256),
                 sharedS, digest, final);
    octopus_store(digest, final, results + 16 * gid);
}

kernel void octopus_hash_simple(device const uint4 *dag     [[buffer(0)]],
                                constant ulong *header       [[buffer(1)]],
                                device const uint4 *points   [[buffer(2)]],
                                constant ulong &startNonce   [[buffer(3)]],
                                constant uint &pages         [[buffer(5)]],
                                device uint *results         [[buffer(6)]],
                                uint gid  [[thread_position_in_grid]],
                                uint lane [[thread_index_in_simdgroup]],
                                uint sg   [[simdgroup_index_in_threadgroup]])
{
    threadgroup uint4 shared[OCTOPUS_GROUP * 8];
    uint digest[8];
    ulong final[4];
    octopus_simple(dag, header, points, startNonce + gid, pages, lane, (threadgroup uint *)(shared + sg * 256),
                   digest, final);
    octopus_store(digest, final, results + 16 * gid);
}
