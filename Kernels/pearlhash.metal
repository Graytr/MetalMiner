// PearlHash (Pearl, PRL): proof of useful work by noisy int7 matrix multiplication (docs/specs/pearlhash.md).
// Per instance (one choice of the miner's matrices A, B): low-rank noise from two BLAKE3 seeds is added
// to A and B; every 4 x 8 tile of A'B' (rows t+{0,8,64,72}, columns u+{0,1,8,9,32,33,40,41}) is one
// attempt: after each block of PEARLHASH_R products the tile's 32 int32 partial sums are XORed into one
// of 16 jackpot words, and BLAKE3(jackpot, key = A's noise seed) is compared, as a little-endian 256-bit
// number, with the bound (target x attempt work). Needs common.metal.
// Compile-time: PEARLHASH_K (common dimension, multiple of PEARLHASH_R), PEARLHASH_R (noise rank, multiple of 32).

#ifndef PEARLHASH_K
#define PEARLHASH_K 2048
#endif
#ifndef PEARLHASH_R
#define PEARLHASH_R 128
#endif
#define PEARLHASH_BLOCKS (PEARLHASH_K / PEARLHASH_R)
#define PEARLHASH_BK 32                 // k values staged in threadgroup memory per step
#define PEARLHASH_LDA 40                // halfs per row of the A' stage (32 + 8: conflict-free half2 reads)
#define PEARLHASH_LDB 72                // halfs per k row of the B' stage (64 + 8)
#define PEARLHASH_STAGE_A (128 * PEARLHASH_LDA)
#define PEARLHASH_STAGE_B (PEARLHASH_BK * PEARLHASH_LDB)
#define PEARLHASH_CHUNKS (PEARLHASH_K / PEARLHASH_BK)
#define PEARLHASH_CHUNKS_PER_BLOCK (PEARLHASH_R / PEARLHASH_BK)

struct PearlHashParams {
    uint m, n, k, r;
    uint aDraws, bDraws, permDraws, writeHashes;
    uint bound[8];          // inclusive bound, little-endian words
};

struct PearlHashInstance {  // one per instance, 256-byte stride on the host
    uint aSeed[8];
    uint bSeed[8];
    ulong nonce;
};

struct PearlHashHit { ulong nonce; uint tRows; uint tCols; };
struct PearlHashHits { atomic_uint count; uint pad; PearlHashHit hit[SEARCH_MAX_HITS]; };

constant uint PEARLHASH_IV[8] = { 0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                                  0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u };

#define PEARLHASH_G(a, b, c, d, x, y) {                                   \
    v[a] += v[b] + (x); v[d] = rotate(v[d] ^ v[a], 16u);                  \
    v[c] += v[d];       v[b] = rotate(v[b] ^ v[c], 20u);                  \
    v[a] += v[b] + (y); v[d] = rotate(v[d] ^ v[a], 24u);                  \
    v[c] += v[d];       v[b] = rotate(v[b] ^ v[c], 25u); }

// BLAKE3 of one whole 64-byte block with a 32-byte key: chunk start + end + root + keyed (flags 27),
// counter 0. Writes the 8-word digest; clobbers the message.
static inline void pearlhash_blake3_block(thread const uint *key, thread uint *m, thread uint *out)
{
    uint v[16] = { key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                   PEARLHASH_IV[0], PEARLHASH_IV[1], PEARLHASH_IV[2], PEARLHASH_IV[3], 0u, 0u, 64u, 27u };
    #pragma unroll
    for (int round = 0; round < 7; round++) {
        PEARLHASH_G(0, 4, 8, 12, m[0], m[1]);
        PEARLHASH_G(1, 5, 9, 13, m[2], m[3]);
        PEARLHASH_G(2, 6, 10, 14, m[4], m[5]);
        PEARLHASH_G(3, 7, 11, 15, m[6], m[7]);
        PEARLHASH_G(0, 5, 10, 15, m[8], m[9]);
        PEARLHASH_G(1, 6, 11, 12, m[10], m[11]);
        PEARLHASH_G(2, 7, 8, 13, m[12], m[13]);
        PEARLHASH_G(3, 4, 9, 14, m[14], m[15]);
        uint t[16] = { m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
                       m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8] };
        #pragma unroll
        for (int i = 0; i < 16; i++) m[i] = t[i];
    }
    #pragma unroll
    for (int i = 0; i < 8; i++) out[i] = v[i] ^ v[i + 8];
}

// Noise factors for one instance. Threads [0, aDraws) fill E_AL (m x r), then E_BR^T (n x r), each thread
// one 32-byte BLAKE3 draw of values (byte & 63) - 32; then the two sparse factors, 8 positions per draw:
// position l gets +1 at w & (r-1) and -1 at that ^ (1 + mulhi(r-1, w)).
kernel void pearlhash_noise(constant PearlHashParams &P       [[buffer(0)]],
                            device const PearlHashInstance &I [[buffer(1)]],
                            device uint *eal                  [[buffer(2)]],
                            device uint *ebr                  [[buffer(3)]],
                            device ushort2 *permA             [[buffer(4)]],
                            device ushort2 *permB             [[buffer(5)]],
                            uint gid [[thread_position_in_grid]])
{
    uint draw = gid;
    bool isA = true;
    bool uniform = true;
    if (draw < P.aDraws) {
    } else if ((draw -= P.aDraws) < P.bDraws) {
        isA = false;
    } else if ((draw -= P.bDraws) < P.permDraws) {
        uniform = false;
    } else if ((draw -= P.permDraws) < P.permDraws) {
        isA = false; uniform = false;
    } else {
        return;
    }
    uint key[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) key[i] = isA ? I.aSeed[i] : I.bSeed[i];
    // 8 i32 slots (index + 1 in slot 0 for the uniform factors, slot 1 for the sparse ones), then the
    // 32-byte label "A_tensor" / "B_tensor".
    uint msg[16] = { uniform ? draw + 1u : 0u, uniform ? 0u : draw + 1u, 0u, 0u, 0u, 0u, 0u, 0u,
                     isA ? 0x65745F41u : 0x65745F42u, 0x726F736Eu, 0u, 0u, 0u, 0u, 0u, 0u };
    uint h[8];
    pearlhash_blake3_block(key, msg, h);
    if (uniform) {
        device uint *dst = (isA ? eal : ebr) + draw * 8u;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            uint t = (h[i] & 0x3F3F3F3Fu) ^ 0x20202020u;   // bytewise (b & 63) - 32 as two's complement
            uint s = t & 0x20202020u;
            dst[i] = t | (s << 1) | (s << 2);
        }
    } else {
        device ushort2 *dst = isA ? permA : permB;
        uint rm1 = P.r - 1u;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            uint l = draw * 8u + uint(j);
            if (l < P.k) {
                uint first = h[j] & rm1;
                dst[l] = ushort2(ushort(first), ushort(first ^ (1u + mulhi(rm1, h[j]))));
            }
        }
    }
}

// A' = A + E_AL E_AR and B'^T = B^T + (E_BL E_BR)^T, 16 entries per thread. The instance nonce replaces
// the first 32 entries of B^T (column 0 of B), 2 bits each as values -2...1.
kernel void pearlhash_apply(constant PearlHashParams &P       [[buffer(0)]],
                            device const PearlHashInstance &I [[buffer(1)]],
                            device const uint4 *A             [[buffer(2)]],
                            device const uint4 *BT            [[buffer(3)]],
                            device const char *eal            [[buffer(4)]],
                            device const char *ebr            [[buffer(5)]],
                            device const ushort2 *permA       [[buffer(6)]],
                            device const ushort2 *permB       [[buffer(7)]],
                            device uint4 *An                  [[buffer(8)]],
                            device uint4 *Bn                  [[buffer(9)]],
                            uint gid [[thread_position_in_grid]])
{
    const uint perRow = P.k >> 4;
    const uint aVecs = P.m * perRow;
    if (gid >= aVecs + P.n * perRow) return;
    const bool isA = gid < aVecs;
    const uint v = isA ? gid : gid - aVecs;
    const uint row = v / perRow;
    const uint l0 = (v - row * perRow) << 4;
    const uint4 src = isA ? A[v] : BT[v];
    device const char *e = (isA ? eal : ebr) + (ulong)row * P.r;
    device const ushort2 *perm = (isA ? permA : permB) + l0;
    const bool nonceRow = !isA && row == 0u && l0 < 32u;
    uint words[4] = { src.x, src.y, src.z, src.w };
    uint outw[4];
    #pragma unroll
    for (int w = 0; w < 4; w++) {
        char4 c = as_type<char4>(words[w]);
        uint packed = 0;
        #pragma unroll
        for (int b = 0; b < 4; b++) {
            uint l = l0 + uint(w * 4 + b);
            int val = int(c[b]);
            if (nonceRow && l < 32u) val = int((I.nonce >> (2u * l)) & 3ul) - 2;
            ushort2 p = perm[w * 4 + b];
            val += int(e[p.x]) - int(e[p.y]);
            packed |= (uint(val) & 0xFFu) << (8u * uint(b));
        }
        outw[w] = packed;
    }
    (isA ? An : Bn)[v] = uint4(outw[0], outw[1], outw[2], outw[3]);
}

// Lane (fm, fn): the row and first column of the two cells of an 8x8 SIMD-group matrix a lane holds
// as thread_elements()[0..1] (the layout MLX uses; pearlhash_layout_probe checks it).
static inline uint pearlhash_lane_row(uint lane) { return ((lane >> 2) & 4u) + ((lane >> 1) & 3u); }
static inline uint pearlhash_lane_col(uint lane) { return ((lane >> 2) & 2u) * 2u + (lane & 1u) * 2u; }

// A fragment from this lane's two cells (consecutive halfs in threadgroup memory). Matrices are built
// per use and kept in named variables: this compiler spills arrays of simdgroup matrices to memory
// (about 20x slower; see pearlhash_lab.metal).
static inline simdgroup_float8x8 pearlhash_frag(threadgroup const half *cells)
{
    float2 v = float2(*(threadgroup const half2 *)cells);
    simdgroup_float8x8 m;
    m.thread_elements()[0] = v.x;
    m.thread_elements()[1] = v.y;
    return m;
}

#define PEARLHASH_MMA16 \
    simdgroup_multiply_accumulate(c00, a0, b0, c00); simdgroup_multiply_accumulate(c01, a0, b1, c01); \
    simdgroup_multiply_accumulate(c02, a0, b2, c02); simdgroup_multiply_accumulate(c03, a0, b3, c03); \
    simdgroup_multiply_accumulate(c10, a1, b0, c10); simdgroup_multiply_accumulate(c11, a1, b1, c11); \
    simdgroup_multiply_accumulate(c12, a1, b2, c12); simdgroup_multiply_accumulate(c13, a1, b3, c13); \
    simdgroup_multiply_accumulate(c20, a2, b0, c20); simdgroup_multiply_accumulate(c21, a2, b1, c21); \
    simdgroup_multiply_accumulate(c22, a2, b2, c22); simdgroup_multiply_accumulate(c23, a2, b3, c23); \
    simdgroup_multiply_accumulate(c30, a3, b0, c30); simdgroup_multiply_accumulate(c31, a3, b1, c31); \
    simdgroup_multiply_accumulate(c32, a3, b2, c32); simdgroup_multiply_accumulate(c33, a3, b3, c33);

// One staged chunk (PEARLHASH_BK values of k) into the 16 accumulators; aC/bC point at this lane's cells.
#define PEARLHASH_COMPUTE(aC, bC) \
    _Pragma("unroll") \
    for (uint kk = 0; kk < PEARLHASH_BK; kk += 8) { \
        const simdgroup_float8x8 a0 = pearlhash_frag((aC) + kk); \
        const simdgroup_float8x8 a1 = pearlhash_frag((aC) + 8 * PEARLHASH_LDA + kk); \
        const simdgroup_float8x8 a2 = pearlhash_frag((aC) + 64 * PEARLHASH_LDA + kk); \
        const simdgroup_float8x8 a3 = pearlhash_frag((aC) + 72 * PEARLHASH_LDA + kk); \
        const simdgroup_float8x8 b0 = pearlhash_frag((bC) + kk * PEARLHASH_LDB); \
        const simdgroup_float8x8 b1 = pearlhash_frag((bC) + kk * PEARLHASH_LDB + 8); \
        const simdgroup_float8x8 b2 = pearlhash_frag((bC) + kk * PEARLHASH_LDB + 32); \
        const simdgroup_float8x8 b3 = pearlhash_frag((bC) + kk * PEARLHASH_LDB + 40); \
        PEARLHASH_MMA16 \
    }

// This thread's share of a chunk, from registers into a stage: 16 values of A' and 8 of B'^T (transposed).
#define PEARLHASH_PUT(aD, bD) { \
    threadgroup half4 *a4 = (threadgroup half4 *)(aD); \
    a4[0] = half4(as_type<char4>(ra.x)); a4[1] = half4(as_type<char4>(ra.y)); \
    a4[2] = half4(as_type<char4>(ra.z)); a4[3] = half4(as_type<char4>(ra.w)); \
    const char4 b0123 = as_type<char4>(rb.x), b4567 = as_type<char4>(rb.y); \
    (bD)[0] = half(b0123.x); (bD)[PEARLHASH_LDB] = half(b0123.y); \
    (bD)[2 * PEARLHASH_LDB] = half(b0123.z); (bD)[3 * PEARLHASH_LDB] = half(b0123.w); \
    (bD)[4 * PEARLHASH_LDB] = half(b4567.x); (bD)[5 * PEARLHASH_LDB] = half(b4567.y); \
    (bD)[6 * PEARLHASH_LDB] = half(b4567.z); (bD)[7 * PEARLHASH_LDB] = half(b4567.w); }

// Block end for one fragment: its two exact float sums join the int32 running totals, which are XORed in.
#define PEARLHASH_FOLD(c, i) \
    total[i] += int2(int(c.thread_elements()[0]), int(c.thread_elements()[1])); \
    x ^= as_type<uint>(total[i].x) ^ as_type<uint>(total[i].y); \
    c = make_filled_simdgroup_matrix<float, 8, 8>(0.0f);

// The search. A threadgroup (8 SIMD groups) computes a 128-row x 64-column block of A'B' over all of k
// with 8x8 float SIMD-group matrices; int8 products and sums of PEARLHASH_R of them are exact in float.
// SIMD group (sr, sc) holds the 16 fragments at row blocks 2sr+{0,1,8,9} and column blocks 2sc+{0,1,4,5},
// so each lane, which owns a row and a column pair of every fragment, owns one whole 4 x 8 tile: rows
// 16sr + fm + {0,8,64,72}, columns 16sc + fn + {0,1,8,9,32,33,40,41}. After each block of PEARLHASH_R
// the lane converts its 32 sums to int32, adds them to running totals, XORs the totals into a rotating
// queue of the 16 jackpot words; at the end it hashes its jackpot and compares it with the bound.
// A' and B' are staged in threadgroup memory as halfs (exact for |x| <= 2048), double-buffered.
kernel void pearlhash_mine(constant PearlHashParams &P       [[buffer(0)]],
                           device const PearlHashInstance &I [[buffer(1)]],
                           device const uint4 *An            [[buffer(2)]],
                           device const uint2 *Bn            [[buffer(3)]],
                           device PearlHashHits *hits        [[buffer(4)]],
                           device uint *hashes               [[buffer(5)]],
                           uint2 group [[threadgroup_position_in_grid]],
                           uint tid    [[thread_index_in_threadgroup]],
                           uint sg     [[simdgroup_index_in_threadgroup]],
                           uint lane   [[thread_index_in_simdgroup]])
{
    threadgroup half As[2 * PEARLHASH_STAGE_A];
    threadgroup half Bs[2 * PEARLHASH_STAGE_B];

    const uint r0 = group.y * 128u;
    const uint c0 = group.x * 64u;
    const uint sr = sg & 3u;
    const uint sc = sg >> 2;
    const uint fm = pearlhash_lane_row(lane);
    const uint fn = pearlhash_lane_col(lane);

    // Global -> threadgroup: each thread moves 16 bytes of A' and 8 bytes of B'^T (transposed) per chunk.
    const uint aRow = tid >> 1, aHalf = tid & 1u;
    const uint bCol = tid >> 2, bQuarter = tid & 3u;
    device const uint4 *aSrc = An + (ulong)(r0 + aRow) * (PEARLHASH_K / 16) + aHalf;
    device const uint2 *bSrc = Bn + (ulong)(c0 + bCol) * (PEARLHASH_K / 8) + bQuarter;
    threadgroup half *aDst = As + aRow * PEARLHASH_LDA + aHalf * 16u;
    threadgroup half *bDst = Bs + bQuarter * 8u * PEARLHASH_LDB + bCol;

    // This lane's cells: A rows 16sr + fm + {0,8,64,72}, B columns 16sc + fn + {0,8,32,40}.
    threadgroup const half *aCells = As + (16u * sr + fm) * PEARLHASH_LDA + fn;
    threadgroup const half *bCells = Bs + fm * PEARLHASH_LDB + 16u * sc + fn;

    simdgroup_float8x8 c00 = make_filled_simdgroup_matrix<float, 8, 8>(0.0f), c01 = c00, c02 = c00, c03 = c00,
        c10 = c00, c11 = c00, c12 = c00, c13 = c00, c20 = c00, c21 = c00, c22 = c00, c23 = c00,
        c30 = c00, c31 = c00, c32 = c00, c33 = c00;
    int2 total[16];
    uint q[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        total[i] = int2(0);
        q[i] = 0u;
    }

    uint4 ra = aSrc[0];
    uint2 rb = bSrc[0];
    PEARLHASH_PUT(aDst, bDst)
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint blk = 0; blk < PEARLHASH_BLOCKS; blk++) {
        for (uint cc = 0; cc < PEARLHASH_CHUNKS_PER_BLOCK; cc++) {
            // Stage ch & 1 holds this chunk; the next one goes into the other stage, which every SIMD
            // group finished reading before the barrier that ended the previous chunk.
            const uint ch = blk * PEARLHASH_CHUNKS_PER_BLOCK + cc;
            const uint s = ch & 1u;
            const bool more = ch + 1u < PEARLHASH_CHUNKS;
            if (more) {
                ra = aSrc[(ch + 1u) * 2u];
                rb = bSrc[(ch + 1u) * 4u];
            }
            PEARLHASH_COMPUTE(aCells + s * PEARLHASH_STAGE_A, bCells + s * PEARLHASH_STAGE_B)
            if (more) PEARLHASH_PUT(aDst + (s ^ 1u) * PEARLHASH_STAGE_A, bDst + (s ^ 1u) * PEARLHASH_STAGE_B)
            threadgroup_barrier(mem_flags::mem_threadgroup);
        }
        uint x = 0u;
        PEARLHASH_FOLD(c00, 0)  PEARLHASH_FOLD(c01, 1)  PEARLHASH_FOLD(c02, 2)  PEARLHASH_FOLD(c03, 3)
        PEARLHASH_FOLD(c10, 4)  PEARLHASH_FOLD(c11, 5)  PEARLHASH_FOLD(c12, 6)  PEARLHASH_FOLD(c13, 7)
        PEARLHASH_FOLD(c20, 8)  PEARLHASH_FOLD(c21, 9)  PEARLHASH_FOLD(c22, 10) PEARLHASH_FOLD(c23, 11)
        PEARLHASH_FOLD(c30, 12) PEARLHASH_FOLD(c31, 13) PEARLHASH_FOLD(c32, 14) PEARLHASH_FOLD(c33, 15)
        const uint first = q[0];   // q[i] holds jackpot word (blk + i) mod 16
        #pragma unroll
        for (int i = 0; i < 15; i++) q[i] = q[i + 1];
        q[15] = rotate(first, 13u) ^ x;
    }

    uint jp[16];
    #pragma unroll
    for (int j = 0; j < 16; j++) jp[j] = q[(j + 16 - (PEARLHASH_BLOCKS % 16)) % 16];
    uint key[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) key[i] = I.aSeed[i];
    uint h[8];
    pearlhash_blake3_block(key, jp, h);

    bool hit = true;
    bool decided = false;
    #pragma unroll
    for (int w = 7; w >= 0; w--) {
        if (!decided && h[w] != P.bound[w]) { hit = h[w] < P.bound[w]; decided = true; }
    }
    if (hit) {
        uint slot = atomic_fetch_add_explicit(&hits->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) {
            hits->hit[slot].nonce = I.nonce;
            hits->hit[slot].tRows = r0 + 16u * sr + fm;
            hits->hit[slot].tCols = c0 + 16u * sc + fn;
        }
    }
    if (P.writeHashes != 0u) {
        const uint rowTile = (r0 >> 7) * 32u + sr * 8u + fm;
        const uint colTile = (c0 >> 6) * 8u + sc * 4u + (fn >> 1);
        device uint *dst = hashes + ((ulong)rowTile * (P.n >> 3) + colTile) * 8ul;
        #pragma unroll
        for (int w = 0; w < 8; w++) dst[w] = h[w];
    }
}

// One SIMD group loads the 8x8 matrix with cell (r, c) = 8r + c and each lane reports which cells it holds
// as thread_elements()[0] and [1], and the cells pearlhash_lane_row/col say it holds.
kernel void pearlhash_layout_probe(device float4 *out [[buffer(0)]],
                                   uint lane [[thread_index_in_simdgroup]])
{
    threadgroup float cells[64];
    cells[lane] = float(lane);
    cells[lane + 32] = float(lane + 32);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    simdgroup_float8x8 mtx;
    simdgroup_load(mtx, cells, 8);
    uint expected = pearlhash_lane_row(lane) * 8u + pearlhash_lane_col(lane);
    out[lane] = float4(mtx.thread_elements()[0], mtx.thread_elements()[1], float(expected), float(expected + 1u));
}
