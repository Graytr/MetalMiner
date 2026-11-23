// PearlHash development micro-benchmarks, not used for mining (run: test pearlhash --set lab=1).
// Each threadgroup has 4 SIMD groups; each SIMD group does `iters` steps of 16 float 8x8x8 MMAs
// (4 A x 4 B fragments). Finding on this Mac (M3 Max, macOS 27 runtime compiler), with plain FMA at
// about 6 TFMA/s: 16 accumulators in an array of simdgroup_float8x8 run at about 0.25 TMAC/s (the array
// is spilled), the same 16 as named variables at 5-6 TMAC/s. Fragment loads from threadgroup memory
// cost little once matrices are named; manual half2 loads were the fastest variant.

#define LAB_LD 36

#define LAB_MMA16 \
    simdgroup_multiply_accumulate(c00, a0, b0, c00); simdgroup_multiply_accumulate(c01, a0, b1, c01); \
    simdgroup_multiply_accumulate(c02, a0, b2, c02); simdgroup_multiply_accumulate(c03, a0, b3, c03); \
    simdgroup_multiply_accumulate(c10, a1, b0, c10); simdgroup_multiply_accumulate(c11, a1, b1, c11); \
    simdgroup_multiply_accumulate(c12, a1, b2, c12); simdgroup_multiply_accumulate(c13, a1, b3, c13); \
    simdgroup_multiply_accumulate(c20, a2, b0, c20); simdgroup_multiply_accumulate(c21, a2, b1, c21); \
    simdgroup_multiply_accumulate(c22, a2, b2, c22); simdgroup_multiply_accumulate(c23, a2, b3, c23); \
    simdgroup_multiply_accumulate(c30, a3, b0, c30); simdgroup_multiply_accumulate(c31, a3, b1, c31); \
    simdgroup_multiply_accumulate(c32, a3, b2, c32); simdgroup_multiply_accumulate(c33, a3, b3, c33);

#define LAB_DECL16 \
    simdgroup_float8x8 c00 = make_filled_simdgroup_matrix<float, 8, 8>(0.0f), c01 = c00, c02 = c00, c03 = c00, \
        c10 = c00, c11 = c00, c12 = c00, c13 = c00, c20 = c00, c21 = c00, c22 = c00, c23 = c00, \
        c30 = c00, c31 = c00, c32 = c00, c33 = c00;

#define LAB_STORE16(o) \
    simdgroup_store(c00, o, 8); simdgroup_store(c01, o + 64, 8); simdgroup_store(c02, o + 128, 8); simdgroup_store(c03, o + 192, 8); \
    simdgroup_store(c10, o + 256, 8); simdgroup_store(c11, o + 320, 8); simdgroup_store(c12, o + 384, 8); simdgroup_store(c13, o + 448, 8); \
    simdgroup_store(c20, o + 512, 8); simdgroup_store(c21, o + 576, 8); simdgroup_store(c22, o + 640, 8); simdgroup_store(c23, o + 704, 8); \
    simdgroup_store(c30, o + 768, 8); simdgroup_store(c31, o + 832, 8); simdgroup_store(c32, o + 896, 8); simdgroup_store(c33, o + 960, 8);

#define LAB_INIT_TG \
    threadgroup float t[64 * LAB_LD]; \
    for (uint i = tid; i < 64 * LAB_LD; i += 128) t[i] = float(i % 7) - 3.0f; \
    threadgroup_barrier(mem_flags::mem_threadgroup);

static inline simdgroup_float8x8 lab_wrap(float2 v) {
    simdgroup_float8x8 m;
    m.thread_elements()[0] = v.x;
    m.thread_elements()[1] = v.y;
    return m;
}

// Accumulators and fragments in arrays of simdgroup matrices (spilled on this compiler).
kernel void pearlhash_lab_arrays(device float *out [[buffer(0)]], constant uint &iters [[buffer(1)]],
                                 uint sg [[simdgroup_index_in_threadgroup]], uint tid [[thread_index_in_threadgroup]],
                                 uint gidx [[threadgroup_position_in_grid]])
{
    LAB_INIT_TG
    simdgroup_float8x8 fa[4], fb[4], acc[16];
    for (int i = 0; i < 4; i++) { simdgroup_load(fa[i], t + i * 8 * LAB_LD, LAB_LD); simdgroup_load(fb[i], t + (32 + i * 8) * LAB_LD, LAB_LD); }
    for (int i = 0; i < 16; i++) acc[i] = make_filled_simdgroup_matrix<float, 8, 8>(0.0f);
    for (uint it = 0; it < iters; it++) {
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            #pragma unroll
            for (int j = 0; j < 4; j++) simdgroup_multiply_accumulate(acc[i * 4 + j], fa[i], fb[j], acc[i * 4 + j]);
        }
    }
    for (int i = 0; i < 16; i++) simdgroup_store(acc[i], out + ((gidx * 4 + sg) * 16 + i) * 64, 8);
}

// Named matrices, fragments loaded once.
kernel void pearlhash_lab_named(device float *out [[buffer(0)]], constant uint &iters [[buffer(1)]],
                                uint sg [[simdgroup_index_in_threadgroup]], uint tid [[thread_index_in_threadgroup]],
                                uint gidx [[threadgroup_position_in_grid]])
{
    LAB_INIT_TG
    simdgroup_float8x8 a0, a1, a2, a3, b0, b1, b2, b3;
    simdgroup_load(a0, t, LAB_LD); simdgroup_load(a1, t + 8 * LAB_LD, LAB_LD);
    simdgroup_load(a2, t + 16 * LAB_LD, LAB_LD); simdgroup_load(a3, t + 24 * LAB_LD, LAB_LD);
    simdgroup_load(b0, t + 32 * LAB_LD, LAB_LD); simdgroup_load(b1, t + 40 * LAB_LD, LAB_LD);
    simdgroup_load(b2, t + 48 * LAB_LD, LAB_LD); simdgroup_load(b3, t + 56 * LAB_LD, LAB_LD);
    LAB_DECL16
    for (uint it = 0; it < iters; it++) { LAB_MMA16 }
    device float *o = out + (gidx * 4 + sg) * 16 * 64;
    LAB_STORE16(o)
}

// Named matrices, simdgroup_load from threadgroup memory every step (B transposed).
kernel void pearlhash_lab_named_load(device float *out [[buffer(0)]], constant uint &iters [[buffer(1)]],
                                     uint sg [[simdgroup_index_in_threadgroup]], uint tid [[thread_index_in_threadgroup]],
                                     uint gidx [[threadgroup_position_in_grid]])
{
    LAB_INIT_TG
    LAB_DECL16
    for (uint it = 0; it < iters; it++) {
        const uint kk = (it & 3u) * 8u;
        simdgroup_float8x8 a0, a1, a2, a3, b0, b1, b2, b3;
        simdgroup_load(a0, t + kk, LAB_LD); simdgroup_load(a1, t + 8 * LAB_LD + kk, LAB_LD);
        simdgroup_load(a2, t + 16 * LAB_LD + kk, LAB_LD); simdgroup_load(a3, t + 24 * LAB_LD + kk, LAB_LD);
        simdgroup_load(b0, t + 32 * LAB_LD + kk, LAB_LD, ulong2(0, 0), true); simdgroup_load(b1, t + 40 * LAB_LD + kk, LAB_LD, ulong2(0, 0), true);
        simdgroup_load(b2, t + 48 * LAB_LD + kk, LAB_LD, ulong2(0, 0), true); simdgroup_load(b3, t + 56 * LAB_LD + kk, LAB_LD, ulong2(0, 0), true);
        LAB_MMA16
    }
    device float *o = out + (gidx * 4 + sg) * 16 * 64;
    LAB_STORE16(o)
}

// Named matrices built from manual half2 loads (each lane its two cells), as pearlhash_mine does.
kernel void pearlhash_lab_named_half2(device float *out [[buffer(0)]], constant uint &iters [[buffer(1)]],
                                      uint sg [[simdgroup_index_in_threadgroup]], uint tid [[thread_index_in_threadgroup]],
                                      uint lane [[thread_index_in_simdgroup]], uint gidx [[threadgroup_position_in_grid]])
{
    threadgroup half t[64 * LAB_LD];
    for (uint i = tid; i < 64 * LAB_LD; i += 128) t[i] = half(i % 7) - 3.0h;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    const uint fm = ((lane >> 2) & 4u) + ((lane >> 1) & 3u);
    const uint fn = ((lane >> 2) & 2u) * 2u + (lane & 1u) * 2u;
    threadgroup const half2 *ta = (threadgroup const half2 *)(t + fm * LAB_LD + fn);
    threadgroup const half2 *tb = (threadgroup const half2 *)(t + (32 + fm) * LAB_LD + fn);
    LAB_DECL16
    for (uint it = 0; it < iters; it++) {
        const uint kk = (it & 3u) * 4u;
        simdgroup_float8x8 a0 = lab_wrap(float2(ta[kk])), a1 = lab_wrap(float2(ta[4 * LAB_LD + kk])), a2 = lab_wrap(float2(ta[8 * LAB_LD + kk])), a3 = lab_wrap(float2(ta[12 * LAB_LD + kk]));
        simdgroup_float8x8 b0 = lab_wrap(float2(tb[kk])), b1 = lab_wrap(float2(tb[4 * LAB_LD + kk])), b2 = lab_wrap(float2(tb[8 * LAB_LD + kk])), b3 = lab_wrap(float2(tb[12 * LAB_LD + kk]));
        LAB_MMA16
    }
    device float *o = out + (gidx * 4 + sg) * 16 * 64;
    LAB_STORE16(o)
}

// Plain FMA throughput: 16 independent float FMA chains per lane.
kernel void pearlhash_lab_fma(device float *out [[buffer(0)]], constant uint &iters [[buffer(1)]],
                              uint gid [[thread_position_in_grid]])
{
    float a[16], b = float(gid & 7u) * 0.5f, c = 1.0001f;
    for (int i = 0; i < 16; i++) a[i] = float(i);
    for (uint it = 0; it < iters; it++) {
        #pragma unroll
        for (int r = 0; r < 4; r++) {
            #pragma unroll
            for (int i = 0; i < 16; i++) a[i] = fma(a[i], c, b);
        }
    }
    float s = 0.0f;
    for (int i = 0; i < 16; i++) s += a[i];
    out[gid] = s;
}
