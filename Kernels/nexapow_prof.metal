// Development micro-benchmarks for NexaPow building blocks: --set profile=N (--set n=R repetitions per
// thread). Appended after the four nexapow files; rates are threads/s, so multiply by R for blocks/s.
// The repetition count is a runtime value (job.pad is 0) so the compiler can't unroll the outer loop.
//   4: mixed point addition with a random table load
//   5: a^((p-3)/4) (253 squarings, 14 multiplications)
//   7: plain squaring chain
//  10: the a^((p-3)/4) step loop without the saved powers
//  40: consistency: the step loop with compile-time counts against the same loop with runtime counts;
//      threads whose results differ are counted (the bench's cross-check line prints the count).
// Finding (2026-11-19, M3 Max): with sqr = mul(a, a), kernels fell into a slow regime (~3.5k lane-cycles
// per field operation) unless shaped exactly like the exponentiation loop (~0.7-0.9k); the dedicated
// squaring in nexapow_field.metal brought the whole search kernel into the fast regime (3.2 -> 9.4 MH/s).
#ifndef NEXAPOW_PROF
#define NEXAPOW_PROF 5
#endif
#ifndef NEXAPOW_PROF_N
#define NEXAPOW_PROF_N 1
#endif

kernel void nexapow_prof(device const uint4 *table     [[buffer(0)]],
                         constant NexaPowJob &job       [[buffer(1)]],
                         constant ulong &startNonce     [[buffer(2)]],
                         device SearchOutput *out       [[buffer(3)]],
                         uint gid [[thread_position_in_grid]])
{
    np_fe x, y;
    for (int i = 0; i < 8; i++) { x.v[i] = job.commit[i] ^ (gid * 0x9E3779B9u + (uint)startNonce); y.v[i] = job.ipad0[i] + gid; }
    uint acc = 0;
    int reps = NEXAPOW_PROF_N + (int)job.pad;
#if NEXAPOW_PROF == 4
    np_jac q;
    q.x = x; q.y = y; q.z = np_fe_one();
    bool inf = false;
    uint idx = gid;
    for (int r = 0; r < reps; r++) {
        np_fe tx, ty;
        idx = idx * 1664525u + 1013904223u;
        np_load_affine(table + 4 * (ulong)(idx % (NEXAPOW_WINDOWS * NEXAPOW_TSIZE)), tx, ty);
        np_madd(q, tx, ty, inf);
    }
    x = q.x;
    acc = inf ? 1u : 0u;
#elif NEXAPOW_PROF == 5
    for (int r = 0; r < reps; r++) x = np_fe_pow_p34(x);
#elif NEXAPOW_PROF == 7
    for (int r = 0; r < reps; r++) x = np_fe_sqr(x);
#elif NEXAPOW_PROF == 10
    for (int r = 0; r < reps; r++) {
        for (int s = 0; s < 14; s++) {
            int n = NP_CHAIN_SQR[s];
            for (int i = 0; i < n; i++) x = np_fe_sqr(x);
            x = np_fe_mul(x, y);
        }
    }
#elif NEXAPOW_PROF == 40
    np_fe x2 = x;
    for (int s = 0; s < 14; s++) {
        int n = NP_CHAIN_SQR[s];
        for (int i = 0; i < n; i++) x = np_fe_sqr(x);
        x = np_fe_mul(x, y);
    }
    for (int s = 0; s < 14; s++) {
        int n = NP_CHAIN_SQR[s] + (int)job.pad;
        for (int i = 0; i < n; i++) x2 = np_fe_sqr(x2);
        x2 = np_fe_mul(x2, y);
    }
    x = np_fe_normalize(x);
    x2 = np_fe_normalize(x2);
    uint diff = 0;
    for (int i = 0; i < 8; i++) diff |= x.v[i] ^ x2.v[i];
    if (diff != 0) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = startNonce + gid;
    }
    return;
#endif
    for (int i = 0; i < 8; i++) acc ^= x.v[i];
    if (acc == job.target[0] + 0x5A5A5A5Au) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = startNonce + gid;
    }
}
