// Shared prelude, prepended to every kernel library at runtime by GPU.library(_:).
// Runtime-compiled Metal source can't #include our own files, so keep this small and generic.
#include <metal_stdlib>
using namespace metal;

static inline uint  rotl32(uint x, uint n)   { return rotate(x, n); }
static inline uint  rotr32(uint x, uint n)   { return rotate(x, (32u - n) & 31u); }
static inline ulong rotl64(ulong x, ulong n) { return rotate(x, n); }
static inline ulong rotr64(ulong x, ulong n) { return rotate(x, (64ul - n) & 63ul); }

static inline uint bswap32(uint x) {
    return (x >> 24) | ((x >> 8) & 0x0000ff00u) | ((x << 8) & 0x00ff0000u) | (x << 24);
}
static inline ulong bswap64(ulong x) {
    return ((ulong)bswap32((uint)x) << 32) | (ulong)bswap32((uint)(x >> 32));
}

// Where search kernels report hits: an atomic count, then the winning nonces.
#define SEARCH_MAX_HITS 62
struct SearchOutput {
    atomic_uint count;
    uint pad;
    ulong nonce[SEARCH_MAX_HITS];
};
