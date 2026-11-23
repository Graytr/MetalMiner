import Foundation

/// CPU reference for NexaPow, Nexa's proof of work (consensus.powAlgorithm = 1 on mainnet), written from
/// the Nexa full node (gitlab.com/nexa/nexa, tag nexa2.2.0.0):
///   src/primitives/block.cpp   GetMiningHeaderCommitment, GetMiningHash (sha256d(commitment || nonce))
///   src/pow.cpp                CheckProofOfWork: h1 = sha256(miningHash), key = miningHash,
///                              sig = SignSchnorr(h1), powHash = sha256(sig), UintToArith256(powHash) <= target
///   src/key.cpp                CKey::SignSchnorr -> secp256k1_schnorr_sign(..., nonce_function_rfc6979, NULL)
///   src/secp256k1/src/modules/schnorr/schnorr_impl.h, secp256k1.c (nonce_function_rfc6979), hash_impl.h
/// Deliberately plain and independent of the GPU kernel: generic multi-limb arithmetic with a generic
/// folding reduction, double-and-add scalar multiplication, Fermat inversion and Euler's criterion.
/// This file: SHA-256 and HMAC. NexaPowCurve.swift: arithmetic and secp256k1. NexaPowSign.swift: signing,
/// NexaPow itself and the known-answer vectors.
enum NexaPowReference {
    static let sha256K: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]
    static let sha256IV: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    @inline(__always) static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }

    /// One SHA-256 compression of a 16-word big-endian block into `state`.
    static func sha256Compress(_ state: inout [UInt32], _ block: [UInt32]) {
        var w = block + [UInt32](repeating: 0, count: 48)
        for t in 16 ..< 64 {
            let s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            let s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
        }
        var a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7]
        for t in 0 ..< 64 {
            let t1 = h &+ (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) &+ ((e & f) ^ (~e & g)) &+ sha256K[t] &+ w[t]
            let t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) &+ ((a & b) ^ (a & c) ^ (b & c))
            h = g; g = f; f = e; e = d &+ t1; d = c; c = b; b = a; a = t1 &+ t2
        }
        for (i, v) in [a, b, c, d, e, f, g, h].enumerated() { state[i] = state[i] &+ v }
    }

    /// Big-endian words of a byte string whose length is a multiple of 4.
    static func words(_ bytes: [UInt8]) -> [UInt32] {
        (0 ..< bytes.count / 4).map { i in (0 ..< 4).reduce(UInt32(0)) { $0 << 8 | UInt32(bytes[4 * i + $1]) } }
    }

    static func sha256(_ data: [UInt8]) -> [UInt8] {
        var message = data
        let bits = UInt64(data.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 { message.append(0) }
        for i in (0 ..< 8).reversed() { message.append(UInt8(truncatingIfNeeded: bits >> (8 * UInt64(i)))) }
        var state = sha256IV
        for offset in stride(from: 0, to: message.count, by: 64) {
            sha256Compress(&state, words(Array(message[offset ..< offset + 64])))
        }
        return state.flatMap { word in (0 ..< 4).map { UInt8(truncatingIfNeeded: word >> (24 - 8 * UInt32($0))) } }
    }

    static func sha256d(_ data: [UInt8]) -> [UInt8] { sha256(sha256(data)) }

    static func hmacSHA256(key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        var k = key.count > 64 ? sha256(key) : key
        k += [UInt8](repeating: 0, count: 64 - k.count)
        return sha256(k.map { $0 ^ 0x5c } + sha256(k.map { $0 ^ 0x36 } + data))
    }

    /// State after compressing one 64-byte block of `byte` (the HMAC pads of an all-zero key).
    static func padMidstate(_ byte: UInt8) -> [UInt32] {
        var state = sha256IV
        sha256Compress(&state, words([UInt8](repeating: byte, count: 64)))
        return state
    }
}
