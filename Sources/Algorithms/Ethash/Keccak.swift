import Foundation

/// Keccak-f[1600] and the legacy (pre-FIPS, 0x01-padded) Keccak hashes Ethereum uses.
enum Keccak {
    static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]

    @inline(__always) static func rol(_ x: UInt64, _ n: UInt64) -> UInt64 { (x &<< n) | (x &>> (64 &- n)) }

    /// The permutation, on 25 lanes.
    static func f1600(_ a: UnsafeMutablePointer<UInt64>) {
        for round in 0 ..< 24 {
            let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
            let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
            let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
            let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
            let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]
            let d0 = c4 ^ rol(c1, 1), d1 = c0 ^ rol(c2, 1), d2 = c1 ^ rol(c3, 1), d3 = c2 ^ rol(c4, 1), d4 = c3 ^ rol(c0, 1)
            for j in stride(from: 0, to: 25, by: 5) {
                a[j] ^= d0; a[j + 1] ^= d1; a[j + 2] ^= d2; a[j + 3] ^= d3; a[j + 4] ^= d4
            }
            // rho and pi, as one cycle through the lanes
            let t = a[1]
            a[1] = rol(a[6], 44); a[6] = rol(a[9], 20); a[9] = rol(a[22], 61); a[22] = rol(a[14], 39)
            a[14] = rol(a[20], 18); a[20] = rol(a[2], 62); a[2] = rol(a[12], 43); a[12] = rol(a[13], 25)
            a[13] = rol(a[19], 8); a[19] = rol(a[23], 56); a[23] = rol(a[15], 41); a[15] = rol(a[4], 27)
            a[4] = rol(a[24], 14); a[24] = rol(a[21], 2); a[21] = rol(a[8], 55); a[8] = rol(a[16], 45)
            a[16] = rol(a[5], 36); a[5] = rol(a[3], 28); a[3] = rol(a[18], 21); a[18] = rol(a[17], 15)
            a[17] = rol(a[11], 10); a[11] = rol(a[7], 6); a[7] = rol(a[10], 3); a[10] = rol(t, 1)
            // chi
            for j in stride(from: 0, to: 25, by: 5) {
                let a0 = a[j], a1 = a[j + 1], a2 = a[j + 2], a3 = a[j + 3], a4 = a[j + 4]
                a[j] = a0 ^ (~a1 & a2); a[j + 1] = a1 ^ (~a2 & a3); a[j + 2] = a2 ^ (~a3 & a4)
                a[j + 3] = a3 ^ (~a4 & a0); a[j + 4] = a4 ^ (~a0 & a1)
            }
            a[0] ^= roundConstants[round]
        }
    }

    /// Legacy Keccak with `rate` bytes (136 for 256-bit output, 72 for 512-bit).
    static func hash(_ input: [UInt8], rate: Int, outputBytes: Int) -> [UInt8] {
        var state = [UInt64](repeating: 0, count: 25)
        state.withUnsafeMutableBufferPointer { s in
            var offset = 0
            var last = false
            while !last {
                var block = [UInt8](repeating: 0, count: rate)
                let take = min(rate, input.count - offset)
                if take > 0 { block.replaceSubrange(0 ..< take, with: input[offset ..< offset + take]) }
                if take < rate {   // final block: pad 0x01 ... 0x80
                    block[take] ^= 0x01
                    block[rate - 1] ^= 0x80
                    last = true
                }
                for i in 0 ..< rate / 8 { s[i] ^= block.le64(at: 8 * i) }
                Keccak.f1600(s.baseAddress!)
                offset += take
            }
        }
        var out: [UInt8] = []
        for i in 0 ..< (outputBytes + 7) / 8 { out.appendLE(state[i]) }
        return Array(out.prefix(outputBytes))
    }

    static func keccak256(_ input: [UInt8]) -> [UInt8] { hash(input, rate: 136, outputBytes: 32) }
    static func keccak512(_ input: [UInt8]) -> [UInt8] { hash(input, rate: 72, outputBytes: 64) }

    /// Keccak-512 of exactly 64 bytes held as 16 little-endian words, in place (the Ethash cache/DAG step).
    static func keccak512InPlace(_ words: UnsafeMutablePointer<UInt32>) {
        withUnsafeTemporaryAllocation(of: UInt64.self, capacity: 25) { buffer in
            let s = buffer.baseAddress!
            s.initialize(repeating: 0, count: 25)
            for i in 0 ..< 8 { s[i] = UInt64(words[2 * i]) | UInt64(words[2 * i + 1]) << 32 }
            s[8] = 0x8000_0000_0000_0001
            f1600(s)
            for i in 0 ..< 8 {
                words[2 * i] = UInt32(truncatingIfNeeded: s[i])
                words[2 * i + 1] = UInt32(truncatingIfNeeded: s[i] >> 32)
            }
        }
    }
}
