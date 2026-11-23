import Foundation

/// BLAKE2b (RFC 7693), unkeyed, for the Autolykos v2 CPU reference. Ergo uses the 32-byte digest
/// (scorex Blake2b256, which wraps BouncyCastle's Blake2bDigest(256)).
enum Autolykos2Blake2b {
    static let iv: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]

    /// Message schedule; round r uses row r % 10.
    static let sigma: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ]

    @inline(__always) private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { (x >> n) | (x << (64 - n)) }

    @inline(__always)
    private static func g(_ v: UnsafeMutablePointer<UInt64>, _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotr(v[d] ^ v[a], 32)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 63)
    }

    /// The compression function F: state `h` absorbs the 16-word block `m`; `t` counts bytes hashed so far.
    static func compress(_ h: UnsafeMutablePointer<UInt64>, _ m: UnsafePointer<UInt64>, t: UInt64, last: Bool) {
        withUnsafeTemporaryAllocation(of: UInt64.self, capacity: 16) { buffer in
            let v = buffer.baseAddress!
            for i in 0 ..< 8 {
                v[i] = h[i]
                v[i + 8] = iv[i]
            }
            v[12] ^= t
            if last { v[14] = ~v[14] }
            sigma.withUnsafeBufferPointer { s in
                for r in 0 ..< 12 {
                    let o = (r % 10) * 16
                    g(v, 0, 4, 8, 12, m[s[o + 0]], m[s[o + 1]])
                    g(v, 1, 5, 9, 13, m[s[o + 2]], m[s[o + 3]])
                    g(v, 2, 6, 10, 14, m[s[o + 4]], m[s[o + 5]])
                    g(v, 3, 7, 11, 15, m[s[o + 6]], m[s[o + 7]])
                    g(v, 0, 5, 10, 15, m[s[o + 8]], m[s[o + 9]])
                    g(v, 1, 6, 11, 12, m[s[o + 10]], m[s[o + 11]])
                    g(v, 2, 7, 8, 13, m[s[o + 12]], m[s[o + 13]])
                    g(v, 3, 4, 9, 14, m[s[o + 14]], m[s[o + 15]])
                }
            }
            for i in 0 ..< 8 { h[i] ^= v[i] ^ v[i + 8] }
        }
    }

    /// BLAKE2b with a `length`-byte digest (1...64), no key.
    static func hash(_ data: UnsafeRawBufferPointer, length: Int = 32) -> [UInt8] {
        precondition((1 ... 64).contains(length))
        var h = iv
        h[0] ^= 0x0101_0000 ^ UInt64(length)
        var block = [UInt64](repeating: 0, count: 16)
        let count = data.count
        h.withUnsafeMutableBufferPointer { hp in
            block.withUnsafeMutableBufferPointer { bp in
                var offset = 0
                // Every full block but the last one; the last block (full, partial or empty) is flagged final.
                while count - offset > 128 {
                    for i in 0 ..< 16 {
                        bp[i] = UInt64(littleEndian: data.loadUnaligned(fromByteOffset: offset + 8 * i, as: UInt64.self))
                    }
                    offset += 128
                    compress(hp.baseAddress!, UnsafePointer(bp.baseAddress!), t: UInt64(offset), last: false)
                }
                for i in 0 ..< 16 { bp[i] = 0 }
                let raw = UnsafeMutableRawBufferPointer(bp)
                for i in 0 ..< count - offset { raw[i] = data[offset + i] }
                compress(hp.baseAddress!, UnsafePointer(bp.baseAddress!), t: UInt64(count), last: true)
            }
        }
        return (0 ..< length).map { UInt8(truncatingIfNeeded: h[$0 / 8] >> (8 * UInt64($0 % 8))) }
    }

    static func hash(_ data: [UInt8], length: Int = 32) -> [UInt8] {
        data.withUnsafeBytes { hash($0, length: length) }
    }
}
