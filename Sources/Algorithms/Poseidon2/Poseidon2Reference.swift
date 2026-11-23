import Foundation

/// CPU reference for Quantus (QTC) proof of work, written from Quantus's own code:
/// qp-poseidon-core (Poseidon2 over Goldilocks, width 12, sponge rate 8, injective byte encoding)
/// and qpow-math (get_nonce_hash, is_valid_nonce). See docs/specs/poseidon2.md.
enum Poseidon2Reference {
    // MARK: Goldilocks field, p = 2^64 - 2^32 + 1. Every value here is kept canonical (< p).

    static let p: UInt64 = 0xFFFF_FFFF_0000_0001
    /// 2^64 mod p = 2^32 - 1.
    static let epsilon: UInt64 = 0xFFFF_FFFF

    @inline(__always) static func add(_ a: UInt64, _ b: UInt64) -> UInt64 {
        let (s, carry) = a.addingReportingOverflow(b)
        if carry { return s &+ epsilon }   // a + b - 2^64 + (2^32 - 1) = a + b - p, already < p
        return s >= p ? s &- p : s
    }

    /// (hi * 2^64 + lo) mod p, from 2^64 = 2^32 - 1 and 2^96 = -1 (mod p).
    @inline(__always) static func reduce(_ hi: UInt64, _ lo: UInt64) -> UInt64 {
        let (t0w, borrow) = lo.subtractingReportingOverflow(hi >> 32)
        let t0 = borrow ? t0w &- epsilon : t0w
        let t1 = (hi & epsilon) &* epsilon
        let (sum, carry) = t0.addingReportingOverflow(t1)
        let r = carry ? sum &+ epsilon : sum
        return r >= p ? r &- p : r
    }

    @inline(__always) static func mul(_ a: UInt64, _ b: UInt64) -> UInt64 {
        let (hi, lo) = a.multipliedFullWidth(by: b)
        return reduce(hi, lo)
    }

    /// The S-box, x^7.
    @inline(__always) static func sbox(_ x: UInt64) -> UInt64 {
        let x2 = mul(x, x), x4 = mul(x2, x2), x6 = mul(x4, x2)
        return mul(x6, x)
    }

    // MARK: Poseidon2 permutation (width 12, 4 + 4 external rounds, 22 internal rounds)

    struct Permutation {
        /// The 4x4 block of the external matrix circ(2*M4, M4, M4).
        let m4: [[UInt64]]
        let initial: [[UInt64]]
        let terminal: [[UInt64]]
        let partial: [UInt64]
        /// The internal matrix is 1 + diag: state[i] = sum(state) + diag[i] * state[i].
        let diag: [UInt64]

        func externalLayer(_ s: inout [UInt64]) {
            var y = [UInt64](repeating: 0, count: 12)
            for c in stride(from: 0, to: 12, by: 4) {
                for r in 0 ..< 4 {
                    var acc: UInt64 = 0
                    for j in 0 ..< 4 { acc = add(acc, mul(m4[r][j], s[c + j])) }
                    y[c + r] = acc
                }
            }
            for k in 0 ..< 4 {
                let sum = add(add(y[k], y[k + 4]), y[k + 8])
                for c in stride(from: 0, to: 12, by: 4) { s[c + k] = add(y[c + k], sum) }
            }
        }

        func internalLayer(_ s: inout [UInt64]) {
            let sum = s.reduce(0, add)
            for i in 0 ..< 12 { s[i] = add(sum, mul(s[i], diag[i])) }
        }

        func permute(_ s: inout [UInt64]) {
            externalLayer(&s)
            for rc in initial {
                for i in 0 ..< 12 { s[i] = sbox(add(s[i], rc[i])) }
                externalLayer(&s)
            }
            for c in partial {
                s[0] = sbox(add(s[0], c))
                internalLayer(&s)
            }
            for rc in terminal {
                for i in 0 ..< 12 { s[i] = sbox(add(s[i], rc[i])) }
                externalLayer(&s)
            }
        }
    }

    /// The mainnet instance: qp-poseidon-core src/poseidon2.rs (constants from seed 0x3141592653589793,
    /// Plonky3's MDS block and Goldilocks width-12 internal diagonal).
    static let poseidon2 = Permutation(
        m4: [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]],
        initial: [
            [0xc002e770975b1607, 0xbca51a8dfe14593a, 0x72938dfbe774f7f9, 0xe4f2fe29e03234ac, 0xd5e0ba2f541b6449, 0xec33b868f3cc46c1,
             0x486dcb55419d475a, 0x6c1cb2a358cc24f1, 0xe3f30d509a1436bb, 0xd9a64f068dca7c29, 0xe59b3f57aabba1ae, 0x2a3dd4505b478fdc],
            [0xada1f8dc7676ed25, 0x2711aa8b5509d516, 0x4ae6acd0c9c92897, 0x56eb3d6b5256d67a, 0x1f7a9d55923bf51e, 0x3600427d397a7f68,
             0xe5076df75b72c3d0, 0xfcd59aa12c6090ad, 0xcd895e8c68b57a9e, 0x41df7ef9d730ae3e, 0xee3e2b889abe977d, 0xd29bb7edbeb9c405],
            [0x7d5c08eef608e382, 0x89ae889caaf0802c, 0xb35a8e976d2af617, 0xdb14234eafaf5173, 0x78f04462d48b1c98, 0x265293b0e47ce88a,
             0x999a649b69b9d32f, 0x64b0a186698e01d3, 0xee0b22d0dfae8bb8, 0x4fd53e50ca04a7ee, 0x5762bfe181f25047, 0xf51593e2beb5e3bd],
            [0x1e5e2b5760e32477, 0x622462a1f9aaaeed, 0xaa284b3ecdb222ae, 0x63c8e72f542bf3fc, 0x3ba588cacb43b5e0, 0x23eda6f3c99150dd,
             0xaad3bea4baac9a5a, 0xe9da8d699b94184a, 0xcdb13f4cd93e024c, 0x902cbd0956f655e3, 0x5b4e40ffc759532f, 0xde795c20a2357af7],
        ],
        terminal: [
            [0x7b72c539e0ea4c6e, 0x144573dae2ce9976, 0x802028b68f35fc88, 0x6d36c5022c4fe7c2, 0xa205d0ffa9b9def3, 0xf6e7e38b1ea6ba2f,
             0x34f7909ae5258d64, 0xb0464d9d77b97fca, 0x64ddb9d5de7e00a6, 0x0ed0d75c27975d97, 0x1cbb36f11127338b, 0x6673e505cfd0b6ba],
            [0x605f902830872e01, 0x3fd5eb927e95fe4f, 0xe81025b5a24c69cd, 0xf7d0ce75de23f74e, 0xf39942b6a8585089, 0x6d808a08f7b71df6,
             0xf8806b6588f49a8b, 0x57df2d8c2a32107a, 0x16e7c2074d654a2d, 0x213de241fcf33835, 0xb0f2b8905a0976f6, 0xd8e3cf2bbd355417],
            [0xe498691679d9330f, 0x763b45d2a3821b28, 0x0908bf65eb0a1f0d, 0x7691eb2d194b24f4, 0x0e43551233ae13b2, 0x93c393dbfc2fe76f,
             0x98f607485d48cdea, 0xe3d95f30309819c0, 0x1ef581a93eaf6acf, 0x0b24c1b7a030fca4, 0x624370be5670b327, 0x5f1e28615a11e486],
            [0xfe04051f909e042b, 0x7257e5b147fd3803, 0xe6ae134bb82f2e78, 0x5711fd5cf4784511, 0xf83a42660c08c0bc, 0x2cd8c96d9a3ce855,
             0x7d2ffb1bb0e17271, 0x85ae1528caea3811, 0x52a345d5c7adb0b8, 0x504c4c51f3faee94, 0xbce34a649cfccaf9, 0xe0a3389266fb6dc9],
        ],
        partial: [
            0x97f7798a784ad863, 0xd1d2bf082f60d4f0, 0x69a377a79f9ad206, 0xa9d06906a3858e24, 0x295275001eede5b5, 0x5874e441117bd746,
            0x8a084bbba8ed86cc, 0x3defd7645cde6425, 0x3998cfe6871cc137, 0x3e52ef8bca48314a, 0x964a209f85dc9ecc, 0x3fcc9ee82cc4577e,
            0x8e79b4a5d0096d6d, 0x8492362ad2392556, 0xee72f470262574d6, 0x1e0e18496da2444a, 0x0f3a74bf215eaac6, 0x1b061b76a1c0ded3,
            0x192c42d86803d7a6, 0xf6d49ff997ae0260, 0x3ec372e7a0fa3786, 0x5538cdf4f23445d3,
        ],
        diag: [
            0xc3b6c08e23ba9300, 0xd84b5de94a324fb6, 0x0d0c371c5b35b84f, 0x7964f570e7188037, 0x5daf18bbd996604b, 0x6743bc47b9595257,
            0x5528b9362c59bb70, 0xac45e25b7127b68b, 0xa2077d7dfbb606b5, 0xf3faac6faee378ae, 0x0c6388b51545e883, 0xd27dbb6944917b60,
        ])

    // MARK: Sponge (qp-poseidon-core src/lib.rs, src/serialization.rs)

    static let rate = 8

    /// The injective byte encoding: one little-endian u32 per 4 bytes, then a final felt holding the
    /// 0-3 leftover bytes followed by a 0x01 terminator byte.
    static func bytesToFelts(_ bytes: [UInt8]) -> [UInt64] {
        var felts: [UInt64] = []
        var i = 0
        while i + 4 <= bytes.count {
            felts.append(UInt64(bytes.le32(at: i)))
            i += 4
        }
        var last = [UInt8](repeating: 0, count: 4)
        for j in 0 ..< bytes.count - i { last[j] = bytes[i + j] }
        last[bytes.count - i] = 1
        felts.append(UInt64(last.le32(at: 0)))
        return felts
    }

    /// Absorb `felts` (8 per permutation), then the padding: a 1 felt and zeros up to a full block.
    static func absorbAndPad(_ felts: [UInt64]) -> [UInt64] {
        var state = [UInt64](repeating: 0, count: 12)
        var block = felts.map { $0 % p } + [1]
        while block.count % rate != 0 { block.append(0) }
        for start in stride(from: 0, to: block.count, by: rate) {
            for i in 0 ..< rate { state[i] = add(state[i], block[start + i]) }
            poseidon2.permute(&state)
        }
        return state
    }

    /// The digest is lanes 0-3, 8 little-endian bytes each.
    static func digestBytes(_ state: [UInt64]) -> [UInt8] {
        var out: [UInt8] = []
        for i in 0 ..< 4 { out.appendLE(state[i]) }
        return out
    }

    static func hashBytes(_ bytes: [UInt8]) -> [UInt8] { digestBytes(absorbAndPad(bytesToFelts(bytes))) }
    static func hashToFelts(_ felts: [UInt64]) -> [UInt64] { Array(absorbAndPad(felts)[0 ..< 4]) }

    /// qp-poseidon-core hash_squeeze_twice: the digest, one more permutation, the digest again.
    static func hashSqueezeTwice(_ bytes: [UInt8]) -> [UInt8] {
        var state = absorbAndPad(bytesToFelts(bytes))
        var out = digestBytes(state)
        poseidon2.permute(&state)
        out += digestBytes(state)
        return out
    }

    // MARK: Proof of work (qpow-math)

    /// get_nonce_hash(block_hash, nonce): hash_squeeze_twice(header || nonce), read as a big-endian U512.
    /// `header` is the 32-byte pre-seal block hash, `nonce` the 64-byte seal.
    static func nonceHash(header: [UInt8], nonce: [UInt8]) -> [UInt8] {
        precondition(header.count == 32 && nonce.count == 64)
        return hashSqueezeTwice(header + nonce)
    }

    /// quantus-miner pow-core mining_midstate: the sponge after the header block and the nonce's high
    /// 32 bytes, which stays fixed while a miner varies only the low bytes of the nonce.
    static func midstate(header: [UInt8], nonceHigh: [UInt8]) -> [UInt64] {
        var state = [UInt64](repeating: 0, count: 12)
        for i in 0 ..< 8 { state[i] = add(state[i], UInt64(header.le32(at: 4 * i))) }
        poseidon2.permute(&state)
        for i in 0 ..< 8 { state[i] = add(state[i], UInt64(nonceHigh.le32(at: 4 * i))) }
        poseidon2.permute(&state)
        return state
    }

    // MARK: U512 helpers: 8 words, most significant first

    /// Big-endian bytes (a multiple of 8 long) to big-endian 64-bit words.
    static func words(_ bytes: [UInt8]) -> [UInt64] {
        (0 ..< bytes.count / 8).map { k in (0 ..< 8).reduce(UInt64(0)) { $0 << 8 | UInt64(bytes[8 * k + $1]) } }
    }

    /// Numeric a < b for equal-length word arrays.
    static func less(_ a: [UInt64], _ b: [UInt64]) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        return false
    }

    static func plusOne(_ a: [UInt64]) -> [UInt64] {
        var r = a
        for i in stride(from: r.count - 1, through: 0, by: -1) {
            r[i] &+= 1
            if r[i] != 0 { break }
        }
        return r
    }

    /// target = U512::MAX / difficulty (is_valid_nonce accepts hash < target), for difficulties below 2^64.
    static func target(difficulty: UInt64) -> [UInt64] {
        precondition(difficulty > 0)
        var remainder: UInt64 = 0
        return (0 ..< 8).map { _ in
            let (q, r) = difficulty.dividingFullWidth((high: remainder, low: UInt64.max))
            remainder = r
            return q
        }
    }

    static func hex(_ words: [UInt64]) -> String { words.map { String(format: "%016llx", $0) }.joined() }
}
