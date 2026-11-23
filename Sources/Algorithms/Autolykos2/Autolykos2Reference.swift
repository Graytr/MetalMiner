import Foundation

/// Autolykos v2 (Ergo) CPU reference, written from ergoplatform/ergo
/// ergo-core/src/main/scala/org/ergoplatform/mining/AutolykosPowScheme.scala (hitForVersion2ForMessage,
/// genIndexes, genElement, calcN) and checked against AutolykosPowSchemeSpec.scala.
enum Autolykos2Reference {
    // MARK: Parameters (k = 32, n = 26 on mainnet)

    static let k = 32
    static let nBase = 1 << 26
    static let increaseStart = 600 * 1024
    static let increasePeriod = 50 * 1024
    static let increaseHeightMax = 4_198_400

    /// Table size N for a block of version >= 2 at `height`: 2^26, then +5% (integer steps) every
    /// 51,200 blocks from height 614,400, frozen from height 4,198,400.
    static func calcN(height: Int) -> Int {
        let h = min(increaseHeightMax, height)
        if h < increaseStart { return nBase }
        var n = nBase
        for _ in 0 ..< (h - increaseStart) / increasePeriod + 1 { n = n / 100 * 105 }
        return n
    }

    /// M: the numbers 0...1023 as 8-byte big-endian integers (8192 bytes).
    static let constantM: [UInt8] = (0 ..< 1024).flatMap { i in
        (0 ..< 8).map { UInt8(truncatingIfNeeded: UInt64(i) >> (56 - 8 * UInt64($0))) }
    }

    /// secp256k1 group order q as 32 big-endian bytes; the target is b = q / difficulty.
    static let q: [UInt8] = [UInt8](hex: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")!

    static func be32(_ x: UInt32) -> [UInt8] { (0 ..< 4).map { UInt8(truncatingIfNeeded: x >> (24 - 8 * UInt32($0))) } }

    // MARK: Table elements

    /// Table elements for one height: element j = Blake2b256(j || h || M) without its first byte, where j and the
    /// height h are 4-byte big-endian. Reuses one 8200-byte buffer.
    final class Elements {
        private var input: [UInt8]
        init(height: UInt32) {
            input = [0, 0, 0, 0] + Autolykos2Reference.be32(height) + Autolykos2Reference.constantM
        }

        /// Element j as 31 big-endian bytes.
        func element(_ j: UInt32) -> [UInt8] {
            for b in 0 ..< 4 { input[b] = UInt8(truncatingIfNeeded: j >> (24 - 8 * UInt32(b))) }
            return Array(Autolykos2Blake2b.hash(input).dropFirst())
        }
    }

    /// A 31-byte big-endian element as the 8 little-endian 32-bit limbs the GPU table stores.
    static func limbs(_ element: [UInt8]) -> [UInt32] {
        let padded = [0] + element
        return (0 ..< 8).map { k in padded.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: 28 - 4 * k, as: UInt32.self)) } }
    }

    // MARK: The PoW function

    /// Every intermediate of one Autolykos v2 evaluation.
    struct Trace {
        /// Index of the element that seeds the index generation (i in the Scala code).
        var i: UInt32 = 0
        /// Blake2b256(f || msg || nonce), the hash the 32 indexes are cut from.
        var seedHash: [UInt8] = []
        var indexes: [UInt32] = []
        /// Sum of the 32 elements as 32 big-endian bytes.
        var sum: [UInt8] = []
        /// Blake2b256(sum): the PoW hit, compared as a big-endian number with the target b.
        var hit: [UInt8] = []
    }

    /// hitForVersion2ForMessage: msg is 32 bytes (Blake2b256 of the header without PoW), nonce 8 bytes.
    static func evaluate(msg: [UInt8], nonce: [UInt8], n: Int, element: (UInt32) -> [UInt8]) -> Trace {
        precondition(msg.count == 32 && nonce.count == 8)
        var trace = Trace()
        let first = Autolykos2Blake2b.hash(msg + nonce)
        let prei8 = first[24 ..< 32].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }   // takeRight(8), unsigned big-endian
        trace.i = UInt32(prei8 % UInt64(n))
        let f = element(trace.i)                                                   // 31 bytes
        trace.seedHash = Autolykos2Blake2b.hash(f + msg + nonce)
        let extended = trace.seedHash + trace.seedHash[0 ..< 3]
        trace.indexes = (0 ..< k).map { s in
            let x = extended[s ..< s + 4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            return x % UInt32(n)
        }
        var limbs = [UInt64](repeating: 0, count: 4)                               // little-endian 64-bit limbs
        for index in trace.indexes {
            let e = [0] + element(index)
            var carry: UInt64 = 0
            for l in 0 ..< 4 {
                let word = e.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(fromByteOffset: 24 - 8 * l, as: UInt64.self)) }
                let (s1, o1) = limbs[l].addingReportingOverflow(word)
                let (s2, o2) = s1.addingReportingOverflow(carry)
                limbs[l] = s2
                carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
            }
        }
        trace.sum = (0 ..< 32).map { UInt8(truncatingIfNeeded: limbs[3 - $0 / 8] >> (56 - 8 * UInt64($0 % 8))) }
        trace.hit = Autolykos2Blake2b.hash(trace.sum)
        return trace
    }

    // MARK: Targets and 256-bit helpers (big-endian byte arrays)

    /// decodeCompactBits for the positive difficulties Ergo uses, when they fit in 64 bits.
    static func difficulty(nBits: UInt32) -> UInt64? {
        let size = Int(nBits >> 24)
        guard size <= 8 else { return nil }
        let mantissa = [UInt8(truncatingIfNeeded: nBits >> 16), UInt8(truncatingIfNeeded: nBits >> 8), UInt8(truncatingIfNeeded: nBits)]
        var bytes = [UInt8](repeating: 0, count: size)
        for i in 0 ..< min(size, 3) { bytes[i] = mantissa[i] }
        if let top = bytes.first, top & 0x80 != 0 { return nil }   // negative
        return bytes.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }

    /// x / d for a 32-byte big-endian x.
    static func divide(_ x: [UInt8], by d: UInt64) -> [UInt8] {
        var remainder: UInt64 = 0
        var out: [UInt8] = []
        for l in 0 ..< 4 {
            let word = x[8 * l ..< 8 * l + 8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            let (quotient, r) = d.dividingFullWidth((high: remainder, low: word))
            remainder = r
            out += (0 ..< 8).map { UInt8(truncatingIfNeeded: quotient >> (56 - 8 * UInt64($0))) }
        }
        return out
    }

    /// The block target b = q / difficulty(nBits) as 32 big-endian bytes.
    static func target(nBits: UInt32) -> [UInt8]? {
        guard let d = difficulty(nBits: nBits), d > 0 else { return nil }
        return divide(q, by: d)
    }

    static func decimal(_ x: [UInt8]) -> String {
        var value = x
        var digits: [String] = []
        let chunk: UInt64 = 10_000_000_000_000_000_000
        while value.contains(where: { $0 != 0 }) {
            var remainder: UInt64 = 0
            var next: [UInt8] = []
            for l in 0 ..< value.count / 8 {
                let word = value[8 * l ..< 8 * l + 8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
                let (quotient, r) = chunk.dividingFullWidth((high: remainder, low: word))
                remainder = r
                next += (0 ..< 8).map { UInt8(truncatingIfNeeded: quotient >> (56 - 8 * UInt64($0))) }
            }
            digits.append(String(remainder))
            value = next
        }
        guard let last = digits.popLast() else { return "0" }
        return last + digits.reversed().map { String(repeating: "0", count: 19 - $0.count) + $0 }.joined()
    }

    static func less(_ a: [UInt8], _ b: [UInt8]) -> Bool { a.lexicographicallyPrecedes(b) }

    // MARK: Headers

    /// The header fields that go into the PoW message and the block id (HeaderSerializer.scala).
    struct Header {
        var version: UInt8
        var parentId: String
        var adProofsRoot: String
        var transactionsRoot: String
        var stateRoot: String
        var timestamp: UInt64
        var extensionHash: String
        var nBits: UInt32
        var height: UInt32
        var votes: String
        var pk: String
        var nonce: String

        static func vlq(_ x: UInt64) -> [UInt8] {
            var out: [UInt8] = []
            var v = x
            while v >= 0x80 {
                out.append(UInt8(truncatingIfNeeded: v) | 0x80)
                v >>= 7
            }
            out.append(UInt8(v))
            return out
        }

        /// version | parentId | adProofsRoot | transactionsRoot | stateRoot (33) | VLQ timestamp | extensionRoot |
        /// nBits (4, big-endian) | VLQ height | votes (3) | for version > 1, a length byte for extra fields (0 here).
        var bytesWithoutPow: [UInt8] {
            var out: [UInt8] = [version]
            out += [UInt8](hex: parentId)! + [UInt8](hex: adProofsRoot)! + [UInt8](hex: transactionsRoot)! + [UInt8](hex: stateRoot)!
            out += Header.vlq(timestamp)
            out += [UInt8](hex: extensionHash)!
            out += Autolykos2Reference.be32(nBits)
            out += Header.vlq(UInt64(height))
            out += [UInt8](hex: votes)!
            if version > 1 { out.append(0) }
            return out
        }

        /// The Autolykos v2 message: Blake2b256 of the header without PoW.
        var msg: [UInt8] { Autolykos2Blake2b.hash(bytesWithoutPow) }
        /// Block id: Blake2b256 of the full header (v2 solution = pk || nonce).
        var id: [UInt8] { Autolykos2Blake2b.hash(bytesWithoutPow + [UInt8](hex: pk)! + [UInt8](hex: nonce)!) }
        var nonceBytes: [UInt8] { [UInt8](hex: nonce)! }
    }

    // MARK: Vectors

    /// AutolykosPowSchemeSpec "test vectors for first increase in N value (height 614,400)".
    static let header614400 = Header(
        version: 2, parentId: "ac2101807f0000ca01ff0119db227f202201007f62000177a080005d440896d0",
        adProofsRoot: "5d3f80dcff7f5e7f59007294c180808d0158d1ff6ba10000f901c7f0ef87dcff",
        transactionsRoot: "f17fffacb6ff7f7f1180d2ff7f1e24ffffe1ff937f807f0797b9ff6ebdae007e",
        stateRoot: "5c8c00b8403d3701557181c8df800001b6d5009e2201c6ff807d71808c00019780",
        timestamp: 4_928_911_477_310_178_288,
        extensionHash: "1480887f80007f4b01cf7f013ff1ffff564a0000b9a54f00770e807f41ff88c0",
        nBits: 37_748_736, height: 614_400, votes: "000000",
        pk: "03bedaee069ff4829500b3c07c4d5fe6b3ea3d3bf76c5c28c1d4dcdb1bed0ade0c", nonce: "0000000000003105")

    /// AutolykosPowSchemeSpec "test vector - invalid solution" (a pool-submitted header that must fail).
    static let headerInvalid = Header(
        version: 2, parentId: "ab19e6c7a4062979dddb534df83f236d1b949c7cef18bcf434a67e87c593eef9",
        adProofsRoot: "49453875a43035c7640dee2f905efe06128b00d41acd2c8df13691576d4fd85c",
        transactionsRoot: "770cbb6e18673ed025d386487f15d3252115d9a6f6c9b947cf3d04731dd6ab75",
        stateRoot: "c0d0b5eafd07b22487dac66628669c42a242b90bef3e1fcdc76d83140d58b6bc0e",
        timestamp: 1_611_225_263_165,
        extensionHash: "9bc7d54583c5d44bb62a7be0473cd78d601822a626afc13b636f2cbff0d87faf",
        nBits: 72_286_528, height: 2870, votes: "000000",
        pk: "0288114b0586efea9f86e4587f2071bc1c85fb77e15eba96b2769733e0daf57903", nonce: "000100000580a91b")

    /// Mainnet blocks from api.ergoplatform.com/api/v1/blocks/<id>: the first Autolykos v2 block, block 1,000,000,
    /// and the chain tip on 2026-11-19 (20:53 UTC). Their ids pin the header serialization; hit < b checks the PoW.
    static let mainnet: [(id: String, header: Header)] = [
        ("0ba60a7db44877aade553beb05200f7d67b586945418d733e455840d283e0508", Header(
            version: 2, parentId: "b21a1c00412b84033185f3cf6cdd345c4276628f3dda1e63b8502a4923c8e2bc",
            adProofsRoot: "8daa8b0dfcf7b1178ec4b1bd813258b41c3e51b4cc91b1466fa1c68116739cee",
            transactionsRoot: "d56f5d1ab2bdc87e238daeccf61f0085c20c14813891207346a5d024d9c5e415",
            stateRoot: "f7593065966c5f9bd60b64789e5b3abfe3e78568e9c220d72497fdf78200038113",
            timestamp: 1_612_280_695_862,
            extensionHash: "4adbc9e8c0e8c5b3cc6fed0b91fd43f53622a98d2359497ec132ae3279d0b259",
            nBits: 107_976_917, height: 417_792, votes: "000000",
            pk: "02b3a06d6eaa8671431ba1db4dd427a77f75a5c2acbd71bfb725d38adc2b55f669", nonce: "16db4fbab447e127")),
        ("f04085962f306d8e4ee9f1a415abb82c32ac6a183d4d286e995569c978a7c5cb", Header(
            version: 3, parentId: "eaf3168103a2f0304e3d6cbf621163fcf5877509a9fb39eeb3948a59f6f8d96c",
            adProofsRoot: "5615575b1afa0be7ce825c2aeb210e4157c37bfa351276388cb0f5ef10498245",
            transactionsRoot: "842c5b47f466e52eb48c2476774ab27f166eccafe069f1e536d7c9a02cf7951d",
            stateRoot: "7c61ff847e4837eb8b445be6f34673850e9f6917b8b0a3492ca57622b2f9f82c19",
            timestamp: 1_683_634_223_508,
            extensionHash: "367ea050a780669223476b7c43a1a5d07b8b0e7dfb508ac10ac93814d4bcd78f",
            nBits: 118_205_088, height: 1_000_000, votes: "000000",
            pk: "03677d088e4958aedcd5cd65845540e91272eba99e4d98e382f5ae2351e0dfbefd", nonce: "cd36b2015e53697f")),
        ("838731fcb67e7b971e7b16c2bf90f1957475da886bf98e9dc97e49ae6953371d", Header(
            version: 4, parentId: "1b3b1bde86cf2d2a8f60ce6f9a45f51bf2c61e2481964df1ef41cc4a690dca24",
            adProofsRoot: "239d19bdc452ba000c0b185ed94594a7bb1f8d12fc04e25babaa12e00433a78c",
            transactionsRoot: "72628b8b15c92b7ab65615a9dbe498d2fce026988cb152db82969d84c019ef39",
            stateRoot: "352f43b65337013d08ecccf7d09764aff16d53b8586eb517148a1e3bfd06a9ee19",
            timestamp: 1_795_121_580_647,
            extensionHash: "8881846cc750cee41014033ecee14a8f7ec00ec488a9d214a084f39653128a7d",
            nBits: 105_011_653, height: 1_920_429, votes: "000000",
            pk: "033602a81fce83c18c4c591f4aea8f2732f479d6b08a21ec57c0de683e8e3815ad", nonce: "529b1187a563afbe")),
    ]

    static func short(_ bytes: [UInt8]) -> String { String(bytes.hex.prefix(16)) + "…" }

    /// Runs every vector; one line each, throws on the first mismatch.
    static func runVectors() throws -> [String] {
        var lines: [String] = []

        // BLAKE2b itself: RFC 7693 Appendix A, BLAKE2b-512("abc").
        let abc = Autolykos2Blake2b.hash(Array("abc".utf8), length: 64).hex
        guard abc == "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                   + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" else {
            throw MinerError("BLAKE2b-512(\"abc\") is \(abc), not the RFC 7693 value")
        }
        lines.append("RFC 7693 BLAKE2b-512(\"abc\") ok")

        // calcN test vectors (AutolykosPowSchemeSpec).
        let nVectors: [(Int, Int)] = [(500_000, nBase), (600_000, nBase), (600 * 1024, 70_464_240), (650 * 1024, 73_987_410),
                                      (700_000, 73_987_410), (788_400, 81_571_035), (1_051_200, 104_107_290),
                                      (4_198_400, 2_143_944_600), (41_984_000, 2_143_944_600)]
        for (height, expected) in nVectors where calcN(height: height) != expected {
            throw MinerError("calcN(\(height)) = \(calcN(height: height)), expected \(expected)")
        }
        lines.append("calcN: \(nVectors.count) official values ok (2^26 below 614,400; 2,143,944,600 from 4,198,400)")

        // Height 614,400: exact msg, N, b and hit from the official test; the id is the one in its header JSON.
        let h = header614400
        guard h.msg.hex == "548c3e602a8f36f8f2738f5f643b02425038044d98543a51cabaa9785e7e864f",
              h.id.hex == "5603a937ec1988220fc44fb5022fb82d5565b961f005ebb55d85bd5a9e6f801f" else {
            throw MinerError("height 614400: msg \(h.msg.hex), id \(h.id.hex)")
        }
        let n614 = calcN(height: Int(h.height))
        guard n614 == 70_464_240 else { throw MinerError("height 614400: N \(n614)") }
        guard let b614 = target(nBits: h.nBits),
              decimal(b614) == "7067388259113537318333190002971674063283542741642755394446115914399301849" else {
            throw MinerError("height 614400: b differs")
        }
        let elements614 = Elements(height: h.height)
        let t614 = evaluate(msg: h.msg, nonce: h.nonceBytes, n: n614, element: elements614.element)
        guard t614.hit.hex == "0002fcb113fe65e5754959872dfdbffea0489bf830beb4961ddc0e9e66a1412a", less(t614.hit, b614) else {
            throw MinerError("height 614400: hit \(t614.hit.hex)")
        }
        lines.append("height 614,400 (AutolykosPowSchemeSpec): id and msg \(short(h.msg)) ok, N 70,464,240, b ok,"
                     + " hit \(short(t614.hit)) exact and < b")

        // The invalid pool solution must not meet its target.
        let bad = headerInvalid
        guard bad.id.hex == "5b0ce6711de6b926f60b67040cc4512804517785df375d063f1bf1d75588af3a",
              let bBad = target(nBits: bad.nBits) else { throw MinerError("height 2870: id \(bad.id.hex)") }
        let tBad = evaluate(msg: bad.msg, nonce: bad.nonceBytes, n: calcN(height: Int(bad.height)),
                            element: Elements(height: bad.height).element)
        guard !less(tBad.hit, bBad) else { throw MinerError("height 2870: the invalid solution passed (hit \(tBad.hit.hex))") }
        lines.append("height 2,870 invalid solution (AutolykosPowSchemeSpec): id ok, hit \(short(tBad.hit)) >= b, rejected")

        // Mainnet blocks: id, then hit < b at that height's N.
        for (id, header) in mainnet {
            guard header.id.hex == id else { throw MinerError("block \(header.height): id \(header.id.hex), expected \(id)") }
            guard let b = target(nBits: header.nBits) else { throw MinerError("block \(header.height): bad nBits") }
            let n = calcN(height: Int(header.height))
            let t = evaluate(msg: header.msg, nonce: header.nonceBytes, n: n, element: Elements(height: header.height).element)
            guard less(t.hit, b) else { throw MinerError("block \(header.height): hit \(t.hit.hex) is not below b \(b.hex)") }
            lines.append("mainnet block \(header.height) (v\(header.version), N \(n)): id ok, msg \(short(header.msg)),"
                         + " hit \(short(t.hit)) < b \(short(b))")
        }
        return lines
    }
}
