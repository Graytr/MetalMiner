import Foundation

/// CPU reference for KawPow (Ravencoin): ProgPoW with RAVENCOINKAWPOW padding, written from
/// RavenCommunity/cpp-kawpow lib/ethash/progpow.cpp and checked against its published vectors.
/// The DAG is Ethash's with 7,500-block epochs (EthashReference does the cache and items).
enum KawPowReference {
    static let epochLength = 7_500
    static let periodLength = 3
    static let lanes = 16
    static let regs = 32
    static let cacheWords = 4_096
    static let cacheOps = 11
    static let mathOps = 18
    static let rounds = 64
    /// KawPow builds its DAG items from 512 cache parents (Ethash uses 256).
    static let datasetParents = 512
    static let fnvPrime: UInt32 = 0x0100_0193
    static let fnvOffset: UInt32 = 0x811C_9DC5
    /// "RAVENCOINKAWPOW", one character per word.
    static let ravencoin: [UInt32] = [0x72, 0x41, 0x56, 0x45, 0x4E, 0x43, 0x4F, 0x49, 0x4E, 0x4B, 0x41, 0x57, 0x50, 0x4F, 0x57]

    @inline(__always) static func fnv1a(_ u: UInt32, _ v: UInt32) -> UInt32 { (u ^ v) &* fnvPrime }
    @inline(__always) static func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        let c = n & 31
        return c == 0 ? x : (x &<< c) | (x &>> (32 - c))
    }
    @inline(__always) static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
        let c = n & 31
        return c == 0 ? x : (x &>> c) | (x &<< (32 - c))
    }

    struct Kiss99 {
        var z, w, jsr, jcong: UInt32
        mutating func next() -> UInt32 {
            z = 36969 &* (z & 0xFFFF) &+ (z >> 16)
            w = 18000 &* (w & 0xFFFF) &+ (w >> 16)
            jcong = 69069 &* jcong &+ 1_234_567
            jsr ^= jsr << 17
            jsr ^= jsr >> 13
            jsr ^= jsr << 5
            return (((z << 16) &+ w) ^ jcong) &+ jsr
        }
    }

    static let roundConstants800: [UInt32] = [
        0x0000_0001, 0x0000_8082, 0x0000_808A, 0x8000_8000, 0x0000_808B, 0x8000_0001, 0x8000_8081, 0x0000_8009,
        0x0000_008A, 0x0000_0088, 0x8000_8009, 0x8000_000A, 0x8000_808B, 0x0000_008B, 0x0000_8089, 0x0000_8003,
        0x0000_8002, 0x0000_0080, 0x0000_800A, 0x8000_000A, 0x8000_8081, 0x0000_8080,
    ]

    /// Keccak-f[800]: 22 rounds on 32-bit lanes.
    static func keccakF800(_ a: inout [UInt32]) {
        for round in 0 ..< 22 {
            let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
            let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
            let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
            let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
            let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]
            let d = [c4 ^ rotl(c1, 1), c0 ^ rotl(c2, 1), c1 ^ rotl(c3, 1), c2 ^ rotl(c4, 1), c3 ^ rotl(c0, 1)]
            for i in 0 ..< 25 { a[i] ^= d[i % 5] }
            let t = a[1]
            a[1] = rotl(a[6], 12); a[6] = rotl(a[9], 20); a[9] = rotl(a[22], 29); a[22] = rotl(a[14], 7)
            a[14] = rotl(a[20], 18); a[20] = rotl(a[2], 30); a[2] = rotl(a[12], 11); a[12] = rotl(a[13], 25)
            a[13] = rotl(a[19], 8); a[19] = rotl(a[23], 24); a[23] = rotl(a[15], 9); a[15] = rotl(a[4], 27)
            a[4] = rotl(a[24], 14); a[24] = rotl(a[21], 2); a[21] = rotl(a[8], 23); a[8] = rotl(a[16], 13)
            a[16] = rotl(a[5], 4); a[5] = rotl(a[3], 28); a[3] = rotl(a[18], 21); a[18] = rotl(a[17], 15)
            a[17] = rotl(a[11], 10); a[11] = rotl(a[7], 6); a[7] = rotl(a[10], 3); a[10] = rotl(t, 1)
            for j in stride(from: 0, to: 25, by: 5) {
                let a0 = a[j], a1 = a[j + 1], a2 = a[j + 2], a3 = a[j + 3], a4 = a[j + 4]
                a[j] = a0 ^ (~a1 & a2); a[j + 1] = a1 ^ (~a2 & a3); a[j + 2] = a2 ^ (~a3 & a4)
                a[j + 3] = a3 ^ (~a4 & a0); a[j + 4] = a4 ^ (~a0 & a1)
            }
            a[0] ^= roundConstants800[round]
        }
    }

    static func randomMath(_ a: UInt32, _ b: UInt32, _ selector: UInt32) -> UInt32 {
        switch selector % 11 {
        case 0: return a &+ b
        case 1: return a &* b
        case 2: return UInt32(truncatingIfNeeded: (UInt64(a) * UInt64(b)) >> 32)
        case 3: return min(a, b)
        case 4: return rotl(a, b)
        case 5: return rotr(a, b)
        case 6: return a & b
        case 7: return a | b
        case 8: return a ^ b
        case 9: return UInt32(a.leadingZeroBitCount + b.leadingZeroBitCount)
        default: return UInt32(a.nonzeroBitCount + b.nonzeroBitCount)
        }
    }

    static func randomMerge(_ a: inout UInt32, _ b: UInt32, _ selector: UInt32) {
        let x = (selector >> 16) % 31 + 1
        switch selector % 4 {
        case 0: a = a &* 33 &+ b
        case 1: a = (a ^ b) &* 33
        case 2: a = rotl(a, x) ^ b
        default: a = rotr(a, x) ^ b
        }
    }

    /// The random program for one period. ProgPoW reseeds the program RNG at the start of every round,
    /// so all 64 rounds of a hash run this same sequence.
    struct Program {
        enum Op {
            case cache(src: Int, dst: Int, sel: UInt32)
            case math(src1: Int, src2: Int, sel1: UInt32, dst: Int, sel2: UInt32)
        }
        var ops: [Op] = []
        var dagDst: [Int] = []
        var dagSel: [UInt32] = []
    }

    static func program(period: UInt64) -> Program {
        let lo = UInt32(truncatingIfNeeded: period), hi = UInt32(truncatingIfNeeded: period >> 32)
        let z = fnv1a(fnvOffset, lo), w = fnv1a(z, hi), jsr = fnv1a(w, lo), jcong = fnv1a(jsr, hi)
        var rng = Kiss99(z: z, w: w, jsr: jsr, jcong: jcong)
        var dstSeq = (0 ..< regs).map { $0 }
        var srcSeq = (0 ..< regs).map { $0 }
        for i in stride(from: regs, to: 1, by: -1) {   // Fisher-Yates, dst then src
            dstSeq.swapAt(i - 1, Int(rng.next() % UInt32(i)))
            srcSeq.swapAt(i - 1, Int(rng.next() % UInt32(i)))
        }
        var dstCounter = 0, srcCounter = 0
        func nextDst() -> Int { defer { dstCounter += 1 }; return dstSeq[dstCounter % regs] }
        func nextSrc() -> Int { defer { srcCounter += 1 }; return srcSeq[srcCounter % regs] }

        var program = Program()
        for i in 0 ..< max(cacheOps, mathOps) {
            if i < cacheOps {
                let src = nextSrc(), dst = nextDst(), sel = rng.next()
                program.ops.append(.cache(src: src, dst: dst, sel: sel))
            }
            if i < mathOps {
                let srcRandom = rng.next() % UInt32(regs * (regs - 1))
                let src1 = Int(srcRandom % UInt32(regs))
                var src2 = Int(srcRandom / UInt32(regs))
                if src2 >= src1 { src2 += 1 }
                let sel1 = rng.next()
                let dst = nextDst()
                let sel2 = rng.next()
                program.ops.append(.math(src1: src1, src2: src2, sel1: sel1, dst: dst, sel2: sel2))
            }
        }
        for i in 0 ..< 4 {
            program.dagDst.append(i == 0 ? 0 : nextDst())
            program.dagSel.append(rng.next())
        }
        return program
    }

    /// The 256-bit mix digest. `item` returns 2048-bit DAG item i as 64 words; `l1` is the DAG's first 4,096 words.
    static func hashMix(seed0: UInt32, seed1: UInt32, program: Program, items: UInt32, l1: [UInt32],
                        item: (UInt32) -> [UInt32]) -> [UInt32] {
        let z = fnv1a(fnvOffset, seed0), w = fnv1a(z, seed1)
        var mix = (0 ..< lanes).map { l -> [UInt32] in
            let jsr = fnv1a(w, UInt32(l))
            var rng = Kiss99(z: z, w: w, jsr: jsr, jcong: fnv1a(jsr, UInt32(l)))
            return (0 ..< regs).map { _ in rng.next() }
        }
        for r in 0 ..< rounds {
            let data = item(mix[r % lanes][0] % items)
            for op in program.ops {
                switch op {
                case let .cache(src, dst, sel):
                    for l in 0 ..< lanes { randomMerge(&mix[l][dst], l1[Int(mix[l][src] % UInt32(cacheWords))], sel) }
                case let .math(src1, src2, sel1, dst, sel2):
                    for l in 0 ..< lanes { randomMerge(&mix[l][dst], randomMath(mix[l][src1], mix[l][src2], sel1), sel2) }
                }
            }
            for l in 0 ..< lanes {
                let offset = ((l ^ r) % lanes) * 4
                for i in 0 ..< 4 { randomMerge(&mix[l][program.dagDst[i]], data[offset + i], program.dagSel[i]) }
            }
        }
        var digest = [UInt32](repeating: fnvOffset, count: 8)
        for l in 0 ..< lanes {
            let laneHash = mix[l].reduce(fnvOffset) { fnv1a($0, $1) }
            digest[l % 8] = fnv1a(digest[l % 8], laneHash)
        }
        return digest
    }

    /// (mix digest, final hash) as bytes, like cpp-kawpow's hash().
    static func hash(header: [UInt8], nonce: UInt64, blockNumber: Int, items: UInt32, l1: [UInt32],
                     item: (UInt32) -> [UInt32]) -> (mix: [UInt8], final: [UInt8]) {
        var state = [UInt32](repeating: 0, count: 25)
        for i in 0 ..< 8 { state[i] = header.le32(at: 4 * i) }
        state[8] = UInt32(truncatingIfNeeded: nonce)
        state[9] = UInt32(truncatingIfNeeded: nonce >> 32)
        for i in 10 ..< 25 { state[i] = ravencoin[i - 10] }
        keccakF800(&state)
        let carry = Array(state[0 ..< 8])
        let digest = hashMix(seed0: carry[0], seed1: carry[1], program: program(period: UInt64(blockNumber / periodLength)),
                             items: items, l1: l1, item: item)
        var final = carry + digest + Array(ravencoin[0 ..< 9])
        keccakF800(&final)
        var mixBytes: [UInt8] = [], finalBytes: [UInt8] = []
        for w in digest { mixBytes.appendLE(w) }
        for w in final[0 ..< 8] { finalBytes.appendLE(w) }
        return (mixBytes, finalBytes)
    }

    /// Light-cache context for an epoch: the cache, 2048-bit item count, the L1 words, and an item function.
    struct Light {
        let cache: [UInt32]
        let items: UInt32
        let l1: [UInt32]

        init(epoch: Int) {
            cache = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epoch), seed: EthashReference.seed(iterations: epoch))
            items = UInt32(EthashReference.datasetSize(epoch: epoch) / 128 / 2)
            var l1: [UInt32] = []
            cache.withUnsafeBufferPointer { c in
                for i in 0 ..< UInt32(cacheWords / 16) {
                    l1 += EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: i, parents: datasetParents)
                }
            }
            self.l1 = l1
        }

        func item(_ index: UInt32) -> [UInt32] {
            cache.withUnsafeBufferPointer { c in
                (0 ..< 4).flatMap { EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: 4 * index + UInt32($0), parents: datasetParents) }
            }
        }
    }

    /// Published vectors from RavenCommunity/cpp-kawpow test/unittests/progpow_test_vectors.hpp.
    static let vectors: [(block: Int, header: String, nonce: String, mix: String, final: String)] = [
        (0, "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000",
         "6e97b47b134fda0c7888802988e1a373affeb28bcd813b6e9a0fc669c935d03a", "e601a7257a70dc48fccc97a7330d704d776047623b92883d77111fb36870f3d1"),
        (49, "63155f732f2bf556967f906155b510c917e48e99685ead76ea83f4eca03ab12b", "0000000007073c07",
         "d36f7e815ee09e74eceb9c96993a3d681edf2bf0921fc7bb710364042db99777", "e7ced124598fd2500a55ad9f9f48e3569327fe50493c77a4ac9799b96efb9463"),
        (50, "9e7248f20914913a73d80a70174c331b1d34f260535ac3631d770e656b5dd922", "00000000076e482e",
         "d6dc634ae837e2785b347648ea515e25e5d8821ae0b95e1c2a9c2d497e0dcfbd", "ab0ad7ef8d8ee317dd12d10310aceed7321d34fb263791c2de5776a6658d177e"),
        (99, "de37e1824c86d35d154cf65a88de6d9286aec4f7f10c3fc9f0fa1bcc2687188d", "000000003917afab",
         "fa706860e5e0e830d5d1d7157e5bea7f5f8a350c7c8612ac1d1fcf2974d64244", "aa85340690f2e907054324a5021937910e15edfd1ef1577231843e7d32ec3a61"),
        (29950, "ac7b55e801511b77e11d52e9599206101550144525b5679f2dab19386f23dcce", "005d409dbc23a62a",
         "5359807b77a74878269c3a3044df8618a576ce8dc52e1c48d927d4a60e7c6b79", "022019e5408683f7f8326b4e46b42864a3a069f17b6151e434fcaedecaadd918"),
        (29999, "e43d7e0bdc8a4a3f6e291a5ed790b9fa1a0948a2b9e33c844888690847de19f5", "005db5fa4c2a3d03",
         "d15de3f9bfedd9b6d0f498273eb3b437115bdc8326c96c6457ac06deb5c9f389", "4e93630b81198752f876b24380999189b7b9366c08222ac05e4237b87114f305"),
        (30000, "d34519f72c97cae8892c277776259db3320820cb5279a299d0ef1e155e5c6454", "005db8607994ff30",
         "de0348b69bf91dfe2c3d3dba6f0132e9048a5284e57b8d9d20adc5f3dc0d3236", "c7953d848cda6e304f77b4c6d735645c8e8508a5e74c9e9814ef37b19087cd6c"),
        (30049, "8b6ce5da0b06d18db7bd8492d9e5717f8b53e7e098d9fef7886d58a6e913ef64", "005e2e215a8ca2e7",
         "975c6a9decc89cba7ace69338d4de8510d9619aef42b1d35d0bef7e0ce0614a9", "c262d8055e288d04b951a844bfca8ba529f5b4d652b408e3942727d7dd90957a"),
        (30050, "c2c46173481b9ced61123d2e293b42ede5a1b323210eb2a684df0874ffe09047", "005e30899481055e",
         "362f2fabdb9699d3634b6499703f939f378ee4eac803396c2b0ed0fe1d154972", "4cd7e6e79e0b63d42b2b06716a919ccc7834077ec727a9ea94edcdaff2fefab8"),
        (30099, "ea42197eb2ba79c63cb5e655b8b1f612c5f08aae1a49ff236795a3516d87bc71", "005ea6aef136f88b",
         "b1196457261bd05ccb387a8ff3fd02687bf496bd7943d89419465289669e27aa", "39d1ebfa783b61a6fa8e9747d0f9f134efae5cfba284a2c80e8deabae6b98676"),
        (59950, "49e15ba4bf501ce8fe8876101c808e24c69a859be15de554bf85dbc095491bd6", "02ebe0503bd7b1da",
         "df3dbb1669fd35dbb0ae96bbea2d498f0c6992cbddd092aeace42dd933505f95", "b8984cf4021c4433f753654848d721f33a0792b4417241f0cf7c7c2db011a54a"),
        (59999, "f5c50ba5c0d6210ddb16250ec3efda178de857b2b1703d8d5403bd0f848e19cf", "02edb6275bd221e3",
         "5017df70e97ca35638cf439cdbe54f30383d335e18eb4a74d6e166736f1038fa", "4cf1fa62f25b577ac822a6a28d55f8b7e3ae7fe983abd868ae00927e68c41016"),
        (170915, "5b3e8dfa1aafd3924a51f33e2d672d8dae32fa528d8b1d378d6e4db0ec5d665d", "0000000044975727",
         "efb29147484c434f1cc59629da90fd0343e3b047407ecd36e9ad973bd51bbac5", "e7e6bb3b2f9acd3864bc86f72f87237eaf475633ef650c726ac80eb0adf116b6"),
    ]

    static func runVectors() throws -> [String] {
        var lights: [Int: Light] = [:]
        var lines: [String] = []
        for v in vectors {
            let epoch = v.block / epochLength
            if lights[epoch] == nil { lights[epoch] = Light(epoch: epoch) }
            let light = lights[epoch]!
            let result = hash(header: [UInt8](hex: v.header)!, nonce: UInt64(v.nonce, radix: 16)!, blockNumber: v.block,
                              items: light.items, l1: light.l1, item: light.item)
            guard result.mix.hex == v.mix, result.final.hex == v.final else {
                throw MinerError("kawpow vector block \(v.block): got mix \(result.mix.hex) final \(result.final.hex)")
            }
            lines.append("block \(v.block) (epoch \(epoch), period \(v.block / periodLength)): mix and final hash match")
        }
        return lines
    }
}
