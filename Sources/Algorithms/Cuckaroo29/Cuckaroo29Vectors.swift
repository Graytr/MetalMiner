import Foundation

/// Published known-answer vectors: tari-project/tari base_layer/core/src/proof_of_work/siphash.rs and cuckaroo_pow.rs
/// tests (two real mainnet C29 proofs among them), and mimblewimble/grin core/src/pow/cuckaroo.rs (cuckaroo19).
extension Cuckaroo29Reference {
    /// tari siphash.rs tests: siphash24(keys, nonce) and siphash_block(keys, nonce, 21).
    static let sipVectors: [([UInt64], UInt64, UInt64)] = [
        ([1, 2, 3, 4], 10, 928_382_149_599_306_901), ([1, 2, 3, 4], 111, 10_524_991_083_049_122_233),
        ([9, 7, 6, 7], 12, 1_305_683_875_471_634_734), ([9, 7, 6, 7], 10, 11_589_833_042_187_638_814),
    ]
    static let blockVectors: [([UInt64], UInt64, UInt64)] = [
        ([1, 2, 3, 4], 10, 1_182_162_244_994_096_396), ([1, 2, 3, 4], 123, 11_303_676_240_481_718_781),
        ([9, 7, 6, 7], 12, 4_886_136_884_237_259_030),
    ]

    /// tari cuckaroo_pow.rs test_header_hash and test_edge_generation_example3: (mining hash, nonce, siphash keys).
    static let keyVectors: [(String, UInt64, String)] = [
        ("4dbfee3eb7b9a6a27d2a4a8d754eb77cc5493006945c1246e50e9beb4de5ffa5", 0x9D58_9ED5_97ED_42D1,
         "49b48f77df94943cf3a422c5a0b528c737cc38a7b6c36076e81abcede5b2be3a"),
        ("93e43a39b44f0875af830b6fd4cc69a421b1f5f0c5efd1b6c2e16d439bfd238c", 0xAB30_DC99_FD05_4F57,
         "094cf89614ed5ee03b1454881361110fc380e9c4072343f5d24b9e2597b0da96"),
    ]

    /// A real C29 block proof (tari test_solution, test_unpack_example, test_edge_generation_example2).
    static let proof1Hash = "4dbfee3eb7b9a6a27d2a4a8d754eb77cc5493006945c1246e50e9beb4de5ffa5"
    static let proof1Nonce: UInt64 = 0x9D58_9ED5_97ED_42D0
    static let proof1Keys = "a216826b5d2752ccf129eef73e1e02a6b56d13195d7998e6b04d02a136b88f4f"
    static let proof1Packed = "ab3c742104de5808220f0ebd1d24e2a279489c9fa8c9264f754181433226655286c69a08f166e523283813e5"
        + "eceabbec042598193013a34cd966601e064d5f3dbb911efe39536e7847f3180071865023e18c6c1c627696aece2ff401938abacc8ed2"
        + "f446b8ba71785b074a086d36d1d61d638dc0eab156b8883214cbff9962f199b96c92349df3d1d7b647ed0cdf6dfde1e49077bcfb74b503"
    static let proof1PowHash = "06d52b90ccfd4db1a52cc133a46dac0dc4577343c1a27d200865a81d717a60e1"
    static let proof1Nonces: [UInt64] = [
        24_394_923, 46_592_033, 58_968_194, 71_842_682, 75_995_694, 81_022_926, 97_860_763, 105_410_600, 106_063_142,
        138_729_012, 150_559_164, 170_291_280, 197_045_966, 202_539_638, 206_356_582, 215_689_620, 218_504_800,
        232_385_274, 243_238_820, 250_666_150, 268_537_652, 296_239_928, 296_891_268, 315_542_595, 338_677_422,
        341_088_271, 346_272_558, 359_697_897, 364_349_211, 377_758_979, 391_857_369, 403_811_427, 408_334_826,
        413_242_437, 413_564_914, 426_980_322, 433_277_222, 460_056_825, 473_150_750, 473_935_291, 477_597_924,
        497_788_893,
    ]
    static let proof1Edges: [SIMD2<UInt32>] = [
        [259_523_165, 501_211_281], [157_516_326, 386_490_295], [163_049_712, 357_352_750], [527_359_151, 457_953_146],
        [43_269_845, 334_867_286], [43_269_845, 341_998_749], [450_586_946, 355_116_366], [117_672_975, 137_509_934],
        [269_707_614, 87_839_857], [117_672_975, 78_269_931], [139_445_939, 87_839_857], [157_516_326, 306_322_638],
        [58_908_345, 390_892_394], [269_707_614, 36_056_555], [101_786_071, 18_252_563], [527_359_151, 482_342_291],
        [356_633_100, 306_322_638], [216_244_743, 373_890_488], [81_971_272, 357_352_750], [521_344_355, 341_998_749],
        [424_927_616, 534_790_392], [302_985_768, 390_892_394], [81_971_272, 386_490_295], [90_433_930, 262_615_890],
        [424_927_616, 10_110_110], [259_523_165, 18_252_563], [163_049_712, 482_342_291], [101_786_071, 334_867_286],
        [58_908_345, 228_032_021], [216_244_743, 262_615_890], [444_797_260, 137_509_934], [90_433_930, 78_269_931],
        [521_344_355, 228_032_021], [302_985_768, 469_085_984], [356_633_100, 469_085_984], [139_445_939, 534_790_392],
        [242_580_855, 373_890_488], [242_580_855, 501_211_281], [450_586_946, 36_056_555], [45_078_436, 457_953_146],
        [444_797_260, 355_116_366], [45_078_436, 10_110_110],
    ]

    /// A second real C29 proof (tari test_edge_generation_example3 and example4); keys from keyVectors[1].
    static let proof2Nonces: [UInt64] = [
        1_252_665, 4_516_819, 17_265_865, 24_709_305, 89_445_155, 99_203_810, 108_059_490, 118_448_252, 126_732_226,
        147_341_567, 162_827_037, 177_849_034, 183_556_179, 191_103_550, 231_377_681, 233_321_258, 237_510_921,
        257_843_213, 266_606_591, 282_340_500, 288_301_862, 333_019_502, 344_766_902, 355_446_190, 368_615_551,
        371_362_415, 371_729_271, 380_994_474, 396_711_753, 400_948_255, 402_047_643, 445_581_804, 452_121_724,
        460_915_916, 464_509_725, 472_201_798, 487_709_959, 488_169_697, 499_236_155, 509_929_107, 516_834_413,
        534_561_363,
    ]
    static let proof2Edges: [SIMD2<UInt32>] = [
        [138_864_790, 173_576_314], [138_864_790, 183_574_123], [475_775_524, 272_345_198], [434_305_107, 118_921_972],
        [145_538_206, 491_299_099], [507_636_712, 57_208_766], [274_489_528, 183_574_123], [475_775_524, 86_499_705],
        [376_165_312, 307_539_583], [361_363_154, 255_932_004], [361_363_154, 491_299_099], [429_018_120, 525_050_564],
        [400_305_596, 173_576_314], [507_636_712, 471_838_093], [534_308_678, 484_814_104], [434_305_107, 104_085_420],
        [152_178_341, 255_932_004], [139_457_798, 471_838_093], [65_921_500, 78_549_354], [429_018_120, 461_321_619],
        [209_554_018, 29_235_998], [184_129_162, 78_549_354], [508_864_826, 118_921_972], [265_651_264, 386_485_268],
        [330_070_098, 178_264_960], [330_070_098, 461_321_619], [274_489_528, 386_997_870], [184_129_162, 272_345_198],
        [65_921_500, 525_050_564], [534_308_678, 86_499_705], [152_178_341, 492_228_492], [507_444_066, 178_264_960],
        [508_864_826, 492_228_492], [398_316_755, 307_539_583], [376_165_312, 29_235_998], [265_651_264, 386_997_870],
        [398_316_755, 104_085_420], [507_444_066, 386_485_268], [139_457_798, 21_811_140], [145_538_206, 484_814_104],
        [400_305_596, 21_811_140], [209_554_018, 57_208_766],
    ]

    /// mimblewimble/grin core/src/pow/cuckaroo.rs: cuckaroo19 keys and their 42-cycles (V1_19, V2_19).
    static let grin19: [(keys: [UInt64], nonces: [UInt64])] = [
        ([0x2379_6193_8720_92EA, 0xF101_7D8A_68C4_B745, 0xD312_BD53_D2CD_307B, 0x840A_CCE5_833D_DC52],
         [0x45E9, 0x6A59, 0xF1AD, 0x10EF7, 0x129E8, 0x13E58, 0x17936, 0x19F7F, 0x208DF, 0x23704, 0x24564, 0x27E64,
          0x2B828, 0x2BB41, 0x2FFC0, 0x304C5, 0x31F2A, 0x347DE, 0x39686, 0x3AB6C, 0x429AD, 0x45254, 0x49200, 0x4F8F8,
          0x5697F, 0x57AD1, 0x5DD47, 0x607F8, 0x66199, 0x686C7, 0x6D5F3, 0x6DA7A, 0x6DBDF, 0x6F6BF, 0x6FFBB, 0x7580E,
          0x78594, 0x785AC, 0x78B1D, 0x7B80D, 0x7C11C, 0x7DA35]),
        ([0x6A54_F2A3_5AB7_E976, 0x6881_8717_FF5C_D30E, 0x09C1_4260_C1BD_BAF7, 0xEA5B_4CD5_D0DE_3CF0],
         [0x2B1E, 0x67D3, 0xB041, 0xB289, 0xC6C3, 0xD31E, 0xD75C, 0x111D7, 0x145AA, 0x1712E, 0x1A3AF, 0x1ECC5,
          0x206B1, 0x2A55C, 0x2A9CD, 0x2B67E, 0x321D8, 0x35DDE, 0x3721E, 0x37AC0, 0x39EDB, 0x3B80B, 0x3FC79, 0x4148B,
          0x42A48, 0x44395, 0x4BBC9, 0x4F775, 0x515C5, 0x56F97, 0x5AA10, 0x5BC1B, 0x5C56D, 0x5D552, 0x60A2E, 0x66646,
          0x6C3AA, 0x70709, 0x71D13, 0x762A3, 0x79D88, 0x7E3AE]),
    ]

    /// tari a_reduced_parameter_forgery_over_real_siphash_edges: at 20 edge bits, with keys from proof 1's mining hash
    /// and nonce 0, these nonces form a merged-namespace "cycle" (xor0 == xor1 != 0) the bipartite verifier rejects.
    static let forgery20Nonces: [UInt64] = [
        2639, 54718, 70105, 104_621, 165_067, 196_341, 198_745, 231_199, 250_304, 252_996, 255_780, 262_799, 303_410,
        321_340, 485_499, 509_862, 510_657, 520_785, 555_257, 559_871, 592_568, 596_753, 616_176, 668_113, 723_720,
        730_138, 735_058, 735_491, 737_532, 760_160, 773_657, 782_417, 782_768, 798_185, 807_422, 812_990, 841_237,
        849_760, 852_242, 951_754, 971_209, 1_016_147,
    ]

    /// Graphs with a published 42-cycle at `edgeBits`, for the GPU solver check.
    static func knownGraphs(edgeBits: Int) -> [(name: String, keys: [UInt64], nonces: [UInt64], powHash: String?)] {
        switch edgeBits {
        case 19:
            return [("grin cuckaroo19 V1", grin19[0].keys, grin19[0].nonces, nil),
                    ("grin cuckaroo19 V2", grin19[1].keys, grin19[1].nonces, nil)]
        case 29:
            return [("tari mainnet proof 1", keys(miningHash: [UInt8](hex: proof1Hash)!, nonce: proof1Nonce),
                     proof1Nonces, proof1PowHash),
                    ("tari mainnet proof 2", keys(fromBytes: [UInt8](hex: keyVectors[1].2)!), proof2Nonces, nil)]
        default:
            return []
        }
    }

    /// Runs every published vector. Throws on the first mismatch.
    static func runVectors() throws -> [String] {
        func check(_ ok: Bool, _ what: @autoclosure () -> String) throws {
            if !ok { throw MinerError("cuckaroo29 vector: \(what())") }
        }
        var lines: [String] = []

        for (keys, nonce, want) in sipVectors {
            let got = siphash24(keys, nonce)
            try check(got == want, "siphash24(\(keys), \(nonce)) = \(got), want \(want)")
        }
        for (keys, nonce, want) in blockVectors {
            let got = sipblock(keys, nonce)
            try check(got == want, "siphash_block(\(keys), \(nonce)) = \(got), want \(want)")
        }
        lines.append("siphash-2-4 (4) and siphash_block (3) match tari siphash.rs")

        for (hash, nonce, want) in keyVectors {
            let got = keyBytes(miningHash: [UInt8](hex: hash)!, nonce: nonce).hex
            try check(got == want, "keys(\(hash.prefix(8)), \(String(nonce, radix: 16))) = \(got), want \(want)")
        }
        let keys1 = keyBytes(miningHash: [UInt8](hex: proof1Hash)!, nonce: proof1Nonce).hex
        try check(keys1 == proof1Keys, "proof 1 keys \(keys1), want \(proof1Keys)")
        lines.append("siphash keys = blake2b-256(nonce BE || mining hash): 3 tari vectors match")

        let k1 = keys(fromBytes: [UInt8](hex: proof1Keys)!)
        let k2 = keys(fromBytes: [UInt8](hex: keyVectors[1].2)!)
        for (name, keys, nonces, edges) in [("1", k1, proof1Nonces, proof1Edges), ("2", k2, proof2Nonces, proof2Edges)] {
            for (n, nonce) in nonces.enumerated() {
                let got = edge(keys, nonce, edgeBits: 29)
                try check(got == edges[n], "proof \(name) edge \(nonce) = \(got), want \(edges[n])")
            }
            if let problem = verify(keys: keys, nonces: nonces, edgeBits: 29) {
                throw MinerError("cuckaroo29 vector: tari proof \(name) rejected: \(problem)")
            }
        }
        lines.append("84 edges of 2 real tari C29 proofs match; both verify as 42-cycles")

        let packed = [UInt8](hex: proof1Packed)!
        try check(packed.count == 153, "packed proof is \(packed.count) bytes, want 153")
        let unpacked = unpack(packed, edgeBits: 29, count: 42)
        try check(unpacked == proof1Nonces, "unpacked proof 1 differs from the published nonces")
        try check(pack(proof1Nonces, edgeBits: 29) == packed, "packing proof 1 doesn't reproduce its pow_data")
        var padded = packed
        padded[152] |= 0x04
        try check(unpack(padded, edgeBits: 29, count: 42) == nil, "non-zero padding bits accepted")
        try check(pack([0, 1, 2, 3], edgeBits: 3) == [0b1000_1000, 0b0000_0110], "pack([0,1,2,3], 3 bits)")
        try check(pack([(1 << 29) - 1, 0, (1 << 29) - 1, 0], edgeBits: 29).hex == "ffffff1f000000fcffff7f00000000",
                  "pack 29-bit vector")
        let powHash = blake2b(packed)
        try check(powHash.hex == proof1PowHash, "proof 1 hash \(powHash.hex), want \(proof1PowHash)")
        lines.append("proof 1 pow_data unpacks, repacks canonically and hashes to \(proof1PowHash.prefix(16))..."
            + " (difficulty \(difficulty(hash: powHash)))")

        for (n, vector) in grin19.enumerated() {
            if let problem = verify(keys: vector.keys, nonces: vector.nonces, edgeBits: 19) {
                throw MinerError("cuckaroo29 vector: grin cuckaroo19 V\(n + 1) rejected: \(problem)")
            }
            let other = grin19[1 - n].nonces
            try check(verify(keys: vector.keys, nonces: other, edgeBits: 19) != nil, "grin V\(n + 1) keys accept V\(2 - n)")
        }
        try check(verify(keys: grin19[0].keys, nonces: [UInt64](repeating: 0, count: 42), edgeBits: 19) != nil,
                  "zero proof accepted")
        lines.append("grin cuckaroo19 V1 and V2 verify; swapped and zero proofs are rejected")

        let forgeryKeys = keys(miningHash: [UInt8](hex: proof1Hash)!, nonce: 0)
        let (uvs, problem) = endpoints(keys: forgeryKeys, nonces: forgery20Nonces, edgeBits: 20)
        try check(problem == nil, "forgery nonces rejected early: \(problem ?? "")")
        let xor0 = stride(from: 0, to: 84, by: 2).reduce(UInt64(0)) { $0 ^ uvs[$1] }
        let xor1 = stride(from: 1, to: 84, by: 2).reduce(UInt64(0)) { $0 ^ uvs[$1] }
        try check(xor0 == xor1 && xor0 != 0, "forgery edges lack the merged-namespace signature")
        let verdict = verify(keys: forgeryKeys, nonces: forgery20Nonces, edgeBits: 20)
        try check(verdict == "endpoints don't match", "forgery verdict \(verdict ?? "accepted")")
        lines.append("tari's 20-bit merged-namespace forgery is rejected by the bipartite verifier")

        try check(difficulty(hash: [UInt8](repeating: 0xFF, count: 32)) == 1, "difficulty of an all-ones hash")
        try check(difficulty(hash: [0, 0, 0, 0, 0, 0, 0, 1] + [UInt8](repeating: 0, count: 24)) == .max,
                  "difficulty of 2^192 (capped)")
        try check(difficulty(hash: [0, 0, 0, 0, 0, 0, 0, 2] + [UInt8](repeating: 0, count: 24)) == 0x7FFF_FFFF_FFFF_FFFF,
                  "difficulty of 2^193")
        return lines
    }
}
