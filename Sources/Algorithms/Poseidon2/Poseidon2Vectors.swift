import Foundation

/// Known-answer vectors, each copied from the official source named next to it.
enum Poseidon2Vectors {
    typealias R = Poseidon2Reference

    /// qp-poseidon-core src/poseidon2.rs tests: permutation outputs from p3-goldilocks with Quantus's constants.
    static let p3ZeroResult: [UInt64] = [
        0xc9bc9432e1686884, 0x03ecbab0dcdd2189, 0x5e7ac885b3dc1215, 0x6ac07513801d191f, 0xca5c593fb184dcfc, 0x414dec5f3e455287,
        0x1a17df170127ae41, 0xe7e592bd0af9b0a5, 0xc71a9b27edc66a4c, 0x2728671759ac43c2, 0xb9969c20f7f672f9, 0xc5140b586823b92f,
    ]
    static let p3SeqResult: [UInt64] = [   // input 1, 2, ..., 12
        0x7e9574e2a3d6c48b, 0x9d7bc16d282d2f2b, 0x798826626d94a498, 0x0831011bb22304c7, 0xbdccb5931fffd16c, 0xe98687714dacbefc,
        0xc6a1ed29dd75e027, 0x1aec96681d15f765, 0xc74b2c710b170a23, 0x5fb4aff45e9c24fb, 0x1fb3d228db0127eb, 0xe201a7e214b16e74,
    ]
    /// Same file: zero state after the first round's constants + S-box, then after its external layer.
    static let p3FirstSbox: [UInt64] = [
        5716687150516714629, 12606094110489894541, 7176561780833472673, 2787933693728327558, 2372134002172061930, 5020691920936401247,
        15687823912570289724, 15071980520517301340, 751173130886275522, 17086029608447879298, 4895459708442877360, 10576769927437500691,
    ]
    static let p3FirstRound: [UInt64] = [
        15870188304392300026, 5420667415882104228, 4061330223075420786, 3907156211996553271, 7220184397568305579, 6276399041015305555,
        10112551490188661599, 920706293309282174, 6439956850909369582, 10360554408705021829, 3933312188334710888, 6787120046090971660,
    ]
    /// Same file: internal and external linear layers applied to 1, 2, ..., 12.
    static let p3Internal: [UInt64] = [
        14102670999874605902, 12724564314584031161, 2820561051427350843, 16542800896675938601, 15306463738286039492, 7752500014678011478,
        6061018803481092188, 7074894295206835361, 12845226504185330854, 9784840285965170449, 9819782087245364719, 15989125545469266117,
    ]
    static let p3External: [UInt64] = [144, 156, 168, 148, 172, 184, 196, 176, 200, 212, 224, 204]

    /// HorizenLabs/poseidon2 plain_implementations: the Goldilocks t = 12 instance (RC12, MAT_DIAG12_M_1 and
    /// the paper's M4) and its kats() vector for input 0..11. Checks the permutation structure
    /// independently of Quantus's constants.
    static let horizenLabs = R.Permutation(
        m4: [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]],
        initial: [
            [0x13dcf33aba214f46, 0x30b3b654a1da6d83, 0x1fc634ada6159b56, 0x937459964dc03466, 0xedd2ef2ca7949924, 0xede9affde0e22f68,
             0x8515b9d6bac9282d, 0x6b5c07b4e9e900d8, 0x1ec66368838c8a08, 0x9042367d80d1fbab, 0x400283564a3c3799, 0x4a00be0466bca75e],
            [0x7913beee58e3817f, 0xf545e88532237d90, 0x22f8cb8736042005, 0x6f04990e247a2623, 0xfe22e87ba37c38cd, 0xd20e32c85ffe2815,
             0x117227674048fe73, 0x4e9fb7ea98a6b145, 0xe0866c232b8af08b, 0x00bbc77916884964, 0x7031c0fb990d7116, 0x240a9e87cf35108f],
            [0x2e6363a5a12244b3, 0x5e1c3787d1b5011c, 0x4132660e2a196e8b, 0x3a013b648d3d4327, 0xf79839f49888ea43, 0xfe85658ebafe1439,
             0xb6889825a14240bd, 0x578453605541382b, 0x4508cda8f6b63ce9, 0x9c3ef35848684c91, 0x0812bde23c87178c, 0xfe49638f7f722c14],
            [0x8e3f688ce885cbf5, 0xb8e110acf746a87d, 0xb4b2e8973a6dabef, 0x9e714c5da3d462ec, 0x6438f9033d3d0c15, 0x24312f7cf1a27199,
             0x23f843bb47acbf71, 0x9183f11a34be9f01, 0x839062fbb9d45dbf, 0x24b56e7e6c2e43fa, 0xe1683da61c962a72, 0xa95c63971a19bfa7],
        ],
        terminal: [
            [0xc68be7c94882a24d, 0xaf996d5d5cdaedd9, 0x9717f025e7daf6a5, 0x6436679e6e7216f4, 0x8a223d99047af267, 0xbb512e35a133ba9a,
             0xfbbf44097671aa03, 0xf04058ebf6811e61, 0x5cca84703fac7ffb, 0x9b55c7945de6469f, 0x8e05bf09808e934f, 0x2ea900de876307d7],
            [0x7748fff2b38dfb89, 0x6b99a676dd3b5d81, 0xac4bb7c627cf7c13, 0xadb6ebe5e9e2f5ba, 0x2d33378cafa24ae3, 0x1e5b73807543f8c2,
             0x09208814bfebb10f, 0x782e64b6bb5b93dd, 0xadd5a48eac90b50f, 0xadd4c54c736ea4b1, 0xd58dbb86ed817fd8, 0x6d5ed1a533f34ddd],
            [0x28686aa3e36b7cb9, 0x591abd3476689f36, 0x047d766678f13875, 0xa2a11112625f5b49, 0x21fd10a3f8304958, 0xf9b40711443b0280,
             0xd2697eb8b2bde88e, 0x3493790b51731b3f, 0x11caf9dd73764023, 0x7acfb8f72878164e, 0x744ec4db23cefc26, 0x1e00e58f422c6340],
            [0x21dd28d906a62dda, 0xf32a46ab5f465b5f, 0xbfce13201f3f7e6b, 0xf30d2e7adb5304e2, 0xecdf4ee4abad48e9, 0xf94e82182d395019,
             0x4ee52e3744d887c5, 0xa1341c7cac0083b2, 0x2302fb26c30c834a, 0xaea3c587273bf7d3, 0xf798e24961823ec7, 0x962deba3e9a2cd94],
        ],
        partial: [
            0x4adf842aa75d4316, 0xf8fbb871aa4ab4eb, 0x68e85b6eb2dd6aeb, 0x07a0b06b2d270380, 0xd94e0228bd282de4, 0x8bdd91d3250c5278,
            0x209c68b88bba778f, 0xb5e18cdab77f3877, 0xb296a3e808da93fa, 0x8370ecbda11a327e, 0x3f9075283775dad8, 0xb78095bb23c6aa84,
            0x3f36b9fe72ad4e5f, 0x69bc96780b10b553, 0x3f1d341f2eb7b881, 0x4e939e9815838818, 0xda366b3ae2a31604, 0xbc89db1e7287d509,
            0x6102f411f9ef5659, 0x58725c5e7ac1f0ab, 0x0df5856c798883e7, 0xf7bb62a8da4c961b,
        ],
        diag: R.poseidon2.diag)   // MAT_DIAG12_M_1 is the same diagonal
    static let horizenLabsKAT: [UInt64] = [
        0x01eaef96bdf1c0c1, 0x1f0d2cc525b2540c, 0x6282c1dfe1e0358d, 0xe780d721f698e1e6, 0x280c0b6f753d833b, 0x1b942dd5023156ab,
        0x43f0df3fcccb8398, 0xe8e8190585489025, 0x56bdbf72f77ada22, 0x7911c32bf9dcd705, 0xec467926508fbe67, 0x6a50450ddf85a6ed,
    ]

    /// qp-poseidon-core src/lib.rs test_known_value_hashes: hash_bytes (injective encoding, first squeeze).
    static let hashBytes: [([UInt8], String)] = [
        ([], "4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86"),
        ([0], "8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad"),
        ([0, 0], "3e6ee24fb61a22f4d825b72fc8ebd359e3b3b9566e246c71c3e450ebe3262f9c"),
        ([0, 0, 0], "34f4338a6f1b671062a3ac00b37ca05a47b43e16e589ccaa5b063416ba42356b"),
        ([UInt8](repeating: 0, count: 4), "7bac8c6bc49b0b750f2ce0912b815a2cb4ae20c75ac430850257882d9d321afa"),
        ([UInt8](repeating: 0, count: 5), "c95cfddb573adf4070b3d7c8d2dfbbee48b4b973d80cbda2b458abe7bb6f0def"),
        ([UInt8](repeating: 0, count: 6), "a4dc08d0a8c5ea44007462fe1fd8e45962d4ea85c420eab4140fbb30b5b5e111"),
        ([UInt8](repeating: 0, count: 7), "b01975012df91d9f9f040c34655f23f3ec1f6d1738d85679e9848143756637c9"),
        ([UInt8](repeating: 0, count: 8), "eacd9e48d2e968131e48c8e69f2a211cc06c7778db6c5467348b45418fc7f585"),
        ([UInt8](repeating: 0, count: 9), "00df670e8ec0751d3fb9b5f0281d0af9a7a82f62ad35a21247a9d6117daec151"),
        ([UInt8](repeating: 0, count: 14), "d6182896f274c5d9640972e2bf2a5e893e516a21adfdd8ebd39969128d619934"),
        ([UInt8](repeating: 0, count: 15), "15fc2f3c3bc51c96797b889d4fecfcd3535b959f510c007598a87f099e356303"),
        ([0, 0, 0, 1], "6ffff0c97262139567c426e916c1fd70c924010153c366bb2a8957ea89902942"),
        ([1, 2, 3, 4, 5, 6, 7, 8], "131020b2e74819343f8568258ae2e9717e9b2253d57baabab78a518bc7499a8b"),
        ([UInt8](repeating: 255, count: 32), "41260a4322e97dc3dda2b5f70b5ffb1b43071ad5510e101f34209721042c0987"),
        (Array("hello world".utf8), "fd1f5d7d4701c25bbdd5dd6e3be6abb474fffbaa402f814dce95f8283abbf3e7"),
        ((0 ..< 32).map { UInt8($0) }, "36884f9093be80632397f5736dce2fece627a4182daf3cdbf8bf12c8e3e02668"),
        ((0 ..< 64).map { UInt8($0) }, "dd0d06fbe4e7575d0eeac53706482cbbe592e269a35bcd5591a495814371724e"),
    ]

    /// Same file, test_hash_twice_vectors: hash_to_bytes(hash_to_felts(felts)).
    static let hashTwice: [([UInt64], String)] = [
        ([], "b8a2f205ad2e2682ab8af6e49946a597920a24d916ca1139b6fce113c207365b"),
        ([0], "6e962ae00104d1c8907142439156035ad71242caab590a74ba8c9850df03ff11"),
        ([1], "50be997dba65a402610d93f8fe853b0974fc72e4605effd5603deb900667e497"),
        ([1, 2, 3, 4], "153624f84074a4503ea9139d64ad54da77849d83eb0e6a8e1f839bfe31c222b5"),
        ([1, 2, 3, 4, 5, 6, 7, 8], "958293c7f14ec2ef872955b510eee16f041217f37f8db0c0287fbe182afde6af"),
    ]

    /// quantus-miner crates/pow-core/src/lib.rs NONCE_HASH_KVS: get_nonce_hash golden vectors plus the
    /// sponge midstate after the header and the nonce's high 32 bytes.
    struct NonceVector {
        let header: String
        let nonce: String
        let hash: String
        let mid: [UInt64]
    }

    static let nonceHash: [NonceVector] = [
        NonceVector(
            header: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            hash: "8e64e3d8e0f38f882e8501f9e525df0a95d2e91e9cfc32c9248d756fb07780e2f8fdca2c5a54441e6fcd8d774a5f6aae72f36d1c76bc19f691a0d4f6c607e8cc",
            mid: [0x8646d336b5a0fccd, 0x818ca59548916345, 0x49475e8bc9c928bc, 0xc469163bcdc4900b, 0xe4421fafacd59087, 0x633f49b998698d66,
                  0x4a9067e3883e76da, 0x193039e85ea14472, 0x203d2d3ee6a8eba8, 0xef5b9ce39bcff072, 0xc16a3c8dd5680003, 0xd77c52ab5bf7cf1f]),
        NonceVector(
            header: "0101010101010101010101010101010101010101010101010101010101010101",
            nonce: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            hash: "e4ef79db80b642a093d7e38e6a6daac7ec1cca7293ddbe3710b4e6781be4add0b93f7e3440626df5bb23b757436787ba8d3fd0a2652e387f8af5bd8a5cc2ce2f",
            mid: [0x788cf743676a5c85, 0xdce1d727e1189b53, 0x36e0e019f5a0bf3a, 0x806487dd9c3bf83f, 0xcb6d7300de1ab5fe, 0x7dbe191fa64fc6b7,
                  0x95dedc7fe99861be, 0xb1a3885303f7467d, 0x891eb002a34a0f17, 0x4be4cf057a87208a, 0xe9113e7dc541745f, 0xfaeda908097d00f1]),
        NonceVector(
            header: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            nonce: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234567890abcdef",
            hash: "7f6c410ce62e7fc54811ad3b8b92664ac0f8b1d2cd6eb163129251146e7ee34d27794aaae1b31eaaeb98ab835bae6a2b9ac4ad6f08c95903e1423f0b865816ff",
            mid: [0xf6fc848ab2dddc18, 0xfd88d1f0ccda99fe, 0x27cfa43b8ab9947a, 0x6a505b37f02183d3, 0x5f98f1d3524fb0c6, 0xd6de4efd98793e2e,
                  0xf3f205bd1e4d4526, 0xc0c9046201e91dd6, 0xcd2d28eef32b18de, 0xa303ecbc8e98000c, 0x3db245e7738f3aca, 0xbc55f7553023863e]),
        NonceVector(
            header: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            nonce: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff",
            hash: "822f70999ee517f610b51bbb79ba88bfbb19cb77b316df25d8aeb4c2682673555e9fc6a588ee96dcce4ff0d2b8d97f4aa89d0f46c97f9027b386d42b14be5100",
            mid: [0xd1fe93daa1f07409, 0x0ea440f2b57a0ecf, 0x3b7a1f3cb2d48e39, 0x43a5a1255658d1b2, 0xebe00ad8f0fe28c0, 0xb5618e7c6d6072d1,
                  0x158b7b19f80ec62c, 0x329a91c8de5575c2, 0xd1637d851a474212, 0x2d927735708f3b7d, 0x6219c7cf8ef5af51, 0x802028c39ccd8f13]),
        NonceVector(
            header: "0707070707070707070707070707070707070707070707070707070707070707",
            nonce: "00000000000000000000000000000000000000000deadbeefcafe000000000000000000000000000000000000000000000000000000000001234567890abcdef",
            hash: "eab81cdb33db293aef7e1f10f85cb08d17bc197c284d46a25d9dc57cdb7ba878adf3f5c354318121876795aab08c0941afda21d835383faa2f139c26be31a30a",
            mid: [0x41885398f5b05a0d, 0xb7f17cee3f70d242, 0x307aecc5bca54c7e, 0xb74164c0d6de7e91, 0x0c0a9b27281c8181, 0xd84ddf12fdddf0ee,
                  0x88f8cdf552c0a15e, 0x88da4cfbfbf92d22, 0x8c344261349149db, 0x0c0fd0d6a8444652, 0x7a57b00736d58568, 0x9ad40597f4fe2abc]),
    ]

    static func bytes(_ hex: String) throws -> [UInt8] {
        guard let b = [UInt8](hex: hex) else { throw MinerError("bad hex in a vector: \(hex)") }
        return b
    }

    static func expect(_ got: [UInt64], _ want: [UInt64], _ what: String) throws {
        guard got == want else { throw MinerError("\(what): got \(R.hex(got)), want \(R.hex(want))") }
    }

    /// Runs every vector against the CPU reference; one line per group, throws on the first mismatch.
    static func run() throws -> [String] {
        var lines: [String] = []
        let seq = (1 ... 12).map { UInt64($0) }

        // 1. The permutation and its parts against p3-goldilocks outputs (Quantus's tests).
        try expect([0, 1, 2, 5, 0xFFFF_FFFF].map(R.sbox), [0, 1, 128, 78125, 0xFFFF_FFFF], "S-box x^7")
        var s = seq
        R.poseidon2.externalLayer(&s)
        try expect(s, p3External, "external layer on 1..12")
        s = seq
        R.poseidon2.internalLayer(&s)
        try expect(s, p3Internal, "internal layer on 1..12")
        s = [UInt64](repeating: 0, count: 12)
        R.poseidon2.externalLayer(&s)
        for i in 0 ..< 12 { s[i] = R.sbox(R.add(s[i], R.poseidon2.initial[0][i])) }
        try expect(s, p3FirstSbox, "zero state, round 1 S-box")
        R.poseidon2.externalLayer(&s)
        try expect(s, p3FirstRound, "zero state, round 1")
        s = [UInt64](repeating: 0, count: 12)
        R.poseidon2.permute(&s)
        try expect(s, p3ZeroResult, "permutation of zero")
        s = seq
        R.poseidon2.permute(&s)
        try expect(s, p3SeqResult, "permutation of 1..12")
        lines.append("permutation: zero and 1..12 inputs, first round, both linear layers, S-box = p3-goldilocks values in qp-poseidon tests")

        // 2. The HorizenLabs reference instance (same structure, its own constants and M4).
        s = (0 ..< 12).map { UInt64($0) }
        horizenLabs.permute(&s)
        try expect(s, horizenLabsKAT, "HorizenLabs Goldilocks t=12 KAT")
        lines.append("HorizenLabs poseidon2 Goldilocks t=12 kats(): match (same round structure, HL constants and M4)")

        // 3. The sponge: byte encoding, padding and digest serialization.
        for (input, want) in hashBytes {
            let got = R.hashBytes(input).hex
            guard got == want else { throw MinerError("hash_bytes(\(input.hex)): got \(got), want \(want)") }
        }
        for (felts, want) in hashTwice {
            let got = R.digestBytes(R.hashToFelts(R.hashToFelts(felts))).hex
            guard got == want else { throw MinerError("hash_twice(\(felts)): got \(got), want \(want)") }
        }
        lines.append("sponge: \(hashBytes.count) hash_bytes + \(hashTwice.count) hash_twice vectors from qp-poseidon-core match")

        // 4. The proof-of-work hash itself, from the official miner's golden vectors.
        for (n, v) in nonceHash.enumerated() {
            let header = try bytes(v.header), nonce = try bytes(v.nonce)
            guard header.count == 32, nonce.count == 64 else { throw MinerError("nonce vector \(n): bad lengths") }
            let got = R.nonceHash(header: header, nonce: nonce).hex
            guard got == v.hash else { throw MinerError("get_nonce_hash vector \(n): got \(got), want \(v.hash)") }
            try expect(R.midstate(header: header, nonceHigh: Array(nonce[0 ..< 32])), v.mid, "midstate vector \(n)")
        }
        lines.append("get_nonce_hash: \(nonceHash.count) quantus-miner golden vectors (512-bit hash + midstate) match")

        // 5. Difficulty to target: U512::MAX / d, compared with hash < target.
        try expect(R.target(difficulty: 1), [UInt64](repeating: .max, count: 8), "target(1)")
        try expect(R.target(difficulty: 256), [0x00ff_ffff_ffff_ffff] + [UInt64](repeating: .max, count: 7), "target(256)")
        let h = R.words(try bytes(nonceHash[0].hash))
        guard R.less(h, R.plusOne(h)), !R.less(h, h) else { throw MinerError("U512 compare") }
        lines.append("target = U512::MAX / difficulty, valid iff hash < target (strict): checked")
        return lines
    }
}
