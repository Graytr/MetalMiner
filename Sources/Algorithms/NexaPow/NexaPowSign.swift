import Foundation

/// Schnorr signing, NexaPow and the known-answer vectors for the CPU reference (see NexaPowReference.swift).
extension NexaPowReference {
    static let schnorrAlgo16 = Array("Schnorr+SHA256  ".utf8)

    /// libsecp256k1 nonce_function_rfc6979: HMAC-DRBG keyed by key32 || msg32 || [data32] || [algo16].
    /// msg32 is used as-is (not reduced mod n), as in the Nexa copy of secp256k1.c.
    static func rfc6979Nonce(key32: [UInt8], msg32: [UInt8], algo16: [UInt8]?, data32: [UInt8]?, counter: Int) -> [UInt8] {
        let keydata = key32 + msg32 + (data32 ?? []) + (algo16 ?? [])
        var v = [UInt8](repeating: 0x01, count: 32)
        var k = [UInt8](repeating: 0x00, count: 32)
        k = hmacSHA256(key: k, v + [0x00] + keydata)
        v = hmacSHA256(key: k, v)
        k = hmacSHA256(key: k, v + [0x01] + keydata)
        v = hmacSHA256(key: k, v)
        var retry = false
        for _ in 0 ... counter {
            if retry {
                k = hmacSHA256(key: k, v + [0x00])
                v = hmacSHA256(key: k, v)
            }
            v = hmacSHA256(key: k, v)
            retry = true
        }
        return v
    }

    /// secp256k1_schnorr_sign with nonce_function_rfc6979 and no extra data (what CKey::SignSchnorr does):
    /// k from RFC6979 (retried while k is 0 or >= n), R = kG, negate k unless jacobi(R.y) = 1,
    /// e = sha256(R.x || compressed(P) || m), s = k + e x. Returns R.x || s, or nil when the key is invalid
    /// or e overflows / is zero (the node fails the signature there).
    static func schnorrSign(msg32: [UInt8], seckey32: [UInt8]) -> [UInt8]? {
        let x = value(be: seckey32)
        guard x != zero, compare(x, n.m) < 0 else { return nil }
        guard let pub = affine(multiply(x, G)) else { return nil }
        var counter = 0
        var k = zero
        repeat {
            k = value(be: rfc6979Nonce(key32: seckey32, msg32: msg32, algo16: schnorrAlgo16, data32: nil, counter: counter))
            counter += 1
        } while k == zero || compare(k, n.m) >= 0
        guard let r = affine(multiply(k, G)) else { return nil }
        if !isQuadraticResidue(r.y) { k = sub(n.m, k).0 }
        let rx = bytesBE(r.x)
        let e = value(be: sha256(rx + compressed(pub) + msg32))
        guard e != zero, compare(e, n.m) < 0 else { return nil }
        let s = modAdd(modMul(e, x, n), k, n)
        return rx + bytesBE(s)
    }

    /// Bitcoin compact-size prefix for a byte vector of `count` bytes (nonces are at most 16 bytes).
    static func compactSize(_ count: Int) -> [UInt8] {
        precondition(count < 253)
        return [UInt8(count)]
    }

    /// GetMiningHash: sha256d(headerCommitment || compactSize(nonce) || nonce), all in internal byte order.
    static func miningHash(commitment: [UInt8], nonce: [UInt8]) -> [UInt8] {
        sha256d(commitment + compactSize(nonce.count) + nonce)
    }

    struct Result {
        var miningHash: [UInt8]
        var h1: [UInt8]
        /// nil when miningHash is not a valid secret key (or e overflows): the nonce can't win.
        var signature: [UInt8]?
        var powHash: [UInt8]?
    }

    /// CheckProofOfWork with params.powAlgorithm == 1. `prevHash` is only set for Tailstorm subblocks
    /// (minerData version = subblock), which mainnet doesn't produce; ordinary blocks pass a null hash.
    static func nexaPow(commitment: [UInt8], nonce: [UInt8], prevHash: [UInt8]? = nil) -> Result {
        let mining = miningHash(commitment: commitment, nonce: nonce)
        let h1 = prevHash.map { sha256(sha256(mining + $0)) } ?? sha256(mining)
        let signature = schnorrSign(msg32: h1, seckey32: mining)
        return Result(miningHash: mining, h1: h1, signature: signature, powHash: signature.map { sha256($0) })
    }

    /// UintToArith256(powHash) <= target: the hash bytes are a little-endian number.
    static func meetsTarget(_ powHash: [UInt8], _ target: U256) -> Bool {
        compare(value(be: powHash.reversed()), target) <= 0
    }

    /// arith_uint256::SetCompact; nil for negative or overflowing encodings.
    static func target(compact: UInt32) -> U256? {
        let size = Int(compact >> 24)
        var word = UInt64(compact & 0x007f_ffff)
        if word != 0 && compact & 0x0080_0000 != 0 { return nil }
        if word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)) { return nil }
        if size <= 3 {
            word >>= UInt64(8 * (3 - size))
            return U256(word, 0, 0, 0)
        }
        var bytes = [UInt8](repeating: 0, count: 32)   // big-endian
        for i in 0 ..< 3 {
            let position = 31 - (size - 3) - i
            if position >= 0 { bytes[position] = UInt8(truncatingIfNeeded: word >> UInt64(8 * i)) }
        }
        return value(be: bytes)
    }

    /// GetMiningHeaderCommitment, for the pool side (stratum miners get the commitment from the pool).
    /// Hash fields are 32 bytes in internal order; integers are little-endian; vectors carry a compact size.
    static func miningHeaderCommitment(hashPrevBlock: [UInt8], nBits: UInt32, hashAncestor: [UInt8], hashTxFilter: [UInt8],
                                       hashMerkleRoot: [UInt8], nTime: UInt32, height: UInt64, chainWork: [UInt8],
                                       size: UInt64, txCount: UInt64, feePoolAmt: UInt64,
                                       utxoCommitment: [UInt8], minerData: [UInt8]) -> [UInt8] {
        var mini = hashPrevBlock
        mini.appendLE(nBits)
        var ext = hashAncestor + hashTxFilter + hashMerkleRoot
        ext.appendLE(nTime)
        ext.appendLE(height)
        ext += chainWork
        ext.appendLE(size)
        ext.appendLE(txCount)
        ext.appendLE(feePoolAmt)
        ext += compactSize(utxoCommitment.count) + utxoCommitment + compactSize(minerData.count) + minerData
        return sha256(sha256(mini) + sha256(ext))
    }

    // MARK: Known-answer vectors

    /// WIF (base58check) to the 32-byte secret.
    static func secret(wif: String) -> [UInt8]? {
        let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        var number: [UInt8] = []   // big-endian base 256
        for ch in wif {
            guard let digit = alphabet.firstIndex(of: ch) else { return nil }
            var carry = digit
            for i in (0 ..< number.count).reversed() {
                carry += Int(number[i]) * 58
                number[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                number.insert(UInt8(carry & 0xff), at: 0)
                carry >>= 8
            }
        }
        let bytes = [UInt8](repeating: 0, count: wif.prefix(while: { $0 == "1" }).count) + number
        guard bytes.count >= 37 else { return nil }
        let payload = Array(bytes.dropLast(4))
        guard Array(sha256d(payload).prefix(4)) == Array(bytes.suffix(4)) else { return nil }
        return Array(payload[1 ... 32])
    }

    /// src/test/key_tests.cpp (key_test1, "test deterministic signing expected values"):
    /// SignSchnorr(Hash("Very deterministic message")) with strSecret1 and strSecret2.
    static let keyVectors: [(wif: String, signature: String)] = [
        ("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj",
         "2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d0717571846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce"),
        ("5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3",
         "e7167ae0afbba6019b4c7fcfe6de79165d555e8295bd72da1b8aa1a5b54305880517cace1bcb0cb515e2eeaffd49f1e4dd49fd72826b4b1573c84da49a38405d"),
    ]

    /// spec.nexa.org/mining/echelon-protocol ("Full hashing examples"). Hashes are printed as uint256
    /// hex (byte-reversed); the 16-byte nonce and the signature are printed as raw bytes.
    static let powVectors: [(commitment: String, nonce: String, miningHash: String, h1: String, signature: String, powHash: String)] = [
        ("0a4ac49b2d02e3c8d12c7093255ba7c49624f9c374d9f1c2f8e37c58705e74b0", "10000000000000001182dc5800000000",
         "7077c3549e088001ff681c2291bbc171f6ea681b5bc79bca9f2e0f563ad3dfef",
         "f97e4711d32f29f4f9f3aa254290eaf486330b3b43507cc03ba93b596c6cce36",
         "93bb5bd98bb9d0817c5594782d4648a995e76755a3c94fdd96673115a06b8483efe485e73c1e4732ce9c34ef6891e7f25ff7c080aacbf71660bf782b067bc4f1",
         "00000042cbc240375242e14641488a0e2dca7b54458a2cea23dc1d2c178bb188"),
        ("0a4ac49b2d02e3c8d12c7093255ba7c49624f9c374d9f1c2f8e37c58705e74b0", "1000000000000000b787915d00000000",
         "5cddd556e7972ee8b3e4ce01f954336cbb223813c1f01c768f299b82f20a0ea9",
         "6c55ec4a361007edaf6561e20a2eccfb51572309f66bf7b04aea315fadc039f9",
         "fc1894a100e6b33d19abac5289403b4c942d75d061b5453904be740681526cae30ed3a59f1a9d3ca165151ddb1ca3069de832cd5cc5fc95a7339f058f1fd155b",
         "0000005f0b59e110863566e77d85e1b4fc713754e5c75f8fc3df44133866a669"),
    ]

    static func reversedHex(_ hex: String) -> [UInt8] { Array([UInt8](hex: hex)!.reversed()) }

    /// Runs every vector; throws on the first mismatch.
    static func runVectors() throws -> [String] {
        var lines: [String] = []
        guard sha256(Array("abc".utf8)).hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" else {
            throw MinerError("nexapow: SHA-256(\"abc\") is wrong")
        }
        guard isOnCurve(G), affine(multiply(n.m, G)) == nil,
              affine(multiply(sub(n.m, one).0, G)) == Affine(x: G.x, y: sub(p.m, G.y).0) else {
            throw MinerError("nexapow: secp256k1 sanity checks failed (G on curve, nG = O, (n-1)G = -G)")
        }
        guard let powLimit = target(compact: 503_382_016), powLimit == U256(0, 0, 0, 1 << 40) else {
            throw MinerError("nexapow: SetCompact(503382016) should be 2^232 (mainnet powLimit)")
        }
        lines.append("SHA-256 \"abc\"; G on curve, nG = O, (n-1)G = -G; mainnet powLimit 0x1e010000 = 2^232")

        let message = sha256d(Array("Very deterministic message".utf8))
        for (i, v) in keyVectors.enumerated() {
            guard let key = secret(wif: v.wif) else { throw MinerError("nexapow: can't decode WIF \(v.wif)") }
            let sig = schnorrSign(msg32: message, seckey32: key)
            guard sig?.hex == v.signature else {
                throw MinerError("nexapow: key_tests Schnorr vector \(i + 1): got \(sig?.hex ?? "nil")")
            }
        }
        lines.append("key_tests.cpp deterministic SignSchnorr: \(keyVectors.count) signatures match")

        for (i, v) in powVectors.enumerated() {
            let result = nexaPow(commitment: reversedHex(v.commitment), nonce: [UInt8](hex: v.nonce)!)
            let got = (Array(result.miningHash.reversed()).hex, Array(result.h1.reversed()).hex,
                       result.signature?.hex ?? "nil", result.powHash.map { Array($0.reversed()).hex } ?? "nil")
            guard got.0 == v.miningHash, got.1 == v.h1, got.2 == v.signature, got.3 == v.powHash else {
                throw MinerError("nexapow: Echelon vector \(i + 1): mining \(got.0) h1 \(got.1) sig \(got.2) pow \(got.3)")
            }
            lines.append("Echelon spec vector \(i + 1): miningHash, h1, signature and powHash \(v.powHash.prefix(16))... match")
        }
        return lines
    }
}
