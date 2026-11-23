import Dispatch
import Foundation

/// CPU reference for XelisHash, written from github.com/xelis-project/xelis-hash (src/v2.rs,
/// src/v3.rs) and the BLAKE3, ChaCha (RFC 8439) and AES (FIPS-197) specifications.
/// v3 is the mainnet proof of work; v2 is kept only as a second witness for the shared stages 1 and 4.
enum XelisHashReference {

    // MARK: - Helpers

    @inline(__always) static func rotl(_ x: UInt64, _ n: Int) -> UInt64 {
        let s = UInt64(n & 63)
        return s == 0 ? x : (x << s) | (x >> (64 - s))
    }

    @inline(__always) static func rotr(_ x: UInt64, _ n: Int) -> UInt64 {
        let s = UInt64(n & 63)
        return s == 0 ? x : (x >> s) | (x << (64 - s))
    }

    @inline(__always) static func combine(_ high: UInt64, _ low: UInt64) -> UInt128 {
        UInt128(high) << 64 | UInt128(low)
    }

    static func be64(_ value: UInt64) -> [UInt8] {
        (0 ..< 8).map { UInt8(truncatingIfNeeded: value >> (56 - 8 * UInt64($0))) }
    }

    /// Writes `nonce` big-endian at bytes 40..<48 of a 112-byte MinerWork.
    static func setNonce(_ work: inout [UInt8], _ nonce: UInt64) {
        work.replaceSubrange(40 ..< 48, with: be64(nonce))
    }

    static func murmurhash3(_ seed: UInt64) -> UInt64 {
        var s = seed
        s ^= s >> 55
        s = s &* 0xff51afd7ed558ccd
        s ^= s >> 32
        s = s &* 0xc4ceb9fe1a85ec53
        s ^= s >> 15
        return s
    }

    /// floor((2^256 - 1) / difficulty) as 32 big-endian bytes (xelis_common/src/difficulty.rs).
    static func target(difficulty: UInt64) -> [UInt8] {
        var remainder: UInt64 = 0
        var out: [UInt8] = []
        for _ in 0 ..< 4 {
            let (q, r) = difficulty.dividingFullWidth((high: remainder, low: UInt64.max))
            remainder = r
            out += be64(q)
        }
        return out
    }

    /// The PoW check: the hash read as a big-endian 256-bit number must be <= target.
    static func meets(_ hash: [UInt8], _ target: [UInt8]) -> Bool {
        !target.lexicographicallyPrecedes(hash)
    }

    // MARK: - BLAKE3 (plain hash mode)

    enum Blake3 {
        static let iv = SIMD8<UInt32>(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
        static let chunkStart: UInt32 = 1
        static let chunkEnd: UInt32 = 2
        static let parent: UInt32 = 4
        static let root: UInt32 = 8
        static let permutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

        @inline(__always) private static func rotr32(_ x: UInt32, _ n: UInt32) -> UInt32 {
            (x >> n) | (x << (32 - n))
        }

        @inline(__always) private static func g(_ s: inout SIMD16<UInt32>, _ a: Int, _ b: Int, _ c: Int, _ d: Int,
                                                _ x: UInt32, _ y: UInt32) {
            s[a] = s[a] &+ s[b] &+ x
            s[d] = rotr32(s[d] ^ s[a], 16)
            s[c] = s[c] &+ s[d]
            s[b] = rotr32(s[b] ^ s[c], 12)
            s[a] = s[a] &+ s[b] &+ y
            s[d] = rotr32(s[d] ^ s[a], 8)
            s[c] = s[c] &+ s[d]
            s[b] = rotr32(s[b] ^ s[c], 7)
        }

        static func compress(_ cv: SIMD8<UInt32>, _ block: SIMD16<UInt32>, counter: UInt64, length: UInt32,
                             flags: UInt32) -> SIMD16<UInt32> {
            var s = SIMD16<UInt32>(lowHalf: cv,
                                   highHalf: SIMD8<UInt32>(iv[0], iv[1], iv[2], iv[3],
                                                           UInt32(truncatingIfNeeded: counter),
                                                           UInt32(truncatingIfNeeded: counter >> 32), length, flags))
            var m = block
            for round in 0 ..< 7 {
                g(&s, 0, 4, 8, 12, m[0], m[1])
                g(&s, 1, 5, 9, 13, m[2], m[3])
                g(&s, 2, 6, 10, 14, m[4], m[5])
                g(&s, 3, 7, 11, 15, m[6], m[7])
                g(&s, 0, 5, 10, 15, m[8], m[9])
                g(&s, 1, 6, 11, 12, m[10], m[11])
                g(&s, 2, 7, 8, 13, m[12], m[13])
                g(&s, 3, 4, 9, 14, m[14], m[15])
                if round < 6 {
                    var p = SIMD16<UInt32>()
                    for i in 0 ..< 16 { p[i] = m[permutation[i]] }
                    m = p
                }
            }
            return SIMD16<UInt32>(lowHalf: s.lowHalf ^ s.highHalf, highHalf: s.highHalf ^ cv)
        }

        struct Output {
            var cv: SIMD8<UInt32>
            var block: SIMD16<UInt32>
            var counter: UInt64
            var length: UInt32
            var flags: UInt32

            var chainingValue: SIMD8<UInt32> {
                Blake3.compress(cv, block, counter: counter, length: length, flags: flags).lowHalf
            }

            var rootHash: [UInt8] {
                let words = Blake3.compress(cv, block, counter: 0, length: length, flags: flags | Blake3.root).lowHalf
                var out: [UInt8] = []
                for i in 0 ..< 8 { out.appendLE(words[i]) }
                return out
            }
        }

        private static func words(_ data: UnsafeRawBufferPointer, _ offset: Int, _ count: Int) -> SIMD16<UInt32> {
            var m = SIMD16<UInt32>()
            if count == 64 {
                for i in 0 ..< 16 {
                    m[i] = UInt32(littleEndian: data.loadUnaligned(fromByteOffset: offset + 4 * i, as: UInt32.self))
                }
            } else {
                for i in 0 ..< count { m[i / 4] |= UInt32(data[offset + i]) << (8 * UInt32(i % 4)) }
            }
            return m
        }

        private static func chunkOutput(_ data: UnsafeRawBufferPointer, _ start: Int, _ length: Int,
                                        _ counter: UInt64) -> Output {
            var cv = iv
            let blocks = max(1, (length + 63) / 64)
            for b in 0 ..< blocks - 1 {
                cv = compress(cv, words(data, start + 64 * b, 64), counter: counter, length: 64,
                              flags: b == 0 ? chunkStart : 0).lowHalf
            }
            let last = length - 64 * (blocks - 1)
            return Output(cv: cv, block: words(data, start + 64 * (blocks - 1), last), counter: counter,
                          length: UInt32(last), flags: (blocks == 1 ? chunkStart : 0) | chunkEnd)
        }

        private static func parentOutput(_ left: SIMD8<UInt32>, _ right: SIMD8<UInt32>) -> Output {
            Output(cv: iv, block: SIMD16<UInt32>(lowHalf: left, highHalf: right), counter: 0, length: 64, flags: parent)
        }

        /// Incremental tree hashing with a chaining-value stack, as in the BLAKE3 reference implementation.
        static func hash(_ data: UnsafeRawBufferPointer) -> [UInt8] {
            let chunks = max(1, (data.count + 1023) / 1024)
            var stack: [SIMD8<UInt32>] = []
            for index in 0 ..< chunks - 1 {
                var cv = chunkOutput(data, 1024 * index, 1024, UInt64(index)).chainingValue
                var total = index + 1
                while total & 1 == 0 {
                    cv = parentOutput(stack.removeLast(), cv).chainingValue
                    total >>= 1
                }
                stack.append(cv)
            }
            var output = chunkOutput(data, 1024 * (chunks - 1), data.count - 1024 * (chunks - 1), UInt64(chunks - 1))
            while let left = stack.popLast() {
                output = parentOutput(left, output.chainingValue)
            }
            return output.rootHash
        }

        static func hash(_ bytes: [UInt8]) -> [UInt8] {
            bytes.withUnsafeBytes { hash($0) }
        }
    }

    // MARK: - ChaCha8 (RFC 8439 layout: 32-bit block counter from 0, 96-bit nonce; 8 rounds)

    enum ChaCha8 {
        @inline(__always) private static func rotl32(_ x: UInt32, _ n: UInt32) -> UInt32 {
            (x << n) | (x >> (32 - n))
        }

        @inline(__always) private static func qr(_ s: inout SIMD16<UInt32>, _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            s[a] = s[a] &+ s[b]; s[d] = rotl32(s[d] ^ s[a], 16)
            s[c] = s[c] &+ s[d]; s[b] = rotl32(s[b] ^ s[c], 12)
            s[a] = s[a] &+ s[b]; s[d] = rotl32(s[d] ^ s[a], 8)
            s[c] = s[c] &+ s[d]; s[b] = rotl32(s[b] ^ s[c], 7)
        }

        static func block(key: SIMD8<UInt32>, counter: UInt32, nonce: SIMD4<UInt32>) -> SIMD16<UInt32> {
            let initial = SIMD16<UInt32>(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                         key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                                         counter, nonce[0], nonce[1], nonce[2])
            var s = initial
            for _ in 0 ..< 4 {
                qr(&s, 0, 4, 8, 12); qr(&s, 1, 5, 9, 13); qr(&s, 2, 6, 10, 14); qr(&s, 3, 7, 11, 15)
                qr(&s, 0, 5, 10, 15); qr(&s, 1, 6, 11, 12); qr(&s, 2, 7, 8, 13); qr(&s, 3, 4, 9, 14)
            }
            return s &+ initial
        }

        /// XORs the keystream into `count` bytes at `p` (count a multiple of 64 here).
        static func apply(key: [UInt8], nonce: [UInt8], to p: UnsafeMutableRawPointer, count: Int) {
            let k = SIMD8<UInt32>((0 ..< 8).map { key.le32(at: 4 * $0) })
            let n = SIMD4<UInt32>(nonce.le32(at: 0), nonce.le32(at: 4), nonce.le32(at: 8), 0)
            var counter: UInt32 = 0
            var offset = 0
            while offset < count {
                let ks = block(key: k, counter: counter, nonce: n)
                if count - offset >= 64 {
                    for i in 0 ..< 16 {
                        let w = p.loadUnaligned(fromByteOffset: offset + 4 * i, as: UInt32.self)
                        p.storeBytes(of: w ^ ks[i].littleEndian, toByteOffset: offset + 4 * i, as: UInt32.self)
                    }
                } else {
                    for i in 0 ..< count - offset {
                        let byte = UInt8(truncatingIfNeeded: ks[i / 4] >> (8 * UInt32(i % 4)))
                        let old = p.load(fromByteOffset: offset + i, as: UInt8.self)
                        p.storeBytes(of: old ^ byte, toByteOffset: offset + i, as: UInt8.self)
                    }
                }
                offset += 64
                counter &+= 1
            }
        }
    }

    // MARK: - One AES encryption round (aes::hazmat::cipher_round = _mm_aesenc_si128)

    enum AES {
        static let sbox: [UInt8] = {
            func mul(_ x: UInt8, _ y: UInt8) -> UInt8 {
                var a = x, b = y, p: UInt8 = 0
                for _ in 0 ..< 8 {
                    if b & 1 != 0 { p ^= a }
                    let high = a & 0x80
                    a <<= 1
                    if high != 0 { a ^= 0x1B }
                    b >>= 1
                }
                return p
            }
            var box = [UInt8](repeating: 0, count: 256)
            for x in 0 ..< 256 {
                var inverse: UInt8 = 0
                if x != 0 {
                    for y in 1 ..< 256 where mul(UInt8(x), UInt8(y)) == 1 {
                        inverse = UInt8(y)
                        break
                    }
                }
                var s = inverse
                for k in 1 ... 4 { s ^= (inverse << UInt8(k)) | (inverse >> UInt8(8 - k)) }
                box[x] = s ^ 0x63
            }
            return box
        }()

        @inline(__always) static func xtime(_ x: UInt8) -> UInt8 { (x << 1) ^ (x & 0x80 != 0 ? 0x1B : 0) }

        /// SubBytes, ShiftRows, MixColumns, AddRoundKey on a 16-byte block (state[r][c] = block[4c + r]).
        static func round(_ block: [UInt8], key: [UInt8]) -> [UInt8] {
            var s = [UInt8](repeating: 0, count: 16)
            for c in 0 ..< 4 {
                for r in 0 ..< 4 { s[4 * c + r] = sbox[Int(block[4 * ((c + r) % 4) + r])] }
            }
            var out = [UInt8](repeating: 0, count: 16)
            for c in 0 ..< 4 {
                let a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3]
                out[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
                out[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
                out[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
                out[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
            }
            for i in 0 ..< 16 { out[i] ^= key[i] }
            return out
        }

        /// The block is lo (bytes 0..7, LE) || hi (bytes 8..15, LE); returns the two LE halves.
        static func round(lo: UInt64, hi: UInt64, key: [UInt8]) -> (UInt64, UInt64) {
            var block: [UInt8] = []
            block.appendLE(lo)
            block.appendLE(hi)
            let out = round(block, key: key)
            return (out.le64(at: 0), out.le64(at: 8))
        }
    }

    // MARK: - Stage 1 (shared by v2 and v3) and the full hash

    /// Fills the scratchpad (`words` u64s) with ChaCha8 keystreams keyed by a BLAKE3 chain over the input.
    static func stage1(_ input: [UInt8], _ sp: UnsafeMutablePointer<UInt64>, words: Int) {
        let outputSize = words * 8
        let bytes = UnsafeMutableRawPointer(sp)
        bytes.initializeMemory(as: UInt8.self, repeating: 0, count: outputSize)
        var inputHash = Blake3.hash(input)
        var nonce = Array(inputHash[0 ..< 12])
        let chunkCount = (input.count + 31) / 32
        var outputOffset = 0
        for chunkIndex in 0 ..< chunkCount {
            var tmp = [UInt8](repeating: 0, count: 64)
            for k in 0 ..< 32 { tmp[k] = inputHash[k] }
            let start = chunkIndex * 32
            for k in start ..< min(input.count, start + 32) { tmp[32 + k - start] = input[k] }
            inputHash = Blake3.hash(tmp)

            let remaining = outputSize - outputOffset
            let chunksLeft = chunkCount - chunkIndex
            let current = min(remaining, remaining / chunksLeft)
            let offset = chunkIndex * current
            ChaCha8.apply(key: inputHash, nonce: nonce, to: bytes + offset, count: current)
            outputOffset += current
            let nonceStart = max(0, current - 12)
            nonce = (0 ..< 12).map { bytes.load(fromByteOffset: offset + nonceStart + $0, as: UInt8.self) }
        }
    }

    static func hash(_ input: [UInt8], words: Int, stage3: (UnsafeMutablePointer<UInt64>) -> Void) -> [UInt8] {
        let sp = UnsafeMutablePointer<UInt64>.allocate(capacity: words)
        defer { sp.deallocate() }
        stage1(input, sp, words: words)
        stage3(sp)
        return Blake3.hash(UnsafeRawBufferPointer(start: sp, count: words * 8))
    }

    // MARK: - XelisHash v3 (mainnet)

    enum V3 {
        static let memorySize = 531 * 128            // u64 words
        static let memoryBytes = memorySize * 8      // 543,744
        static let bufferSize = memorySize / 2
        static let iterations = 2
        static let key = Array("xelishash-pow-v3".utf8)

        @inline(__always) static func mapIndex(_ value: UInt64) -> Int {
            var x = value
            x ^= x >> 33
            x = x &* 0xff51afd7ed558ccd
            return Int(x.multipliedFullWidth(by: UInt64(bufferSize)).high)
        }

        @inline(__always) static func pickHalf(_ seed: UInt64) -> Bool {
            murmurhash3(seed) & (1 << 58) != 0
        }

        /// As in the reference: an f64 square root, then a +-1 correction with wrapping u64 products.
        static func isqrt(_ n: UInt64) -> UInt64 {
            if n < 2 { return n }
            let approx = UInt64(Double(n).squareRoot())
            if approx &* approx > n { return approx - 1 }
            if (approx &+ 1) &* (approx &+ 1) <= n { return approx + 1 }
            return approx
        }

        static func modularPower(_ base: UInt64, _ exp: UInt64, _ mod: UInt64) -> UInt64 {
            guard mod != 0 else { return 0 }   // the reference panics (probability 2^-64)
            var result: UInt64 = 1
            var b = base % mod
            var e = exp
            while e > 0 {
                if e & 1 == 1 { result = UInt64(truncatingIfNeeded: UInt128(result) * UInt128(b) % UInt128(mod)) }
                b = UInt64(truncatingIfNeeded: UInt128(b) * UInt128(b) % UInt128(mod))
                e /= 2
            }
            return result
        }

        static func stage3(_ sp: UnsafeMutablePointer<UInt64>) {
            let n = bufferSize
            let memA = sp, memB = sp + n
            var addrA = memB[n - 1]
            var addrB = memA[n - 1] >> 32
            var r = 0
            for i in 0 ..< iterations {
                let ma = memA[mapIndex(addrA)]
                let mb = memB[mapIndex(ma ^ addrB)]
                let (hash1, hash2) = AES.round(lo: mb, hi: ma, key: key)
                var result = ~(hash1 ^ hash2)
                let iu = UInt64(i)
                for j in 0 ..< n {
                    let ju = UInt64(j)
                    let a = memA[mapIndex(result)]
                    let b = memB[mapIndex(a ^ ~rotr(result, r))]
                    let c = r < n ? memA[r] : memB[r - n]
                    r = r < memorySize - 1 ? r + 1 : 0

                    let v: UInt64
                    switch rotl(result, Int(c & 63)) & 0xf {
                    case 0:
                        let t1 = combine(a &+ iu, isqrt(b &+ ju))
                        let denom = murmurhash3(c ^ result ^ iu ^ ju) | 1
                        v = UInt64(truncatingIfNeeded: t1 % UInt128(denom))
                    case 1:
                        let t1 = (c &+ iu) % isqrt(b | 2)
                        v = rotl(t1, i + j) &* isqrt(a &+ ju)
                    case 2:
                        v = (isqrt(a &+ iu) &* isqrt(c &+ ju)) ^ (b &+ iu &+ ju)
                    case 3: v = (a &+ b) &* c
                    case 4: v = (b &- c) &* a
                    case 5: v = c &- a &+ b
                    case 6: v = a &- b &+ c
                    case 7: v = b &* c &+ a
                    case 8: v = c &* a &+ b
                    case 9: v = a &* b &* c
                    case 10:
                        v = UInt64(truncatingIfNeeded: combine(a, b) % UInt128(c | 1))
                    case 11:
                        let t1 = combine(b, c), t2 = combine(rotl(result, r), a | 2)
                        v = t2 > t1 ? c : UInt64(truncatingIfNeeded: t1 % t2)
                    case 12:
                        v = UInt64(truncatingIfNeeded: combine(c, a) / UInt128(b | 4))
                    case 13:
                        let t1 = combine(rotl(result, r), b), t2 = combine(a, c | 8)
                        v = t1 > t2 ? UInt64(truncatingIfNeeded: t1 / t2) : a ^ b
                    case 14:
                        v = UInt64(truncatingIfNeeded: (combine(b, a) &* UInt128(c)) >> 64)
                    default:
                        v = UInt64(truncatingIfNeeded: (combine(a, c) &* combine(rotr(result, r), b)) >> 64)
                    }

                    let seed = v ^ result
                    result = rotl(seed, r)
                    let ti = mapIndex(seed)
                    let t = (pickHalf(v) ? memB[ti] : memA[ti]) ^ result
                    let ia = mapIndex(t ^ result ^ 0x9e3779b97f4a7c15)
                    let ib = mapIndex(UInt64(ia) ^ ~result ^ 0xd2b74407b1ce6e93)
                    let old = memA[ia]
                    memA[ia] = t
                    memB[ib] ^= old ^ rotr(t, i + j)
                }
                addrA = modularPower(addrA, addrB, result)
                addrB = isqrt(result) &* (UInt64(r) &+ 1) &* isqrt(addrA)
            }
        }

        static func hash(_ input: [UInt8]) -> [UInt8] {
            XelisHashReference.hash(input, words: memorySize, stage3: stage3)
        }

        /// Hashes `work` with each nonce (bytes 40..<48, big-endian), in parallel on the CPU cores.
        static func hashes(work: [UInt8], nonces: [UInt64]) -> [[UInt8]] {
            var out = [[UInt8]](repeating: [], count: nonces.count)
            out.withUnsafeMutableBufferPointer { buffer in
                let base = buffer.baseAddress!
                DispatchQueue.concurrentPerform(iterations: nonces.count) { k in
                    var input = work
                    setNonce(&input, nonces[k])
                    (base + k).pointee = hash(input)
                }
            }
            return out
        }
    }

    // MARK: - XelisHash v2 (mainnet from height 434,100 to 3,282,149; checked for the shared stages)

    enum V2 {
        static let memorySize = 429 * 128
        static let bufferSize = memorySize / 2
        static let iterations = 3
        static let key = Array("xelishash-pow-v2".utf8)

        static func isqrt(_ n: UInt64) -> UInt64 {
            if n < 2 { return n }
            var x = n
            var y = (x &+ 1) >> 1
            while y < x {
                x = y
                if x == 0 { return 0 }   // the reference divides by zero here (n = 2^64 - 1)
                y = (x &+ n / x) >> 1
            }
            return x
        }

        static func stage3(_ sp: UnsafeMutablePointer<UInt64>) {
            let n = bufferSize
            let size = UInt64(bufferSize)
            let memA = sp, memB = sp + n
            var addrA = memB[n - 1]
            var addrB = memA[n - 1] >> 32
            var r = 0
            for i in 0 ..< iterations {
                let ma = memA[Int(addrA % size)]
                let mb = memB[Int(addrB % size)]
                let (hash1, _) = AES.round(lo: mb, hi: ma, key: key)
                var result = ~(hash1 ^ (ma ^ mb))
                for j in 0 ..< n {
                    let a = memA[Int(result % size)]
                    let b = memB[Int(~rotr(result, r) % size)]
                    let c = r < n ? memA[r] : memB[r - n]
                    r = r < memorySize - 1 ? r + 1 : 0
                    let ij = Int(UInt32(truncatingIfNeeded: i &* j))
                    let x: UInt64
                    switch rotl(result, Int(c & 63)) & 0xf {
                    case 0: x = rotl(c, ij) ^ b
                    case 1: x = rotr(c, ij) ^ a
                    case 2: x = a ^ b ^ c
                    case 3: x = (a &+ b) &* c
                    case 4: x = (b &- c) &* a
                    case 5: x = c &- a &+ b
                    case 6: x = a &- b &+ c
                    case 7: x = b &* c &+ a
                    case 8: x = c &* a &+ b
                    case 9: x = a &* b &* c
                    case 10: x = UInt64(truncatingIfNeeded: combine(a, b) % UInt128(c | 1))
                    case 11: x = UInt64(truncatingIfNeeded: combine(b, c) % combine(rotl(result, r), a | 2))
                    case 12: x = UInt64(truncatingIfNeeded: combine(c, a) / UInt128(b | 4))
                    case 13:
                        let t1 = combine(rotl(result, r), b), t2 = combine(a, c | 8)
                        x = t1 > t2 ? UInt64(truncatingIfNeeded: t1 / t2) : a ^ b
                    case 14: x = UInt64(truncatingIfNeeded: (combine(b, a) &* UInt128(c)) >> 64)
                    default: x = UInt64(truncatingIfNeeded: (combine(a, c) &* combine(rotr(result, r), b)) >> 64)
                    }
                    result = rotl(result ^ x, 1)
                    let t = memA[n - j - 1] ^ result
                    memA[n - j - 1] = t
                    memB[j] ^= rotr(t, Int(result & 63))
                }
                addrA = result
                addrB = isqrt(result)
            }
        }

        static func hash(_ input: [UInt8]) -> [UInt8] {
            XelisHashReference.hash(input, words: memorySize, stage3: stage3)
        }
    }

    // MARK: - Real mainnet blocks (explorer.xelis.io, 2026-11-19)

    /// Decodes a XELIS bech32 address ("xel:" + data + 6 checksum characters) to its payload bytes:
    /// the 32-byte compressed public key followed by the address type (0 = normal).
    static func bech32Payload(_ address: String) throws -> [UInt8] {
        let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
        guard let separator = address.lastIndex(of: ":") else { throw MinerError("no ':' in address \(address)") }
        var values: [UInt32] = []
        for ch in address[address.index(after: separator)...] {
            guard let v = charset.firstIndex(of: ch) else { throw MinerError("invalid bech32 character \(ch)") }
            values.append(UInt32(v))
        }
        guard values.count > 6 else { throw MinerError("address too short") }
        values.removeLast(6)
        var acc: UInt32 = 0
        var bits: UInt32 = 0
        var out: [UInt8] = []
        for v in values {
            acc = (acc << 5) | v
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: acc >> bits))
            }
        }
        return out
    }

    struct MainnetBlock {
        let height: UInt64
        let topoheight: UInt64
        let version: UInt8
        let hash: String
        let tips: [String]
        let txs: [String]
        let timestamp: UInt64
        let nonce: UInt64
        let extraNonce: String
        let miner: String
        let difficulty: UInt64

        /// The 112-byte PoW input (xelis_common/src/block/header.rs get_pow_challenge):
        /// BLAKE3(version | height BE | BLAKE3(tips) | BLAKE3(txs)) | timestamp BE | nonce BE | extra nonce | miner key.
        func minerWork() throws -> [UInt8] {
            var header: [UInt8] = [version]
            header += XelisHashReference.be64(height)
            header += Blake3.hash(tips.flatMap { [UInt8](hex: $0) ?? [] })
            header += Blake3.hash(txs.flatMap { [UInt8](hex: $0) ?? [] })
            var work = Blake3.hash(header)
            work += XelisHashReference.be64(timestamp)
            work += XelisHashReference.be64(nonce)
            work += [UInt8](hex: extraNonce) ?? []
            let payload = try XelisHashReference.bech32Payload(miner)
            guard payload.count == 33, payload[32] == 0 else { throw MinerError("unexpected address payload for \(miner)") }
            work += payload[0 ..< 32]
            guard work.count == 112 else { throw MinerError("MinerWork is \(work.count) bytes") }
            return work
        }
    }

    static let mainnetBlocks = [
        MainnetBlock(height: 8_682_175, topoheight: 10_026_785, version: 7,
                     hash: "09e88961871ffd371df20ca2f2c67e457fbe8ccc20969bf18069f2089d97a704",
                     tips: ["eda978c474166c0493d194cae88c5b4fae727dd2d69dd5176331ddc29c20d4f8",
                            "80fcd8c008dbe084d3b50b4d8688e189b31b53edb60bf2806ea0a4c88a19d8bc",
                            "6eb37cf9d09a74e2f3bbc5a3f7171f492fa173ab132ebf7d2d727ab64cfabaf9"],
                     txs: [], timestamp: 1_795_122_149_354, nonce: 11_844_555_442_053_251_072,
                     extraNonce: "5081e0436ce476f3ec6864ad67b3ae8faddae03e16459252019434b80c73c573",
                     miner: "xel:cm6qlldx6vs9t05z2twzf7vkk4797rt8lxr93w9ctyc7nvx7y9uqqqeglul",
                     difficulty: 81_673_695),
        MainnetBlock(height: 8_682_180, topoheight: 10_026_790, version: 7,
                     hash: "a36b14abfa101167c62faea6805a3cfefe67447ac7a5bd999a26f7253545819d",
                     tips: ["e6499102bd2158b425761ac18ae3ac31ef4eeabe3549c052cbf07cf37b2d2099"],
                     txs: [], timestamp: 1_795_122_177_127, nonce: 13_407_838_862_181_662_720,
                     extraNonce: "66b948d6a637304b033dc76ca80db79090864660625279acf9c86c80f3af8862",
                     miner: "xel:p692xuntphjr4uyesggnpyvd36g4xdmj5k6y5e8zjx399hs84svsqruxpza",
                     difficulty: 79_987_125),
    ]

    // MARK: - Known-answer tests

    /// Vectors from xelis-hash src/v2.rs and src/v3.rs (test_zero_hash, test_verify_output).
    static let verifyInput: [UInt8] = [
        172, 236, 108, 212, 181, 31, 109, 45, 44, 242, 54, 225, 143, 133,
        89, 44, 179, 108, 39, 191, 32, 116, 229, 33, 63, 130, 33, 120, 185, 89,
        146, 141, 10, 79, 183, 107, 238, 122, 92, 222, 25, 134, 90, 107, 116,
        110, 236, 53, 255, 5, 214, 126, 24, 216, 97, 199, 148, 239, 253, 102,
        199, 184, 232, 253, 158, 145, 86, 187, 112, 81, 78, 70, 80, 110, 33,
        37, 159, 233, 198, 1, 178, 108, 210, 100, 109, 155, 106, 124, 124, 83,
        89, 50, 197, 115, 231, 32, 74, 2, 92, 47, 25, 220, 135, 249, 122,
        172, 220, 137, 143, 234, 68, 188,
    ]
    static let v2Zero: [UInt8] = [126, 219, 112, 240, 116, 133, 115, 144, 39, 40, 164, 105, 30, 158, 45, 126,
                                  64, 67, 238, 52, 200, 35, 161, 19, 144, 211, 214, 225, 95, 190, 146, 27]
    static let v2Verify: [UInt8] = [199, 114, 154, 28, 4, 164, 196, 178, 117, 17, 148, 203, 125, 228, 51, 145,
                                    162, 222, 106, 202, 205, 55, 244, 178, 94, 29, 248, 242, 98, 221, 158, 179]
    static let v3Zero: [UInt8] = [105, 172, 103, 40, 94, 253, 92, 162, 42, 252, 5, 196, 236, 238, 91, 218,
                                  22, 157, 228, 233, 239, 8, 250, 57, 212, 166, 121, 132, 148, 205, 103, 163]
    static let v3Verify: [UInt8] = [242, 8, 176, 222, 203, 27, 104, 187, 22, 40, 68, 73, 79, 79, 65, 83,
                                    138, 101, 10, 116, 194, 41, 153, 21, 92, 163, 12, 206, 231, 156, 70, 83]

    static func runVectors() throws -> [String] {
        var lines: [String] = []
        func check(_ name: String, _ got: [UInt8], _ expected: [UInt8]) throws {
            guard got == expected else { throw MinerError("\(name): got \(got.hex), expected \(expected.hex)") }
            lines.append("\(name) = \(got.hex.prefix(16))... ok")
        }
        guard AES.sbox[0x00] == 0x63, AES.sbox[0x01] == 0x7c, AES.sbox[0x53] == 0xed, AES.sbox[0xff] == 0x16 else {
            throw MinerError("AES S-box is wrong")
        }
        try check("AES round, FIPS-197 App. B round 1",
                  AES.round([UInt8](hex: "193de3bea0f4e22b9ac68d2ae9f84808")!, key: [UInt8](hex: "a0fafe1788542cb123a339392a6c7605")!),
                  [UInt8](hex: "a49c7ff2689f352b6b5bea43026a5049")!)
        try check("BLAKE3(\"\")", Blake3.hash([]),
                  [UInt8](hex: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")!)
        try check("BLAKE3(\"abc\")", Blake3.hash(Array("abc".utf8)),
                  [UInt8](hex: "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")!)
        try check("v2 test_zero_hash", V2.hash([UInt8](repeating: 0, count: 112)), v2Zero)
        try check("v2 test_verify_output", V2.hash(verifyInput), v2Verify)
        try check("v3 test_zero_hash", V3.hash([UInt8](repeating: 0, count: 112)), v3Zero)
        try check("v3 test_verify_output", V3.hash(verifyInput), v3Verify)
        for block in mainnetBlocks {
            let work = try block.minerWork()
            try check("block \(block.height) BLAKE3(MinerWork) = block hash", Blake3.hash(work), [UInt8](hex: block.hash)!)
            let pow = V3.hash(work)
            guard meets(pow, target(difficulty: block.difficulty)) else {
                throw MinerError("block \(block.height): v3 PoW \(pow.hex) is above the target for difficulty \(block.difficulty)")
            }
            lines.append("block \(block.height) v3 PoW \(pow.hex.prefix(16))... <= (2^256-1)/\(block.difficulty) ok")
        }
        return lines
    }
}
