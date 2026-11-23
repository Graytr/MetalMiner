import Foundation

/// BLAKE3 (BLAKE3-team/BLAKE3-specs), which Pearl uses through the `blake3` crate for every hash in
/// PearlHash: plain and keyed hashing of any length, plus the pieces a miner needs to update a
/// commitment cheaply (chunk and parent chaining values, and the left-most path of the tree).
enum PearlHashBlake3 {
    static let iv: [UInt32] = [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
                               0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19]
    static let chunkStart: UInt32 = 1
    static let chunkEnd: UInt32 = 2
    static let parentFlag: UInt32 = 4
    static let rootFlag: UInt32 = 8
    static let keyedFlag: UInt32 = 16
    static let chunkLength = 1024

    /// Message word order for each of the 7 rounds (the spec's permutation applied 0...6 times).
    static let schedule: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
        3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1,
        10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6,
        12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4,
        9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7,
        11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13,
    ]

    @inline(__always)
    private static func g(_ a: inout UInt32, _ b: inout UInt32, _ c: inout UInt32, _ d: inout UInt32,
                          _ x: UInt32, _ y: UInt32) {
        a = a &+ b &+ x
        d ^= a; d = (d >> 16) | (d << 16)
        c = c &+ d
        b ^= c; b = (b >> 12) | (b << 20)
        a = a &+ b &+ y
        d ^= a; d = (d >> 8) | (d << 24)
        c = c &+ d
        b ^= c; b = (b >> 7) | (b << 25)
    }

    /// The compression function. Writes all 16 output words; the first 8 are the chaining value.
    static func compress(_ cv: UnsafePointer<UInt32>, _ block: UnsafePointer<UInt32>, counter: UInt64,
                         blockLength: UInt32, flags: UInt32, into out: UnsafeMutablePointer<UInt32>) {
        var v0 = cv[0], v1 = cv[1], v2 = cv[2], v3 = cv[3], v4 = cv[4], v5 = cv[5], v6 = cv[6], v7 = cv[7]
        var v8 = iv[0], v9 = iv[1], v10 = iv[2], v11 = iv[3]
        var v12 = UInt32(truncatingIfNeeded: counter), v13 = UInt32(truncatingIfNeeded: counter >> 32)
        var v14 = blockLength, v15 = flags
        schedule.withUnsafeBufferPointer { s in
            for round in 0 ..< 7 {
                let o = round * 16
                g(&v0, &v4, &v8, &v12, block[s[o]], block[s[o + 1]])
                g(&v1, &v5, &v9, &v13, block[s[o + 2]], block[s[o + 3]])
                g(&v2, &v6, &v10, &v14, block[s[o + 4]], block[s[o + 5]])
                g(&v3, &v7, &v11, &v15, block[s[o + 6]], block[s[o + 7]])
                g(&v0, &v5, &v10, &v15, block[s[o + 8]], block[s[o + 9]])
                g(&v1, &v6, &v11, &v12, block[s[o + 10]], block[s[o + 11]])
                g(&v2, &v7, &v8, &v13, block[s[o + 12]], block[s[o + 13]])
                g(&v3, &v4, &v9, &v14, block[s[o + 14]], block[s[o + 15]])
            }
        }
        out[0] = v0 ^ v8; out[1] = v1 ^ v9; out[2] = v2 ^ v10; out[3] = v3 ^ v11
        out[4] = v4 ^ v12; out[5] = v5 ^ v13; out[6] = v6 ^ v14; out[7] = v7 ^ v15
        out[8] = v8 ^ cv[0]; out[9] = v9 ^ cv[1]; out[10] = v10 ^ cv[2]; out[11] = v11 ^ cv[3]
        out[12] = v12 ^ cv[4]; out[13] = v13 ^ cv[5]; out[14] = v14 ^ cv[6]; out[15] = v15 ^ cv[7]
    }

    /// Little-endian words of a key or digest.
    static func words(_ bytes: [UInt8]) -> [UInt32] { (0 ..< bytes.count / 4).map { bytes.le32(at: 4 * $0) } }

    static func bytes(_ words: [UInt32]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(4 * words.count)
        for w in words { out.appendLE(w) }
        return out
    }

    /// Chaining value of one chunk (at most 1,024 bytes) at position `index`, or the root output when `root`.
    static func chunk(_ data: UnsafeRawBufferPointer, key: [UInt32], baseFlags: UInt32, index: UInt64, root: Bool) -> [UInt32] {
        var cv = key
        var block = [UInt32](repeating: 0, count: 16)
        var out = [UInt32](repeating: 0, count: 16)
        let blocks = max(1, (data.count + 63) / 64)
        for b in 0 ..< blocks {
            let start = b * 64
            let length = min(64, data.count - start)
            for w in 0 ..< 16 {
                let o = start + 4 * w
                if o + 4 <= start + length {
                    block[w] = UInt32(littleEndian: data.loadUnaligned(fromByteOffset: o, as: UInt32.self))
                } else {
                    var x: UInt32 = 0
                    var i = 0
                    while o + i < start + length && i < 4 {
                        x |= UInt32(data[o + i]) << UInt32(8 * i)
                        i += 1
                    }
                    block[w] = x
                }
            }
            var flags = baseFlags
            if b == 0 { flags |= chunkStart }
            if b == blocks - 1 {
                flags |= chunkEnd
                if root { flags |= rootFlag }
            }
            compress(cv, block, counter: index, blockLength: UInt32(length), flags: flags, into: &out)
            cv = Array(out[0 ..< 8])
        }
        return cv
    }

    static func parent(_ left: [UInt32], _ right: [UInt32], key: [UInt32], baseFlags: UInt32, root: Bool) -> [UInt32] {
        let block = left + right
        var out = [UInt32](repeating: 0, count: 16)
        compress(key, block, counter: 0, blockLength: 64, flags: baseFlags | parentFlag | (root ? rootFlag : 0), into: &out)
        return Array(out[0 ..< 8])
    }

    /// Largest power of two strictly below `n` (n >= 2): the size of BLAKE3's left subtree.
    static func leftSubtreeChunks(_ n: Int) -> Int { 1 << (Int.bitWidth - 1 - (n - 1).leadingZeroBitCount) }

    /// Chaining value (or root) of a run of chunk chaining values, split the way BLAKE3 splits its tree.
    static func subtree(_ cvs: ArraySlice<[UInt32]>, key: [UInt32], baseFlags: UInt32, root: Bool) -> [UInt32] {
        if cvs.count == 1 { return cvs[cvs.startIndex] }
        let left = leftSubtreeChunks(cvs.count)
        let mid = cvs.startIndex + left
        let l = subtree(cvs[cvs.startIndex ..< mid], key: key, baseFlags: baseFlags, root: false)
        let r = subtree(cvs[mid ..< cvs.endIndex], key: key, baseFlags: baseFlags, root: false)
        return parent(l, r, key: key, baseFlags: baseFlags, root: root)
    }

    static func chunkCVs(_ raw: UnsafeRawBufferPointer, key: [UInt32], baseFlags: UInt32) -> [[UInt32]] {
        let chunks = max(1, (raw.count + chunkLength - 1) / chunkLength)
        var cvs: [[UInt32]] = []
        cvs.reserveCapacity(chunks)
        for c in 0 ..< chunks {
            let start = c * chunkLength
            let piece = UnsafeRawBufferPointer(rebasing: raw[start ..< min(raw.count, start + chunkLength)])
            cvs.append(chunk(piece, key: key, baseFlags: baseFlags, index: UInt64(c), root: false))
        }
        return cvs
    }

    /// BLAKE3 of `data`, keyed when `key` (32 bytes) is given. 32-byte output.
    static func hash(_ data: [UInt8], key: [UInt8]? = nil) -> [UInt8] {
        let keyWords = key.map { words($0) } ?? iv
        let flags = key == nil ? 0 : keyedFlag
        return data.withUnsafeBytes { raw -> [UInt8] in
            if raw.count <= chunkLength {
                return bytes(chunk(raw, key: keyWords, baseFlags: flags, index: 0, root: true))
            }
            let cvs = chunkCVs(raw, key: keyWords, baseFlags: flags)
            return bytes(subtree(cvs[...], key: keyWords, baseFlags: flags, root: true))
        }
    }

    /// The siblings on the path from chunk 0 to the root, bottom-up. A commitment whose first chunk
    /// changes (where the miner puts its nonce) is then rehashed with one chunk plus one parent per level.
    struct LeftPath {
        let key: [UInt32]
        let baseFlags: UInt32
        let siblings: [[UInt32]]

        init(data: [UInt8], key: [UInt8]?) {
            let keyWords = key.map { PearlHashBlake3.words($0) } ?? PearlHashBlake3.iv
            let flags = key == nil ? 0 : PearlHashBlake3.keyedFlag
            self.key = keyWords
            baseFlags = flags
            let cvs = data.withUnsafeBytes { PearlHashBlake3.chunkCVs($0, key: keyWords, baseFlags: flags) }
            var top: [[UInt32]] = []
            var hi = cvs.count
            while hi > 1 {
                let left = PearlHashBlake3.leftSubtreeChunks(hi)
                top.append(PearlHashBlake3.subtree(cvs[left ..< hi], key: keyWords, baseFlags: flags, root: false))
                hi = left
            }
            siblings = top.reversed()
        }

        /// Root hash of the data with its first chunk replaced by `firstChunk` (same length as before).
        func root(firstChunk: UnsafeRawBufferPointer) -> [UInt8] {
            var cv = PearlHashBlake3.chunk(firstChunk, key: key, baseFlags: baseFlags, index: 0, root: siblings.isEmpty)
            for (i, sibling) in siblings.enumerated() {
                cv = PearlHashBlake3.parent(cv, sibling, key: key, baseFlags: baseFlags, root: i == siblings.count - 1)
            }
            return PearlHashBlake3.bytes(cv)
        }
    }
}
