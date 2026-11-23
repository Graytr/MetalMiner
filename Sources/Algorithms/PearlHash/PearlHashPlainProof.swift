import Foundation

/// The 76-byte job header a pool sends (zk-pow `IncompleteBlockHeader`), parsed back into its fields; nil unless
/// exactly 76 bytes. `bytes` gives the same 76 bytes back.
extension PearlHashHeader {
    init?(bytes b: [UInt8]) {
        guard b.count == 76 else { return nil }
        self.init(version: b.le32(at: 0), prevBlock: Array(b[4 ..< 36]), merkleRoot: Array(b[36 ..< 68]),
                  timestamp: b.le32(at: 68), bits: b.le32(at: 72))
    }
}

extension PearlHashConfig {
    /// `PeriodicPattern::from_list` for untrusted input: the (stride, length) dimensions of an increasing offset list
    /// that starts at 0, innermost first, padded to 3; nil when the list isn't periodic, needs more than 3
    /// dimensions or doesn't fit the 6-byte encoding. Same search as `shape`, which traps instead.
    static func periodicShape(_ list: [Int]) -> [(stride: Int, length: Int)]? {
        guard list.first == 0, zip(list, list.dropFirst()).allSatisfy({ $0 < $1 }) else { return nil }
        var p = list
        var dims: [(stride: Int, length: Int)] = []
        while p.count > 1 {
            let q = p
            guard let period = (1 ..< q.count).first(where: { period in
                q.count % period == 0 && (0 ..< q.count - period).allSatisfy { q[$0] + q[period] == q[$0 + period] }
            }) else { return nil }
            dims.append((q[period], q.count / period))
            p = Array(q[0 ..< period])
        }
        dims.reverse()
        guard dims.count <= 3 else { return nil }
        let period = dims.last.map { $0.stride * $0.length } ?? 1
        while dims.count < 3 { dims.append((period, 1)) }
        var minStride = 1
        for d in dims {
            guard d.stride % minStride == 0, (1 ... 256).contains(d.stride / minStride), (1 ... 256).contains(d.length) else {
                return nil
            }
            minStride = d.stride * d.length
        }
        return dims
    }
}

/// 256-bit share targets as 8 little-endian words, the form PearlHashReference compares hashes with.
enum PearlHashTarget {
    static let zero = [UInt32](repeating: 0, count: 8)

    /// A big-endian hex number of up to 64 digits, as pools send targets.
    static func fromHex(_ text: String) -> [UInt32]? {
        var digits = text.hasPrefix("0x") ? String(text.dropFirst(2)) : text
        guard !digits.isEmpty, digits.count <= 64 else { return nil }
        digits = String(repeating: "0", count: 64 - digits.count) + digits
        guard let be = [UInt8](hex: digits) else { return nil }
        return (0 ..< 8).map { w in
            let o = 28 - 4 * w
            return UInt32(be[o]) << 24 | UInt32(be[o + 1]) << 16 | UInt32(be[o + 2]) << 8 | UInt32(be[o + 3])
        }
    }

    /// 64 big-endian hex digits.
    static func hex(_ t: [UInt32]) -> String { t.reversed().map { String(format: "%08x", $0) }.joined() }

    /// floor(t / divisor), divisor at least 1.
    static func divide(_ t: [UInt32], by divisor: UInt64) -> [UInt32] {
        let d = max(divisor, 1)
        var out = zero
        var remainder: UInt64 = 0
        for i in stride(from: 7, through: 0, by: -1) {
            let (q, r) = d.dividingFullWidth((high: remainder >> 32, low: remainder << 32 | UInt64(t[i])))
            out[i] = UInt32(truncatingIfNeeded: q)
            remainder = r
        }
        return out
    }

    /// 2^224 / d: the target of a share of difficulty d when one difficulty unit is 2^32 hashes (Kryptex's
    /// hashes_per_diff), since a target T takes 2^256 / T hashes on average.
    static func kryptex(difficulty d: UInt64) -> [UInt32] {
        var t = zero
        t[7] = 1
        return divide(t, by: d)
    }

    /// Bitcoin's pdiff convention, 0xFFFF * 2^208 / d: a hair below 2^224 / d, so never easier than the pool's target.
    static func pdiff(difficulty d: UInt64) -> [UInt32] {
        var t = zero
        t[6] = 0xFFFF_0000
        return divide(t, by: d)
    }

    /// The target rounded down to compact (nbits) form, the way a pool that checks shares with Pearl's
    /// `verify_plain_proof(nbits_override)` sees it (Bitcoin GetCompact), decoded back. Never above t.
    static func compactFloor(_ t: [UInt32]) -> [UInt32] {
        let be = t.reversed().flatMap { w in
            [UInt8(w >> 24), UInt8(truncatingIfNeeded: w >> 16), UInt8(truncatingIfNeeded: w >> 8), UInt8(truncatingIfNeeded: w)]
        }
        guard let first = be.firstIndex(where: { $0 != 0 }) else { return zero }
        var size = 32 - first
        var mantissa: UInt32 = 0
        for i in 0 ..< 3 { mantissa = mantissa << 8 | (first + i < 32 ? UInt32(be[first + i]) : 0) }
        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8
            size += 1
        }
        return PearlHashReference.target(bits: UInt32(size) << 24 | mantissa)
    }

    /// Expected hashes per share at target t: 2^256 / t.
    static func work(_ t: [UInt32]) -> Double {
        let value = t.enumerated().reduce(0.0) { $0 + Double($1.element) * pow(2.0, Double(32 * $1.offset)) }
        return value > 0 ? pow(2.0, 256) / value : .infinity
    }
}

/// pearl-blake3's `MerkleTree` (src/merkle.rs): keyed BLAKE3 chunk chaining values, combined pairwise per layer (an
/// odd last node moves up unchanged) until two remain, which make the root. That is BLAKE3's own tree, so the root
/// equals the keyed hash of the chunk-padded data, i.e. the matrix commitment.
struct PearlHashMerkleTree {
    let keyWords: [UInt32]
    /// layers[0] holds the chunk chaining values, the last layer the root; 8 words per node.
    let layers: [[UInt32]]
    let chunkCount: Int

    init(data: [UInt8], key: [UInt8]) {
        let keyWords = PearlHashBlake3.words(key)
        let flags = PearlHashBlake3.keyedFlag
        let chunks = max(1, (data.count + 1023) / 1024)
        var layer: [UInt32] = []
        layer.reserveCapacity(8 * chunks)
        data.withUnsafeBytes { raw in
            if raw.count <= 1024 {   // one chunk: the tree is just the hash
                layer = PearlHashBlake3.chunk(raw, key: keyWords, baseFlags: flags, index: 0, root: true)
                return
            }
            for c in 0 ..< chunks {
                let piece = UnsafeRawBufferPointer(rebasing: raw[c * 1024 ..< min(raw.count, (c + 1) * 1024)])
                layer += PearlHashBlake3.chunk(piece, key: keyWords, baseFlags: flags, index: UInt64(c), root: false)
            }
        }
        var layers = [layer]
        if chunks > 1 {
            while layers[layers.count - 1].count > 16 {
                let previous = layers[layers.count - 1]
                let count = previous.count / 8
                var next: [UInt32] = []
                next.reserveCapacity(8 * ((count + 1) / 2))
                for i in stride(from: 0, to: count, by: 2) {
                    if i + 1 < count {
                        next += PearlHashBlake3.parent(Array(previous[8 * i ..< 8 * i + 8]), Array(previous[8 * i + 8 ..< 8 * i + 16]),
                                                       key: keyWords, baseFlags: flags, root: false)
                    } else {
                        next += previous[8 * i ..< 8 * i + 8]
                    }
                }
                layers.append(next)
            }
            let last = layers[layers.count - 1]
            layers.append(PearlHashBlake3.parent(Array(last[0 ..< 8]), Array(last[8 ..< 16]), key: keyWords, baseFlags: flags, root: true))
        }
        self.keyWords = keyWords
        self.layers = layers
        chunkCount = chunks
    }

    var root: [UInt8] { PearlHashBlake3.bytes(Array(layers[layers.count - 1][0 ..< 8])) }

    private func node(_ level: Int, _ i: Int) -> [UInt8] { PearlHashBlake3.bytes(Array(layers[level][8 * i ..< 8 * i + 8])) }

    /// `MerkleTree::get_multileaf_proof` for the chunks holding `rows` (each `rowLength` bytes) of `data`, the bytes
    /// this tree was built from: the chunks themselves and the siblings needed to rebuild the root, collected level by
    /// level, in increasing index order within a level.
    func open(rows: [Int], rowLength: Int, data: [UInt8]) -> PearlHashPlainProof.MatrixProof {
        var wanted = Set<Int>()
        for row in rows {   // MerkleTree::compute_leaf_indices_from_rows
            for leaf in (row * rowLength) / 1024 ... ((row + 1) * rowLength - 1) / 1024 { wanted.insert(leaf) }
        }
        let leaves = wanted.sorted()
        let leafData = leaves.map { i -> [UInt8] in
            var chunk = [UInt8](repeating: 0, count: 1024)
            let end = min((i + 1) * 1024, data.count)
            if i * 1024 < end { chunk.replaceSubrange(0 ..< end - i * 1024, with: data[i * 1024 ..< end]) }
            return chunk
        }
        var siblings: [[UInt8]] = []
        var current = leaves
        var length = chunkCount
        var level = 0
        while length > 1 && !current.isEmpty {
            let set = Set(current)
            for i in current {
                if i % 2 == 1 {
                    if !set.contains(i - 1) { siblings.append(node(level, i - 1)) }
                } else if !set.contains(i + 1) && i + 1 < length {
                    siblings.append(node(level, i + 1))
                }
            }
            current = Set(current.map { $0 / 2 }).sorted()
            length = (length + 1) / 2
            level += 1
        }
        return PearlHashPlainProof.MatrixProof(leafData: leafData, leafIndices: leaves, totalLeaves: chunkCount, root: root,
                                               siblings: siblings, rowIndices: rows)
    }

    /// `MerkleProof::compute_root`: the root rebuilt from an opening's leaves and siblings; nil when its shape is wrong.
    static func root(of p: PearlHashPlainProof.MatrixProof, key: [UInt8]) -> [UInt8]? {
        guard !p.leafIndices.isEmpty, p.leafIndices.count == p.leafData.count else { return nil }
        let keyWords = PearlHashBlake3.words(key)
        let flags = PearlHashBlake3.keyedFlag
        func parent(_ left: [UInt32], _ right: [UInt32], root: Bool) -> [UInt32] {
            PearlHashBlake3.parent(left, right, key: keyWords, baseFlags: flags, root: root)
        }
        var current: [Int: [UInt32]] = [:]
        for (index, data) in zip(p.leafIndices, p.leafData) {
            current[index] = data.withUnsafeBytes { PearlHashBlake3.chunk($0, key: keyWords, baseFlags: flags, index: UInt64(index), root: false) }
        }
        var siblings = p.siblings.makeIterator()
        func nextSibling() -> [UInt32]? { siblings.next().map { PearlHashBlake3.words($0) } }
        var length = p.totalLeaves
        if length == 1 { return p.siblings.isEmpty ? current[0].map { PearlHashBlake3.bytes($0) } : nil }
        while length > 2 {
            var next: [Int: [UInt32]] = [:]
            for i in current.keys.sorted() {
                let cv = current[i]!
                if i % 2 == 0 {
                    var right = current[i + 1]
                    if right == nil, i + 1 < length {
                        guard let sibling = nextSibling() else { return nil }
                        right = sibling
                    }
                    next[i / 2] = right.map { parent(cv, $0, root: false) } ?? cv
                } else if current[i - 1] == nil {
                    guard let left = nextSibling() else { return nil }
                    next[i / 2] = parent(left, cv, root: false)
                }
            }
            current = next
            length = (length + 1) / 2
        }
        guard let left = current[0] ?? nextSibling(), let right = current[1] ?? nextSibling(), nextSibling() == nil else { return nil }
        return PearlHashBlake3.bytes(parent(left, right, root: true))
    }
}

/// Pearl's `PlainProof` (zk-pow src/ffi/plain_proof.rs): what a miner submits for a share. It opens the winning
/// tile's rows of A and columns of B (rows of B^T) as Merkle multi-leaf proofs against the commitments hash_a and
/// hash_b, and declares m, n, k and the noise rank; the tile pattern and offset are read back from the opened row
/// indices. A pool checks it with BLAKE3 only (`verify_plain_proof`) and turns it into the block's Plonky2
/// certificate itself (`prove_plain_proof_ffi`) when the share also meets the network target.
/// Wire form: bincode 1 with fixed-width little-endian integers (zk-pow bindings/go/src/plain.rs), base64 in JSON.
struct PearlHashPlainProof {
    /// pearl-blake3 `MerkleProof` plus the opened row indices (`MatrixMerkleProof`).
    struct MatrixProof {
        var leafData: [[UInt8]]
        var leafIndices: [Int]
        var totalLeaves: Int
        var root: [UInt8]
        var siblings: [[UInt8]]
        var rowIndices: [Int]

        /// `MerkleProof::extract_bytes`: bytes [start, start + count) of the matrix, from the opened leaves.
        func bytes(from start: Int, count: Int) throws -> [UInt8] {
            var out = [UInt8](repeating: 0, count: count)
            var copied = 0
            for (index, data) in zip(leafIndices, leafData) {
                let lo = max(start, index * 1024), hi = min(start + count, index * 1024 + 1024)
                if lo < hi {
                    out.replaceSubrange(lo - start ..< hi - start, with: data[lo - index * 1024 ..< hi - index * 1024])
                    copied += hi - lo
                }
            }
            guard copied == count else { throw MinerError("the opened leaves don't cover bytes \(start)..<\(start + count)") }
            return out
        }
    }

    var m: Int
    var n: Int
    var k: Int
    var noiseRank: Int
    var a: MatrixProof
    var bt: MatrixProof

    /// bincode: m, n, k, noise_rank as u64; per matrix: leaf_data (u64 count, then each leaf as u64 1024 + bytes),
    /// leaf_indices (u64 count + u64s), total_leaves (u64), root (32 bytes), siblings (u64 count + 32 bytes each),
    /// row_indices (u64 count + u64s); then the `moe: None` tag (one zero byte).
    var bytes: [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(64 + 1040 * (a.leafData.count + bt.leafData.count) + 40 * (a.siblings.count + bt.siblings.count))
        func u64(_ v: Int) { out.appendLE(UInt64(v)) }
        u64(m)
        u64(n)
        u64(k)
        u64(noiseRank)
        for p in [a, bt] {
            u64(p.leafData.count)
            for leaf in p.leafData {
                u64(leaf.count)
                out += leaf
            }
            u64(p.leafIndices.count)
            p.leafIndices.forEach(u64)
            u64(p.totalLeaves)
            out += p.root
            u64(p.siblings.count)
            for sibling in p.siblings { out += sibling }
            u64(p.rowIndices.count)
            p.rowIndices.forEach(u64)
        }
        out.append(0)
        return out
    }

    private struct Reader {
        let bytes: [UInt8]
        var position = 0
        var remaining: Int { bytes.count - position }

        mutating func take(_ count: Int) throws -> [UInt8] {
            guard count >= 0, count <= remaining else { throw MinerError("PlainProof truncated at byte \(position)") }
            defer { position += count }
            return Array(bytes[position ..< position + count])
        }

        mutating func int(_ what: String, max: Int) throws -> Int {
            let value = try take(8).le64(at: 0)
            guard value <= UInt64(max) else { throw MinerError("PlainProof \(what) \(value) out of range") }
            return Int(value)
        }
    }

    private static func matrix(_ r: inout Reader) throws -> MatrixProof {
        let leafCount = try r.int("leaf count", max: r.remaining / 1032)
        var leafData: [[UInt8]] = []
        for _ in 0 ..< leafCount {
            guard try r.int("leaf length", max: 1024) == 1024 else { throw MinerError("PlainProof leaf is not 1,024 bytes") }
            leafData.append(try r.take(1024))
        }
        let indexCount = try r.int("leaf index count", max: r.remaining / 8)
        var leafIndices: [Int] = []
        for _ in 0 ..< indexCount { leafIndices.append(try r.int("leaf index", max: 1 << 40)) }
        let totalLeaves = try r.int("leaf total", max: 1 << 40)
        let root = try r.take(32)
        let siblingCount = try r.int("sibling count", max: r.remaining / 32)
        var siblings: [[UInt8]] = []
        for _ in 0 ..< siblingCount { siblings.append(try r.take(32)) }
        let rowCount = try r.int("row count", max: r.remaining / 8)
        var rows: [Int] = []
        for _ in 0 ..< rowCount { rows.append(try r.int("row index", max: 1 << 24)) }
        return MatrixProof(leafData: leafData, leafIndices: leafIndices, totalLeaves: totalLeaves, root: root,
                           siblings: siblings, rowIndices: rows)
    }

    init(m: Int, n: Int, k: Int, noiseRank: Int, a: MatrixProof, bt: MatrixProof) {
        self.m = m
        self.n = n
        self.k = k
        self.noiseRank = noiseRank
        self.a = a
        self.bt = bt
    }

    /// `PlainProof::deserialize_compat`: the current form (ending in the `moe: None` tag) or the legacy one without it.
    /// MoE proofs (tag 1) are refused, as mainnet's dense-only rule does.
    init(bytes: [UInt8]) throws {
        var r = Reader(bytes: bytes)
        m = try r.int("m", max: 1 << 24)
        n = try r.int("n", max: 1 << 24)
        k = try r.int("k", max: 1 << 16)
        noiseRank = try r.int("noise rank", max: 1024)
        a = try Self.matrix(&r)
        bt = try Self.matrix(&r)
        if r.remaining == 0 { return }   // the legacy form, without the tag
        guard r.remaining == 1, try r.take(1) == [0] else { throw MinerError("PlainProof is MoE or has trailing bytes") }
    }

    enum Verdict {
        case accepted(hash: [UInt8])
        case lowDifficulty(hash: [UInt8])
        case invalid(String)

        var isAccepted: Bool { if case .accepted = self { return true } else { return false } }
        var description: String {
            switch self {
            case .accepted(let hash): return "accepted, jackpot hash \(hash.hex)"
            case .lowDifficulty(let hash): return "jackpot hash \(hash.hex) misses the target"
            case .invalid(let why): return "invalid: \(why)"
            }
        }
    }

    /// A pool's share check on the CPU reference, after Pearl's `verify_plain_proof` (zk-pow src/api/verify.rs) with
    /// the share target in place of the header's nbits: consensus parameter limits (sanity_checks.rs), Merkle tree
    /// sizes pinned to the declared dimensions, both openings rebuilding their roots under the job key, opened values
    /// in -64...64, then noise from the commitments, the tile's jackpot and its hash against target x attempt work
    /// (and the rank-penalised bound). `header` is the job's 76 bytes; `salted` selects V3 noise seeds.
    static func verify(bytes: [UInt8], header: [UInt8], target: [UInt32], salted: Bool) -> Verdict {
        do {
            return try PearlHashPlainProof(bytes: bytes).check(header: header, target: target, salted: salted)
        } catch {
            return .invalid("\(error)")
        }
    }

    func check(header: [UInt8], target: [UInt32], salted: Bool) throws -> Verdict {
        guard let parsed = PearlHashHeader(bytes: header) else { throw MinerError("the job header is not 76 bytes") }
        guard noiseRank.nonzeroBitCount == 1, (128 ... 1024).contains(noiseRank) else {
            throw MinerError("noise rank \(noiseRank) is not a power of two from 128 (the rank-penalty floor) to 1,024")
        }
        guard k % 64 == 0, k >= 1024, k >= 16 * noiseRank, k <= 4 * noiseRank * noiseRank else {
            throw MinerError("k = \(k) breaks the limits for rank \(noiseRank)")
        }
        guard m >= 1, n >= 1, a.totalLeaves == (m * k + 1023) / 1024, bt.totalLeaves == (n * k + 1023) / 1024 else {
            throw MinerError("Merkle tree sizes don't match m = \(m), n = \(n), k = \(k)")
        }
        for (name, p, dimension) in [("A", a, m), ("B^T", bt, n)] {
            guard !p.leafIndices.isEmpty, p.leafIndices.count == p.leafData.count, p.leafIndices.last! < p.totalLeaves,
                  zip(p.leafIndices, p.leafIndices.dropFirst()).allSatisfy({ $0 < $1 }) else {
                throw MinerError("\(name) Merkle proof is malformed")
            }
            guard !p.rowIndices.isEmpty, p.rowIndices.last! < dimension,
                  zip(p.rowIndices, p.rowIndices.dropFirst()).allSatisfy({ $0 < $1 }) else {
                throw MinerError("\(name) row indices are not increasing within the matrix")
            }
        }
        // The tile: pattern and offset from the opened rows (plain_proof.rs `list_to_pattern`).
        let tRows = a.rowIndices[0], tCols = bt.rowIndices[0]
        let rows = a.rowIndices.map { $0 - tRows }, cols = bt.rowIndices.map { $0 - tCols }
        guard PearlHashConfig.periodicShape(rows) != nil, PearlHashConfig.periodicShape(cols) != nil else {
            throw MinerError("the opened rows or columns are not a periodic pattern")
        }
        guard PearlHashConfig.offsetIsValid(rows, tRows), PearlHashConfig.offsetIsValid(cols, tCols) else {
            throw MinerError("tile offset (\(tRows), \(tCols)) is not valid for its pattern")
        }
        let config = PearlHashConfig(k: k, rank: noiseRank, rows: rows, cols: cols)
        guard (32 ... 256).contains(config.tileSize), (rows.count + cols.count) * config.dotProductLength <= 1 << 22 else {
            throw MinerError("tile \(rows.count) x \(cols.count) is outside the consensus limits")
        }
        // Commitments: each opening must rebuild its root under the job key.
        let jobKey = PearlHashReference.jobKey(parsed, config)
        guard PearlHashMerkleTree.root(of: a, key: jobKey) == a.root else { throw MinerError("A's Merkle opening doesn't rebuild hash_a") }
        guard PearlHashMerkleTree.root(of: bt, key: jobKey) == bt.root else { throw MinerError("B^T's Merkle opening doesn't rebuild hash_b") }
        let length = config.dotProductLength
        let aStrips = try a.rowIndices.map { try a.bytes(from: $0 * k, count: length) }
        let bStrips = try bt.rowIndices.map { try bt.bytes(from: $0 * k, count: length) }
        for strip in aStrips + bStrips where !strip.allSatisfy({ (-64 ... 64).contains(Int8(bitPattern: $0)) }) {
            throw MinerError("an opened matrix value is outside -64...64")
        }
        // Noise from the commitments, the noisy tile's jackpot, its hash and the bound.
        let seeds = PearlHashReference.noiseSeeds(jobKey: jobKey, hashA: a.root, hashB: bt.root, m: m, n: n, salted: salted)
        let permA = PearlHashReference.permutation(k: k, rank: noiseRank, label: PearlHashReference.labelA, key: seeds.a)
        let permB = PearlHashReference.permutation(k: k, rank: noiseRank, label: PearlHashReference.labelB, key: seeds.b)
        let noisyRows = zip(a.rowIndices, aStrips).map { row, strip in
            PearlHashReference.noised(strip[...], e: PearlHashReference.uniformRow(row, rank: noiseRank, label: PearlHashReference.labelA, key: seeds.a), perm: permA)
        }
        let noisyCols = zip(bt.rowIndices, bStrips).map { col, strip in
            PearlHashReference.noised(strip[...], e: PearlHashReference.uniformRow(col, rank: noiseRank, label: PearlHashReference.labelB, key: seeds.b), perm: permB)
        }
        let hash = PearlHashReference.jackpotHash(PearlHashReference.jackpot(rows: noisyRows, cols: noisyCols, config: config), aSeed: seeds.a)
        let meets = PearlHashReference.meets(hash, PearlHashReference.scale(target, by: config.attemptWork))
            && PearlHashReference.meets(hash, PearlHashReference.scale(target, by: config.penalizedAttemptWork))
        return meets ? .accepted(hash: hash) : .lowDifficulty(hash: hash)
    }
}
