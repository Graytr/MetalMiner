import Foundation
import Metal

/// GPU-against-CPU checks for PearlHashAlgorithm.
extension PearlHashAlgorithm {
    /// Attempt index <-> tile origin (first row of A, first column of B), as pearlhash_mine numbers them.
    static func tileOrigin(_ tile: Int, colTiles: Int) -> (rows: Int, cols: Int) {
        let rt = tile / colTiles, ct = tile % colTiles
        return ((rt / 32) * 128 + ((rt % 32) / 8) * 16 + rt % 8, (ct / 8) * 64 + ((ct % 8) / 4) * 16 + (ct % 4) * 2)
    }

    static func tileIndex(rows tr: Int, cols tc: Int, colTiles: Int) -> Int {
        ((tr / 128) * 32 + ((tr % 128) / 16) * 8 + tr % 8) * colTiles + (tc / 64) * 8 + ((tc % 64) / 16) * 4 + (tc % 8) / 2
    }

    /// The search kernel assumes which two cells of an 8x8 SIMD-group matrix each lane holds; check it.
    func checkMatrixLayout() throws {
        let probe = try gpu.buffer(32 * 16, label: "pearlhash layout probe")
        try gpu.compute("pearlhash layout probe") { encoder in
            encoder.setBuffer(probe, offset: 0, index: 0)
            gpu.dispatch(encoder, probePipeline, threads: 32, group: 32)
        }
        let cells = probe.contents().bindMemory(to: Float.self, capacity: 128)
        for lane in 0 ..< 32 where cells[4 * lane] != cells[4 * lane + 2] || cells[4 * lane + 1] != cells[4 * lane + 3] {
            let held = (0 ..< 32).map { "\(Int(cells[4 * $0]))/\(Int(cells[4 * $0 + 1]))" }.joined(separator: " ")
            throw MinerError("SIMD-group matrix layout differs from the kernel's assumption (lane \(lane)); lanes hold cells \(held)")
        }
    }

    func crossCheck(samples: Int) throws -> String {
        if options.int("lab") != nil { return try lab() }
        if let count = options.int("profile") { return try profile(instances: count) }
        try checkMatrixLayout()
        let k = config.k
        let colTiles = n / 8
        let tiles = (m / 4) * colTiles
        let nonce = UInt64.random(in: 0 ... .max)
        // A bound most tiles miss: about 8 hits expected in the instance.
        let bits = 259 - Int(log2(Double(tiles)).rounded())
        var bound = [UInt32](repeating: .max, count: 8)
        if bits < 256 { bound[7] = (UInt32(1) << UInt32(bits - 224)) - 1 }

        try reserveInstances(1)
        writeInstance(0, nonce: nonce)
        hitsBuffer.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        let hashes = try gpu.buffer(tiles * 32, label: "pearlhash tile hashes")
        let p = params(bound: bound, writeHashes: true)
        try gpu.compute("pearlhash check") { encoder in encode(encoder, instance: 0, params: p, hashes: hashes) }
        let gpuWords = hashes.contents().bindMemory(to: UInt32.self, capacity: tiles * 8)
        func gpuHash(_ tile: Int) -> [UInt8] { PearlHashBlake3.bytes(Array(UnsafeBufferPointer(start: gpuWords + 8 * tile, count: 8))) }

        // The CPU rebuilds the instance from scratch: B^T with the nonce, its full commitment, the seeds.
        var bt = btBase
        bt.replaceSubrange(0 ..< 32, with: Self.nonceEntries(nonce))
        let hashB = PearlHashReference.commitment(bt, jobKey: jobKey)
        let seeds = PearlHashReference.noiseSeeds(jobKey: jobKey, hashA: hashA, hashB: hashB, m: m, n: n, salted: true)
        let viaPath = instanceSeeds(nonce: nonce)
        guard viaPath.a == seeds.a, viaPath.b == seeds.b else { throw MinerError("left-path commitment of B differs from the full hash") }
        let permA = PearlHashReference.permutation(k: k, rank: config.rank, label: PearlHashReference.labelA, key: seeds.a)
        let permB = PearlHashReference.permutation(k: k, rank: config.rank, label: PearlHashReference.labelB, key: seeds.b)
        func cpuHash(_ tile: Int) -> [UInt8] {
            let origin = Self.tileOrigin(tile, colTiles: colTiles)
            let rows = config.rows.map { r -> [Int8] in
                let row = origin.rows + r
                let e = PearlHashReference.uniformRow(row, rank: config.rank, label: PearlHashReference.labelA, key: seeds.a)
                return PearlHashReference.noised(a[row * k ..< (row + 1) * k], e: e, perm: permA)
            }
            let cols = config.cols.map { c -> [Int8] in
                let col = origin.cols + c
                let e = PearlHashReference.uniformRow(col, rank: config.rank, label: PearlHashReference.labelB, key: seeds.b)
                return PearlHashReference.noised(bt[col * k ..< (col + 1) * k], e: e, perm: permB)
            }
            return PearlHashReference.jackpotHash(PearlHashReference.jackpot(rows: rows, cols: cols, config: config), aSeed: seeds.a)
        }

        // Full 32-byte jackpot hashes: random tiles plus the first and last.
        var check = Set((0 ..< samples).map { _ in Int.random(in: 0 ..< tiles) })
        check.insert(0)
        check.insert(tiles - 1)
        for t in check.sorted() {
            let cpu = cpuHash(t)
            guard cpu == gpuHash(t) else {
                let origin = Self.tileOrigin(t, colTiles: colTiles)
                throw MinerError("tile (\(origin.rows), \(origin.cols)), nonce \(String(nonce, radix: 16)): GPU \(gpuHash(t).hex) vs CPU \(cpu.hex)")
            }
        }

        // Hits: the GPU's list must be exactly the tiles whose hash meets the bound, each confirmed on the CPU.
        var expected = Set<Int>()
        for t in 0 ..< tiles where PearlHashReference.meets(gpuHash(t), bound) { expected.insert(t) }
        let hitCount = Int(hitsBuffer.contents().load(as: UInt32.self))
        guard hitCount == expected.count else { throw MinerError("GPU reported \(hitCount) hits, its hashes show \(expected.count)") }
        var reported = Set<Int>()
        for i in 0 ..< min(hitCount, Self.maxHits) {
            let base = hitsBuffer.contents() + 8 + 16 * i
            guard base.load(as: UInt64.self) == nonce else { throw MinerError("hit \(i) carries the wrong nonce") }
            let tr = Int(base.load(fromByteOffset: 8, as: UInt32.self))
            let tc = Int(base.load(fromByteOffset: 12, as: UInt32.self))
            reported.insert(Self.tileIndex(rows: tr, cols: tc, colTiles: colTiles))
        }
        guard hitCount > Self.maxHits || reported == expected else { throw MinerError("GPU hit list differs from the tiles that meet the bound") }
        for t in expected.sorted() where !check.contains(t) {
            let cpu = cpuHash(t)
            guard cpu == gpuHash(t), PearlHashReference.meets(cpu, bound) else { throw MinerError("hit tile \(t) differs from the CPU") }
        }
        return "SIMD-matrix layout ok; nonce \(String(nonce, radix: 16)): \(check.count) random tiles' 32-byte jackpot hashes match the CPU;"
            + " \(hitCount) hits at bound 2^\(bits)-1 = exactly the tiles that meet it, all confirmed on the CPU; left-path B commitment = full hash"
    }
}
