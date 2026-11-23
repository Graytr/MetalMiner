import Foundation
import Metal

enum NexaPowFamily {
    static let algorithms: [MiningAlgorithm.Type] = [NexaPow.self]
    static let poolMiners: [PoolMiner.Type] = [NexaPowPoolMiner.self]
}

/// NexaPow (Nexa, NEXA): sha256d mining hash, a Schnorr signature over secp256k1 keyed by it, sha256 of
/// the signature. One nonce per GPU thread; k G uses a precomputed table of signed-window multiples of G.
/// See docs/specs/nexapow.md. NexaPow has no height-dependent parameters (no DAG or epoch).
/// Options: --set window=N (table window bits, 4...22; default 20 = 416 MiB table, --quick 8),
/// --set group=N (threads per threadgroup, default 256).
/// Development: --set profile=N runs a building-block micro-benchmark from nexapow_prof.metal (--set n=R
/// repetitions per thread); profile=100 runs the real search kernel without the cross-check, for timing
/// with --set defines=NEXAPOW_SKIP_EC|NEXAPOW_SKIP_POW|NEXAPOW_SKIP_RFC (comma-separated kernel macros).
final class NexaPow: MiningAlgorithm {
    static let id = "nexapow"
    static let coins = ["NEXA"]
    static let kernelFiles = ["nexapow_field.metal", "nexapow_sha.metal", "nexapow_ec.metal", "nexapow.metal"]

    /// Where the pool's extranonce and the miner's counter sit in the nonce: `prefix` (up to 8 bytes), then the
    /// kernel's 64-bit counter little-endian, cut to the bytes left (at most 8), then zeros up to `length` bytes (at
    /// most 16, Nexa's MAX_NONCE_SIZE). Echelon: 8 + 8 bytes; Kryptex's subscribe: 4 + 4; MiningCore-style: 4 + 8.
    struct NonceLayout: Equatable {
        let prefix: [UInt8]
        let length: Int

        init(prefix: [UInt8], length: Int) throws {
            guard prefix.count <= 8, length > prefix.count, length <= 16 else {
                throw MinerError("nonce layout: a \(prefix.count)-byte extranonce in a \(length)-byte nonce isn't supported (16 bytes at most, 1 for the miner)")
            }
            self.prefix = prefix
            self.length = length
        }

        /// The counter's bytes inside the nonce.
        var counterBytes: Int { min(8, length - prefix.count) }
        /// Counters must stay below this when the nonce holds fewer than 8 counter bytes (nil: the whole 64 bits).
        var counterLimit: UInt64? { counterBytes >= 8 ? nil : UInt64(1) << UInt64(8 * counterBytes) }

        /// The nonce bytes for one counter value.
        func bytes(_ counter: UInt64) -> [UInt8] {
            var le: [UInt8] = []
            le.appendLE(counter)
            let out = prefix + le.prefix(counterBytes)
            return out + [UInt8](repeating: 0, count: length - out.count)
        }
    }

    let gpu: GPU
    let window: Int
    let windows: Int
    let bases: [NexaPowReference.Affine]
    let table: MTLBuffer
    let tableEntries: Int
    /// Stand-in job: header commitment (internal byte order) and the Echelon layout with a random extranonce.
    let commitment: [UInt8]
    let benchLayout: NonceLayout
    let benchJob: MTLBuffer
    /// The pool job (`setJob`).
    let poolJob: MTLBuffer
    let output: MTLBuffer
    let searchPipeline: MTLComputePipelineState
    let hashPipeline: MTLComputePipelineState
    let group: Int
    let profile: Int?
    let setupSummary: String
    var defaultBatch: Int { 1 << 18 }

    required init(gpu: GPU, config: AlgoConfig) throws {
        let window = config.int("window") ?? (config.quick ? 8 : 20)
        guard (4 ... 22).contains(window) else { throw MinerError("window must be 4...22") }
        // Signed digits need a carry window only when W divides 256.
        let windows = 256 % window == 0 ? 256 / window + 1 : (256 + window - 1) / window
        let perWindow = 1 << (window - 1)
        let group = config.int("group") ?? 256
        guard group > 0, group % 32 == 0, group <= 1024 else { throw MinerError("group must be a positive multiple of 32") }

        profile = config.int("profile")
        var macros = ["NEXAPOW_W": "\(window)", "NEXAPOW_WINDOWS": "\(windows)"]
        for pair in (config.options["defines"] ?? "").split(separator: ",") {
            let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
            macros[kv[0]] = kv.count > 1 ? kv[1] : "1"
        }
        var files = NexaPow.kernelFiles
        var searchKernel = "nexapow_search"
        if let profile, profile != 100 {
            macros["NEXAPOW_PROF"] = "\(profile)"
            macros["NEXAPOW_PROF_N"] = "\(config.int("n") ?? 1)"
            files.append("nexapow_prof.metal")
            searchKernel = "nexapow_prof"
        }
        let library = try gpu.library(files, macros: macros)
        let tablePipeline = try gpu.pipeline(library, "nexapow_table")
        searchPipeline = try gpu.pipeline(library, searchKernel)
        hashPipeline = try gpu.pipeline(library, "nexapow_hash")

        // Window bases 2^(W i) G on the CPU, then every j * base on the GPU.
        var bases: [NexaPowReference.Affine] = []
        var point = NexaPowReference.Jacobian(NexaPowReference.G)
        for _ in 0 ..< windows {
            bases.append(NexaPowReference.affine(point)!)
            for _ in 0 ..< window { point = NexaPowReference.double(point) }
        }
        let baseWords = bases.flatMap { NexaPowReference.limbs32($0.x) + NexaPowReference.limbs32($0.y) }
        let baseBuffer = try gpu.buffer(baseWords, label: "nexapow bases")
        let tableEntries = windows * perWindow
        let table = try gpu.buffer(tableEntries * 64, label: "nexapow table")
        let t0 = now()
        var first = 0
        while first < tableEntries {   // chunks keep each command buffer well under the GPU watchdog
            var start = UInt32(first)
            var count = UInt32(min(1 << 16, tableEntries - first))
            try gpu.compute("nexapow table") { encoder in
                encoder.setBuffer(baseBuffer, offset: 0, index: 0)
                encoder.setBuffer(table, offset: 0, index: 1)
                encoder.setBytes(&start, length: 4, index: 2)
                encoder.setBytes(&count, length: 4, index: 3)
                gpu.dispatch(encoder, tablePipeline, threads: Int(count), group: 64)
            }
            first += Int(count)
        }
        let tableSeconds = now() - t0

        self.gpu = gpu
        self.window = window
        self.windows = windows
        self.bases = bases
        self.table = table
        self.tableEntries = tableEntries
        self.group = group
        commitment = randomBytes(32)
        benchLayout = try NonceLayout(prefix: randomBytes(8), length: 16)
        let words = NexaPow.jobWords(commitment: commitment, layout: benchLayout, target: NexaPowReference.zero)
        benchJob = try gpu.buffer(words, label: "nexapow job")
        poolJob = try gpu.buffer(words, label: "nexapow pool job")
        output = try gpu.buffer(MemoryLayout<UInt64>.stride * 64, label: "nexapow hits")
        setupSummary = "window \(window) bits · \(windows) windows · table \(formatBytes(tableEntries * 64)) built in \(fmt(tableSeconds, 2)) s"
            + " · group \(min(group, searchPipeline.maxTotalThreadsPerThreadgroup))"
            + (profile.map { " · PROFILE \($0) x \(config.int("n") ?? 1) \(config.options["defines"] ?? "")" } ?? "")
    }

    /// The NexaPowJob struct in nexapow.metal: commitment words; block words 8..15 of the mining hash (nonce length,
    /// extranonce, fill, padding, bit length) with zeros where the counter goes; the counter's word and bit offset;
    /// target limbs; the HMAC pad states of the all-zero RFC6979 key. The kernel ORs all 8 counter bytes in, so a
    /// layout with fewer counter bytes relies on counters below `counterLimit` (their extra bytes are zero).
    static func jobWords(commitment: [UInt8], layout: NonceLayout, target: NexaPowReference.U256) -> [UInt32] {
        // One SHA-256 block: commitment (32) || length (1) || nonce || 0x80 || zeros || bit length (8, big-endian).
        var block = commitment + [UInt8(layout.length)] + layout.bytes(0)
        let bits = UInt64(block.count) * 8
        block.append(0x80)
        block += [UInt8](repeating: 0, count: 56 - block.count)
        for i in (0 ..< 8).reversed() { block.append(UInt8(truncatingIfNeeded: bits >> (8 * UInt64(i)))) }
        let counterByte = 33 + layout.prefix.count
        var words = NexaPowReference.words(block)
        words += [UInt32(counterByte / 4), UInt32(8 * (counterByte % 4)), 0, 0]
        words += NexaPowReference.limbs32(target)
        words += NexaPowReference.padMidstate(0x36) + NexaPowReference.padMidstate(0x5c)
        return words
    }

    /// The 16-byte nonce for a 64-bit miner nonce in the benchmark's job: extranonce, then the counter little-endian.
    func nonceBytes(_ nonce: UInt64) -> [UInt8] { benchLayout.bytes(nonce) }

    // MARK: Pool jobs

    /// A pool job: the header commitment (internal byte order), where the extranonce and counter go, and the share
    /// target (a hit's powHash, read little-endian, is at most this).
    func setJob(commitment: [UInt8], layout: NonceLayout, target: NexaPowReference.U256) {
        let words = Self.jobWords(commitment: commitment, layout: layout, target: target)
        words.withUnsafeBytes { poolJob.contents().copyMemory(from: $0.baseAddress!, byteCount: $0.count) }
    }

    /// The search kernel over counters [start, start + count) of the pool job (keep them below the layout's
    /// `counterLimit`). Returns the counters that hit (at most 62, sorted) and how many the kernel counted.
    func searchJob(start: UInt64, count: Int) throws -> (nonces: [UInt64], hits: Int) {
        var first = start
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("nexapow job search") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(poolJob, offset: 0, index: 1)
            encoder.setBytes(&first, length: 8, index: 2)
            encoder.setBuffer(output, offset: 0, index: 3)
            gpu.dispatch(encoder, searchPipeline, threads: count, group: group)
        }
        let hits = Int(output.contents().load(as: UInt32.self))
        let stored = (output.contents() + 8).bindMemory(to: UInt64.self, capacity: 62)
        return ((0 ..< min(hits, 62)).map { stored[$0] }.sorted(), hits)
    }

    // MARK: Checks

    func knownAnswerTests() throws -> [String] { try NexaPowReference.runVectors() }

    func crossCheck(samples: Int) throws -> String {
        if let profile {
            // Profile kernels count "hits" only for their own consistency checks (profile 40).
            guard profile != 100 else { return "profile mode 100: cross-check skipped" }
            _ = try runBatch(startNonce: 12345, count: 65536)
            return "profile mode \(profile): \(output.contents().load(as: UInt32.self)) flagged of 65536 threads"
        }
        typealias Ref = NexaPowReference
        // 1. Random table entries against CPU scalar multiplication
        let entries = (0 ..< 6).map { _ in Int.random(in: 0 ..< tableEntries) }
        let tableWords = table.contents().bindMemory(to: UInt32.self, capacity: tableEntries * 16)
        for e in entries {
            let w = e >> (window - 1), j = (e & ((1 << (window - 1)) - 1)) + 1
            let expect = Ref.affine(Ref.multiply(Ref.U256(UInt64(j), 0, 0, 0), bases[w]))!
            let got = Array(UnsafeBufferPointer(start: tableWords + 16 * e, count: 16))
            guard got == Ref.limbs32(expect.x) + Ref.limbs32(expect.y) else {
                throw MinerError("table entry \(e) (window \(w), \(j) x base) differs from the CPU")
            }
        }
        // 2. Nonce layouts: Echelon's (8-byte extranonce, 16-byte nonce), Kryptex's subscribe (4 + 4 counter bytes),
        //    and three more, so the counter starts at every byte offset of a block word.
        let count = max(32, samples)
        let shapes = [(4, 8), (3, 12), (5, 16), (2, 10)]
        let layouts = [benchLayout] + (try shapes.map { try NonceLayout(prefix: randomBytes($0.0), length: $0.1) })
        let hits = try layouts.map { try checkLayout($0, count: count) }
        return "\(entries.count) table entries; \(count) nonces per nonce layout (extranonce + counter bytes 8+8 as in Echelon, 4+4,"
            + " 3+8+1, 5+8+3, 2+8) through miningHash, h1, signature, powHash and the target test, and the search kernel's"
            + " hits (\(hits.map(String.init).joined(separator: ", "))) at a median target, match the CPU reference"
    }

    /// A run of consecutive nonces in one layout: the hash kernel's every intermediate and hit flag, and the search
    /// kernel's hit set, against the CPU. The target is the run's median powHash, so about half hit. Returns the hits.
    private func checkLayout(_ layout: NonceLayout, count: Int) throws -> Int {
        typealias Ref = NexaPowReference
        let start = UInt64.random(in: 0 ... (layout.counterLimit ?? UInt64.max) - UInt64(count))
        let nonces = (0 ..< count).map { start + UInt64($0) }
        let cpu = nonces.map { Ref.nexaPow(commitment: commitment, nonce: layout.bytes($0)) }
        let values = cpu.compactMap { $0.powHash.map { Ref.value(be: $0.reversed()) } }.sorted { Ref.compare($0, $1) < 0 }
        guard !values.isEmpty else { throw MinerError("no valid CPU hashes") }
        let target = values[values.count / 2]
        let job = try gpu.buffer(NexaPow.jobWords(commitment: commitment, layout: layout, target: target), label: "nexapow check job")
        let cpuHits = Set(nonces.indices.filter { cpu[$0].powHash.map { Ref.meetsTarget($0, target) } ?? false }.map { nonces[$0] })

        // The hash kernel: every intermediate and the hit flag
        let nonceBuffer = try gpu.buffer(nonces, label: "nexapow nonces")
        let results = try gpu.buffer(count * 48 * 4, label: "nexapow results")
        try gpu.compute("nexapow hash") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(job, offset: 0, index: 1)
            encoder.setBuffer(nonceBuffer, offset: 0, index: 2)
            encoder.setBuffer(results, offset: 0, index: 3)
            gpu.dispatch(encoder, hashPipeline, threads: count, group: 32)
        }
        let r = results.contents().bindMemory(to: UInt32.self, capacity: count * 48)
        func bytes(_ offset: Int, _ words: Int) -> [UInt8] {
            (0 ..< words).flatMap { w in (0 ..< 4).map { UInt8(truncatingIfNeeded: r[offset + w] >> (24 - 8 * UInt32($0))) } }
        }
        let targetTop = Ref.limbs32(target).reversed().prefix(6)
        let shape = "layout \(layout.prefix.count)+\(layout.counterBytes) of \(layout.length) bytes"
        for (i, c) in cpu.enumerated() {
            let base = 48 * i
            let valid = r[base + 40] == 1
            let what = "\(shape), nonce \(layout.bytes(nonces[i]).hex)"
            guard bytes(base, 8) == c.miningHash else { throw MinerError("\(what): GPU miningHash \(bytes(base, 8).hex) vs CPU \(c.miningHash.hex)") }
            guard bytes(base + 8, 8) == c.h1 else { throw MinerError("\(what): GPU h1 \(bytes(base + 8, 8).hex) vs CPU \(c.h1.hex)") }
            guard valid == (c.signature != nil) else { throw MinerError("\(what): GPU valid=\(valid), CPU signature \(c.signature?.hex ?? "nil")") }
            if let sig = c.signature, let pow = c.powHash {
                guard bytes(base + 16, 16) == sig else { throw MinerError("\(what): GPU signature \(bytes(base + 16, 16).hex) vs CPU \(sig.hex)") }
                guard bytes(base + 32, 8) == pow else { throw MinerError("\(what): GPU powHash \(bytes(base + 32, 8).hex) vs CPU \(pow.hex)") }
            }
            let gpuTarget = (0 ..< 6).map { r[base + 42 + $0] }
            guard gpuTarget == Array(targetTop) else { throw MinerError("\(what): the kernel read target words \(gpuTarget), expected \(Array(targetTop))") }
            let gpuHit = r[base + 41] == 1, cpuHit = cpuHits.contains(nonces[i])
            guard gpuHit == cpuHit else {
                let number = c.powHash.map { Array($0.reversed()).hex } ?? "none"
                throw MinerError("\(what): GPU hit \(gpuHit), CPU hit \(cpuHit) for powHash \(number) against target \(Ref.bytesBE(target).hex)")
            }
        }

        // The search kernel (the one that mines) over the same nonces must report exactly the CPU's hits
        var first = start
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("nexapow search check") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(job, offset: 0, index: 1)
            encoder.setBytes(&first, length: 8, index: 2)
            encoder.setBuffer(output, offset: 0, index: 3)
            gpu.dispatch(encoder, searchPipeline, threads: count, group: group)
        }
        let found = Int(output.contents().load(as: UInt32.self))
        let foundNonces = Set((0 ..< min(found, 62)).map { output.contents().load(fromByteOffset: 8 + 8 * $0, as: UInt64.self) })
        guard found == cpuHits.count, foundNonces == cpuHits else {
            throw MinerError("\(shape): search kernel found \(found) hits, CPU expects \(cpuHits.count)")
        }
        return found
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        var start = startNonce
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("nexapow search") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(benchJob, offset: 0, index: 1)   // target 0: unreachable
            encoder.setBytes(&start, length: 8, index: 2)
            encoder.setBuffer(output, offset: 0, index: 3)
            gpu.dispatch(encoder, searchPipeline, threads: count, group: group)
        }
        return Double(count)
    }
}
