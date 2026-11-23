import Foundation
import Metal

// Real pool mining shared by the Ethash coins (ETC, ETHW, OCTA) and KawPow (RVN, QUAI): share targets, seed hashes,
// jobs, and the session loop that turns a Stratum dialect's jobs into GPU batches and submits shares without
// waiting for the replies. KawPow builds on this folder, so everything here is prefixed Ethash.

/// Share targets as pools send them: 32 bytes, big-endian. A hash meets a target when, read as a big-endian number,
/// it is at most the target (Ethereum's and Ravencoin's rule). The search kernels compare the first 8 bytes; the CPU
/// then checks all 32.
enum EthashTarget {
    /// Difficulty 1 in EthereumStratum/1.0.0 (NiceHash's spec, ethminer's getTargetFromDiff): 0x00000000ffff00…00.
    static let stratumDiff1 = 65_535.0 * 0x1p208
    /// Difficulty 1 on Ravencoin pools (MiningCore's RavencoinConstants.Diff1): 0x00000000ff0000…00.
    static let ravencoinDiff1 = 255.0 * 0x1p216

    /// A target from hex, "0x" optional; shorter values are padded on the left. nil when malformed.
    static func parse(_ text: String) -> [UInt8]? {
        var digits = Substring(text)
        if digits.hasPrefix("0x") || digits.hasPrefix("0X") { digits = digits.dropFirst(2) }
        guard !digits.isEmpty, digits.count <= 64 else { return nil }
        return [UInt8](hex: String(repeating: "0", count: 64 - digits.count) + String(digits))
    }

    /// diff1 / difficulty as a target (all ones when that doesn't fit in 256 bits).
    static func fromDifficulty(_ difficulty: Double, diff1: Double) -> [UInt8] {
        bytes(difficulty > 0 ? diff1 / difficulty : .infinity)
    }

    /// A non-negative number below 2^256 as 32 bytes, big-endian; anything larger (or NaN) saturates to all ones.
    static func bytes(_ value: Double) -> [UInt8] {
        guard value < 0x1p256 else { return [UInt8](repeating: 0xFF, count: 32) }
        var rest = max(0, value.rounded(.down))
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0 ..< 32 {
            let scale = Double(sign: .plus, exponent: 8 * (31 - i), significand: 1)
            let byte = (rest / scale).rounded(.down)
            out[i] = UInt8(min(255, byte))
            rest -= byte * scale
        }
        return out
    }

    /// The 32 bytes as a number (53 bits of precision are plenty for targets and difficulties).
    static func value(_ bytes: [UInt8]) -> Double { bytes.reduce(0.0) { $0 * 256 + Double($1) } }

    /// Expected hashes per share at this target: 2^256 / (target + 1). This is a share's `work` for PoolEvents.
    static func work(_ target: [UInt8]) -> Double { 0x1p256 / (value(target) + 1) }

    /// hash <= target, both 32 bytes big-endian.
    static func meets(_ hash: [UInt8], _ target: [UInt8]) -> Bool {
        for i in 0 ..< 32 where hash[i] != target[i] { return hash[i] < target[i] }
        return true
    }

    /// The first 8 bytes as a big-endian number: the search kernels report nonces whose hash's first 8 bytes are <= it.
    static func top64(_ target: [UInt8]) -> UInt64 { target.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) } }
}

/// Seed hashes are keccak256 applied k times to 32 zero bytes; pools send the seed, and k says the epoch.
enum EthashSeeds {
    private static let lock = NSLock()
    private static var known: [[UInt8]] = [[UInt8](repeating: 0, count: 32)]

    /// k with EthashReference.seed(iterations: k) == seed, trying up to `limit` rounds; nil when it isn't a seed hash.
    static func iterations(of seed: [UInt8], limit: Int = 8_192) -> Int? {
        lock.lock()
        defer { lock.unlock() }
        if let k = known.firstIndex(of: seed) { return k }
        while known.count <= limit {
            known.append(Keccak.keccak256(known[known.count - 1]))
            if known[known.count - 1] == seed { return known.count - 1 }
        }
        return nil
    }
}

/// A pool job in the form the GPU search needs.
struct EthashPoolJob: Equatable {
    var id: String
    /// Header hash, the 32 bytes the pool sent, in that order.
    var header: [UInt8]
    /// Seed hash: says the epoch, so the DAG.
    var seed: [UInt8]
    /// Block height when the pool sends one (KawPow's program period needs it).
    var height: Int?
    /// Share target, 32 bytes big-endian.
    var target: [UInt8]
    /// The pool's extranonce: the nonce's most significant bytes.
    var extranonce: [UInt8]

    /// Expected hashes per share.
    var work: Double { EthashTarget.work(target) }
}

/// A share: the nonce, plus the mix digest and final hash the GPU computed (and the CPU recomputed).
struct EthashPoolSolution {
    let nonce: UInt64
    let mix: [UInt8]
    let final: [UInt8]
}

/// The GPU side of pool mining.
protocol EthashPoolSearch: AnyObject {
    var defaultBatch: Int { get }
    /// Readies the GPU for `job`: builds the DAG when the epoch changes (and compiles KawPow's program when the period
    /// does); cheap otherwise. Returns a line for the log when it built something.
    func prepare(_ job: EthashPoolJob) throws -> String?
    /// Hashes `count` nonces from `startNonce` (rounded up to whole threadgroups) for the prepared job. Returns how many
    /// it hashed and the shares that meet the job's full target, each recomputed on the CPU before it's returned.
    func search(startNonce: UInt64, count: Int) throws -> (hashes: Int, solutions: [EthashPoolSolution])
}

/// A pool's Stratum dialect once logged in: its notifications and its submit message.
protocol EthashPoolDialect: AnyObject {
    var name: String { get }
    /// The job to mine now, once the pool has sent one.
    var job: EthashPoolJob? { get }
    /// Handles a notification or pool request; false when it isn't one of this dialect's.
    func handle(_ message: [String: Any], connection: StratumConnection, log: (String) -> Void) throws -> Bool
    /// The submit request for `solution` (the session adds "id").
    func submit(_ solution: EthashPoolSolution, job: EthashPoolJob, login: String) -> [String: Any]
    /// Called every few seconds while mining.
    func idle(_ connection: StratumConnection, log: (String) -> Void) throws
}

/// Reading loosely typed JSON-RPC values.
enum EthashPoolValue {
    /// A 32-byte hash from hex ("0x" optional, shorter values padded on the left).
    static func hash(_ value: Any?) -> [UInt8]? { (value as? String).flatMap(EthashTarget.parse) }

    /// An integer from a JSON number, a decimal string or a 0x-prefixed hex string.
    static func int(_ value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        guard let text = value as? String, !text.isEmpty else { return nil }
        if text.hasPrefix("0x") || text.hasPrefix("0X") { return Int(text.dropFirst(2), radix: 16) }
        return Int(text)
    }

    static func double(_ value: Any?) -> Double? {
        if let number = value as? NSNumber { return number.doubleValue }
        return (value as? String).flatMap { Double($0) }
    }

    /// Job ids are strings in every dialect we speak, but take numbers too.
    static func jobID(_ value: Any?) -> String? {
        if let text = value as? String { return text }
        return (value as? NSNumber)?.stringValue
    }

    /// A message's id as an Int (numbers or numeric strings).
    static func id(_ message: [String: Any]) -> Int? {
        (message["id"] as? NSNumber)?.intValue ?? (message["id"] as? String).flatMap { Int($0) }
    }

    /// A pool's extranonce: even-length hex of at most `maxBytes` bytes ("0x" optional; empty or missing means none).
    static func extranonce(_ value: Any?, maxBytes: Int) throws -> [UInt8] {
        guard let text = value as? String, !text.isEmpty else { return [] }
        var digits = Substring(text)
        if digits.hasPrefix("0x") || digits.hasPrefix("0X") { digits = digits.dropFirst(2) }
        guard digits.count % 2 == 0, digits.count <= 2 * maxBytes, let bytes = [UInt8](hex: String(digits)) else {
            throw MinerError("the pool sent an unusable extranonce \"\(text.prefix(20))\"")
        }
        return bytes
    }
}

/// Connecting and describing, for the miners and their handshakes.
enum EthashPoolKit {
    /// What we tell pools we are.
    static let agent = "metalminer/1.0"

    static func connect(_ endpoint: PoolEndpoint) throws -> StratumConnection {
        try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls, timeout: 15)
    }

    /// A short, safe rendering of something a pool sent (long strings shortened), for handshake reports.
    static func describe(_ value: Any?) -> String {
        switch value {
        case nil, is NSNull: return "null"
        case let text as String: return text.count > 20 ? "\"\(text.prefix(16))…\"" : "\"\(text)\""
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            return number.stringValue
        case let array as [Any]:
            return "[" + array.prefix(8).map { describe($0) }.joined(separator: ", ") + (array.count > 8 ? ", …" : "") + "]"
        case let object as [String: Any]:
            return "{" + object.keys.sorted().prefix(8).map { "\($0): \(describe(object[$0]))" }.joined(separator: ", ") + "}"
        default: return "?"
        }
    }

    /// Everything the pool pushes within `seconds`, one description each (for handshakes: what a pool says unasked).
    static func pushed(_ connection: StratumConnection, seconds: Double) -> [String] {
        var lines: [String] = []
        let end = now() + seconds
        while now() < end, lines.count < 6 {
            do {
                guard let message = try connection.nextNotification(timeout: max(0.05, end - now())) else { continue }
                let method = message["method"] as? String ?? "(no method)"
                let body = message["params"] ?? message["result"]
                lines.append("pushed \(method) \(describe(body))")
            } catch {
                lines.append("then the connection closed (\(error))")
                break
            }
        }
        return lines
    }

    /// Compares a few DAG items built on the GPU (the first, the last and some random ones) with the light cache, so a
    /// bad DAG is caught before any share is submitted.
    static func spotCheck(dag: MTLBuffer, cache: [UInt32], datasetBytes: Int, parents: Int, samples: Int = 8) throws {
        let count = UInt32(datasetBytes / 64)
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: datasetBytes / 4)
        try cache.withUnsafeBufferPointer { c in
            for n in 0 ..< samples {
                let index = n == 0 ? 0 : n == 1 ? count - 1 : UInt32.random(in: 0 ..< count)
                let cpu = EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: index, parents: parents)
                guard cpu == Array(UnsafeBufferPointer(start: words + 16 * Int(index), count: 16)) else {
                    throw MinerError("DAG item \(index) built on the GPU differs from the light cache")
                }
            }
        }
    }
}

/// The mining loop for one pool, any dialect and any GPU search: reads the pool's messages between GPU batches of about
/// 150 ms, submits shares without waiting for their replies, reports the rate every 5 s and each share's result, and
/// follows client.reconnect. The GPU search (and its DAG) outlives connections.
final class EthashPoolSession {
    /// Thrown inside the loop when the pool asks us to reconnect.
    struct ReconnectRequest: Error {
        let endpoint: PoolEndpoint
        let wait: Double
    }

    private(set) var endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    let search: EthashPoolSearch
    /// Seconds between rate reports (tests shorten it).
    var rateInterval = 5.0
    /// Seconds without a reply after which a submitted share counts as not accepted.
    var replyTimeout = 60.0

    private struct Pending {
        let job: String
        let work: Double
        let sent: Double
    }
    private var pending: [Int: Pending] = [:]
    private var nextID = 1_000_000   // far above StratumConnection.call's ids, so replies can't be confused
    private let lock = NSLock()
    private var corruptNext = false

    init(endpoint: PoolEndpoint, login: String, events: PoolEvents, search: EthashPoolSearch) {
        self.endpoint = endpoint
        self.login = login
        self.events = events
        self.search = search
    }

    /// Test hook: the next share goes out with its nonce changed (after the CPU check), so the pool must refuse it.
    func corruptNextShare() {
        lock.lock()
        corruptNext = true
        lock.unlock()
    }

    private func takeCorruption() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let corrupt = corruptNext
        corruptNext = false
        return corrupt
    }

    /// Connects with `connect` (which logs in with the dialect it returns), mines until `shouldStop()`, and reconnects
    /// when the pool asks. Throws when the login is refused or the connection fails.
    func run(shouldStop: () -> Bool, connect: (PoolEndpoint) throws -> (StratumConnection, EthashPoolDialect)) throws {
        while !shouldStop() {
            let (connection, dialect) = try connect(endpoint)
            do {
                try mine(connection, dialect, shouldStop)
                finish(connection, note: "no reply before we disconnected")
                connection.close()
                return
            } catch let request as ReconnectRequest {
                finish(connection, note: "no reply before the pool's reconnect")
                connection.close()
                endpoint = request.endpoint
                events.log("the pool asked us to reconnect; reconnecting to \(endpoint) in \(Int(request.wait)) s")
                let until = now() + request.wait
                while now() < until, !shouldStop() { Thread.sleep(forTimeInterval: 0.1) }
            } catch {
                connection.close()
                abandon("the connection failed before the pool replied")
                throw error
            }
        }
    }

    private func mine(_ connection: StratumConnection, _ dialect: EthashPoolDialect, _ shouldStop: () -> Bool) throws {
        var prepared: EthashPoolJob?
        var prefix: UInt64 = 0, counter: UInt64 = 0, limit = UInt64.max
        var exhausted = false
        var batch = max(4096, search.defaultBatch)
        var windowStart = now(), windowHashes = 0.0
        var lastIdle = now()
        while !shouldStop() {
            // Everything the pool sent since the last batch; wait a little when there's nothing to hash.
            var wait = dialect.job == nil || exhausted ? 0.25 : 0
            while let message = try connection.nextNotification(timeout: wait) {
                wait = 0
                try handle(message, connection, dialect)
            }
            expire()
            if now() - lastIdle >= 5 {
                try dialect.idle(connection, log: events.log)
                lastIdle = now()
            }
            guard let job = dialect.job else { continue }
            if job != prepared {
                let t = now()
                if let line = try search.prepare(job) { events.log(line) }
                if now() - t > 0.5 {   // a DAG build or compile: don't count it against the rate
                    windowStart = now()
                    windowHashes = 0
                }
                if job.id != prepared?.id || job.header != prepared?.header || job.extranonce != prepared?.extranonce {
                    // A new job: a fresh nonce range under the extranonce, from a random point in its lower half.
                    let free = 64 - 8 * job.extranonce.count
                    let high = job.extranonce.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
                    prefix = free >= 64 ? 0 : high << UInt64(free)
                    limit = free >= 64 ? UInt64.max : (UInt64(1) << UInt64(free)) - 1
                    counter = UInt64.random(in: 0 ... limit / 2)
                    exhausted = false
                }
                prepared = job
                continue   // pick up whatever arrived while preparing
            }
            if exhausted { continue }
            if limit - counter < UInt64(batch) + 1 << 16 {
                exhausted = true
                events.log("job \(job.id): this connection's nonce range is used up; waiting for the next job")
                continue
            }
            let t = now()
            let result = try search.search(startNonce: prefix | counter, count: batch)
            let took = max(now() - t, 1e-4)
            counter += UInt64(result.hashes)
            windowHashes += Double(result.hashes)
            batch = min(1 << 26, max(4096, Int(Double(batch) * min(2, max(0.5, 0.15 / took)))))
            for solution in result.solutions { try submit(solution, job, dialect, connection) }
            if now() - windowStart >= rateInterval {
                events.hashrate(windowHashes / (now() - windowStart))
                windowStart = now()
                windowHashes = 0
            }
        }
    }

    /// Share replies, reconnect requests and version queries here; everything else goes to the dialect.
    private func handle(_ message: [String: Any], _ connection: StratumConnection, _ dialect: EthashPoolDialect) throws {
        let method = message["method"] as? String
        if method == nil, let id = EthashPoolValue.id(message), let share = pending.removeValue(forKey: id) {
            let error = stratumError(message)
            let accepted = error == nil && (message["result"] as? Bool ?? false)
            let ms = Int((now() - share.sent) * 1000)
            events.share(accepted, share.work, accepted ? "job \(share.job), \(ms) ms" : "\(error ?? "refused") (job \(share.job))")
            return
        }
        let params = message["params"] as? [Any] ?? []
        switch method {
        case "client.reconnect"?:
            // Only to the same host (a port change is fine); a different host could be anyone.
            var next = endpoint
            if let host = params.first as? String, !host.isEmpty {
                if host.caseInsensitiveCompare(endpoint.host) == .orderedSame {
                    if let port = EthashPoolValue.int(params.count > 1 ? params[1] : nil), let value = UInt16(exactly: port) { next.port = value }
                } else {
                    events.log("the pool asked us to move to \(host.prefix(60)); staying with \(endpoint.host)")
                }
            }
            let wait = Double(EthashPoolValue.int(params.count > 2 ? params[2] : nil) ?? 0)
            throw ReconnectRequest(endpoint: next, wait: min(60, max(1, wait)))
        case "client.get_version"?:
            if let id = message["id"], !(id is NSNull) { try connection.send(["id": id, "result": EthashPoolKit.agent, "error": NSNull()]) }
        case "client.show_message"?:
            if let text = params.first as? String { events.log("pool message: \(text.prefix(120))") }
        default:
            if try dialect.handle(message, connection: connection, log: events.log) { return }
            if method != nil, let id = message["id"], !(id is NSNull) {
                try connection.send(["id": id, "result": NSNull(), "error": "method not found"])
            }
        }
    }

    private func submit(_ found: EthashPoolSolution, _ job: EthashPoolJob, _ dialect: EthashPoolDialect,
                        _ connection: StratumConnection) throws {
        let solution = takeCorruption() ? EthashPoolSolution(nonce: found.nonce ^ 1, mix: found.mix, final: found.final) : found
        var request = dialect.submit(solution, job: job, login: login)
        let id = nextID
        nextID += 1
        request["id"] = id
        pending[id] = Pending(job: job.id, work: job.work, sent: now())
        try connection.send(request)
    }

    /// Shares the pool hasn't answered within `replyTimeout` count as not accepted.
    private func expire() {
        let cutoff = now() - replyTimeout
        for (id, share) in pending where share.sent < cutoff {
            pending[id] = nil
            events.share(false, share.work, "no reply from the pool within \(Int(replyTimeout)) s (job \(share.job))")
        }
    }

    /// Before closing: up to 3 s for the replies to shares still in flight.
    private func finish(_ connection: StratumConnection, note: String) {
        let end = now() + 3
        while !pending.isEmpty, now() < end {
            do {
                guard let message = try connection.nextNotification(timeout: 0.1) else { continue }
                if message["method"] == nil, let id = EthashPoolValue.id(message), let share = pending.removeValue(forKey: id) {
                    let error = stratumError(message)
                    let accepted = error == nil && (message["result"] as? Bool ?? false)
                    events.share(accepted, share.work, accepted ? "job \(share.job)" : "\(error ?? "refused") (job \(share.job))")
                }
            } catch {
                break
            }
        }
        abandon(note)
    }

    private func abandon(_ note: String) {
        for share in pending.values { events.share(false, share.work, "\(note) (job \(share.job))") }
        pending.removeAll()
    }
}

/// Runs a pool miner on its own thread for a selfTest, records what it reports, and stops it again.
final class EthashPoolTestRun: @unchecked Sendable {
    /// Not anyone's account: the mock pools expect exactly this.
    static let login = "selftest/metalminer"

    private let lock = NSLock()
    private var stopping = false
    private var failure: Error?
    private var returned = false
    private var running = false
    private let done = DispatchSemaphore(value: 0)
    private var shareLog: [(accepted: Bool, work: Double, note: String?)] = []
    private var rateLog: [Double] = []
    private var lineLog: [String] = []

    func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    var events: PoolEvents {
        PoolEvents(
            share: { [self] accepted, work, note in locked { shareLog.append((accepted, work, note)) } },
            hashrate: { [self] rate in locked { rateLog.append(rate) } },
            log: { [self] line in locked { lineLog.append(line) } })
    }

    var shares: [(accepted: Bool, work: Double, note: String?)] { locked { shareLog } }
    var rates: [Double] { locked { rateLog } }
    var lines: [String] { locked { lineLog } }

    func start(_ miner: PoolMiner) {
        running = true
        let thread = Thread { [self] in
            do {
                try miner.run(shouldStop: { self.locked { self.stopping } })
            } catch {
                locked { failure = error }
            }
            locked { returned = true }
            done.signal()
        }
        thread.name = "selfTest miner"
        thread.start()
    }

    /// Polls `condition` until it holds; throws if the miner fails or returns first, or after `timeout` seconds.
    func waitFor(_ what: String, timeout: Double, _ condition: () -> Bool) throws {
        let end = now() + timeout
        while !condition() {
            if let failure = locked({ failure }) { throw MinerError("the miner failed while waiting for \(what): \(failure)") }
            if locked({ returned }) { throw MinerError("the miner returned while waiting for \(what)") }
            guard now() < end else { throw MinerError("no \(what) within \(Int(timeout)) s") }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    /// Asks the miner to stop and waits for run() to return; rethrows what run() threw.
    func stop(timeout: Double = 60) throws {
        guard running else { return }
        running = false
        locked { stopping = true }
        if done.wait(timeout: .now() + timeout) == .timedOut { throw MinerError("the miner didn't stop within \(Int(timeout)) s") }
        if let failure = locked({ failure }) { throw failure }
    }
}

extension EthashPoolTestRun {
    /// The search's own rate on its prepared job: whole batches of about 150 ms for `seconds`, outside the session loop.
    static func rawRate(_ search: EthashPoolSearch, seconds: Double) throws -> Double {
        var batch = search.defaultBatch, hashes = 0, nonce = UInt64.random(in: 0 ..< (1 << 62))
        let start = now()
        while now() - start < seconds {
            let t = now()
            let result = try search.search(startNonce: nonce, count: batch)
            nonce &+= UInt64(result.hashes)
            hashes += result.hashes
            batch = min(1 << 26, max(4096, Int(Double(batch) * min(2, max(0.5, 0.15 / max(now() - t, 1e-4))))))
        }
        return Double(hashes) / (now() - start)
    }
}

extension EthashPoolTestRun {
    /// A fresh miner with a login the mock refuses: run() has to stop straight away with PoolLoginRefused carrying the
    /// pool's words, so the engine skips the coin instead of retrying.
    static func refusedLogin(_ type: PoolMiner.Type, gpu: GPU, endpoint: PoolEndpoint) throws -> PoolLoginRefused {
        let miner = try type.init(gpu: gpu, endpoint: endpoint, login: "selftest/refused", events: PoolEvents())
        let deadline = now() + 30
        do {
            try miner.run(shouldStop: { now() > deadline })
        } catch let refused as PoolLoginRefused {
            return refused
        }
        throw MinerError("a login the pool refused didn't stop the miner with PoolLoginRefused")
    }
}
