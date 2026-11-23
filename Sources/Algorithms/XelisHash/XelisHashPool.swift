import Foundation
import Metal

// Real XEL mining on Kryptex Pool: the XELIS stratum protocol on top of the verified v3 kernel.
// Protocol notes, sources and what only a live test can confirm: docs/specs/xelishash.md, "Pool protocol".

// MARK: - Job-driven GPU search

extension XelisHashV3 {
    /// One dispatch of `slots` nonces from `start` over a pool job's 112-byte MinerWork; the kernel writes each nonce
    /// big-endian at bytes 40..<48. Returns the hits (PoW hash <= target, both read big-endian) with their GPU hashes, at
    /// most 62 of them (SEARCH_MAX_HITS), and how many the dispatch found in all.
    func searchJob(work: [UInt8], target: [UInt8], start: UInt64) throws -> (hits: [(nonce: UInt64, hash: [UInt8])], total: Int) {
        precondition(work.count == 112 && target.count == 32)
        resetHits()
        let p = params(work: work, target: target, start: start, count: slots, storeHashes: true)
        try gpu.compute("xelishash pool search") { encoder in encodeSearch(encoder, p, count: slots) }
        let total = Int(output.contents().load(as: UInt32.self))
        let words = hashes.contents().bindMemory(to: UInt32.self, capacity: slots * 8)
        let found = hits().map { nonce -> (nonce: UInt64, hash: [UInt8]) in
            let slot = Int(nonce &- start)
            var bytes: [UInt8] = []
            for w in 0 ..< 8 { bytes.appendLE(words[8 * slot + w]) }
            return (nonce, bytes)
        }
        return (found, total)
    }
}

// MARK: - Stratum

/// A XELIS stratum job as GPU input.
struct XelisHashPoolJob {
    let id: String
    /// The 112-byte MinerWork: header work hash | timestamp ms (u64 BE) | nonce (zero here; the kernel fills it) |
    /// extra nonce | pool public key.
    let work: [UInt8]
    /// floor((2^256 - 1) / difficulty), 32 bytes big-endian: a share's PoW hash, read big-endian, must be <= it.
    let target: [UInt8]
    /// The share difficulty, which is also the expected hashes per share (the share's `work`).
    let difficulty: Double

    init(id: String, header: [UInt8], timestamp: UInt64, extraNonce: [UInt8], publicKey: [UInt8], difficulty: Double) {
        self.id = id
        work = header + XelisHashReference.be64(timestamp) + [UInt8](repeating: 0, count: 8) + extraNonce + publicKey
        target = XelisHashPoolMiner.target(difficulty: difficulty)
        self.difficulty = difficulty
    }
}

/// XEL on Kryptex Pool (slug "xel") with the XELIS stratum protocol, v0.1.1 (docs.xelis.io/developers-api/stratum):
/// mining.subscribe [agent, ["xel/v3"]] -> [session, extra nonce hex, its length, pool public key hex];
/// mining.authorize [login, worker, password] -> true. The pool then sends mining.set_difficulty [d],
/// mining.notify [job, timestamp ms hex, header work hash, algorithm, clean], and may send mining.set_extranonce,
/// mining.ping (answered with mining.pong), mining.print and client.reconnect. Shares go out as
/// mining.submit [worker, job, nonce hex], the 8 nonce bytes exactly as they sit at MinerWork bytes 40..<48.
final class XelisHashPoolMiner: PoolMiner {
    static let pools = ["xel"]
    static let algorithm = XelisHashV3.id
    static let agent = "MetalMiner/1.0"

    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    let hasher: XelisHashV3
    /// Seconds between hashrate reports, and without any new job before the connection counts as dead.
    var rateInterval = 5.0
    var jobTimeout = 120.0
    /// selfTest hooks: where the nonce counter starts, and which submitted share (1-based) goes out with a nonce that
    /// misses the target instead.
    var testStartNonce: UInt64?
    var testCorruptShare: Int?

    convenience init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        try self.init(gpu: gpu, endpoint: endpoint, login: login, events: events, config: AlgoConfig())
    }

    /// `config` sizes the kernel as for benchmarks: 2048 scratchpads (1.04 GiB) by default, 256 with `quick`.
    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents, config: AlgoConfig) throws {
        self.endpoint = endpoint
        self.login = login
        self.events = events
        hasher = try XelisHashV3(gpu: gpu, config: config)
    }

    /// The worker part of Kryptex's "wallet/worker" or "username/worker" login: mining.authorize's second parameter and
    /// mining.submit's first, as the spec names them.
    var worker: String {
        guard let slash = login.lastIndex(of: "/"), login.index(after: slash) < login.endIndex else { return "metalminer" }
        return String(login[login.index(after: slash)...])
    }

    /// The share target for a pool difficulty: floor((2^256 - 1) / d), big-endian. A fractional difficulty is rounded up
    /// (a slightly harder target, so every share still meets the pool's); d <= 1 gives the all-ones target.
    static func target(difficulty: Double) -> [UInt8] {
        guard difficulty > 1 else { return [UInt8](repeating: 0xFF, count: 32) }
        let d = difficulty.rounded(.up)
        return XelisHashReference.target(difficulty: d >= 0x1p64 ? .max : UInt64(d))
    }

    // MARK: Session

    private enum Outcome { case stopped, reconnect(Double) }

    /// What the pool has told one connection, and the shares still waiting for an answer.
    private struct State {
        var extraNonce: [UInt8]
        var publicKey: [UInt8]
        var counter: UInt64
        var difficulty: Double?        // the latest mining.set_difficulty
        var jobDifficulty: Double?     // what the current job is mined at
        var jobID = ""
        var header: [UInt8]?
        var timestamp: UInt64 = 0
        var job: XelisHashPoolJob?
        var submitted = 0
        var nextID = 1000              // our own request ids for shares (call() numbers from 1)
        var pending: [Int: Double] = [:]
        var lastJob = now()

        init(extraNonce: [UInt8], publicKey: [UInt8], counter: UInt64) {
            self.extraNonce = extraNonce
            self.publicKey = publicKey
            self.counter = counter
        }

        /// The GPU job from the current fields; none until both a job and a share difficulty have arrived.
        mutating func rebuild() {
            guard let header, let jobDifficulty else {
                job = nil
                return
            }
            job = XelisHashPoolJob(id: jobID, header: header, timestamp: timestamp, extraNonce: extraNonce,
                                   publicKey: publicKey, difficulty: jobDifficulty)
        }
    }

    func run(shouldStop: () -> Bool) throws {
        while !shouldStop() {
            guard case .reconnect(let wait) = try mine(shouldStop: shouldStop) else { return }
            events.log("xel: the pool asked for a reconnect; reconnecting to \(endpoint) in \(Int(wait)) s")
            let resume = now() + wait
            while now() < resume, !shouldStop() { Thread.sleep(forTimeInterval: 0.1) }
        }
    }

    /// One connection: subscribe, authorize, then mine until told to stop or to reconnect.
    private func mine(shouldStop: () -> Bool) throws -> Outcome {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        defer { connection.close() }
        let subscribed = try connection.call("mining.subscribe", params: [Self.agent, ["xel/v3"]])
        if let error = stratumError(subscribed) { throw MinerError("xel: mining.subscribe refused: \(error)") }
        guard let result = subscribed["result"] as? [Any], result.count >= 4,
              let extraNonce = Self.extraNonce(result[1], length: result[2]), let publicKey = Self.publicKey(result[3]) else {
            throw MinerError("xel: unexpected mining.subscribe result \(Self.compact(subscribed["result"]))")
        }
        let authorized = try connection.call("mining.authorize", params: [login, worker, "x"])
        if let error = stratumError(authorized) { throw PoolLoginRefused(login: login, reason: error) }
        guard authorized["result"] as? Bool == true else {
            throw PoolLoginRefused(login: login, reason: "no reason given (authorize answered \(Self.compact(authorized["result"])))")
        }
        events.log("xel: logged in as \(login) at \(endpoint)")

        var state = State(extraNonce: extraNonce, publicKey: publicKey,
                          counter: testStartNonce ?? UInt64.random(in: 0 ..< (1 << 62)))
        var lastRate = now()
        var hashed = 0.0
        while !shouldStop() {
            while let message = try connection.nextNotification(timeout: 0) {
                if let outcome = try handle(message, &state, connection) { return outcome }
            }
            if now() - state.lastJob > jobTimeout { throw MinerError("xel: no job from the pool in \(Int(jobTimeout)) s") }
            guard let job = state.job else {
                if let message = try connection.nextNotification(timeout: 0.25),
                   let outcome = try handle(message, &state, connection) { return outcome }
                continue
            }
            let start = state.counter
            state.counter &+= UInt64(hasher.slots)
            let found = try hasher.searchJob(work: job.work, target: job.target, start: start)
            hashed += Double(hasher.slots)
            if found.total > found.hits.count {
                events.log("xel: \(found.total - found.hits.count) shares beyond the per-dispatch limit were dropped")
            }
            if !found.hits.isEmpty { try submit(found.hits, job, &state, connection) }
            if now() - lastRate >= rateInterval {
                events.hashrate(hashed / (now() - lastRate))
                lastRate = now()
                hashed = 0
            }
        }
        settle(&state, connection)
        return .stopped
    }

    /// After a stop: up to 2 s for the answers to shares still in flight, so each one is reported.
    private func settle(_ state: inout State, _ connection: StratumConnection) {
        let end = now() + 2
        while !state.pending.isEmpty, now() < end {
            do {
                if let message = try connection.nextNotification(timeout: max(0.01, end - now())) {
                    _ = try handle(message, &state, connection)
                }
            } catch {
                return
            }
        }
    }

    /// Applies one message from the pool; returns an outcome when the connection should end.
    private func handle(_ message: [String: Any], _ state: inout State, _ connection: StratumConnection) throws -> Outcome? {
        // The answer to one of our shares, by the rule StratumConnection applies to calls: no method, or a result or error.
        let isReply = message["method"] == nil || message["result"] != nil || stratumError(message) != nil
        if isReply, let id = Self.integer(message["id"]), let difficulty = state.pending.removeValue(forKey: id) {
            let error = stratumError(message)
            let accepted = error == nil && message["result"] as? Bool == true
            events.share(accepted, difficulty, accepted ? nil : error ?? "rejected (result \(Self.compact(message["result"])))")
            return nil
        }
        guard let method = message["method"] as? String else { return nil }   // an answer to nothing we track
        let params = message["params"] as? [Any] ?? []
        switch method {
        case "mining.set_difficulty":
            guard let difficulty = Self.number(params.first), difficulty > 0 else {
                events.log("xel: ignoring mining.set_difficulty \(Self.compact(params))")
                return nil
            }
            if difficulty != state.difficulty { events.log("xel: share difficulty \(Self.format(difficulty))") }
            state.difficulty = difficulty
            // A harder target applies at once, an easier one from the next job; a job that was waiting for its first
            // difficulty starts now.
            if state.jobDifficulty.map({ difficulty > $0 }) ?? true {
                state.jobDifficulty = difficulty
                state.rebuild()
            }
        case "mining.notify":
            guard params.count >= 3, let id = Self.string(params[0]), let timestamp = Self.timestamp(params[1]),
                  let headerHex = params[2] as? String, let header = [UInt8](hex: headerHex), header.count == 32 else {
                events.log("xel: ignoring malformed mining.notify \(Self.compact(params))")
                return nil
            }
            state.lastJob = now()
            let name = params.count > 3 ? (params[3] as? String ?? "") : ""
            if ["xel/v1", "xel/0", "xel/v2", "xel/1"].contains(name.lowercased()) {
                events.log("xel: job \(id) is for \(name), not xelis-hash v3; waiting for a v3 job")
                state.header = nil
                state.rebuild()
                return nil
            }
            if state.jobID.isEmpty {
                if !["xel/v3", "xel/2", ""].contains(name.lowercased()) {
                    events.log("xel: unknown algorithm name \(name); mining it as xelis-hash v3")
                }
                events.log("xel: first job \(id) (\(name.isEmpty ? "no algorithm name" : name)), share difficulty "
                    + (state.difficulty.map { Self.format($0) } ?? "not sent yet (waiting for mining.set_difficulty)"))
            }
            state.jobID = id
            state.header = header
            state.timestamp = timestamp
            state.jobDifficulty = state.difficulty
            state.rebuild()
        case "mining.set_extranonce":
            guard let extraNonce = Self.extraNonce(params.first, length: params.count > 1 ? params[1] : nil) else {
                events.log("xel: ignoring mining.set_extranonce \(Self.compact(params))")
                return nil
            }
            state.extraNonce = extraNonce
            if params.count > 2, let key = Self.publicKey(params[2]) { state.publicKey = key }
            state.rebuild()   // the pool checks shares against the new extra nonce from now on
            events.log("xel: new extra nonce from the pool")
        case "mining.ping":
            try connection.send(["id": message["id"] ?? NSNull(), "method": "mining.pong"])
        case "mining.print":
            events.log("xel pool: " + (params.count > 1 ? "\(params[1])" : Self.compact(params)))
        case "client.reconnect", "mining.reconnect":
            let wait = params.count > 2 ? Self.number(params[2]) ?? 0 : 0
            return .reconnect(min(max(wait, 1), 60))
        default:
            events.log("xel: ignoring \(method)")
        }
        return nil
    }

    /// Checks each GPU hit on the CPU reference, then sends it without waiting for the answer.
    private func submit(_ hits: [(nonce: UInt64, hash: [UInt8])], _ job: XelisHashPoolJob, _ state: inout State,
                        _ connection: StratumConnection) throws {
        let cpu = XelisHashReference.V3.hashes(work: job.work, nonces: hits.map { $0.nonce })
        for (k, hit) in hits.enumerated() {
            guard cpu[k] == hit.hash, XelisHashReference.meets(cpu[k], job.target) else {
                events.log("xel: nonce \(Self.nonceHex(hit.nonce)): GPU hash \(hit.hash.hex) differs from the CPU's \(cpu[k].hex); not submitted")
                continue
            }
            state.submitted += 1
            let nonce = state.submitted == testCorruptShare ? failingNonce(after: hit.nonce, job) : hit.nonce
            let id = state.nextID
            state.nextID += 1
            state.pending[id] = job.difficulty
            try connection.send(["id": id, "method": "mining.submit", "params": [worker, job.id, Self.nonceHex(nonce)]])
        }
    }

    /// The first nonce after `nonce` whose hash misses the job's target (selfTest's deliberately invalid share).
    private func failingNonce(after nonce: UInt64, _ job: XelisHashPoolJob) -> UInt64 {
        var n = nonce
        repeat { n &+= 1 } while XelisHashReference.meets(XelisHashReference.V3.hashes(work: job.work, nonces: [n])[0], job.target)
        return n
    }

    // MARK: Live check

    /// Connects without logging in, sends only mining.subscribe (the protocol's first message, before authorize) and
    /// reports the answer plus anything else the pool sends within 2 s.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls, timeout: 10)
        defer { connection.close() }
        let reply = try connection.call("mining.subscribe", params: [agent, ["xel/v3"]], timeout: 10)
        var pushed: [String] = []
        let end = now() + 2
        do {
            while now() < end {
                if let message = try connection.nextNotification(timeout: max(0.01, end - now())) {
                    pushed.append(message["method"] as? String ?? compact(message))
                }
            }
        } catch {
            pushed.append("then the pool closed the connection (\(error))")
        }
        var text = "mining.subscribe -> \(compact(reply))"
        if let error = stratumError(reply) {
            text += " · refused: \(error)"
        } else if let result = reply["result"] as? [Any], result.count >= 4, let raw = result[1] as? String,
                  extraNonce(result[1], length: result[2]) != nil, publicKey(result[3]) != nil {
            text += " · XELIS stratum subscribe result: session \(result[0]), \(raw.count / 2)-byte extra nonce"
                + " (declared \(compact(result[2]))), 32-byte pool public key"
        } else {
            text += " · NOT the XELIS stratum subscribe result [session, extra nonce, length, public key]"
        }
        return text + (pushed.isEmpty ? " · nothing else within 2 s" : " · then: " + pushed.joined(separator: ", "))
    }

    // MARK: JSON helpers

    /// mining.subscribe's and mining.set_extranonce's extra nonce: hex, at most 32 bytes (cut to the declared length if
    /// shorter), left-aligned in MinerWork bytes 48..<80 with zeros after it.
    static func extraNonce(_ hex: Any?, length: Any?) -> [UInt8]? {
        guard let text = hex as? String, var bytes = [UInt8](hex: text), bytes.count <= 32 else { return nil }
        if let n = integer(length), n >= 0, n < bytes.count { bytes = Array(bytes[0 ..< n]) }
        return bytes + [UInt8](repeating: 0, count: 32 - bytes.count)
    }

    static func publicKey(_ hex: Any?) -> [UInt8]? {
        guard let text = hex as? String, let bytes = [UInt8](hex: text), bytes.count == 32 else { return nil }
        return bytes
    }

    /// mining.notify's timestamp: milliseconds as hex text (the spec), or a plain number.
    static func timestamp(_ value: Any?) -> UInt64? {
        if let text = value as? String {
            return UInt64(text.hasPrefix("0x") || text.hasPrefix("0X") ? String(text.dropFirst(2)) : text, radix: 16)
        }
        return (value as? NSNumber)?.uint64Value
    }

    static func nonceHex(_ nonce: UInt64) -> String { String(format: "%016llx", nonce) }

    static func number(_ value: Any?) -> Double? {
        if let n = value as? NSNumber { return n.doubleValue }
        return (value as? String).flatMap { Double($0) }
    }

    static func integer(_ value: Any?) -> Int? {
        if let n = value as? NSNumber { return n.intValue }
        return (value as? String).flatMap { Int($0) }
    }

    static func string(_ value: Any?) -> String? {
        if let s = value as? String { return s }
        return (value as? NSNumber)?.stringValue
    }

    static func format(_ d: Double) -> String {
        d == d.rounded() && d < 1e15 ? String(Int64(d)) : String(format: "%.6g", d)
    }

    /// A JSON value as compact text for logs, cut at 400 characters.
    static func compact(_ value: Any?) -> String {
        guard let value, !(value is NSNull) else { return "null" }
        guard JSONSerialization.isValidJSONObject(value), let data = try? JSONSerialization.data(withJSONObject: value),
              let text = String(data: data, encoding: .utf8) else { return "\(value)" }
        return text.count > 400 ? String(text.prefix(400)) + "…" : text
    }
}
