import Foundation

// Real QTC mining on Kryptex Pool: the XMRig-style JSON-RPC stratum that pools and SRBMiner-MULTI speak for Quantus,
// on top of the verified Poseidon2 search kernel. Protocol notes, sources and what only a live test can confirm:
// docs/specs/poseidon2.md, "Pool protocol".

/// QTC on Kryptex Pool (slug "qtc"): login {login, pass, agent} -> {id, job, status, extensions}; the pool pushes
/// `job` {clean_jobs, job: {job_id, mining_hash, extranonce, target, difficulty}}; shares go out as submit {id (session),
/// job_id, nonce (the 64-byte nonce as hex, starting with the extranonce), result (the 64-byte hash as hex)};
/// keepalived {id} after a minute without other requests. Every request carries "jsonrpc": "2.0".
final class Poseidon2PoolMiner: PoolMiner {
    typealias R = Poseidon2Reference
    static let pools = ["qtc"]
    static let algorithm = Poseidon2Quantus.id
    static let agent = "MetalMiner/1.0"

    /// One pool job as GPU input.
    struct Job {
        let id: String
        /// mining_hash: the 32-byte pre-seal block hash.
        let header: [UInt8]
        /// Nonce bytes 0..<56: the pool's extranonce, then this connection's own bytes. The GPU walks bytes 56..<64.
        let noncePrefix: [UInt8]
        /// The sponge after the header and nonce bytes 0..<56 (Poseidon2Quantus.jobState).
        let state: [UInt64]
        /// U512 share target, most significant word first: a share is valid when its hash (big-endian) is < target.
        let target: [UInt64]
        /// Expected hashes per share, which is the share's `work`.
        let difficulty: Double
        /// Set when the job's target and difficulty fields disagree; the harder of the two is mined.
        let warning: String?

        /// The 64-byte nonce for a counter: the prefix, then the counter big-endian.
        func nonce(_ counter: UInt64) -> [UInt8] {
            var bytes = noncePrefix
            bytes.appendLE(counter.byteSwapped)
            return bytes
        }
    }

    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    let hasher: Poseidon2Quantus
    /// Seconds between hashrate reports, without any new job before the connection counts as dead, and without any
    /// request before a keepalived; GPU seconds per dispatch (the nonce count adapts to it).
    var rateInterval = 5.0
    var jobTimeout = 300.0
    var keepaliveInterval = 60.0
    var dispatchSeconds = 0.15
    /// selfTest hook: which submitted share (1-based) goes out with a nonce that misses the target instead.
    var testCorruptShare: Int?

    convenience init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        try self.init(gpu: gpu, endpoint: endpoint, login: login, events: events, config: AlgoConfig())
    }

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents, config: AlgoConfig) throws {
        self.endpoint = endpoint
        self.login = login
        self.events = events
        hasher = try Poseidon2Quantus(gpu: gpu, config: config)
    }

    /// A job object from login's result or a `job` push. The target (64 bytes hex, big-endian U512) is used as sent, a
    /// difficulty d gives U512::MAX / d, and when both are present and disagree by more than 1 % (a target in the other
    /// byte order, say) the harder one is mined and the job carries a warning. `fill` (56 bytes) supplies the nonce bytes
    /// after the extranonce. A share's work is the difficulty field, or the target's when there is none.
    static func job(from object: [String: Any], fill: [UInt8]) throws -> Job {
        guard let id = string(object["job_id"]) else { throw MinerError("qtc: job without job_id: \(compact(object))") }
        guard let hashHex = object["mining_hash"] as? String, let header = [UInt8](hex: hashHex), header.count == 32 else {
            throw MinerError("qtc: job \(id) has no 32-byte mining_hash: \(compact(object))")
        }
        var extraNonce: [UInt8] = []
        if let hex = object["extranonce"] as? String, !hex.isEmpty {
            guard let bytes = [UInt8](hex: hex), bytes.count <= 56 else { throw MinerError("qtc: job \(id) has a bad extranonce \(hex)") }
            extraNonce = bytes
        }
        let difficulty = number(object["difficulty"]).flatMap { $0 >= 1 ? $0 : nil }
        let fromDifficulty = difficulty.map { R.target(difficulty: $0 >= 0x1p64 ? .max : UInt64($0.rounded(.up))) }
        var sent: [UInt64]?
        if let hex = object["target"] as? String, let bytes = [UInt8](hex: hex), bytes.count == 64 { sent = R.words(bytes) }
        var warning: String?
        let target: [UInt64]
        switch (sent, fromDifficulty) {
        case let (sent?, fromDifficulty?):
            target = R.less(sent, fromDifficulty) ? sent : fromDifficulty
            if let difficulty, abs(estimatedDifficulty(sent) / difficulty - 1) > 0.01 {
                warning = "its target means difficulty \(format(estimatedDifficulty(sent))) but its difficulty"
                    + " field says \(format(difficulty)); mining at the harder of the two"
            }
        case let (sent?, nil):
            target = sent
        case let (nil, fromDifficulty?):
            target = fromDifficulty
        default:
            throw MinerError("qtc: job \(id) has neither a 64-byte target nor a difficulty: \(compact(object))")
        }
        let prefix = extraNonce + fill[extraNonce.count ..< 56]
        return Job(id: id, header: header, noncePrefix: prefix, state: Poseidon2Quantus.jobState(header: header, noncePrefix: prefix),
                   target: target, difficulty: difficulty ?? estimatedDifficulty(target), warning: warning)
    }

    /// Expected hashes per share for a U512 target: about 2^512 / target, from its two leading words.
    static func estimatedDifficulty(_ target: [UInt64]) -> Double {
        guard let k = target.firstIndex(where: { $0 != 0 }) else { return .infinity }
        let lead = Double(target[k]) + (k + 1 < target.count ? Double(target[k + 1]) / 0x1p64 : 0)
        return pow(2, 64 * Double(k + 1)) / lead
    }

    // MARK: Session

    private enum Outcome { case stopped, reconnect(Double) }
    private enum Pending { case share(Double), keepalive }

    /// What the pool has told one connection, and the requests still waiting for an answer.
    private struct State {
        let session: String
        /// Nonce bytes after the extranonce, random per connection.
        let fill = randomBytes(56)
        var counter = UInt64.random(in: 0 ..< (1 << 62))
        var job: Job?
        var submitted = 0
        var nextID = 1000              // our own request ids (call() numbers from 1)
        var pending: [Int: Pending] = [:]
        var lastJob = now()
        var lastSend = now()

        init(session: String) {
            self.session = session
        }

        var sharesPending: Bool {
            pending.values.contains { if case .share = $0 { return true } else { return false } }
        }
    }

    func run(shouldStop: () -> Bool) throws {
        while !shouldStop() {
            guard case .reconnect(let wait) = try mine(shouldStop: shouldStop) else { return }
            events.log("qtc: the pool asked for a reconnect; reconnecting to \(endpoint) in \(Int(wait)) s")
            let resume = now() + wait
            while now() < resume, !shouldStop() { Thread.sleep(forTimeInterval: 0.1) }
        }
    }

    /// One connection: log in, then mine until told to stop or to reconnect.
    private func mine(shouldStop: () -> Bool) throws -> Outcome {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        connection.requestFields = ["jsonrpc": "2.0"]
        defer { connection.close() }
        let reply = try connection.call("login", params: ["login": login, "pass": "x", "agent": Self.agent])
        if let error = stratumError(reply) { throw PoolLoginRefused(login: login, reason: error) }
        guard let result = reply["result"] as? [String: Any] else {
            if reply["result"] as? Bool == false { throw PoolLoginRefused(login: login, reason: "no reason given") }
            throw MinerError("qtc: login \(login): no result in \(Self.compact(reply))")
        }
        if let status = result["status"] as? String, status.uppercased() != "OK" {
            throw PoolLoginRefused(login: login, reason: status)
        }
        var state = State(session: Self.string(result["id"]) ?? "")
        if let job = result["job"] as? [String: Any] { try accept(job, &state) }
        events.log("qtc: logged in as \(login) at \(endpoint)")

        var batch = 1 << 22
        var lastRate = now()
        var hashed = 0.0
        while !shouldStop() {
            while let message = try connection.nextNotification(timeout: 0) {
                if let outcome = try handle(message, &state, connection) { return outcome }
            }
            if now() - state.lastJob > jobTimeout { throw MinerError("qtc: no job from the pool in \(Int(jobTimeout)) s") }
            if now() - state.lastSend > keepaliveInterval {
                try send("keepalived", ["id": state.session], .keepalive, &state, connection)
            }
            guard let job = state.job else {
                if let message = try connection.nextNotification(timeout: 0.25),
                   let outcome = try handle(message, &state, connection) { return outcome }
                continue
            }
            let start = state.counter
            state.counter &+= UInt64(batch)
            let began = now()
            let found = try hasher.search(state: job.state, start: start, count: batch, target: job.target)
            let took = max(now() - began, 1e-4)
            hashed += Double(batch)
            if found.total > found.hits.count {
                events.log("qtc: \(found.total - found.hits.count) shares beyond the per-dispatch limit were dropped")
            }
            if !found.hits.isEmpty { try submit(found.hits, job, &state, connection) }
            batch = min(1 << 27, max(1 << 16, Int(Double(batch) * min(2, max(0.5, dispatchSeconds / took)))))
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
        while state.sharesPending, now() < end {
            do {
                if let message = try connection.nextNotification(timeout: max(0.01, end - now())) {
                    _ = try handle(message, &state, connection)
                }
            } catch {
                return
            }
        }
    }

    private func accept(_ object: [String: Any], _ state: inout State) throws {
        let job = try Self.job(from: object, fill: state.fill)
        if state.job == nil {
            events.log("qtc: first job \(job.id): extranonce \(object["extranonce"] as? String ?? "none"), share difficulty \(Self.format(job.difficulty))")
        } else if job.difficulty != state.job?.difficulty {
            events.log("qtc: share difficulty \(Self.format(job.difficulty))")
        }
        if let warning = job.warning, warning != state.job?.warning { events.log("qtc: job \(job.id): \(warning)") }
        state.job = job
        state.lastJob = now()
    }

    /// Applies one message from the pool; returns an outcome when the connection should end.
    private func handle(_ message: [String: Any], _ state: inout State, _ connection: StratumConnection) throws -> Outcome? {
        // The answer to a submit or keepalived of ours, by the rule StratumConnection applies to calls: no method, or a
        // result or error.
        let isReply = message["method"] == nil || message["result"] != nil || stratumError(message) != nil
        if isReply, let id = Self.integer(message["id"]), let pending = state.pending.removeValue(forKey: id) {
            let error = stratumError(message)
            switch pending {
            case .share(let difficulty):
                let status = (message["result"] as? [String: Any])?["status"] as? String
                let accepted = error == nil && (status?.uppercased() == "OK" || message["result"] as? Bool == true)
                events.share(accepted, difficulty, accepted ? nil : error ?? "rejected (result \(Self.compact(message["result"])))")
            case .keepalive:
                if let error { events.log("qtc: keepalived refused: \(error)") }
            }
            return nil
        }
        guard let method = message["method"] as? String else { return nil }   // an answer to nothing we track
        switch method {
        case "job":
            guard let params = message["params"] as? [String: Any] else {
                events.log("qtc: ignoring job without params: \(Self.compact(message))")
                return nil
            }
            do {
                try accept(params["job"] as? [String: Any] ?? params, &state)
            } catch {
                events.log("\(error)")
            }
        case "client.reconnect":
            let params = message["params"] as? [Any] ?? []
            let wait = params.count > 2 ? Self.number(params[2]) ?? 0 : 0
            return .reconnect(min(max(wait, 1), 60))
        default:
            events.log("qtc: ignoring \(method)")
        }
        return nil
    }

    /// Checks each GPU hit on the CPU reference, then sends it without waiting for the answer.
    private func submit(_ hits: [(counter: UInt64, hash: [UInt64])], _ job: Job, _ state: inout State,
                        _ connection: StratumConnection) throws {
        for hit in hits {
            let nonce = job.nonce(hit.counter)
            let cpu = R.words(R.nonceHash(header: job.header, nonce: nonce))
            guard cpu == hit.hash, R.less(cpu, job.target) else {
                events.log("qtc: nonce \(nonce.hex): GPU hash \(R.hex(hit.hash)) differs from the CPU's \(R.hex(cpu)); not submitted")
                continue
            }
            state.submitted += 1
            let share = state.submitted == testCorruptShare ? failingShare(after: hit.counter, job) : (nonce: nonce, hash: cpu)
            try send("submit", ["id": state.session, "job_id": job.id, "nonce": share.nonce.hex, "result": R.hex(share.hash)],
                     .share(job.difficulty), &state, connection)
        }
    }

    private func send(_ method: String, _ params: [String: Any], _ kind: Pending, _ state: inout State,
                      _ connection: StratumConnection) throws {
        let id = state.nextID
        state.nextID += 1
        state.pending[id] = kind
        state.lastSend = now()
        try connection.send(["id": id, "jsonrpc": "2.0", "method": method, "params": params])
    }

    /// The first counter after `counter` whose nonce misses the job's target, with its true hash (selfTest's
    /// deliberately invalid share).
    private func failingShare(after counter: UInt64, _ job: Job) -> (nonce: [UInt8], hash: [UInt64]) {
        var c = counter
        while true {
            c &+= 1
            let nonce = job.nonce(c)
            let hash = R.words(R.nonceHash(header: job.header, nonce: nonce))
            if !R.less(hash, job.target) { return (nonce, hash) }
        }
    }

    // MARK: Live check

    /// Connects without logging in. These sessions open with `login`, which is never sent here: the check listens for
    /// 2 s, then sends the dialect's one request that is neither a login nor a share, keepalived (with no session id),
    /// and reports the answer.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls, timeout: 10)
        defer { connection.close() }
        var text = ""
        if let greeting = try connection.nextNotification(timeout: 2) {
            text += "the pool spoke first: \(compact(greeting)) · "
        } else {
            text += "nothing from the pool in 2 s without a login · "
        }
        connection.requestFields = ["jsonrpc": "2.0"]
        do {
            let reply = try connection.call("keepalived", params: ["id": ""], timeout: 8)
            text += "keepalived (no login) -> \(compact(reply))"
            if (reply["result"] as? [String: Any])?["status"] as? String == "KEEPALIVED" {
                text += " · the XMRig-style reply shape (result.status)"
            }
        } catch {
            text += "keepalived (no login): \(error)"
        }
        return text
    }

    // MARK: JSON helpers

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
