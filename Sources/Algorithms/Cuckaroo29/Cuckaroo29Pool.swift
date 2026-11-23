import Foundation

/// One Tari C29 pool job, in the Stratum dialect C29 pools speak (docs/specs/cuckaroo29.md, "Pool protocol").
struct Cuckaroo29PoolJob {
    /// The pool's job id, echoed in every submit for this job.
    let id: String
    /// Tari's 32-byte header mining hash, the job's "blob". Graph n's siphash keys are blake2b-256(n as 8 big-endian
    /// bytes || mining hash).
    let miningHash: [UInt8]
    /// The block height, when sent. Only used to drop solutions for a block the pool has moved past.
    let height: UInt64?
    /// Share difficulty: a 42-cycle is a share when its Tari difficulty reaches this.
    let difficulty: UInt64
    /// The "target" field as sent, for logs.
    let target: String?
    /// The pool's extra nonce ("xn"): the leading bytes of every header nonce, most significant first. Empty when the
    /// pool sends none.
    let extraNonce: [UInt8]

    /// A share's expected work in graphs, which is what it is worth: a random Cuckaroo29 graph holds 1/42 of a 42-cycle
    /// on average, and a cycle's proof hash reaches difficulty D with probability 1/D.
    var work: Double { Double(Cuckaroo29Reference.cycleLength) * Double(difficulty) }

    /// The job as a pool sends it, for the mock pool.
    var json: [String: Any] {
        var object: [String: Any] = ["algo": "cuckaroo", "blob": miningHash.hex, "job_id": id,
                                     "target": target ?? Cuckaroo29Stratum.target(difficulty: difficulty)]
        if let height { object["height"] = height }
        if !extraNonce.isEmpty { object["xn"] = extraNonce.hex }
        return object
    }

    var summary: String {
        "job \(Cuckaroo29Stratum.clip(id, 20)) at height \(height.map { String($0) } ?? "?"), share difficulty \(difficulty)"
            + (extraNonce.isEmpty ? "" : ", extra nonce \(extraNonce.hex)")
    }
}

/// The Tari C29 pool dialect: xmrig-style JSON-RPC lines ("login", "job", "submit", "keepalived", "getjob"), as Tari's
/// own C29 pool miner (tari-project/TARI.Miner), the go-tari-c29-solo-stratum server and MoneroOcean's XTM-C pool speak
/// it. Field layouts and byte orders are in docs/specs/cuckaroo29.md.
enum Cuckaroo29Stratum {
    /// Share difficulty from a job's "target": 16 hex digits are a little-endian u64, (2^64 - 1) / difficulty, the form
    /// every C29 reference sends; 8 hex digits are xmrig's compact 32-bit form, (2^32 - 1) / difficulty.
    static func difficulty(target hex: String) -> UInt64? {
        guard let bytes = [UInt8](hex: hex) else { return nil }
        switch bytes.count {
        case 8:
            let value = bytes.le64(at: 0)
            return value == 0 ? .max : max(1, UInt64.max / value)
        case 4:
            let value = UInt64(bytes.le32(at: 0))
            return value == 0 ? .max : max(1, UInt64(UInt32.max) / value)
        default:
            return nil
        }
    }

    /// The 8-byte target pools send for `difficulty`, as hex.
    static func target(difficulty: UInt64) -> String {
        var bytes: [UInt8] = []
        bytes.appendLE(UInt64.max / max(1, difficulty))
        return bytes.hex
    }

    /// A header nonce as submitted: its 8 bytes big-endian (the order Tari hashes them in), 16 lowercase hex digits.
    static func nonceHex(_ nonce: UInt64) -> String { String(format: "%016llx", nonce) }

    /// Reads a job: the login reply's "job" or a "job" notification's params. A "target" or "xn" the job leaves out
    /// carries over from `previous`, as in TARI.Miner. A numeric "difficulty" stands in for a missing target.
    static func job(_ object: [String: Any], previous: Cuckaroo29PoolJob?) throws -> Cuckaroo29PoolJob {
        guard let id = text(object["job_id"]), !id.isEmpty else { throw MinerError("xtm-c29: a job without a job_id") }
        guard let blobHex = object["blob"] as? String, let blob = [UInt8](hex: blobHex) else {
            throw MinerError("xtm-c29: job \(clip(id, 20)) has no hex blob")
        }
        guard blob.count == 32 else {
            throw MinerError("xtm-c29: the job's blob is \(blob.count) bytes; C29 work is Tari's 32-byte mining hash")
        }
        var shareDifficulty = previous?.difficulty
        var target = previous?.target
        if let hex = object["target"] as? String {
            guard let value = difficulty(target: hex) else { throw MinerError("xtm-c29: unreadable target \(clip(hex, 40))") }
            shareDifficulty = value
            target = hex
        } else if let number = object["difficulty"] as? NSNumber, boolean(number) == nil, number.doubleValue >= 1 {
            shareDifficulty = UInt64(min(number.doubleValue, 1.8e19))
            target = nil
        }
        guard let shareDifficulty else { throw MinerError("xtm-c29: job \(clip(id, 20)) has no target") }
        var extraNonce = previous?.extraNonce ?? []
        if let xn = object["xn"] as? String {
            guard let bytes = [UInt8](hex: xn), bytes.count < 8 else {
                throw MinerError("xtm-c29: unusable extra nonce \(clip(xn, 40))")
            }
            extraNonce = bytes
        }
        var height: UInt64?
        if let number = object["height"] as? NSNumber, boolean(number) == nil, number.doubleValue >= 0 {
            height = number.uint64Value
        } else if let string = object["height"] as? String {
            height = UInt64(string)
        }
        return Cuckaroo29PoolJob(id: id, miningHash: blob, height: height, difficulty: shareDifficulty, target: target,
                                 extraNonce: extraNonce)
    }

    /// A share's submit params: the session id from the login reply, the job id, the header nonce (16 hex digits,
    /// big-endian), "pow" (the 42 edge indices, ascending, as JSON numbers) and "result" (the proof hash, blake2b-256 of
    /// the 153-byte pow_data, in hex).
    static func submitParams(session: String?, job: String, nonce: UInt64, solution: Cuckaroo29Miner.Solution) -> [String: Any] {
        var params: [String: Any] = ["job_id": job, "nonce": nonceHex(nonce), "pow": solution.nonces.map { Int($0) },
                                     "result": solution.hash.hex]
        if let session { params["id"] = session }
        return params
    }

    /// A reply's error as text, or nil when it carries none. Pools send null, leave it out, or (Go servers) send an
    /// empty string on success; errors come as {"code", "message"}, a string, or [code, message, data].
    static func errorText(_ reply: [String: Any]) -> String? {
        guard let error = reply["error"], !(error is NSNull) else { return nil }
        if let string = error as? String { return string.isEmpty ? nil : clip(string) }
        if let flag = boolean(error) { return flag ? "error" : nil }
        if let object = error as? [String: Any] { return clip(text(object["message"]) ?? describe(object)) }
        if let parts = error as? [Any] { return clip(parts.filter { !($0 is NSNull) }.map { "\($0)" }.joined(separator: " ")) }
        return clip("\(error)")
    }

    /// Whether a submit (or login) reply accepts, and the pool's reason when it doesn't. Accepted means no error and a
    /// result of true, {"status": "OK"} or "OK": pools in this dialect answer either way.
    static func verdict(_ reply: [String: Any]) -> (accepted: Bool, note: String?) {
        if let error = errorText(reply) { return (false, error) }
        let result = reply["result"]
        if let flag = boolean(result) { return flag ? (true, nil) : (false, "refused (result false)") }
        if let status = ((result as? [String: Any])?["status"] as? String) ?? (result as? String) {
            return status.uppercased() == "OK" ? (true, nil) : (false, clip(status))
        }
        return (false, "no result in the pool's answer")
    }

    /// A JSON boolean's value; nil for anything else, numbers included.
    static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    /// A string or number as text.
    static func text(_ value: Any?) -> String? {
        if let string = value as? String { return string }
        if let number = value as? NSNumber, boolean(number) == nil { return number.stringValue }
        return nil
    }

    /// A request id, sent back as a number or a numeric string.
    static func requestID(_ value: Any?) -> Int? { text(value).flatMap { Int($0) } }

    /// Pool text for logs: control characters replaced, at most `limit` characters.
    static func clip(_ text: String, _ limit: Int = 160) -> String {
        let clean = String(text.unicodeScalars.map { scalar -> Character in
            scalar.value < 0x20 || (0x7F ... 0x9F).contains(scalar.value) ? "." : Character(scalar)
        })
        return clean.count > limit ? String(clean.prefix(limit)) + "..." : clean
    }

    /// A message as compact JSON for logs, clipped.
    static func describe(_ message: [String: Any], limit: Int = 200) -> String {
        guard JSONSerialization.isValidJSONObject(message),
              let data = try? JSONSerialization.data(withJSONObject: message, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return clip("\(message)", limit) }
        return clip(text, limit)
    }
}

/// Real mining on Kryptex's Tari C29 pool (xtm-c29). Logs in with the payout login, turns each job into graphs on the
/// GPU (header nonce = the pool's extra nonce, if any, then a counter), submits the best 42-cycle of any graph that
/// reaches the share difficulty, and follows new jobs, difficulty changes (a job with a new target) and reconnect
/// requests. Reports the graph rate every few seconds and each share's verdict with its expected work, 42 x difficulty
/// graphs.
final class Cuckaroo29PoolMiner: PoolMiner {
    static let pools = ["xtm-c29"]
    static let algorithm = Cuckaroo29Miner.id

    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    /// The verified solver at mainnet parameters (2^29 edges, 6.7 GiB of edge buffers).
    let solver: Cuckaroo29Miner

    /// Sent with the login. Kryptex's examples use "x" as the password.
    var password = "x"
    var agent = "metalminer/0.1"
    /// Seconds between rate reports, between keepalives while nothing else is sent, and between summaries in the log;
    /// and how long a submit may wait for its answer before it counts as not accepted.
    var rateInterval = 5.0
    var keepaliveInterval = 120.0
    var summaryInterval = 60.0
    var submitTimeout = 60.0
    /// Reconnect requests followed in one run, each to `endpoint` (never to a host the pool names).
    var maxReconnects = 5
    /// Logs every 42-cycle and what became of it (the self-test reads these lines).
    var logCycles = false
    /// Self-test hooks: the first nonce counter for a job (nil: random), and whether to corrupt a job's share before it
    /// is sent.
    var counterStart: ((Cuckaroo29PoolJob) -> UInt64?)?
    var corruptShare: ((Cuckaroo29PoolJob) -> Bool)?

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        self.endpoint = endpoint
        self.login = login
        self.events = events
        solver = try Cuckaroo29Miner(gpu: gpu, config: AlgoConfig())
    }

    func run(shouldStop: () -> Bool) throws {
        var reconnects = 0
        while !shouldStop() {
            let session = try Cuckaroo29PoolSession(miner: self)
            defer { session.close() }
            guard case .reconnect(let wait) = try session.run(shouldStop: shouldStop) else { return }
            reconnects += 1
            guard reconnects <= maxReconnects else {
                throw MinerError("xtm-c29: the pool asked for \(reconnects) reconnects in one run")
            }
            let resume = now() + wait
            while now() < resume {
                if shouldStop() { return }
                Thread.sleep(forTimeInterval: max(0.01, min(0.25, resume - now())))
            }
        }
    }

    /// How the log names a 42-cycle.
    static func cycleName(nonce: UInt64, difficulty: UInt64) -> String {
        "42-cycle at nonce \(Cuckaroo29Stratum.nonceHex(nonce)), difficulty \(difficulty)"
    }

    /// The same proof with its last edge index moved up by one (or its first moved down): still 42 ascending indices
    /// below 2^29, no longer a cycle. The self-test's deliberately invalid share.
    static func corrupted(_ solution: Cuckaroo29Miner.Solution) -> Cuckaroo29Miner.Solution {
        var nonces = solution.nonces
        if let last = nonces.last, last < (1 << 29) - 1 {
            nonces[nonces.count - 1] = last + 1
        } else if let first = nonces.first, first > 0 {
            nonces[0] = first - 1
        }
        let powData = Cuckaroo29Reference.pack(nonces, edgeBits: 29)
        let hash = Cuckaroo29Reference.blake2b(powData)
        return Cuckaroo29Miner.Solution(nonces: nonces, powData: powData, hash: hash,
                                        difficulty: Cuckaroo29Reference.difficulty(hash: hash))
    }
}

/// One connection to the pool: log in, then mine until the run stops or the pool asks for a reconnect. Throws when the
/// pool refuses the login or the connection fails.
final class Cuckaroo29PoolSession {
    enum End {
        case stopped
        case reconnect(TimeInterval)
    }

    private let miner: Cuckaroo29PoolMiner
    private let connection: StratumConnection
    private var session: String?
    private var job: Cuckaroo29PoolJob?
    private var counter: UInt64 = 0
    private var nextID = 2
    private var submits: [Int: (job: Cuckaroo29PoolJob, sent: Double)] = [:]
    private var keepalive: (id: Int, sent: Double)?
    private var keepalivesRefused = false
    private var jobRequest: Int?
    private var askedForJob = false
    private var end: End?
    private var lastSend = now()
    private var rateStart = now()
    private var rateGraphs = 0
    private var summaryStart = now()
    private var graphs = 0
    private var cycles = 0
    private var best: UInt64 = 0
    private var accepted = 0
    private var rejected = 0
    private var ignored = 0

    init(miner: Cuckaroo29PoolMiner) throws {
        self.miner = miner
        connection = try StratumConnection(host: miner.endpoint.host, port: miner.endpoint.port, tls: miner.endpoint.tls)
    }

    func close() { connection.close() }

    private var sessionParams: [String: Any] {
        guard let session else { return [:] }
        return ["id": session]
    }

    private func send(_ message: [String: Any]) throws {
        guard JSONSerialization.isValidJSONObject(message) else { throw MinerError("xtm-c29: a malformed outgoing message") }
        try connection.send(message)
        lastSend = now()
    }

    private func request(_ method: String, _ params: [String: Any]) throws -> Int {
        let id = nextID
        nextID += 1
        try send(["id": id, "jsonrpc": "2.0", "method": method, "params": params])
        return id
    }

    func run(shouldStop: () -> Bool) throws -> End {
        try logIn(shouldStop: shouldStop)
        let loggedIn = now()
        rateStart = loggedIn
        summaryStart = loggedIn
        while true {
            try drain()
            if let end { return end }
            if shouldStop() { return .stopped }
            guard let current = job else {
                guard now() - loggedIn < 60 else { throw MinerError("xtm-c29: logged in, but no job came within 60 s") }
                if !askedForJob {
                    askedForJob = true
                    jobRequest = try request("getjob", sessionParams)
                }
                if let message = try connection.nextNotification(timeout: 0.5) { try handle(message) }
                continue
            }
            let nonce = nextNonce(for: current)
            let found = try miner.solver.solve(miningHash: current.miningHash, nonce: nonce)
            rateGraphs += 1
            graphs += 1
            try drain()
            try take(found, job: current, nonce: nonce)
            try housekeeping()
        }
    }

    /// Sends the login and waits up to 20 s for its answer: {"id": session, "job": {...}, "status": "OK"}.
    private func logIn(shouldStop: () -> Bool) throws {
        try send(["id": 1, "jsonrpc": "2.0", "method": "login",
                  "params": ["login": miner.login, "pass": miner.password, "agent": miner.agent]])
        let deadline = now() + 20
        while now() < deadline {
            if shouldStop() { return }
            guard let message = try connection.nextNotification(timeout: min(0.5, max(0.01, deadline - now()))) else { continue }
            guard (message["method"] as? String) != "job", Cuckaroo29Stratum.requestID(message["id"]) == 1,
                  message["result"] != nil || message["error"] != nil else {
                try handle(message)
                continue
            }
            if let error = Cuckaroo29Stratum.errorText(message) {
                throw PoolLoginRefused(login: miner.login, reason: error)
            }
            if let result = message["result"] as? [String: Any] {
                session = Cuckaroo29Stratum.text(result["id"])
                if let status = result["status"] as? String, status.uppercased() != "OK" {
                    throw PoolLoginRefused(login: miner.login, reason: Cuckaroo29Stratum.clip(status))
                }
                if let object = result["job"] as? [String: Any] { try adopt(object) }
            } else {
                let verdict = Cuckaroo29Stratum.verdict(message)
                if !verdict.accepted { throw PoolLoginRefused(login: miner.login, reason: verdict.note ?? "no reason given") }
            }
            miner.events.log("logged in to \(miner.endpoint)" + (job.map { "; \($0.summary)" } ?? "; waiting for a job"))
            return
        }
        throw MinerError("xtm-c29: no answer to the login from \(miner.endpoint) within 20 s")
    }

    private func drain() throws {
        while let message = try connection.nextNotification(timeout: 0) { try handle(message) }
    }

    /// Everything the pool sends: jobs, reconnect requests, and answers to submits, keepalives and getjob, matched by
    /// id whether or not the answer repeats the method.
    private func handle(_ message: [String: Any]) throws {
        let method = message["method"] as? String
        if method == "job" {
            guard let params = message["params"] as? [String: Any] else { throw MinerError("xtm-c29: a job without params") }
            return try adopt(params)
        }
        if let method, ["client.reconnect", "reconnect", "mining.reconnect"].contains(method) {
            let wait = Self.reconnectWait(message["params"])
            end = .reconnect(wait)
            miner.events.log("the pool asked for a reconnect" + (wait > 0 ? " in \(Int(wait)) s" : "")
                + "; reconnecting to \(miner.endpoint)")
            return
        }
        if let id = Cuckaroo29Stratum.requestID(message["id"]), message["result"] != nil || message["error"] != nil {
            if let submit = submits.removeValue(forKey: id) { return record(submit.job, Cuckaroo29Stratum.verdict(message)) }
            if id == keepalive?.id {
                keepalive = nil
                if let error = Cuckaroo29Stratum.errorText(message) {
                    keepalivesRefused = true
                    miner.events.log("the pool refused a keepalive (\(error)); no more keepalives on this connection")
                }
                return
            }
            if id == jobRequest {
                jobRequest = nil
                if let object = message["result"] as? [String: Any] {
                    if object["blob"] != nil { return try adopt(object) }
                    if let inner = object["job"] as? [String: Any] { return try adopt(inner) }
                }
                if let error = Cuckaroo29Stratum.errorText(message) { miner.events.log("the pool refused getjob: \(error)") }
                return
            }
        }
        if ignored < 5 {
            ignored += 1
            miner.events.log("ignored from the pool: \(Cuckaroo29Stratum.describe(message))")
        }
    }

    /// Seconds to wait before reconnecting: params [host, port, wait] (Stratum's client.reconnect) or {"wait": n},
    /// clamped to 0 ... 60. The host and port are ignored: the miner only ever connects to its own endpoint.
    private static func reconnectWait(_ params: Any?) -> TimeInterval {
        var wait: Double?
        if let list = params as? [Any], list.count >= 3 {
            wait = (list[2] as? NSNumber)?.doubleValue ?? (list[2] as? String).flatMap { Double($0) }
        } else if let object = params as? [String: Any] {
            wait = (object["wait"] as? NSNumber)?.doubleValue
        }
        return min(60, max(0, wait ?? 0))
    }

    /// Makes `object` the current job and restarts the nonce counter at a random point (or the self-test's).
    private func adopt(_ object: [String: Any]) throws {
        let next = try Cuckaroo29Stratum.job(object, previous: job)
        if let previous = job, previous.difficulty != next.difficulty {
            miner.events.log("share difficulty \(previous.difficulty) -> \(next.difficulty) (job \(Cuckaroo29Stratum.clip(next.id, 20)))")
        }
        job = next
        counter = miner.counterStart?(next) ?? UInt64.random(in: 0 ... .max)
    }

    /// The next header nonce: the extra nonce's bytes on top, the counter below.
    private func nextNonce(for job: Cuckaroo29PoolJob) -> UInt64 {
        let free = UInt64(64 - 8 * job.extraNonce.count)
        let prefix = job.extraNonce.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let nonce = free == 64 ? counter : (prefix << free) | (counter & ((1 << free) - 1))
        counter &+= 1
        return nonce
    }

    /// Submits the best 42-cycle of a graph when it reaches the share difficulty of the job it was mined for, unless
    /// the pool has moved to a higher block since. One share per graph: some pools refuse a repeated nonce.
    private func take(_ found: [Cuckaroo29Miner.Solution], job graphJob: Cuckaroo29PoolJob, nonce: UInt64) throws {
        cycles += found.count
        guard var share = found.max(by: { $0.difficulty < $1.difficulty }) else { return }
        best = max(best, share.difficulty)
        let name = Cuckaroo29PoolMiner.cycleName(nonce: nonce, difficulty: share.difficulty)
        guard share.difficulty >= graphJob.difficulty else {
            if miner.logCycles { miner.events.log("\(name): held back, below the share difficulty \(graphJob.difficulty)") }
            return
        }
        if let height = graphJob.height, let latest = job?.height, latest > height {
            miner.events.log("\(name): dropped, found for height \(height) after the pool moved on to \(latest)")
            return
        }
        if miner.corruptShare?(graphJob) == true { share = Cuckaroo29PoolMiner.corrupted(share) }
        let params = Cuckaroo29Stratum.submitParams(session: session, job: graphJob.id, nonce: nonce, solution: share)
        let id = try request("submit", params)
        submits[id] = (graphJob, now())
        if miner.logCycles { miner.events.log("\(name): submitted for job \(Cuckaroo29Stratum.clip(graphJob.id, 20))") }
    }

    private func record(_ job: Cuckaroo29PoolJob, _ verdict: (accepted: Bool, note: String?)) {
        if verdict.accepted { accepted += 1 } else { rejected += 1 }
        miner.events.share(verdict.accepted, job.work, verdict.note)
    }

    /// Rate reports, submits that never got an answer, keepalives while idle, and a summary line now and then.
    private func housekeeping() throws {
        let t = now()
        if t - rateStart >= miner.rateInterval {
            miner.events.hashrate(Double(rateGraphs) / (t - rateStart))
            rateStart = t
            rateGraphs = 0
        }
        for (id, submit) in submits where t - submit.sent > miner.submitTimeout {
            submits[id] = nil
            record(submit.job, (false, "no answer from the pool within \(Int(miner.submitTimeout)) s"))
        }
        if let pending = keepalive, t - pending.sent > 60 { keepalive = nil }
        if !keepalivesRefused, keepalive == nil, t - lastSend >= miner.keepaliveInterval {
            let id = try request("keepalived", sessionParams)
            keepalive = (id, t)
        }
        if t - summaryStart >= miner.summaryInterval {
            let seconds = t - summaryStart
            miner.events.log("last \(Int(seconds.rounded())) s: \(graphs) graphs (\(fmt(Double(graphs) / seconds)) G/s), "
                + "\(cycles) 42-cycles" + (cycles > 0 ? " (best difficulty \(best))" : "")
                + ", shares \(accepted) accepted, \(rejected) rejected" + (job.map { "; \($0.summary)" } ?? ""))
            summaryStart = t
            graphs = 0
            cycles = 0
            best = 0
            accepted = 0
            rejected = 0
        }
    }
}

extension Cuckaroo29PoolMiner {
    /// The live check, without logging in: connects, listens a second for anything the pool says unprompted, sends one
    /// message, "getjob" with an empty session id (the dialect's only request besides login that asks for anything),
    /// reports the answer and whatever follows within a moment, and disconnects.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        defer { connection.close() }
        var messages: [[String: Any]] = []
        var closed: String?
        func listen(for seconds: Double, until done: () -> Bool) {
            let deadline = now() + seconds
            while closed == nil, !done(), now() < deadline {
                do {
                    if let message = try connection.nextNotification(timeout: min(0.25, max(0.01, deadline - now()))) {
                        messages.append(message)
                    }
                } catch {
                    closed = "\(error)"
                }
            }
        }
        var parts = ["\(endpoint.tls ? "TLS" : "TCP") connection up"]
        listen(for: 1) { !messages.isEmpty }
        let unprompted = messages.count
        if unprompted > 0 {
            parts.append("the pool spoke first: " + messages.map { Cuckaroo29Stratum.describe($0, limit: 300) }.joined(separator: " | "))
        }
        if let closed { return (parts + ["it closed the connection before any request (\(closed))"]).joined(separator: "; ") }
        try connection.send(["id": 1, "jsonrpc": "2.0", "method": "getjob", "params": ["id": ""]])
        listen(for: 10) {
            messages.dropFirst(unprompted).contains {
                Cuckaroo29Stratum.requestID($0["id"]) == 1 || ($0["method"] as? String) == "job"
            }
        }
        listen(for: 1.5) { false }   // whatever follows the answer: a job, or the pool hanging up
        let answers = Array(messages.dropFirst(unprompted))
        if answers.isEmpty {
            parts.append("sent getjob without logging in; no answer within 10 s")
        } else {
            parts.append("sent getjob without logging in; the pool answered "
                + answers.map { Cuckaroo29Stratum.describe($0, limit: 300) }.joined(separator: " | "))
        }
        for answer in answers {
            if let error = Cuckaroo29Stratum.errorText(answer) {
                let shape = answer["error"] is [String: Any] ? "an error object" : answer["error"] is String ? "an error string" : "an error"
                parts.append("read as \(shape) (\(error))" + (answer["jsonrpc"] != nil ? " in a JSON-RPC 2.0 reply" : ""))
            }
            var object: [String: Any]?
            if (answer["method"] as? String) == "job" {
                object = answer["params"] as? [String: Any]
            } else if let result = answer["result"] as? [String: Any] {
                if result["blob"] != nil { object = result } else { object = result["job"] as? [String: Any] }
            }
            if let object {
                if let job = try? Cuckaroo29Stratum.job(object, previous: nil) {
                    parts.append("read as a C29 job: \(job.summary), 32-byte blob")
                } else {
                    parts.append("a job this miner can't read")
                }
            }
        }
        parts.append(closed.map { "then the pool closed the connection (\($0))" } ?? "disconnected")
        return parts.joined(separator: "; ")
    }
}
