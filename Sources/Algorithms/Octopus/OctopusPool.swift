import Foundation

/// Real Conflux mining on Kryptex's CFX pool (slug "cfx") in Conflux's own Stratum dialect (conflux-rust
/// crates/stratum and crates/blockgen/src/miner/stratum.rs, open-cfxmine's StratumClient, NiceHash's Octopus note;
/// see docs/specs/octopus.md, "Pool protocol"). JSON-RPC 2.0:
///
///     > mining.subscribe [login, password]                     < true    (the subscribe is the login)
///     < mining.notify [job, height, "0x" pow hash, "0x" boundary]   optional "xn": the nonce's first byte(s)
///     > mining.submit [login, job, "0x" nonce (16 hex digits), "0x" pow hash]   < [true] or [false, reason]
///
/// Also handled: a Bitcoin-style subscribe reply ([subscriptions, extranonce1, size]) is followed by mining.authorize
/// and extranonce1 becomes the nonce prefix; mining.set_difficulty d gives the boundary 2^256 / d to a job without
/// one; a notify without height ([job, pow hash, boundary]) uses the estimated height.
final class OctopusPoolMiner: PoolMiner {
    static let pools = ["cfx"]
    static let algorithm = "octopus"
    static let agent = "metalminer/1.0"

    let gpu: GPU
    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    /// Test settings (selfTest): --quick DAG sizes, nonces per GPU batch, and a hook that may replace a verified nonce
    /// just before it is submitted (to send a deliberately invalid share).
    var quick = false
    var batch = 1 << 21
    var replaceShare: ((UInt64) -> UInt64?)?

    private var octopus: Octopus?
    private var loadedHeader: [UInt8]?
    private var loadedBoundary: [UInt64]?

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        self.gpu = gpu
        self.endpoint = endpoint
        self.login = login
        self.events = events
    }

    struct Job: Equatable {
        var id: String
        var height: Int
        var header: [UInt8]
        /// The pow hash as the pool wrote it, echoed in submits.
        var headerText: String
        /// Share boundary, four 64-bit limbs, most significant first: a share's hash (big-endian) is below it.
        var boundary: [UInt64]
        /// The nonce's first bytes ("xn" or extranonce1).
        var prefix: [UInt8]
    }

    struct Reconnect {
        var host: String
        var port: UInt16
        var wait: Double
    }

    private final class Session {
        let host: String
        let port: UInt16
        var extranonce: [UInt8] = []
        var difficulty: Double?
        var job: Job?
        var counter: UInt64 = 0
        var exhausted = false
        var pending: [Int: Double] = [:]
        var nextID = 100
        init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }
    }

    // MARK: Mining

    func run(shouldStop: () -> Bool) throws {
        var host = endpoint.host, port = endpoint.port
        while !shouldStop() {
            let connection = try StratumConnection(host: host, port: port, tls: endpoint.tls)
            connection.requestFields = ["jsonrpc": "2.0"]
            let move: Reconnect?
            do {
                move = try mine(connection, Session(host: host, port: port), shouldStop: shouldStop)
            } catch {
                connection.close()
                throw error
            }
            connection.close()
            guard let move else { return }
            events.log("pool asked to reconnect to \(move.host):\(move.port) in \(Int(move.wait)) s")
            let resume = now() + move.wait
            while now() < resume {
                if shouldStop() { return }
                Thread.sleep(forTimeInterval: 0.1)
            }
            (host, port) = (move.host, move.port)
        }
    }

    private func logIn(_ connection: StratumConnection, _ session: Session) throws {
        let reply = try connection.call("mining.subscribe", params: [login, "x"])
        if let result = reply["result"] as? [Any], result.count >= 2, let hex = result[1] as? String, let extranonce = [UInt8](hex: hex) {
            // A Bitcoin-style pool: extranonce1 starts every nonce, and the login goes in mining.authorize.
            guard extranonce.count <= 4 else { throw MinerError("extranonce1 \(hex) leaves too little of the 8-byte nonce") }
            session.extranonce = extranonce
            let authorize = try connection.call("mining.authorize", params: [login, "x"])
            guard Self.accepted(authorize) else { throw PoolLoginRefused(login: login, reason: Self.refusal(authorize)) }
            events.log("logged in to \(connection.label) as \(login) (subscribe + authorize); extranonce1 \(hex)")
            return
        }
        // Conflux's subscribe carries the login, so refusing it refuses the login.
        guard Self.accepted(reply) else { throw PoolLoginRefused(login: login, reason: Self.refusal(reply)) }
        events.log("logged in to \(connection.label) as \(login) (Conflux mining.subscribe)")
    }

    private func mine(_ connection: StratumConnection, _ session: Session, shouldStop: () -> Bool) throws -> Reconnect? {
        try logIn(connection, session)
        let deadline = now() + 60
        var lastReport = now()
        var hashes = 0.0
        while !shouldStop() {
            var wait = session.job == nil || session.exhausted ? 0.2 : 0
            while let message = try connection.nextNotification(timeout: wait) {
                if let move = try handle(message, session, connection) { return move }
                wait = 0
            }
            guard let job = session.job, !session.exhausted else {
                if session.job == nil, now() > deadline { throw MinerError("no job from \(connection.label) within 60 s of logging in") }
                continue
            }
            let before = octopus
            let oct = try prepare(job)
            if before !== oct {   // a new cache and DAG were built: start the rate from here
                lastReport = now()
                hashes = 0
            }
            let bits = 64 - 8 * job.prefix.count
            let remaining = bits >= 64 ? UInt64.max : (UInt64(1) << UInt64(bits)) - session.counter
            let count = Int(min(UInt64(batch), remaining)) / oct.group * oct.group
            guard count > 0 else {
                session.exhausted = true
                events.log("job \(job.id): every nonce under prefix \(job.prefix.hex) searched; waiting for the next job")
                continue
            }
            let prefix = job.prefix.reduce(UInt64(0)) { $0 << 8 | UInt64($1) } << UInt64(bits & 63)
            let hits = try oct.search(oct.searchPipeline, start: prefix | session.counter, threads: count)
            hashes += Double(count)
            session.counter += UInt64(count)
            // Replies and new jobs from during the batch, then the shares. Conflux keeps a window of recent problems,
            // so shares for the previous job still go out.
            while let message = try connection.nextNotification(timeout: 0) {
                if let move = try handle(message, session, connection) { return move }
            }
            for nonce in hits.sorted() { try submit(nonce, job: job, oct, session, connection) }
            if now() - lastReport >= 5 {
                events.hashrate(hashes / (now() - lastReport))
                hashes = 0
                lastReport = now()
            }
        }
        return nil
    }

    /// The GPU state for a job: cache and DAG for its stage (rebuilt when the stage changes), header and boundary.
    private func prepare(_ job: Job) throws -> Octopus {
        let stage = quick ? 0 : OctopusReference.stage(height: job.height)
        if octopus?.stage != stage {
            octopus = nil   // release the old DAG first
            loadedHeader = nil
            loadedBoundary = nil
            events.log("building the Octopus cache and DAG for stage \(stage) (height \(job.height))…")
            let made = try Octopus(gpu: gpu, config: AlgoConfig(quick: quick, options: ["height": String(job.height)]))
            events.log("DAG ready: \(made.setupSummary)")
            octopus = made
        }
        let oct = octopus!
        if loadedHeader != job.header {
            oct.setJob(header: job.header)
            loadedHeader = job.header
        }
        if loadedBoundary != job.boundary {
            oct.setTarget(job.boundary)
            loadedBoundary = job.boundary
        }
        return oct
    }

    /// Checks a GPU hit with the CPU reference (over the GPU's DAG), then submits it.
    private func submit(_ nonce: UInt64, job: Job, _ oct: Octopus, _ session: Session, _ connection: StratumConnection) throws {
        let hash = OctopusReference.hash(header: job.header, nonce: nonce, datasetBytes: oct.datasetBytes) { oct.dagItem($0) }
        guard OctopusReference.limbs(hash.final).lexicographicallyPrecedes(job.boundary) else {
            events.log("GPU nonce \(String(format: "%016llx", nonce)) fails the CPU check (hash \(hash.final.hex)); not submitted")
            return
        }
        let sent = replaceShare?(nonce) ?? nonce
        let id = session.nextID
        session.nextID += 1
        session.pending[id] = Self.work(job.boundary)
        try connection.send(["jsonrpc": "2.0", "id": id, "method": "mining.submit",
                             "params": [login, job.id, String(format: "0x%016llx", sent), job.headerText]])
    }

    private func handle(_ message: [String: Any], _ session: Session, _ connection: StratumConnection) throws -> Reconnect? {
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.notify"?:
            notify(message, session)
        case "mining.set_difficulty"?:
            if let d = Self.number(params.first), d > 0 { session.difficulty = d }
        case "mining.set_extranonce"?:
            if let hex = params.first as? String, let value = [UInt8](hex: hex), value.count <= 4 { session.extranonce = value }
        case "client.reconnect"?:
            let host = (params.first as? String).flatMap { $0.isEmpty ? nil : $0 } ?? session.host
            let port = params.count > 1 ? Self.integer(params[1]).flatMap { UInt16(exactly: $0) } : nil
            let wait = params.count > 2 ? Self.number(params[2]) ?? 0 : 0
            return Reconnect(host: host, port: port ?? session.port, wait: min(max(wait, 0), 600))
        case "client.show_message"?:
            events.log("pool says: \(params.first.map { "\($0)" } ?? "")")
        case "client.get_version"?:
            if let id = message["id"], !(id is NSNull) { try connection.send(["jsonrpc": "2.0", "id": id, "result": Self.agent]) }
        case nil:
            guard let id = Self.integer(message["id"]), let work = session.pending.removeValue(forKey: id) else { return nil }
            let ok = Self.accepted(message)
            events.share(ok, work, ok ? nil : Self.refusal(message))
        default:
            break
        }
        return nil
    }

    private func notify(_ message: [String: Any], _ session: Session) {
        let params = message["params"] as? [Any] ?? []
        let withHeight = params.count >= 4
        guard params.count >= 3, let id = Self.string(params[0]),
              let height = withHeight ? Self.integer(params[1]) : OctopusChain.estimatedHeight, height >= 0,
              let headerText = params[withHeight ? 2 : 1] as? String, let header = [UInt8](hex: headerText), header.count == 32 else {
            events.log("ignored a mining.notify I can't read: \(Self.json(params))")
            return
        }
        var boundary = Self.limbs(params[withHeight ? 3 : 2])
        if boundary == nil || boundary == [0, 0, 0, 0], let d = session.difficulty { boundary = Self.boundary(difficulty: d) }
        guard let boundary, boundary != [0, 0, 0, 0] else {
            events.log("job \(id) has no boundary; ignored")
            return
        }
        if !withHeight { events.log("job \(id) carries no height; using the estimated height \(height)") }
        let prefix = (message["xn"] as? String).flatMap { [UInt8](hex: $0) }.flatMap { $0.count <= 4 ? $0 : nil } ?? session.extranonce
        if header != session.job?.header || prefix != session.job?.prefix {
            session.counter = Self.startCounter(bits: 64 - 8 * prefix.count)
            session.exhausted = false
        }
        if boundary != session.job?.boundary {
            events.log("job \(id), height \(height): boundary \(Self.hexNumber(boundary)) (\(Int64(Self.work(boundary).rounded())) hashes per share)")
        }
        session.job = Job(id: id, height: height, header: header, headerText: headerText, boundary: boundary, prefix: prefix)
    }

    /// A random start in the lower half of the nonce space, on a 4096 boundary, so two miners on one login without an
    /// extranonce rarely overlap.
    static func startCounter(bits: Int) -> UInt64 {
        guard bits > 13 else { return 0 }
        let half = bits >= 64 ? UInt64(1) << 63 : UInt64(1) << UInt64(bits - 1)
        return UInt64.random(in: 0 ..< half) & ~UInt64(4095)
    }

    // MARK: Numbers

    /// A U256 written as hex (with or without 0x, any number of digits up to 64) as four limbs, most significant first.
    static func limbs(_ value: Any?) -> [UInt64]? {
        guard let text = value as? String else { return nil }
        var digits = Substring(text.trimmingCharacters(in: .whitespaces))
        if digits.hasPrefix("0x") || digits.hasPrefix("0X") { digits = digits.dropFirst(2) }
        digits = digits.drop { $0 == "0" }
        guard digits.count <= 64 else { return nil }
        let padded = String(repeating: "0", count: 64 - digits.count) + digits
        let limbs = (0 ..< 4).compactMap { UInt64(padded.dropFirst(16 * $0).prefix(16), radix: 16) }
        return limbs.count == 4 ? limbs : nil
    }

    /// As conflux-rust writes a U256: lowercase hex without leading zeros.
    static func hexNumber(_ limbs: [UInt64]) -> String {
        guard let first = limbs.firstIndex(where: { $0 != 0 }) else { return "0x0" }
        return "0x" + String(limbs[first], radix: 16) + limbs[(first + 1)...].map { String(format: "%016llx", $0) }.joined()
    }

    static func double(_ limbs: [UInt64]) -> Double { limbs.reduce(0.0) { $0 * 0x1p64 + Double($1) } }

    /// Expected hashes per share: 2^256 / boundary (the share difficulty).
    static func work(_ boundary: [UInt64]) -> Double { 0x1p256 / max(double(boundary), 1) }

    /// The boundary for a difficulty in hashes per share: 2^256 / d.
    static func boundary(difficulty d: Double) -> [UInt64]? {
        guard d >= 1, d.isFinite else { return nil }
        if d >= 2, d < 0x1p64, d == d.rounded() { return OctopusReference.twoPow256(dividedBy: UInt64(d)) }
        var rest = 0x1p256 / d
        guard rest < 0x1p256 else { return [.max, .max, .max, .max] }
        return (0 ..< 4).map { k in
            let scale = Double(sign: .plus, exponent: 64 * (3 - k), significand: 1)
            let digit = (rest / scale).rounded(.down)
            rest -= digit * scale
            return UInt64(digit)
        }
    }

    /// 2^k as four limbs, most significant first.
    static func pow2Limbs(_ k: Int) -> [UInt64] {
        var limbs: [UInt64] = [0, 0, 0, 0]
        limbs[3 - k / 64] = 1 << UInt64(k % 64)
        return limbs
    }

    // MARK: JSON values

    static func integer(_ value: Any?) -> Int? {
        if let n = value as? NSNumber { return n.intValue }
        if let s = value as? String { return Int(s) ?? (s.hasPrefix("0x") ? Int(s.dropFirst(2), radix: 16) : nil) }
        return nil
    }

    static func number(_ value: Any?) -> Double? {
        if let n = value as? NSNumber { return n.doubleValue }
        if let s = value as? String { return Double(s) }
        return nil
    }

    static func string(_ value: Any?) -> String? {
        if let s = value as? String { return s }
        if let n = value as? NSNumber { return n.stringValue }
        return nil
    }

    static func bool(_ value: Any?) -> Bool? {
        if let b = value as? Bool { return b }
        if let s = value as? String { return s.lowercased() == "true" }
        return nil
    }

    /// true, "true" or [true, ...] with no error.
    static func accepted(_ reply: [String: Any]) -> Bool {
        if stratumError(reply) != nil { return false }
        if let list = reply["result"] as? [Any] { return list.first.flatMap { bool($0) } ?? false }
        return bool(reply["result"]) ?? false
    }

    /// Why a reply refuses, in the pool's words: the error, the reason in a [false, reason] result, or the bare result.
    static func refusal(_ reply: [String: Any]) -> String {
        if let error = stratumError(reply) { return error }
        if let list = reply["result"] as? [Any], list.count > 1 { return "\(list[1])" }
        return "the pool answered \(json(reply["result"] ?? NSNull()))"
    }

    static func json(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject([value]),
              let data = try? JSONSerialization.data(withJSONObject: [value]), let text = String(data: data, encoding: .utf8) else {
            return "\(value)"
        }
        let inner = String(text.dropFirst().dropLast())
        return inner.count > 400 ? String(inner.prefix(400)) + "…" : inner
    }

    // MARK: Live check

    /// Connects to the real pool without sending anything: in Conflux's dialect the first message, mining.subscribe,
    /// already carries the login. Reports whatever the pool sends unprompted within 3 s, then disconnects.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let started = now()
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        defer { connection.close() }
        let connected = now() - started
        var heard: [String] = []
        let end = now() + 3
        do {
            while now() < end, let message = try connection.nextNotification(timeout: end - now()) { heard.append(json(message)) }
        } catch {
            heard.append("(connection closed: \(error))")
        }
        return "\(endpoint.tls ? "TLS" : "TCP") connection up in \(Int(connected * 1000)) ms; nothing sent (Conflux's first message,"
            + " mining.subscribe, is the login); " + (heard.isEmpty ? "the pool sent nothing within 3 s" : "the pool sent: " + heard.joined(separator: " | "))
    }

    // MARK: Offline round trip

    private final class Mock {
        struct MockJob {
            var header: [UInt8]
            var height: Int
            var boundaries: [[UInt64]]
            var xn: String?
        }
        let lock = NSLock()
        let cache: [UInt32]
        let datasetBytes: Int
        let a: String, b: String
        var jobs: [String: MockJob] = [:]
        var current = ""
        var phase = 0
        var notifyID = 16
        var accepted: [String: Int] = [:]
        var firstPhase = 0, hardShares = 0, softAfterChange = 0, staleAfterB = 0
        var rejected: [(nonce: String, reason: String)] = []
        var seen = Set<String>()
        var wantInvalid = false
        var corrupted: String?
        var done = false
        var badPrefix = 0

        init(cache: [UInt32], datasetBytes: Int, a: String, b: String) {
            self.cache = cache
            self.datasetBytes = datasetBytes
            self.a = a
            self.b = b
        }

        func notify(_ id: String) -> [String: Any] {
            notifyID += 1
            let job = jobs[id]!
            var message: [String: Any] = ["jsonrpc": "2.0", "id": notifyID, "method": "mining.notify",
                                          "params": [id, String(job.height), "0x" + job.header.hex,
                                                     OctopusPoolMiner.hexNumber(job.boundaries.last!)]]
            if let xn = job.xn { message["xn"] = xn }
            return message
        }

        func respond(_ message: [String: Any], _ pool: MockPool) -> [[String: Any]] {
            lock.lock()
            defer { lock.unlock() }
            let id = message["id"] ?? NSNull()
            let params = message["params"] as? [Any] ?? []
            switch message["method"] as? String {
            case "mining.subscribe"?:
                // As conflux-rust: the subscribe is the login, and a refusal is a plain false.
                guard params.count == 2, params[0] as? String == "selftest/worker" else {
                    return [["jsonrpc": "2.0", "result": false, "id": id]]
                }
                return [["jsonrpc": "2.0", "result": true, "id": id], notify(current)]
            case "mining.submit"?:
                return [submit(id, params, pool)]
            default:
                return [["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "Method not found"]]]
            }
        }

        private func refuse(_ id: Any, _ nonce: String, _ reason: String) -> [String: Any] {
            rejected.append((nonce, reason))
            return ["jsonrpc": "2.0", "result": [false, reason], "id": id]
        }

        private func submit(_ id: Any, _ params: [Any], _ pool: MockPool) -> [String: Any] {
            guard params.count == 4, params[0] as? String == "selftest/worker", let jobID = params[1] as? String,
                  let job = jobs[jobID], let nonceText = params[2] as? String, params[3] as? String == "0x" + job.header.hex,
                  nonceText.hasPrefix("0x"), let nonce = UInt64(nonceText.dropFirst(2), radix: 16) else {
                return refuse(id, "?", "Solution for a stale job or malformed submit")
            }
            if let xn = job.xn, String(format: "%016llx", nonce).hasPrefix(xn) == false {
                badPrefix += 1
                return refuse(id, nonceText, "nonce outside xn \(xn)")
            }
            guard seen.insert(jobID + nonceText).inserted else { return refuse(id, nonceText, "Problem already solved") }
            let final = cache.withUnsafeBufferPointer { c in
                OctopusReference.hash(header: job.header, nonce: nonce, datasetBytes: datasetBytes) {
                    EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: $0)
                }.final
            }
            let value = OctopusReference.limbs(final)
            guard job.boundaries.contains(where: { value.lexicographicallyPrecedes($0) }) else {
                return refuse(id, nonceText, "Incorrect Nonce!")
            }
            let latest = value.lexicographicallyPrecedes(job.boundaries.last!)
            accepted[jobID, default: 0] += 1
            switch phase {
            case 0 where jobID == a:
                firstPhase += 1
                if firstPhase >= 3 {
                    // Difficulty change: the same problem again with a 64 times smaller boundary.
                    phase = 1
                    jobs[a]!.boundaries.append(OctopusPoolMiner.pow2Limbs(234))
                    pool.push(notify(a))
                }
            case 1 where jobID == a:
                if latest { hardShares += 1 } else { softAfterChange += 1 }
                if hardShares >= 3 {
                    phase = 2
                    current = b
                    pool.push(notify(b))
                }
            case 2 where jobID == a, 3 where jobID == a:
                staleAfterB += 1
            case 2 where jobID == b && accepted[b]! >= 3:
                phase = 3
                wantInvalid = true
            default:
                break
            }
            return ["jsonrpc": "2.0", "result": [true], "id": id]
        }

        func replace(_ nonce: UInt64) -> UInt64? {
            lock.lock()
            defer { lock.unlock() }
            guard wantInvalid else { return nil }
            wantInvalid = false
            corrupted = String(format: "0x%016llx", nonce ^ 1)
            return nonce ^ 1
        }

        func afterRefusal() {
            lock.lock()
            defer { lock.unlock() }
            if phase == 3, rejected.contains(where: { $0.nonce == corrupted }) {
                phase = 4
                done = true
            }
        }
    }

    static func selfTest(gpu: GPU) throws -> [String] {
        let vectorA = OctopusReference.vectors[6], vectorB = OctopusReference.vectors[4]
        // Quick sizes (stage 0 seed, 1 MiB cache, 64 MiB DAG); the mock checks shares from its own light cache.
        let cache = EthashReference.makeCache(size: OctopusReference.quickCacheBytes, seed: EthashReference.seed(iterations: 0))
        let a = "0x" + vectorA.problem, b = "0x" + vectorB.problem
        let mock = Mock(cache: cache, datasetBytes: OctopusReference.quickDatasetBytes, a: a, b: b)
        mock.jobs = [a: Mock.MockJob(header: [UInt8](hex: vectorA.problem)!, height: vectorA.height, boundaries: [pow2Limbs(240)], xn: nil),
                     b: Mock.MockJob(header: [UInt8](hex: vectorB.problem)!, height: vectorB.height, boundaries: [pow2Limbs(236)], xn: "5a")]
        mock.current = a
        let pool = try MockPool { message, pool in
            let replies = mock.respond(message, pool)
            if message["method"] as? String == "mining.submit" {
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { mock.afterRefusal() }
            }
            return replies
        }
        defer { pool.close() }

        // A login the pool doesn't know is refused with PoolLoginRefused, so the engine stops retrying it.
        let stranger = try OctopusPoolMiner(gpu: gpu, endpoint: pool.endpoint, login: "nobody/worker", events: PoolEvents())
        var refusal = "no refusal"
        let t0 = now()
        do {
            try stranger.run(shouldStop: { now() - t0 > 10 })
        } catch let error as PoolLoginRefused {
            refusal = error.reason
        }
        guard refusal.contains("false") else { throw MinerError("an unknown login wasn't refused as PoolLoginRefused: \(refusal)") }

        var accepted = 0, rejected: [String] = [], rates: [Double] = [], logs: [String] = []
        let events = PoolEvents(share: { ok, _, note in if ok { accepted += 1 } else { rejected.append(note ?? "") } },
                                hashrate: { rates.append($0) }, log: { logs.append($0) })
        let miner = try OctopusPoolMiner(gpu: gpu, endpoint: pool.endpoint, login: "selftest/worker", events: events)
        miner.quick = true
        miner.batch = 1 << 18
        miner.replaceShare = { mock.replace($0) }
        let started = now()
        var finished: Double?
        try miner.run(shouldStop: {
            mock.lock.lock()
            let done = mock.done
            mock.lock.unlock()
            if done, finished == nil { finished = now() }
            return (finished.map { now() - $0 > 0.2 } ?? false) || now() - started > 120
        })
        let seconds = now() - started

        mock.lock.lock()
        defer { mock.lock.unlock() }
        guard mock.done else {
            throw MinerError("stalled in phase \(mock.phase) after \(Int(seconds)) s: accepted \(mock.accepted.values.reduce(0, +)), refused \(mock.rejected.map { $0.reason }); miner log: \(logs.suffix(4))")
        }
        guard mock.badPrefix == 0 else { throw MinerError("\(mock.badPrefix) shares ignored the xn prefix") }
        guard mock.rejected.count == 1, let refused = mock.rejected.first, refused.nonce == mock.corrupted else {
            throw MinerError("the mock refused \(mock.rejected.map { "\($0.nonce): \($0.reason)" }), expected only the corrupted share")
        }
        guard rejected == ["Incorrect Nonce!"] else { throw MinerError("the miner reported refusals \(rejected)") }
        guard mock.softAfterChange <= 24, mock.staleAfterB <= 24 else {
            throw MinerError("\(mock.softAfterChange) shares at the old boundary after the change, \(mock.staleAfterB) for job A after job B")
        }
        let total = mock.accepted.values.reduce(0, +)
        guard accepted >= 9, accepted <= total else { throw MinerError("miner counted \(accepted) accepted shares, the mock \(total)") }
        let rate = rates.max().map { " · \(formatRate($0, "H/s"))" } ?? ""
        return [
            "unknown login: Conflux mining.subscribe refused (\(refusal)) → PoolLoginRefused",
            "login: Conflux mining.subscribe [login, password] accepted (JSON-RPC 2.0)",
            "job A = mainnet pivot block \(vectorA.height) (its pow hash and height; quick DAG, stage-0 seed), boundary 2^240:"
                + " \(mock.firstPhase) shares found on the GPU, each recomputed by the mock from its own light cache"
                + " (CPU reference, hash < boundary) and accepted with [true]",
            "difficulty change (job A re-sent with boundary 2^234, 64x smaller): \(mock.hardShares) shares below the new boundary,"
                + " \(mock.softAfterChange) in flight at the old one",
            "new job B = block \(vectorB.height) with \"xn\": \"5a\": \(mock.accepted[b] ?? 0) shares accepted, every nonce 0x5a…",
            "invalid share (a found nonce with its low bit flipped, \(refused.nonce)) refused by the mock with [false, \"\(refused.reason)\"];"
                + " the miner reported it rejected",
            "nonces submitted as 0x + 16 hex digits with the pow hash echoed; miner counted \(accepted) accepted, 1 rejected"
                + " in \(fmt(seconds, 1)) s\(rate)",
        ]
    }
}
