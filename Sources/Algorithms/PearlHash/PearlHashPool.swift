import Foundation

/// Real mining on Kryptex's Pearl pool (`prl`), in the Stratum dialect independent miners captured from it
/// (docs/specs/pearlhash.md, "Pool protocol"):
///
///     -> mining.subscribe  ["metalminer/1.0"]                                 never answered; sent without waiting
///     -> mining.authorize  ["<wallet or username>/<worker>", "d=2097152"]     share difficulty in the password
///     <- mining.notify     {job_id, header: the 76-byte job header, target: 256-bit big-endian hex, height, cert_version}
///     -> mining.submit     {worker, job_id, plain_proof: base64 of Pearl's bincode PlainProof}
///     <- result true, or an error
///
/// A share opens the winning tile's rows of A and columns of B with their Merkle paths (PearlHashPlainProof). The
/// pool checks it with BLAKE3 alone and makes the block's Plonky2 proof itself when a share is also a block: miners
/// never prove. Each GPU hit is re-checked on the CPU reference before it is sent.
final class PearlHashPoolMiner: PoolMiner {
    static let pools = ["prl"]
    static let algorithm = PearlHashAlgorithm.id
    static let agent = "metalminer/1.0"
    /// Kryptex's minimum (and default) share difficulty, 2^21 units of 2^32 hashes (~27 min per share at 5.6 TH/s),
    /// asked for explicitly in the password field.
    static let shareDifficulty = 2_097_152
    static var password: String { "d=\(shareDifficulty)" }

    /// One pool job, ready for the GPU.
    struct Job {
        let id: String
        /// The 76 bytes mined on (zk-pow IncompleteBlockHeader), verbatim.
        let header: [UInt8]
        let height: Int?
        /// Certificate version 3 (mainnet from height 99,000) salts the noise seeds.
        let salted: Bool
        /// The pool's share target, and what the GPU compares jackpot hashes with: that target rounded down to compact
        /// form (as a pool that checks shares with nbits sees it) times the work of one attempt.
        let target: [UInt32]
        let bound: [UInt32]
        /// A share's expected work: 2^256 / target hashes (on Kryptex, difficulty x 2^32).
        var work: Double { PearlHashTarget.work(target) }
    }

    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    /// The verified kernels and this miner's matrices.
    let pearl: PearlHashAlgorithm
    private(set) var job: Job?
    /// GPU hits the CPU reference didn't confirm. They are never submitted; this stays 0 unless something is broken.
    private(set) var unconfirmedHits = 0
    private var difficulty: Double?
    private var reconnectAfter: Double?
    private var mining: (header: [UInt8], salted: Bool)?
    private var nonce: UInt64 = 0

    convenience init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        var config = AlgoConfig()
        // For live tests: another common dimension (a multiple of 128 from 2,048 to 65,536), should a pool want one.
        if let k = ProcessInfo.processInfo.environment["PEARLHASH_POOL_K"] { config.options["k"] = k }
        try self.init(gpu: gpu, endpoint: endpoint, login: login, events: events, config: config)
    }

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents, config: AlgoConfig) throws {
        self.endpoint = endpoint
        self.login = login
        self.events = events
        pearl = try PearlHashAlgorithm(gpu: gpu, config: config)
    }

    func run(shouldStop: () -> Bool) throws {
        var connection = try open()
        defer { connection.close() }
        var batch = 4
        var reportStart = now()
        var reportWork = 0.0
        func report() {
            let elapsed = now() - reportStart
            if elapsed > 0.5, reportWork > 0 { events.hashrate(reportWork / elapsed) }
            reportStart = now()
            reportWork = 0
        }
        while !shouldStop() {
            while let message = try connection.nextNotification(timeout: job == nil ? 0.5 : 0) { handle(message) }
            if let wait = reconnectAfter {
                reconnectAfter = nil
                job = nil
                connection.close()
                events.log("\(endpoint.pool) asked for a reconnect")
                let resume = now() + min(max(wait, 0), 30)
                while now() < resume, !shouldStop() { Thread.sleep(forTimeInterval: 0.1) }
                if shouldStop() { break }
                connection = try open()
                continue
            }
            guard let current = job else { continue }
            if mining?.header != current.header || mining?.salted != current.salted {
                guard let header = PearlHashHeader(bytes: current.header) else { continue }
                pearl.setJob(header: header, salted: current.salted)
                mining = (current.header, current.salted)
                nonce = UInt64.random(in: 0 ... .max)
            }
            let start = now()
            let hits = try pearl.search(startNonce: nonce, count: batch, bound: current.bound)
            let took = max(now() - start, 1e-3)
            nonce &+= UInt64(batch)
            reportWork += Double(batch) * pearl.hashesPerInstance
            // About 0.2 s per batch: the GPU stays busy, new jobs are picked up quickly, and the watchdog is far away.
            batch = max(1, min(64, Int((Double(batch) * min(2, max(0.5, 0.2 / took))).rounded())))
            for hit in hits { try submit(hit, of: current, on: connection) }
            if now() - reportStart >= 5 { report() }
        }
        report()
    }

    /// Connects, sends mining.subscribe, logs in. Throws when the pool refuses the login.
    private func open() throws -> StratumConnection {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        do {
            // Kryptex never answers mining.subscribe (live, 2026-11-20), but the captures that logged in sent it first, so it
            // goes out without waiting. Id 0 is one `call` never uses; a late reply is ignored as an unknown message.
            try connection.send(["id": 0, "method": "mining.subscribe", "params": [Self.agent]])
            var reply = try connection.call("mining.authorize", params: [login, Self.password], timeout: 20)
            if let error = stratumError(reply), error.lowercased().contains("object") {
                reply = try connection.call("mining.authorize", params: ["wallet": login, "pass": Self.password, "agent": Self.agent],
                                            timeout: 20)
            }
            if let error = stratumError(reply) { throw PoolLoginRefused(login: login, reason: error) }
            guard (reply["result"] as? Bool) == true else { throw PoolLoginRefused(login: login, reason: "no reason given") }
        } catch {
            connection.close()
            throw error
        }
        events.log("logged in to \(endpoint) as \(login)")
        return connection
    }

    private func handle(_ message: [String: Any]) {
        let params = message["params"]
        switch message["method"] as? String {
        case "mining.notify"?:
            guard let fields = params as? [String: Any] else {
                events.log("ignored a mining.notify without named params")
                return
            }
            do {
                let next = try makeJob(fields)
                if next.id != job?.id || next.target != job?.target {
                    events.log("job \(next.id)" + (next.height.map { " at height \($0)" } ?? "")
                               + String(format: ", share difficulty %.0f", next.work / 4_294_967_296))
                }
                job = next
            } catch {
                events.log("ignored a job: \(error)")
            }
        case "mining.set_difficulty"?:
            if let value = (params as? [Any])?.first as? NSNumber, value.doubleValue >= 1 { difficulty = value.doubleValue }
        case "client.reconnect"?:
            reconnectAfter = (params as? [Any]).flatMap { $0.count > 2 ? $0[2] as? NSNumber : nil }?.doubleValue ?? 0
        case "client.show_message"?:
            if let text = (params as? [Any])?.first as? String { events.log("\(endpoint.pool) says: \(text)") }
        default:
            break   // replies to calls that timed out, and anything unknown
        }
    }

    /// A job from mining.notify's named params. The target is authoritative; without one, a difficulty (the job's
    /// own, its id's "_<difficulty>" suffix or mining.set_difficulty) gives one in the pdiff convention.
    func makeJob(_ fields: [String: Any]) throws -> Job {
        guard let id = (fields["job_id"] as? String) ?? (fields["job_id"] as? NSNumber)?.stringValue, !id.isEmpty else {
            throw MinerError("no job_id")
        }
        guard let hex = fields["header"] as? String, let header = [UInt8](hex: hex), header.count == 76 else {
            throw MinerError("job \(id): the header is not 76 bytes of hex")
        }
        var sent = (fields["target"] as? String).flatMap { PearlHashTarget.fromHex($0) }
        if sent == nil {
            let suffix = id.contains("_") ? id.split(separator: "_").last.flatMap { Double($0) } : nil
            let d = (fields["difficulty"] as? NSNumber)?.doubleValue ?? (fields["diff"] as? NSNumber)?.doubleValue ?? suffix ?? difficulty
            if let d, d >= 1 { sent = PearlHashTarget.pdiff(difficulty: UInt64(min(d, 1e18))) }
        }
        guard let target = sent, target != PearlHashTarget.zero else { throw MinerError("job \(id): no usable share target") }
        let height = (fields["height"] as? NSNumber)?.intValue
        let certificate = (fields["cert_version"] as? NSNumber)?.intValue
        let config = pearl.config
        let bound = PearlHashReference.scale(PearlHashTarget.compactFloor(target), by: min(config.attemptWork, config.penalizedAttemptWork))
        return Job(id: id, header: header, height: height, salted: certificate.map { $0 >= 3 } ?? ((height ?? .max) >= 99_000),
                   target: target, bound: bound)
    }

    /// Builds the share, checks it on the CPU reference as the pool will, sends it and reports the pool's answer.
    private func submit(_ hit: PearlHashAlgorithm.Hit, of job: Job, on connection: StratumConnection) throws {
        let bytes = try pearl.plainProof(nonce: hit.nonce, tRows: hit.tRows, tCols: hit.tCols).bytes
        let verdict = PearlHashPlainProof.verify(bytes: bytes, header: job.header, target: job.target, salted: job.salted)
        guard verdict.isAccepted else {
            unconfirmedHits += 1
            events.log("GPU hit (nonce \(String(hit.nonce, radix: 16)), tile \(hit.tRows), \(hit.tCols)) not submitted: \(verdict.description)")
            return
        }
        let reply: [String: Any]
        do {
            reply = try connection.call("mining.submit", params: ["worker": login, "job_id": job.id,
                                                                  "plain_proof": Data(bytes).base64EncodedString()], timeout: 30)
        } catch {
            // No answer in time: report it and keep mining, unless the connection is gone (then this throws).
            if let message = try connection.nextNotification(timeout: 0) { handle(message) }
            events.share(false, job.work, "no answer from the pool: \(error)")
            return
        }
        let error = stratumError(reply)
        let accepted = error == nil && (reply["result"] as? Bool) == true
        events.share(accepted, job.work, accepted ? nil : error ?? "result \(reply["result"].map { "\($0)" } ?? "missing")")
    }

    // MARK: - Checks

    /// Connects to the real pool, sends mining.subscribe (the first message that isn't the login), reports the answer
    /// and disconnects without logging in.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let start = now()
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        defer { connection.close() }
        let connected = now() - start
        var answer: String
        var pushed: [String: Any]?
        do {
            let t = now()
            let reply = try connection.call("mining.subscribe", params: [agent], timeout: 10)
            answer = "mining.subscribe answered in \(Int((now() - t) * 1000)) ms: \(compactJSON(reply))"
        } catch {
            var state = "the connection stayed open"
            do { pushed = try connection.nextNotification(timeout: 0) } catch { state = "the pool closed the connection: \(error)" }
            answer = "mining.subscribe: no answer within 10 s, \(state)"
        }
        if pushed == nil { pushed = try? connection.nextNotification(timeout: 1) }
        if let pushed { answer += "; the pool sent \(compactJSON(pushed))" }
        return "\(endpoint.tls ? "TLS" : "TCP") connection in \(Int(connected * 1000)) ms; \(answer); disconnected without logging in"
    }

    static func compactJSON(_ object: Any) -> String {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "\(object)" }
        return text.count > 400 ? String(text.prefix(400)) + "..." : text
    }

    /// Offline round trip against a MockPool speaking Kryptex's dialect: jobs from a real block header, GPU shares
    /// checked by the test pool with the CPU reference, a new job with a 16x harder target mid-run, a client.reconnect,
    /// then invalid shares that must be refused.
    static func selfTest(gpu: GPU) throws -> [String] {
        let t0 = now()
        var lines = [try PearlHashTestPool.merkleCheck()]

        // Block 145,681's real header (the benchmark job), then two later templates at the same height, as a pool
        // sends when transactions arrive: newer time, another merkle root. V3 certificates; easy share targets.
        let block = PearlHashAlgorithm.referenceHeader
        func template(_ seconds: UInt32, _ tag: String) -> [UInt8] {
            var header = block
            header.timestamp += seconds
            header.merkleRoot = PearlHashBlake3.hash(Array(tag.utf8))
            return header.bytes
        }
        let height = PearlHashAlgorithm.referenceHeight
        let pool = PearlHashTestPool(jobs: [
            .init(id: "6f1a2c3b_256", header: block.bytes, height: height, difficulty: 256),
            .init(id: "93d0e4f5_4096", header: template(29, "metalminer test template 2"), height: height, difficulty: 4096),
            .init(id: "0b7c8d9e_256", header: template(71, "metalminer test template 3"), height: height, difficulty: 256),
        ], perJob: 2)
        let mock = try MockPool { message, _ in pool.respond(message) }
        defer { mock.close() }

        let recorder = PearlHashTestPool.Recorder()
        let events = PoolEvents(share: { recorder.share($0, $1, $2) }, hashrate: { recorder.rate($0) }, log: { recorder.log($0) })
        let login = "selftest/metalminer"
        let miner = try PearlHashPoolMiner(gpu: gpu, endpoint: mock.endpoint, login: login, events: events, config: AlgoConfig())
        let setup = now() - t0
        let deadline = now() + 150
        let stopped = DispatchSemaphore(value: 0)
        Thread {
            do { try miner.run(shouldStop: { pool.done || now() > deadline }) } catch { recorder.fail(error) }
            stopped.signal()
        }.start()
        stopped.wait()
        let mined = now() - t0 - setup
        if let failure = recorder.failure { throw MinerError("the miner stopped with an error: \(failure)") }
        let shares = pool.shares
        let jobs = pool.jobs
        guard pool.done else {
            throw MinerError("not done after 150 s: shares per job \(jobs.map { job in shares.filter { $0.job == job.id }.count }); "
                             + "miner log: \(recorder.logs.suffix(4).joined(separator: " | "))")
        }

        // Every GPU share was accepted by the pool's CPU check, and the miner reported each with its job's work.
        let refused = shares.filter { !$0.accepted }
        guard refused.isEmpty else { throw MinerError("the test pool refused GPU shares: \(refused.map(\.reply))") }
        let reported = recorder.shares
        guard reported.count == shares.count, reported.allSatisfy(\.accepted) else {
            throw MinerError("the miner reported \(reported.count) shares (\(reported.filter { !$0.accepted }.count) refused), the pool saw \(shares.count)")
        }
        for (share, report) in zip(shares, reported) {
            let work = jobs.first { $0.id == share.job }!.work
            guard abs(report.work / work - 1) < 1e-9 else { throw MinerError("share on \(share.job) credited \(report.work) H, expected \(work)") }
        }
        guard miner.unconfirmedHits == 0 else { throw MinerError("\(miner.unconfirmedHits) GPU hits failed the CPU check") }
        let logins = pool.logins
        guard logins.count == 2, logins.allSatisfy({ $0 == [login, password] }) else { throw MinerError("logins seen: \(logins)") }
        let counts = jobs.map { job in shares.filter { $0.job == job.id }.count }
        guard counts[0] >= 2, counts[1] >= 2, counts[2] >= 1 else { throw MinerError("shares per job \(counts)") }
        guard let rate = recorder.rates.max(), rate > 0 else { throw MinerError("no hashrate reported") }
        let switchedAt = shares.first { $0.job == jobs[1].id }?.at ?? 0

        // Shares the pool must refuse, sent on a fresh connection after the miner stopped.
        let job3 = jobs[2]
        guard miner.pearl.header.bytes == job3.header, let good = shares.last(where: { $0.job == job3.id })?.bytes else {
            throw MinerError("the miner didn't end on job 3")
        }
        var corrupted = good
        corrupted[32 + 8 + 8 + 100] ^= 0x01   // a byte of the first opened chunk of A
        var weak: [UInt8] = []
        for nonce in UInt64(1) ... 8 where weak.isEmpty {   // tile (0, 0) of fresh instances, until one misses the target
            let bytes = try miner.pearl.plainProof(nonce: nonce, tRows: 0, tCols: 0).bytes
            if case .lowDifficulty = PearlHashPlainProof.verify(bytes: bytes, header: job3.header, target: job3.target, salted: true) { weak = bytes }
        }
        guard !weak.isEmpty else { throw MinerError("no low-difficulty tile found to test with") }
        let check = try StratumConnection(host: mock.endpoint.host, port: mock.port, tls: false)
        defer { check.close() }
        _ = try check.call("mining.authorize", params: ["selftest/check", "x"])
        var refusals: [String] = []
        for (what, jobID, bytes, code) in [("a flipped byte in an opened row of A", job3.id, corrupted, 26),
                                           ("tile (0, 0) of a fresh instance", job3.id, weak, 23),
                                           ("an accepted share sent again", job3.id, good, 22),
                                           ("a job the pool never sent", "00000000_256", good, 21)] {
            let reply = try check.call("mining.submit", params: ["worker": "selftest/check", "job_id": jobID,
                                                                 "plain_proof": Data(bytes).base64EncodedString()])
            guard let error = stratumError(reply), error.hasPrefix("\(code) ") else {
                throw MinerError("\(what) was not refused with code \(code): \(compactJSON(reply))")
            }
            refusals.append("\(what) -> \(error.replacingOccurrences(of: " <null>", with: ""))")
        }

        let k = miner.pearl.config.k
        lines += [
            "test pool 127.0.0.1:\(mock.port) in Kryptex's dialect (subscribe left unanswered; authorize [login, \"\(password)\"]; named notify and submit);"
                + " miner set up in \(fmt(setup, 1)) s: A \(miner.pearl.m)x\(k), B \(k)x\(miner.pearl.n), rank 128, 4x8 tiles",
            "job 1 = block \(height)'s header, cert v3, difficulty 256: \(counts[0]) GPU shares, each re-checked by the pool on the CPU"
                + " (Merkle openings, noise, jackpot, hash <= target x 65,536) and accepted",
            "job 2 (new template, difficulty 4,096 = 16x harder) pushed mid-run: first share on it at \(fmt(switchedAt, 1)) s;"
                + " \(counts[1]) accepted at the new target, each credited \(formatRate(jobs[1].work, "H"))",
            "client.reconnect: reconnected and logged in again; job 3: \(counts[2]) accepted; GPU hits the CPU didn't confirm: 0",
            "refused: " + refusals.joined(separator: "; "),
            "PlainProof \(good.count) bytes (\(Data(good).base64EncodedString().count) base64 chars); peak \(formatRate(rate, "H/s"))"
                + " (GPU shared); \(fmt(mined, 1)) s mining, \(fmt(now() - t0, 1)) s in all",
        ]
        return lines
    }
}

/// The pool side of PearlHashPoolMiner.selfTest: Kryptex's dialect on a MockPool, and every share checked the way a
/// pool runs Pearl's `verify_plain_proof`, here with the CPU reference.
final class PearlHashTestPool {
    struct Job {
        let id: String
        let header: [UInt8]
        let height: Int
        let difficulty: UInt64
        var target: [UInt32] { PearlHashTarget.kryptex(difficulty: difficulty) }
        var work: Double { PearlHashTarget.work(target) }
    }

    struct Share {
        let job: String
        let accepted: Bool
        let reply: String
        let bytes: [UInt8]
        /// Seconds since the test pool started.
        let at: Double
    }

    /// What the miner reported through PoolEvents.
    final class Recorder {
        private let lock = NSLock()
        private var _shares: [(accepted: Bool, work: Double, note: String?)] = []
        private var _rates: [Double] = []
        private var _logs: [String] = []
        private var _failure: Error?

        func share(_ accepted: Bool, _ work: Double, _ note: String?) { lock.lock(); _shares.append((accepted, work, note)); lock.unlock() }
        func rate(_ value: Double) { lock.lock(); _rates.append(value); lock.unlock() }
        func log(_ line: String) { lock.lock(); _logs.append(line); lock.unlock() }
        func fail(_ error: Error) { lock.lock(); _failure = error; lock.unlock() }
        var failure: Error? { lock.lock(); defer { lock.unlock() }; return _failure }
        var shares: [(accepted: Bool, work: Double, note: String?)] { lock.lock(); defer { lock.unlock() }; return _shares }
        var rates: [Double] { lock.lock(); defer { lock.unlock() }; return _rates }
        var logs: [String] { lock.lock(); defer { lock.unlock() }; return _logs }
    }

    /// Job 1 at the first login; job 2 once job 1 has `perJob` accepted shares; a client.reconnect once job 2 has;
    /// job 3 at the next login; done after one accepted share on job 3.
    let jobs: [Job]
    let perJob: Int
    private let lock = NSLock()
    private let start = now()
    private var issued = Set<String>()
    private var seen = Set<[UInt8]>()
    private var phase = 0
    private var _logins: [[String]] = []
    private var _shares: [Share] = []
    private var _done = false

    init(jobs: [Job], perJob: Int) {
        self.jobs = jobs
        self.perJob = perJob
    }

    var done: Bool { lock.lock(); defer { lock.unlock() }; return _done }
    var logins: [[String]] { lock.lock(); defer { lock.unlock() }; return _logins }
    var shares: [Share] { lock.lock(); defer { lock.unlock() }; return _shares }

    static func notify(_ job: Job) -> [String: Any] {
        ["id": NSNull(), "method": "mining.notify",
         "params": ["job_id": job.id, "header": job.header.hex, "target": PearlHashTarget.hex(job.target), "height": job.height,
                    "cert_version": 3] as [String: Any]]
    }

    func respond(_ message: [String: Any]) -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        let id = message["id"] ?? NSNull()
        func reply(_ result: Any) -> [String: Any] { ["id": id, "result": result, "error": NSNull()] }
        func refuse(_ code: Int, _ text: String) -> [String: Any] { ["id": id, "result": NSNull(), "error": [code, text, NSNull()] as [Any]] }
        switch message["method"] as? String {
        case "mining.subscribe"?:
            return []   // Kryptex never answers it (handshake, 2026-11-20)
        case "mining.authorize"?:
            guard let params = message["params"] as? [String], params.count == 2 else { return [refuse(20, "params must be [login, password]")] }
            _logins.append(params)
            let job = _logins.count == 1 ? jobs[0] : jobs[2]
            issued.insert(job.id)
            return [Self.notify(job), reply(true)]   // the job before the ack, as some Pearl pools send it
        case "mining.submit"?:
            guard let fields = message["params"] as? [String: Any], let jobID = fields["job_id"] as? String,
                  let encoded = fields["plain_proof"] as? String else { return [refuse(20, "params must be an object")] }
            guard issued.contains(jobID), let job = jobs.first(where: { $0.id == jobID }) else { return [refuse(21, "job not found")] }
            guard let data = Data(base64Encoded: encoded) else { return [refuse(25, "bad proof encoding")] }
            let bytes = [UInt8](data)
            let digest = PearlHashBlake3.hash(bytes)
            guard !seen.contains(digest) else { return [refuse(22, "duplicate share")] }
            let verdict = PearlHashPlainProof.verify(bytes: bytes, header: job.header, target: job.target, salted: true)
            var out: [[String: Any]]
            switch verdict {
            case .accepted:
                seen.insert(digest)
                out = [reply(true)]
            case .lowDifficulty:
                out = [refuse(23, "low difficulty share")]
            case .invalid(let why):
                out = [refuse(26, "invalid proof: \(why)")]
            }
            _shares.append(Share(job: jobID, accepted: verdict.isAccepted, reply: verdict.description, bytes: bytes, at: now() - start))
            guard verdict.isAccepted else { return out }
            func accepted(_ job: Job) -> Int { _shares.filter { $0.accepted && $0.job == job.id }.count }
            if phase == 0, accepted(jobs[0]) >= perJob {
                phase = 1
                issued.insert(jobs[1].id)
                out.append(Self.notify(jobs[1]))
            } else if phase == 1, accepted(jobs[1]) >= perJob {
                phase = 2
                out.append(["id": NSNull(), "method": "client.reconnect", "params": [Any]()])
            } else if phase == 2, accepted(jobs[2]) >= 1 {
                phase = 3
                _done = true
            }
            return out
        default:
            return [refuse(20, "method not supported")]
        }
    }

    /// The Merkle tree against plain BLAKE3: for 2 to 9 chunks (odd counts carry a node up a layer), the root equals the
    /// keyed hash, and multi-leaf openings rebuild it.
    static func merkleCheck() throws -> String {
        let key = PearlHashBlake3.hash(Array("metalminer merkle check".utf8))
        var openings = 0
        for chunks in 2 ... 9 {
            let data = (0 ..< chunks * 1024).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ $0 / 1024) }
            let tree = PearlHashMerkleTree(data: data, key: key)
            guard tree.root == PearlHashBlake3.hash(data, key: key) else { throw MinerError("Merkle root of \(chunks) chunks differs from BLAKE3") }
            for rows in [[0], [chunks - 1], [0, chunks - 1], Array(stride(from: 1, to: chunks, by: 2))] where !rows.isEmpty {
                let opening = tree.open(rows: rows, rowLength: 1024, data: data)
                guard PearlHashMerkleTree.root(of: opening, key: key) == tree.root else {
                    throw MinerError("opening rows \(rows) of \(chunks) chunks doesn't rebuild the root")
                }
                openings += 1
            }
        }
        return "Merkle tree: roots of 2-9 chunks equal BLAKE3 keyed hashes; \(openings) multi-leaf openings rebuild them"
    }
}
