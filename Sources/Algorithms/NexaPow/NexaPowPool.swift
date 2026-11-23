import Foundation

/// Real Nexa mining on Kryptex's NEXA pool (slug "nexa"), in the Echelon protocol 1.0.4 (Nexa's Stratum,
/// spec.nexa.org/mining/echelon-protocol) or the MiningCore-style variant; see docs/specs/nexapow.md, "Pool protocol".
///
///     > mining.subscribe [agent]          < [[subscriptions], extranonce hex, extranonce2 size]
///     > mining.authorize [login, "x"]     < true
///     < mining.set_difficulty [d]         (applies from the next job)
///     < mining.notify, then > mining.submit, by notify shape:
///       Echelon (5 params):     [job, commitment, nbits, time, clean]  >  [login, job, nonce hex, time]
///         the commitment is written as a uint256 (byte-reversed); nonce = extranonce + extranonce2 size bytes
///       MiningCore-style (4):   [job, commitment, height, nbits]       >  [login, job, extranonce, ntime, 8 bytes hex]
///         the commitment is in internal byte order; nonce = extranonce + 8 bytes
///     < mining.set_extranonce [extranonce, size]   (applies from the next job)
///
/// The miner's part of the nonce is its counter, little-endian. A share's powHash, read as a little-endian number,
/// is at most Bitcoin's difficulty-1 target (0xFFFF * 2^208) / d. Kryptex's subscribe gives a 4-byte extranonce and
/// extranonce2 size 4 (Echelon itself has 8 and 8); which notify shape it sends is only known from a live login.
final class NexaPowPoolMiner: PoolMiner {
    static let pools = ["nexa"]
    static let algorithm = "nexapow"
    static let agent = "metalminer/1.0"

    let gpu: GPU
    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    /// Test settings (selfTest): the small --quick table, counters per GPU batch, the first counter of a job, and a
    /// hook that may replace a verified counter just before it is submitted (to send a deliberately invalid share).
    var quick = false
    var batch = 1 << 20
    var firstCounter: UInt64 = 0
    var replaceShare: ((UInt64) -> UInt64?)?

    private var nexapow: NexaPow?
    private var loaded: Job?

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        self.gpu = gpu
        self.endpoint = endpoint
        self.login = login
        self.events = events
    }

    enum Dialect: Equatable {
        case echelon
        case miningCore
    }

    struct Job: Equatable {
        var id: String
        /// Header commitment in internal byte order.
        var commitment: [UInt8]
        /// Echoed in Echelon submits.
        var time: String
        var target: NexaPowReference.U256
        var layout: NexaPow.NonceLayout
        /// The extranonce as the pool wrote it (MiningCore-style pools compare it as text).
        var extranonceText: String
        var dialect: Dialect
        var generation: Int
    }

    struct Reconnect {
        var host: String
        var port: UInt16
        var wait: Double
    }

    private final class Session {
        let host: String
        let port: UInt16
        var extranonce = ""
        var extranonce2Size = 8
        var nextExtranonce: (String, Int)?
        var difficulty: Double = 1
        var job: Job?
        var generation = 0
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
        let subscribe = try connection.call("mining.subscribe", params: [Self.agent])
        if let error = stratumError(subscribe) { throw MinerError("\(connection.label) refused mining.subscribe: \(error)") }
        guard let result = subscribe["result"] as? [Any], result.count >= 2, let hex = result[1] as? String,
              let extranonce = [UInt8](hex: hex), extranonce.count <= 8 else {
            throw MinerError("can't read the mining.subscribe reply: \(Self.json(subscribe))")
        }
        session.extranonce = hex
        if result.count > 2, let size = Self.integer(result[2]) { session.extranonce2Size = size }
        let authorize = try connection.call("mining.authorize", params: [login, "x"])
        guard Self.accepted(authorize) else {
            throw PoolLoginRefused(login: login, reason: stratumError(authorize) ?? "mining.authorize answered \(Self.json(authorize["result"] ?? NSNull()))")
        }
        events.log("logged in to \(connection.label) as \(login); extranonce \(hex), extranonce2 size \(session.extranonce2Size)")
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
            let built = nexapow == nil
            let np = try prepare(job)
            if built {   // the first job compiled the kernels and built the table: start the rate from here
                lastReport = now()
                hashes = 0
            }
            let remaining = job.layout.counterLimit.map { $0 > session.counter ? $0 - session.counter : 0 } ?? UInt64.max
            let count = Int(min(UInt64(batch), remaining))
            guard count > 0 else {
                session.exhausted = true
                events.log("job \(job.id): all \(job.layout.counterBytes)-byte counters searched; waiting for the next job")
                continue
            }
            let found = try np.searchJob(start: session.counter, count: count)
            hashes += Double(count)
            session.counter &+= UInt64(count)
            if found.hits > found.nonces.count { events.log("\(found.hits) hits in one batch; the first 62 are submitted") }
            while let message = try connection.nextNotification(timeout: 0) {
                if let move = try handle(message, session, connection) { return move }
            }
            for counter in found.nonces {
                if session.generation != job.generation {
                    events.log("job \(job.id) was replaced by a clean job; share dropped")
                    continue
                }
                try submit(counter, job: job, session, connection)
            }
            if now() - lastReport >= 5 {
                events.hashrate(hashes / (now() - lastReport))
                hashes = 0
                lastReport = now()
            }
        }
        return nil
    }

    /// The GPU state: the window table (built once), then the job's commitment, nonce layout and target.
    private func prepare(_ job: Job) throws -> NexaPow {
        if nexapow == nil {
            events.log("compiling the NexaPow kernels and building the window table…")
            let made = try NexaPow(gpu: gpu, config: AlgoConfig(quick: quick))
            events.log("NexaPow ready: \(made.setupSummary)")
            nexapow = made
        }
        let np = nexapow!
        if loaded != job {
            np.setJob(commitment: job.commitment, layout: job.layout, target: job.target)
            loaded = job
        }
        return np
    }

    /// Checks a GPU hit with the CPU reference, then submits it in the job's dialect.
    private func submit(_ counter: UInt64, job: Job, _ session: Session, _ connection: StratumConnection) throws {
        let nonce = job.layout.bytes(counter)
        let result = NexaPowReference.nexaPow(commitment: job.commitment, nonce: nonce)
        guard let pow = result.powHash, NexaPowReference.meetsTarget(pow, job.target) else {
            events.log("GPU nonce \(nonce.hex) fails the CPU check (powHash \(result.powHash.map { Array($0.reversed()).hex } ?? "none")); not submitted")
            return
        }
        let sent = job.layout.bytes(replaceShare?(counter) ?? counter)
        let id = session.nextID
        session.nextID += 1
        session.pending[id] = Self.work(job.target)
        let params: [Any]
        switch job.dialect {
        case .echelon:
            params = [login, job.id, sent.hex, job.time]
        case .miningCore:
            params = [login, job.id, job.extranonceText, "", Array(sent[job.layout.prefix.count...]).hex]
        }
        try connection.send(["id": id, "method": "mining.submit", "params": params])
    }

    private func handle(_ message: [String: Any], _ session: Session, _ connection: StratumConnection) throws -> Reconnect? {
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.notify"?:
            notify(params, session)
        case "mining.set_difficulty"?:
            if let d = Self.number(params.first), d > 0, d.isFinite { session.difficulty = d }
        case "mining.set_extranonce"?:
            if let hex = params.first as? String, let value = [UInt8](hex: hex), value.count <= 8 {
                session.nextExtranonce = (hex, params.count > 1 ? Self.integer(params[1]) ?? session.extranonce2Size : session.extranonce2Size)
            }
        case "client.reconnect"?:
            let host = (params.first as? String).flatMap { $0.isEmpty ? nil : $0 } ?? session.host
            let port = params.count > 1 ? Self.integer(params[1]).flatMap { UInt16(exactly: $0) } : nil
            let wait = params.count > 2 ? Self.number(params[2]) ?? 0 : 0
            return Reconnect(host: host, port: port ?? session.port, wait: min(max(wait, 0), 600))
        case "client.show_message"?:
            events.log("pool says: \(params.first.map { "\($0)" } ?? "")")
        case "client.get_version"?:
            if let id = message["id"], !(id is NSNull) { try connection.send(["id": id, "result": Self.agent, "error": NSNull()]) }
        case nil:
            guard let id = Self.integer(message["id"]), let work = session.pending.removeValue(forKey: id) else { return nil }
            let ok = Self.accepted(message)
            events.share(ok, work, ok ? nil : stratumError(message) ?? "refused: \(Self.json(message))")
        default:
            break
        }
        return nil
    }

    private func notify(_ params: [Any], _ session: Session) {
        guard params.count >= 4, let id = Self.string(params[0]), let hex = params[1] as? String,
              let raw = [UInt8](hex: hex), raw.count == 32 else {
            events.log("ignored a mining.notify I can't read: \(Self.json(params))")
            return
        }
        let dialect: Dialect = params.count == 4 ? .miningCore : .echelon
        if let next = session.nextExtranonce {
            (session.extranonce, session.extranonce2Size) = next
            session.nextExtranonce = nil
        }
        let prefix = [UInt8](hex: session.extranonce) ?? []
        let layout: NexaPow.NonceLayout
        do {
            layout = try NexaPow.NonceLayout(prefix: prefix, length: prefix.count + (dialect == .echelon ? session.extranonce2Size : 8))
        } catch {
            events.log("job \(id) can't be mined: \(error)")
            return
        }
        let clean = dialect == .echelon && params.count > 4 ? Self.bool(params[4]) ?? false : false
        if clean { session.generation += 1 }
        let commitment = dialect == .echelon ? Array(raw.reversed()) : raw
        let target = Self.target(difficulty: session.difficulty)
        if commitment != session.job?.commitment || layout != session.job?.layout {
            session.counter = firstCounter
            session.exhausted = false
        }
        if target != session.job?.target || dialect != session.job?.dialect || layout != session.job?.layout {
            events.log("job \(id): \(dialect == .echelon ? "Echelon" : "MiningCore-style") notify, nonce \(prefix.count)+\(layout.length - prefix.count)"
                       + " bytes, difficulty \(session.difficulty), \(Int64(Self.work(target).rounded())) hashes per share")
        }
        session.job = Job(id: id, commitment: commitment, time: dialect == .echelon ? Self.string(params[3]) ?? "" : "",
                          target: target, layout: layout, extranonceText: session.extranonce, dialect: dialect,
                          generation: session.generation)
    }

    // MARK: Numbers

    /// Bitcoin's difficulty-1 target 0xFFFF * 2^208 over d, as a little-endian 256-bit number (exact for d = 1).
    static func target(difficulty d: Double) -> NexaPowReference.U256 {
        var rest = 65535 * 0x1p208 / d
        guard rest.isFinite, rest < 0x1p256 else { return NexaPowReference.U256(.max, .max, .max, .max) }
        var lanes: [UInt64] = [0, 0, 0, 0]
        for k in (0 ..< 4).reversed() {
            let scale = Double(sign: .plus, exponent: 64 * k, significand: 1)
            let digit = (rest / scale).rounded(.down)
            rest -= digit * scale
            lanes[k] = UInt64(digit)
        }
        return NexaPowReference.U256(lanes[0], lanes[1], lanes[2], lanes[3])
    }

    /// Expected hashes per share: 2^256 / (target + 1).
    static func work(_ target: NexaPowReference.U256) -> Double {
        let value = (0 ..< 4).reversed().reduce(0.0) { $0 * 0x1p64 + Double(target[$1]) }
        return 0x1p256 / (value + 1)
    }

    // MARK: JSON values

    static func integer(_ value: Any?) -> Int? {
        if let n = value as? NSNumber { return n.intValue }
        if let s = value as? String { return Int(s) }
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

    static func accepted(_ reply: [String: Any]) -> Bool {
        if stratumError(reply) != nil { return false }
        if let list = reply["result"] as? [Any] { return list.first.flatMap { bool($0) } ?? false }
        return bool(reply["result"]) ?? false
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

    /// Connects to the real pool and sends mining.subscribe, the first message and not a login; reports the reply and
    /// anything else the pool sends within 3 s, then disconnects.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        defer { connection.close() }
        let reply = try connection.call("mining.subscribe", params: [agent], timeout: 10)
        var parts = ["mining.subscribe → \(json(reply))"]
        if let result = reply["result"] as? [Any], result.count >= 2, let hex = result[1] as? String {
            let size = result.count > 2 ? integer(result[2]).map { String($0) } ?? "?" : "?"
            parts.append("extranonce \(hex) (\(hex.count / 2) bytes), extranonce2 size \(size)")
        }
        var unsolicited: [String] = []
        let end = now() + 3
        do {
            while now() < end, let message = try connection.nextNotification(timeout: end - now()) { unsolicited.append(json(message)) }
        } catch {
            unsolicited.append("(connection closed: \(error))")
        }
        parts.append(unsolicited.isEmpty ? "nothing else within 3 s" : "then: " + unsolicited.joined(separator: " | "))
        return parts.joined(separator: "; ")
    }

    // MARK: Offline round trip

    /// The Echelon spec's hashing example: commitment (as written in a notify), nonce, and the resulting powHash.
    static let specCommitment = "0a4ac49b2d02e3c8d12c7093255ba7c49624f9c374d9f1c2f8e37c58705e74b0"
    static let specNonce = "10000000000000001182dc5800000000"
    static let specPowHash = "00000042cbc240375242e14641488a0e2dca7b54458a2cea23dc1d2c178bb188"

    private final class Mock {
        struct MockJob {
            var commitment: [UInt8]   // internal byte order
            var targets: [NexaPowReference.U256]
            var extranonce: String
            var nonceLength: Int
        }
        let lock = NSLock()
        let dialect: Dialect
        var jobs: [String: MockJob] = [:]
        var difficulty: Double
        var current: String
        var extranonce: String
        var phase = 0
        var accepted: [String: Int] = [:]
        var easyOnly = 0, staleAfterB = 0, badLayout = 0
        var vector: String?
        var rejected: [(nonce: String, reason: String)] = []
        var seen = Set<String>()
        var wantInvalid = false
        var corrupted: String?
        var done = false

        init(dialect: Dialect, current: String, extranonce: String, difficulty: Double) {
            self.dialect = dialect
            self.current = current
            self.extranonce = extranonce
            self.difficulty = difficulty
        }

        func notify(_ id: String, clean: Bool) -> [String: Any] {
            let job = jobs[id]!
            let params: [Any] = dialect == .echelon
                ? [id, Array(job.commitment.reversed()).hex, "1d00ffff", "0000000063b1fb60", clean]
                : [id, job.commitment.hex, 1_194_996, "1b02fab2"]
            return ["id": NSNull(), "method": "mining.notify", "params": params]
        }

        func respond(_ message: [String: Any], _ pool: MockPool) -> [[String: Any]] {
            lock.lock()
            defer { lock.unlock() }
            let id = message["id"] ?? NSNull()
            let params = message["params"] as? [Any] ?? []
            switch message["method"] as? String {
            case "mining.subscribe"?:
                return [["id": id, "result": [[["mining.set_difficulty", "s1"], ["mining.notify", "s1"]], extranonce,
                                              dialect == .echelon ? 8 : 4], "error": NSNull()]]
            case "mining.authorize"?:
                guard params.first as? String == "selftest/worker" else {
                    return [["id": id, "result": false, "error": [24, "Unauthorized worker", NSNull()]]]
                }
                return [["id": id, "result": true, "error": NSNull()],
                        ["id": NSNull(), "method": "mining.set_difficulty", "params": [difficulty]], notify(current, clean: true)]
            case "mining.submit"?:
                return [submit(id, params, pool)]
            default:
                return [["id": id, "result": NSNull(), "error": [20, "unknown method", NSNull()]]]
            }
        }

        private func refuse(_ id: Any, _ nonce: String, _ code: Int, _ reason: String) -> [String: Any] {
            rejected.append((nonce, reason))
            return ["id": id, "result": false, "error": [code, reason, NSNull()]]
        }

        private func submit(_ id: Any, _ params: [Any], _ pool: MockPool) -> [String: Any] {
            guard params.first as? String == "selftest/worker", params.count >= 4, let jobID = params[1] as? String,
                  let job = jobs[jobID] else {
                return refuse(id, "?", 21, "Job not found")
            }
            let nonceHex: String
            switch dialect {
            case .echelon:
                guard params.count == 4, let hex = params[2] as? String, params[3] as? String == "0000000063b1fb60" else {
                    return refuse(id, "?", 20, "malformed submit")
                }
                nonceHex = hex
            case .miningCore:
                guard params.count == 5, params[2] as? String == job.extranonce, let hex = params[4] as? String, hex.count == 16 else {
                    return refuse(id, "?", 20, "invalid extranonce or nonce")
                }
                nonceHex = job.extranonce + hex
            }
            guard nonceHex.hasPrefix(job.extranonce), let nonce = [UInt8](hex: nonceHex), nonce.count == job.nonceLength else {
                badLayout += 1
                return refuse(id, nonceHex, 20, "incorrect nonce")
            }
            guard seen.insert(jobID + nonceHex).inserted else { return refuse(id, nonceHex, 22, "Duplicate share") }
            let result = NexaPowReference.nexaPow(commitment: job.commitment, nonce: nonce)
            guard let pow = result.powHash, job.targets.contains(where: { NexaPowReference.meetsTarget(pow, $0) }) else {
                return refuse(id, nonceHex, 23, "Low difficulty share")
            }
            let latest = NexaPowReference.meetsTarget(pow, job.targets.last!)
            let previous = job.targets.count > 1 && NexaPowReference.meetsTarget(pow, job.targets[job.targets.count - 2])
            accepted[jobID, default: 0] += 1
            switch (dialect, phase) {
            case (.echelon, 0) where jobID == "a1":
                // The first share must be the spec's example nonce, with the spec's powHash; then an easier difficulty.
                vector = nonceHex + " " + Array(pow.reversed()).hex
                phase = 1
                difficulty = 0x1p-18
                jobs["a1"]!.targets.append(NexaPowPoolMiner.target(difficulty: difficulty))
                pool.push(["id": NSNull(), "method": "mining.set_difficulty", "params": [difficulty]])
                pool.push(notify("a1", clean: false))
            case (.echelon, 1) where jobID == "a1":
                if latest && !previous { easyOnly += 1 }
                if easyOnly >= 3 {
                    // A new extranonce as Kryptex hands them out (4 bytes, extranonce2 size 4: an 8-byte nonce), then a clean job.
                    phase = 2
                    current = "b2"
                    extranonce = "3153f1c9"
                    pool.push(["id": NSNull(), "method": "mining.set_extranonce", "params": [extranonce, 4]])
                    pool.push(notify("b2", clean: true))
                }
            case (.echelon, 2) where jobID == "a1", (.echelon, 3) where jobID == "a1":
                staleAfterB += 1
            case (.echelon, 2) where jobID == "b2" && accepted["b2"]! >= 3:
                phase = 3
                wantInvalid = true
            case (.miningCore, _) where accepted[jobID]! >= 2:
                done = true
            default:
                break
            }
            return ["id": id, "result": true, "error": NSNull()]
        }

        func replace(_ counter: UInt64) -> UInt64? {
            lock.lock()
            defer { lock.unlock() }
            guard wantInvalid, let job = jobs[current], let prefix = [UInt8](hex: job.extranonce),
                  let layout = try? NexaPow.NonceLayout(prefix: prefix, length: job.nonceLength) else { return nil }
            wantInvalid = false
            corrupted = layout.bytes(counter ^ 1).hex
            return counter ^ 1
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

    /// Runs one miner against a mock until it is done, after checking that an unknown login is refused with
    /// PoolLoginRefused. Returns that refusal, the miner's accepted count, refusals, best rate and seconds.
    private static func drive(_ mock: Mock, gpu: GPU, firstCounter: UInt64, batch: Int) throws
        -> (refusal: String, accepted: Int, rejected: [String], rate: Double, seconds: Double) {
        let pool = try MockPool { message, pool in
            let replies = mock.respond(message, pool)
            if message["method"] as? String == "mining.submit" {
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { mock.afterRefusal() }
            }
            return replies
        }
        defer { pool.close() }

        let stranger = try NexaPowPoolMiner(gpu: gpu, endpoint: pool.endpoint, login: "nobody/worker", events: PoolEvents())
        var refusal = "no refusal"
        let t0 = now()
        do {
            try stranger.run(shouldStop: { now() - t0 > 10 })
        } catch let error as PoolLoginRefused {
            refusal = error.reason
        }
        guard refusal.contains("Unauthorized") else { throw MinerError("an unknown login wasn't refused as PoolLoginRefused: \(refusal)") }

        var accepted = 0, rejected: [String] = [], rates: [Double] = [], logs: [String] = []
        let events = PoolEvents(share: { ok, _, note in if ok { accepted += 1 } else { rejected.append(note ?? "") } },
                                hashrate: { rates.append($0) }, log: { logs.append($0) })
        let miner = try NexaPowPoolMiner(gpu: gpu, endpoint: pool.endpoint, login: "selftest/worker", events: events)
        miner.quick = true
        miner.batch = batch
        miner.firstCounter = firstCounter
        miner.replaceShare = { mock.replace($0) }
        let started = now()
        var finished: Double?
        try miner.run(shouldStop: {
            mock.lock.lock()
            let done = mock.done
            mock.lock.unlock()
            if done, finished == nil { finished = now() }
            return (finished.map { now() - $0 > 0.2 } ?? false) || now() - started > 150
        })
        mock.lock.lock()
        let done = mock.done, phase = mock.phase, refused = mock.rejected.map { $0.reason }
        mock.lock.unlock()
        guard done else {
            throw MinerError("stalled in phase \(phase) after \(Int(now() - started)) s: refused \(refused); miner log: \(logs.suffix(4))")
        }
        return (refusal, accepted, rejected, rates.max() ?? 0, now() - started)
    }

    static func selfTest(gpu: GPU) throws -> [String] {
        typealias Ref = NexaPowReference
        // Echelon: job a1 is the spec's hashing example (its commitment and extranonce); the first counter is set just
        // below the example's, so the GPU must find exactly the spec's nonce at a target the example meets.
        let echelon = Mock(dialect: .echelon, current: "a1", extranonce: "1000000000000000", difficulty: 1.0 / 128)
        echelon.jobs = ["a1": Mock.MockJob(commitment: Ref.reversedHex(specCommitment), targets: [target(difficulty: 1.0 / 128)],
                                           extranonce: "1000000000000000", nonceLength: 16),
                        "b2": Mock.MockJob(commitment: Ref.sha256(Array("metalminer pool selftest job b2".utf8)),
                                           targets: [target(difficulty: 0x1p-18)], extranonce: "3153f1c9", nonceLength: 8)]
        let exampleCounter: UInt64 = 0x58dc_8211   // the example nonce's last 8 bytes, 1182dc5800000000, little-endian
        let a = try drive(echelon, gpu: gpu, firstCounter: exampleCounter - 300, batch: 1 << 14)

        echelon.lock.lock()
        defer { echelon.lock.unlock() }
        guard echelon.vector == specNonce + " " + specPowHash else {
            throw MinerError("the first share was \(echelon.vector ?? "none"), not the spec's nonce \(specNonce) with powHash \(specPowHash)")
        }
        guard echelon.badLayout == 0 else { throw MinerError("\(echelon.badLayout) shares had the wrong extranonce or length") }
        guard echelon.rejected.count == 1, let refused = echelon.rejected.first, refused.nonce == echelon.corrupted else {
            throw MinerError("the mock refused \(echelon.rejected.map { "\($0.nonce): \($0.reason)" }), expected only the corrupted share")
        }
        guard a.rejected.count == 1, a.rejected[0].contains("Low difficulty") else { throw MinerError("the miner reported refusals \(a.rejected)") }
        guard echelon.staleAfterB <= 24 else { throw MinerError("\(echelon.staleAfterB) shares for job a1 after the clean job b2") }
        let totalA = echelon.accepted.values.reduce(0, +)
        guard a.accepted >= 7, a.accepted <= totalA else { throw MinerError("miner counted \(a.accepted) accepted shares, the mock \(totalA)") }

        // The MiningCore-style variant: 4-byte extranonce1, 12-byte nonce, commitment in internal order, height in the job.
        let fork = Mock(dialect: .miningCore, current: "c1", extranonce: "c0ffee01", difficulty: 0x1p-18)
        fork.jobs = ["c1": Mock.MockJob(commitment: Ref.reversedHex(specCommitment), targets: [target(difficulty: 0x1p-18)],
                                        extranonce: "c0ffee01", nonceLength: 12)]
        let b = try drive(fork, gpu: gpu, firstCounter: 0, batch: 1 << 14)
        fork.lock.lock()
        defer { fork.lock.unlock() }
        guard fork.rejected.isEmpty, fork.badLayout == 0, b.rejected.isEmpty, b.accepted >= 2 else {
            throw MinerError("MiningCore-style run: mock refused \(fork.rejected.map { $0.reason }), miner refusals \(b.rejected), accepted \(b.accepted)")
        }
        let rate = max(a.rate, b.rate)
        return [
            "unknown login: mining.authorize refused (\(a.refusal)) → PoolLoginRefused",
            "Echelon login: mining.subscribe gave extranonce 1000000000000000 and extranonce2 size 8; mining.authorize accepted",
            "job a1 = the Echelon spec's hashing example (commitment \(specCommitment.prefix(8))… written as a uint256), difficulty 1/128:"
                + " the GPU's first share was exactly the spec's nonce \(specNonce), and the mock's CPU reference gave the spec's powHash"
                + " \(specPowHash.prefix(16))…",
            "difficulty change to 2^-18 (job a1 re-sent): \(echelon.easyOnly) shares only the new target allows, each recomputed by"
                + " the mock (CPU NexaPow, powHash <= target) and accepted",
            "mining.set_extranonce 3153f1c9 with size 4 (Kryptex's shape: an 8-byte nonce) + clean job b2: \(echelon.accepted["b2"] ?? 0)"
                + " shares accepted, every nonce 3153f1c9 + a 4-byte counter",
            "invalid share (a found nonce with its counter's low bit flipped) refused by the mock: \(refused.reason); the miner reported it rejected",
            "MiningCore-style notify (4 params; extranonce1 c0ffee01, 12-byte nonce, commitment in internal order): \(fork.accepted["c1"] ?? 0)"
                + " shares accepted with submit [login, job, extranonce1, ntime, 8 nonce bytes]",
            "miner counted \(a.accepted + b.accepted) accepted, 1 rejected in \(fmt(a.seconds + b.seconds, 1)) s"
                + (rate > 0 ? " · \(formatRate(rate, "H/s"))" : ""),
        ]
    }
}
