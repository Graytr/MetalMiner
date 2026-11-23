import Foundation

/// EthereumStratum/1.0.0 (NiceHash's spec; ethminer's "stratum2"): mining.subscribe names the protocol and returns the
/// extranonce (the nonce's first bytes), mining.set_difficulty (difficulty 1 = 0x00000000ffff00…00, applied from the
/// next job), mining.notify [job id, seed hash, header hash, clean], mining.submit [login, job id, nonce without the
/// extranonce]. The pool recomputes the mix digest itself.
final class EthashStratumDialect: EthashPoolDialect {
    /// The pool didn't answer mining.subscribe as an EthereumStratum/1.0.0 pool.
    struct NotSpoken: Error, CustomStringConvertible { let description: String }

    let name = "EthereumStratum/1.0.0"
    private(set) var job: EthashPoolJob?
    private(set) var extranonce: [UInt8] = []
    /// The spec: difficulty 1 until the pool sets one.
    private var target = EthashTarget.fromDifficulty(1, diff1: EthashTarget.stratumDiff1)

    func login(_ connection: StratumConnection, login: String, log: (String) -> Void) throws {
        let reply: [String: Any]
        do {
            reply = try connection.call("mining.subscribe", params: [EthashPoolKit.agent, "EthereumStratum/1.0.0"], timeout: 5)
        } catch {
            throw NotSpoken(description: "no answer to mining.subscribe (\(error))")
        }
        if let error = stratumError(reply) { throw NotSpoken(description: "mining.subscribe refused: \(error)") }
        guard let result = reply["result"] as? [Any], let subscription = result.first as? [Any], subscription.count >= 3,
              subscription[2] as? String == "EthereumStratum/1.0.0" else {
            throw NotSpoken(description: "mining.subscribe answered without EthereumStratum/1.0.0")
        }
        extranonce = try EthashPoolValue.extranonce(result.count > 1 ? result[1] : nil, maxBytes: 4)
        let authorized = try connection.call("mining.authorize", params: [login, "x"], timeout: 15)
        if let error = stratumError(authorized) { throw PoolLoginRefused(login: login, reason: error) }
        if authorized["result"] as? Bool == false { throw PoolLoginRefused(login: login, reason: "mining.authorize returned false") }
        log("logged in with EthereumStratum/1.0.0, extranonce \(extranonce.isEmpty ? "none" : extranonce.hex)")
    }

    func handle(_ message: [String: Any], connection: StratumConnection, log: (String) -> Void) throws -> Bool {
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.set_difficulty"?:
            if let difficulty = EthashPoolValue.double(params.first), difficulty > 0 {
                target = EthashTarget.fromDifficulty(difficulty, diff1: EthashTarget.stratumDiff1)
            } else {
                log("ignored mining.set_difficulty \(EthashPoolKit.describe(params))")
            }
            return true
        case "mining.notify"?:
            guard params.count >= 3, let id = EthashPoolValue.jobID(params[0]), let seed = EthashPoolValue.hash(params[1]),
                  let header = EthashPoolValue.hash(params[2]) else {
                log("ignored a malformed mining.notify")
                return true
            }
            job = EthashPoolJob(id: id, header: header, seed: seed, height: nil, target: target, extranonce: extranonce)
            return true
        case "mining.set_extranonce"?:
            extranonce = try EthashPoolValue.extranonce(params.first, maxBytes: 4)   // from the next job on
            log("extranonce now \(extranonce.isEmpty ? "none" : extranonce.hex)")
            return true
        default:
            return false
        }
    }

    func submit(_ solution: EthashPoolSolution, job: EthashPoolJob, login: String) -> [String: Any] {
        let nonce = String(String(format: "%016llx", solution.nonce).dropFirst(2 * job.extranonce.count))
        return ["method": "mining.submit", "params": [login, job.id, nonce]]
    }

    func idle(_ connection: StratumConnection, log: (String) -> Void) throws {}
}

/// ETHPROXY (eth-proxy; ethminer's "stratum1"): eth_submitLogin [login, password], eth_getWork, new work pushed as
/// {"id": 0, "result": [header hash, seed hash, target(, height)]}, eth_submitWork [nonce, header hash, mix digest], all
/// 0x-prefixed. No extranonce: the whole 64-bit nonce is ours.
final class EthashProxyDialect: EthashPoolDialect {
    let name = "ETHPROXY"
    private(set) var job: EthashPoolJob?
    private var lastWork = now()

    func login(_ connection: StratumConnection, login: String, log: (String) -> Void) throws {
        connection.requestFields = ["jsonrpc": "2.0"]
        let reply = try connection.call("eth_submitLogin", params: [login, "x"], timeout: 15)
        if let error = stratumError(reply) { throw PoolLoginRefused(login: login, reason: error) }
        if reply["result"] as? Bool == false { throw PoolLoginRefused(login: login, reason: "eth_submitLogin returned false") }
        try requestWork(connection, log: log)
        log("logged in with ETHPROXY")
    }

    private func requestWork(_ connection: StratumConnection, log: (String) -> Void) throws {
        let reply = try connection.call("eth_getWork", params: [] as [Any], timeout: 15)
        lastWork = now()
        if let error = stratumError(reply) { return log("eth_getWork: \(error)") }
        if let fields = reply["result"] as? [Any] { apply(fields, id: nil, log: log) }
    }

    private func apply(_ fields: [Any], id: String?, log: (String) -> Void) {
        guard fields.count >= 3, let header = EthashPoolValue.hash(fields[0]), let seed = EthashPoolValue.hash(fields[1]),
              let target = (fields[2] as? String).flatMap(EthashTarget.parse) else {
            return log("ignored malformed work \(EthashPoolKit.describe(fields))")
        }
        let height = fields.count > 3 ? EthashPoolValue.int(fields[3]) : nil
        job = EthashPoolJob(id: id ?? String(header.hex.prefix(16)), header: header, seed: seed, height: height, target: target,
                            extranonce: [])
        lastWork = now()
    }

    func handle(_ message: [String: Any], connection: StratumConnection, log: (String) -> Void) throws -> Bool {
        if message["method"] == nil, let fields = message["result"] as? [Any] {
            apply(fields, id: nil, log: log)
            return true
        }
        // Some eth-proxy pools push "mining.notify" [job id, header hash, seed hash, target(, height)] instead.
        if message["method"] as? String == "mining.notify", let params = message["params"] as? [Any], params.count >= 4 {
            apply(Array(params.dropFirst()), id: EthashPoolValue.jobID(params[0]), log: log)
            return true
        }
        return false
    }

    func submit(_ solution: EthashPoolSolution, job: EthashPoolJob, login: String) -> [String: Any] {
        ["jsonrpc": "2.0", "method": "eth_submitWork",
         "params": [String(format: "0x%016llx", solution.nonce), "0x" + job.header.hex, "0x" + solution.mix.hex]]
    }

    /// Asks again when the pool has sent no work for a minute.
    func idle(_ connection: StratumConnection, log: (String) -> Void) throws {
        if now() - lastWork > 60 { try requestWork(connection, log: log) }
    }
}

/// Real mining on Kryptex's Ethash pools. Logs in with EthereumStratum/1.0.0 when the pool speaks it (a unique
/// extranonce per connection), otherwise with ETHPROXY, as ethminer's autodetection does, and keeps that choice.
class EthashPoolMinerBase: PoolMiner {
    class var chain: EthashChain { fatalError("subclasses set chain") }
    class var pools: [String] { [] }
    class var algorithm: String { chain.id }

    let session: EthashPoolSession
    private var useProxy: Bool?

    required init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        session = EthashPoolSession(endpoint: endpoint, login: login, events: events,
                                    search: try EthashJobSearch(gpu: gpu, chain: Self.chain))
    }

    func run(shouldStop: () -> Bool) throws {
        try session.run(shouldStop: shouldStop) { endpoint in try self.connect(endpoint) }
    }

    private func connect(_ endpoint: PoolEndpoint) throws -> (StratumConnection, EthashPoolDialect) {
        let log = session.events.log
        if useProxy != true {
            let connection = try EthashPoolKit.connect(endpoint)
            let dialect = EthashStratumDialect()
            do {
                try dialect.login(connection, login: session.login, log: log)
                useProxy = false
                return (connection, dialect)
            } catch let notSpoken as EthashStratumDialect.NotSpoken {
                connection.close()
                log("\(notSpoken); trying ETHPROXY")
            } catch {
                connection.close()
                throw error
            }
        }
        let connection = try EthashPoolKit.connect(endpoint)
        let dialect = EthashProxyDialect()
        do {
            try dialect.login(connection, login: session.login, log: log)
        } catch {
            connection.close()
            throw error
        }
        useProxy = true
        return (connection, dialect)
    }

    class func selfTest(gpu: GPU) throws -> [String] { try EthashPoolTest.run(self, gpu: gpu) }

    /// Sends only mining.subscribe with EthereumStratum/1.0.0 (ETHPROXY's first message is the login itself), reports
    /// the answer and anything the pool pushes in the next 2 s, and disconnects.
    class func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try EthashPoolKit.connect(endpoint)
        defer { connection.close() }
        var parts: [String] = []
        let start = now()
        do {
            let reply = try connection.call("mining.subscribe", params: [EthashPoolKit.agent, "EthereumStratum/1.0.0"], timeout: 10)
            let ms = Int((now() - start) * 1000)
            if let error = stratumError(reply) {
                parts.append("mining.subscribe refused in \(ms) ms (\(error)): ETHPROXY only")
            } else if let result = reply["result"] as? [Any], let subscription = result.first as? [Any], subscription.count >= 3,
                      subscription[2] as? String == "EthereumStratum/1.0.0" {
                let extranonce = result.count > 1 ? EthashPoolKit.describe(result[1]) : "none"
                parts.append("speaks EthereumStratum/1.0.0 (answered in \(ms) ms, extranonce \(extranonce))")
            } else {
                parts.append("answered mining.subscribe in \(ms) ms but not as EthereumStratum/1.0.0: \(EthashPoolKit.describe(reply["result"]))")
            }
        } catch {
            parts.append("no answer to mining.subscribe within 10 s (\(error)): ETHPROXY only")
        }
        parts += EthashPoolKit.pushed(connection, seconds: 2)
        return parts.joined(separator: "; ")
    }
}

final class EthashPoolMinerETC: EthashPoolMinerBase {
    override class var chain: EthashChain { .ethereumClassic }
    override class var pools: [String] { ["etc"] }
}

final class EthashPoolMinerETHW: EthashPoolMinerBase {
    override class var chain: EthashChain { .ethereumPoW }
    override class var pools: [String] { ["ethw"] }
}

final class EthashPoolMinerOcta: EthashPoolMinerBase {
    override class var chain: EthashChain { .octaSpace }
    override class var pools: [String] { ["octa"] }
}

extension EthashFamily {
    static let poolMiners: [PoolMiner.Type] = [EthashPoolMinerETC.self, EthashPoolMinerETHW.self, EthashPoolMinerOcta.self]
}
