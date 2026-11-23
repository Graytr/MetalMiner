import Foundation
import Network

/// What each algorithm folder provides: its benchmarkable algorithms and the pool miners that mine its coins for
/// real. build.sh declares the conformance for every folder it compiles; a folder without pool miners gets none.
protocol AlgorithmFamily {
    static var algorithms: [MiningAlgorithm.Type] { get }
    static var poolMiners: [PoolMiner.Type] { get }
}

extension AlgorithmFamily {
    static var poolMiners: [PoolMiner.Type] { [] }
}

/// Where a pool listens.
struct PoolEndpoint: Codable, CustomStringConvertible {
    var host: String
    var port: UInt16
    var tls: Bool
    /// Kryptex pool slug, e.g. "rvn" or "xtm-c29" ("mock" for tests).
    var pool: String

    var description: String { "\(tls ? "stratum+ssl" : "stratum+tcp")://\(host):\(port)" }

    /// The pool's address from Kryptex's pool info: the given region ("Global" by default), SSL unless `tls` is false.
    static func kryptex(pool: String, region: String = "Global", tls: Bool = true) throws -> PoolEndpoint {
        guard let info = try Earnings.getJSON("/\(pool)/api/v1/pool/info") as? [String: Any],
              let servers = info["servers"] as? [[String: Any]] else { throw MinerError("no server list for \(pool)") }
        let server = servers.first { ($0["geo"] as? String)?.caseInsensitiveCompare(region) == .orderedSame } ?? servers.first
        let urls = (server?[tls ? "ssl_urls" : "urls"] as? [String]) ?? []
        guard let address = urls.first, let colon = address.lastIndex(of: ":"),
              let port = UInt16(address[address.index(after: colon)...]) else {
            throw MinerError("no \(tls ? "SSL" : "TCP") address for \(pool) in \(region)")
        }
        return PoolEndpoint(host: String(address[..<colon]), port: port, tls: tls, pool: pool)
    }
}

/// What a pool miner tells whoever runs it. `work` is a share's expected work in the algorithm's unit (hashes, or
/// graphs for Cuckoo), so its value is work x (USD per unit per day) / 86,400.
struct PoolEvents {
    var share: (_ accepted: Bool, _ work: Double, _ note: String?) -> Void = { _, _, _ in }
    var hashrate: (_ rate: Double) -> Void = { _ in }
    var log: (_ line: String) -> Void = { _ in }
}

/// What a pool miner throws when the pool refuses its login (an unknown account, a bad wallet address). Retrying can't
/// help, so the engine stops mining that coin for real until the payout settings change.
struct PoolLoginRefused: Error, CustomStringConvertible {
    let login: String
    /// The pool's own words, e.g. "Invalid wallet address".
    let reason: String
    var description: String { "the pool refused the login \(login): \(reason)" }
}

/// Real mining on one coin's pool: speaks its Stratum dialect, turns jobs into GPU work, submits shares. Written per
/// coin, in the algorithm's folder, and listed in `<Folder>Family.poolMiners`.
protocol PoolMiner: AnyObject {
    /// Kryptex pool slugs this miner speaks, e.g. ["rvn", "quai-kawpow"].
    static var pools: [String] { get }
    /// The algorithm id it mines with, as in the benchmarks and ranking.
    static var algorithm: String { get }
    /// `login` is "username/worker" or "wallet/worker" (MinerSettings.login(coin:)).
    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws
    /// Connects, logs in and mines until `shouldStop()` returns true. Throws `PoolLoginRefused` when the pool refuses
    /// the login, and another error when the connection fails; reconnecting is the caller's job.
    func run(shouldStop: () -> Bool) throws
    /// Offline check against a MockPool: real jobs in, valid shares out, an invalid share refused. One line per check.
    static func selfTest(gpu: GPU) throws -> [String]
    /// Optional live check without logging in: connect to the real pool and describe what it says first.
    static func handshake(endpoint: PoolEndpoint) throws -> String
}

extension PoolMiner {
    static func handshake(endpoint: PoolEndpoint) throws -> String { "no handshake check written" }
}

/// A pool on 127.0.0.1 for offline tests. It accepts miners, answers each message they send with `respond`, and can
/// push notifications (new jobs, difficulty changes) at any time.
final class MockPool {
    private(set) var port: UInt16 = 0
    private let listener: NWListener
    private let queue = DispatchQueue(label: "mock pool")
    private let lock = NSLock()
    private var connection: NWConnection?
    private var buffer = Data()
    private var log: [[String: Any]] = []
    private let respond: (_ message: [String: Any], _ pool: MockPool) -> [[String: Any]]

    var endpoint: PoolEndpoint { PoolEndpoint(host: "127.0.0.1", port: port, tls: false, pool: "mock") }
    /// Everything the miner has sent so far.
    var received: [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        return log
    }

    init(respond: @escaping (_ message: [String: Any], _ pool: MockPool) -> [[String: Any]]) throws {
        self.respond = respond
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
            if case .failed = state { ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)
        guard let port = listener.port?.rawValue else { throw MinerError("mock pool couldn't listen") }
        self.port = port
    }

    deinit { close() }

    private func accept(_ connection: NWConnection) {
        lock.lock()
        self.connection?.cancel()
        self.connection = connection
        buffer = Data()
        lock.unlock()
        connection.start(queue: queue)
        receive(on: connection)
    }

    private func receive(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data { self.consume(data) }
            if error == nil, !complete { self.receive(on: connection) }
        }
    }

    private func consume(_ data: Data) {
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex ..< newline]
            buffer.removeSubrange(buffer.startIndex ... newline)
            guard let message = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
            lock.lock()
            log.append(message)
            lock.unlock()
            for reply in respond(message, self) { push(reply) }
        }
    }

    /// Sends a message to the connected miner.
    func push(_ message: [String: Any]) {
        lock.lock()
        let connection = self.connection
        lock.unlock()
        guard let connection, var data = try? JSONSerialization.data(withJSONObject: message) else { return }
        data.append(0x0A)
        connection.send(content: data, completion: .idempotent)
    }

    func close() {
        listener.cancel()
        lock.lock()
        connection?.cancel()
        lock.unlock()
    }
}
