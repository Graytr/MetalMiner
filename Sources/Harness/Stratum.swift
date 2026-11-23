import Foundation
import Network

/// A Stratum connection: newline-delimited JSON-RPC over TCP or TLS. Replies are matched to calls by id; everything
/// else the pool sends (mining.notify, mining.set_difficulty, job, client.reconnect, ...) queues as a notification.
final class StratumConnection {
    let label: String
    /// Merged into every request, e.g. ["jsonrpc": "2.0"] for pools that require it.
    var requestFields: [String: Any] = [:]
    /// Called with every line sent (">") and received ("<"), for tests and debugging.
    var trace: ((String) -> Void)?
    /// When set (the CLI's --trace), every new connection prints its traffic.
    static var printTraffic = false

    private let connection: NWConnection
    private let queue: DispatchQueue
    /// Guards the state below; broadcast when a notification arrives or the connection fails.
    private let lock = NSCondition()
    private var buffer = Data()
    private var nextID = 1
    private var waiting: [Int: DispatchSemaphore] = [:]
    private var replies: [Int: [String: Any]] = [:]
    private var notifications: [[String: Any]] = []
    private var failure: Error?

    init(host: String, port: UInt16, tls: Bool, timeout: TimeInterval = 15) throws {
        label = "\(host):\(port)"
        queue = DispatchQueue(label: "stratum \(host):\(port)")
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw MinerError("bad port \(port)") }
        connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: tls ? .tls : .tcp)
        let ready = DispatchSemaphore(value: 0)
        var startError: Error?
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let error), .waiting(let error):
                startError = error
                ready.signal()
            default: break
            }
        }
        connection.start(queue: queue)
        if ready.wait(timeout: .now() + timeout) == .timedOut {
            connection.cancel()
            throw MinerError("timed out connecting to \(label)")
        }
        if let startError {
            connection.cancel()
            throw MinerError("can't connect to \(label): \(startError)")
        }
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed(let error): self?.fail(error)
            case .cancelled: self?.fail(MinerError("connection to \(self?.label ?? "pool") closed"))
            default: break
            }
        }
        if Self.printTraffic { trace = { print("   \($0)") } }
        receive()
    }

    deinit { connection.cancel() }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.consume(data) }
            if let error { return self.fail(error) }
            if complete { return self.fail(MinerError("pool closed the connection")) }
            self.receive()
        }
    }

    private func consume(_ data: Data) {
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex ..< newline]
            buffer.removeSubrange(buffer.startIndex ... newline)
            guard !line.isEmpty else { continue }
            trace?("< " + (String(data: line, encoding: .utf8) ?? "(binary)"))
            guard let message = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
            route(message)
        }
    }

    /// A reply carries the id of one of our calls and either no method or a result or error (some pools echo the
    /// method in replies); anything else is a notification or a request from the pool. Ids may come back as numbers
    /// or numeric strings.
    private func route(_ message: [String: Any]) {
        let id = (message["id"] as? NSNumber)?.intValue ?? (message["id"] as? String).flatMap { Int($0) }
        let isReply = message["method"] == nil || message["result"] != nil || stratumError(message) != nil
        lock.lock()
        if isReply, let id, let waiter = waiting.removeValue(forKey: id) {
            replies[id] = message
            lock.unlock()
            waiter.signal()
            return
        }
        notifications.append(message)
        lock.broadcast()
        lock.unlock()
    }

    private func fail(_ error: Error) {
        lock.lock()
        if failure == nil { failure = error }
        let waiters = Array(waiting.values)
        waiting.removeAll()
        lock.broadcast()
        lock.unlock()
        waiters.forEach { $0.signal() }
    }

    /// True until the connection fails or is closed.
    var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return failure == nil
    }

    private func checkOpen() throws {
        lock.lock()
        defer { lock.unlock() }
        if let failure { throw failure }
    }

    /// Sends one JSON object as a line, fire-and-forget (use `call` when a reply is expected).
    func send(_ message: [String: Any]) throws {
        try checkOpen()
        var data = try JSONSerialization.data(withJSONObject: message)
        trace?("> " + (String(data: data, encoding: .utf8) ?? ""))
        data.append(0x0A)
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error { self?.fail(error) }
        })
    }

    /// Sends a request and waits for its reply (the whole reply object: read "result" and "error").
    func call(_ method: String, params: Any, timeout: TimeInterval = 20) throws -> [String: Any] {
        try checkOpen()
        let waiter = DispatchSemaphore(value: 0)
        lock.lock()
        let id = nextID
        nextID += 1
        waiting[id] = waiter
        lock.unlock()
        var request = requestFields
        request["id"] = id
        request["method"] = method
        request["params"] = params
        try send(request)
        if waiter.wait(timeout: .now() + timeout) == .timedOut {
            lock.lock()
            waiting[id] = nil
            lock.unlock()
            throw MinerError("\(method): no reply from \(label) within \(Int(timeout)) s")
        }
        lock.lock()
        let reply = replies.removeValue(forKey: id)
        lock.unlock()
        guard let reply else { try checkOpen(); throw MinerError("\(method): connection to \(label) closed") }
        return reply
    }

    /// The next notification or pool request, or nil after `timeout` seconds (0 checks without waiting). Queued
    /// messages come first; after them it throws once the connection has failed.
    func nextNotification(timeout: TimeInterval) throws -> [String: Any]? {
        let deadline = Date(timeIntervalSinceNow: max(0, timeout))
        lock.lock()
        defer { lock.unlock() }
        while notifications.isEmpty, failure == nil, lock.wait(until: deadline) {}
        if !notifications.isEmpty { return notifications.removeFirst() }
        if let failure { throw failure }
        return nil
    }

    func close() { connection.cancel() }
}

/// The error a reply carries, if any, as text; nil when the call succeeded. Pools say "no error" with null, an empty
/// string or false.
func stratumError(_ reply: [String: Any]) -> String? {
    guard let error = reply["error"], !(error is NSNull) else { return nil }
    if let text = error as? String, text.isEmpty { return nil }
    if let flag = error as? NSNumber, CFGetTypeID(flag) == CFBooleanGetTypeID(), !flag.boolValue { return nil }
    if let parts = error as? [Any] { return parts.map { "\($0)" }.joined(separator: " ") }
    if let object = error as? [String: Any] { return (object["message"] as? String) ?? "\(object)" }
    return "\(error)"
}
