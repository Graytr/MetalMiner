import Foundation

enum StratumTests {
    /// A message as the JSON layer hands it over.
    static func message(_ json: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
    }

    static let suite = TestSuite(name: "Stratum", tests: [
        ("pools say no error with null, an empty string or false", { expect in
            expect.equal(stratumError(message(#"{"id":1,"result":true,"error":null}"#)), nil)
            expect.equal(stratumError(message(#"{"id":1,"result":true}"#)), nil)
            expect.equal(stratumError(message(#"{"id":1,"result":true,"error":""}"#)), nil)
            expect.equal(stratumError(message(#"{"id":1,"result":true,"error":false}"#)), nil)
        }),
        ("error forms become text", { expect in
            expect.equal(stratumError(message(#"{"id":1,"result":null,"error":[21,"Job not found",null]}"#)), "21 Job not found <null>")
            expect.equal(stratumError(message(#"{"id":1,"error":{"code":-1,"message":"Low difficulty share"}}"#)), "Low difficulty share")
            expect.equal(stratumError(message(#"{"id":1,"error":"Invalid login"}"#)), "Invalid login")
        }),
        ("a reply that echoes its method reaches the call", { expect in
            let pool = try MockPool { request, _ in
                [["id": request["id"] ?? NSNull(), "method": request["method"] ?? "", "result": true, "error": NSNull()]]
            }
            defer { pool.close() }
            let connection = try StratumConnection(host: "127.0.0.1", port: pool.port, tls: false)
            defer { connection.close() }
            let reply = try connection.call("mining.authorize", params: ["someone/rig", "x"], timeout: 5)
            expect.equal(reply["result"] as? Bool, true)
        }),
        ("a pool request that reuses a pending call's id is a notification", { expect in
            let pool = try MockPool { request, _ in
                let id = request["id"] ?? NSNull()
                return [["id": id, "method": "client.get_version", "params": [] as [Any]], ["id": id, "result": "answer", "error": NSNull()]]
            }
            defer { pool.close() }
            let connection = try StratumConnection(host: "127.0.0.1", port: pool.port, tls: false)
            defer { connection.close() }
            let reply = try connection.call("ask", params: [], timeout: 5)
            expect.equal(reply["result"] as? String, "answer")
            expect.equal(try connection.nextNotification(timeout: 2)?["method"] as? String, "client.get_version")
        }),
        ("waiting for notifications: queued ones first, no early wake-ups after them", { expect in
            let pool = try MockPool { request, _ in
                [["id": NSNull(), "method": "mining.notify", "params": ["job-1"]],
                 ["id": NSNull(), "method": "mining.notify", "params": ["job-2"]],
                 ["id": request["id"] ?? NSNull(), "result": "pong", "error": NSNull()]]
            }
            defer { pool.close() }
            let connection = try StratumConnection(host: "127.0.0.1", port: pool.port, tls: false)
            defer { connection.close() }
            _ = try connection.call("ping", params: [], timeout: 5)
            expect.equal(((try connection.nextNotification(timeout: 2))?["params"] as? [String])?.first, "job-1")
            expect.equal(((try connection.nextNotification(timeout: 2))?["params"] as? [String])?.first, "job-2")
            var start = now()
            expect.that(try connection.nextNotification(timeout: 0) == nil, "nothing should be left")
            expect.that(now() - start < 0.05, "timeout 0 waited \(fmt(now() - start, 3)) s")
            start = now()
            expect.that(try connection.nextNotification(timeout: 0.3) == nil, "nothing should arrive")
            expect.that(now() - start >= 0.29, "returned after \(fmt(now() - start, 3)) s, before the 0.3 s timeout")
        }),
    ])
}
