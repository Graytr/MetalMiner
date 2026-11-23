import Foundation

/// A named group of unit tests. Each test gets an `Expect` to record its failures in.
struct TestSuite {
    let name: String
    let tests: [(name: String, body: (Expect) throws -> Void)]
}

/// One test's checks. A failed check records the file and line and the test carries on.
final class Expect {
    private(set) var failures: [String] = []

    func that(_ condition: Bool, _ message: @autoclosure () -> String = "expected true",
              file: StaticString = #fileID, line: UInt = #line) {
        if !condition { failures.append("\(file):\(line): \(message())") }
    }

    func equal<T: Equatable>(_ actual: T, _ expected: T, file: StaticString = #fileID, line: UInt = #line) {
        if actual != expected { failures.append("\(file):\(line): got \(actual), expected \(expected)") }
    }

    func near(_ actual: Double, _ expected: Double, within tolerance: Double,
              file: StaticString = #fileID, line: UInt = #line) {
        if !(abs(actual - expected) <= tolerance) {
            failures.append("\(file):\(line): got \(actual), expected \(expected) ± \(tolerance)")
        }
    }

    /// Passes when `body` throws an error whose text contains `text`.
    func throwsError(containing text: String, file: StaticString = #fileID, line: UInt = #line, _ body: () throws -> Void) {
        do {
            try body()
            failures.append("\(file):\(line): expected an error containing \"\(text)\", got none")
        } catch {
            if !"\(error)".contains(text) { failures.append("\(file):\(line): the error \"\(error)\" doesn't contain \"\(text)\"") }
        }
    }
}

enum TestRunner {
    /// Runs every test whose "Suite.test" name contains `filter` (all of them when nil). Returns the exit status.
    static func run(_ suites: [TestSuite], filter: String?) -> Int32 {
        var passed = 0, failed = 0
        let start = now()
        for suite in suites {
            for test in suite.tests {
                let name = "\(suite.name).\(test.name)"
                if let filter, !name.localizedCaseInsensitiveContains(filter) { continue }
                let expect = Expect()
                do { try test.body(expect) } catch { expect.that(false, "threw \(error)") }
                if expect.failures.isEmpty {
                    passed += 1
                    print("  ok    \(name)")
                } else {
                    failed += 1
                    print("  FAIL  \(name)")
                    for failure in expect.failures { print("          \(failure)") }
                }
            }
        }
        print("\(passed) passed, \(failed) failed (\(fmt(now() - start, 1)) s)")
        return failed == 0 && passed > 0 ? 0 : 1
    }
}
