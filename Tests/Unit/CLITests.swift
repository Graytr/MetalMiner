import Foundation

enum CLITests {
    /// Starts a test from no saved settings.
    static func clearSettings() throws {
        try? FileManager.default.removeItem(at: MinerSettings.url(root: try MinerPaths.data()))
    }

    static let suite = TestSuite(name: "CLI", tests: [
        ("settings flags are saved to the data folder", { expect in
            try clearSettings()
            expect.equal(try CLI.run(["settings", "--quiet", "yes", "--kryptex-user", "someone@example.com", "--worker", "rig2"]), 0)
            let saved = try MinerSettings.load(root: try MinerPaths.data())
            expect.equal(saved.quietMode, true)
            expect.equal(saved.login(coin: "XTM"), "someone@example.com/rig2")
            expect.equal(try CLI.run(["settings", "--quiet", "no"]), 0)
            expect.equal(try MinerSettings.load(root: try MinerPaths.data()).quietMode, false)
        }),
        ("bad flag values are refused before anything runs", { expect in
            expect.throwsError(containing: "--shares needs a positive number") { _ = try CLI.run(["mine", "xtm-c29", "--shares", "0"]) }
            expect.throwsError(containing: "--quiet takes yes or no") { _ = try CLI.run(["settings", "--quiet", "maybe"]) }
            expect.throwsError(containing: "--profit-only takes yes or no") { _ = try CLI.run(["settings", "--profit-only", "sometimes"]) }
        }),
        ("mine needs a pool connection and a payout, and says how to set one", { expect in
            try clearSettings()
            expect.throwsError(containing: "needs a pool that has a pool miner") { _ = try CLI.run(["mine", "no-such-pool"]) }
            expect.throwsError(containing: "no payout set for XTM") { _ = try CLI.run(["mine", "xtm-c29"]) }
        }),
    ])
}
