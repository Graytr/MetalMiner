import Foundation
import Metal

/// One proof-of-work algorithm as the benchmark harness sees it. Use one class per mainnet
/// variant (Ethash and Etchash are separate types because their DAG sizes differ).
protocol MiningAlgorithm: AnyObject {
    /// Command-line id, lowercase, e.g. "etchash".
    static var id: String { get }
    /// Kryptex Pool coins mined with exactly this variant, e.g. ["ETC"].
    static var coins: [String] { get }
    /// Unit the coins' network hashrate is quoted in, so our rate compares with pool and network
    /// numbers: "H/s" for nearly everything, "G/s" (graphs) for Cuckoo-family algorithms.
    static var unit: String { get }

    /// Build all GPU state at today's mainnet parameters, or small test parameters when `config.quick`.
    init(gpu: GPU, config: AlgoConfig) throws

    /// What setup built, e.g. "epoch 433 · DAG 4.38 GiB".
    var setupSummary: String { get }

    /// Check the CPU reference against published known-answer vectors.
    /// Return one line per vector; throw on any mismatch.
    func knownAnswerTests() throws -> [String]

    /// Hash `samples` random inputs on the GPU and on the CPU reference at the current parameters.
    /// Return a one-line summary; throw on any mismatch.
    func crossCheck(samples: Int) throws -> String

    /// Fraction of mining time lost to work repeated while mining, such as Autolykos2 rebuilding its table every
    /// block. Rankings use rate x (1 - overheadFraction). Defaults to 0.
    var overheadFraction: Double { get }

    /// Starting batch size. The harness rescales it so one batch takes about 150 ms.
    var defaultBatch: Int { get }

    /// One real mining batch of `count` nonces from `startNonce`, against a target that can't be hit,
    /// done synchronously (encode, commit, wait, any CPU post-processing).
    /// Return the work done in `unit` terms, usually the number of hashes.
    func runBatch(startNonce: UInt64, count: Int) throws -> Double
}

extension MiningAlgorithm {
    static var unit: String { "H/s" }
    var overheadFraction: Double { 0 }
}

struct AlgoConfig {
    /// Small, fast test parameters; rates aren't comparable to mainnet.
    var quick = false
    /// Algorithm-specific options from `--set key=value`.
    var options: [String: String] = [:]

    func int(_ key: String) -> Int? { options[key].flatMap { Int($0) } }
}

struct MinerError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Algorithms compiled into this binary. build.sh generates `GeneratedRegistry` from the folders under
/// Sources/Algorithms that it compiles, so adding an algorithm means adding a folder that defines
/// `<Folder>Family.algorithms` (and, for real mining, `<Folder>Family.poolMiners`); nothing here changes.
enum Registry {
    static var all: [MiningAlgorithm.Type] { GeneratedRegistry.families.flatMap { $0.algorithms } }
    static var poolMiners: [PoolMiner.Type] { GeneratedRegistry.families.flatMap { $0.poolMiners } }
    static func poolMiner(for pool: String) -> PoolMiner.Type? { poolMiners.first { $0.pools.contains(pool) } }
}
