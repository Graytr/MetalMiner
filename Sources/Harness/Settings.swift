import Foundation

/// Where pool payouts go. Kryptex accepts either form of login for every coin.
public enum PayoutMode: String, Codable, CaseIterable, Sendable {
    /// One Kryptex username for every coin: earnings collect in the Kryptex account and pay out in BTC or USDT.
    case kryptexAccount
    /// The user's own wallet address for each coin, paid in that coin. Coins without an address are skipped.
    case ownWallets
}

/// User settings, kept in settings.json next to the results. Electricity is free unless a price is set.
public struct MinerSettings: Codable, Equatable, Sendable {
    /// Electricity price per kWh, in USD. 0 means free: rank by gross earnings.
    public var electricityPricePerKWh: Double = 0
    /// Mine only while the best coin earns more than its electricity costs. Off means mine regardless.
    public var mineOnlyWhenProfitable = false
    /// Quiet mode: mine more slowly, so the fans stay near their slowest speed.
    public var quietMode = false
    public var payoutMode: PayoutMode = .kryptexAccount
    public var kryptexUsername = ""
    /// Coin ticker (upper case) to the user's wallet address for that coin.
    public var wallets: [String: String] = [:]
    /// Shown on the pool's dashboard.
    public var workerName = "metalminer"

    public init() {}

    /// Missing keys fall back to the defaults, so older or hand-edited files still load.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        electricityPricePerKWh = try c.decodeIfPresent(Double.self, forKey: .electricityPricePerKWh) ?? 0
        mineOnlyWhenProfitable = try c.decodeIfPresent(Bool.self, forKey: .mineOnlyWhenProfitable) ?? false
        quietMode = try c.decodeIfPresent(Bool.self, forKey: .quietMode) ?? false
        payoutMode = try c.decodeIfPresent(PayoutMode.self, forKey: .payoutMode) ?? .kryptexAccount
        kryptexUsername = try c.decodeIfPresent(String.self, forKey: .kryptexUsername) ?? ""
        wallets = try c.decodeIfPresent([String: String].self, forKey: .wallets) ?? [:]
        workerName = try c.decodeIfPresent(String.self, forKey: .workerName) ?? "metalminer"
    }

    /// The pool login for a coin, "username/worker" or "wallet/worker", or nil when there's nowhere to pay it.
    public func login(coin: String) -> String? {
        let worker = workerName.trimmingCharacters(in: .whitespaces).isEmpty ? "metalminer" : workerName
        switch payoutMode {
        case .kryptexAccount:
            let user = kryptexUsername.trimmingCharacters(in: .whitespaces)
            return user.isEmpty ? nil : "\(user)/\(worker)"
        case .ownWallets:
            guard let wallet = wallets[coin.uppercased()]?.trimmingCharacters(in: .whitespaces), !wallet.isEmpty else { return nil }
            return "\(wallet)/\(worker)"
        }
    }

    /// The settings say where to pay at least one coin: a Kryptex username, or a wallet.
    public var hasPayout: Bool {
        switch payoutMode {
        case .kryptexAccount: return !kryptexUsername.trimmingCharacters(in: .whitespaces).isEmpty
        case .ownWallets: return wallets.values.contains { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        }
    }

    static func url(root: URL) -> URL { root.appendingPathComponent("settings.json") }

    public static func load(root: URL) throws -> MinerSettings {
        let file = url(root: root)
        guard FileManager.default.fileExists(atPath: file.path) else { return MinerSettings() }
        do {
            return try JSONDecoder().decode(MinerSettings.self, from: Data(contentsOf: file))
        } catch {
            throw MinerError("can't read \(file.lastPathComponent): \(error)")
        }
    }

    public func save(root: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: MinerSettings.url(root: root))
    }

    public var summary: String {
        let power = electricityPricePerKWh > 0 ? String(format: "$%.4g per kWh", electricityPricePerKWh) : "free"
        let payout: String
        switch payoutMode {
        case .kryptexAccount:
            payout = kryptexUsername.isEmpty ? "Kryptex account (username not set)" : "Kryptex account \(kryptexUsername)"
        case .ownWallets:
            let coins = wallets.filter { !$0.value.isEmpty }.keys.sorted()
            payout = coins.isEmpty ? "own wallets (none set)" : "own wallets for \(coins.joined(separator: ", "))"
        }
        return "electricity \(power) · mine only when profitable: \(mineOnlyWhenProfitable ? "yes" : "no")"
            + " · quiet mode: \(quietMode ? "yes" : "no")"
            + " · payout: \(payout) · worker \(workerName)"
    }
}
