import Foundation

enum EngineTests {
    /// A ranked coin as Earnings.rows makes them. "xtm-c29" and "quai-kawpow" have pool connections in every full
    /// build; "test-coin" has none.
    static func row(_ coin: String, pool: String, usd: Double, watts: Double? = 10, accountPayouts: Bool? = true) -> RankRow {
        let economics = CoinEconomics(pool: pool, ticker: coin, name: coin, algorithm: "test", networkHashrate: 1,
                                      dailyEmission: 1, poolEstimate: nil, price: 1, fee: 0, feeType: "PROP")
        return RankRow(coin: coin, pool: pool, algorithm: "test", unit: "H/s", rate: 1, networkShare: 0, usdPerDay: usd,
                       watts: watts, powerUsdPerDay: nil, netUsdPerDay: nil, economics: economics,
                       accountPayouts: accountPayouts)
    }

    static func account() -> MinerSettings {
        var settings = MinerSettings()
        settings.kryptexUsername = "someone@example.com"
        return settings
    }

    static let suite = TestSuite(name: "Engine", tests: [
        ("a Kryptex account can't pay coins Kryptex won't pay to accounts", { expect in
            let rows = [row("XTM", pool: "xtm-c29", usd: 0.45), row("QUAI", pool: "quai-kawpow", usd: 0.06, accountPayouts: false)]
            let options = MinerEngine.options(rows, account(), refused: [:])
            let quai = options.first { $0.coin == "QUAI" }
            expect.equal(quai?.accountPayouts, false)
            expect.equal(quai?.payoutReady, false)
            expect.equal(quai?.canMine, false)
            expect.equal(options.first { $0.coin == "XTM" }?.canMine, true)
        }),
        ("own wallets pay any coin with a wallet, account payouts or not", { expect in
            let rows = [row("XTM", pool: "xtm-c29", usd: 0.45), row("QUAI", pool: "quai-kawpow", usd: 0.06, accountPayouts: false)]
            var settings = MinerSettings()
            settings.payoutMode = .ownWallets
            settings.wallets = ["QUAI": "0xQuaiWallet"]
            let options = MinerEngine.options(rows, settings, refused: [:])
            expect.equal(options.first { $0.coin == "QUAI" }?.canMine, true)
            expect.equal(options.first { $0.coin == "XTM" }?.payoutReady, false)
        }),
        ("a refused login and a missing pool connection keep a coin from being mined", { expect in
            let rows = [row("XTM", pool: "xtm-c29", usd: 0.45), row("TEST", pool: "test-coin", usd: 9)]
            let options = MinerEngine.options(rows, account(), refused: ["xtm-c29": "Invalid login"])
            let xtm = options.first { $0.coin == "XTM" }
            expect.equal(xtm?.loginRefused, "Invalid login")
            expect.equal(xtm?.canMine, false)
            let test = options.first { $0.coin == "TEST" }
            expect.equal(test?.hasPoolConnection, false)
            expect.equal(test?.canMine, false)
        }),
        ("with an electricity price, coins rank by net earnings", { expect in
            // At $0.15/kWh: A nets 0.45 - 30 W x 24 h x $0.15 = 0.342, B nets 0.40 - 5 W x 24 h x $0.15 = 0.382.
            let rows = [row("A", pool: "a", usd: 0.45, watts: 30), row("B", pool: "b", usd: 0.40, watts: 5)]
            var settings = account()
            expect.equal(MinerEngine.options(rows, settings, refused: [:]).map(\.coin), ["A", "B"])
            settings.electricityPricePerKWh = 0.15
            let priced = MinerEngine.options(rows, settings, refused: [:])
            expect.equal(priced.map(\.coin), ["B", "A"])
            expect.near(priced[0].netUsdPerDay ?? 0, 0.382, within: 1e-9)
        }),
        ("choosing: the best coin that can be mined, otherwise why not", { expect in
            let rows = [row("TEST", pool: "test-coin", usd: 9), row("XTM", pool: "xtm-c29", usd: 0.45),
                        row("QUAI", pool: "quai-kawpow", usd: 0.06)]
            expect.equal(MinerEngine.choose([], mineOnlyWhenProfitable: false).reason, "no benchmark results yet")
            let best = MinerEngine.choose(MinerEngine.options(rows, account(), refused: [:]), mineOnlyWhenProfitable: false)
            expect.equal(best.option?.coin, "XTM")
            let noPayout = MinerEngine.choose(MinerEngine.options(rows, MinerSettings(), refused: [:]), mineOnlyWhenProfitable: false)
            expect.that(noPayout.option == nil && noPayout.reason?.contains("no payout set") == true, "\(noPayout)")
            let refused = MinerEngine.options(rows, account(), refused: ["xtm-c29": "no", "quai-kawpow": "no"])
            expect.that(MinerEngine.choose(refused, mineOnlyWhenProfitable: false).reason?.contains("refused") == true)
            let noPools = MinerEngine.options([row("TEST", pool: "test-coin", usd: 9)], account(), refused: [:])
            expect.equal(MinerEngine.choose(noPools, mineOnlyWhenProfitable: false).reason, "this build has no pool connections")
        }),
        ("mine only when profitable: nothing when the best coin loses money", { expect in
            var settings = account()
            settings.electricityPricePerKWh = 0.50   // 30 W costs $0.36 a day, more than $0.20
            let options = MinerEngine.options([row("XTM", pool: "xtm-c29", usd: 0.20, watts: 30)], settings, refused: [:])
            let choice = MinerEngine.choose(options, mineOnlyWhenProfitable: true)
            expect.that(choice.option == nil, "chose \(String(describing: choice.option?.coin))")
            expect.equal(choice.reason, "nothing earns more than its electricity")
            expect.equal(MinerEngine.choose(options, mineOnlyWhenProfitable: false).option?.coin, "XTM")
        }),
        ("new mining time goes to the row a saved ledger reads back as", { expect in
            let option = MinerEngine.options([row("XTM", pool: "xtm-c29", usd: 0.45)], account(), refused: [:])[0]
            let saved = EarningsRow(algorithm: option.algorithm, coin: option.coin, seconds: 1, estimatedUSD: 0, acceptedShares: 0)
            expect.equal(MinerEngine.ledgerKey(option), saved.id)
        }),
        ("a ledger saved with a coin twice loads as one row with the totals added", { expect in
            let url = try MinerPaths.data().appendingPathComponent("ledger-duplicates.json")
            try JSONEncoder().encode([
                EarningsRow(algorithm: "cuckaroo29", coin: "XTM", seconds: 60, estimatedUSD: 0.01, acceptedShares: 1),
                EarningsRow(algorithm: "cuckaroo29", coin: "XTM", seconds: 90, estimatedUSD: 0.02, acceptedShares: 2),
                EarningsRow(algorithm: "kawpow", coin: "RVN", seconds: 30, estimatedUSD: 0, acceptedShares: 0),
            ]).write(to: url)
            let ledger = MinerEngine.loadLedger(at: url)
            expect.equal(ledger.count, 2)
            expect.equal(ledger["cuckaroo29/XTM"]?.seconds, 150)
            expect.equal(ledger["cuckaroo29/XTM"]?.acceptedShares, 3)
            expect.near(ledger["cuckaroo29/XTM"]?.estimatedUSD ?? 0, 0.03, within: 1e-12)
        }),
    ])
}
