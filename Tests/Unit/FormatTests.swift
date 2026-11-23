import Foundation

enum FormatTests {
    static let suite = TestSuite(name: "Format", tests: [
        ("dollars", { expect in
            expect.equal(MinerFormat.usd(0), "$0.00")
            expect.equal(MinerFormat.usd(1.234), "$1.23")
            expect.equal(MinerFormat.usd(0.0098), "$0.0098")
            expect.equal(MinerFormat.usd(0.0000034), "$3.4e-06")
            expect.equal(MinerFormat.usd(-0.02), "$-0.02")
        }),
        ("rates", { expect in
            expect.equal(formatRate(14_930_000, "H/s"), "14.93 MH/s")
            expect.equal(formatRate(5.64, "G/s"), "5.64 G/s")
            expect.equal(formatRate(5_540_000_000_000, "H/s"), "5.54 TH/s")
            expect.equal(formatRate(999, "H/s"), "999.00 H/s")
        }),
        ("hex", { expect in
            expect.equal([UInt8](hex: "0x00ff10"), [0, 255, 16])
            expect.equal([UInt8](hex: "abc"), nil)
            expect.equal([UInt8](hex: "zz"), nil)
            expect.equal([UInt8]([1, 171]).hex, "01ab")
        }),
        ("earnings: Kryptex's estimate when it has one, else the share of emission after the fee", { expect in
            var economics = CoinEconomics(pool: "p", ticker: "T", name: "T", algorithm: "a", networkHashrate: 1000,
                                          dailyEmission: 500, poolEstimate: nil, price: 2, fee: 0.01, feeType: "PROP")
            expect.near(economics.coinsPerDayPerUnit, 0.495, within: 1e-12)
            expect.near(economics.usdPerDayPerUnit, 0.99, within: 1e-12)
            economics.poolEstimate = 0.7
            expect.near(economics.coinsPerDayPerUnit, 0.7, within: 1e-12)
            economics.poolEstimate = nil
            economics.networkHashrate = 0
            expect.equal(economics.coinsPerDayPerUnit, 0)
        }),
    ])
}
