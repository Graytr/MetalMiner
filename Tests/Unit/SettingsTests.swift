import Foundation

enum SettingsTests {
    static let suite = TestSuite(name: "Settings", tests: [
        ("a Kryptex account pays every coin", { expect in
            var settings = MinerSettings()
            expect.equal(settings.login(coin: "XTM"), nil)
            expect.that(!settings.hasPayout, "no username yet")
            settings.kryptexUsername = " someone@example.com "
            expect.equal(settings.login(coin: "XTM"), "someone@example.com/metalminer")
            expect.equal(settings.login(coin: "rvn"), "someone@example.com/metalminer")
            settings.workerName = "  "
            expect.equal(settings.login(coin: "XTM"), "someone@example.com/metalminer")
            settings.workerName = "rig2"
            expect.equal(settings.login(coin: "XTM"), "someone@example.com/rig2")
            expect.that(settings.hasPayout)
        }),
        ("own wallets pay only the coins that have one", { expect in
            var settings = MinerSettings()
            settings.payoutMode = .ownWallets
            settings.kryptexUsername = "someone@example.com"
            expect.that(!settings.hasPayout, "a Kryptex username doesn't count in wallet mode")
            settings.wallets["RVN"] = "RWalletAddress"
            expect.equal(settings.login(coin: "rvn"), "RWalletAddress/metalminer")
            expect.equal(settings.login(coin: "XTM"), nil)
            expect.that(settings.hasPayout)
            settings.wallets["RVN"] = "   "
            expect.that(!settings.hasPayout, "a blank wallet doesn't count")
        }),
        ("older or partial settings files load with defaults", { expect in
            let settings = try JSONDecoder().decode(MinerSettings.self, from: Data(#"{"kryptexUsername":"someone"}"#.utf8))
            expect.equal(settings.kryptexUsername, "someone")
            expect.equal(settings.payoutMode, .kryptexAccount)
            expect.equal(settings.workerName, "metalminer")
            expect.equal(settings.quietMode, false)
            expect.equal(settings.mineOnlyWhenProfitable, false)
            expect.equal(settings.electricityPricePerKWh, 0)
        }),
        ("save and load round trip", { expect in
            let root = try MinerPaths.data()
            var settings = MinerSettings()
            settings.quietMode = true
            settings.electricityPricePerKWh = 0.12
            settings.payoutMode = .ownWallets
            settings.wallets = ["ERG": "9fErgoWallet"]
            try settings.save(root: root)
            expect.equal(try MinerSettings.load(root: root), settings)
            expect.that(settings.summary.contains("quiet mode: yes"), settings.summary)
        }),
    ])
}
