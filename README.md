# Metal Miner

An open-source miner for Apple GPUs. Proof-of-work algorithms are ported to Metal, checked against each
coin's official vectors, benchmarked on your Mac, and ranked by what they'd earn on Kryptex Pool right
now. The app mines whichever coin pays best and re-checks as prices move.

Requires an Apple silicon Mac on macOS 15 or later.

Status: all nine algorithm families (12 coins) are ported and pass their tests; the engine, ranking, GPU
power measurement and app run. Every coin has a pool connection, tested offline against a local test pool
(real jobs in, each GPU share re-checked with the CPU reference). On Kryptex itself (2026-11-23), XTM, XEL,
QTC, PRL, RVN, CFX, ERG, ETHW and OCTA have had shares accepted; NEXA and ETC logged in and mined cleanly but
haven't found a share yet (about one every 9 minutes on an M3 Max), and Quai needs a wallet (Kryptex doesn't pay
it to accounts). The app asks where earnings go (your Kryptex account or your own wallets) before it starts
mining.

## Install

Releases are zips of the app, signed with a Developer ID and notarized by Apple, so macOS opens them like
any other downloaded app: unzip, move Metal Miner to Applications, open it. Metal Miner can't be in the Mac
App Store, because Apple's rules don't allow apps that mine cryptocurrency on the device (App Review
Guideline 3.1.5(ii)). `release.sh` builds a release; its header lists the signing and notarization steps.

## Use

    ./build.sh                                        # -> .build/all/metalminer and .build/all/Metal Miner.app
    open ".build/all/Metal Miner.app"                 # the app: GPUs, Start Mining, best coins, earnings
    .build/all/metalminer info                        # GPUs, memory limits, GPU power now
    ./test.sh                                         # unit tests: offline, no GPU, under a minute or two
    ./test.sh --gpu                                   # plus every algorithm and pool connection on the GPU
    .build/all/metalminer test all                    # official vectors + GPU/CPU cross-check
    .build/all/metalminer bench all --seconds 30 --cooldown 30
    .build/all/metalminer rank                        # live Kryptex data; electricity free unless set
    .build/all/metalminer power                       # chip power by channel, from its energy counters
    .build/all/metalminer settings --kwh 0.12         # electricity price (0 = free, the default)
    .build/all/metalminer settings --profit-only yes  # idle when nothing beats the power cost
    .build/all/metalminer settings --quiet yes        # quiet mode: slower, so the fans stay at their lowest speed
    .build/all/metalminer settings --payout kryptex --kryptex-user NAME
    .build/all/metalminer settings --payout wallets --wallet RVN=ADDRESS --wallet ERG=ADDRESS
    .build/all/metalminer pooltest                    # each pool connection against a local test pool
    .build/all/metalminer mine xtm-c29 --seconds 600  # real mining on one Kryptex pool with your payout
                                                      # (--trace prints every line to and from the pool)

Payout: either a Kryptex account (its email or username, for every coin; earnings pay out in BTC or USDT)
or your own wallet per coin (paid in that coin; coins without a wallet are skipped). Kryptex doesn't pay
every coin to accounts (Quai, as of November 2026); the app marks those "Needs a wallet".

Quiet mode rests the GPU between pieces of work, holding its power at a target that moves with the fans:
down when they speed up, slowly up while they stay at their slowest. It mines more slowly, so it earns less.

`bench` records each algorithm's rate and GPU power (from the GPU's energy counter; memory and CPU power
aren't exposed to apps, so wall power is higher). `rank` and the app value each rate with Kryptex's public
API: Kryptex's own payout estimate for PPS+ pools, or our share of the network's daily emission after the
fee for PROP pools, checked against Kryptex's calculator. Results so far: `docs/RESULTS.md`.

## Where things go

Built from this folder, the CLI and app keep settings, results and earnings here (`settings.json`,
`results/`). An installed copy of the app uses `~/Library/Application Support/Metal Miner` and carries its
own kernels. The build writes only inside this folder: `./build.sh` calls the Xcode toolchain directly with
its caches in `.build/`. macOS itself keeps a shader cache for any app that uses the GPU, and the app's window
state, as it does for every app. `.gitignore` keeps settings and results out of the repository.

## Layout

- `Sources/Algorithms/<Folder>/`: one plug-in folder per algorithm family (CPU reference, GPU host code,
  pool connection), registered automatically by the build
- `Kernels/`: Metal source, compiled at runtime (`common.metal` is prepended to each library)
- `Sources/Harness/`: protocol, GPU helper, tests and benchmarks, earnings, power, settings, Stratum and
  pool plumbing, CLI commands
- `Sources/Engine/`: the engine and its public interface (devices, ranked coins, mining, earnings)
- `Sources/CLI/`, `Sources/App/`: front-ends; they import only the engine's public interface
- `Sources/Tools/`: build helpers (the app icon)
- `docs/ARCHITECTURE.md`, `docs/PORTING.md`, `docs/RESULTS.md`, `docs/specs/`: design, how to add an
  algorithm or pool connection, benchmark results, one note per algorithm

## License

GPL-3.0 (see `LICENSE`): anyone may use, study, change and share Metal Miner, and anyone who shares a
changed version has to share its source under the same license.
