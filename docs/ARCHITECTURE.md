# Architecture

Goal: a Mac miner whose front-ends know nothing about specific algorithms or GPUs. Everything
specific is a plug-in behind a small interface, and front-ends only talk to the engine.

## Plug-ins

| Kind | What it is | Status |
|---|---|---|
| Algorithm | `Sources/Algorithms/<Folder>/`: CPU reference, Metal kernels, the coins it mines. Registered by dropping in the folder. | all 9 families (12 coin variants) |
| Pool connection | A `PoolMiner` in the same folder: the coin's Stratum dialect on top of the algorithm's kernels, tested offline against `MockPool`. | in progress, coin by coin |
| Device | Each Metal GPU macOS exposes (on Apple silicon, exactly one built-in GPU; there's no eGPU support). Later the CPU, for CPU-friendly algorithms such as XelisHash or RandomX. | GPU listing done |
| Profit source | Live network hashrate, emission, fees and prices. Kryptex's public API today. | done |

## Engine

- Benchmarks each algorithm and keeps its rate and GPU power (from the GPU's energy counter).
- Values every coin with live prices, subtracting electricity when a price is set, and picks the best
  coin it can mine: one with a pool connection, a payout set and a login the pool hasn't refused. With
  none it waits and says why; the app asks where earnings go before it starts.
- While mining, a monitor thread reads GPU power, re-prices every 10 minutes, and asks for a switch only
  when another coin beats the current one by 10%, the current one can't be mined any more, or (with "mine
  only when profitable") nothing pays. Switching costs seconds (DAG and table builds) and prices are noisy.
- Reconnects to the pool with growing back-off when it drops. When a pool refuses the login, it skips
  that coin (marked "Login refused" in the app) until the payout settings change.
- Quiet mode (a setting): `GPUThrottle` rests the GPU after each piece of work (`GPU.run`), and
  `QuietController` holds its power to a target that moves with the fans' speed, read from the SMC
  (`FanSensor`), so the fans stay near their slowest. Benchmarks always run at full speed.
- Keeps earnings (accepted shares valued at the time) in `results/ledger.json`.
- Exposes one interface to every front-end: a state snapshot (devices, ranked coins, what each GPU is
  mining, hashrate, shares, power, earnings, settings) and commands (start, stop, benchmark, settings).

## Front-ends

- CLI: `metalminer` (test, bench, rank, power, settings, pooltest, handshake, mine).
- Mac app: the GPUs, a start button, the auto-picked coin with live hashrate, shares and GPU power,
  earnings per algorithm, the live ranking, and settings (electricity, payout). Built only against the
  engine interface.

## Build pieces

`./build.sh` compiles the harness, the engine and every algorithm folder into one library module,
`MinerCore`, then links the CLI (`Sources/CLI/`) and the app (`Sources/App/`) against it. The front-ends
can only use what's `public` in MinerCore (the engine interface, settings, paths and the command-line
entry), so they can't depend on a specific algorithm, coin or GPU. The app carries its own kernels and an
ad-hoc signature; it targets Apple silicon on macOS 15 or later.

## Open items

- Pool connections for every coin, then a live test with real shares on Kryptex.
- Release signing and notarization (a Developer ID), and a license.
- The CPU as a second device for CPU-friendly algorithms (XelisHash, RandomX).
- A background or menu-bar mode, so mining can continue with the window closed.
