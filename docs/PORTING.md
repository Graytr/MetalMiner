# Porting an algorithm to Metal Miner

Metal Miner measures how fast this Mac's GPU mines each Kryptex Pool coin, so coins can be ranked
by earnings and mined with automatic switching. Each algorithm is a Swift class that
conforms to `MiningAlgorithm` (`Sources/Harness/Algorithm.swift`), plus Metal kernels compiled at
runtime from `Kernels/`.

The finished reference port is Ethash: `Sources/Algorithms/Ethash/` (CPU reference with official
vectors, chain parameters, host code) and `Kernels/ethash.metal` + `Kernels/ethash_coop.metal`
(DAG generation, a simple kernel, and a faster cooperative kernel where 8 lanes share each hash).

## Rules

1. Keep the build self-contained: no package managers, downloads or third-party code. `./build.sh`
   calls the Xcode toolchain directly and keeps its module cache and temp files in `.build/`.
2. Build with `./build.sh` (or `./build.sh <Folder> ...` for just those folders).
3. Read specs and reference code, then write the port yourself: implement from the spec and check it
   against published vectors. Metal Miner is GPL-3.0; never copy code whose license doesn't allow
   that.
4. An algorithm owns `Sources/Algorithms/<Folder>/`, `Kernels/<prefix>*.metal` and
   `docs/specs/<prefix>.md`. Changes to the harness, engine or front-ends (`Sources/Harness/`,
   `Sources/Engine/`, `Sources/CLI/`, `Sources/App/`, `build.sh`, `Kernels/common.metal`) belong in a
   change of their own.
5. Develop with `--quick`, keep full-size benchmark runs short, and pass `--no-save` for experiments,
   so `results/` keeps only real benchmark runs.
6. Every folder compiles into one Swift module in the full build, so top-level names must not
   collide. Prefix every top-level Swift type, function and constant with your folder name
   (`Autolykos2Blake2b`, `XelisHashChaCha`, ...) or nest helpers inside your own namespace enum.
   Generic names such as `Keccak`, `Blake2b`, `SHA256`, `fnv` or `rotl` at top level are not allowed
   (`Keccak` and `EthashReference` already belong to the Ethash folder). Metal libraries are compiled
   per algorithm from the files you list, so kernel names only need to be unique within your files,
   but prefix them anyway. To reuse the Ethash code (for example its light cache and DAG), build
   with `./build.sh Ethash <YourFolder>` and call it without modifying it. Build Ethash-style DAGs only
   through `EthashDAG.build(gpu:cache:datasetBytes:parents:)`, never by dispatching `ethash_dag`
   yourself: its arguments change (KawPow added `parents`), and a direct dispatch then silently
   builds a wrong DAG.

## Build and run

Run from the project folder (quote the path if it has spaces):

    ./build.sh Ethash                                  # -> .build/Ethash/metalminer, only that folder
    .build/Ethash/metalminer list
    .build/Ethash/metalminer test etchash --quick      # vectors + GPU/CPU cross-check, small params
    .build/Ethash/metalminer test etchash              # the same at mainnet params
    .build/Ethash/metalminer bench etchash --seconds 10 --no-save
    ./build.sh                                         # every folder -> .build/all/metalminer

## Registering

Algorithms are plug-in folders. `build.sh` generates the registry from the folders it compiles
(`.build/<name>/GeneratedRegistry.swift`), so adding an algorithm touches nothing outside its own
folder. The folder must define

    enum <Folder>Family { static let algorithms: [MiningAlgorithm.Type] = [MyAlgorithm.self] }

## The protocol

- `id`: lowercase command-line name. `coins`: Kryptex tickers mined with exactly this variant.
  `unit`: what the network hashrate is quoted in ("H/s" unless the coin uses something else).
- `init(gpu:config:)`: build everything at today's mainnet parameters (for example the DAG for the
  current epoch). Record the block height and date you used in the spec note and accept an override
  through `config.options` (`--set height=...`). With `config.quick`, use small parameters so setup
  takes seconds.
- `knownAnswerTests()`: the CPU reference against published vectors from the coin's official code.
- `crossCheck(samples:)`: GPU against CPU on random inputs at the current parameters. Compare the
  full final hash, not just whether a nonce hit.
- `runBatch(startNonce:count:)`: one real mining batch. Every nonce gets the full work, including
  the final hash and the comparison with a target held in a GPU buffer, and hits are appended to a
  `SearchOutput` (see `Kernels/common.metal`) or your own buffer. Benchmarks pass a target that
  can't be hit; because it's runtime data, the compiler can't drop the work. Return the work done in
  `unit` terms.
- `defaultBatch`: a starting size. The harness rescales it toward about 150 ms per batch.
- `overheadFraction` (optional, default 0): the share of mining time lost to work a real miner repeats,
  such as Autolykos2 rebuilding its 7 GiB table every block (rebuild GPU seconds / block seconds). The
  ranking multiplies the measured rate by (1 - overheadFraction).

## GPU helper (`Sources/Harness/GPU.swift`)

- `gpu.library(["mine.metal"], macros: [...])` compiles `Kernels/common.metal` plus your files,
  concatenated in order. Runtime-compiled source can't `#include` our own files, so list every file
  you need.
- `gpu.pipeline(library, "kernel")`, `gpu.buffer(length, label:)`, `gpu.buffer(array, label:)`,
  `gpu.privateBuffer(length, label:)`, `gpu.dispatch(encoder, pipeline, threads:group:)`,
  `gpu.compute(label) { encoder in … }`, `gpu.run(label) { commandBuffer in … }`.
- This Mac: Apple M3 Max, 40-core GPU, 64 GiB unified memory; largest single buffer 38.88 GiB,
  recommended GPU working set 51.84 GiB.
- Keep every command buffer under about 1 s (the macOS GPU watchdog). Split long setup work such as
  DAG generation into chunks.
- Apple GPU notes: SIMD groups are 32 wide; 64-bit integer math is emulated with 32-bit pairs, so
  prefer 32-bit operations where the algorithm allows; 32 KiB of threadgroup memory per threadgroup;
  `simd_shuffle` for cooperation inside a SIMD group. On Ethash, letting 8 lanes share each hash's
  128-byte reads (coalesced loads) was worth +70%.
- It's a MacBook Pro: sustained load raises the thermal state and lowers clocks. Benchmark numbers
  taken while other ports share the GPU, or at thermal "fair" or worse, are rough. The final ranking
  run is done separately, one algorithm at a time.

## Correctness bar

1. The CPU reference, written in Swift from the spec, passes known-answer vectors from the official
   implementation. Cite the source files (URLs) in the spec note. If no vectors are published,
   derive them from real mainnet blocks and explain how.
2. The GPU matches the CPU reference on random inputs at the parameters being benchmarked.
3. The construction matches mainnet mining exactly: header or job layout, nonce position and width,
   byte order, and how the result compares with the target. The same kernel has to mine for real
   once the pool client exists.

## Spec note: `docs/specs/<prefix>.md`

What the algorithm is; mainnet parameters and how they change with height; sources (links); vectors
used; memory needs; how the kernel is organised; measured rate (and whether the GPU was shared);
open questions and speed-up ideas.

## Pool miners (real mining)

Each coin's pool protocol lives with its algorithm, in the same folder, as a class conforming to
`PoolMiner` (`Sources/Harness/Pool.swift`) and listed in `<Folder>Family.poolMiners`:

- `pools`: the Kryptex pool slugs it speaks (`rvn`, `quai-kawpow`, `xtm-c29`, ...); `algorithm`: the id
  it mines with.
- `init(gpu:endpoint:login:events:)` and `run(shouldStop:)`: connect with `StratumConnection`
  (`Sources/Harness/Stratum.swift`), log in with the given `login` ("username/worker" or
  "wallet/worker"), turn each job into GPU work with the algorithm's verified kernels, submit shares,
  follow difficulty changes, new jobs and reconnect requests, and return when `shouldStop()` is true.
  Report the rate through `events.hashrate` every few seconds and each share through
  `events.share(accepted, work, note)`, where `work` is the share's expected work in the algorithm's
  unit (the engine values a share at work x USD per unit).
  When the pool refuses the login, throw `PoolLoginRefused(login:reason:)` with the pool's own words
  rather than another error: the engine then skips that coin until the payout settings change instead
  of retrying it.
- `selfTest(gpu:)`: a full offline round trip with `MockPool`: realistic jobs in (from a real block or
  the coin's vectors, with an easy share target), shares found on the GPU, each checked by the mock with
  the CPU reference, and a deliberately invalid share rejected. Run with `metalminer pooltest`.
- `handshake(endpoint:)`: optional live check that connects to the real Kryptex endpoint and sends at
  most the protocol's first non-login message. Run with `metalminer handshake`.

Never log in to or submit to a real pool from a test, and never use anyone's wallet or username: the live
test (`metalminer mine <pool>`) runs only with the user's own saved payout login.
