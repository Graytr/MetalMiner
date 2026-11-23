# Poseidon2: Quantus (QTC)

Id `poseidon2`, coin QTC, unit H/s. Kryptex lists the algorithm as "Poseidon2"; Quantus's own name for
its consensus is QPoW. Files: `Sources/Algorithms/Poseidon2/` (CPU reference, vectors, host code) and
`Kernels/poseidon2.metal`.

## Construction (mainnet)

`qpow-math::get_nonce_hash(block_hash, nonce)`, checked by `is_valid_nonce`:

- `block_hash`: 32 bytes, the "mining hash" the node hands out: the pre-seal block hash, i.e.
  `Header::hash()` of the header with the seal digest item popped. That header hash is itself a
  Poseidon hash (`primitives/header`): `hash_to_bytes` over 45 felts (parent hash, block number,
  state root, extrinsics root, ZK tree root, then the SCALE digest padded to 110 bytes). Miners never
  compute it; it comes with the job.
- `nonce`: 64 bytes, stored as the block's `Seal(POW_ENGINE_ID, nonce)` digest item. The runtime
  rejects the all-zero nonce.
- `hash = qp_poseidon_core::hash_squeeze_twice(block_hash ‖ nonce)` (96 bytes):
  - Byte encoding: every 4 bytes become one felt (little-endian u32), then one terminator felt holding
    the 0-3 leftover bytes followed by a 0x01 byte. For 96 bytes: 24 felts, then the felt 1.
  - Sponge: width 12, rate 8 (lanes 0-7), state starts at zero, blocks are field-added into lanes 0-7
    and permuted. Padding: append the felt 1, then zeros to the end of the block. So the four blocks
    are header felts, nonce bytes 0-31, nonce bytes 32-63, and `[1, 1, 0, 0, 0, 0, 0, 0]` (terminator
    and pad felt): 4 permutations.
  - Squeeze: lanes 0-3, each as the 8 little-endian bytes of its canonical value (32 bytes); permute
    once more; lanes 0-3 again (32 bytes). 5 permutations in total.
- The 64 bytes are read as a big-endian U512, so hash word k (most significant first) is
  `bswap64(canonical lane value)`.
- Valid iff `hash < U512::MAX / difficulty` (integer division, strict).

Permutation (`qp-poseidon-core` `src/poseidon2.rs`): Poseidon2 over Goldilocks, p = 2^64 - 2^32 + 1,
width 12, S-box x^7, 4 + 4 external rounds, 22 internal rounds. External matrix circ(2·M4, M4, M4)
with Plonky3's M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] (not the paper's), applied once before
the first round. Internal matrix 1 + diag: `state[i] = sum(state) + diag[i]·state[i]`, with Plonky3's
`MATRIX_DIAG_12_GOLDILOCKS` (the same as HorizenLabs' `MAT_DIAG12_M_1`). Round constants are Quantus's
own (from seed 0x3141592653589793, `qp-poseidon-constants`). Round order: M_E; 4 × (add constants,
S-box on all lanes, M_E); 22 × (add constant to lane 0, S-box lane 0, M_I); 4 × (add constants,
S-box on all lanes, M_E).

The first two permutations depend only on the header and nonce bytes 0-31 (`pow-core::mining_midstate`),
so a miner fixes those per job and varies the low bytes: 3 permutations per nonce, and only 2 when the
top 64 hash bits already exceed the target's (quantus-miner's `MiningHasher` and its GPU kernels do the
same).

## Parameters

There are no size or height-dependent parameters; only the difficulty moves. pallet-qpow retargets
every block, Homestead-style: `new = parent + parent/2048 · max(1 - ⌊block_time / 10 s⌋, -99)` for a
12 s target (`TARGET_BLOCK_TIME_MS = 12_000`), floor 131,072, genesis 99,999,999,999 (runtime
spec_version 153 on `main`).

Reference point, 2026-11-19 about 21:00 UTC: height 438,893 (explorer.quantus.com). Kryptex: network
difficulty about 379.16 T (372.35 T later that day), hashrate about 31.5 TH/s, a block every ~15.3 s,
0.30 QTC per block; Kryptex Pool static share difficulty 18,253,611,008 (= 0x440000000, so the share
target's top word is 0x3c3c3c3c). `--set difficulty=N` only changes the setup line (the benchmark always
uses an unreachable all-zero target); `--set height=N` is recorded only.

## Job and pool mapping

- Node ↔ miner (chain `MINING.md`, QUIC, length-prefixed JSON): `NewJob { job_id, mining_hash (64 hex),
  difficulty (U512 decimal) }`; the miner picks a random 64-byte starting nonce and walks it, and
  answers `JobResult { nonce (U512 hex), work (128 hex = the 64 nonce bytes), hash_count, … }`.
- Our job layout: header = mining_hash; nonce bytes 0-55 fixed per job (`noncePrefix`, any value);
  bytes 56-63 = a big-endian 64-bit counter walked by the GPU. The host folds bytes 32-55 into the job
  state as six felts, so an extranonce anywhere in bytes 0-55 costs nothing.
- Kryptex (qtc.kryptex.network:7049, SSL 8049): an XMRig-style stratum, see "Pool protocol" below.

## Pool protocol (Kryptex `qtc`)

`Poseidon2PoolMiner` (`Poseidon2Pool.swift`; offline test in `Poseidon2PoolTest.swift`). Quantus's own miner talks
only to its node (QUIC, above), and Quantus publishes no pool protocol. Pools speak the XMRig-style JSON-RPC dialect
(`login` / `job` / `submit` / `keepalived`) that SRBMiner-MULTI uses with `--algorithm quantus`, documented in code by the
open-source minershaven/miningcore pool, whose notes call it "the same shape Kryptex uses"
(https://github.com/minershaven/miningcore: `docs/quantus.md`, `src/Miningcore/Blockchain/Quantus/QuantusPool.cs`,
`QuantusStratum.cs`, `QuantusJob.cs`, `QuantusJobManager.cs`, `QuantusConstants.cs`). Newline-delimited JSON over TCP
7049 or TLS 8049; every request carries `"jsonrpc": "2.0"`.

| | message | params / result |
|---|---|---|
| → | `login` | `{"login": login exactly as saved ("wallet/worker" or "username/worker"), "pass": "x", "agent": "MetalMiner/1.0"}` |
| ← | result | `{"id": session id, "job": {…}, "status": "OK", "extensions": ["keepalive"]}` |
| ← | `job` | `{"clean_jobs": bool, "job": {…}}`; a bare job object is accepted too |
| | job object | `job_id`, `mining_hash` (32 bytes hex), `extranonce` (hex, 4 bytes in Miningcore), `target` (64 bytes hex, a big-endian U512), `difficulty` (integer) |
| → | `submit` | `{"id": session id, "job_id", "nonce": the 64-byte nonce as 128 hex digits, "result": the 64-byte hash as 128 hex digits}` |
| ← | result | `{"status": "OK"}`, or an error `{"code", "message"}` |
| → | `keepalived` | `{"id": session id}` after 60 s without another request; answer `{"status": "KEEPALIVED"}` |
| ← | `client.reconnect` | reconnect to the same endpoint (a pool-supplied host is never followed) |

**Nonce layout.** Bytes 0..<e = the job's extranonce (Miningcore rejects a nonce that doesn't start with it); bytes
e..<56 = random per connection; bytes 56..<64 = the GPU's counter, big-endian (a random start below 2^62, never
restarted within a connection, so a re-sent job can't produce duplicate shares). The host folds bytes 0..<56 into the
job state (2 permutations per job), so the extranonce costs nothing per nonce. `nonce` is the 64 bytes in order, as
`get_nonce_hash` takes them (the official pool-service in quantus-miner, `crates/pool-service/src/state.rs`, hands out
U512 ranges and hashes `nonce.to_big_endian()`; its sessions differ only in the low bytes, as ours do). `result` is the
64-byte `hash_squeeze_twice` output in order, which is the big-endian U512 that is compared with the target.

**Difficulty → target → work.** The job's `target` is used as sent (64 bytes → 8 big-endian words for the kernel);
without one, target = U512::MAX / difficulty (difficulty rounded up). When a job has both and they disagree by more
than 1 % (a target sent in the other byte order, say), the harder of the two is mined and the miner logs the mismatch
once. A share is valid when hash < target, strictly (`is_valid_nonce`, Miningcore). Its expected work is the job's
difficulty (Kryptex pool info: `hashes_per_diff` 1), estimated from the target when a job has no difficulty; that is
what `events.share` reports. Kryptex's static difficulty 18,253,611,008 means one share per ~3.6 min at 85 MH/s. Every
job carries its own target, so a difficulty change arrives as a new job.

**Mining loop.** Dispatches sized toward 0.15 s of GPU time (2^16..2^27 nonces), with every message from the pool
applied between dispatches; at most 64 hits per dispatch (POSEIDON2_MAX_HITS). Each hit's 512-bit hash is recomputed
on the CPU and compared with the GPU's and the target before it is sent; shares go out without waiting and their
answers are matched by request id (ids from 1000; `call()` uses 1). The rate goes to `events.hashrate` every 5 s; no
job for 300 s throws, so the engine reconnects. A login answered with an error, `false` or a status other than OK
throws `PoolLoginRefused` with the pool's words, so the engine skips QTC instead of retrying. `metalminer mine qtc
--trace` prints every stratum line.

**Live check** (`metalminer handshake qtc`, 2026-11-20, `stratum+ssl://qtc.kryptex.network:8049`): the pool says
nothing before a login. The check never sends `login` (the dialect's first message); it sends the one request that
is neither a login nor a share, `keepalived` with an empty session id, and Kryptex answered
`{"error":null,"result":{"status":"KEEPALIVED"},"id":1}`: the XMRig-style result shape, and the same status string as
Miningcore's.

**Offline test** (`metalminer pooltest qtc`, ~1 s): first the job path alone: quantus-miner's golden vector 2 given as
a pool job (mining_hash 00..1f, extranonce 00000000, the vector's other nonce bytes as the connection's own) and
searched on the GPU at its counter gives the official 512-bit hash `7f6c410c…`. Then MockPool plays the pool: login
returns job j1 (mining_hash = golden vector 1's header, extranonce `5a17c0de`, difficulty 2^22 with its 128-digit
target): 8 shares in the recorded run, each re-hashed by the mock with the CPU reference (nonce prefix, no duplicates,
`result` equal to the hash, hash < target). One share is deliberately sent with a nonce that misses the target: the
mock answers "Low difficulty share" and the miner reports it rejected. Then a pushed job j2 (clean_jobs, vector 3's
header, a new extranonce `a1b2c3d4`, difficulty 2^21): 12 more shares at the new target. keepalived was answered, and
every accepted share was reported with its job's difficulty as work.
A second mock that refuses the login makes `run()` throw `PoolLoginRefused` with the pool's words ("invalid login").

**Only a live test can confirm:** the login answer and the job fields Kryptex actually sends (their names, the
extranonce length, `target` as 128 hex digits rather than a shorter form, `difficulty` as a number; the miner logs the
first job's extranonce and difficulty); whether its job push wraps the job in `{clean_jobs, job}`; whether submit
needs `result` (we send it) and in which byte order; its success answer (`{"status": "OK"}` and `true` both count as
accepted); and that shares are accepted at all.

**Live on Kryptex (2026-11-23):** the login with a Kryptex account (`email/worker`) was accepted, and its job carried
the difficulty (18,253,611,008) and an extranonce; `keepalived` was answered each minute, and the first share was
accepted (`{"status":"OK"}`) after about 4.5 minutes.

## Sources

- qpow-math: https://github.com/Quantus-Network/chain/blob/main/qpow-math/src/lib.rs
- pallet-qpow (difficulty): https://github.com/Quantus-Network/chain/blob/main/pallets/qpow/src/lib.rs
- consensus (pre-hash, seal): https://github.com/Quantus-Network/chain/blob/main/client/consensus/qpow/src/lib.rs
- header hash: https://github.com/Quantus-Network/chain/blob/main/primitives/header/src/lib.rs
- protocol: https://github.com/Quantus-Network/chain/blob/main/MINING.md; runtime constants in
  `runtime/src/lib.rs` and `runtime/src/configs/mod.rs` of the same repo
- Poseidon2 and sponge: https://github.com/Quantus-Network/qp-poseidon (`src/poseidon2.rs`, `src/lib.rs`,
  `src/serialization.rs`)
- official miner: https://github.com/Quantus-Network/quantus-miner (`crates/pow-core/src/lib.rs`; its
  Apple kernel `crates/engine-gpu/src/kernels/mining_u64_apple.wgsl` was read for comparison;
  NVIDIA rates in `docs/clore-gpu-benches.md`)
- HorizenLabs reference: https://github.com/HorizenLabs/poseidon2 (`plain_implementations/src/poseidon2/
  poseidon2.rs` kats, `poseidon2_instance_goldilocks.rs`)
- Kryptex: https://pool.kryptex.com/qtc and /qtc/about-coin
- Pool protocol: https://github.com/minershaven/miningcore (`docs/quantus.md`, `src/Miningcore/Blockchain/Quantus/`:
  the XMRig-style stratum as SRBMiner-MULTI and Kryptex speak it); quantus-miner `crates/pool-service/src/state.rs`
  (the official share pool: U512 nonce ranges, `is_valid_nonce` at a share difficulty);
  https://pool.kryptex.com/qtc/api/v1/pool/info (servers, static difficulty, `hashes_per_diff`).

## Verification

CPU reference (`Poseidon2Reference.swift`, vectors in `Poseidon2Vectors.swift`), all passing:

1. qp-poseidon-core `poseidon2.rs` tests, which are p3-goldilocks outputs with Quantus's constants:
   permutation of zero and of 1..12, the zero state after round 1's S-box and after its linear layer,
   both linear layers on 1..12, S-box spot values.
2. HorizenLabs Goldilocks t = 12 `kats()` (input 0..11) through the same permutation code with HL's
   constants and M4: checks the round structure independently of Quantus's constants.
3. qp-poseidon-core `lib.rs`: 18 `hash_bytes` vectors (byte encoding, padding, digest bytes) and
   5 `hash_twice` vectors.
4. quantus-miner `pow-core` `NONCE_HASH_KVS`: 5 `get_nonce_hash` golden vectors (full 512-bit hash and
   the midstate), i.e. the proof-of-work function itself.
5. Target arithmetic: U512::MAX / 1 and / 256, strict comparison.

GPU (`crossCheck`, run by `test`): the plain sponge kernel on the 5 golden vectors plus random headers
with random full 64-byte nonces; the mining path (job state + counter, the search kernel's own code)
on consecutive counters across a 2^32 carry; and the search kernel against targets set to the smallest
of 64 CPU hashes (no hit), that hash + 1 (exactly that nonce, with its full hash: this exercises the
rare full-comparison path and the second squeeze) and U512::MAX (all 64 hit, each hash checked).
Every comparison is on all 512 bits. Passes at `--quick` and at mainnet parameters (they're the same
here).

Not done: a check against a real mainnet block. That needs a full header (digest logs, seal) and the
parent's difficulty from an RPC node; the explorer doesn't show them. The golden vectors come from the
official miner, which mines mainnet.

## Memory

None to speak of: a 176-byte job (`setBytes`) and a 4.6 KB hit buffer. Compute-bound.

## Kernel (`Kernels/poseidon2.metal`)

- One thread per nonce: load the job state, add the counter's two felts to lanes 6-7, permute, add the
  padding block, permute. If `bswap64(lane 0)` exceeds the target's top word, stop (that is all but
  about one nonce in 2^64 at an unreachable target, one in the difficulty at a real one). Otherwise
  finish the hash (second squeeze) and compare all 512 bits; hits go to `Poseidon2Output` with their
  full hash. `--set squeeze=always` finishes every hash instead.
- Field elements are lazy 64-bit representatives. Products are 32×32+64 multiply-add chains
  (`ulong(a0) * b0 + …`); reduction uses 2^64 = 2^32 - 1 and 2^96 = -1 on 32-bit words and ends in one
  sign-extended correction instead of selects. The external layer sums into (64-bit, carry count)
  accumulators and reduces once per output; the internal layer's sum rides inside each lane's
  multiply-add chain. Every linear layer also adds the next S-box layer's round constants.
- Round loops are rolled, lane loops unrolled; constants live in `constant` arrays. Threadgroup 256
  (`--set group=N`); the pipeline allows 1024, so register pressure isn't limiting.
- `poseidon2_walk` (mining path with full hashes) and `poseidon2_hash` (whole sponge from scratch)
  exist only for the cross-check.

## Measured (M3 Max 40-core, 2026-11-19, GPU shared with other ports)

| Kernel step | Rate |
|---|---|
| First version: plain 64-bit code, a full modular add per addition | 44.65 MH/s (10 s run) |
| Carry-count accumulators, 32-bit-word reduction, constants folded into layers | 55-57 MH/s |
| Products as multiply-add chains + one signed correction in the reduction | ~81 MH/s |
| Internal-layer sum inside the multiply-add chain (shipped) | best 85.4 MH/s |

Short runs, best of several, because other ports were benchmarking at the same time. No measurable
effect: `mulhi` vs `ulong` partial products (before the multiply-add chain), unrolling either round
loop, threadgroup 64/128/256. Slower: summing 32-bit halves separately in the linear layers instead of
carry counts (~75 vs ~82 MH/s); the two-select reduction tail (-15 to -30%).

`bench poseidon2 --seconds 10 --no-save` on the shipped kernel: **56.05 MH/s** while XelisHash and
NexaPow benchmarks ran alongside (thermal "fair"), and **73.47 MH/s** in a second run (82.99 MH/s over
its first 5 s, before other benchmarks started; thermal nominal). Treat ~83-85 MH/s as the uncontended
rate until a clean sequential run confirms it. `--set squeeze=always` (3 permutations per nonce):
28.3 MH/s in a contended run. For scale: quantus-miner's own CUDA kernel does ~235 MH/s on an
RTX 3080 Ti and ~140 MH/s on a 3060 Ti; at 85 MH/s against a ~31 TH/s network this Mac would earn
about 0.0047 QTC/day (about $0.18 at $39.22).

## Open questions

- Kryptex's QTC stratum: the live check confirms the XMRig-style shape (`keepalived` answered with
  `result.status`); the job fields and share answers are confirmed only by a live test (see "Pool protocol").
- No real-mainnet-block check (needs an RPC read). The vectors are from `main` of qp-poseidon and
  quantus-miner; the mainnet runtime version wasn't compared with `main` (spec_version 153).
- Sustained (thermal) rate and a clean uncontended 10 s number.

## Speed-up ideas

- Precompute the first external layer per job (the counter only adds small multiples of two columns)
  and compute only lane 0 of the final layer before the early reject: under 1% each by instruction count.
- Karatsuba (3 multiply-adds per product instead of 4), if the multiplier rather than the ALU is the
  limit; needs a clean GPU to judge.
- Profile the compiled shader (GPU profiler) to see whether multiply-adds or 64-bit compares dominate,
  then target the external layer's carry compares.
