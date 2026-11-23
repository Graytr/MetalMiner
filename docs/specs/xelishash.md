# XelisHash v3 (XEL)

Port: `Sources/Algorithms/XelisHash/` (CPU reference, host code, checks) and `Kernels/xelishash.metal`.
Id `xelishash`, coin XEL, unit H/s. Options: `--set slots=N` (hashes per dispatch, default 2048),
`group=N` (threadgroup width, default 64), `kernel=pipelined|simple`, `trace=1` (GPU time per
dispatch), `check=N` (cross-check sample size), `m.NAME=VALUE` (Metal macro, e.g. `m.XH_FAST_DIV=0`),
`height=N`.

## Which version mainnet uses

XELIS picks the PoW by block version (`xelis_daemon/src/core/hard_fork.rs`, `get_pow_algorithm_for_version`;
heights in `xelis_daemon/src/config.rs`):

| heights | block version | PoW |
|---|---|---|
| 0 – 434,099 | V0 | xelis-hash v1 |
| 434,100 – 3,282,149 | V1, V2 | xelis-hash v2 |
| 3,282,150 onwards (13 Dec 2025, "Smart Contracts, xelis-hash v3, 5s block time") | V3 … V7 | **xelis-hash v3** |

Checked on 2026-11-19 ~21:02 UTC at explorer.xelis.io: height 8,682,177 (topoheight 10,026,787),
block version 7, difficulty ~81.3 M, network ~16.3 MH/s, block time target 5 s (5.7 s average).
Every version up to V7 (the latest configured hard fork, height 6,909,122) uses v3, so only v3 is
ported. `--set height=N` is accepted; heights below 3,282,150 are rejected. The parameters don't
change with height within v3 (no epochs, no DAG).

Kryptex (pool.kryptex.com/xel, 2026-11-19): algorithm "Xelishash", `xel.kryptex.network:7019`
(regional: `xel-eu`, `xel-us`, `xel-br`, `xel-sg`, `xel-hk`, `xel-ru`, `xel-ae` `.kryptex.network:7019`,
TCP and SSL), static share difficulty 1,048,576 (2^20, so a share needs the top 20 bits of the
hash zero), pool 8.72 MH/s, 188 miners / 565 workers, PROP and SOLO 1 %.

## Mining input and target

The PoW input is the 112-byte `MinerWork` (`xelis_common/src/block/miner.rs`, `BLOCK_WORK_SIZE`;
the repo README's "120 bytes" is stale, and the real-block check below confirms 112):

| bytes | field | encoding |
|---|---|---|
| 0..32 | header work hash = BLAKE3(version u8 \| height u64 BE \| BLAKE3(tips) \| BLAKE3(tx hashes)) | as is |
| 32..40 | timestamp, milliseconds | u64 big-endian |
| **40..48** | **nonce** | **u64 big-endian** (`Worker::increase_nonce` writes `nonce.to_be_bytes()` here) |
| 48..80 | extra nonce (miner/pool controlled; xelis-miner puts a thread id in the last 1–2 bytes) | as is |
| 80..112 | miner public key (compressed Ristretto, 32 bytes) | as is |

The block hash is BLAKE3 of the same 112 bytes; the PoW hash is `xelis_hash_v3(MinerWork)`.
Target check (`xelis_common/src/difficulty.rs`): the 32-byte PoW hash read as a **big-endian**
U256 must be `<= U256::MAX / difficulty`. The kernel takes the whole 112-byte template from the host,
writes `startNonce + gid` big-endian at bytes 40..47, and compares the hash against a 256-bit
big-endian target held in the parameter block, appending hits to `SearchOutput`. Real miners put
arbitrary bytes in the nonce field (the two blocks below have nonces 0xA460506B5E010000 and
0xBA1236684A040000), so a 64-bit counter is valid.

## The algorithm (v3)

Scratchpad: 531 × 128 u64 words = 543,744 bytes (531 KiB), viewed as little-endian u64 words.

1. **Stage 1** (shared with v2, `v2::stage_1`): h = BLAKE3(input); nonce = h[0..12]. The input is
   cut into 32-byte chunks (4 for 112 bytes; the last is 16 bytes, zero-padded). For each chunk:
   h = BLAKE3(h ‖ chunk) (a single 64-byte block); the next quarter of the scratchpad (135,936 bytes =
   2,124 blocks) is the ChaCha8 keystream (RFC 8439 layout: 32-bit block counter from 0, 96-bit nonce,
   8 rounds; the `chacha20` 0.9 crate's `ChaCha8`) keyed by h; the next nonce is the last 12 bytes
   just written.
2. **Stage 3** (`v3::stage_3`): two passes of 33,984 iterations over halves A = words [0, 33984) and
   B = [33984, 67968). Per pass: one AES round (`aesenc`, key "xelishash-pow-v3") seeds `result`.
   Each iteration reads a = A[map_index(result)], b = B[map_index(a ^ !rotr(result, r))], c = the
   sequential word r, picks one of 16 branches with `rotl(result, c) & 15` (wrapping u64 arithmetic,
   u128 div/rem in 6 branches, u128 multiply-high, isqrt), then reads t from A or B (pick_half), and
   does two read-modify-writes: A[ia] = t, B[ib] ^= old ^ rotr(t, i + j). `map_index` is a
   murmur-style mix then `(x * 33984) >> 64`. Between passes `addr_a = modular_power(addr_a, addr_b,
   result)` (u128 square-and-multiply) and `addr_b = isqrt(result) * (r + 1) * isqrt(addr_a)`.
3. **Stage 4**: BLAKE3 of the whole 543,744-byte scratchpad (531 chunks of 1 KiB; tree
   P(P[0..512), P(P[512..528), P(P(528, 529), 530)))).

v3's `isqrt` uses `(n as f64).sqrt() as u64` and a ±1 fix with *wrapping* products. That equals
floor(sqrt(n)) except at the top of the range: n >= 2^64 − 2^33 + 1 = (2^32 − 1)^2 gives 2^32 and
n >= 2^64 − 1024 (where f64(n) rounds to 2^64) gives 2^32 + 1. The GPU has no f64, so
`xh_isqrt` computes floor(sqrt) with a float estimate, one Newton step and exact integer fix-ups,
and special-cases those two ranges; the primitive tests compare it with Swift's `Double`-based copy
of the reference on both boundaries.

## Sources

- https://github.com/xelis-project/xelis-hash — `src/v3.rs`, `src/v2.rs` (stage 1, stage 4,
  `combine_u64`), `src/scratchpad.rs`, `C/xelis_hash_v3.c` (same algorithm in C), `Cargo.toml`
  (chacha20 0.9.1, blake3 1.5, aes 0.8 hazmat).
- https://github.com/xelis-project/xelis-blockchain — `xelis_common/src/block/miner.rs` (MinerWork,
  nonce at 40..48 BE), `xelis_common/src/block/header.rs` (`get_work`, `get_pow_challenge`),
  `xelis_common/src/crypto/hash.rs` (`pow_hash`), `xelis_common/src/difficulty.rs` (target),
  `xelis_common/src/crypto/address.rs` (bech32 address = key ‖ type byte),
  `xelis_daemon/src/config.rs` (hard-fork heights), `xelis_daemon/src/core/hard_fork.rs`.
- BLAKE3 spec, RFC 8439 (ChaCha), FIPS-197 (AES); explorer.xelis.io (blocks); pool.kryptex.com/xel.
- Pool protocol: https://docs.xelis.io/developers-api/stratum (XELIS stratum v0.1.1, also
  https://github.com/vipor-net/xelis-stratum-protocol); client side https://github.com/Tritonn204/tnn-miner
  (`src/net/xelis/net_xelis_stratum.cpp`, `src/coins/mine_xelis.cpp`, `include/stratum/xelis-stratum.h`); pool side
  https://github.com/blackmennewstyle/miningcore (branch dev, `src/Miningcore/Blockchain/Xelis/`: `XelisPool.cs`,
  `XelisJob.cs`, `XelisJobManager.cs`, `XelisConstants.cs`); https://pool.kryptex.com/xel/api/v1/pool/info (servers,
  static difficulty, `hashes_per_diff`).

## Vectors (all pass)

- xelis-hash `v3.rs`: `test_zero_hash` (112 zero bytes → 69ac6728…cd67a3) and `test_verify_output`
  (→ f208b0de…9c4653). Also v2's two vectors (`v2.rs`), which share stages 1 and 4 with v3.
- Two real mainnet blocks (version 7, from explorer.xelis.io): height 8,682,175 (hash 09e88961…,
  3 tips, difficulty 81,673,695) and 8,682,180 (hash a36b14ab…, difficulty 79,987,125). For each,
  the MinerWork rebuilt from the header fields (miner key decoded from the `xel:` bech32 address)
  hashes with BLAKE3 to the block hash (layout, field order, byte order), and its v3 PoW hash
  (0x00000024e1…, 0x0000000a50…) is below (2^256 − 1) / difficulty.
- Building blocks: BLAKE3("") and BLAKE3("abc"), FIPS-197 Appendix B round 1, AES S-box spot values.
- GPU (`crossCheck`): N random MinerWork/nonce pairs, full 32-byte hashes against the CPU (32 in
  `test`; 512 and 1,024 also passed with `--set check=N`); the hit list at a 1/4 target; the kernel
  finds block 8,682,175's nonce under its network target; ~600 primitive cases (isqrt boundaries,
  u128 division corner cases, every S-box input, modpow, map_index/murmur, mulhi/pick_half).

## Memory

543,744 bytes per hash in flight, no shared tables. `--set slots=N` sets the hashes per dispatch
(default 2048 = 1.04 GiB; `--quick` uses 256 = 133 MiB). The scratchpad doesn't fit in threadgroup
memory (32 KiB, ~1 KiB per hash for a 32-thread group, a 0.2 % hit rate), so it lives in device memory.

## Kernel

One thread per nonce; scratchpads of 32 consecutive threads interleaved word by word
(word w of lane L at w·32 + L), so stage 1's writes, stage 4's reads and stage 3's sequential `c`
stream are coalesced; stage 3's random accesses touch one 128-byte line per lane either way.
Stage 4 writes each chunk's chaining value over the chunk's first 32 bytes and merges the tree in
place. `runBatch` rounds the batch up to whole dispatches of `slots` nonces (one command buffer
each) and returns the hashes actually computed (see the harness note below).

Stage 3 is the whole cost: 67,968 dependent iterations, each with 3 random reads and 2 random
read-modify-writes. What was tried (M3 Max, GPU shared with other ports, best dispatch of a run):

| variant | slots | ms per dispatch | H/s |
|---|---|---|---|
| reference-shaped loop, 16-way divergent switch | 2048 | ~1700 | 1.2 k |
| pipelined + unified branches, native u64 division | 2048 | 608 | 3.4 k |
| pipelined + unified + float-assisted division (default) | 32 (one SIMD group) | 280 | 114 |
| 〃 | 512 / 1024 / 1536 | 313 / 333 / 344 | 1.6 k / 3.1 k / 4.5 k |
| 〃 | **2048** | **360** | **5.67 k** |
| 〃 | 2560 / 3072 / 4096 | 457 / 564 / 780 | 5.6 k / 5.45 k / 5.24 k |
| 〃, threadgroup 32 / 128 / 256 at 2048 slots | | | 5.7 k / 5.6 k / 5.0 k |

- **Pipelined**: the next iteration's a, b and c are loaded before this iteration's two stores and
  patched when they alias (a hit on A[ia], B[ib] or the c word: about 1–2 of each per hash, so
  the cross-check exercises them), which leaves 2 dependent memory round trips per iteration instead of 4.
- **Unified branches**: every lane computes the same two isqrt and one u128 division with
  per-branch operands, then a cheap per-branch combination, instead of the SIMD group running
  ~14 of the 16 branches one after another (5–6 of them with their own division).
- **Float-assisted division**: the two 64/32 divisions inside each 128/64 step use a float
  reciprocal plus exact fix-ups instead of Metal's emulated u64 division: latency 553 → 280 ms.
- Up to ~1.5k slots the dispatch takes about one hash's latency (~280–340 ms, ~4 µs per
  iteration), so the rate grows with slots. From 2048 it stops growing, whatever the threadgroup
  width (even 8 groups of 256 on 40 cores reach 5.0 k): 5.67 kH/s × 67,968 iterations × 7 line
  transfers (5 random reads + 2 dirty write-backs) ≈ 2.7 G random accesses/s, ≈ 345 GB/s at
  128-byte lines, close to the M3 Max's ~400 GB/s. More slots get slightly slower (bigger random
  footprint; TLB/DRAM-page effects are a guess).

## Measured rate

- Default (pipelined, 2048 slots, group 64): best dispatches **5.67 kH/s**; the 10 s
  `bench xelishash --seconds 10 --no-save` run gave **4.55 kH/s** while Poseidon2 and NexaPow
  benchmarks were sharing the GPU (thermal nominal). Treat ~5.5 kH/s as the unshared estimate,
  to be confirmed in the solo ranking run.
- For comparison, the unoptimized Swift CPU reference hashes at ~3–4 kH/s on the 16 CPU cores
  (printed by the cross-check). XelisHash is designed CPU-first (the scratchpad fits in a CPU L2), so on
  this Mac the CPU, or CPU + GPU, likely out-mines the GPU alone.

## Harness note

The harness sizes batches toward ~150 ms, but one XelisHash dispatch takes ~0.3 s whatever its
size (latency-bound), so the first version shrank to 1-nonce batches and measured 2.7 H/s. `runBatch`
therefore rounds up to whole dispatches of `slots` nonces and returns the real count, like Ethash
rounds to threadgroups. A per-algorithm minimum batch (or target batch time) in the harness would
make this explicit.

## Pool protocol (Kryptex `xel`)

`XelisHashPoolMiner` (`XelisHashPool.swift`; offline test in `XelisHashPoolTest.swift`) speaks the XELIS stratum
protocol v0.1.1 (by Vipor.net, published as the official spec at https://docs.xelis.io/developers-api/stratum, source
https://github.com/vipor-net/xelis-stratum-protocol): newline-delimited JSON-RPC over TCP 7019 or TLS 8019 (the miner
uses `PoolEndpoint`'s choice, SSL by default). No "jsonrpc" field is sent, as in the spec's examples.

| | message | params / result |
|---|---|---|
| → | `mining.subscribe` | `["MetalMiner/1.0", ["xel/v3"]]` |
| ← | result | `[session id, extra nonce hex, extra nonce length in bytes, pool public key hex]` |
| → | `mining.authorize` | `[login, worker, "x"]`: login exactly as saved (Kryptex's `wallet/worker` or `username/worker`), worker = the part after the last `/` |
| ← | result | `true`, or an error |
| ← | `mining.set_difficulty` | `[d]` |
| ← | `mining.notify` | `[job id, timestamp in ms as hex, header work hash (32 bytes hex), algorithm, clean jobs]` |
| ← | `mining.set_extranonce` | `[extra nonce hex, length, pool public key hex (optional)]`, applied to the current job at once |
| ← | `mining.ping` | answered with `{"id": same id, "method": "mining.pong"}` |
| ← | `mining.print` | `[level, text]`, logged |
| ← | `client.reconnect` | reconnect to the same endpoint (a pool-supplied host is never followed) |
| → | `mining.submit` | `[worker, job id, nonce as 16 hex digits]` |
| ← | result | `true`, or an error `{"code": 21 job not found / 22 duplicate / 23 low difficulty / 24 unauthorized, "message"}` |

**Job → MinerWork** (112 bytes, the layout above): bytes 0..<32 = notify's header work hash as sent; 32..<40 = notify's
timestamp hex read as a number and written u64 big-endian; 40..<48 = the nonce; 48..<80 = the extra nonce from subscribe
or set_extranonce, cut to its declared length if shorter and zero-padded on the right; 80..<112 = the pool's public key
(the block pays the pool, so Kryptex's key replaces the miner's). The miner owns all 8 nonce bytes: the kernel writes a
64-bit counter big-endian at 40..<48, and mining.submit sends those 8 bytes in the same order (`%016llx` of the
counter). Pools copy the hex back into bytes 40..<48 as raw bytes (tnn-miner's client writes its nonce in place and
submits `hexStr(&WORK[40], 8)`; the blackmennewstyle Miningcore pool rebuilds MinerWork as header | timestamp | nonce
bytes | extra nonce | key and requires 16 hex digits). The counter starts at a random value below 2^62 per connection and
never restarts, so a re-sent job can't produce duplicate shares.

**Difficulty → target → work.** target = floor((2^256 − 1) / d) (`XelisHashReference.target`, the node's rule); a
fractional d is rounded up first, so every share still meets the pool's target. A share is valid when its v3 hash,
read big-endian, is <= target (node and Miningcore: `hash <= target`). Its expected work is d hashes (Kryptex pool info:
`hashes_per_diff` 1), the value `events.share` reports. Kryptex's static d = 1,048,576 = 2^20 means one share per ~3 min
at 5.6 kH/s. A harder difficulty applies to the current job at once, an easier one from the next notify; a job that
arrives before any set_difficulty waits for one rather than mining at difficulty 1. Jobs named `xel/v1`, `xel/0`,
`xel/v2` or `xel/1` are skipped (only v3 is ported); `xel/v3`, `xel/2` (the legacy name of v3) or no name are mined, and
an unknown name is mined as v3 with a log line.

**Mining loop.** One dispatch of `slots` nonces (2048, ~0.36 s) per iteration, with every message from the pool applied
between dispatches. Each GPU hit's hash is compared with the CPU reference (and the target) before it is sent; shares go
out without waiting and their answers are matched by request id (ids from 1000; `call()` uses 1, 2). The rate goes to
`events.hashrate` every 5 s; no job for 120 s throws, so the engine reconnects. A mining.authorize answered with an
error or `false` throws `PoolLoginRefused` with the pool's words, so the engine skips XEL instead of retrying.
`metalminer mine xel --trace` prints every stratum line.

**Live check** (`metalminer handshake xel`, 2026-11-20, `stratum+ssl://xel.kryptex.network:8019`, no login): mining.subscribe
→ `{"error":null,"result":["77d984126017b02b","c81fce4e…8086929fb",32,"c6f40ffd…b0de2178"],"id":1}`, exactly the spec's
result (16-hex-digit session id, 32-byte extra nonce declared as 32, 32-byte pool public key); nothing else is pushed
before authorize.

**Offline test** (`metalminer pooltest xel`, 256 scratchpads, ~2.5 s): MockPool plays the pool with the fields of the
two real blocks above. Job b0 = block 8,682,175's header work hash and timestamp, extra nonce and key from subscribe, at
the block's network difficulty 81,673,695, with the counter started 8 below the block's nonce: the GPU finds exactly
the block's own nonce `a460506b5e010000` and the mock's CPU re-hash accepts it, which checks every field's position and
byte order end to end. Then job b0e (same block, difficulty 64): 7 shares in the recorded run, each re-hashed by the
mock with the CPU reference. One share is deliberately sent with a nonce that misses the target: the mock answers 23
low difficulty share and the miner reports it rejected. Mid-run the mock sends mining.ping (answered), set_extranonce
with block 8,682,180's extra nonce and key, difficulty 128 and job b1 on that block: 6 more shares accepted at the new
target. All 14 accepted shares were reported with their job's difficulty as work.
A second mock that refuses mining.authorize makes `run()` throw `PoolLoginRefused` with the pool's words
("unauthorized worker").

**Only a live test can confirm:** that Kryptex takes `wallet/worker` or `username/worker` as authorize's first parameter
(its pages say so for every coin) and what it does with the second; what it expects as submit's first parameter (the
spec says the worker name, which we send; open-source pools ignore it); the algorithm name in its notify; that
set_difficulty comes before the first notify; its share answers; and that shares are accepted at all.

**Live on Kryptex (2026-11-23):** mining.authorize accepted a Kryptex account login (`email/worker`) as its first
parameter; the pool set difficulty 1,048,576 and accepted the first share within a minute.

## Open questions

- Kryptex's XEL stratum: its subscribe answer matches the XELIS stratum spec (live check above); login, jobs,
  difficulty and share answers are confirmed only by a live test (see "Pool protocol").
- What bounds the plateau (DRAM bandwidth at 128-byte granularity vs TLB misses) isn't measured;
  no profiler was used.
- One dispatch is ~360 ms alone but was seen at up to ~870 ms while other ports loaded the GPU;
  if a real miner shares the GPU heavily, lower `slots` to keep command buffers under the watchdog.
- The reference panics if `result == 0` before `modular_power` (probability 2^-64); the GPU returns 0.

## Speed-up ideas

- Mine XEL on the CPU too (an optimized C/Rust-style implementation should beat the Swift reference).
- Cut stage 3's ALU latency so the plateau is reached with fewer slots (smaller footprint, maybe a
  slightly higher plateau): a reciprocal-based (Möller–Granlund) 128/64 division instead of two
  divlu steps, issuing b's load before the a-alias check (re-load on the rare alias), cheaper isqrt.
- Split stages 1 and 4 (estimated ~5 % of a hash's latency) into wide kernels where lanes share
  ChaCha blocks and BLAKE3 chunks.
