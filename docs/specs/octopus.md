# Octopus (Conflux, CFX)

Folder `Sources/Algorithms/Octopus/` (`Octopus.swift` host, `OctopusReference.swift` CPU reference and
vectors, `OctopusPool.swift` pool miner), kernels `Kernels/octopus.metal`, id `octopus`, coins `["CFX"]`, unit H/s.
Build with `./build.sh Ethash Octopus`: Octopus reuses the Ethash folder's light cache, DAG items, Keccak and DAG
builder (`EthashReference.makeCache`, `.seed`, `.datasetItem`, `Keccak`, `EthashDAG.build`, and `ethash_keccakf` /
`ethash_fnv` from `ethash.metal`).

Octopus is Ethash with two changes: the walk reads 32 pages of 256 bytes (instead of 64 of 128), and before
the walk every nonce does a large modular-arithmetic job: SipHash chains fill the 1024 coefficients of a
polynomial over F_P (P = 1032193 = 2^20 - 2^14 + 1), shared by 32 consecutive nonces, and each nonce evaluates
it at 32 points. Those 32 values steer the walk and are folded into the Keccak seed. The polynomial work
(32 x 1024 multiply-adds mod P per nonce) dominates the GPU time on this Mac.

Octopus has been Conflux's mainnet PoW since launch (October 2020), not since a 2021 fork: `PowComputer` uses it
whenever `!test_mode`, there is no height switch, and the height-4096 block from 2020-10-28 verifies with it.

## Mainnet construction

**Job.** Conflux stratum (`mining.notify`, as conflux-rust writes it and open-cfxmine parses it):
`[jobId, height (decimal string), powHash (0x + 32 bytes), boundary (0x + big-endian hex)]`.
`powHash` is the block's PoW problem hash, keccak256(rlp(header without nonce)) (`BlockHeader::problem_hash`).
`height` picks the stage (cache and DAG). Solutions go back as `mining.submit [worker, jobId, "0x" + hex(nonce), powHash]`.
See "Pool protocol".

**Nonce.** The header nonce is a U256, but only `nonce.low_u64()` is hashed. Bits 128..254 of the nonce (kept
in place) used to form a "lower bound" subtracted from the hash before the comparison. Since conflux-rust's
hn_fix (commit 2e8a77d, July 2026) the stratum server rejects any nonce with its top 128 bits set, and such a
block is invalid from the `cip_hn_fix` height. So a miner uses a 64-bit nonce. Bits 64..127 are allowed but not
hashed (two of the vectors below have them). The kernels take 64-bit nonces from a start that is a multiple of 32.

**Hash** (compute.rs `hash_compute`; all word reads little-endian; Keccak is the legacy 0x01-padded one):

1. `v0..v3` = the problem hash as four little-endian u64.
2. Job constants: `remap(h) = 11^e mod P` with `e = h mod (P-2) + 1`, divided by `gcd(e, P-1)` until coprime.
   `a = remap(v0)`, `b = remap(v1)`, `w = remap(v3)`, `c = remap(v2 + t)` for the smallest `t >= 0` (wrapping
   u64) with `b^2 != 4ac (mod P)`.
3. Coefficients, shared by the warp of nonces with the same `n / 32`: for lane `i < 32`, a SipHash state set
   directly to `(v0, v1, v2, v3)` (no key constants) runs `hash24(32 * (n / 32) + i)` (`v3 ^= m`; 2 SipRounds;
   `v0 ^= m`; `v2 ^= 0xff`; 4 SipRounds); then for `j < 32`: one more SipRound and
   `d[32 j + i] = low32(v0 ^ v1 ^ v2 ^ v3) mod P`.
4. Values: for `i < 32`, `k = n mod 32 + 32 i`, `x_k = a*w^(2k) + b*w^k + c mod P`,
   `res_i = sum_{j<1024} d_j x_k^j mod P` (Horner from `d_1023`), and
   `result = result * 0x01000193 ^ res_i` (wrapping u64, from 0).
5. `seed = keccak512(powHash || result as 8 little-endian bytes)` (40-byte input).
6. Walk: `mix` = the 16 seed words repeated 4 times (64 words, 256 bytes). For `i < 32`:
   `page = fnv(seed_word0 ^ i ^ res_i, mix_i) mod pages` (`fnv(a, b) = a * 0x01000193 ^ b`,
   `pages = DAG bytes / 256`), then `mix = fnv(mix, DAG items 4 page .. 4 page + 3)` word by word.
7. Digest: `digest_i = fnv(red(mix[4i ..< 4i+4]), red(mix[32+4i ..< 32+4i+4]))` for `i < 8`, where `red` folds 4
   words with fnv.
8. `hash = keccak256(seed || digest)` (96-byte input).

**Target.** Valid when `U256::from_big_endian(hash) - lower_bound < boundary` (wrapping; lower bound 0 for
64-bit nonces), with `boundary = floor(2^256 / difficulty)` (`U256::MAX` for difficulty 1). So: the hash read
as a big-endian 256-bit number must be strictly below the boundary. The RPC's `powQuality` is
`floor(2^256 / (hash + 1))`. The search kernel compares all 256 bits strictly against a boundary held in a GPU
buffer (4 limbs, most significant first). open-cfxmine's CUDA kernel only compares the top 64 bits with `<=` and
leaves the exact check to the pool.

**Cache and DAG.** Exactly Ethash's: `seed = keccak256` applied `stage` times to 32 zero bytes, the 3-round
SeqMemoHash light cache, DAG items of 64 bytes with 256 parents (cache.rs, `calculate_dag_item`). Only the sizes
differ.

## Parameters and how they change with height

| | value |
|---|---|
| stage | `height / 2^19` (524,288 heights, about 7.2 days at 1.187 s per height) |
| cache | 16 MiB + 64 KiB x stage - 64, stepped down by 128 bytes until the 64-byte node count is prime |
| DAG | 4 GiB + 16 MiB x stage - 256, stepped down by 512 bytes until the 256-byte page count is prime |
| walk | 32 accesses of 256 bytes (8 KiB per hash, like Ethash) |
| polynomial | 1024 coefficients, 32 points per nonce, P = 1032193, generator 11 |

Used: pivot block 161,619,968 (0x9a22000) at 2026-11-19 21:16:32 UTC → **stage 308** (heights 161,480,704 to
162,004,991): cache 36,961,984 bytes (35.25 MiB), DAG 9,462,346,496 bytes (8.81 GiB; 9,024 MiB, Kryptex's
"9,024 MB" at height 161,619,504). `OctopusChain.estimatedHeight` extrapolates from that block at 1.1874 s per
height (measured over the year from block 134,217,728). Stage 309 starts at height 162,004,992, around
2026-11-25 04:15 UTC, with a 9,479,124,736-byte DAG. Override with `--set height=N` or `--set stage=N`.
`--quick` uses a 1 MiB cache and a 64 MiB DAG (not a real stage).

## Sources

- conflux-rust, PoW crate (master, read 2026-11-19; the algorithm is unchanged since #1878, 2020-10-03):
  https://github.com/Conflux-Chain/conflux-rust/tree/master/crates/cfxcore/pow/src: `shared.rs` (sizes,
  constants), `compute.rs` (hash), `cache.rs`, `seed_compute.rs`, `keccak.rs`, `lib.rs` (nonce, lower bound,
  boundary, quality, `test_octopus` without expected values)
- Header hashing: https://github.com/Conflux-Chain/conflux-rust/blob/master/crates/primitives/src/block_header.rs
- RPC block fields (1559 blocks report 90% of the header gas limit; `powQuality`):
  https://github.com/Conflux-Chain/conflux-rust/blob/master/crates/rpc/rpc-cfx-impl/src/helpers/block_provider.rs
- hn_fix: https://github.com/Conflux-Chain/conflux-rust/commit/2e8a77d7ab
- Stratum: conflux-rust `crates/stratum/src/lib.rs` (subscribe, submit replies, notify framing) and
  `crates/blockgen/src/miner/stratum.rs` (notify payload, submit parsing, the high-nonce check),
  https://github.com/Conflux-Chain/conflux-doc/blob/master/docs/stratum.md, and NiceHash's "xn" extension,
  https://github.com/nicehash/Specifications/blob/master/Octopus_NiceHash_v1.0.txt
- Conflux's open-source GPU miner: https://github.com/Conflux-Chain/open-cfxmine (`src/cuda/octopus.cuh`,
  `src/light.cc`, `src/OctopusCUDAMiner.cu`, `src/AbstractMiner.h`, `src/StratumClient.cc`)
- Kryptex: https://pool.kryptex.com/cfx, https://pool.kryptex.com/cfx/dag-size-calculator,
  https://pool.kryptex.com/cfx/api/v1/pool/info

## Vectors

Conflux publishes no known-answer vectors: `test_octopus` in lib.rs computes a hash without checking it, and
open-cfxmine has no tests. So the vectors are seven real mainnet pivot blocks
(`OctopusReference.vectors`), derived like this:

1. Block fields from `cfx_getBlockByEpochNumber` on https://main.confluxrpc.com, plus `eth_getBlockByNumber` on
   https://evm.confluxrpc.com for the eSpace base price of post-1559 blocks (read in a browser tab on
   2026-11-19).
2. Rebuilt the header RLP (`stream_rlp`): miner address decoded from base32, `Option` fields as 1-item lists,
   `base_price = [[core, eSpace]]`, and for 1559 blocks the header gas limit = RPC `gasLimit` x 10/9. For all
   seven blocks, keccak256 of the RLP with the nonce equals the block hash, which proves the field encoding.
3. Problem hash = keccak256 of the same RLP without the nonce.
4. Check: the CPU reference's hash (light verification from the cache) must lie in the range whose quality
   `floor(2^256 / (hash + 1))` equals the block's `powQuality`. That range pins the top ~80 bits, so a wrong
   problem hash, size formula or algorithm step fails with probability about 1 - 2^-80.

| height | stage | block hash | nonce (only the low 64 bits are hashed) | powQuality |
|---|---|---|---|---|
| 4,096 (2020-10-28) | 0 | ed9d8ad1…9572097f | 0xb4de08708 | 0x1e301c8bfd |
| 100,000,000 | 190 | 029130a0…6b20b143 | 0x35847700061b0795 | 0xce2083c3a2f |
| 134,217,728 | 256 | 0e5e5837…030ced48 | 0xdbd8e3da6184c51f | 0x12bc15abf85 |
| 161,619,713 | 308 | faf7d352…b4562590 | 0x6d82fe68eea21cd504823a31d72d312f | 0xb1f347a037 |
| 161,619,725 | 308 | 1d3435d7…9bb204c4 | 0x84450a74b6707338 | 0x1b18fb543e9 |
| 161,619,767 | 308 | fdec84ab…3ee2a79b | 0x8d78df3aa29952da06c8ecd0e738dc6d | 0x2074303e5aa |
| 161,619,968 | 308 | 00ecd3aa…443b3839 | 0x118e78927a61af2e | 0x19354b78650 |

They cover four stages (so the size and seed formulas), 128-bit nonces, and headers with pool tags in `custom`.
All pass (`test octopus`, about 2 s of cache building).

GPU cross-check (`crossCheck`, at mainnet parameters in `test octopus`): 16 random DAG items against the CPU;
128 consecutive nonces (four warps) from a random multiple of 32 with a random header through both kernels,
comparing digest and final hash; one hash computed entirely from the light cache; and both search kernels with
the boundary set to the lowest of those hashes + 1 (must report exactly that nonce) and to the lowest hash
itself (must report nothing, so the comparison is strict).

## Memory

DAG 8.81 GiB (shared storage, growing 16 MiB per stage), light cache 35 MiB (CPU array plus a GPU copy while
building), a 16 KiB point table, and 24 KiB of threadgroup memory per 128-thread threadgroup (128 bytes per
thread for coefficients then values, 64 bytes per thread for seeds).

## Kernel design (`Kernels/octopus.metal`)

- **Per job, on the CPU:** `a, b, c, w` and the 1024 points `x_k`, uploaded as (x as float, x/P as float, x,
  floor(x 2^32 / P)).
- **Coefficients:** a SIMD group is one warp (lane = nonce mod 32). Each lane runs its SipHash chain (64-bit
  ops) and writes its column of `d` to threadgroup memory.
- **Polynomial:** each lane evaluates its 32 points by Horner, 8 points per pass (4 passes over `d`, read as
  broadcast float4). The arithmetic is fp32: `ph = pv*x` and `pl = fma(pv, x, -ph)` give the exact 41-bit product,
  `q = rint(pv * (x/P))` is within 1 of the quotient, and `r = fma(-q, P, ph)` is exact because it is small. So
  `pv' = (r + pl) + d` stays an exact integer in (-P, 2P) and is normalised once at the end. That is 7 full-rate
  fp32 ops per step, 32,768 steps per nonce.
- **Walk:** keccak512 seed per thread, then a cooperative walk. 16 lanes share each hash, lane t loads uint4 t of
  each 256-byte page (one coalesced load per access), and the index comes from lane i/4 via `simd_shuffle`. Each
  16-lane group has 2 hashes in flight. The page modulo uses a float reciprocal with a ±1 correction. The digest
  is gathered with shuffles, then keccak256, then the 256-bit strict compare; hits go to `SearchOutput`.
- **Variants** (all cross-checked): `--set kernel=simple` (one thread walks its own hash, 64 mix words in
  registers), `--set mulmod=shoup|wide` (32-bit Shoup / 64-bit `%` arithmetic), `chains`, `par`, `group`,
  `fastmod`. Diagnostics: `--set phase=walk|poly|none` skips the polynomial and/or the DAG loads to time each
  part (hashes are then wrong, and the cross-check is skipped).
- **Pool jobs** use the same search kernel through `setJob(header:)`, `setTarget(_:)` and `search(_:start:threads:)`;
  `dagItem` is also how the pool miner re-checks a hit on the CPU.

## Pool protocol (Kryptex CFX: `OctopusPool.swift`)

Dialect: Conflux's own Stratum (conflux-rust `crates/stratum`, `crates/blockgen/src/miner/stratum.rs`), as
open-cfxmine speaks it, plus NiceHash's "xn". JSON-RPC 2.0 lines over TLS (`cfx.kryptex.network:8027`, the default)
or TCP (`:7027`).

| Step | Message | Fields |
|---|---|---|
| 1 | `> mining.subscribe [login, "x"]` (`"jsonrpc": "2.0"`) | In Conflux's dialect the subscribe **is** the login (worker, secret). `< true` (conflux-rust); false or an error throws `PoolLoginRefused` with the pool's words. If the pool answers Bitcoin-style instead (`[subscriptions, extranonce1, size]`), the miner sends `mining.authorize [login, "x"]` and uses extranonce1 as the nonce's top bytes. |
| 2 | `< mining.notify ["0x" job, "height", "0x" pow hash, "0x" boundary]` | conflux-rust writes `["0x{pow_hash:x}", "{height}", "0x{pow_hash:x}", "0x{boundary:x}"]` with an id counter from 17 and expects no reply. The pow hash has 64 hex digits; the boundary is a U256 in hex without leading zeros (a big-endian number). NiceHash adds `"xn"`: the nonce's first byte(s), kept fixed. The older `[job, pow hash, boundary]` form gets the estimated height. |
| 3 | `> mining.submit [login, job, "0x" + 16 hex digits, "0x" pow hash]` | the 64-bit nonce as a number (`low_u64()` of the U256 the pool parses; nonces with the top 128 bits set are refused since hn_fix); the pow hash as received. `< [true]` or `[false, reason]` (conflux-rust); plain true/false and errors are read too. |
| also | `mining.set_difficulty [d]` (boundary 2^256 / d for a job without one); `mining.set_extranonce`; `client.reconnect` (in place, keeping the DAG); `client.show_message`; `client.get_version`. |

- **Targets and work.** A share's hash, read big-endian, is below the boundary (all 256 bits compared).
  `work` = 2^256 / boundary = the share difficulty in hashes; Kryptex's API states 10,737,418,240 with
  `hashes_per_diff` 1, so expect a boundary of 2^256 / 10,737,418,240. Each boundary change is logged with its
  hashes per share.
- **Mining.** The job's height gives the stage; a new stage builds a new cache and DAG (8.8 GiB, about 5 s; the old
  DAG is released first). A new pow hash (about every 0.5 s) only reloads the points table (about 1 ms). Nonces start
  at a random multiple of 4096 in the lower half of the counter space, so two miners on one login without an
  extranonce rarely overlap; batches of 2^21 in whole threadgroups, with any prefix in the top bytes. Every GPU hit
  is re-hashed on the CPU (OctopusReference over the GPU's DAG items) before it is sent. Shares found on the previous
  job still go out: conflux-rust keeps a window of recent problems. The rate goes to `events.hashrate` every 5 s.
- **Offline round trip** (`metalminer pooltest cfx`, about 2 s): a MockPool in Conflux's dialect with the pow hashes
  and heights of mainnet pivot blocks 161,619,968 and 161,619,725 (quick DAG, stage-0 cache). Checked: an unknown
  login (subscribe answered false) is refused as `PoolLoginRefused`; shares at boundary 2^240 found on the GPU, each
  recomputed by the mock from its own light cache and accepted with `[true]`; the job re-sent with a 64 times smaller
  boundary yields shares below it; a new job with `"xn": "5a"` yields only 0x5a… nonces; a found nonce with its low
  bit flipped is refused with `[false, "Incorrect Nonce!"]` and reported as rejected.
- **Live handshake** (`metalminer handshake cfx`) connects and sends nothing, since the first message carries the
  login. 2026-11-20: TLS up in about 0.4 s, and the pool said nothing within 3 s.
- **Only a live login can confirm** whether Kryptex speaks Conflux's subscribe-as-login (the Bitcoin-style fallback
  is ready), its notify layout and whether it sends "xn" or an extranonce, the boundary it sends, how it wants the
  nonce written, and its share replies.

**Live on Kryptex (2026-11-23):** Conflux's own dialect: mining.subscribe [login, "x"] answered `true` for a Kryptex
account login (`email/worker`); the boundary set 10.7 G hashes per share; the stage-308 DAG (8.81 GiB) built in
3.4 s, and the first share was accepted (`[true]`) after about 7 minutes.

## Measured (2026-11-19, M3 Max 40-core GPU, shared with other ports throughout)

| run | rate |
|---|---|
| `bench octopus --seconds 10 --no-save` (mainnet, stage 308, default kernel) | **20.96 MH/s** (first 5 s at 23.47) |
| other 5 s mainnet runs of the default kernel, depending on load from other ports | 17.1 to 24.4 MH/s |
| `--quick` (64 MiB DAG, compute-bound), default kernel | about 25.5 MH/s |
| `--quick`, `mulmod=shoup` / `mulmod=wide` | 6.7 MH/s / 0.22 MH/s |
| `--quick`, `kernel=simple` | 18.2 MH/s (cooperative walk is +36%) |
| mainnet, float-reciprocal page modulo vs integer `%` (same period) | 17.07 vs 16.28 MH/s (+5%) |
| mainnet diagnostics, same period: walk only / polynomial only / both | 28.6 / 18.9 / 17.1 MH/s |

DAG build 3.7 to 5.2 s, cache 0.5 to 0.6 s. Tried without gain: `chains` 4, 16 and 32 (32 runs 2.5 to 3.6 times
slower, probably register spills); `par` 1 and 4; group 64 and 160; a magic-constant FMA instead of `rint`; and
running some Horner chains in integer Shoup arithmetic alongside the fp32 ones (the integer and FP32 pipes didn't
add up). Run-to-run noise from the shared GPU was about ±30%, so only large effects are reliable. The polynomial
is about 60% of the compute at quick size, and the kernel is compute-bound: the best mainnet run (24.4 MH/s) is
close to the quick-size rate.

## Open questions

- Kryptex's CFX dialect after login (see "Pool protocol"): the TLS endpoint is confirmed live; everything a login
  would show is not.
- The mainnet `cip_hn_fix` height (part of the V3.1 hard fork) isn't known here. It doesn't matter for 64-bit
  nonces.
- The fp32 trick relies on the Metal compiler keeping `fma(pv, x, -pv*x)` and `rint` intact under the harness's
  default fast math. It does today, and the cross-check would catch a change.
- A miner must rebuild the DAG at each stage boundary (about weekly, 4 to 5 s). The engine also creates a new pool
  miner (and DAG) after a dropped connection; a `client.reconnect` from the pool keeps it.

## Speed-up ideas

1. **Fast multipoint evaluation (largest).** All 32 nonces of a warp evaluate the same polynomial at
   `x_k = Q(w^k)`, k < 1024, with `Q(y) = a y^2 + b y + c`. Rewrite `P(Q(y)) = R((y + s)^2)` with `s = b/2a` and
   `R(z) = P(a z + c - b^2/4a)` (a Taylor shift and a scaling: one convolution), shift `R(y^2)` by `s` (a second
   convolution), then evaluate at the geometric points `w^k` with Bluestein's chirp-z
   (`w^km = w^(C(k+m,2) - C(k,2) - C(m,2))`, a third convolution). P - 1 = 2^14 x 63, so NTTs up to 16,384
   points exist, and the per-job kernel transforms can be precomputed on the CPU. That is about 3 NTTs of 2048
   and 3 of 4096 per warp (~110K butterflies) instead of 1M Horner steps: roughly 4 to 5 times less polynomial
   work. The kernel would then be bound by the walk (28.6 MH/s measured alone), for an estimated +30 to 50%.
2. Split the polynomial and the walk into separate kernels on a concurrent encoder (slice i's walk alongside
   slice i+1's polynomial), so compute and memory overlap without sharing one kernel's registers.
3. Smaller: a bit-interleaved 32-bit Keccak (two Keccak-f per hash on emulated 64-bit lanes), fewer registers
   in the walk (more SIMD groups per core).
