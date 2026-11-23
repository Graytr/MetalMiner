# Autolykos v2 (Ergo, ERG)

Folder `Autolykos2`, id `autolykos2`, coins `ERG`, unit H/s. Files: `Sources/Algorithms/Autolykos2/`
(`Autolykos2.swift` host, `Autolykos2Reference.swift` CPU reference + vectors, `Autolykos2Blake2b.swift`,
`Autolykos2Pool.swift` pool miner, `Autolykos2PoolTest.swift` its offline round trip), `Kernels/autolykos2.metal`.

## What it is

Autolykos v2 is Ergo's proof of work since block 417,792. It is a k-sum puzzle over a table of N
pseudo-random 31-byte numbers: each nonce picks k = 32 table elements, sums them, and hashes the sum.
The table depends on the block height, so a miner rebuilds it for every block (about 15.5 G BLAKE2b
compressions at today's N). Mining itself is memory-bound: 33 random 32-byte table reads per nonce.

## Mainnet construction (exact)

All hashes are BLAKE2b-256 (unkeyed, 32-byte digest; scorex `Blake2b256`). All integers in hash inputs
are big-endian.

- **Message.** `msg = Blake2b256(header without PoW)`, 32 bytes. The header without PoW (v2 and later,
  `HeaderSerializer.serializeWithoutPow`) is: version (1) | parentId (32) | adProofsRoot (32) |
  transactionsRoot (32) | stateRoot (33) | timestamp in ms (VLQ) | extensionRoot (32) | nBits (4, big-endian) |
  height (VLQ) | votes (3) | length of extra fields (1 byte, 0 for block versions 2 to 4; version 5 and later
  may append fields). The block id is `Blake2b256(that || pk (33) || nonce (8))`. A pool sends `msg`
  directly, so a pool miner never builds headers.
- **Nonce.** 8 bytes, big-endian (`Longs.toByteArray` in the node). The kernel takes a 64-bit start nonce
  and adds the thread index, so a pool's extranonce1 goes in the top bytes of the start nonce.
- **Height bytes.** `h = height` as 4 big-endian bytes.
- **Table size.** `N = calcN(height)`: 2^26 below height 614,400; from there `N = N / 100 * 105`
  (integer division first) once per 51,200 blocks, counting the first step at 614,400; frozen from
  height 4,198,400 at 2,143,944,600 (< 2^31).
- **Constant M.** The numbers 0 ... 1023, each as 8 big-endian bytes (8,192 bytes).
- **Element j.** `Blake2b256(BE32(j) || h || M)` without its first byte: a 31-byte big-endian number
  (8,200-byte input, 65 compressions).
- **Per nonce** (`hitForVersion2ForMessage`):
  1. `i = BE64(Blake2b256(msg || nonce)[24..31]) mod N`.
  2. `seed = Blake2b256(element(i) || msg || nonce)` (31 + 32 + 8 = 71 bytes).
  3. `idx[k] = BE32(ext[k..k+3]) mod N` for k = 0 ... 31, where `ext = seed || seed[0..2]`.
  4. `f = element(idx[0]) + ... + element(idx[31])` as integers (< 2^253), written as 32 big-endian bytes.
  5. `hit = Blake2b256(f)` read as a 256-bit big-endian number.
- **Target.** Valid if `hit < b` (strict), with `b = floor(q / D)`, `D = decodeCompactBits(nBits)` (Bitcoin-style
  compact form) and q the secp256k1 group order
  `fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`. Expected hashes per block ≈ D.
  The kernel holds the target as 8 32-bit words, most significant first, in a GPU buffer.
- **Pool shares.** Kryptex shows a static share difficulty of 4,294,967,296 (2^32) with `hashes_per_diff` 1 in its
  pool API, custom difficulty not supported: one share per ~4.3 G hashes (~71 s at 60 MH/s). See "Pool protocol".

## Current parameters (2026-11-19)

- Mainnet tip used: **block 1,920,429** (id `838731fc…6953371d`, version 4, 2026-11-19 20:53:00 UTC),
  difficulty 72,953,324,634,112 (nBits 0x064259C5), about 0.60 TH/s of network hashrate at 121 s blocks.
  Blocks averaged 121.1 s between heights 1,000,000 and 1,920,429. Source:
  `api.ergoplatform.com/api/v1/networkState` and `/api/v1/blocks/<id>`.
- **N = 238,614,390** (26 increase steps). Kryptex's DAG size calculator shows 7,054 MB for ERG at this
  height, which is N × 31 bytes in MiB, so it agrees.
- Next step at height 1,945,600 (~2026-12-24): N = 250,545,015. N grows 5% every 51,200 blocks (~72 days)
  until height 4,198,400.
- Default height: the reference block 1,920,429 while the estimated current height (reference + elapsed /
  121.1 s) has the same N, which lets the cross-check mine that real block on the GPU. After the next N
  step, the estimated height. The rate depends only on N.
- Kryptex pool (pool.kryptex.com/erg): `erg.kryptex.network:7021` (TCP) / `:8021` (SSL); regional hosts
  `erg-eu`, `erg-us`, `erg-br`, `erg-sg`, `erg-hk`, `erg-ru`, `erg-ae` (same ports); PPS+ 1%, SOLO 1%;
  static share difficulty 2^32; pool hashrate 51.6 GH/s on 2026-11-19.
- Options: `--set height=H`, `--set n=N` (table size override), `--set kernel=simple|coop`,
  `--set blake=u32|mix|u64`, `--set storage=shared|private`, `--set group=G`. `--quick` uses N = 1,234,567.

## Sources

- Consensus code (ergoplatform/ergo, master): `ergo-core/src/main/scala/org/ergoplatform/mining/AutolykosPowScheme.scala`
  (calcN, M, hitForVersion2ForMessage, genIndexes, genElement, getB), `mining/mining.scala` (hash = Blake2b256,
  toBigInt, q), `mining/difficulty/DifficultySerializer.scala` (nBits), `mining/AutolykosSolution.scala` (v2 solution
  = pk || nonce), `modifiers/history/header/HeaderSerializer.scala`.
  https://github.com/ergoplatform/ergo/tree/master/ergo-core/src/main/scala/org/ergoplatform
- Tests: `ergo-core/src/test/scala/org/ergoplatform/mining/AutolykosPowSchemeSpec.scala`.
- Mainnet blocks: https://api.ergoplatform.com/api/v1/blocks/{id} (ids below), explorer.ergoplatform.com.
- Reference GPU miner, read for design only: https://github.com/mhssamadani/Autolykos2_NV_Miner
  (`secp256k1/src/prehash.cu`, `mining.cu`). It also stores elements as little-endian 256-bit numbers.
- Pool side: MiningCore's Ergo code (https://github.com/oliverw/miningcore, `src/Miningcore/Blockchain/Ergo/
  ErgoPool.cs`, `ErgoJob.cs`, `ErgoJobManager.cs`): share check identical to the node's, and the stratum job layout.
  The ErgoStratumServer (https://github.com/mhssamadani/ErgoStratumServer, `lib/stratum.js`, `lib/jobManager.js`,
  `lib/blockTemplate.js`) and its client, https://github.com/mhssamadani/ErgoStratumProxy (`client.js`, built on
  https://github.com/arnabk/stratum-client `src/messageContants.js`).
- Kryptex: https://pool.kryptex.com/erg and its API https://pool.kryptex.com/erg/api/v1/pool/info. BLAKE2b: RFC 7693.

## Vectors used (all pass; `knownAnswerTests`)

| Vector | Source | What is checked |
|---|---|---|
| BLAKE2b-512("abc") | RFC 7693 App. A | the BLAKE2b core |
| calcN at 500,000 / 600,000 / 614,400 / 665,600 / 700,000 / 788,400 / 1,051,200 / 4,198,400 / 41,984,000 | AutolykosPowSchemeSpec "calcN test vectors" | N schedule, incl. the cap |
| Header at height 614,400, nonce 0x3105 | AutolykosPowSchemeSpec "first increase in N" | header id and msg `548c3e60…`, N 70,464,240, b (decimal), **hit `0002fcb113fe65e5754959872dfdbffea0489bf830beb4961ddc0e9e66a1412a` exactly**, hit < b |
| Header at height 2,870 (pool-submitted, invalid) | AutolykosPowSchemeSpec "invalid solution" | id, hit ≥ b (rejected); weak on its own |
| Mainnet 417,792 (`0ba60a7d…`, v2, N 2^26) | explorer API | header id, hit < b |
| Mainnet 1,000,000 (`f0408596…`, v3, N 99,149,820) | explorer API | header id, hit < b |
| Mainnet 1,920,429 (`838731fc…`, v4, N 238,614,390) | explorer API | header id, hit < b; and on the GPU, below |

The mainnet blocks have no published hit values. Their ids pin the header serialization, and hit < b at
their difficulty (≤ 2^-46 by chance) checks the PoW end to end at three table sizes.

GPU checks (`crossCheck`, every `test`/`bench`): 64 table elements (first, last, random) equal the CPU's;
for consecutive random nonces the GPU's i, seed hash and hit equal the CPU's (32 in `test`, 8 in `bench`);
the search kernel with the target set to (smallest hit + 1) reports exactly that nonce, and with target =
smallest hit reports nothing (strict <); at the reference height, the search kernel, given block
1,920,429's msg and its own target, finds nonce `529b1187a563afbe` among 4,096 nonces and nothing else.

## Memory

- Table: N × 32 bytes = **7.11 GiB** (7,635,660,480 bytes) today, one shared buffer; 7.47 GiB after the
  next step. It passes the 38.88 GiB single-buffer limit at height 3,686,400 (~2033) and would need 63.9 GiB
  at the cap, more than this Mac's 51.84 GiB GPU working set. Storing 31 bytes per element would save 3%
  but misalign every read.
- Everything else is a few KiB. Double-buffering the next height's table (idea 1 below) would need 14.2 GiB.

## Kernel design (`Kernels/autolykos2.metal`)

- **Table layout.** Element j is stored as 8 little-endian `uint` limbs of the 248-bit number (limb 7 < 2^24),
  as two `uint4`. Summing needs no byte swaps. The seed hash needs the element's big-endian bytes,
  rebuilt with 4 `bswap64`s and an 8-bit shift per word.
- **`autolykos2_table`**: one element per thread, 65 compressions. Message words are generated in registers:
  M[k] as a little-endian word is `bswap32(k) << 32`, so the low halves are zero and those carries fold away.
  Dispatched in chunks sized to ~0.25 s per command buffer.
- **`autolykos2_search`**: one nonce per thread. Steps:
  1. Hash 1 (40 bytes, one block).
  2. `i` by Barrett reduction (`mulhi` with floor((2^64-1)/N), one correction).
  3. Load element i and form the 71-byte seed block. Message bytes 1..24 sit one byte off the word grid, so the host
     precomputes those three words per job.
  4. Cut 32 windows and reduce each with a 32-bit Barrett (floor((2^32-1)/N)).
  5. Make 32 element loads (2 × `uint4`) into eight `ulong` limb accumulators, with carries propagated once at the end.
  6. Hash the 32-byte big-endian sum and compare 8 words, most significant first, against the target buffer.
     Hits go to `SearchOutput`. Every nonce does the full work, and the target is runtime data.
- **`autolykos2_hash`**: the same per nonce, writing i, the seed hash and the hit for the cross-check.
- **BLAKE2b arithmetic** (`--set blake`): `u32` (default) keeps each 64-bit word as `uint2` with explicit carries
  (`lo < a.x`), rotation by 32 as a swizzle and 24/16/63 as 32-bit shift pairs. `mix` does the adds on `ulong`.
  `u64` leaves all of it to the compiler.
- **`*_coop` variants** (`--set kernel=coop`): 8 lanes gather each element (lane t loads limb t, so each load
  instruction reads 4 whole elements), sum one limb for 8 nonces, and transpose through threadgroup memory
  (the Ethash port's trick). They need whole SIMD groups, so the host pads dispatches to multiples of 32.
  They pass the same checks but measured no faster, so `simple` is the default.
- **Pool jobs** (`Autolykos2.setJob(msg:height:target:)`, `searchJob(start:count:)`): the same search kernel with the
  job's AL2Params and share target in their own buffers (the benchmark's stay untouched). A job at another height
  rebuilds the table in place, reallocating it only when N changes (the old table is released first).

## Pool protocol (Kryptex ERG: `Autolykos2Pool.swift`)

Dialect: the Ergo Stratum of MiningCore (`ErgoPool.cs`, `ErgoJob.cs`, `ErgoJobManager.cs`) and the ErgoStratumServer,
newline-delimited JSON-RPC over TLS (`:8021`, the default) or TCP (`:7021`). The client side matches the
ErgoStratumProxy.

| Step | Message | Fields |
|---|---|---|
| 1 | `> mining.subscribe ["metalminer/1.0"]` | `< [subscriptions, extranonce1, extranonce2 size]`; extranonce1 + extranonce2 = the 8-byte nonce. **Live 2026-11-20** (`handshake erg`): `{"error":null,"id":1,"result":[null,"8304",6]}`: no subscriptions, a 2-byte extranonce1, 6 bytes to search, nothing else sent before a login. |
| 2 | `> mining.authorize [login, "x"]` | `< true`. An error or false throws `PoolLoginRefused` with the pool's words. The login is "username/worker" or "wallet/worker". |
| 3 | `< mining.set_difficulty [d]` | MiningCore always sends 1 (the target is in the job); used only for a job without b. Takes effect with the next job. |
| 4 | `< mining.notify [job, height, msg, "", "", version, b, ntime, clean]` | height a number; msg 64 hex digits (the message bytes as written); **b = the share target, a decimal integer** (MiningCore: Diff1 / difficulty; also read: 0x-hex, a JSON number); ntime empty for Ergo; clean = a new block. |
| 5 | `> mining.submit [login, job, extranonce2, ntime, nonce]` | nonce: 16 hex digits, the 8 nonce bytes big-endian (extranonce1 then extranonce2); extranonce2: its last 8 − len(extranonce1) bytes; ntime: the job's, or the current Unix time as 8 hex digits when empty (MiningCore requires a non-empty ntime and uses it only to spot duplicates). `< true`, or an error `[code, message, null]`. |
| also | `mining.set_extranonce [extranonce1, size]` (from the next job); `client.reconnect [host, port, wait]` (handled in place, keeping the table); `client.show_message`; `client.get_version`. |

- **Targets and work.** A share's hit (big-endian) is below b. A job without b takes it from the difficulty: d ≥ 65,536
  is read as hashes per share (b = q / d, as Kryptex's API states 4,294,967,296 with `hashes_per_diff` 1), smaller d in
  Bitcoin units (b = 0xFFFF × 2^208 / d, MiningCore's Diff1). `work` = expected hashes per share = 2^256 / b
  (≈ 2^32 at Kryptex's difficulty). Each target change is logged with its hashes per share.
- **Mining.** The first job builds the table at its height; a new height rebuilds it (about 13 GPU-s at mainnet N); a
  new message at the same height only reloads AL2Params. The start nonce is extranonce1 in the top bytes plus a
  counter that restarts at each new message; batches of 2^22 nonces (~70 ms). With a 6-byte extranonce2 the space
  never runs out; a smaller one is searched to the end, then the miner waits for the next job. Every GPU hit is
  recomputed with the CPU reference before it is sent; shares found on a job that a clean job replaced are dropped.
  Share replies arrive asynchronously (`events.share`); the rate goes to `events.hashrate` every 5 s (wall time, so
  per-block rebuilds count against it).
- **Offline round trip** (`metalminer pooltest erg`, about 2 s; `Autolykos2PoolTest.swift`): a MockPool in this dialect,
  jobs from mainnet blocks 1,920,429, 1,000,000 and 417,792 (their msg and height, quick table N = 1,234,567), easy
  targets. Checked: an unknown login is refused as `PoolLoginRefused`; shares at b = 2^237 are found on the GPU and
  each recomputed by the mock with the CPU reference; job 1 re-sent with b 64 times smaller (MiningCore's vardiff
  path) yields shares below the new b; a clean job at another height rebuilds the table; a found nonce with its low
  bit flipped is refused ("low difficulty share") and reported as rejected; `client.reconnect` leads to a new login
  and a share on job 3; every nonce is extranonce1 + extranonce2.
- **Only a live login can confirm:** that Kryptex's notify carries b and that b is the share target (expected:
  2^32 hashes per share, which matches MiningCore's Diff1 at difficulty 1); the set_difficulty value it sends;
  whether it accepts the ntime we send; the share reply format; and that accepted shares are worth 2^32 hashes.
  The miner's log shows b and hashes per share at the first job.

**Live on Kryptex (2026-11-23):** subscribe returned extranonce1 `2006` with 6 bytes to search; a Kryptex account
login (`email/worker`) was accepted; b set 2^32 hashes per share, and the accepted share confirms b as the share
target and the ntime sent. The 7.11 GiB table took 11-14 GPU seconds per block (about 11% of mining time); the
first share was accepted after about 3 minutes.

## Measured (M3 Max 40-core GPU, 2026-11-19; GPU shared with other ports, thermal "fair"; rough)

- **Mining: 60.6 MH/s** at N = 238,614,390 (10 s bench, `--no-save`, simple kernel, u32). The first version
  (u64) measured 59.7 MH/s; a run that overlapped another port's test got 52.6 MH/s.
- **Table rebuild: 9.76 GPU-s per block** at 1.59 G compressions/s, 8.1% of a 121 s block. The u64 build took
  11.8 s (1.32 G/s). If mining pauses for the rebuild, as miners do, the average is about
  **55.7 MH/s**. `bench` reports the raw rate; the rebuild cost is in `setupSummary`.
- Rate against table size (same kernel): 38 MiB (fits in the system cache) 285 MH/s, 128 MiB 175, 512 MiB 114,
  2 GiB 66–68, 7.11 GiB 60. Even at 512 MiB, accesses run at 3.8 G/s, about twice today's ~2.0 G/s. So DRAM
  bandwidth isn't what stops mainnet. The steep drop between 512 MiB and 2 GiB points to GPU TLB reach /
  page walks. That is an inference from this sweep, not a counter measurement.
- No change (within noise) from:
  - the cooperative gather (67.2–67.7 vs 68.3 MH/s at 2 GiB)
  - private vs shared table storage (67.4 vs 67.6, two runs each)
  - threadgroup size 64/128/256 (63.7/65.9/66.3)
  - u32 vs u64 BLAKE2b in the search (68.3 vs 66.3)
- **What 64-bit emulation costs.**
  - Op count: a BLAKE2b compression is 1,344 64-bit operations (96 G-steps × 6 adds, 4 xors, 4 rotations).
    With no carry flag and no 64-bit ALU, each add is about 4 32-bit instructions, a rotation by 24/16/63 about 4–6,
    a rotation by 32 free. That is an estimated ~4.5 K instructions per compression, about 3.4× the native op count.
  - Measured: at 1.59 G compressions/s that estimate puts the table build near the GPU's ~7 T 32-bit ops/s, so
    the build is ALU-bound and the emulation is its whole cost. The compiler's own `ulong` lowering is 16–18%
    slower than the hand-written `uint2` version (mix: 1.39–1.40 G/s, in between).
  - Effect on mining: at mainnet N mining is memory-bound; the same kernel runs 4.7× faster on a cache-sized
    table. So the 3 compressions per nonce don't limit it, and emulation costs mining nothing beyond the
    per-block rebuild.

## Open questions

- **Kryptex's ERG stratum after login** (see "Pool protocol"): the subscribe reply is confirmed live; the notify's
  b, the difficulty, the ntime and the share replies are not.
- The TLB explanation above is unconfirmed. Metal exposes no page-size control that I found.
- Block versions ≥ 5 may append header fields; this only matters if headers are built locally (solo
  against a node), not for pool mining.
- This MacBook Pro throttles under sustained load. All rates come from 10 s runs on a shared GPU.
- The engine creates a new pool miner after a dropped connection, so the 7.1 GiB table is rebuilt then; a
  `client.reconnect` from the pool keeps it.

## Speed-up ideas

1. **Hide the table rebuild.** The table for height H+1 depends only on the height, so it can be built on a
   second command queue while mining H. The search leaves ALUs idle, and the build is ALU-bound. Needs
   2 × 7.1 GiB. Could recover most of the 8%.
2. **Bigger GPU pages / better TLB reach**, if any allocation path (heaps, sparse buffers) provides them. The size
   sweep suggests up to ~1.7× (the 512 MiB rate) if the table could behave like a TLB-resident one.
3. Faster BLAKE2b for the build (byte-permute idioms for the 16/24-bit rotations, fewer carry instructions).
   The build is ALU-bound, so every instruction counts there.
4. Per-job precomputation of the round-0 G steps that only touch job constants (3 of 8 column steps in
   hash 1, 1 in the seed hash). This is irrelevant while memory-bound; it only helps on smaller tables.
