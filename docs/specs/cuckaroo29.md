# Cuckaroo29 (Tari C29, XTM)

Tari's GPU proof of work, listed by Kryptex as "C29" (pool `xtm-c29`), is **Cuckaroo29**: the Cuckaroo variant
Grin launched with in January 2019 (siphash rotation 21, blocks of 64 chained hashes xored with the block's last
value), not Grin's later Cuckarood/Cuckaroom/Cuckarooz. Tari adds its own key derivation, proof encoding, proof hash
and difficulty. Tari's other XTM pools (SHA3X for ASICs, RandomX for CPUs) are different algorithms.

- Folder `Sources/Algorithms/Cuckaroo29/`, id `cuckaroo29`, coins `["XTM"]`, unit `G/s` (graphs per second).
- Kernels: `Kernels/cuckaroo29.metal`.
- Pool miner: `Cuckaroo29PoolMiner` for Kryptex `xtm-c29` (`Cuckaroo29Pool.swift`, self-test in
  `Cuckaroo29PoolTest.swift`); see "Pool protocol" below.

## Mainnet construction

From tari-project/tari, development branch, November 2026 (`base_layer/core/src/proof_of_work/cuckaroo_pow.rs`,
`siphash.rs`):

1. **Mining hash** (32 bytes): `BlockHeader::mining_hash()`, a domain-separated Blake2b-256 ("block_header") over
   version, height, prev_hash, timestamp, the Merkle roots and sizes, the kernel and script offsets and the validator
   node root and size: everything except `nonce` and `pow`. A pool sends it with each job.
2. **Siphash keys**: `blake2b-256(nonce as 8 big-endian bytes || mining hash)` (`determine_sip_hash`), read as four
   little-endian u64 words k0..k3. The nonce is the header's u64 nonce; one nonce is one graph.
3. **Edges**: for edge index n < 2^29, take n's block of 64 indices (`n & ~63`). Start a siphash-2-4 state at
   v0..v3 = k0..k3 (Cuckoo style: no initialisation constants). For i = 0 ... 63, hash the index *without resetting
   the state* (`v3 ^= m; 2 rounds; v0 ^= m; v2 ^= 0xff; 4 rounds; h_i = v0 ^ v1 ^ v2 ^ v3`; rotations 13, 16, 32, 17,
   **21**, 32). Then xor every h_i except h_63 with h_63. Edge n joins U node `h & (2^29 - 1)` and V node
   `(h >> 32) & (2^29 - 1)`; the U and V node sets are separate (bipartite graph, 2^29 nodes each).
4. **Proof**: 42 strictly ascending edge indices, each < 2^29, whose edges form one 42-cycle. From height 350,000 Tari
   verifies with the bipartite reference verifier (Grin's `verify`: xor of all U endpoints and xor of all V endpoints
   must each be 0, then a walk that alternates U and V). Below that height it used a "legacy" verifier that merged the
   U and V namespaces (advisory GHSA-3qmx-q9pv-f3m4). A genuine cycle passes both, except in the roughly 441/2^29 case
   where a U value equals a V value, which only the legacy verifier rejects.
5. **pow_data**: the 42 indices bit-packed 29 bits each, least significant bit first: exactly 153 bytes, with the unused
   top 6 bits of the last byte zero (anything else is non-canonical and rejected). The header's pow bytes are
   `[3] || pow_data` (3 = Cuckaroo).
6. **Proof hash**: `blake2b-256(pow_data)`. **Difficulty**: `min(2^64 - 1, floor((2^256 - 1) / H))` with H the hash
   read big-endian (`Difficulty::big_endian_difficulty`). A block (or share) is valid when this reaches the target
   difficulty. The miner computes it on the CPU for each found cycle and compares it with `targetDifficulty`. The
   benchmark target is 2^64 - 1, which can't be reached.

**Parameters** (`consensus_constants.rs`): edge bits 29 and cycle length 42 on every network. On mainnet C29 started
at height 95,000 (block version 2: four algorithms, each with a 480 s target, so 2-minute blocks), with minimum
difficulty 1. Its difficulty has counted toward the chain total from 126,000, and the bipartite verifier applies from
350,000. The graph doesn't change with height (there's no DAG or epoch), so there is no `height` option. The explorer
showed height 391,140 on 2026-11-19. `overheadFraction` stays 0: nothing is rebuilt per block.

## Hashrate unit

C29 hashrate is quoted in **graphs per second**, which is what `runBatch` counts.

- Tari's node estimates it as `difficulty × 42 / 480 s` (`applications/minotari_node/src/grpc/hash_rate.rs`: "Cuckaroo
  is special as we need to multiply by the cycle length"). A random Cuckaroo29 graph holds on average about 1/42 of a
  42-cycle, so difficulty × 42 is the expected number of graphs per block. explore.tari.com shows it in "g": 13.10 Kg/s
  on 2026-11-19, which puts the C29 difficulty near 150,000.
- Kryptex shows the pool as 10.97 KH/s with 552 workers (about 20 per worker, a GPU-sized graph rate). It found 15 C29
  blocks in 2 h 14 min against about 17 expected for the whole network, consistent with 10.97 K of a 13.1 K network.
  So Kryptex's "H/s" for XTM-C29 is graphs/s on the same scale as Tari's: **1 G/s here = 1 H/s on Kryptex = 1 g/s on
  the explorer.** Kryptex's static share difficulty is 20, so one share takes about 20 × 42 = 840 graphs.
- This solver's yield: 165 verified 42-cycles in 7,115 random graphs (quick mode), 0.97 × the 1/42 expected. Graphs/s
  therefore converts to solutions at the rate the network assumes.

## Sources

- https://github.com/tari-project/tari/blob/development/base_layer/core/src/proof_of_work/cuckaroo_pow.rs
- https://github.com/tari-project/tari/blob/development/base_layer/core/src/proof_of_work/siphash.rs
- https://github.com/tari-project/tari/blob/development/base_layer/transaction_components/src/tari_proof_of_work/difficulty.rs
- https://github.com/tari-project/tari/blob/development/base_layer/transaction_components/src/consensus/consensus_constants.rs
- https://github.com/tari-project/tari/blob/development/base_layer/node_components/src/blocks/block_header.rs (mining_hash)
- https://github.com/tari-project/tari/blob/development/applications/minotari_node/src/grpc/hash_rate.rs
- https://github.com/mimblewimble/grin/blob/master/core/src/pow/cuckaroo.rs (cuckaroo19 vectors, reference verifier)
- https://explore.tari.com/ (and its JSON at textexplore.tari.com/?json), https://pool.kryptex.com/xtm-c29 and /blocks
- Pool protocol sources: listed in "Pool protocol" below.

## Vectors (`Cuckaroo29Vectors.swift`, all pass in `knownAnswerTests`)

- Tari siphash.rs: siphash24 (4 values) and siphash_block (3 values).
- Tari key derivation: `test_header_hash` and `test_edge_generation_example3`. Proof 1's keys (mining hash 4dbfee…,
  nonce 9d589ed597ed42d0) also equal the a216826b… keys of example 2, which ties the two vectors together.
- Two real 42-cycle C29 proofs (Tari's tests describe them as taken from real blocks): every edge of
  `test_edge_generation_example2` and `example4` (84 edges) matches, and both verify.
- `test_solution`: the 153-byte pow_data unpacks to proof 1's nonces, repacks byte for byte (canonical), rejects
  non-zero padding, and hashes to `06d52b90ccfd4db1…` (difficulty 37). Tari's 3-bit and 29-bit packing vectors also
  pass.
- Grin cuckaroo19 V1_19 and V2_19 (keys and 42-cycles) verify; swapped and all-zero proofs are rejected.
- Tari's 20-bit merged-namespace forgery (xor0 == xor1 != 0) is rejected by the bipartite verifier with "endpoints
  don't match".
- Difficulty edge cases (all-ones hash → 1, 2^192 → capped, 2^193 → 2^63 - 1).

## GPU checks (`crossCheck`, all pass)

1. The full GPU solver (seed, trim, CPU cycle finding, GPU nonce recovery, CPU verification, proof hash) finds the
   published cycles: Tari mainnet proofs 1 and 2 at 29 bits (proof 1's hash matches `06d52b90…`), and Grin
   cuckaroo19 V1 and V2 in quick mode.
2. Stepwise on random keys (2 graphs in `test`, 1 in `bench`): seeding is compared bucket by bucket with the CPU's own
   generation of all 2^29 edges, as count plus a sum of a bijective 64-bit mix of each edge, so the edge multiset must
   match. Then every one of the 192 rounds is run on its own (24 bit-map and 168 hash-table rounds), and the CPU
   applies the trimming rule to that round's GPU input and compares each output bucket's count and fingerprint. By
   induction every round is exact.
3. Quick mode also trims the whole graph independently on the CPU (degree arrays over all nodes) and compares the
   surviving edges exactly.
4. Any 42-cycle the solver reports must pass the CPU verifier, or the run fails.

## Memory

At 29 bits there are two edge buffers of `uint2` (u32 node on the bucketed side, u32 other node), 4096 buckets each:
A holds 134,720 edges per bucket (2^17 + 10σ, 4.11 GiB) and B holds 85,760 (63.2 % of that + 10σ, 2.62 GiB), for
**6.73 GiB** in total plus about 100 KiB of counters. A lean solver (bit maps only, about 200 MB) is possible, but on
Cuckaroo every round would regenerate all 2^29 siphashes in blocks of 64, around 30 ms per pass for dozens of rounds,
so it would be several times slower. Not implemented.

## Solver design

Per graph (`trim` then `solutions`; `solve(miningHash:nonce:)` derives the keys and runs both, for pool jobs and for
`runBatch` alike):

1. **Seed** (`cuckaroo29_seed`): one thread per 64-edge siphash block, with the 64 hashes kept in a per-thread array.
   Each edge is appended to the bucket of its U node's top 12 bits (atomic counter per bucket). 48 ms: 29 ms of
   siphash, the rest scattered 8-byte stores (the atomics alone cost nothing measurable).
2. **Rounds 1-24** (`cuckaroo29_trim`): one threadgroup per bucket. Two 2^17-bit maps ("seen", "seen twice") fill the
   whole 32 KiB of threadgroup memory. Edges whose node in this bucket has another edge survive and are written,
   swapped, to the bucket of their other node, so odd rounds trim U and even rounds trim V. Edges are read twice (count,
   then move). There are 1024 threads per threadgroup to round 8 and 256 after.
3. **Rounds 25-192** (`cuckaroo29_trim_sparse`): the same rule, but with an open-addressing table in threadgroup memory
   sized to the bucket's edge count (at least twice it, at most 4096 entries) in place of the bit maps: about 0.05 ms
   per late round instead of 0.1 ms. If the table ever fills, the bucket keeps all its edges, which is safe.
4. **Cycle finding** on the CPU over the roughly 55,000 surviving edges (`Cuckaroo29CycleFinder`): Tromp's cuckoo-hash
   path following, about 5 ms. Each 42-cycle's nonces are recovered on the GPU (`cuckaroo29_recover` regenerates every
   edge and matches the 42 (u, v) pairs), sorted, verified, packed, hashed and compared with the target.

Each bucket's count is zeroed by the round that consumes it, so no clearing pass is needed. Overflowing buckets drop
edges and are counted (`stats[0]`); the checks fail on any drop. Command buffers stay at or under about 100 ms
(seed + rounds 1-2, rounds 3-18, then 32 rounds each).

Edges left after round k: 63.2 % (1), 29.6 % (2), 17.5 % (3), 4.0 % (8), 1.2 % (16), 0.34 % (32), 0.091 % (64),
then roughly 1/k²: about 225,000 after 96 rounds and about 55,000 after 192.

## Measured rate

- **6.24 G/s** (`bench cuckaroo29 --seconds 10 --no-save`, 2026-11-19, 63 graphs, thermal nominal). Every counted graph
  is complete: seed, all rounds, CPU cycle finding, and recovery, verification and the target comparison for any cycle
  found. No other Metal Miner benchmark was running at the start or end of that run. A later run of the final build,
  while another agent's NexaPow benchmark shared the GPU, gave 4.85 G/s. Rank on a run with the GPU to itself.
- Per graph with the GPU to itself: about 151 ms GPU (seed 48, round 1 35, round 2 22, round 3 9, round 4 6, rounds
  5-36 23, rounds 37-192 9) plus about 5 ms CPU.
- First version, before tuning (8192 buckets, 96 bit-map rounds): about 155 ms GPU + 28 ms CPU per graph, about
  5.4 G/s when not shared (1.22 G/s in a bench while sharing the GPU).
- Tuning kept: 4096 buckets of 2^17 nodes instead of 8192 (fewer write fronts: −8 %), hash-table late rounds, 192
  rounds instead of 96 (CPU 28 → 5 ms).
- Tried and dropped: holding edges in registers (needs ≤ 2^14-node buckets, whose extra write fronts cost more than the
  saved read); recomputing the seed chain instead of holding 64 hashes (58 vs 48 ms); seed threadgroup sizes from 64 to
  1024 (no change).
- 2026-11-20, while the pool miner was written: the same benchmark gave only 1.29 G/s at 4 W of GPU power (thermal
  nominal, AC power, no other metalminer running, macOS's mediaanalysisd at 100 % CPU), and the pool self-test's rate
  reports had a median of 1.24-1.59 G/s. The GPU was contended system-wide; the pool path costs nothing measurable
  over `runBatch` (about 1 s of CPU in a 62 s self-test).

## Options (`--set key=value`)

`rounds` (192; quick 40), `edgebits` (29; quick 19), `zbits` (node bits per bucket, 17; quick 12; at most 17), `seed`
(0 keeps hashes in registers, 1 recomputes), `seedgroup` (256), `group` (1024, rounds 1 ... `early`), `early` (8),
`lategroup` (256, up to round `sparse`), `sparse` (24; later rounds use hash tables), `sparsegroup` (128), `margin`
(bucket spare capacity in standard deviations, 10), `verbose=1` (GPU time per command buffer, edges per round, CPU
times, yield of 42-cycles), `check=0` (skips crossCheck, for timing only). The pool miner always runs the mainnet
defaults.

## Pool protocol (Kryptex `xtm-c29`)

`Cuckaroo29PoolMiner` mines each job through `Cuckaroo29Miner.solve(miningHash:nonce:)`: the same GPU trimmer, CPU
cycle finder and CPU verifier as the benchmark. `metalminer pooltest` runs its self-test, `metalminer handshake` its
live check, `metalminer mine xtm-c29` real mining with the saved payout login.

**Dialect.** Tari C29 pools speak xmrig-style JSON-RPC: one JSON object per line over TCP or TLS, with the methods
`login`, `job`, `submit`, `keepalived` and `getjob`. Three open-source implementations agree on every field, and a
miner log ties the dialect to Kryptex:

- tari-project/TARI.Miner, Tari's own C29 pool miner (LuckyPool and "other deployments"), https://github.com/tari-project/TARI.Miner:
  `tari_c29_pool_miner.cu` (login, job parsing, nonce and extra nonce, submit), `tari_pool_protocol.h` (target to
  difficulty, the two accepted-reply forms), `tari_c29.cpp` (key derivation, packing, difficulty: identical to ours),
  `docs/amd-validation.md` (a stub pool in the same dialect).
- Jagtech-Services/go-tari-c29-solo-stratum, a server "compatible with current C29 miners",
  https://github.com/Jagtech-Services/go-tari-c29-solo-stratum: `subsystems/poolStratum/miner.go` (login, job, the
  submit checks), `subsystems/messages/minerStructs.go` (field names), `subsystems/minerTracking/structs.go` (target =
  (2^64 - 1) / difficulty, little-endian).
- MoneroOcean/nodejs-pool, whose XTM-C coin is Tari C29, https://github.com/MoneroOcean/nodejs-pool: `lib/coins/xtm_c.js`,
  `lib/coins/core/factories.js` (`buildXtmCJobPayload` with `"algo": "cuckaroo"`, `validateXtmCSubmit`,
  `verifyXtmCShare`, `hashesPerDifficulty: 42`), `lib/pool/state.js` (`getTargetHex`), `lib/pool/protocol.js` (methods
  and replies).
- Kryptex: a lolMiner 1.98a log in https://github.com/Lolliedieb/lolMiner-releases/discussions/2153, connected to
  `xtm-c29-ru.kryptex.network:7040`, shows `New Tari job (Algorithm: cuckaroo) with id c5cd0cb25bcf and difficulty 20.00`
  and accepted shares of difficulty 21.96 to 84.69, 8 of them in 241 s at 30.1 g/s (907 graphs per share against 840
  expected). BzMiner's C29 guide (https://www.bzminer.com/guides/c29/) mines Kryptex, LuckyPool and MoneroOcean with the
  same `-a c29` client. Kryptex's guide (https://pool.kryptex.com/articles/how-to-mine-tari-c29-en) gives the login as
  `WALLET_ADDRESS/WORKER_NAME`.
- Tari's minotari_miner (`applications/minotari_miner/src/stratum/`) speaks the same login/job/submit family for SHA3x,
  with other encodings (base64 blob, decimal target). It is not the C29 dialect.

**Servers** (https://pool.kryptex.com/xtm-c29/api/v1/pool/info): `xtm-c29.kryptex.network` and regional
`xtm-c29-eu`, `-us`, `-br`, `-sg`, `-hk`, `-ru` and `-ae`; port 7040 TCP, 8040 TLS. Static share difficulty 20
(`"default": 20, "vardiff": false`). PROP or SOLO (`solo:wallet`), 1 % fee.

**Messages.** Request ids are the miner's; replies are matched by id, whether or not they repeat the method.

| Direction | Message |
|---|---|
| miner → pool | `{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"WALLET_OR_USER/WORKER","pass":"x","agent":"metalminer/0.1"}}` |
| pool → miner | `{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"SESSION","job":JOB,"status":"OK"}}` |
| pool → miner | `{"jsonrpc":"2.0","method":"job","params":JOB}` for a new block, a new template or a new difficulty |
| JOB | `{"algo":"cuckaroo","blob":"<64 hex>","height":391750,"job_id":"c5cd0cb25bcf","target":"cccccccccccccc0c","xn":"9d58"}` |
| miner → pool | `{"id":N,"jsonrpc":"2.0","method":"submit","params":{"id":"SESSION","job_id":"…","nonce":"<16 hex>","pow":[42 numbers],"result":"<64 hex>"}}` |
| pool → miner | accepted: `"result":true` or `"result":{"status":"OK"}`; refused: `"error":{"code":-1,"message":"Low difficulty share"}`, an error string, or `"result":false` |
| miner → pool | `keepalived` with `{"id":"SESSION"}` after 120 s without sending anything (stops for the connection if refused); `getjob` only when the login reply has no job |
| pool → miner | `client.reconnect`, `reconnect` or `mining.reconnect`: reconnect after `wait` seconds (0-60) to the configured endpoint; a host or port in the request is ignored |

**Fields and byte orders**

- `blob`: the 32-byte header mining hash (Tari's `BlockHeader::mining_hash`, the `merge_mining_hash` of a node's
  new-block result), hex, in hash byte order. Any other length is refused.
- Header nonce: a u64. The siphash keys are blake2b-256 of its 8 big-endian bytes followed by the blob (construction
  step 2), and `nonce` is submitted as those same 8 bytes in hex (`9d589ed597ed42d0` for proof 1). `xn`, when sent, is
  the extra nonce: the nonce's leading bytes (0-7 of them; MoneroOcean and the solo stratum reject a nonce without that
  prefix). The miner fills the remaining bytes with a counter that starts at a random point for each job.
- `pow`: the cycle's 42 edge indices, ascending, each below 2^29, as JSON numbers. The pool packs them into the block's
  153-byte pow_data itself. `result` is blake2b-256 of that pow_data, in hex: the solo stratum rejects a mismatch and
  MoneroOcean ignores the field.
- `target`: 8 bytes little-endian, T = floor((2^64 - 1) / D). The miner reads D = floor((2^64 - 1) / T), as TARI.Miner
  does. Eight hex digits would be xmrig's compact form, D = (2^32 - 1) / T, and a numeric `difficulty` field is read
  too. Kryptex's D = 20 is `cccccccccccccc0c`. A job that leaves out `target` or `xn` keeps the previous job's.
- Share rule: the cycle's Tari difficulty, floor((2^256 - 1) / H) with H the `result` hash read big-endian (capped at
  2^64 - 1), must reach D. The miner submits only the best cycle of a graph, and drops it when the pool's latest job is
  already at a higher height.
- Work: a random graph holds 1/42 of a 42-cycle on average and a cycle reaches D with probability 1/D, so a share is
  42 × D graphs of expected work. `events.share` reports that (840 graphs at D = 20). MoneroOcean credits XTM-C shares
  the same way (`hashesPerDifficulty: 42`), and it is the scale of Kryptex's and Tari's hashrates ("Hashrate unit"). At
  6.24 G/s a share comes every 135 s on average, about 640 a day.

**Self-test** (`metalminer pooltest`, PASS, 62 s on 2026-11-20 with the GPU contended as described under "Measured
rate"). First the encoding on the CPU: target and difficulty both ways, the nonce, job fields and carry-over, 4 unusable
jobs refused, 8 reply forms, and proof 1 as a submit, which passes the mock's checks at difficulty 37 and fails at 38 and
when corrupted. Then a `MockPool` round trip in which the mock checks every share with the CPU reference (session, job,
nonce and extra nonce, 42 ascending edges, `result`, the cycle, the difficulty, duplicates):

1. Login, then job a1: proof 1's mining hash `4dbfee3e…`, the top two bytes of its block nonce as `xn`, difficulty 1.
   The counter starts at the block's nonce, so the first GPU graph is that block's: proof 1 found, submitted and
   accepted (difficulty 37).
2. Difficulty change: job a2, the same header at difficulty 1000 (target `efa7c64b37894100`). Proof 1 is found again
   and held back.
3. New job b1 at the next height, with proof 2's mining hash `93e43a39…`. Proof 2 is found on the first graph and sent
   deliberately corrupted (last edge index + 1): the mock refuses it ("endpoints don't match") and the miner reports a
   rejected share.
4. The graphs after proof 2 on b1: 91 graphs later (nonce `ab30dc99fd054fb2`) a graph nobody published holds a 42-cycle,
   accepted at difficulty 1.
5. `client.reconnect`: the miner reconnects, logs in again (job c1, no `xn`) and mines on.
6. In all, 3 submits (2 accepted, 1 refused). The miner's share reports match the mock's verdicts, each worth 42 graphs,
   and nothing went out for a2.

**Handshake** (`metalminer handshake`, 2026-11-20): TLS to `xtm-c29.kryptex.network:8040` connects with its
certificate accepted. A `getjob` sent without a login got no answer within 10 s, and the connection stayed open until
the miner closed it, so Kryptex seems to ignore requests before a login (MoneroOcean answers "Unauthenticated" and
closes; the solo stratum sends a job). The handshake confirms the endpoint and TLS, not the dialect.

**Only a live test can confirm**

1. The login reply's shape, the session id, and whether the first job comes in it or as a separate `job`.
2. Whether Kryptex sends `xn`, and how many bytes.
3. The target encoding: 16 hex digits decoding to 20 is expected (lolMiner shows difficulty 20.00); a numeric
   `difficulty` field would also work.
4. That Kryptex takes this submit (`id`, `job_id`, `nonce`, `pow`, `result`) and answers `true` or `{"status":"OK"}`.
5. That Kryptex scores shares by Tari's big-endian difficulty. MoneroOcean's generic `hashBuffDiff` reads hashes
   little-endian, with its own `c29_cycle_hash`; a different rule at Kryptex would show as good shares refused for low
   difficulty.
6. Whether `keepalived` is understood (sent only after 120 s without sending anything; it stops after one refusal).
7. Whether shares for the previous job at the same height are still accepted once a new job has arrived.
8. What a reconnect request looks like, if Kryptex sends one.
9. That Kryptex's dashboard shows about the rate the miner reports, which would confirm work = 42 × D.

**Live on Kryptex (2026-11-23):** 15 minutes with a Kryptex account login (`email/worker`, SSL port 8040): the
pool's static difficulty 20, 20 jobs followed, `keepalived` answered, 7 shares accepted and none rejected at
5.9 graphs/s.

## Open questions and speed-up ideas

- Whether deployed mainnet nodes already run the bipartite verifier. The 350,000 activation is in the development
  branch, and mainnet is past it. Mining is unaffected: genuine cycles satisfy both verifiers.
- The seed and the first two rounds are about 70 % of the time, bound by scattered 8-byte stores and the second read of
  each bucket. Ideas: stage writes in threadgroup memory (needs a smaller per-bucket footprint); compress edges to 32
  bits after the first rounds (node renaming, or dropping the bits the bucket implies), which would halve traffic; keep
  part of each bucket on-chip between the count and move passes.
- Overlapping CPU cycle finding with the next graph's GPU work would hide about 5 ms (3 %). That needs multi-graph
  batches, which the harness's 150 ms batch sizing won't give for 150 ms graphs, or a persistent pipeline. The pool
  miner could do it on its own (it runs graphs back to back), at the cost of a second set of edge buffers.
- SipHash on 64-bit lanes is emulated with 32-bit operations (29 ms per graph); a hand-split 32-bit version might help
  once the stores are no longer the limit.
- The path-following cycle finder can miss a 42-cycle that only exists as a combination of overlapping cycles; the
  measured yield (0.97 of 1/42) suggests this is rare.
- 6.7 GiB is large next to the other ports. It could fall to about 4 GiB if seeding made two passes (count U degrees in
  a 128 MB map, then store only round 1's survivors), at the cost of a second siphash pass.
