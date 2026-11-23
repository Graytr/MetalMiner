# PearlHash (Pearl, PRL)

Pearl is a 2026 L1 (a btcd fork) whose proof of work is a by-product of matrix multiplication
("proof of useful work", after Komargodski, Schen and Weinstein, *Proofs of Useful Work from Arbitrary
Matrix Multiplication*). Kryptex calls the algorithm PearlHash. There is no header nonce: a miner commits
to two int7 matrices A (m × k) and B (k × n), low-rank noise derived from those commitments and the job is
added to both, and every small tile of the noisy product A'B' is one lottery ticket. Real miners
(Pearl's vLLM miner) use LLM activations and weights as A and B; a pure miner can use any matrices.
Winning blocks carry a Plonky2/STARK proof of the winning tile, made once per block, not per attempt, and
by the pool (or a solo miner's gateway), never by a pool miner: see "Pool protocol".

It can be benchmarked offline: everything per attempt depends only on the job header, the miner's own
matrices and public rules. The port does the full per-attempt work on the GPU.

Port: `Sources/Algorithms/PearlHash/` (CPU reference, host code), `Kernels/pearlhash.metal` (kernels),
`Kernels/pearlhash_lab.metal` (development micro-benchmarks, not used for mining). Id `pearlhash`, coin PRL.
Pool mining: `PearlHashPool.swift` (the `prl` pool miner, its test pool), `PearlHashPlainProof.swift` (the
share format, Merkle openings, the pool's share check on the CPU reference).

## Mainnet construction

All hashing is standard BLAKE3 (the `blake3` crate), plain or keyed, 32-byte output.

1. **Job header** (`IncompleteBlockHeader`, 76 bytes): `version` u32 LE · `prev_block` 32 bytes · `merkle_root`
   32 bytes · `timestamp` u32 LE · `bits` u32 LE. Hashes are in wire (internal) order, the reverse of how
   explorers print them. This is the 108-byte wire header (`node/wire/blockheader.go`) without its trailing
   32-byte `ProofCommitment`, which commits to the certificate after mining. The block id is SHA-256d of
   the 108 bytes; it is not part of the proof of work.
2. **Mining configuration** (52 bytes, chosen by the miner): `common_dim` k u32 LE · `rank` u16 LE ·
   `mma_type` u16 (0 = Int7xInt7ToInt32) · `rows_pattern` 6 bytes · `cols_pattern` 6 bytes · 32 bytes trailer
   (MoE `e`, `top_k`, zeros; all zero for a dense job). A pattern is a list of offsets stored as up to
   3 (stride, length) dimensions, each byte pair = (stride / previous period − 1, length − 1).
3. **Job key** = BLAKE3(header ‖ config), 128 bytes.
4. **Commitments**: `hash_a` = BLAKE3(A row-major as int8 bytes, zero-padded to whole 1,024-byte chunks,
   key = job key); `hash_b` likewise for Bᵀ (B column-major). These equal the roots of pearl-blake3's
   Merkle tree, which is BLAKE3's own chunk tree.
5. **Noise seeds** (V3 "salted" certificates, required from height 99,000):
   `hash_a' = BLAKE3(hash_a ‖ m u32 LE ‖ 28 zero bytes, key = BLAKE3("pearl/cert-v3/noise-seed/A"))`,
   `hash_b'` the same with n and ".../B"; `b_seed = BLAKE3(job_key ‖ hash_b')`,
   `a_seed = BLAKE3(b_seed ‖ hash_a')`. (Legacy V2 used the raw roots.)
6. **Noise** (rank r): message = 8 little-endian i32 slots ‖ 32-byte label ("A_tensor" / "B_tensor",
   zero-padded); keyed by the seed. `E_AL` (m × r): byte j of draw i (slot 0 = i + 1) gives entry 32i + j
   (row-major) = (byte & 63) − 32. `E_AR` (k positions): word j of draw i (slot 1 = i + 1) gives position
   8i + j: +1 at `w & (r−1)`, −1 at that `^ (1 + mulhi(r−1, w))`. B uses `b_seed`, the B label, `E_BL`
   (positions) and `E_BRᵀ` (n × r). So `A'[i][l] = A[i][l] + E_AL[i][plus(l)] − E_AL[i][minus(l)]` and the
   same for columns of B; entries stay within int8.
7. **Attempts**: for every valid offset pair (t_rows, t_cols) of the patterns, the tile is rows
   `rows_pattern + t_rows` × columns `cols_pattern + t_cols`. Run the dot products over k in blocks of r:
   after each block b, XOR the tile's int32 running sums (two's complement) into x and set
   `jackpot[b mod 16] = rotl32(jackpot[b mod 16], 13) ^ x` (16 words, all zero at start).
8. **Final hash** = BLAKE3(jackpot as 64 bytes, 16 words LE, key = a_seed), read as a **little-endian**
   256-bit integer.
9. **Target**: `target` = compact `bits` (mantissa · 256^(exponent−3)); the attempt wins if
   hash ≤ target × W, with W = tile size × (k − k mod r) (`extract_difficulty_bound`), and, from height
   96,251 (rank-penalty rule), also ≤ target × tile size × ((k − k mod r)/r) × 128 with r ≥ 128. At r = 128
   the two bounds are equal. Pool shares use the same bound with the share target.

**Hash unit.** W is "the work one attempt costs", so each attempt counts as W hashes and the expected
work per block is 2^256 / target: one PearlHash "hash" is one int7 × int7 → int32 multiply-accumulate of
the noisy product. Checks: block 145,681 has bits 0x1743ee30, i.e. difficulty
0xffff·2^192 / target = 63,225,014 (matches the explorer), so a block takes 63,225,014 × 2^64/65,535 ≈
1.78 × 10^22 hashes; at ~173 s per block that is ≈103 EH/s, which matches prlscan's 200-block estimate
(101.7 EH/s). Kryptex's 117 EH/s implies a ~152 s average over its window. Kryptex's own share calculator
(d = 7,264,316 → one share per 60 s at 520 TH/s) means a share of difficulty d is d × 2^32 hashes, the same
convention. Its figure of 220 TH/s for an RTX 5090 is roughly half that card's dense INT8
multiply-accumulate rate, which fits. Our rate (attempts/s × W) is therefore in the units Kryptex and the
network use.

**Nonce.** Pearl has no nonce field; a miner's search space is its choice of A and B plus the tile offset.
Here A is random and fixed per job, and B's column 0 starts with 32 entries that carry a 64-bit instance
nonce, 2 bits each as values −2…1 (all other entries random in −64…63). Changing those entries changes only
B's first BLAKE3 chunk, so the CPU rehashes B's commitment with one chunk plus one parent per tree level
(~30 compressions) and computes the seeds; the GPU does everything else. One instance = m/4 × n/8
attempts of W = 32 · k hashes each. Hits report (instance nonce, t_rows, t_cols), enough for a pool client
to rebuild the winning rows and columns and their Merkle proofs.

## Parameters used (2026-11-19)

- Job: mainnet block 145,681 (explorer.pearlresearch.ai, 21:02 UTC): version 0x20000000, prev
  `c229cf7a…7d05`, merkle `a311aef2…82d0`, time 1,795,122,127, bits 0x1743ee30 (difficulty 63,225,014).
  The benchmark target is the unreachable bound 0, so the job only matters as real data.
- Consensus (node/chaincfg/params.go): target block time 194 s, PowLimitBits 0x1b00ffff; MoE fork (V2) 71,935,
  dense-only 91,630, rank penalty 96,251, salted seeds (V3) 99,000. All active at today's height; nothing in
  the algorithm changes with height otherwise.
- Mining configuration: Pearl's own default (`build_default_config`): rank 128 (the penalty floor),
  k = 2,048, rows [0, 8, 64, 72], columns [0, 1, 8, 9, 32, 33, 40, 41] (4 × 8 tile, W = 65,536).
  m = n = 4,096 (one instance = 524,288 attempts = 34.36 GH). `--quick`: m = n = 512.
  Options: `--set m=`, `n=`, `k=` (multiple of 128, 2,048 to 65,536).

## Sources

- https://github.com/pearl-research-labs/pearl (master, 2026-11-19; release v1.5.7), linked from
  pool.kryptex.com/prl/about-coin: `zk-pow/src/ffi/mine.rs` (`try_mine_one`), `zk-pow/src/api/proof.rs`,
  `proof_utils.rs` (serialization, `nbits_to_difficulty`, `compute_jackpot_hash`), `seed.rs`,
  `sanity_checks.rs` (bounds, rank penalty, parameter limits), `zk-pow/src/circuit/pearl_noise.rs`,
  `pearl_program.rs` (JACKPOT_SIZE 16, LROT_PER_TILE 13), `zk-pow/bindings/go/src/mine.rs` (default config),
  `pearl-blake3/src/hasher.rs`, `merkle.rs`, `node/wire/blockheader.go`, `node/chaincfg/params.go`,
  `node/zkpow/verify.go`, `miner/miner-base/src/miner_base/settings.py` (the vLLM miner's tile).
- Pool side (2026-11-20): Pearl master `zk-pow/bindings/go/src/plain.rs` (the pool FFI), `zk-pow/src/api/verify.rs`
  (`verify_plain_proof`), `zk-pow/src/ffi/plain_proof.rs` (`PlainProof`), `pearl-blake3/src/merkle.rs`
  (multi-leaf proofs), `miner/pearl-gateway/README.md`; https://pool.kryptex.com/prl/api/v1/pool/info and
  pool.kryptex.com/prl; Suprnova's spec https://prl.suprnova.cc/stratum-spec.html; Kryptex captures in
  github.com/Breakwater-ecosystem/pearl-metal-miner (`pearl_metal_miner/stratum/kryptex.py`,
  `docs/research/2026-08-10-pool-survey.md`), github.com/arabel1a/ascend_prl (`src/pools/kryptex.c`,
  `src/pools/stratum.c`, README) and github.com/lunin02118-ops/apexprl (`crates/apexprl-stratum/src/lib.rs`,
  `docs/05_…Kryptex_Stratum_v2.md`); an independent PlainProof parser in github.com/NINJAK1DD/miningcore
  (`src/Miningcore/Blockchain/Pearl/PearlPlainProof.cs`, fixture `srb-proof.json`); miner.download/en/krig.
- rust-random/rand 0.9.2 (`src/distr/uniform_int.rs`, `rand_core/src/lib.rs` `seed_from_u64`,
  `rand_chacha/src/guts.rs`), to rebuild the fixture's random matrices.
- BLAKE3 test vectors: BLAKE3-team/BLAKE3 `test_vectors/test_vectors.json`.
- explorer.pearlresearch.ai, prlscan.com, pool.kryptex.com/prl.

## Vectors (CPU reference, `PearlHashReference.runVectors`, ~0.1 s)

1. BLAKE3 official `hash` and `keyed_hash` at 13 lengths from 0 to 102,400 bytes, plus the left-path rehash
   used for nonces against a full hash.
2. zk-pow `seed.rs`: the V3 salts equal BLAKE3 of their strings, and the pinned legacy and salted
   `commitment_hash` vectors (job key 0x11…, hash_a 0xAA…, hash_b 0xBB…, m 192, n 320).
3. zk-pow `fixures/v2_stark_proof.bin`, a proof mined by the official code (`compat_test.rs`):
   ChaCha20Rng::seed_from_u64(0xdeadbeef) → A 6,144 × 1,216 and B 1,216 × 4,096 (rand 0.9's
   `random_range(-64..=64)`), header `new_for_test(0x1D2FFFFF)`, rank 64, 8 × 8 tile. Its 164-byte public data
   (read from the GitHub contents API) pins the config bytes, hash_a, hash_b, hash_jackpot and the tile
   (4, 1312). The reference reproduces all of them, and in mining order (row offset first) the first of
   1,193 tiles to meet target 0x1D2FFFFF × 77,824 is exactly (4, 1312). That covers header and config
   serialization, commitments, noise, the jackpot fold, the final hash and the comparison. The V3 salting
   is covered by vector 2; the default 4 × 8 patterns go through the same serializer that reproduces the
   fixture's pattern bytes.

No real mainnet tile can be recomputed: blocks carry only a ZK proof, not the winning rows.

## GPU check (`crossCheck`)

A layout probe confirms which two cells of an 8 × 8 SIMD-group matrix each lane holds. Then, for a random
instance nonce at the benchmark size, the GPU writes all 524,288 tile hashes under a bound that hits ~8 tiles.
The CPU rebuilds the instance from scratch: B with the nonce, a full commitment (checking the incremental
one), seeds, noise and dot products. It compares the full 32-byte hash of 32 random tiles plus the first and
last, and checks that the GPU's hit list is exactly the set of tiles whose hash meets the bound, each one
confirmed on the CPU.

## Memory

At m = n = 4,096, k = 2,048: A and Bᵀ 8 MiB each (shared), A′ and B′ᵀ 8 MiB each, noise factors 1 MiB,
under 40 MiB in all, plus 16 MiB of tile hashes during the check. The CPU keeps copies of A and Bᵀ. Pool mining
adds A's Merkle tree (0.5 MiB) and, while a share is built, a copy of Bᵀ with its tree (8.5 MiB).

## Kernels

Per instance, in one compute encoder: `pearlhash_noise` (one BLAKE3 compression per thread:
(m + n)·r/32 + k/4 threads) → `pearlhash_apply` (A′, B′ᵀ as int8, 16 entries per thread) →
`pearlhash_mine`. The search runs on float SIMD-group matrices: int8 values, products (≤ 16,129) and sums
of r = 128 products (≤ 2.07 M < 2^24) are exact in float. A threadgroup of 8 SIMD groups covers 128 rows
× 64 columns (one period of both patterns). SIMD group (sr, sc) holds the 16 fragments at row blocks
2sr + {0, 1, 8, 9} and column blocks 2sc + {0, 1, 4, 5}. Each lane holds the same (row, column pair) of
every fragment, so it owns exactly one whole 4 × 8 tile and needs no cross-lane traffic. A′ and B′ are
staged in threadgroup memory as halfs, double-buffered, 32 values of k per stage; fragments are built from
manual half2 reads. Every r values of k each lane turns its 32 float sums into int32 totals, XORs them and
feeds a rotating 16-word jackpot queue. At the end it does one BLAKE3 compression and compares the result
with the bound held in the parameter buffer.

The first version kept its 16 accumulators in an array of `simdgroup_float8x8`. This macOS 27 runtime
compiler spills such arrays: 0.39 TH/s. With named matrix variables it runs 13× faster. `pearlhash_lab.metal`
(`test pearlhash --set lab=1`) shows the effect: arrays ≈ 0.25–0.45 TMAC/s, named ≈ 5–6 TMAC/s, plain FMA
≈ 5.4–6.4 TFMA/s. This applies to any port that uses SIMD-group matrices. `--set profile=N` times each
kernel. Double-buffering the stage added ~4%; the per-block fold costs ≤ 3%.

## Measured rate

`bench pearlhash --seconds 10 --no-save`, M3 Max 40-core, final build, started when no other port was
benchmarking: **5.66 TH/s** (thermal nominal, 76 W system vs 28 W idle). An earlier run of the same kernel
gave 5.54 TH/s; runs that overlapped other ports' benchmarks gave 3.2–3.8 TH/s. The search kernel alone runs at
5.2–5.65 T multiply-accumulates/s, about 90% of the measured plain-FMA peak; noise and noisy matrices add
~2.5%. For scale: Kryptex lists an RTX 5090 at 220 TH/s. At ~5.6 TH/s against 102–117 EH/s the Mac would earn
about 0.05–0.06 PRL/day (~$0.12/day at $2.28), and a minimum-difficulty Kryptex share (2^21 · 2^32 hashes)
would take ~27 minutes.

## Pool protocol (Kryptex `prl`, 2026-11-20)

**Who makes the proof: the pool.** A pool miner never makes a ZK proof. A share is Pearl's *plain proof*: the
winning tile's rows of A and columns of B (rows of Bᵀ) as raw int7 bytes, with BLAKE3 Merkle multi-leaf
openings against hash_a and hash_b, plus m, n, k and the noise rank. Pearl ships the pool side itself in
`zk-pow/bindings/go/src/plain.rs`, "PlainProof FFI for the mining pool": `verify_plain_proof_ffi` is the cheap
BLAKE3-only share check (the job header plus the share target as an `nbits_override`), and
`prove_plain_proof_ffi` makes the Plonky2 certificate, "the master's block-finalization step (EXPENSIVE)", which
the pool runs only for a share that also meets the network target. Pearl's solo setup has the same split: the
vLLM miner sends `submitPlainProof` to pearl-gateway, whose ProofGenerator proves and submits the block. So
nothing beyond the verified kernels and some BLAKE3 on the CPU is needed to mine on a pool.

**Wire format.** Kryptex publishes nothing about it. Three open-source miners describe the same dialect from
live Kryptex traffic (Breakwater's pool survey, "bytes on the wire", prl-eu:7048, 2026-08-09; ascend_prl's
Kryptex front end, "tested with Kryptex"; apexprl). It is the family Suprnova documents publicly, with a
classic array-form login:

    -> {"id":0,"method":"mining.subscribe","params":["metalminer/1.0"]}       never answered (see below)
    -> {"id":1,"method":"mining.authorize","params":["<wallet or username>/<worker>","d=2097152"]}
    <- {"id":null,"method":"mining.notify","params":{"job_id":"<hex8>_<difficulty>","header":"<152 hex>",
          "target":"<64 hex, big-endian>","height":146117,"cert_version":3}}
    <- {"id":1,"result":true,"error":null}
    -> {"id":2,"method":"mining.submit","params":{"worker":"<login>","job_id":"…","plain_proof":"<base64>"}}
    <- {"id":2,"result":true,"error":null}, or an error such as [21, "stale", null]

- Newline-delimited JSON over TLS (port 8048, what `PoolEndpoint.kryptex` picks) or TCP (7048).
- The password `d=N` sets the static share difficulty (pool info: `custom`, no vardiff, 2,097,152 to
  4,294,967,296, `hashes_per_diff` 2^32). We ask for the minimum, which is also the default. If a pool answers
  that params must be an object, the miner logs in again with `{"wallet","pass","agent"}` (Suprnova's form).
  An object login with `"type":"v2"` negotiates gzipped proofs on Kryptex (ascend_prl, apexprl); not used,
  since our proofs are random int7 bytes and barely compress.
- `header` is the 76-byte job header, used verbatim for the job key. `target` is authoritative; a new difficulty
  arrives as a new target in a new notify. `cert_version` 3 means salted (V3) seeds; without it the miner uses
  the height (≥ 99,000 → V3). `mining.set_difficulty` [d] (a fallback when a notify has no target, in the
  0xffff·2^208/d convention), `client.reconnect` (same endpoint, wait capped at 30 s) and `client.show_message`
  are handled; a dropped connection throws, and the engine reconnects with back-off.
- A share is valid when its jackpot hash (little-endian) is ≤ target × tile size × (k − k mod r) and ≤ the
  rank-penalised bound (equal at r = 128): the block rule with the share target. It is worth 2^256 / target
  hashes = d × 2^32 (9.0 × 10^15 at the minimum; ~27 minutes at 5.6 TH/s). The GPU uses the target rounded down
  to compact form, as a pool that calls `verify_plain_proof` with nbits sees it (at most 3 × 10⁻⁵ stricter).

**PlainProof bytes** (bincode 1, fixed-width little-endian; `PlainProof::deserialize_compat`): m, n, k,
noise_rank as u64; then for A and for Bᵀ: the leaf count and each leaf as u64 1,024 + its 1,024 bytes; the leaf
indices (u64 count + u64s, increasing); the tree's leaf total (must equal ⌈rows·k/1024⌉); the root (32 bytes);
the siblings (u64 count + 32 bytes each, collected level by level, increasing index within a level, as
pearl-blake3's `get_multileaf_proof`); the opened row indices (u64 count + u64s); then one 0 byte (`moe: None`).
The pool reads the tile pattern and offset back from the row indices (`list_to_pattern`), so any
consensus-valid configuration travels in the proof. miningcore's independent C# parser reads the same layout.
Ours opens 4 rows × 2 chunks of A and 8 columns × 2 chunks of Bᵀ plus ~37 siblings: 26,417 bytes, 35,224
base64 characters.

**The miner** (`PearlHashPoolMiner`): on each job the same A and B are recommitted under the new job key (A's
Merkle tree kept for shares, ~0.1 s of CPU); GPU batches of ~0.2 s use bound = compact(target) × 65,536; each
hit becomes a PlainProof (Bᵀ rebuilt with the instance nonce, both trees opened) and is re-checked with
`PearlHashPlainProof.verify` before it is sent. That check ports Pearl's `verify_plain_proof` onto the CPU
reference: parameter limits and the rank floor, tree sizes pinned to m, n, k, both openings rebuilding their
roots under the job key, values in −64…64, then seeds, noise, jackpot, hash and both bounds. The rate goes out
every 5 s, each pool answer through `events.share` with work 2^256 / target. For live tests,
`PEARLHASH_POOL_K=<k>` (environment) mines with another common dimension.

**Self-test** (`metalminer pooltest`, ~25–35 s with the GPU shared): a Merkle check (roots of 2–9 chunks equal
BLAKE3 keyed hashes, 32 openings rebuild them); then the production miner (m = n = 4,096, k = 2,048) against a
MockPool speaking Kryptex's dialect, subscribe unanswered: job 1 is block 145,681's real header with
cert_version 3 at difficulty 256; after two accepted shares a new template (newer time, other merkle root) at
difficulty 4,096 (16× harder); after two shares there a `client.reconnect`; job 3 after the second login.
Every share is decoded from its bytes and checked by the test pool with the CPU reference, and must be accepted
and credited with its own job's work; logins must carry `d=2097152`. Then the test pool must refuse a flipped
byte in an opened row of A (26, "A's Merkle opening doesn't rebuild hash_a"), tile (0, 0) of a fresh instance
(23, low difficulty), a resent share (22) and an unknown job (21).

**Handshake** (`metalminer handshake`, 2026-11-20): `stratum+ssl://prl.kryptex.network:8048`, TLS connection in
~330 ms with a certificate valid for that host; `mining.subscribe` got no answer within 10 s and the
connection stayed open; disconnected without logging in. KRig's documented log (`authorize sent`,
`authorized`, `notify`) and Suprnova's dialect have no subscribe either, so the miner sends it without waiting,
as the captures that did log in on Kryptex did.

**Only a live test can confirm:**
- That Kryptex accepts this shape: m = n = 4,096, k = 2,048, rank 128, 4 × 8 tile. It is Pearl's own default
  and the configuration in Pearl's pool-FFI test, and consensus-valid, but pools may admit only some shapes:
  the miningcore fork takes only k = 32,768, rank 128, 8 × 16 tiles; ascend_prl mines Kryptex at rank 128
  or 256 with k = 4,096; Suprnova sees k from 4,096 to 65,536 on its pool. If shares come back refused as invalid,
  retry with `PEARLHASH_POOL_K=4096` (or larger).
- That the array login with the `/`-separated login and the `d=` password, and plain (un-gzipped) proofs in
  that session, are still accepted (the captures are from August; KRig may use the v2 session).
- Kryptex's error codes and texts, how long shares on a replaced job stay valid, and that `cert_version` is 3.
- At the minimum difficulty a share takes ~27 minutes on average (63% chance within 27 minutes, 95% within
  80), so the first answer may be slow.

**Live on Kryptex (2026-11-23):** mining.subscribe went unanswered, as expected; mining.authorize
[`email/worker`, "d=2097152"] was accepted; jobs came at difficulty 2,097,152, and a share (a PlainProof) was
accepted within 90 seconds.

## Open questions

- Which shapes Kryptex admits (see "Pool protocol"): the per-hash work does not depend on the shape, but a
  pool may refuse shapes its prover hasn't been sized for.
- Entry range: Pearl's test miner draws A and B from −64…64, and `verify_plain_proof` checks −64…64. The port
  uses −64…63 (noisy entries stay within ±127 either way).
- Block-level STARK proving (Plonky2) is not ported; needed only to mine solo.

## Speed-up ideas left

- Larger register tile per SIMD group (2 tiles per lane) to cut fragment reads per multiply; watch register
  pressure.
- Overlap CPU seed computation and command-buffer submission with GPU work (async double-buffered batches);
  fuse noise and noisy-matrix kernels (together ~2.5%).
- Chips with GPU matrix units for int8 (M5-class with Metal 4 tensor ops) could change the picture entirely; on
  M3 the float FMA path is the ceiling.
