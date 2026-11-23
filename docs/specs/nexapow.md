# NexaPow: Nexa (NEXA)

Id: `nexapow`, coin NEXA. Kryptex: `stratum+tcp://nexa.kryptex.network:7026` (SSL `:8026`; regional
`nexa-eu`, `-us`, `-br`, `-sg`, `-hk`, `-ru`, `-ae`), static share difficulty 1 (custom difficulty not
supported; the pool API says `hashes_per_diff` 4,294,967,296), PPS+ 3 % / SOLO 1 %. Pool hashrate 61.17 GH/s,
520 miners on 2026-11-19. Pool miner: `Sources/Algorithms/NexaPow/NexaPowPool.swift` (see "Pool protocol").

## Construction (mainnet)

From the Nexa full node (Bitcoin Unlimited), tag `nexa2.2.0.0` (2026-08-26; `dev` is identical for these
files). Mainnet is `CNexaParams`: `powAlgorithm = 1`, 2-minute blocks, powLimit = SetCompact(0x1e010000)
= 2^232, ASERT difficulty (2-day half-life). Nothing depends on height: no DAG, no epochs.

1. **Header commitment** (pool side; stratum miners receive it). `GetMiningHeaderCommitment` =
   sha256( sha256(hashPrevBlock ‖ nBits) ‖ sha256(hashAncestor ‖ hashTxFilter ‖ hashMerkleRoot ‖ nTime ‖
   height as u64 ‖ chainWork ‖ size ‖ txCount ‖ feePoolAmt ‖ utxoCommitment ‖ minerData) ), single SHA-256s
   (`CSHA256Writer`), integers little-endian, the two byte vectors with compact-size prefixes. The CPU
   reference has it (`miningHeaderCommitment`), unverified (open question 3).
2. **miningHash** = sha256d(commitment ‖ length ‖ nonce) (`GetMiningHash`, `CHashWriter`): the nonce is a
   byte vector of at most 16 bytes with a compact-size length byte. A pool hands out the first bytes (the
   extranonce) and the miner fills the rest: Echelon (protocol 1.0.4, Nexa's stratum) uses an 8-byte
   extranonce and 8 miner bytes; Kryptex's subscribe gives 4 + 4; MiningCore-style pools 4 + 8. The kernel
   writes its 64-bit counter little-endian right after the extranonce (see "Pool protocol"). The `time` field
   of an Echelon `mining.notify` is only echoed back; it is already inside the commitment.
3. **h1** = sha256(miningHash). `CheckProofOfWork` mixes in the previous block hash,
   h1 = sha256(sha256(miningHash ‖ prevhash)), only for Tailstorm subblocks (`minerData` carrying the
   subblock version); ordinary blocks pass a null prevhash (open question 4).
4. **Key**: x = miningHash read big-endian (`CKey::Set`); x = 0 or x >= n fails the proof of work.
5. **Signature**: `CKey::SignSchnorr(h1)` = `secp256k1_schnorr_sign(…, nonce_function_rfc6979, NULL)`, the
   2017 BCH-style Schnorr module. k = libsecp256k1's RFC6979 HMAC-SHA256 DRBG keyed by
   x ‖ h1 ‖ `"Schnorr+SHA256  "` (h1 not reduced mod n), retried while k = 0 or k >= n; R = kG; k := n - k
   unless jacobi(R.y) = 1; e = sha256(R.x ‖ compressed P ‖ h1) mod n (the node fails the signature when
   e >= n or e = 0); s = k + e x mod n; sig = R.x ‖ s, 64 bytes big-endian.
6. **powHash** = sha256(sig). A hit is `UintToArith256(powHash) <= target`: the 32 hash bytes read as a
   little-endian number (the usual byte-reversed uint256 hex, compared numerically). The kernel compares
   all 256 bits with a target held in the job buffer.

The failure paths (invalid x, RFC6979 retry, e overflow) each have probability about 2^-128; the CPU
reference and the kernel implement them anyway (the kernel runs the retry loop and treats the other two as
"no hit").

## Sources

- gitlab.com/nexa/nexa, tag nexa2.2.0.0: `src/pow.cpp` (CheckProofOfWork), `src/primitives/block.cpp`
  and `block.h` (commitment, GetMiningHash, MAX_NONCE_SIZE), `src/validation/headervalidation.cpp`
  (which prevhash is passed), `src/key.cpp` (SignSchnorr), `src/hashwrapper.h` (CHashWriter = sha256d,
  CSHA256Writer = sha256), `src/chainparams.cpp` (CNexaParams),
  `src/secp256k1/src/modules/schnorr/main_impl.h` and `schnorr_impl.h`, `src/secp256k1/src/secp256k1.c`
  (nonce_function_rfc6979), `src/secp256k1/src/hash_impl.h` (HMAC-DRBG), `src/test/key_tests.cpp`.
- spec.nexa.org/mining/NexaPOW/ and spec.nexa.org/mining/echelon-protocol/ (pool protocol and hashing
  examples; spec repository gitlab.com/OneThirtySeven/nexa/echelon-mining-protocol); pool.kryptex.com/nexa
  and pool.kryptex.com/nexa/api/v1/pool/info.
- MiningCore-style Nexa pool code: https://github.com/blackmennewstyle/miningcore (archived),
  `src/Miningcore/Blockchain/Nexa/NexaPool.cs`, `NexaJob.cs`, `NexaJobManager.cs`.

## Verification

- **CPU reference** (Swift; deliberately independent of the kernel: generic multi-limb arithmetic with a
  folding reduction, double-and-add, Fermat inversion, Euler's criterion):
  - Nexa `key_tests.cpp` (`key_test1`, deterministic signing): SignSchnorr(Hash("Very deterministic
    message")) with strSecret1 and strSecret2 (WIF, decoded by our base58check): both signatures match.
  - Echelon spec "Full hashing examples": commitment `0a4ac49b…705e74b0` with nonces
    `10000000000000001182dc5800000000` and `1000000000000000b787915d00000000`: miningHash, h1, signature
    and powHash (`00000042cbc24037…`, `0000005f0b59e110…`) all match. These fix the byte orders:
    commitment and hashes are printed as uint256 hex (byte-reversed), the nonce and signature as raw bytes.
  - Sanity: SHA-256("abc"), G on the curve, nG = O, (n-1)G = -G, SetCompact(0x1e010000) = 2^232.
- **GPU** (`test nexapow`, window 20, and `--quick`, window 8): 6 random table entries against CPU scalar
  multiplication; then, for each of five nonce layouts (extranonce + counter bytes 8 + 8 as in Echelon,
  4 + 4 as Kryptex hands out, and 3 + 8 + 1 fill, 5 + 8 + 3 fill, 2 + 8, so the counter starts at every
  byte of a block word), 32 consecutive random nonces through the hash kernel, compared word for word
  (miningHash, h1, 64-byte signature, powHash) and on the hit flag, with the target set to the median
  powHash so about half hit; then the search kernel (the mining kernel) over the same nonces must report
  exactly the CPU's hit set.

## Memory

Fixed-base table of signed W-bit windows: entry (i, j) = j · 2^(W i) · G, affine, 64 bytes, j = 1 … 2^(W-1)
(window bases on the CPU, entries on the GPU). Default W = 20: 13 windows × 524,288 entries = 416 MiB,
built in 0.65 s. W = 16: 34 MiB; 18: 120 MiB; 22: 1.5 GiB; `--quick`: W = 8, 264 KiB. Nothing else per job.

## Kernels

`Kernels/nexapow_field.metal`, `nexapow_sha.metal`, `nexapow_ec.metal`, `nexapow.metal` (one library, in
that order); host code `Sources/Algorithms/NexaPow/NexaPow.swift`. One nonce per thread:

- The mining hash is one SHA-256 block. The host lays out block words 8-15 (nonce length byte, extranonce,
  zero fill, 0x80, bit length) with zeros where the counter goes and passes the counter's block word (8-10)
  and byte offset; the kernel ORs in the counter's 8 little-endian bytes. A nonce with fewer than 8 counter
  bytes (Kryptex's 4 + 4) works because its counters stay below 2^32, so the extra bytes are zero.
  (`NexaPow.NonceLayout`; any extranonce up to 8 bytes, nonce up to 16.)
- SHA-256: 3 compressions (miningHash, h1), 16 for RFC6979 (the zero-key pad states come from the CPU and
  each key's pad states are reused by consecutive HMACs), 2 for e, 2 for powHash.
- P = xG and R = kG from the table: one mixed Jacobian + affine addition (8M + 3S) per nonzero window digit,
  12 per scalar at W = 20, instead of 256 doublings and additions.
- One exponentiation does all inversions and the Legendre symbol: with a = Zp² · Yr · Zr and
  t = a^((p-3)/4) (253 squarings, 14 multiplications; a table-driven addition chain with one squaring
  and one multiplication site), t² a = jacobi(Yr Zr) = jacobi(R.y) and t⁴ a = a^-1 gives Zp^-1 and Zr^-1.
- s = e x + k mod n with two folds by 2^256 - n; 256-bit target comparison as a borrow chain.

Representation: 8 × 32-bit limbs, lazily reduced below 2^256. Apple GPUs multiply 32 × 32 -> 64 in one
instruction (`ulong(a) * ulong(b)`, 8 cycles) but have no add-with-carry and only emulated 64-bit adds,
and p = 2^256 - 0x1000003D1 folds the high half with small multiplies, so 32-bit limbs with 64-bit
partial sums are the natural fit. Jacobian coordinates keep inversions out of the additions, affine table
points make them mixed additions, signed digits halve the table, and squaring computes 36 limb products
instead of 64.

Options: `--set window=N` (4-22), `--set group=N` (default 256). Development only: `--set profile=N`
(building-block micro-benchmarks in `nexapow_prof.metal`, `--set n=R`), `--set profile=100` with
`--set defines=NEXAPOW_SKIP_EC|NEXAPOW_SKIP_POW|NEXAPOW_SKIP_RFC` (the search kernel with a phase compiled
out, no cross-check; wrong results, timing only).

## Pool protocol (Kryptex NEXA: `NexaPowPool.swift`)

Live (2026-11-20, `metalminer handshake nexa`, mining.subscribe only):
`{"id":1,"result":[[["mining.set_difficulty","890a10deb0297fd1"],["mining.notify","890a10deb0297fd1"]],"3153f1c9",4],"error":null}`,
then nothing within 3 s. So Kryptex hands out a **4-byte extranonce with extranonce2 size 4**, not Echelon's 8 + 8.
Its notify is only seen after a login, so the miner reads both known shapes and picks by the notify's length:

| | Echelon 1.0.4 (spec.nexa.org) | MiningCore-style (blackmennewstyle/miningcore) |
|---|---|---|
| subscribe → | [subscriptions, extranonce, extranonce2 size] | [subscriptions, extranonce1 (4 bytes), 4] |
| authorize | [login, "x"] → true; a refusal throws `PoolLoginRefused` | same |
| set_difficulty | [d], applied from the next job | [d] |
| notify | 5 params: [job, commitment, nbits, time, clean] | 4 params: [job, commitment, height (a number), nbits] |
| commitment | written as a uint256 (byte-reversed); the miner reverses it | internal byte order, used as is |
| nonce | extranonce + extranonce2-size bytes: 8 + 8 = 16 (Echelon), 4 + 4 = 8 (Kryptex's subscribe) | extranonce1 + 8 bytes = 12 (the reported size 4 is ignored, as the pool's own code does) |
| submit | [login, job, all nonce bytes as hex, time as received] | [login, job, extranonce1, ntime (unused, sent ""), 8 miner bytes as hex] |
| set_extranonce | [extranonce, size], applied from the next job | — |

- **Counter and nonce.** The miner's bytes are the kernel's 64-bit counter, little-endian, cut to the bytes
  available. With Kryptex's 4 + 4 a job has 2^32 nonces (about 7 minutes at 10 MH/s), after which the miner waits
  for the next job (Nexa blocks come every 2 minutes).
- **Targets and work.** A share's powHash, read as a little-endian number, is at most Bitcoin's difficulty-1 target
  0xFFFF × 2^208 divided by d (≤, as the node compares). Kryptex: d = 1. `work` = 2^256 / (target + 1) =
  4,295,032,833 hashes per share at d = 1 (Kryptex's API: 2^32 per difficulty).
- **Mining.** The first job compiles the kernels (about 13 s, cached afterwards) and builds the window table (0.7 s);
  later jobs only rewrite the job buffer. Batches of 2^20 counters. Every GPU hit is recomputed with the CPU
  reference before it is sent; shares found on a job that a clean job replaced are dropped. The rate goes to
  `events.hashrate` every 5 s.
- **Offline round trip** (`metalminer pooltest nexa`, under a second once the kernels are compiled): an unknown login
  is refused as `PoolLoginRefused`; Echelon job a1 is the spec's hashing example (its commitment written as a
  uint256, extranonce 1000000000000000) at difficulty 1/128 with the first counter set just below the example's, and
  the GPU's first share is exactly the spec nonce `10000000000000001182dc5800000000`, for which the mock's CPU reference
  gives the spec's powHash; difficulty 2^-18 (job re-sent) brings shares only the new target allows; mining.set_extranonce
  `3153f1c9` with size 4 (Kryptex's shape) and a clean job bring 8-byte nonces with that prefix; a found nonce with its
  counter's low bit flipped is refused ("Low difficulty share") and reported as rejected; and a second session in the
  MiningCore-style shape (4-param notify, extranonce1 c0ffee01, 12-byte nonces) gets its shares accepted.
- **Only a live login can confirm:** which notify shape Kryptex sends; with an Echelon shape, whether its nonce really
  is 4 + 4 = 8 bytes; the commitment's byte order (if every share is refused as low difficulty, flip it first: the
  `commitment` line in `NexaPowPoolMiner.notify`); the time field; the difficulty it sends; and its share replies.

**Live on Kryptex (2026-11-23):** subscribe returned the MiningCore shape (a 4-byte extranonce, size 4) and the miner
chose the MiningCore-style notify (4 parameters) with a 4 + 8-byte nonce; a Kryptex account login (`email/worker`)
was accepted at difficulty 1 (2^32 hashes per share, about 9 minutes at 8 MH/s). Eight minutes found no share, so
the nonce layout and commitment byte order are still unconfirmed.

## Measured (M3 Max 40-core, 2026-11-20; rough, the GPU was shared)

- **10.48 MH/s**, `bench nexapow --seconds 10`: window 20, group 256, thermal nominal, 91 W system
  (+82 W over idle, about 128 kH/J). The Metal Miner app test was also running on the GPU (87 % device
  utilization just before the run), so this is likely an underestimate.
- Window 16 / 18 / 20 / 22: 9.37 / 10.02 / 10.71 / 4.70 MH/s (the 1.5 GiB table's random reads are no
  longer cache-friendly). Group 64 / 128 / 256: 8.4 / 8.8 / 9.05 MH/s (same session, shared GPU).
- Phase split at window 16 (rate with one phase compiled out): full 9.41, without the exponentiation
  13.85, without RFC6979 10.3, without the point multiplications 22.3 MH/s: about 58 % point
  multiplications, 32 % exponentiation, 10 % SHA-256/HMAC.
- After the nonce-layout change (2026-11-20): 9.31, 8.66 and 4.84 MH/s in three back-to-back 8 s runs while
  another agent was building and using the GPU, so no comparison is possible; the change adds a few shifts and
  selects per nonce.

Compiler behaviour worth knowing (Apple GPU compiler, macOS 27):

- Code shape decided speed more than operation counts. With squaring written as mul(a, a) the whole search
  kernel ran at 3.2 MH/s, about 3.5k lane-cycles per field multiplication; a dedicated squaring routine
  moved it to about 0.7-0.9k and 9.4 MH/s. The micro-benchmarks showed the same split for identical
  arithmetic in different loop shapes; the trigger wasn't pinned down.
- After that change an early-exit 256-bit comparison loop returned wrong hit flags while every hash still
  matched (the loop was correct and had passed before). It is now a branch-free borrow comparison. The
  cross-check's hit-flag and search-kernel stages caught it; keep them.
- Any `__attribute__((noinline))` function in the library made every kernel about 5× slower.
- One profiling variant once crashed the compiler service (XPC_ERROR_CONNECTION_INTERRUPTED).

## Open questions

1. Kryptex's notify shape, nonce length and commitment byte order (see "Pool protocol"): only a login shows them.
2. Share difficulty 1 at Kryptex: the pool API's `hashes_per_diff` of 2^32 matches Bitcoin's difficulty-1 target
   0xFFFF × 2^208, which the miner uses; the Echelon spec doesn't define it.
3. The header commitment hasn't been checked against a real mainnet block (explorer.nexa.org returned a
   Cloudflare 520 on 2026-11-19). Miners don't compute it; only solo or pool-side code would.
4. Tailstorm: the node has subblock rules (prevhash mixed into h1) with no mainnet activation gate visible
   in chainparams, but Echelon jobs carry no prevhash, so pool work today is ordinary blocks. If subblocks go
   live the job needs hashPrevBlock and the kernel's h1 step changes.
5. Nexa's spec site proposes a future proof-of-work hard fork ("BlindedPOW", signature verification). It is
   not in nexa2.2.0.0.

## Speed-up ideas

1. Replace the exponentiation (about a third of the time) with a safegcd (Bernstein-Yang) inversion plus a
   divsteps/binary Jacobi symbol: roughly 55k instead of 240k lane-cycles, maybe +30 %.
2. madd-2007-bl (7M + 4S) now that squaring is cheaper than multiplication (a few %).
3. SHA-256: start the mining hash from a per-job state after the 8 constant commitment words (rounds 0-7)
   and precompute the schedules of the constant padding blocks (a few %).
