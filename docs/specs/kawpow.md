# KawPow: Ravencoin (RVN) and Quai (QUAI)

Id `kawpow`, coins RVN and QUAI (Kryptex pools `rvn`, PPS+ 1%, and `quai-kawpow`, PROP 1%).

## Construction (RavenCommunity/cpp-kawpow, ProgPoW revision 0.9.4)

- DAG: Ethash's DAG, but with 7,500-block epochs and **512 cache parents per item** (Ethash uses
  256; `full_dataset_item_parents = 512` in cpp-kawpow lib/ethash/ethash.cpp). Seed = keccak256
  applied `epoch` times. Built by `ethash_dag` with `parents = 512`.
- Initial Keccak-f[800] over 25 words: header hash (8 words), nonce low and high words, then
  "RAVENCOINKAWPOW" one character per word (15 words). The first 8 output words carry over; words
  0 and 1 seed the mix.
- Mix: 16 lanes x 32 registers, filled by KISS99 per lane (z, w from the seed; jsr, jcong from the
  lane id). 64 rounds; each loads a 2048-bit DAG item chosen by lane `r % 16`'s register 0, runs the
  period's random program (11 cache reads from the first 16 KiB of the DAG, 18 random math ops,
  interleaved), then merges the item's 4 words for each lane into registers.
- The random program depends only on the period (height / 3, so a new program every 3 blocks, ~3
  minutes on Ravencoin); the program RNG restarts each round, so all 64 rounds run the same sequence.
- Digest: per-lane FNV-1a of the 32 registers, folded into 8 words. Final Keccak-f[800] over the
  carried 8 words, the 8-word digest and "RAVENCOI" + "N" (first 9 padding words). The final hash
  (its 8 words in little-endian byte order) is compared big-endian with the boundary.

Quai: go-quai `consensus/kawpow` uses the same constants (512 parents, 7,500-block epochs) and
verifies KawPow on a Ravencoin "donor" header carried in AuxPow (seal hash, nonce and height from
the Ravencoin header). The work per nonce is identical, so one rate serves both coins; Kryptex's
DAG calculator shows the same height and DAG size for both. Quai caps donor heights at 14,000,000.
[go-quai kawpow.go](https://github.com/dominant-strategies/go-quai/blob/main/consensus/kawpow/kawpow.go)
`ComputePowLight` takes the block number for the epoch and the period from `ravencoinHeader.Height()`,
and hashes the byte-reversed SHA-256d seal hash (the same bytes as Ravencoin's
`GetKAWPOWHeaderHash().GetHex()`). minerstat's DAG calculator lists QUAI KawPow at epoch 1497
(12.7 GB): that is Quai's own height divided by 7,500, which go-quai doesn't use.

## Verification

- CPU reference passes all 13 vectors in cpp-kawpow `test/unittests/progpow_test_vectors.hpp`
  (blocks 0 to 170915: epochs 0, 3, 4, 7, 22), mix digest and final hash.
- GPU: 32 random nonces at the benchmark height match the CPU reference over the GPU DAG, plus one
  hash computed entirely from the light cache.

## Kernel

- The host generates `kawpow_program(mix, cache, data)` for the period with every register index and
  selector as constants (`KawPowFamily.metalProgram`), prepends it to `Kernels/kawpow.metal`, and
  compiles at runtime (about 0.06 s). Real mining recompiles when the period changes.
- Each thread owns one nonce; the 16 lanes of each half SIMD group work through their 16 hashes
  together, broadcasting the item index with `simd_shuffle`. Lane l loads uint4 `(l ^ r) % 16` of
  the 256-byte item, so each load fetches whole items. The 16 KiB L1 cache sits in threadgroup memory.

## Measured (M3 Max 40-core, 2026-11-19; other ports were sharing the GPU)

Ravencoin height 4,632,866: epoch 617, DAG 5.82 GiB (built in about 8.5 s), period 1,544,288:
**19.0 to 20.3 MH/s**. That is about 16 KiB of DAG per hash, or roughly 310 to 330 GB/s, close to
80% of the M3 Max's 400 GB/s.

## Pool protocol (Kryptex `rvn` and `quai-kawpow`)

Code: `KawPowPool.swift` (`KawPowStratumDialect`, `KawPowPoolMiner` for both slugs),
`KawPowPoolSearch.swift` (GPU search per job), `KawPowPoolTest.swift` (selfTest and mock pool); the
session loop, targets and seed hashes are shared with Ethash (`Ethash/EthashPoolKit.swift`).

Endpoints (`https://pool.kryptex.com/<slug>/api/v1/pool/info`, 2026-11-20): `rvn.kryptex.network`
7031, SSL 8031; `quai-kawpow.kryptex.network` 7043, SSL 8043; plus regional hosts. Fixed share
difficulty of 2^31 hashes for both, no vardiff, no custom difficulty. Kryptex's setup pages give plain
kawpow settings for Quai (WildRig `--algo kawpow`, SRBMiner `--algorithm kawpow`; Rigel's `--coin quai`
only avoids DAG rebuilds), so both pools speak the same KawPow Stratum.

Handshake (2026-11-20, SSL, only `mining.subscribe ["metalminer/1.0"]` as JSON-RPC 2.0, then
disconnect): RVN answered `[null, "7134c3"]` (a 3-byte extranonce) and Quai `[null, "996c"]` (2 bytes),
both in about 320 ms; neither pushes anything before login, so the job layout below comes from
kawpowminer and MiningCore, not yet from Kryptex.

Messages: kawpowminer's client in its "stratum" mode
([EthStratumClient.cpp](https://github.com/RavenCommunity/kawpowminer/blob/master/libpoolprotocols/stratum/EthStratumClient.cpp))
and MiningCore's Progpow pool
([ProgpowPool.cs, ProgpowJobManager.cs, ProgpowConstants.cs](https://github.com/blackmennewstyle/miningcore/tree/dev/src/Miningcore/Blockchain/Progpow)).

- → `mining.subscribe [agent]` ← `[subscriptions or null, extranonce]`
- → `mining.authorize [login, "x"]` ← `true` (an error or `false` → `PoolLoginRefused`)
- ← `mining.set_target [target, 64 hex digits]`: applies at once, to the current job too (kawpowminer)
- ← `mining.notify [job id, header hash, seed hash, target, clean, height, nbits]` (hashes as hex
  without 0x; an empty target means the last set_target)
- → `mining.submit [login, job id, "0x" + nonce (16 digits), "0x" + header hash, "0x" + mix digest]` ←
  `true`. MiningCore strips the 0x and compares header and mix as lowercase hex.
- Also handled: `mining.set_difficulty [d]` (target = 0x00000000ff000000…00 / d, MiningCore's Ravencoin
  difficulty 1; kawpowminer ignores this message), `mining.set_extranonce`, `client.reconnect` (same
  host only), `client.get_version`.

Byte orders: the header hash is the 32 bytes of its hex, in order, loaded as 8 little-endian words.
The nonce enters Keccak-f[800] as two little-endian 32-bit words, low word first; in messages it is
big-endian hex, and the extranonce is its most significant bytes (kawpowminer's processExtranonce;
MiningCore puts its extranonce in the coinbase instead and ignores the nonce's top bytes, so prefixing
is right for both). The final hash is its 8 words little-endian, compared big-endian with the target;
the mix digest goes out as the hex of its 8 words little-endian (cpp-kawpow's `mix_hash` bytes).

Epoch and period: the DAG follows the seed hash (k keccak256 rounds = epoch, as kawpowminer's
`find_epoch_number`), the program follows the height (period = height / 3). The miner logs a line when
the seed's epoch and height / 7,500 disagree; for Quai the height must be the Ravencoin donor's. The
program for a new period is compiled with `device.makeLibrary` (about 0.1 to 0.3 s, near zero when
Metal's shader cache has it) and the last three are kept: `GPU.library(source:key:)` would keep every
period's library forever, about 480 a day.

Work per share: 2^256 / (target + 1) expected hashes. Kryptex's 2^31 is a target near 2^225
(0000000200…), difficulty 0.498 in MiningCore's Ravencoin units.

Mining: the shared session loop (see the Ethash note): about 150 ms GPU batches, candidates re-hashed
by `kawpow_hash` (padded to whole SIMD groups) for their mix digest, checked against the full target
and recomputed on the CPU over the GPU's DAG before they are submitted; submits are asynchronous; the
rate goes out every 5 s; the DAG is spot-checked against the light cache after every build.

selfTest (`metalminer pooltest kawpow`, 2026-11-20, passes in 11.5 s on an idle GPU): a MockPool
answers the subscribe as Kryptex does (`[null, "a3f1c2"]`), then sends set_target and 7-field
notifies, and checks every share with KawPowReference over its own epoch-0 light cache (header,
extranonce prefix, mix digest, full target, duplicates). Jobs are cpp-kawpow vector header hashes:
blocks 49 and 50 (period 16), a corrupted share (nonce changed after the CPU check) refused as "bad
mix hash", then set_target 4x harder with block 99 (period 33: program recompiled), then
client.reconnect and a share after logging in again. Accepted counts, the refusal and each share's
work match the mock; a refused login ends `run()` with `PoolLoginRefused`. Rate in the loop 19.65 MH/s
vs 19.72 MH/s searching alone (epoch-0 DAG).

Unverified until a live test: Kryptex's job messages after login (set_target or set_difficulty, the
notify fields, and for Quai that the height is the Ravencoin donor's), that shares in this form are
accepted, whether the 3-byte RVN extranonce is a nonce prefix (sent as one either way), the
`wallet/worker` and `username/worker` logins, and `client.reconnect`.

**Live on Kryptex (2026-11-23):** RVN accepted a Kryptex account login (`email/worker`), sent `mining.set_target`,
and accepted the first share (epoch 618 DAG, 5.83 GiB, built in 9 s). Quai refuses Kryptex account logins
(`[20, "Invalid login"]`): Kryptex doesn't pay Quai to accounts yet (its pool index has `directMining: false`), so
mining QUAI needs a Quai wallet.

## Ideas

- Try 2 hashes in flight per 16-lane group to hide DAG latency.
- Check `group` 128 vs 256 in the clean run.
- Compile the next period's program in the background a block ahead.
