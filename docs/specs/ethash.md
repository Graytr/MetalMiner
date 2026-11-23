# Ethash family: Etchash (ETC), Ethash (ETHW), OctaSpace (OCTA)

Ids: `etchash` (ETC), `ethash` (ETHW), `ethash-octa` (OCTA). All three are filed under ASIC coins on
Kryptex: dedicated Ethash ASICs dominate their networks.

## Construction

Standard Ethash (Ethereum yellow paper appendix J; ethereum.org "Ethash"):

- Light cache: `cacheSize(epoch)` bytes of 64-byte items, `keccak512` chain from the seed, then 3
  RandMemoHash rounds. Seed = keccak256 applied `seedIterations` times to 32 zero bytes.
- DAG: `datasetSize(epoch)` bytes of 64-byte items; item i = keccak512 of the cache item `i mod n`
  (word 0 xor i), mixed with 256 FNV-selected cache parents, keccak512 again.
- Hash: `s = keccak512(headerHash ‖ nonce as 8 bytes little-endian)`; mix = s ‖ s (32 words);
  64 accesses to 128-byte pages chosen by `fnv(i ^ s[0], mix[i % 32]) % pages`; compress to an
  8-word digest; `final = keccak256(s ‖ digest)`. All Keccak is legacy (0x01 padding).
- Target: `final` read as a big-endian 256-bit number must be at most `2^256 / difficulty`.
  The kernel compares the first 8 bytes (big-endian) with a 64-bit target and reports candidate
  nonces; the full comparison happens on the CPU.

What differs per coin is the epoch length:

| Coin | Epoch length | Size epoch / seed iterations at height h | Height on 2026-11-19 | DAG |
|---|---|---|---|---|
| ETC | 60,000 from block 11,700,000 (ECIP-1099) | h/60000 / 2·(h/60000) | 25,766,650 (epoch 429) | 4,456 MB |
| ETHW | 30,000 | h/30000 / h/30000 | 25,494,818 (epoch 849) | 7,816 MB |
| OCTA | 30,000 | h/30000 / h/30000 | 10,783,465 (epoch 359) | 3,896 MB |

Heights come from Kryptex's DAG size calculators (pool.kryptex.com/<coin>/dag-size-calculator); for
ETC and ETHW our sizes match theirs. Today's height is estimated from that point and the average
block time; override with `--set height=N` or `--set epoch=N`.

The ETC seed follows core-geth's `seedHash(epoch, epochLength)`, which still counts 30,000-block
periods.

OCTA uses standard 30,000-block epochs (corrected 2026-11-20; until then the benchmark assumed
60,000-block epochs and a 2.40 GiB DAG). Sources:
[go-octa consensus/ethash/algorithm.go](https://github.com/octaspace/go-octa/blob/main/consensus/ethash/algorithm.go)
(`epochLength = 30000`, `seedHash(block)` = keccak256 applied block/30000 times; the later "eras" change
only block rewards), Kryptex's own OCTA miner settings (lolMiner `--algo ETHASH`, not `ETCHASH`;
Rigel `-a ethash`), and minerstat's DAG calculator (epoch 359, 3.80 GB). Kryptex's DAG calculator
alone says 60,000 blocks (epoch 179, 2,456 MB), which is wrong for OCTA.

## Verification

- CPU reference passes all 7 hash vectors from chfast/ethash `test/unittests/test_cases.hpp`
  (blocks 0, 2, 2683077, 5000000-5000002, 5306861: epochs 0, 89, 166, 176), mix digest and final hash.
- GPU: random DAG items match the CPU, both hash kernels match CPU hashimoto on random nonces over
  the GPU-built DAG, and one hash is recomputed entirely from the light cache.

## Kernels

- `ethash_dag`: one item per thread, 1M items per command buffer. The ETC DAG builds in ~3.3 s.
- `ethash_search` (simple): one thread per hash, 8 × 16-byte loads per page. 18.75 MH/s on ETC.
- `ethash_search_coop` (default): 8 lanes share each hash; for every access the owning lane's page
  index is broadcast with `simd_shuffle` and lane t loads uint4 t of the page, so each load
  instruction fetches whole 128-byte lines. `ETHASH_PAR` hashes per 8-lane group in flight
  (2 was best: 32.7 MH/s; 4: 31.5; 8: 32.0). Options: `--set kernel=simple|coop`, `group=N`, `par=N`.

## Measured (M3 Max 40-core, 2026-11-19, rough: thermal state rising)

| Coin | DAG | Rate |
|---|---|---|
| ETC | 4.35 GiB | 32.7 MH/s (thermal nominal) |
| ETHW | 7.63 GiB | 23.6 MH/s |
| OCTA | 2.40 GiB | 22.6 MH/s (thermal "fair": throttled; measured with the wrong, smaller DAG: re-measure at 3.80 GiB) |

The bandwidth ceiling at 400 GB/s is 48.8 MH/s (8 KiB of DAG reads per hash); 32.7 MH/s is about
67% of it. Whether the ETHW drop comes from the bigger DAG (TLB reach) or heat needs a clean run.

## Pool protocol (Kryptex `etc`, `ethw`, `octa`)

Code: `EthashPool.swift` (the two dialects, `EthashPoolMinerETC`, `EthashPoolMinerETHW`,
`EthashPoolMinerOcta`), `EthashPoolSearch.swift` (GPU search per job), `EthashPoolKit.swift` (targets,
seed hashes and the session loop, shared with KawPow), `EthashPoolTest.swift` (selfTest and mock pool).

Endpoints (`https://pool.kryptex.com/<slug>/api/v1/pool/info`, 2026-11-20): `etc.kryptex.network`
7033, SSL 8033; `ethw.kryptex.network` 7034 / 8034; `octa.kryptex.network` 7032 / 8032; plus regional
hosts. Fixed share difficulty, no vardiff, no custom difficulty: ETC and OCTA 17,179,869,184 = 2^34
hashes per share, ETHW 2^31.

Handshake (2026-11-20, SSL, only `mining.subscribe ["metalminer/1.0", "EthereumStratum/1.0.0"]`, then
disconnect): all three answer as EthereumStratum/1.0.0 in about 320 to 380 ms with a 2-byte
extranonce (`[["mining.notify", …, "EthereumStratum/1.0.0"], "36a8"]`) and push nothing before login.

Two dialects, both from ethminer's client
([EthStratumClient.cpp](https://github.com/ethereum-mining/ethminer/blob/master/libpoolprotocols/stratum/EthStratumClient.cpp));
the miner tries EthereumStratum/1.0.0 first and falls back to ETHPROXY when `mining.subscribe` is
refused or unanswered within 5 s, as ethminer's autodetection does, then keeps the choice.

EthereumStratum/1.0.0
([NiceHash spec](https://github.com/nicehash/Specifications/blob/master/EthereumStratum_NiceHash_v1.0.0.txt)),
hex without 0x:

- → `mining.subscribe [agent, "EthereumStratum/1.0.0"]` ← `[["mining.notify", id, "EthereumStratum/1.0.0"], extranonce]`
- → `mining.authorize [login, "x"]` ← `true` (an error or `false` → `PoolLoginRefused`)
- ← `mining.set_difficulty [d]`: target = 0x00000000ffff0000…00 / d (Bitcoin's difficulty 1, ethminer's
  `getTargetFromDiff`); applies from the next job. Difficulty 1 until the pool sets one.
- ← `mining.notify [job id, seed hash, header hash, clean]`
- → `mining.submit [login, job id, miner nonce]` ← `true`. The 64-bit nonce is extranonce ‖ miner nonce,
  16 hex digits big-endian; the miner nonce is the rest (12 digits after Kryptex's 2-byte extranonce).
  The pool recomputes the mix digest.
- ← `mining.set_extranonce [hex]` (for the next jobs).

ETHPROXY (eth-proxy), all values 0x-prefixed, JSON-RPC 2.0:

- → `eth_submitLogin [login, "x"]` ← `true`; → `eth_getWork []` ← `[header hash, seed hash, target(, height)]`
- ← `{"id": 0, "result": [header hash, seed hash, target(, height)]}` pushes new work (target given directly)
- → `eth_submitWork [nonce (16 digits), header hash, mix digest]` ← `true`. No extranonce.

Both: `client.reconnect [host, port, wait]` is followed to the same host only (another host is
ignored and logged); `client.get_version` is answered; other pool requests get "method not found".

Byte orders: header and seed hashes are the 32 bytes of their hex, in order. The nonce enters
hashimoto as 8 bytes little-endian; in messages it is big-endian hex, so the extranonce is its most
significant bytes. A share meets the target when the final hash, read big-endian, is at most the
target. The mix digest goes out as the hex of hashimoto's 32-byte digest.

Seed hash → DAG: k = the keccak256 rounds from 32 zero bytes that give the seed (found by iterating,
up to 8,192, cached). The size epoch is k for ETHW and OCTA; for ETC it is k/2 once k ≥ 390 (block
11,700,000), else k (`EthashChain.sizeEpoch(seedIterations:)`). A new seed rebuilds the DAG; the old
one is freed first, and 8 items (first, last, 6 random) are checked against the light cache.

Work per share (`PoolEvents.share`): expected hashes = 2^256 / (target + 1), which is d × 2^32 ×
65536/65535 for an EthereumStratum difficulty d. Kryptex's 2^34 hashes on ETC would be difficulty 4.

Mining: about 150 ms GPU batches on the current job; candidates (hash's first 8 bytes ≤ the target's)
are re-hashed for their mix digest, checked against the full target, and recomputed on the CPU over
the GPU's DAG before they are submitted (a mismatch stops the miner rather than submit it). Replies
are matched to submits by id without blocking the GPU; no reply within 60 s counts as not accepted.
The rate goes to `events.hashrate` every 5 s; the loop runs at the search's own rate (selfTest:
34.4 MH/s in the loop vs 34.3 MH/s searching alone on a 1-2.5 GiB DAG, idle GPU).

selfTest (`metalminer pooltest etc ethw octa`, 2026-11-20, all pass in 16 to 23 s each): ETHW first
recomputes the NiceHash spec's worked example (seed of epoch 50, extranonce a2eea0 + miner nonce
cfae7df760) and gets share difficulty 1.863, as the spec says, which pins the nonce layout and
difficulty 1. Then each coin mines against a MockPool that checks every share with EthashReference
over its own light caches: ETC's mock speaks EthereumStratum/1.0.0 (2-byte extranonce), ETHW's
refuses it and serves ETHPROXY, OCTA's ignores it (5 s timeout) and serves ETHPROXY. Jobs use chfast
vector header hashes: two at epoch 0, a corrupted share (nonce changed after the CPU check) refused,
then difficulty x4 with a seed from another epoch (ETC: block 11,700,000, k = 390 → epoch 195; ETHW and
OCTA: block 2,683,077 → epoch 89), DAG rebuilt; ETC also follows client.reconnect. Accepted counts,
refusals and each share's work match what the mock decided; a refused login ends `run()` with
`PoolLoginRefused`.

Unverified until a live test: what Kryptex sends after login (the `mining.set_difficulty` value and
its unit: 4 for ETC and OCTA and 0.5 for ETHW if difficulty 1 means 2^32 hashes; any extra notify
fields), that Kryptex accepts shares in this form, the `wallet/worker` and `username/worker` logins,
and how it uses `client.reconnect`.

**Live on Kryptex (2026-11-23):** all three accepted a Kryptex account login (`email/worker`) over
EthereumStratum/1.0.0 with 2-byte extranonces. ETHW (difficulty 0.5, epoch 850 DAG of 7.64 GiB) and OCTA
(difficulty 4, epoch 360 DAG of 3.81 GiB, which confirms the 30,000-block epochs) each had a share accepted. ETC
(difficulty 4, about 9 minutes per share at 32 MH/s; epoch 429 DAG of 4.35 GiB) found none in a first 8-minute run
and had a share accepted 11 minutes into a longer one.

## Ideas

- Larger pages for the DAG allocation (fewer TLB misses) if Metal exposes any control.
- Retune `group`/`par` in the clean sequential run; check sustained (throttled) rate over minutes.
