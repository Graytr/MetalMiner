# Results: Apple M3 Max (40-core GPU, 64 GB), 2026-11-20

Every algorithm passes its tests at mainnet parameters. Each one was then benchmarked alone for 30 s with
30 s cool-downs between them (`bench all --seconds 30 --cooldown 30`, 12:38 local time). OCTA and NEXA were
re-benchmarked the same way at 16:56, after the pool work corrected OctaSpace's epoch length (30,000 blocks,
so a 3.80 GiB DAG) and let Nexa's kernel take any extranonce layout. Every row is valued with Kryptex's live
pool data at 16:58. GPU power comes from the GPU's energy counter, less its idle draw (0.5-0.8 W).

| Coin | Algorithm | Rate | GPU power | $/day gross | $/day net at $0.15/kWh |
|---|---|---|---|---|---|
| XTM (Tari) | cuckaroo29 | 5.64 graphs/s | 30 W | 0.45 | +0.34 |
| XEL (Xelis) | xelishash v3 | 5.65 kH/s | 13 W | 0.18 | +0.14 |
| QTC (Quantus) | poseidon2 | 81.06 MH/s | 48 W | 0.12 | -0.05 |
| PRL (Pearl) | pearlhash | 5.54 TH/s | 39 W | 0.11 | -0.03 |
| QUAI | kawpow | 14.93 MH/s | 20 W | 0.06 | -0.01 |
| RVN (Ravencoin) | kawpow | 14.93 MH/s | 20 W | 0.05 | -0.02 |
| CFX (Conflux) | octopus | 20.46 MH/s | 31 W | 0.04 | -0.07 |
| ERG (Ergo) | autolykos2 | 55.71 MH/s effective (60.61 raw, 8% table rebuild) | 25 W | 0.04 | -0.05 |
| ETHW | ethash | 21.78 MH/s | 10 W | 0.02 | -0.02 |
| NEXA (Nexa) | nexapow | 10.53 MH/s | 46 W | 0.01 | -0.15 |
| OCTA | ethash (OctaSpace) | 33.15 MH/s | 26 W | 0.01 | -0.08 |
| ETC | etchash | 29.36 MH/s | 19 W | 0.01 | -0.06 |

With free electricity the order is by gross earnings. With a price, the order follows net earnings,
and power matters. Quantus earns two thirds of what Xelis does but draws almost four times the power, so at
$0.15/kWh it drops from third to a small loss.

Notes:
- Coin prices and network hashrates move daily: `metalminer rank` and the app re-value the latest benchmark
  with live data.
- GPU power leaves out memory (DRAM) and CPU power, which macOS doesn't report to normal apps, so wall
  power is higher, more so for memory-bound algorithms (Ethash, KawPow, Autolykos2).
- Rates vary run to run, mostly with heat: an earlier sustained run (11:31, "fair" thermal state) gave
  Quantus 56.8 MH/s instead of 81, and ETHW 31.4 MH/s instead of 21.8 (its 7.6 GiB DAG is the largest of
  the Ethash coins). Expect a MacBook to settle lower over hours than in a 30 s run.
- Kryptex compares GPUs against an RTX 4070 Ti. On KawPow and Tari C29 the M3 Max reaches roughly half to
  three quarters of that card.
