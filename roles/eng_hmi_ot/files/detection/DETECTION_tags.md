# Detection Tags — Cheat Sheet

`<N>` = microgrid id (mg1→1 … mg4→4). Output is a space-separated tag list;
`no_*_attack` is the only lone-token case. See `DETECTION.md` for full detail.

**Modes:** default = quiet (tokens only) · `--verbose` = full report · `--json` = object.

## Breaker — `scada_breaker_detect.py` - A (4 assets - load breaker)
| Tag | Fires when |
|---|---|
| `breaker_attack<N>` | MG's downstream breaker open in ScadaLTS **AND** Point Links disabled |
| `breaker_override` | ScadaLTS **Point Links disabled** (breaker attack's unique artifact). *Quiet mode: shown only when it's the sole signal (dropped when a `breaker_attack<N>` is present).* |
| `no_breaker_attack` | clean |

## Market — `scada_market_detect.py` - I (3 ), A (3 assests- bidder breaker)
| Tag | Fires when |
|---|---|
| `market_attack<N>` | **register manipulation present** AND load MG has shed coil active / `alloc=0` with a bid. **N ∈ 1–3 only** (MG4 = generator, no bidder load) |
| `market_spoof` | price spike **≥ $80/MWh** or false scarcity (`surplus=0 & generation=0`). *Quiet mode: shown only when it's the sole signal (dropped when a `market_attack<N>` is present).* |
| `no_market_attack` | clean (incl. legitimate shedding — no register manipulation) |

## MITM — `scada_mitm_detect.py`- CIA 
| Tag | Fires when |
|---|---|
| `mitm_attack<N>` | MG's ScadaLTS data source **DISABLED** (blinded) or **REDIRECTED** (proxy) |
| `mitm_unknown<N>` | MG's PLC unreachable over Modbus **and** not otherwise flagged |
| `no_mitm_attack` | clean |

## Historian — `scada_historian_detect.py`- CIA 
| Tag | Fires when |
|---|---|
| `historian_attack<N>` | MG has **deleted history** on its points: `NO_DATA`/`GAP` (holes / empty window) or `DENSITY_DROP` (bulk deletion) |
| `no_historian_attack` | clean |

*(The attack only deletes measurement records, never the events table, so there is no `historian_events` tag.)*

## Global rules
- **Quiet mode** drops `breaker_override` / `market_spoof` when a per-MG `*_attack<N>`
  tag already implies them (kept when they're the sole signal). `--json`/`--verbose`
  always keep the full set. `mitm_unknown` is always shown.
- Exit code: `0` clean · `1` any attack tag · `2` connection/query error (stderr, empty stdout).
- `Operator_Mode ENABLED` is informational only (shared breaker/market) — never a tag.
