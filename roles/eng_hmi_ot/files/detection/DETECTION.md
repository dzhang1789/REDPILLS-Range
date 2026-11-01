# Detection Sensors — String Indicator Reference

The four `scada_*_detect.py` scripts are **read-only** sensors. They never change
grid, market, or database state — they scan for attack indicators and emit
compact **string tokens** that are easy to parse from a shell, a pipeline, or an
RL observation. Each detector reuses the proven `detect()` routine from its
matching recovery module, so the sensor and the recovery agree on what is found.

| Attack family | Detect script | Companion attack |
|---------------|---------------|------------------|
| Breaker | `scada_breaker_detect.py` | `scada_breaker_attack.py` |
| Market | `scada_market_detect.py` | `scada_market_attack.py` |
| MITM | `scada_mitm_detect.py` | `scada_mitm_attack.py` |
| Historian | `scada_historian_detect.py` | `scada_historian_attack.py` |

---

## Common conventions (all four detectors)

- **Output.** **Default is quiet** — stdout is a single line of the
  space-separated tokens (e.g. `historian_attack1 historian_attack2 …`), nothing
  else. `--verbose` shows the full human report (banner, per-MG detail, and an
  `INDICATORS:` line). `--json` prints a single JSON object. Errors go to
  **stderr**, so quiet stdout stays clean (the exit code signals failure).
  Quiet mode omits `breaker_override` / `market_spoof` when a per-MG `*_attack<N>`
  tag already implies them (they still print when they're the sole signal);
  `--json`/`--verbose` keep the full token set.
- **Microgrid numbering.** The trailing digit on a per-MG token is the microgrid
  id: `mg1 → 1`, `mg2 → 2`, `mg3 → 3`, `mg4 → 4`.
- **`no_*_attack`.** The lone token when nothing is found (grid clean).
- **Scope.** `--mg mg1 mg3` restricts the scan to a subset (default: all four).
- **Exit code** (drives shell conditionals):
  - `0` — clean (no indicators)
  - `1` — one or more attack indicators present
  - `2` — connection/query error (could not assess)
- **Addressing.** `--env-file deployment/prod.env` resolves remote service
  addresses; otherwise localhost defaults are used.

---

## Token reference

### Breaker — `scada_breaker_detect.py`

| Token | Meaning |
|-------|---------|
| `breaker_attack1` … `breaker_attack4` | that MG's breaker reads **open** (via ScadaLTS) **and** Point Links are cut — the SCADA-path breaker attack |
| `breaker_override` | ScadaLTS **Point Links DISABLED** — the breaker attack's unique control-path artifact |
| `no_breaker_attack` | clean |

- **Attribution key:** Point Links DISABLED (unique to the breaker attack). An
  open breaker **without** cut Point Links is *not* attributed here — the market
  attack opens the bidder/gen breaker via gateway coils, not ScadaLTS.
  Operator_Mode is **shared** with the market attack, so it is informational only
  (an `[info]` line / `operator_mode` JSON field), never a trigger. See
  [§ Attribution](#attribution--unique-per-attack).
- **Source:** ScadaLTS REST reads (breaker states, Operator_Mode) + the Point
  Links table. All reads go through one endpoint, so there is **no per-MG
  `unknown`** — if ScadaLTS is unreachable the run exits `2`.
- **Flags:** `--mg`, `--json`, `--scada-url`, `--env-file`, `-v`.

### Market — `scada_market_detect.py`

| Token | Meaning |
|-------|---------|
| `market_attack1` … `market_attack3` | the market registers show manipulation **and** this **load** MG has a shed coil active / a zeroed allocation. **No `market_attack4`** — MG4 is the generator (no bidder load), never a market target |
| `market_spoof` | market-register manipulation: clearing-price spike (≥ $80/MWh) or false scarcity (`surplus=0, generation=0`) |
| `no_market_attack` | clean |

- **Attribution key:** the **register-manipulation signature** — a clearing-price
  spike (the attack hard-writes $99/MWh) and/or false-scarcity registers. This is
  the gate: a shed coil (`bidder_shed`/`fixed_shed`) or a zeroed allocation is the
  attack's *impact*, **but those also occur in legitimate market clearing** — a
  microgrid that bids below the clearing price loses its allocation (`alloc=0`)
  and its bidder load is legitimately shed. So per-MG shed/alloc signals are only
  attributed to the attack when `market_spoof` is present; otherwise it's normal
  market operation and the detector stays clean.
- **Deliberately not used** (all shared with the breaker attack): the gateway
  `override`/Market_Control coil, the MG4 PLC Market_Control override, and
  Operator_Mode (informational only). See
  [§ Attribution](#attribution--unique-per-attack).
- **Source:** SCADA gateway registers/coils only, read once — they cover every
  MG, so there is **no per-MG `unknown`**. If the gateway is unreadable the run
  exits `2`.
- **Flags:** `--mg`, `--json`, `--gateway-host`, `--gateway-port`, `--plc-host`, `--env-file`, `-v`.

### MITM — `scada_mitm_detect.py`

| Token | Meaning |
|-------|---------|
| `mitm_attack1` … `mitm_attack4` | that MG's ScadaLTS data source is **disabled** (SCADA blinded) or **redirected** (proxy) — the MITM mechanism. Corroborating detail (breakers open per Modbus, MG4 override) is shown in `reasons` but does **not** trigger the token on its own |
| `mitm_unknown1` … `mitm_unknown4` | that MG's PLC is unreachable — no ground truth — and nothing else flagged it |
| `no_mitm_attack` | clean |

- **Attribution key:** `mitm_attack<N>` fires **only** on the blinding/redirect
  signature (data source disabled or redirected). This is unique to MITM — no
  other attack touches ScadaLTS data sources. An open breaker alone (without
  blinding) is *not* MITM; it belongs to the breaker or market detector. See
  [§ Attribution](#attribution--unique-per-attack) below.
- **Source:** ScadaLTS data-source status (catches the mechanism even while the
  operator view is frozen) **plus** direct Modbus breaker reads (used to
  corroborate a confirmed blinding). Gateway `Operator_Mode` is reported on a
  separate `[GATEWAY]` line / JSON field, **not** as a per-MG token.
- Because each PLC is an independent ground-truth source, MITM is the only
  family with **per-MG `unknown`** on unreachable PLCs.
- **Flags:** `--mg`, `--json`, `--plc-host`, `--scada-url`, `--env-file`, `-v`.

### Historian — `scada_historian_detect.py`

| Token | Meaning |
|-------|---------|
| `historian_attack1` … `historian_attack4` | that MG has deleted history on its points: `NO_DATA`/`GAP` (holes / empty window) or `DENSITY_DROP` (bulk deletion) |
| `no_historian_attack` | clean |

*(The in-scope attack `--all` deletes only `pointValues` records, never the
events table, so there is no `historian_events` token.)*

- **Source:** MySQL history via `docker exec` (default) or `--tcp`. Deletion
  shows as a ≥10 s gap in the ~1 Hz series (`GAP`), a fully empty window
  (`NO_DATA`), or a record-count drop vs the prior window (`DENSITY_DROP`).
- **Window:** `--minutes` (default 60). Choose a window at least as large as the
  deletion you want to catch; a deletion right at the tail (up to "now") shows as
  `NO_DATA`/`DENSITY_DROP` rather than a clean `GAP`.
- **Flags:** `--mg`, `--minutes`, `--json`, `--db-host`, `--db-port`, `--tcp`, `--env-file`, `-v`.

---

## Attribution — unique per attack

Several attacks share the same *impact* — most obviously, both the SCADA breaker
attack and the MITM attack **open breakers**. The bare "breaker is open" state is
therefore **ambiguous** and is not used for attribution. Instead each detector
keys on the attack's **unique control-path fingerprint** — the artifact only that
attack leaves behind:

| Attack | Unique fingerprint (what only it does) | Detector keys on |
|--------|----------------------------------------|------------------|
| **Breaker** (SCADA-path) | Opens breakers *through ScadaLTS* — **Point Links DISABLED**; SCADA stays live and shows the real open state | Point Links disabled (+ breaker open in ScadaLTS) |
| **Market** | **Register manipulation** — clearing-price spike ($99/MWh) / false scarcity — that makes shedding *look* justified | price-spike / false-scarcity, then per-MG shed-coil / alloc=0 |
| **MITM** | **Blinds SCADA** — PLC data source DISABLED / REDIRECTED; SCADA frozen on stale-closed while Modbus shows open | data source disabled/redirected |
| **Historian** | **DB history gap / deletion** in `pointValues` | gap / no-data / density-drop |

**Why the shared signals are excluded.** Several signals look tempting but are
produced by more than one attack, so none of them attribute:

| Shared signal | Set by | Verdict |
|---------------|--------|---------|
| Breaker physically OPEN | breaker, market, MITM | impact, not attribution |
| Bidder/fixed shed coil, `alloc=0` | market attack **and** legitimate clearing (a low bidder loses the auction) | impact — only counts when `market_spoof` is present |
| Operator_Mode ENABLED | breaker **and** market | informational only |
| MG4 PLC Market_Control TRUE | breaker **and** market | not a trigger |
| Gateway `override` coil (load MGs) | normal-TRUE; surfaces with Operator_Mode | not a trigger |

### Full attribution matrix

Each attack lights up **exactly one** detector (verified by simulation):

| Running attack | `breaker_detect` | `market_detect` | `mitm_detect` | `historian_detect` |
|----------------|:----------------:|:---------------:|:-------------:|:------------------:|
| **Breaker** | `breaker_attack<N>` + `breaker_override` | `no_market_attack` | `no_mitm_attack` | `no_historian_attack` |
| **Market** | `no_breaker_attack` | `market_attack<N>` (+`market_spoof`) | `no_mitm_attack` | `no_historian_attack` |
| **MITM** | `no_breaker_attack` (blinded → stale-closed) | `no_market_attack` | `mitm_attack<N>` | `no_historian_attack` |
| **Historian** | `no_breaker_attack` | `no_market_attack` | `no_mitm_attack` | `historian_attack<N>` |

Historian is isolated by domain: it only deletes rows in the MySQL history
table, changing no live breaker/gateway/data-source state, so the three live
detectors stay clean; conversely the live attacks don't punch gaps in the
1 Hz history, so `historian_detect` stays clean on them.

---

## Shared token grammar

Across all four families the tokens follow the same shape:

```
<family>_attack<N>     per-MG compromise            (N = 1..4)
<family>_unknown<N>    ground truth unavailable     (MITM only)
no_<family>_attack     clean
```

Plus a family-specific "global" token (breaker/market only) for tampering that
has no single-MG home:

```
breaker_override       Point Links disabled
market_spoof           price spike / false scarcity
```

---

## Example output

**Quiet — the default.** stdout is exactly one line of space-separated tokens:

```
$ python detection/scada_breaker_detect.py
breaker_attack1 breaker_attack3 breaker_override
```

**Verbose (`--verbose`)** — the full human report:

```
$ python detection/scada_breaker_detect.py --verbose
============================================================
  Blue Team Sensing: Breaker Attack Indicators
============================================================
  [MG1] ATTACKED — breaker OPEN via SCADA path: load
  [MG3] ATTACKED — breaker OPEN via SCADA path: main, load
  [SCADA] control-path tampering (1):
      - 2 Point Link(s) disabled: PL_MG1_Load_Cmd, PL_MG3_Load_Cmd

INDICATORS: breaker_attack1 breaker_attack3 breaker_override
```

**JSON (`--json`)** — a single object per run:

```json
{
  "scope": ["mg1", "mg2", "mg3", "mg4"],
  "tokens": ["breaker_attack1", "breaker_attack3", "breaker_override"],
  "compromised": ["mg1", "mg3"],
  "reasons": {"mg1": ["breaker OPEN via SCADA path: load"], ...},
  "override": ["2 Point Link(s) disabled: PL_MG1_Load_Cmd, PL_MG3_Load_Cmd"]
}
```

The JSON keys vary slightly by family (`override` / `spoof` / `events`,
`unknown` where applicable), but `scope`, `tokens`, and `compromised` are
always present.

---

## Using the tokens

The default output *is* the token line, so consume it directly:

```bash
tokens=$(python detection/scada_mitm_detect.py)
# -> "mitm_attack1 mitm_unknown2"
```

Shell conditional on exit code (`0` clean / `1` indicators / `2` error):

```bash
if python detection/scada_market_detect.py >/dev/null; then
  echo "market clean"
else
  echo "market: $(python detection/scada_market_detect.py)"
fi
```

RL / tooling: parse `--json` and feed `tokens` (or a per-MG one-hot from
`compromised`) straight into an observation vector.
