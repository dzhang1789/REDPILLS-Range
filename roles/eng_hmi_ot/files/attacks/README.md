# Attack, Detection & Recovery Playbook

Quick reference for the four attack families implemented against the PULSE
microgrid co-simulation, each with a read-only **detection** sensor and a
**recovery** action.

> **Scope:** Authorized security research on the PULSE microgrid co-simulation framework.

---

## The Four Attack Families

| # | Family | Attack | Detection (read-only sensor) | Recovery |
|---|--------|--------|------------------------------|----------|
| 1 | **Breaker** | `scada_breaker_attack.py --all` | `scada_breaker_recovery.py --detect` | `scada_breaker_recovery.py --restore` |
| 2 | **Market** | `scada_market_attack.py --all` | `scada_market_recovery.py --detect` | `scada_market_recovery.py --stop-attacker --restore` |
| 3 | **MITM** | `scada_mitm_attack.py --all` | `scada_mitm_recovery.py --detect` | `scada_mitm_recovery.py --stop-attacker --restore ` |
| 4 | **Historian** | `scada_historian_attack.py --all` | `scada_historian_recovery.py --detect` | `No recovery` |

Attack + recovery scripts live in `attacks/`  folder. (Recovery
scripts also carry a `--detect` mode, so `attacks/` folder alone can detect,attack and recover .)

`env_loader.py` is the shared helper that resolves service addresses from an
env file; it is imported by every script.

### One attack mode each

Every attack script has a read-only `--recon`.
Default command to launch each attack:

| Attack | Default command | Read-only | Attack options |
|--------|-----------------|-----------|----------------|
| Breaker | `python attacks/scada_breaker_attack.py --all` | `--recon` | — |
| Market | `python attacks/scada_market_attack.py --all` | `--recon` | `--duration`, `--interval` |
| MITM | `python attacks/scada_mitm_attack.py --all` | `--recon` | `--reveal` |
| Historian | `python attacks/scada_historian_attack.py --all` | `--recon` | `--minutes` |

(All four attacks use `--all` as the single attack trigger and target every
microgrid; historian's `--all` deletes the point-value history.)

### Microgrid layout

- **MG1, MG2, MG3** — *load* microgrids: breakers are `main`, `load`, `bidder`.
- **MG4** — *generator* microgrid: breakers are `main`, `gen` (no load breaker).

The "downstream" breaker is `load` on MG1–3 and `gen` on MG4.

---

## Service Addresses (env file)

Scripts need to know where ScadaLTS, the SCADA gateway, the PLCs, and MySQL
live. Resolution order (highest priority first):

1. Explicit CLI flag (`--scada-url`, `--gateway-host`, `--db-host`, …)
2. `--env-file <path>` — `env_loader` reads `SCADALTS_HOST/PORT`,
   `SCADA_GATEWAY_HOST/PORT`, `MG*_PLC_HOST`, `DATABASE_HOST`, …
3. Built-in **localhost** defaults (ScadaLTS `:8080`, gateway `:5020`, DB `:3306`)

So on a local single-host stack **no env file is needed**; for a distributed
deployment pass `--env-file deployment/prod.env`.

- `deployment/dev.env` — localhost
- `deployment/prod.env` — generated from `config.yml` by `generate_deployment.py`

> Note: the Point Link and historian steps shell out to
> `docker exec scada_database …`, so those must run on the host where the
> ScadaLTS DB container lives. REST/DWR/Modbus calls work remotely.

---

## 1. Breaker Attack

Opens circuit breakers through the legitimate ScadaLTS control path. Exploits
default credentials and control-mode overrides. Attack Mg1,2,3, and 4. (Only A)

| | |
|---|---|
| **Target** | ScadaLTS (:8080) → PLCs |
| **Impact** | Load shed / blackout (breakers forced open) |
| **Stealth** | Low — SCADA shows the real breaker states |
| **MITRE ICS** | T0866, T0831, T0806 |

**Chain:** brute-force login → set Operator Mode → disable Point Links →
ensure `Market_Control = TRUE` → set `Cmd_Input = FALSE` (breaker opens).

```bash
# Read current state only
python attacks/scada_breaker_attack.py --recon

# Open the downstream breaker on every microgrid (load on MG1-3, gen on MG4)
python attacks/scada_breaker_attack.py --all

# Detect (token sensor) and recover
python attacks/scada_breaker_recovery.py --detect
python attacks/scada_breaker_recovery.py --restore
```

Recovery closes whatever is open **main**, so a blackout where `main` was
opened restores `main` + the downstream breaker; a load-only shed restores just
`load`. Add `--interval 5` for a continuous detect + auto-restore loop.

---

## 2. Market Attack

Spoofs the gateway market registers to create false scarcity, then forces load
shedding on target microgrids so the shedding looks legitimate to the operator.
Attack bidder load on Mg 1,2 and 3 (not 4). 

| | |
|---|---|
| **Target** | SCADA Gateway (:5020) + PLCs |
| **Impact** | Bidder loads disconnected, economic disruption |
| **Stealth** | High — spoofed data justifies the shedding |
| **MITRE ICS** | T0830, T0831, T0836, T0856 |

```bash
# Read current market state
python attacks/scada_market_attack.py --recon

# Attack all microgrids (default) — runs until Ctrl+C
python attacks/scada_market_attack.py --all

# Attack all microgrids for a fixed 60s
python attacks/scada_market_attack.py --all --duration 60

# Detect (token sensor) and recover
python attacks/scada_market_recovery.py --detect
# stop the attack first, else its ~1 s re-injection overwrites the restore:
python attacks/scada_market_recovery.py --stop-attacker --restore 
```

`--duration` defaults to `0` (run until Ctrl+C); `--interval` (default `1.0`s)
is the re-inject cadence that keeps the spoof/breaker-open sticking against the
gateway's ~1 s overwrite cycle.
> **`--stop-attacker` (all recovery scripts).** The **market** and
> **MITM** attacks re-inject continuously (~1 s and ~0.5 s loops), so a bare
> `--restore` is overwritten before it can stick. `--stop-attacker` `pkill`s the
> local attack process first, then restores — **required for market and MITM**.
> The **breaker** and **historian** attacks are one-shot (breaker disables Point
> Links so its value sticks; historian is a one-time delete), so `--stop-attacker`
> is a harmless no-op there. Thus `--restore --stop-attacker` works as a uniform
> recovery command across all four. It is a **test/sim convenience only**: a real
> blue team can't kill the adversary's process — it would isolate the injection
> path (block the gateway Modbus port / disable the compromised channel) instead.
> Kept opt-in, never the default.

---

## 3. MITM Attack

Stops ScadaLTS from polling the PLCs so the operator's display freezes on the
last "normal" values, then writes coils directly to the PLCs via raw Modbus —
grid goes down while SCADA shows stale-normal data. Attack all Mg1 ,2,3 and 4 (all breakers)

| | |
|---|---|
| **Target** | ScadaLTS (:8080) + PLCs (:502-505) |
| **Impact** | Blackout, invisible to the SCADA operator |
| **Stealth** | High — SCADA frozen on stale data |
| **MITRE ICS** | T0830, T0856, T0806, T0831 |

```bash
# Read current state (data-source status + ground-truth breaker states)
python attacks/scada_mitm_attack.py --recon

# Full attack on all MGs (default)
python attacks/scada_mitm_attack.py --all

# Attack then auto-reveal after 60s
python attacks/scada_mitm_attack.py --all --reveal 60

# Detect (token sensor) and recover
python detection/scada_mitm_detect.py
# stop the attack first — it re-injects every ~0.5 s, else restore is overwritten:
python attacks/scada_mitm_recovery.py --stop-attacker --restore
```

Because the attack blinds SCADA, detection does **not** trust SCADA point
values — it checks data-source status (disabled = blinded / redirected =
proxied) and reads PLC breaker coils directly over Modbus (ground truth).

---

## 4. Historian Tampering

Directly deletes historical measurement data from the ScadaLTS MySQL database
for every microgrid within a time window — used to cover tracks after an attack. 
Only one attack surface - historian database so returns only historian_attack (we can attach C,I, and A)

| | |
|---|---|
| **Target** | MySQL (:3306) |
| **Impact** | Erased history (permanent data loss) |
| **Stealth** | High — the attack window simply has no records |
| **MITRE ICS** | T0811, T0832 |

```bash
# Read-only recon (DB stats)
python attacks/scada_historian_attack.py --recon

# Delete history for all microgrids (default window = last 60 min)
python attacks/scada_historian_attack.py --all

# Delete the last 30 min for all microgrids
python attacks/scada_historian_attack.py --all --minutes 30

# Detect (token sensor) and forensic snapshot
python attacks/scada_historian_recovery.py --detect
python detection/scada_historian_detect.py --minutes 60
python attacks/scada_historian_recovery.py --forensic
```

Deleted history is **not recoverable** (data loss is permanent) — detection +
forensic export is the defence. Detection is gap analysis: it runs in last 10 minutes windows and see 
if drop is significant below a threshold and report it if threshold reaches.

---

## Detection Sensors (indicator tokens)

The four `scada_*_detect.py` scripts (in the sibling **`detection/`** folder)
are **read-only** and emit compact, machine-readable indicator tokens (great for
scripting / RL observations). Each supports `--mg` for a subset, `--json` for
structured output, `--env-file` for remote addresses, and exits `0` clean /
`1` indicators found / `2` on a connection error. The trailing number is the
microgrid id (`mg1→1 … mg4→4`). They import the reused detection logic from the
matching `attacks/scada_*_recovery.py`, so keep both folders side by side.

> **Full token reference:** see [`detection/DETECTION.md`](../detection/DETECTION.md)
> — every token per family, semantics, exit codes, example human + JSON output,
> and scripting/RL usage.

Quick map: with out CIA triad letter attached

| Sensor | Tokens |
|--------|--------|
| `scada_breaker_detect.py` | `breaker_attack1..4`, `no_breaker_attack` |
| `scada_market_detect.py` | `market_attack1..3`, `no_market_attack` |
| `scada_mitm_detect.py` | `mitm_attack1..4`, `no_mitm_attack` |
| `scada_historian_detect.py` | `historian_attack`, `no_historian_attack` |

