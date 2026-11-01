# Unauthorized Breaker Manipulation via SCADA Command Injection

Multi-stage attack through the ScadaLTS SCADA system that exploits default credentials and control mode overrides to open circuit breakers, causing grid blackout. Paired with a blue team recovery script that detects and reverses the attack.

Inspired by real-world ICS incidents: **2015 Ukraine BlackEnergy** and **2016 Industroyer/CrashOverride**.

## Attack Chain (MITRE ATT&CK for ICS)

| Phase | Action | MITRE ICS Technique |
|-------|--------|---------------------|
| 1. Credential Brute Force | Enumerate default credentials (admin:admin) | **T0866** Exploitation of Remote Services |
| 2. Seize Control Authority | Set Operator Mode on SCADA Gateway | **T0858** Change Operating Mode |
| 3. Disable Point Links | Cut SCADA→PLC auto-restore path (load/bidder/market_control) | **T0831** Manipulation of Control |
| 4. Force Market Mode | Ensure Market_Control = TRUE on target PLCs | **T0858** Change Operating Mode |
| 5. Malicious Command | Set downstream Cmd_Input = FALSE (open load/gen breaker) | **T0855** Unauthorized Command Message |
| **Impact** | Load shed on every microgrid (downstream breakers open) | **T0813** Denial of Control |

## Scripts

### Red Team: `scada_breaker_attack.py`

```
# Read current grid state (no attack)
python attacks/scada_breaker_attack.py --recon

# Open the downstream breaker on every microgrid (load on MG1-3, gen on MG4)
python attacks/scada_breaker_attack.py --all
```

`--all` is the only attack mode; it targets every microgrid and opens the
downstream breaker (LOAD on the load microgrids, GEN on MG4).

### Blue Team: `scada_breaker_recovery.py`

```
# Detect only (sensing S1)
python attacks/scada_breaker_recovery.py --detect

# Detect + restore all compromised microgrids (D1)
python attacks/scada_breaker_recovery.py --restore

# Continuous detect + auto-restore (every 5s)
python attacks/scada_breaker_recovery.py --restore --interval 5
```

Recovery closes whatever is open **main-first**: if `main` was opened it
restores `main` + the downstream breaker; a downstream-only shed restores just
that breaker. (Breaker recovery has no `--mg` — it always covers all MGs.)

### Sensing: `detection/scada_breaker_detect.py`

Read-only token sensor (see `detection/DETECTION.md`):

```
python detection/scada_breaker_detect.py          # human summary + INDICATORS line
python detection/scada_breaker_detect.py --json    # structured output
```

Tokens: `breaker_attack1..4`, `breaker_override`, `no_breaker_attack`.

## Attack Path

```
Attacker                    ScadaLTS                SCADA Gateway         PLCs (MG1-4)
   |                           |                        |                    |
   |-- brute force login ----->|                        |                    |
   |<---- session cookie ------|                        |                    |
   |                           |                        |                    |
   |-- REST: Operator_Mode=1 ->|--- Modbus write ------>|                    |
   |                           |                 (coil 12, unit 10)          |
   |                           |                        |                    |
   |-- DWR: disable links --->|  Point Links DISABLED   |                    |
   |                           |  (SCADA→PLC path cut)  |                    |
   |                           |                        |                    |
   |-- DWR: Cmd_Input=0 ----->|--- Modbus write -------|--- coils 4,5,6 --->|
   |                           |                        |   (breakers OPEN)  |
   |                           |                        |                    |
   |                           |                        |            BLACKOUT|
```

> **Why disable Point Links?** Point Links are ScadaLTS internal connections that
> continuously copy gateway shed recommendations → PLC Cmd_Input coils (~1s interval).
> Without disabling them, load/bidder breaker attacks get overwritten back to TRUE
> within the next poll cycle. Main breaker has no Point Link, so it works without
> this step.

## Detection Indicators

Under the current `--all` attack (downstream breaker only):

| Indicator | Normal | Under Attack |
|-----------|--------|--------------|
| Operator_Mode | false | **true** |
| Point Links | All ENABLED | **DISABLED** (load links cut) |
| Market_Control (MG1-3) | true (normal) | true (same) |
| Market_Control (MG4) | false (normal) | **true** (attacker forced) |
| Load_Breaker_Closed (MG1-3) | true | **false** |
| Gen_Online (MG4) | true | **false** |
| Main_Breaker_Closed | true | true (untouched) |
| Bidder_Breaker_Closed | true | true (untouched) |

> The detector/recovery still watch *all* breakers (main/load/bidder, gen), so
> they flag `main`/`bidder` too if some other action opens them.

## Requirements

- Python 3.x with `requests` library
- Running PULSE co-simulation with ScadaLTS configured (`run_experiment.py --config cosim_config_full.json`)
- ScadaLTS accessible at `localhost:8090` (or specify `--scada-url`)
- Docker access (for querying Point Links from ScadaLTS database)
