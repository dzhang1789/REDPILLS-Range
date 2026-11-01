# Market Manipulation Attack (False Scarcity)

Attack against the SCADA Gateway's market layer that fabricates an energy
scarcity, then forces bidder-load shedding on the microgrids. Because the
spoofed market data makes the shedding look economically justified, the operator
sees a plausible "market crisis" while the grid is actually being attacked.

Paired with a blue team recovery script that detects and reverses the
manipulation.

## Attack Chain (MITRE ATT&CK for ICS)

| Phase | Action | MITRE ICS Technique |
|-------|--------|---------------------|
| 1. Reconnaissance | Read current market registers/coils on the gateway | **T0846** Remote System Discovery |
| 2. Spoof Market Data | Write false registers: generation ≈ fixed demand, surplus ≈ 0, price spike | **T0836** Modify Parameter |
| 3. Recommend Shedding | Set gateway bidder-shed + override coils TRUE | **T0831** Manipulation of Control |
| 4. Malicious Command | Inject to PLCs: Market_Control = TRUE, Bidder_Cmd_Input = FALSE (open bidder breaker; gen on MG4) | **T0855** Unauthorized Command Message |
| 5. Persist | Re-inject every `--interval` s to beat the gateway's ~1 s overwrite cycle | **T0856** Spoof Reporting Message |
| **Impact** | Bidder loads disconnected; economic disruption, disguised as a legitimate market outcome | **T0813** Denial of Control |

No credentials are required — the SCADA Gateway's Modbus server (`:5020`,
unit 10) is directly writable.

## Scripts

### Red Team: `scada_market_attack.py`

```
# Read current market state (no attack)
python attacks/scada_market_attack.py --recon

# Attack all microgrids (default) — runs until Ctrl+C
python attacks/scada_market_attack.py --all

# Attack all microgrids for a fixed 60 seconds
python attacks/scada_market_attack.py --all --duration 60
```

`--all` is the only attack mode (targets every microgrid; opens the bidder
breaker on MG1–3 and the gen breaker on MG4). `--duration` defaults to `0`
(run until Ctrl+C); `--interval` (default `1.0` s) is the re-inject cadence
that keeps the spoof + open breaker sticking against the gateway overwrite.

### Blue Team: `scada_market_recovery.py`

```
# Detect only (sensing S2)
python attacks/scada_market_recovery.py --detect

# Detect + restore (D2) — stop the attack first (it re-injects every ~1s)
python attacks/scada_market_recovery.py --restore --stop-attacker

# Continuous detect + auto-restore (every 5s)
python attacks/scada_market_recovery.py --restore --stop-attacker --interval 5
```

> The market attack re-injects continuously (~1 s), so a bare `--restore` is
> overwritten — use `--stop-attacker` (sim-only) to stop it first.

### Sensing: `detection/scada_market_detect.py`

Read-only token sensor (see `detection/DETECTION.md`):

```
python detection/scada_market_detect.py            # human summary + INDICATORS line
python detection/scada_market_detect.py --json      # structured output for tooling/RL
```

Tokens: `market_attack1..3`, `market_spoof`, `no_market_attack`
(no `market_attack4` — MG4 is the generator, no bidder load).

## Attack Path

```
Attacker                 SCADA Gateway (:5020)        ScadaLTS            PLCs (MG1-4)
   |                          |                          |                    |
   |-- read market state ---->|                          |                    |
   |<--- registers/coils -----|                          |                    |
   |                          |                          |                    |
   |-- spoof registers ------>|  surplus=0, gen≈fixed,    |                    |
   |   (false scarcity)       |  price spike             |                    |
   |                          |                          |                    |
   |-- set shed coils ------->|  bidder_shed=1,          |                    |
   |                          |  override=1              |                    |
   |                          |----- polled by --------->| "shedding looks    |
   |                          |                          |  legitimate"       |
   |                          |                          |                    |
   |-- inject to PLC (Modbus) ----------------------------------------------->|
   |   Market_Control=1, Bidder_Cmd_Input=0                (bidder breaker OPEN)
   |                          |                          |                    |
   |-- re-inject every ~1s (beat gateway overwrite) ------------------------->|
```

> **Why re-inject?** The gateway rewrites its shed/breaker outputs roughly once
> per second. A single injection is overwritten within a cycle, so the attack
> re-asserts the spoofed registers and the open bidder breaker every `--interval`
> seconds for the duration of the attack.

## Detection Indicators

| Indicator | Normal | Under Attack |
|-----------|--------|--------------|
| Clearing price | market rate | **≥ $80/MWh** (spike) |
| Surplus / Generation | > 0 | **0 / 0** (false scarcity) |
| Bidder-shed coil (MG1-3) | off | **ON** |
| Allocation vs bid | alloc > 0 | **alloc = 0 while bid > 0** |
| Market_Control (MG4) | false (normal) | **true** (attacker forced) |
| Bidder_Breaker_Closed (MG1-3) | true | **false** |
| Gen_Online (MG4) | true | **false** |
| Operator_Mode | false | may be **true** |

## Requirements

- Python 3.x with `requests` (Modbus is stdlib-only in this script)
- Running PULSE co-simulation with the SCADA Gateway reachable at `localhost:5020`
  (or specify `--gateway-host` / `--env-file`)
- PLC Modbus ports reachable (`502-505`) for the direct injection step
