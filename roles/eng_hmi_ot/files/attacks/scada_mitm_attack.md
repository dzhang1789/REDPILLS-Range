# Man-in-the-Middle Stealth Breaker Manipulation

Stealth attack that blinds the SCADA operator, then opens circuit breakers via
direct Modbus. It disables ScadaLTS polling so the SCADA View freezes on stale
"normal" data while the physical grid is blacked out — only the God's View
(ground truth) reveals the real state.

This demonstrates why ground truth monitoring that bypasses the SCADA/PLC control
layer is essential for detecting sophisticated attacks.

## Attack Chain (MITRE ATT&CK for ICS)

| Phase | Action | MITRE ICS Technique |
|-------|--------|---------------------|
| 1. Credential Reuse | Login to ScadaLTS (admin:admin) | **T0866** Exploitation of Remote Services |
| 2. Reconnaissance | Enumerate PLC data source IDs | **T0846** Remote System Discovery |
| 3. Blind SCADA | Disable PLC data source polling via DWR | **T0856** Spoof Reporting Message |
| 4. Modbus Injection | Raw TCP to PLCs: Override + Open breakers | **T0830** Man in the Middle |
| 5. Concealment | SCADA frozen on stale "normal" values | **T0872** Indicator Removal on Host |
| **Impact** | Grid blackout, invisible to SCADA operator | **T0813** Denial of Control |

## How It Works

```
                    ScadaLTS (SCADA View)           God's View
                    =====================           ==========
Normal operation:   Polls PLC every 1s              Reads bridge JSON every 1s
                    Shows real-time values           Shows real-time values

During attack:      Polling DISABLED (frozen)        Still reads bridge JSON
                    Shows last "good" values         Shows breakers OPEN
                    Operator sees NORMAL             Ground truth: BLACKOUT

After uncloak:      Polling RE-ENABLED               Continues showing real state
                    SCADA discovers real state        No change needed
                    Operator sees BLACKOUT            (was already showing truth)
```

## Attack Sequence

```
Attacker                    ScadaLTS                   PLCs (MG1-4)
   |                           |                          |
   |-- login (admin:admin) --->|                          |
   |                           |                          |
   |-- GET datasource/getAll ->|                          |
   |<-- ds_ids: 1,2,3,4 ------|                          |
   |                           |                          |
   |-- toggleDataSource(1) --->| STOP polling MG1         |
   |-- toggleDataSource(2) --->| STOP polling MG2         |
   |-- toggleDataSource(3) --->| STOP polling MG3         |
   |-- toggleDataSource(4) --->| STOP polling MG4         |
   |                           |                          |
   |                           | (frozen on last values)  |
   |                           |                          |
   |------- raw Modbus TCP (bypass SCADA entirely) ------>|
   |         Market_Control = TRUE                       |
   |         Cmd_Input = FALSE (open breakers)            |
   |                           |                          |
   |                    SCADA shows:              Physical state:
   |                    "breakers CLOSED"         breakers OPEN
   |                    "voltage normal"          BLACKOUT
   |                           |                          |
   |  ... attacker waits ...   |                          |
   |                           |                          |
   |-- toggleDataSource(1) --->| RESUME polling           |
   |-- toggleDataSource(2) --->| RESUME polling           |
   |-- toggleDataSource(3) --->| RESUME polling           |
   |-- toggleDataSource(4) --->| RESUME polling           |
   |                           |                          |
   |                    SCADA discovers:                   |
   |                    "breakers OPEN!"                   |
   |                    ALARM                              |
```

## Scripts

### Attack: `scada_mitm_attack.py`

```
# Read current state (data-source status + ground-truth breaker states)
python attacks/scada_mitm_attack.py --recon

# Full stealth attack on all microgrids
python attacks/scada_mitm_attack.py --all

# Attack then auto-reveal after 60 seconds (re-enable SCADA polling)
python attacks/scada_mitm_attack.py --all --reveal 60
```

`--all` is the only attack mode (all microgrids). `--reveal N` auto-uncloaks
after N seconds; without it the attack holds until Ctrl+C.

### Recovery: `scada_mitm_recovery.py`

```
# Detect only (sensing S3)
python attacks/scada_mitm_recovery.py --detect

# Detect + restore (D3) — stop the attack first (it re-injects every ~0.5s)
python attacks/scada_mitm_recovery.py --restore --stop-attacker

# Continuous detect + auto-restore (every 5s)
python attacks/scada_mitm_recovery.py --restore --stop-attacker --interval 5
```

> The MITM attack re-injects continuously (Phase 6, ~0.5 s), so a bare
> `--restore` is overwritten — use `--stop-attacker` (sim-only) to stop it first.

### Sensing: `detection/scada_mitm_detect.py`

Read-only token sensor (see `detection/DETECTION.md`):

```
python detection/scada_mitm_detect.py           # human summary + INDICATORS line
python detection/scada_mitm_detect.py --json     # structured output
```

Tokens: `mitm_attack1..4`, `mitm_unknown1..4`, `no_mitm_attack`.

## Detection Comparison

| What the operator sees | SCADA View (port 8888) | God's View (port 8889) |
|------------------------|------------------------|------------------------|
| Main Breaker | closed (STALE) | **OPEN** |
| Load Breaker | closed (STALE) | **OPEN** |
| Voltage | 8660 V (STALE) | 8660.3 V (live) |
| Status | online | **attack** |
| Data freshness | Frozen (no updates) | Updating every 1s |

## Key Difference from Attack 1

| | Attack 1 (SCADA Command Injection) | Attack 2 (MITM Stealth) |
|---|---|---|
| Attack path | Through ScadaLTS API | Direct raw Modbus to PLCs |
| SCADA visibility | SCADA shows real state (attack visible) | SCADA blinded (shows stale normal) |
| Operator awareness | Operator sees breakers open immediately | Operator sees nothing wrong |
| Detection | Easy (SCADA alarms) | Hard (requires ground truth monitoring) |
| God's View | Shows same as SCADA | **Only way to detect the attack** |

## Requirements

- Python 3.x with `requests` library
- Running PULSE co-simulation with ScadaLTS configured
- Network access to PLC Modbus ports (502-505)
- ScadaLTS accessible at `localhost:8090` (or specify `--scada-url`)
