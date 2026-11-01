# Data Historian Tampering Attack: ScadaLTS MySQL History Deletion

Directly accesses the ScadaLTS MySQL database and **deletes** historical
measurement records for every microgrid within a time window. Primarily used as
a post-attack tool to erase evidence after a physical attack (breaker / market /
MITM), leaving no time-series record of the event.

> This attack has a single destructive mode — `--all` (delete history) — plus a
> read-only `--recon`. (Earlier falsify / inject / event-wipe / corrupt modes
> were removed to keep the attack focused; deletion is what the detector is
> validated against.)

## Attack Chain (MITRE ATT&CK for ICS)

| Phase | Action | MITRE ICS Technique |
|-------|--------|---------------------|
| 1. Credential Brute Force | Try default MySQL credentials (root:root, scadalts:scadalts) | **T0812** Default Credentials |
| 2. Reconnaissance | Read DB stats, table sizes, point counts, time ranges | **T0811** Data from Information Repositories |
| 3. History Deletion | Delete `pointValues` records for all MGs in the time window | **T0809** Data Destruction |
| **Impact** | Destroyed forensic evidence; the attack window simply has no records | **T0813** Denial of Control |

## How It Works

```
Normal data flow:
    GridLAB-D → HELICS → Bridge → PLC → ScadaLTS → MySQL (pointValues table)
                                                         ↑
                                                    ~1-second poll interval
                                                    stores voltage, breaker, load readings

During attack:
    Attacker → docker exec scada_database mysql    (or direct TCP :3306)
                         ↓
                    ScadaLTS MySQL
                    └── pointValues: DELETE rows in the time window

After attack:
    Operator/investigator sees:
    └── A hole in the history — no voltage/breaker records for the attack window
```

## Architecture

```
Access method 1 — Docker exec (same host, default):
    Attacker ──docker exec scada_database mysql──► MySQL (:3306 internal)

Access method 2 — Direct TCP (distributed deployment, --tcp):
    Attacker ──TCP──► scada_service:3306 ──► MySQL

Target database: scadalts
    ├── pointValues    Time-series measurements (voltage, power, breaker state)  ← target
    └── dataPoints     Point definitions (XID → ID mapping)
```

## Target Data Points

Deletion covers each microgrid's voltage and breaker points (resolved XID → ID
at runtime).

| MG | Voltage (3-phase) | Breakers |
|----|-------------------|----------|
| MG1 | `DP_MG1_PLC_Voltage_A/B/C` | `Main_Breaker_Closed`, `Load_Breaker_Closed`, `Bidder_Breaker_Closed` |
| MG2 | `DP_MG2_PLC_Voltage_A/B/C` | `Main_Breaker_Closed`, `Load_Breaker_Closed`, `Bidder_Breaker_Closed` |
| MG3 | `DP_MG3_PLC_Voltage_A/B/C` | `Main_Breaker_Closed`, `Load_Breaker_Closed`, `Bidder_Breaker_Closed` |
| MG4 | `DP_MG4_PLC_Voltage_A/B/C` | `Main_Breaker_Closed`, `Gen_Online` |

## Attack Modes

### Read-Only Reconnaissance (`--recon`)
Shows database statistics without modifying anything: table sizes and row
counts, point value history range (oldest/newest), records per data point,
event counts, and the XID → numeric ID mapping.

### History Deletion (`--all`)
Deletes `pointValues` records for all microgrids within the time window
(`--minutes`, default 60).

```sql
DELETE FROM pointValues
WHERE dataPointId IN (resolved_ids)
AND ts > UNIX_TIMESTAMP(NOW() - INTERVAL N MINUTE) * 1000;
```

**Effect:** Creates a gap (or a fully empty window) in the time series.
Deletion is **permanent** — the records cannot be recovered.

## CIA Impact

| CIA Pillar | Level | Justification |
|-----------|-------|---------------|
| **Confidentiality** | HIGH | Brute-forces MySQL credentials; `--recon` reads all historical data and point configs |
| **Integrity** | HIGH | Permanently deletes historical records |
| **Availability** | MEDIUM | No direct power outage, but destroys forensic evidence and undermines compliance/trending |

## Scripts

### Attack: `scada_historian_attack.py`

```bash
# Read-only recon (safe)
python attacks/scada_historian_attack.py --recon

# Delete history for all microgrids (default window = last 60 min)
python attacks/scada_historian_attack.py --all

# Delete the last 30 minutes for all microgrids
python attacks/scada_historian_attack.py --all --minutes 30

# Remote database (distributed deployment)
python attacks/scada_historian_attack.py --all --env-file deployment/prod.env
python attacks/scada_historian_attack.py --all --db-host 192.168.10.40 --tcp
```

`--all` and `--recon` are the only modes; `--all` always targets every
microgrid (no per-MG selection) and deletes its history.

### Detection: `scada_historian_recovery.py --detect` (S6 Sensing)

```bash
# One-shot detection across all MGs (last 60 min)
python attacks/scada_historian_recovery.py --detect

# Detect over a longer time window
python attacks/scada_historian_recovery.py --detect --minutes 120

# Continuous monitoring (every 30 seconds)
python attacks/scada_historian_recovery.py --detect --interval 30
```

### Forensics: `scada_historian_recovery.py --forensic` (D5 Defence)

```bash
# Export forensic snapshot (baseline for investigation)
python attacks/scada_historian_recovery.py --forensic
python attacks/scada_historian_recovery.py --forensic --minutes 120
```

### Sensing: `detection/scada_historian_detect.py`

Read-only token sensor (see `detection/DETECTION.md`):

```bash
python detection/scada_historian_detect.py --minutes 60          # human + INDICATORS line
python detection/scada_historian_detect.py --minutes 30 --json    # structured output
```

Tokens: `historian_attack1..4`, `historian_events`, `no_historian_attack`.

## Detection Methods (S6 Sensing)

The recovery detector runs several independent checks; the ones that fire for a
deletion are marked below. (The other checks remain in place to catch any
manual/other tampering.)

| Check | What It Detects | Indicator | Fires on delete? |
|-------|----------------|-----------|------------------|
| Gap Analysis | Missing records | `GAP`, `NO_DATA` | **YES** — gap > 10 s, or an empty window |
| Record Density | Bulk deletion | `DENSITY_DROP` | **YES** — 70%+ drop vs prior window |
| Uniform Value | Fabricated data | `UNIFORM` | no |
| Event Record | Deleted alarms | `EVENTS_DELETED` | no (deletion no longer touches events) |
| Statistical Shift | Drift/scale | `STATISTICAL_SHIFT` | no |
| Cross-Phase | Single-phase corruption | `PHASE_DIVERGENCE` | no |
| Data Replay | Replayed old data | `DATA_REPLAY` | no |

**Window guidance:** pick a `--minutes` window at least as large as the deletion
you want to catch. A deletion right up to "now" shows as `NO_DATA` /
`DENSITY_DROP` rather than a clean `GAP` (there's no later record to bracket the
hole).

## Detection Limitations

| Limitation | Impact |
|-----------|--------|
| **Cannot undo deletion** | Deleted records are permanently lost — detection + forensic export is the only defence |
| **No baseline comparison** | Detection compares recent vs prior window; if both are wiped, no anomaly is visible |
| **Tail deletion** | A deletion up to "now" can't form a bracketed gap; relies on `NO_DATA` / density drop |

## Database Schema Reference

```sql
-- Target: time-series measurements
pointValues (
    dataPointId INT,      -- FK to dataPoints.id
    dataType    INT,      -- 1 = numeric, 2 = binary
    pointValue  VARCHAR,  -- Value (voltage in V, breaker state as 0/1)
    ts          BIGINT    -- Timestamp (milliseconds since epoch)
);

-- Point definition (used for XID → ID resolution)
dataPoints (
    id  INT,
    xid VARCHAR   -- e.g., 'DP_MG1_PLC_Voltage_A'
);
```

## Requirements

- Python 3.x
- Running PULSE co-simulation with ScadaLTS and its MySQL database
- **Docker exec mode** (default): Docker access to the `scada_database` container
- **Direct TCP mode** (`--tcp`): `mysql-connector-python` + network access to port 3306
- Credentials: default `root:root` or `scadalts:scadalts` (brute-forced automatically)
