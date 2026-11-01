#!/usr/bin/env python3
"""
Blue Team Defence: Detect & Recover from Historian Tampering (AV-12)
====================================================================
Counter-action for scada_historian_attack.py — event-log deletion.

Detection (S6):
  - Compares the recent event-count to a prior-window baseline; a sharp drop
    (or an empty recent window) means alarm/event records were deleted.

Recovery (D5):
  - Cannot undo deleted events (data loss is permanent).
  - Exports a forensic snapshot of the current event log for investigation.

Because the attack deletes the event log system-wide (events are not tied to a
single microgrid), detection is a single global signal, not per-MG.

Usage:
    # Detection only (S6 sensing) — scan for event-deletion indicators
    python attacks/scada_historian_recovery.py --detect

    # Export forensic snapshot (D5 defence)
    python attacks/scada_historian_recovery.py --forensic

    # Continuous monitoring
    python attacks/scada_historian_recovery.py --detect --interval 30

    # Remote database
    python attacks/scada_historian_recovery.py --detect --env-file deployment/prod.env

MITRE ATT&CK ICS: D3-PSA (Process State Awareness), D3-ORA (Operational Risk Assessment)
"""

import argparse
import datetime
import subprocess
import sys
import time


# ScadaLTS event source types (events.typeId) — for forensic breakdown.
EVENT_TYPE_NAMES = {
    1: 'Point alarm', 2: 'Data source', 3: 'System', 4: 'Compound',
    5: 'Scheduled', 6: 'Publisher', 8: 'Audit',
}

# A recent window holding less than this fraction of the baseline count is
# treated as a deletion (90%+ drop). Natural event-rate variation rarely
# drops this far, so it is a low-false-positive signal.
DELETION_DROP_FRACTION = 0.1
# A softer drop (recent < this fraction of baseline) is flagged as a weaker
# "reduced" anomaly worth a look.
REDUCED_DROP_FRACTION = 0.5
# Minimum baseline event count before the ratio checks are meaningful.
MIN_BASELINE_EVENTS = 5


class HistorianDefender:
    """Blue team: detect event-log deletion and export forensic data."""

    def __init__(self, db_host='localhost', db_port=3306, use_docker=True, verbose=False):
        self.db_host = db_host
        self.db_port = db_port
        self.use_docker = use_docker
        self.verbose = verbose
        self.db_user = None
        self.db_pass = None
        self.connection = None

    def log(self, msg):
        if self.verbose:
            print(f"  [*] {msg}")

    # ------------------------------------------------------------------
    # Database access
    # ------------------------------------------------------------------
    def _query_docker(self, sql):
        try:
            cmd = ['docker', 'exec', 'scada_database', 'mysql',
                   '-u', self.db_user, f'-p{self.db_pass}', 'scadalts',
                   '-e', sql, '-N']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                self.log(f"MySQL error: {result.stderr.strip()}")
                return None
            return result.stdout
        except Exception as e:
            self.log(f"Docker exec failed: {e}")
            return None

    def _query_direct(self, sql):
        if not self.connection:
            return None
        try:
            cursor = self.connection.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            return '\n'.join('\t'.join(str(c) for c in row) for row in rows)
        except Exception as e:
            self.log(f"Query failed: {e}")
            return None

    def query(self, sql):
        if self.use_docker:
            return self._query_docker(sql)
        else:
            return self._query_direct(sql)

    def _scalar(self, sql, default=0):
        result = self.query(sql)
        if result and result.strip():
            try:
                return int(result.strip().split('\t')[0])
            except (ValueError, IndexError):
                return default
        return default

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def connect(self):
        """Connect to MySQL database."""
        print("[+] Connecting to MySQL database...")
        credentials = [('root', 'root'), ('scadalts', 'scadalts')]

        if self.use_docker:
            for user, passwd in credentials:
                try:
                    cmd = ['docker', 'exec', 'scada_database', 'mysql',
                           '-u', user, f'-p{passwd}', 'scadalts',
                           '-e', 'SELECT 1;', '-N']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.db_user = user
                        self.db_pass = passwd
                        print(f"    [OK] Connected via docker exec ({user})")
                        return True
                except Exception:
                    continue
            print("    [FAIL] Cannot connect via docker exec")
            return False
        else:
            try:
                import mysql.connector
            except ImportError:
                print("    [FAIL] mysql-connector-python not installed")
                return False
            for user, passwd in credentials:
                try:
                    conn = mysql.connector.connect(
                        host=self.db_host, port=self.db_port,
                        user=user, password=passwd, database='scadalts',
                        connect_timeout=5,
                    )
                    self.connection = conn
                    self.db_user = user
                    self.db_pass = passwd
                    print(f"    [OK] Connected via TCP {self.db_host}:{self.db_port} ({user})")
                    return True
                except Exception:
                    continue
            print(f"    [FAIL] Cannot connect to {self.db_host}:{self.db_port}")
            return False

    def _ts_to_str(self, ts_ms):
        try:
            return datetime.datetime.fromtimestamp(int(ts_ms) / 1000).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError):
            return str(ts_ms)

    # ------------------------------------------------------------------
    # Detection: Event-log deletion (count vs baseline)
    # ------------------------------------------------------------------
    def detect_event_anomalies(self, minutes):
        """Detect deleted alarm/event records.

        Compares the event count in the recent --minutes window to the prior
        window of equal length. The attack deletes the recent window, so recent
        collapses toward zero while the untouched baseline stays populated.
        Uses `activeTs` (the events table's timestamp column — there is no
        `ts` column on events).
        """
        findings = []

        total = self._scalar("SELECT COUNT(*) FROM events;")
        recent = self._scalar(
            f"SELECT COUNT(*) FROM events "
            f"WHERE activeTs > UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000;"
        )
        baseline = self._scalar(
            f"SELECT COUNT(*) FROM events "
            f"WHERE activeTs BETWEEN UNIX_TIMESTAMP(NOW() - INTERVAL {minutes * 2} MINUTE) * 1000 "
            f"AND UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000;"
        )
        self.log(f"events: total={total} recent={recent} baseline={baseline}")

        if total == 0:
            findings.append({
                'type': 'NO_EVENTS',
                'recent': recent, 'baseline': baseline,
                'message': 'Event table is EMPTY (all events deleted)',
            })
        elif baseline >= MIN_BASELINE_EVENTS and recent < baseline * DELETION_DROP_FRACTION:
            findings.append({
                'type': 'EVENTS_DELETED',
                'recent': recent, 'baseline': baseline,
                'message': (f'{recent} events in last {minutes} min vs {baseline} in the '
                            f'prior window (>{int((1-DELETION_DROP_FRACTION)*100)}% drop — deletion)'),
            })
        elif baseline >= MIN_BASELINE_EVENTS and recent < baseline * REDUCED_DROP_FRACTION:
            findings.append({
                'type': 'EVENTS_REDUCED',
                'recent': recent, 'baseline': baseline,
                'message': (f'{recent} events in last {minutes} min vs {baseline} baseline '
                            f'(partial reduction — possible deletion)'),
            })

        return findings

    # ------------------------------------------------------------------
    # Combined Detection
    # ------------------------------------------------------------------
    def detect(self, minutes):
        """Run event-deletion detection. Returns list of findings."""
        print("[+] Checking event-log integrity (recent vs baseline)...")
        return self.detect_event_anomalies(minutes)

    def print_findings(self, findings):
        """Print detection results."""
        print()
        if not findings:
            print("  No event-deletion indicators detected")
            return

        print(f"  ALERT: {len(findings)} tampering indicator(s) found:")
        print()

        type_labels = {
            'NO_EVENTS': 'Event Table Empty',
            'EVENTS_DELETED': 'Events Deleted (Recent Window Wiped)',
            'EVENTS_REDUCED': 'Event Count Anomaly (Partial Reduction)',
        }
        for item in findings:
            label = type_labels.get(item['type'], item['type'])
            print(f"  --- {label} ---")
            print(f"    {item['message']}")
            print()

    # ------------------------------------------------------------------
    # Forensic Snapshot
    # ------------------------------------------------------------------
    def forensic_snapshot(self, minutes):
        """Export a forensic snapshot of the event log for investigation."""
        print("[+] Exporting forensic snapshot...")
        print()

        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        print(f"  Snapshot time: {ts}")
        print(f"  Window: last {minutes} minutes")
        print()

        # Table row counts
        print("  --- Table Row Counts ---")
        for table in ['events', 'userEvents', 'pointValues', 'dataPoints', 'pointLinks']:
            count = self._scalar(f"SELECT COUNT(*) FROM {table};", default=-1)
            shown = 'N/A' if count < 0 else str(count)
            print(f"    {table:<20} {shown:>10} rows")
        print()

        # Event counts: recent window vs baseline
        recent = self._scalar(
            f"SELECT COUNT(*) FROM events "
            f"WHERE activeTs > UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000;"
        )
        baseline = self._scalar(
            f"SELECT COUNT(*) FROM events "
            f"WHERE activeTs BETWEEN UNIX_TIMESTAMP(NOW() - INTERVAL {minutes * 2} MINUTE) * 1000 "
            f"AND UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000;"
        )
        print("  --- Event Counts ---")
        print(f"    Recent {minutes} min (window):   {recent:>8}")
        print(f"    Prior  {minutes} min (baseline): {baseline:>8}")
        print()

        # Event breakdown by type in window
        print("  --- In-Window Events by Type ---")
        result = self.query(
            f"SELECT typeId, COUNT(*) AS cnt FROM events "
            f"WHERE activeTs > UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000 "
            f"GROUP BY typeId ORDER BY cnt DESC;"
        )
        if result and result.strip():
            for line in result.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    tid = int(parts[0])
                    tname = EVENT_TYPE_NAMES.get(tid, f'Type {tid}')
                    print(f"    {tname:<20} {parts[1]:>8} events")
        else:
            print("    No events in window")
        print()

        # Oldest/newest event timestamps
        print("  --- Event Log Extent ---")
        result = self.query("SELECT MIN(activeTs), MAX(activeTs) FROM events;")
        if result and result.strip():
            parts = result.strip().split('\t')
            if len(parts) >= 2 and parts[0] not in ('NULL', ''):
                print(f"    oldest={self._ts_to_str(parts[0])}  newest={self._ts_to_str(parts[1])}")

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None


def stop_attacker():
    """Kill the local attack process — SIM-ONLY convenience. No-op if no such
    process is running (the historian attack is one-shot). Provided for a
    uniform recovery interface; real incidents can't kill the adversary."""
    import subprocess
    script = 'scada_historian_attack.py'
    try:
        r = subprocess.run(['pkill', '-f', f'python.*{script}'], capture_output=True, text=True)
    except FileNotFoundError:
        print(f"    [--] 'pkill' not available — stop {script} manually")
        return
    if r.returncode == 0:
        print(f"    [OK] Stopped local attack process ({script})")
    else:
        print(f"    [--] No running {script} found")


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team: Detect & recover from historian tampering (AV-12)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
    --detect      Sensing (S6) — scan for event-deletion indicators
    --forensic    Defence (D5) — export forensic event-log snapshot

Examples:
    # S6: Detect event deletion (last 10 min)
    python attacks/scada_historian_recovery.py --detect

    # S6: Detect over a longer time window
    python attacks/scada_historian_recovery.py --detect --minutes 120

    # D5: Export forensic snapshot
    python attacks/scada_historian_recovery.py --forensic

    # Continuous monitoring (every 30s)
    python attacks/scada_historian_recovery.py --detect --interval 30

    # Remote database
    python attacks/scada_historian_recovery.py --detect --env-file deployment/prod.env
        """
    )
    parser.add_argument('--detect', action='store_true',
                        help='Sensing (S6) — scan for event-deletion indicators')
    parser.add_argument('--forensic', action='store_true',
                        help='Defence (D5) — export forensic event-log snapshot')
    parser.add_argument('--stop-attacker', action='store_true',
                        help='Kill the local attack process first (SIM-ONLY)')

    parser.add_argument('--minutes', type=int, default=10,
                        help='Time window in minutes (default: 10)')
    parser.add_argument('--interval', type=int, default=0,
                        help='Continuous loop interval in seconds (0 = one-shot)')

    parser.add_argument('--db-host', default='localhost',
                        help='MySQL host (default: localhost)')
    parser.add_argument('--db-port', type=int, default=3306,
                        help='MySQL port (default: 3306)')
    parser.add_argument('--docker', action='store_true', default=True,
                        help='Use docker exec for DB access (default)')
    parser.add_argument('--tcp', action='store_true',
                        help='Use direct TCP for DB access')
    parser.add_argument('--env-file', default=None,
                        help='Load service addresses from env file (e.g., deployment/prod.env)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # Override defaults from env file
    if args.env_file:
        from env_loader import load_env_file, resolve_addresses
        addrs = resolve_addresses(load_env_file(args.env_file))
        if args.db_host == 'localhost':
            args.db_host = addrs['db_host']
        if args.db_port == 3306:
            args.db_port = addrs['db_port']
        # Do NOT auto-switch to --tcp: the scada_database container has no host
        # port published in the generated scada_service compose, so docker exec is the
        # only reliable path when running on scada_service. Pass --tcp explicitly if
        # you truly need TCP access.

    if not args.detect and not args.forensic and not args.stop_attacker:
        parser.print_help()
        sys.exit(1)

    if args.stop_attacker:
        print("[+] Stopping local attack process (sim-only)...")
        stop_attacker()
        print()
        if not args.detect and not args.forensic:
            sys.exit(0)

    use_docker = not args.tcp

    # Determine mode
    if args.detect and args.interval > 0:
        mode = f"Detect (S6 — continuous, every {args.interval}s)"
    elif args.detect:
        mode = "Detect (S6 — one-shot)"
    else:
        mode = "Forensic Snapshot (D5)"

    print("=" * 65)
    print("  Blue Team: Historian Tampering Detection & Forensics")
    print("=" * 65)
    print(f"  Mode: {mode}")
    print(f"  Scope: event log (system-wide)")
    print(f"  Window: {args.minutes} minutes")
    print(f"  DB access: {'docker exec' if use_docker else f'TCP {args.db_host}:{args.db_port}'}")
    print()

    defender = HistorianDefender(
        db_host=args.db_host, db_port=args.db_port,
        use_docker=use_docker, verbose=args.verbose,
    )

    if not defender.connect():
        sys.exit(1)
    print()

    # --detect mode
    if args.detect:
        if args.interval > 0:
            print(f"[+] Continuous monitoring every {args.interval}s (Ctrl+C to stop)...")
            print()
            try:
                while True:
                    findings = defender.detect(args.minutes)
                    ts = time.strftime('%H:%M:%S')
                    if findings:
                        print(f"  [{ts}] ALERT: {len(findings)} tampering indicator(s)")
                        defender.print_findings(findings)
                    else:
                        print(f"  [{ts}] OK — no event deletion detected")
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                print("\n  Monitoring stopped.")
        else:
            findings = defender.detect(args.minutes)
            defender.print_findings(findings)

    # --forensic mode
    if args.forensic:
        defender.forensic_snapshot(args.minutes)

    defender.close()

    print()
    print("=" * 65)
    print("  Done!")
    print("=" * 65)


if __name__ == '__main__':
    main()

