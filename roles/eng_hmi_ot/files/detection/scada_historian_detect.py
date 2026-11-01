#!/usr/bin/env python3
"""
Blue Team Sensing: Historian Tampering Failure Indicators
=========================================================
Detection-only companion to scada_historian_recovery.py. It NEVER changes the
database — it only reads and emits a compact machine-readable indicator token
for the historian tampering attack (scada_historian_attack.py --all: event-log
deletion).

The attack deletes the alarm/event log system-wide (events are not tied to a
single microgrid), so detection is a single global signal — there is no per-MG
token.

Indicator tokens (printed alone by default; `--verbose` shows them on an
`INDICATORS:` line under a full report):

    historian_attack     alarm/event records were deleted (recent window wiped)
    no_historian_attack  no indicators found — the event log is intact

Detection compares the event count in the last --minutes window against the
prior window of equal length; a sharp drop (or an empty recent window) means
events were deleted. Run detection within a few minutes of a suspected attack:
the live system writes ~25 events/min, so a deleted window refills over time.

This reuses the proven detection routine from scada_historian_recovery.detect().

Exit code: 0 if clean, 1 if any tampering indicator present, 2 on DB error
(so it can drive shell conditionals).

Usage:
    python detection/scada_historian_detect.py                    # last 10 min
    python detection/scada_historian_detect.py --minutes 30       # last 30 min
    python detection/scada_historian_detect.py --json             # structured output
    python detection/scada_historian_detect.py --env-file deployment/prod.env

MITRE ATT&CK ICS: D3-PSA (Process State Awareness), D3-ORA (Operational Risk Assessment)
"""

import argparse
import contextlib
import json
import os
import sys

# env_loader.py is bundled in this folder; the reused recovery modules live in
# the sibling attacks/ directory — append it so they can be imported (this
# folder stays first on the path, so the local env_loader is used).
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'attacks'))

# Reuse the tested detection machinery; do not duplicate it.
import scada_historian_recovery as hist

# Event-deletion finding types emitted by detect_event_anomalies().
EVENT_FINDING_TYPES = {'NO_EVENTS', 'EVENTS_DELETED', 'EVENTS_REDUCED'}


@contextlib.contextmanager
def _silence(enabled):
    """Suppress stdout from the reused (chatty) detection routine unless verbose."""
    if not enabled:
        yield
        return
    with open(os.devnull, 'w') as devnull, contextlib.redirect_stdout(devnull):
        yield


def build_report(findings):
    """Map event-deletion findings to reasons and the global token.

    The attack deletes the event log system-wide, so this is a single global
    signal (`historian_attack`), not per-microgrid.
    """
    reasons = [f"{f['type']}: {f['message']}"
               for f in findings if f.get('type') in EVENT_FINDING_TYPES]

    tampered = bool(reasons)
    tokens = ["historian_attack"] if tampered else ["no_historian_attack"]

    return {
        'tokens': tokens,
        'tampered': tampered,
        'reasons': reasons,
    }


def print_human(report):
    if report['tampered']:
        print(f"  [EVENT LOG] TAMPERED ({len(report['reasons'])}):")
        for r in report['reasons']:
            print(f"      - {r}")
    else:
        print("  [EVENT LOG] ok")

    print()
    print(f"INDICATORS: {' '.join(report['tokens'])}")


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team sensing: emit historian tampering indicators (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python detection/scada_historian_detect.py                 # last 10 min
    python detection/scada_historian_detect.py --minutes 30    # last 30 min
    python detection/scada_historian_detect.py --json          # JSON for tooling/RL

Indicator tokens: historian_attack, no_historian_attack
        """
    )
    parser.add_argument('--minutes', type=int, default=10,
                        help='Detection window in minutes (default: 10)')
    parser.add_argument('--json', action='store_true',
                        help='Emit a single JSON object instead of human text')
    parser.add_argument('--db-host', default='localhost',
                        help='MySQL host (default: localhost)')
    parser.add_argument('--db-port', type=int, default=3306,
                        help='MySQL port (default: 3306)')
    parser.add_argument('--tcp', action='store_true',
                        help='Use direct TCP for DB access (default: docker exec)')
    parser.add_argument('--env-file', default=None,
                        help='Load service addresses from env file (e.g., deployment/prod.env)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show the full human report (default: print only the tokens)')

    args = parser.parse_args()

    # Override DB address from env file (does NOT auto-switch to --tcp; the
    # scada_database container has no published host port in the generated
    # compose, so docker exec is the reliable path unless --tcp is given).
    if args.env_file:
        from env_loader import load_env_file, resolve_addresses
        addrs = resolve_addresses(load_env_file(args.env_file))
        if args.db_host == 'localhost':
            args.db_host = addrs['db_host']
        if args.db_port == 3306:
            args.db_port = addrs['db_port']

    use_docker = not args.tcp

    if args.verbose:
        print("=" * 65)
        print("  Blue Team Sensing: Historian Tampering Indicators")
        print("=" * 65)
        print(f"  Scope: event log (system-wide)")
        print(f"  Window: {args.minutes} minutes")
        print(f"  DB access: {'docker exec' if use_docker else f'TCP {args.db_host}:{args.db_port}'}")
        print()

    defender = hist.HistorianDefender(
        db_host=args.db_host, db_port=args.db_port,
        use_docker=use_docker, verbose=args.verbose,
    )

    with _silence(not args.verbose):
        connected = defender.connect()
    if not connected:
        if args.json:
            print(json.dumps({'error': 'db_connection_failed', 'tokens': []}))
        else:
            print("error: MySQL connection failed", file=sys.stderr)
        sys.exit(2)

    with _silence(not args.verbose):
        findings = defender.detect(args.minutes)

    report = build_report(findings)

    if args.json:
        print(json.dumps({
            'minutes': args.minutes,
            'tokens': report['tokens'],
            'tampered': report['tampered'],
            'reasons': report['reasons'],
        }))
    elif args.verbose:
        print_human(report)
    else:
        print(' '.join(report['tokens']))

    sys.exit(1 if report['tampered'] else 0)


if __name__ == '__main__':
    main()

