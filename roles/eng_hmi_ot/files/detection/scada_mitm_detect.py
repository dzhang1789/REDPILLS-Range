#!/usr/bin/env python3
"""
Blue Team Sensing: MITM Attack Failure Indicators
=================================================
Detection-only companion to scada_mitm_recovery.py. It NEVER changes grid
state — it only reads and emits compact machine-readable indicator tokens for
the MITM breaker-manipulation attack (scada_mitm_attack.py). It flags both the
blinding variant (PLC data source disabled) and any data-source redirection
(proxy) that remains visible in the ScadaLTS configuration.

Indicator tokens (printed alone by default; `--verbose` shows them on an
`INDICATORS:` line under a full report):

    mitm_attack1    MG1 shows MITM attack indicators
    mitm_attack2    MG2 shows MITM attack indicators
    mitm_attack3    MG3 shows MITM attack indicators
    mitm_attack4    MG4 shows MITM attack indicators
    mitm_unknown1   MG1 PLC unreachable — no ground truth, state unknown
                    (only when no other indicator flagged that MG)
    no_mitm_attack  no indicators found — grid clean

The trailing number is the microgrid id (mg1 -> 1, ... mg4 -> 4).

An MG is flagged as MITM ONLY by the MITM *mechanism* — unique to this attack:
  - its ScadaLTS PLC data source is DISABLED (SCADA blinded), or
  - its data source is REDIRECTED to a proxy host (stealth MITM).

An open breaker on its own is NOT attributed to MITM: a SCADA-path breaker
attack or a market attack opens breakers too, without blinding. The direct
Modbus ground-truth read (breakers OPEN, MG4 Market_Control override) is used
only to *corroborate* a confirmed blinding — the MITM signature is SCADA showing
stale-closed while the breaker is physically open. This keeps MITM attribution
distinct from the breaker/market detectors (see DETECTION.md § Attribution).

This reuses the proven detection routine from scada_mitm_recovery.detect().

Exit code: 0 if clean, 1 if any MITM indicator present, 2 on connection error
(so it can drive shell conditionals).

Usage:
    python detection/scada_mitm_detect.py                  # all microgrids
    python detection/scada_mitm_detect.py --mg mg1 mg3     # subset
    python detection/scada_mitm_detect.py --json           # structured output
    python detection/scada_mitm_detect.py --env-file deployment/prod.env

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
import scada_mitm_recovery as mitm

DEFAULT_ENV_FILE = mitm.DEFAULT_ENV_FILE
ALL_TARGETS = ['mg1', 'mg2', 'mg3', 'mg4']


def mg_num(mg_id):
    """'mg3' -> 3."""
    return int(mg_id[2:])


@contextlib.contextmanager
def _silence(enabled):
    """Suppress stdout from the reused login/detect routines unless verbose."""
    if not enabled:
        yield
        return
    with open(os.devnull, 'w') as devnull, contextlib.redirect_stdout(devnull):
        yield


def mg_indicators(findings, mg_id):
    """Return the list of MITM indicator reasons for one microgrid (empty = clean).

    Attribution keys on the MITM *mechanism* — the SCADA data source being
    DISABLED (blinding) or REDIRECTED (proxy). Those are unique to MITM: no
    other attack touches ScadaLTS data sources. An open breaker on its own is
    NOT attributed to MITM (a SCADA-path breaker attack or a market attack opens
    breakers too, without blinding) — the direct-Modbus read is used only to
    corroborate a confirmed blinding, which is the MITM signature (SCADA shows
    stale-closed while the breaker is physically open).
    """
    ds_name = f"{mg_id.upper()}_PLC"

    blinded = ds_name in findings['disabled_ds']
    redirected = next(
        (rd for rd in findings['redirected_ds'] if rd['name'] == ds_name), None)

    # No blinding/redirect => not a MITM attack, regardless of breaker state.
    if not blinded and not redirected:
        return []

    reasons = []
    if blinded:
        reasons.append("data source DISABLED (SCADA blinded)")
    if redirected:
        reasons.append(
            f"data source REDIRECTED to {redirected['current_host']}:{redirected['current_port']}")

    # Corroborating impact (only reported once MITM is confirmed).
    open_brk = findings['open_breakers'].get(mg_id)
    if open_brk:  # non-empty list
        reasons.append(f"breakers OPEN under blinding (ground truth): {', '.join(open_brk)}")
    if mg_id == 'mg4' and findings['plc_overrides'].get('mg4') is True:
        reasons.append("Market_Control override TRUE")

    return reasons


def build_report(findings, targets):
    """Compute per-MG reasons, indicator tokens, and unreachable notes."""
    per_mg = {}
    unreachable = []
    for mg_id in targets:
        reasons = mg_indicators(findings, mg_id)
        per_mg[mg_id] = reasons
        # PLC unreachable => ground-truth unknown (open_breakers is None)
        if findings['open_breakers'].get(mg_id) is None:
            unreachable.append(mg_id)

    compromised = [mg for mg in targets if per_mg[mg]]
    # "unknown" only when we couldn't get ground truth AND no other indicator
    # (a disabled/redirected data source still flags the MG as compromised).
    unknown = [mg for mg in unreachable if mg not in compromised]

    tokens = [f"mitm_attack{mg_num(mg)}" for mg in compromised]
    tokens += [f"mitm_unknown{mg_num(mg)}" for mg in unknown]
    if not tokens:
        tokens = ["no_mitm_attack"]

    return {
        'tokens': tokens,
        'compromised': compromised,
        'unknown': unknown,
        'reasons': per_mg,
        'unreachable': unreachable,
        # Gateway-wide indicator surfaced separately (not a per-MG token)
        'operator_mode': findings['operator_mode'],
    }


def print_human(report, targets):
    for mg_id in targets:
        reasons = report['reasons'][mg_id]
        if reasons:
            print(f"  [{mg_id.upper()}] COMPROMISED — {'; '.join(reasons)}")
        elif mg_id in report['unreachable']:
            print(f"  [{mg_id.upper()}] unknown — PLC unreachable (no ground truth)")
        else:
            print(f"  [{mg_id.upper()}] ok")

    if report['operator_mode'] is True:
        print("  [GATEWAY] Operator_Mode ENABLED (MITM staging indicator)")

    print()
    print(f"INDICATORS: {' '.join(report['tokens'])}")


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team sensing: emit MITM attack failure indicators (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python detection/scada_mitm_detect.py                 # all microgrids
    python detection/scada_mitm_detect.py --mg mg1 mg3    # subset
    python detection/scada_mitm_detect.py --json          # JSON for tooling/RL

Indicator tokens: mitm_attack1..4, no_mitm_attack
        """
    )
    parser.add_argument('--mg', nargs='+', choices=ALL_TARGETS,
                        help='Target specific microgrid(s) (default: all)')
    parser.add_argument('--json', action='store_true',
                        help='Emit a single JSON object instead of human text')
    parser.add_argument('--plc-host', default='localhost',
                        help='PLC host (default: localhost)')
    parser.add_argument('--scada-url', default='http://localhost:8080/Scada-LTS',
                        help='ScadaLTS base URL')
    parser.add_argument('--env-file', default=DEFAULT_ENV_FILE,
                        help=f'Load service addresses from env file (default: {DEFAULT_ENV_FILE})')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show the full human report (default: print only the tokens)')

    args = parser.parse_args()

    # Override service addresses from env file (explicit CLI args take priority).
    # These mutate the imported module's globals, which detect() reads.
    if args.env_file and os.path.isfile(args.env_file):
        from env_loader import load_env_file, resolve_addresses
        addrs = resolve_addresses(load_env_file(args.env_file))
        if args.scada_url == 'http://localhost:8080/Scada-LTS':
            args.scada_url = addrs['scada_url']
        for mg, (host, port) in addrs['plc_hosts'].items():
            mitm.PLC_HOSTS[mg] = host
            mitm.PLC_PORTS[mg] = port
        mitm.GATEWAY_HOST = addrs['gateway_host']
    elif args.plc_host != 'localhost':
        for mg in mitm.PLC_HOSTS:
            mitm.PLC_HOSTS[mg] = args.plc_host

    targets = args.mg if args.mg else ALL_TARGETS

    if args.verbose:
        print("=" * 60)
        print("  Blue Team Sensing: MITM Attack Failure Indicators")
        print("=" * 60)
        print(f"  SCADA: {args.scada_url}")
        print(f"  Scope: {', '.join(t.upper() for t in targets)}")
        print()

    scada = mitm.ScadaClient(args.scada_url, verbose=args.verbose)
    with _silence(not args.verbose):
        logged_in = scada.login()
    if not logged_in:
        if args.json:
            print(json.dumps({'error': 'scada_login_failed', 'tokens': []}))
        else:
            print("error: ScadaLTS login failed", file=sys.stderr)
        sys.exit(2)
    with _silence(not args.verbose):
        discovered = scada.discover_datasources()
    if not discovered:
        if args.json:
            print(json.dumps({'error': 'datasource_enumeration_failed', 'tokens': []}))
        else:
            print("error: failed to enumerate data sources", file=sys.stderr)
        sys.exit(2)

    with _silence(not args.verbose):
        findings = mitm.detect(scada, targets)
    report = build_report(findings, targets)

    if args.json:
        print(json.dumps({
            'scope': targets,
            'tokens': report['tokens'],
            'compromised': report['compromised'],
            'unknown': report['unknown'],
            'reasons': report['reasons'],
            'unreachable': report['unreachable'],
            'operator_mode': report['operator_mode'],
        }))
    elif args.verbose:
        print_human(report, targets)
    else:
        print(' '.join(report['tokens']))

    sys.exit(1 if report['compromised'] else 0)


if __name__ == '__main__':
    main()
