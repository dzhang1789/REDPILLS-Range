#!/usr/bin/env python3
"""
Blue Team Sensing: Breaker Attack Failure Indicators
====================================================
Detection-only companion to scada_breaker_recovery.py. It NEVER changes grid
state — it only reads and emits compact machine-readable indicator tokens for
the SCADA-path breaker attack (scada_breaker_attack.py).

Indicator tokens (printed alone by default; `--verbose` shows them on an
`INDICATORS:` line under a full report):

    breaker_attack1    MG1 has one or more breakers open
    breaker_attack2    MG2 ...
    breaker_attack3    MG3 ...
    breaker_attack4    MG4 ...
    breaker_override   ScadaLTS Point Links DISABLED — the breaker attack's
                       unique SCADA-path artifact
    no_breaker_attack  no indicators found — grid clean

The trailing number is the microgrid id (mg1 -> 1, ... mg4 -> 4).

Attribution keys on the breaker attack's UNIQUE fingerprint: ScadaLTS Point
Links DISABLED. `breaker_attack<N>` fires when the MG's breaker reads open (via
ScadaLTS) AND Point Links are cut. An open breaker WITHOUT cut Point Links is
attributed elsewhere — the market attack opens the bidder/gen breaker via
gateway shed coils, not via ScadaLTS. Operator_Mode is NOT used to attribute
(the market attack sets it too); it is surfaced as an informational note. See
DETECTION.md § Attribution.

All reads go through ScadaLTS (a single endpoint), so there is no per-MG
"unknown": if ScadaLTS is unreachable the whole run exits 2.

This reuses the proven detection routine from scada_breaker_recovery.detect().

Exit code: 0 if clean, 1 if any breaker indicator present, 2 on connection
error (so it can drive shell conditionals).

Usage:
    python detection/scada_breaker_detect.py                  # all microgrids
    python detection/scada_breaker_detect.py --mg mg1 mg3     # subset
    python detection/scada_breaker_detect.py --json           # structured output
    python detection/scada_breaker_detect.py --env-file deployment/prod.env

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
import scada_breaker_recovery as brk

DEFAULT_ENV_FILE = brk.DEFAULT_ENV_FILE
ALL_TARGETS = ['mg1', 'mg2', 'mg3', 'mg4']


def mg_num(mg_id):
    """'mg3' -> 3."""
    return int(mg_id[2:])


@contextlib.contextmanager
def _silence(enabled):
    """Suppress stdout from the reused login/detect routines in JSON mode."""
    if not enabled:
        yield
        return
    with open(os.devnull, 'w') as devnull, contextlib.redirect_stdout(devnull):
        yield


def build_report(findings, targets):
    """Map findings to per-MG reasons, global override reasons, and tokens.

    Attribution keys on the breaker attack's UNIQUE fingerprint: ScadaLTS
    Point Links DISABLED. Only the SCADA-path breaker attack cuts them (MITM
    disables data sources; market uses gateway shed coils; historian touches DB
    history). An open breaker WITHOUT cut Point Links is attributed elsewhere —
    e.g. the market attack opens the bidder/gen breaker via gateway coils.
    Operator_Mode is NOT used to attribute: the market attack sets it too.
    """
    point_links_cut = bool(findings['disabled_links'])

    per_mg = {mg: [] for mg in targets}
    for mg in targets:
        detail = findings['details'].get(mg, {})
        open_brk = detail.get('open_breakers', [])
        # breaker-attack signature = breaker open AND Point Links cut
        if open_brk and point_links_cut:
            per_mg[mg].append(f"breaker OPEN via SCADA path: {', '.join(open_brk)}")

    compromised = [mg for mg in targets if per_mg[mg]]

    # breaker-unique control-path artifact
    global_reasons = []
    if point_links_cut:
        global_reasons.append(
            f"{len(findings['disabled_links'])} Point Link(s) disabled: "
            f"{', '.join(findings['disabled_links'])}")

    tokens = [f"breaker_attack{mg_num(mg)}" for mg in compromised]
    if point_links_cut:
        tokens.append("breaker_override")
    if not tokens:
        tokens = ["no_breaker_attack"]

    return {
        'tokens': tokens,
        'compromised': compromised,
        'reasons': per_mg,
        'override': global_reasons,
        # Operator_Mode is shared with the market attack — informational only.
        'operator_mode': findings['operator_mode'],
    }


def print_human(report, targets):
    for mg_id in targets:
        reasons = report['reasons'][mg_id]
        if reasons:
            print(f"  [{mg_id.upper()}] ATTACKED — {'; '.join(reasons)}")
        else:
            print(f"  [{mg_id.upper()}] ok")

    if report['override']:
        print(f"  [SCADA] control-path tampering ({len(report['override'])}):")
        for r in report['override']:
            print(f"      - {r}")

    if report['operator_mode']:
        print("  [info] Operator_Mode ENABLED (shared with market attack — not "
              "used for breaker attribution)")

    print()
    print(f"INDICATORS: {' '.join(report['tokens'])}")


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team sensing: emit breaker attack indicators (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python detection/scada_breaker_detect.py                 # all microgrids
    python detection/scada_breaker_detect.py --mg mg1 mg3    # subset
    python detection/scada_breaker_detect.py --json          # JSON for tooling/RL

Indicator tokens: breaker_attack1..4,
                  breaker_override, no_breaker_attack
        """
    )
    parser.add_argument('--mg', nargs='+', choices=ALL_TARGETS,
                        help='Target specific microgrid(s) (default: all)')
    parser.add_argument('--json', action='store_true',
                        help='Emit a single JSON object instead of human text')
    parser.add_argument('--scada-url', default='http://localhost:8080/Scada-LTS',
                        help='ScadaLTS base URL')
    parser.add_argument('--env-file', default=DEFAULT_ENV_FILE,
                        help=f'Load service addresses from env file (default: {DEFAULT_ENV_FILE})')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show the full human report (default: print only the tokens)')

    args = parser.parse_args()

    # Override the ScadaLTS URL from the env file (explicit CLI arg wins).
    if args.env_file and os.path.isfile(args.env_file):
        from env_loader import load_env_file, resolve_addresses
        addrs = resolve_addresses(load_env_file(args.env_file))
        if args.scada_url == 'http://localhost:8080/Scada-LTS':
            args.scada_url = addrs['scada_url']

    targets = args.mg if args.mg else ALL_TARGETS

    if args.verbose:
        print("=" * 60)
        print("  Blue Team Sensing: Breaker Attack Indicators")
        print("=" * 60)
        print(f"  SCADA: {args.scada_url}")
        print(f"  Scope: {', '.join(t.upper() for t in targets)}")
        print()

    defender = brk.ScadaDefender(args.scada_url, verbose=args.verbose)

    with _silence(not args.verbose):
        connected = defender.login()
    if not connected:
        if args.json:
            print(json.dumps({'error': 'scada_login_failed', 'tokens': []}))
        else:
            print("error: ScadaLTS login failed", file=sys.stderr)
        sys.exit(2)

    with _silence(not args.verbose):
        findings = defender.detect()

    report = build_report(findings, targets)

    if args.json:
        print(json.dumps({
            'scope': targets,
            'tokens': report['tokens'],
            'compromised': report['compromised'],
            'reasons': report['reasons'],
            'override': report['override'],
            'operator_mode': report['operator_mode'],
        }))
    elif args.verbose:
        print_human(report, targets)
    else:
        # Quiet: drop breaker_override when a per-MG attack tag already implies it
        # (keep it when it is the sole signal, e.g. Point Links cut / staging).
        toks = report['tokens']
        if report['compromised']:
            toks = [t for t in toks if t != 'breaker_override']
        print(' '.join(toks))

    sys.exit(1 if (report['compromised'] or report['override']) else 0)


if __name__ == '__main__':
    main()
