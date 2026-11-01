#!/usr/bin/env python3
"""
Blue Team Sensing: Market Manipulation Failure Indicators
=========================================================
Detection-only companion to scada_market_recovery.py. It NEVER changes grid or
market state — it only reads and emits compact machine-readable indicator
tokens for the market manipulation attack (scada_market_attack.py: forced load
shedding, false-scarcity spoofing, price spikes, operator-mode override).

Indicator tokens (printed alone by default; `--verbose` shows them on an
`INDICATORS:` line under a full report):

    market_attack1    MG1 shows market attack indicators
    market_attack2    MG2 ...
    market_attack3    MG3 ...
    market_spoof      gateway/register-level manipulation not tied to one MG
                      (clearing-price spike, false scarcity)
    no_market_attack  no indicators found — market clean

The trailing number is the microgrid id. Only mg1-3 appear — bidder shedding
applies to the LOAD microgrids; MG4 is the generator (no bidder load) and is
never a market target, so there is no `market_attack4`.

Attribution keys on the market attack's UNIQUE fingerprint: a gateway SHED coil
(bidder_shed / fixed_shed) driven active, a zeroed allocation while a bid still
exists, or the false-scarcity registers (price spike / surplus=gen=0). The
gateway 'override' / Market_Control coil, the MG4 PLC Market_Control override,
and Operator_Mode are all shared with the breaker attack, so they are NOT used
for attribution (Operator_Mode is surfaced as an informational note). Every
trigger is read from the gateway, so there is no per-MG `unknown`. See
DETECTION.md § Attribution.

This reuses the proven detection routine from scada_market_recovery.detect().

Exit code: 0 if clean, 1 if any market attack indicator present, 2 if the
gateway is unreadable (so it can drive shell conditionals).

Usage:
    python detection/scada_market_detect.py                   # all microgrids
    python detection/scada_market_detect.py --mg mg1 mg3      # subset
    python detection/scada_market_detect.py --json            # structured output
    python detection/scada_market_detect.py --env-file deployment/prod.env

MITRE ATT&CK ICS: D3-PSA (Process State Awareness), D3-ORA (Operational Risk Assessment)
"""

import argparse
import json
import os
import sys

# env_loader.py is bundled in this folder; the reused recovery modules live in
# the sibling attacks/ directory — append it so they can be imported (this
# folder stays first on the path, so the local env_loader is used).
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'attacks'))

# Reuse the tested detection machinery; do not duplicate it.
import scada_market_recovery as mkt

DEFAULT_ENV_FILE = mkt.DEFAULT_ENV_FILE
ALL_TARGETS = ['mg1', 'mg2', 'mg3', 'mg4']
# Only the load microgrids have bidder loads; MG4 (generator) is never a
# market bidder-shedding target.
LOAD_MGS = ('mg1', 'mg2', 'mg3')


def mg_num(mg_id):
    """'mg3' -> 3."""
    return int(mg_id[2:])


def build_report(findings, targets):
    """Map findings to per-MG reasons, global spoof reasons, and tokens.

    Attribution keys on the market attack's UNIQUE **register-manipulation**
    signature — a clearing-price spike (the attack hard-writes $99/MWh) and/or
    false-scarcity registers. A shed coil (bidder_shed/fixed_shed) or a zeroed
    allocation is the attack's *impact*, but those ALSO occur in legitimate
    market clearing: a microgrid that bids below the clearing price loses its
    allocation (alloc=0) and its bidder load is legitimately shed. So the per-MG
    shed/alloc signals are only attributed to the attack when the register
    manipulation is present — otherwise it's normal market operation.

    Deliberately NOT used for attribution (all shared with the breaker attack):
    the gateway 'override'/Market_Control coil, the MG4 PLC Market_Control
    override, and Operator_Mode. Every trigger is read from the gateway (which
    covers all MGs), so there is no per-MG 'unknown'.
    """
    state = findings.get('market_state')

    # Gateway register-level manipulation — the attack's tell. Legitimate
    # clearing keeps a normal price (~$50) and real surplus, so this stays empty.
    global_reasons = []
    if state and state['clearing_price'] >= mkt.PRICE_SPIKE_THRESHOLD:
        global_reasons.append(
            f"clearing price ${state['clearing_price']:.2f}/MWh "
            f"(>= ${mkt.PRICE_SPIKE_THRESHOLD}/MWh)")
    if state and state['surplus'] == 0 and state['generation'] == 0:
        global_reasons.append("false scarcity (surplus=0, generation=0)")
    spoof_present = bool(global_reasons)

    # Bidder shedding only applies to the LOAD microgrids (mg1-3). MG4 is the
    # generator and has no bidder load, so it is never a market target — even
    # though the gateway exposes an (unused) bidder-shed coil for it.
    market_targets = [mg for mg in targets if mg in LOAD_MGS]

    per_mg = {mg: [] for mg in targets}
    if spoof_present:
        # Only attribute the shed/alloc impact once the market registers show
        # manipulation — otherwise a shed is legitimate price-based clearing.
        for mg in market_targets:
            for shed in findings['shed_active'].get(mg, []):
                if shed in ('bidder_shed', 'fixed_shed'):
                    per_mg[mg].append(f"gateway shed coil active: {shed}")
            if state and state.get(f'alloc_{mg}') == 0 and state.get(f'bid_{mg}', 0) > 0:
                per_mg[mg].append(f"allocation=0 but bid={state[f'bid_{mg}']}kW")

    compromised = [mg for mg in market_targets if per_mg[mg]]

    tokens = [f"market_attack{mg_num(mg)}" for mg in compromised]
    if global_reasons:
        tokens.append("market_spoof")
    if not tokens:
        tokens = ["no_market_attack"]

    return {
        'tokens': tokens,
        'compromised': compromised,
        'reasons': per_mg,
        'spoof': global_reasons,
        # Operator_Mode is shared with the breaker attack — informational only.
        'operator_mode': findings['operator_mode'],
    }


def print_human(report, targets):
    for mg_id in targets:
        reasons = report['reasons'][mg_id]
        if reasons:
            print(f"  [{mg_id.upper()}] ATTACKED ({len(reasons)}):")
            for r in reasons:
                print(f"      - {r}")
        else:
            print(f"  [{mg_id.upper()}] ok")

    if report['spoof']:
        print(f"  [GATEWAY] market spoofing ({len(report['spoof'])}):")
        for r in report['spoof']:
            print(f"      - {r}")

    if report['operator_mode']:
        print("  [info] Operator_Mode ENABLED (shared with breaker attack — not "
              "used for market attribution)")

    print()
    print(f"INDICATORS: {' '.join(report['tokens'])}")


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team sensing: emit market manipulation indicators (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python detection/scada_market_detect.py                 # all microgrids
    python detection/scada_market_detect.py --mg mg1 mg3    # subset
    python detection/scada_market_detect.py --json          # JSON for tooling/RL

Indicator tokens: market_attack1..3, market_spoof,
                  no_market_attack
        """
    )
    parser.add_argument('--mg', nargs='+', choices=ALL_TARGETS,
                        help='Target specific microgrid(s) (default: all)')
    parser.add_argument('--json', action='store_true',
                        help='Emit a single JSON object instead of human text')
    parser.add_argument('--gateway-host', default='localhost',
                        help='SCADA gateway host (default: localhost)')
    parser.add_argument('--gateway-port', type=int, default=mkt.GATEWAY_PORT,
                        help=f'SCADA gateway port (default: {mkt.GATEWAY_PORT})')
    parser.add_argument('--plc-host', default='localhost',
                        help='PLC host (default: localhost)')
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
        if args.gateway_host == 'localhost':
            args.gateway_host = addrs['gateway_host']
        if args.gateway_port == mkt.GATEWAY_PORT:
            args.gateway_port = addrs['gateway_port']
        for mg, (host, port) in addrs['plc_hosts'].items():
            mkt.PLC_HOSTS[mg] = host
            mkt.PLC_PORTS[mg] = port
    elif args.plc_host != 'localhost':
        for mg in mkt.PLC_HOSTS:
            mkt.PLC_HOSTS[mg] = args.plc_host

    targets = args.mg if args.mg else ALL_TARGETS

    if args.verbose:
        print("=" * 60)
        print("  Blue Team Sensing: Market Manipulation Indicators")
        print("=" * 60)
        print(f"  Gateway: {args.gateway_host}:{args.gateway_port} (unit {mkt.GATEWAY_UNIT_ID})")
        print(f"  Scope: {', '.join(t.upper() for t in targets)}")
        print()

    gw = mkt.ModbusClient(args.gateway_host, args.gateway_port, mkt.GATEWAY_UNIT_ID)
    if not gw.connect():
        if args.json:
            print(json.dumps({'error': 'gateway_connection_failed', 'tokens': []}))
        else:
            print(f"error: cannot connect to SCADA gateway at "
                  f"{args.gateway_host}:{args.gateway_port}", file=sys.stderr)
        sys.exit(2)

    findings = mkt.detect(gw, targets)
    gw.close()

    # Gateway registers unreadable => cannot assess the market at all.
    if findings.get('market_state') is None:
        if args.json:
            print(json.dumps({'error': 'gateway_registers_unreadable', 'tokens': []}))
        else:
            print("error: gateway registers unreadable — cannot assess market",
                  file=sys.stderr)
        sys.exit(2)

    report = build_report(findings, targets)

    if args.json:
        print(json.dumps({
            'scope': targets,
            'tokens': report['tokens'],
            'compromised': report['compromised'],
            'reasons': report['reasons'],
            'spoof': report['spoof'],
            'operator_mode': report['operator_mode'],
        }))
    elif args.verbose:
        print_human(report, targets)
    else:
        # Quiet: drop market_spoof when a per-MG attack tag already implies it
        # (keep it when it is the sole signal, e.g. price spike without a shed).
        toks = report['tokens']
        if report['compromised']:
            toks = [t for t in toks if t != 'market_spoof']
        print(' '.join(toks))

    sys.exit(1 if (report['compromised'] or report['spoof']) else 0)


if __name__ == '__main__':
    main()
