#!/usr/bin/env python3
"""
Rigorous attribution test for the four detection sensors.

For every "world" (which attacks are active, on which microgrids) we:
  1. synthesize the findings each detector would read from that world, and
  2. compute the expected tokens from an INDEPENDENT oracle (the attribution
     spec), then assert build_report() matches.

No live stack required — this exercises the pure token logic exhaustively.

Run:  python detection/test_detection.py
"""

import itertools
import os
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'attacks'))

import scada_breaker_detect as B
import scada_market_detect as M
import scada_mitm_detect as MI
import scada_historian_detect as H
import scada_historian_recovery as HR

ALL = ['mg1', 'mg2', 'mg3', 'mg4']
DOWN = lambda mg: 'gen' if mg == 'mg4' else 'load'      # downstream breaker name
N = lambda mg: int(mg[2:])


# =============================================================================
# World -> findings (models how each attack shows up to each detector)
# =============================================================================
class World:
    def __init__(self, breaker=(), market=(), mitm=(), historian=(),
                 legit_shed=(), unreachable=()):
        self.breaker = set(breaker)
        self.market = set(market)
        self.mitm = set(mitm)
        self.historian = set(historian)
        self.legit_shed = set(legit_shed)      # market shed w/o register spoof
        self.unreachable = set(unreachable)    # PLC unreachable over Modbus

    def op_mode(self):
        # both the breaker and the market attack set gateway Operator_Mode
        return bool(self.breaker or self.market)


def breaker_findings(w):
    """ScadaLTS view: shows a breaker open only if it was opened via the SCADA
    path (breaker attack) or market opened mg4's gen — UNLESS MITM blinded it
    (then SCADA is frozen on stale-closed). Point Links are cut only by the
    breaker attack."""
    details = {}
    for mg in ALL:
        scada_open = ((mg in w.breaker) or (mg == 'mg4' and mg in w.market)) \
                     and mg not in w.mitm
        details[mg] = {'market_control': True,
                       'open_breakers': ([DOWN(mg)] if scada_open else [])}
    return {'compromised': [], 'operator_mode': w.op_mode(),
            'disabled_links': (['PL_MG1_Load_Cmd'] if w.breaker else []),
            'system_alerts': [], 'details': details}


def market_findings(w):
    """Gateway view. Market attack spikes price to $99 & zeroes surplus; a shed
    coil / alloc=0 appears for both attack targets and legitimately-shed MGs."""
    attack = bool(w.market)
    shed = w.market | w.legit_shed
    st = {'clearing_price': 99.0 if attack else 52.0,
          'surplus': 0 if attack else 30,
          'generation': 590 if attack else 632}
    for mg in ALL:
        st[f'alloc_{mg}'] = 0 if mg in shed else 50
        st[f'bid_{mg}'] = 50
    shed_active = {}
    for mg in ALL:
        # MG4 (generator) has no bidder load, so its bidder-shed coil is never set.
        s = (['bidder_shed'] if (mg in shed and mg != 'mg4') else [])
        if w.op_mode() and mg in ('mg1', 'mg2', 'mg3'):
            s.append('override')          # normal-TRUE coil, surfaces w/ op-mode
        shed_active[mg] = s
    plc_ovr = {mg: (mg == 'mg4' and (mg in w.breaker or mg in w.market))
               for mg in ALL}
    return {'operator_mode': w.op_mode(), 'shed_active': shed_active,
            'plc_overrides': plc_ovr, 'market_state': st}


def mitm_findings(w):
    """Data-source status + direct-Modbus ground truth (watches main+load/gen)."""
    disabled = [f"{mg.upper()}_PLC" for mg in w.mitm]
    ob, ovr = {}, {}
    for mg in ALL:
        if mg in w.unreachable:
            ob[mg] = None
            ovr[mg] = None
            continue
        phys_open = (mg in w.breaker) or (mg in w.mitm) \
                    or (mg == 'mg4' and mg in w.market)
        ob[mg] = ([DOWN(mg)] if phys_open else [])
        ovr[mg] = (mg == 'mg4' and (mg in w.breaker or mg in w.market or mg in w.mitm))
    return {'disabled_ds': disabled, 'redirected_ds': [],
            'open_breakers': ob, 'plc_overrides': ovr,
            'operator_mode': w.op_mode()}


def historian_findings(w):
    finds = []
    for mg in w.historian:
        for xid in HR.VOLTAGE_POINTS[mg] + HR.BREAKER_POINTS[mg]:
            finds.append({'type': 'NO_DATA', 'point': xid,
                          'message': 'No records in last 60 min'})
    return finds


# =============================================================================
# Independent oracle (the attribution spec) -> expected token SET
# =============================================================================
def _pack(prefix, per_mg, targets, extra=()):
    toks = [f"{prefix}_attack{N(mg)}" for mg in targets if mg in per_mg]
    toks += list(extra)
    return set(toks) if toks else {f"no_{prefix}_attack"}


def expect_breaker(w, targets):
    cut = bool(w.breaker)
    # SCADA-visible open AND Point Links cut
    per_mg = {mg for mg in ALL
              if cut and (((mg in w.breaker) or (mg == 'mg4' and mg in w.market))
                          and mg not in w.mitm)}
    return _pack('breaker', per_mg, targets,
                 extra=(['breaker_override'] if cut else []))


def expect_market(w, targets):
    spoof = bool(w.market)                     # price spike present
    shed = w.market | w.legit_shed
    # Bidder shedding is load-MG (mg1-3) only; MG4 is never a market target.
    market_targets = [mg for mg in targets if mg in ('mg1', 'mg2', 'mg3')]
    per_mg = {mg for mg in market_targets if spoof and mg in shed}
    return _pack('market', per_mg, market_targets,
                 extra=(['market_spoof'] if spoof else []))


def expect_mitm(w, targets):
    blinded = {mg for mg in ALL if mg in w.mitm}
    unknown = [mg for mg in targets
               if mg in w.unreachable and mg not in blinded]
    base = _pack('mitm', blinded, targets)
    if base == {'no_mitm_attack'} and unknown:
        base = set()
    base |= {f"mitm_unknown{N(mg)}" for mg in unknown}
    return base or {'no_mitm_attack'}


def expect_historian(w, targets):
    per_mg = {mg for mg in ALL if mg in w.historian}
    return _pack('historian', per_mg, targets)


# =============================================================================
# Runner
# =============================================================================
CASES = []


def check(name, w, targets=ALL):
    results = {
        'breaker': (set(B.build_report(breaker_findings(w), targets)['tokens']),
                    expect_breaker(w, targets)),
        'market': (set(M.build_report(market_findings(w), targets)['tokens']),
                   expect_market(w, targets)),
        'mitm': (set(MI.build_report(mitm_findings(w), targets)['tokens']),
                 expect_mitm(w, targets)),
        'historian': (set(H.build_report(historian_findings(w), targets)['tokens']),
                      expect_historian(w, targets)),
    }
    for det, (got, exp) in results.items():
        CASES.append((name, det, got == exp, got, exp))


GEN = {'breaker': breaker_findings, 'market': market_findings,
       'mitm': mitm_findings, 'historian': historian_findings}
MOD = {'breaker': B, 'market': M, 'mitm': MI, 'historian': H}
ANCHOR_FAILS = []


def anchor(name, w, det, expected_literal, targets=ALL):
    """Hand-verified literal expectation — independent of the oracle."""
    got = set(MOD[det].build_report(GEN[det](w), targets)['tokens'])
    if got != set(expected_literal):
        ANCHOR_FAILS.append((name, det, got, set(expected_literal)))


def anchors():
    """~ hand-computed ground truth, so the suite can't pass by oracle circularity."""
    # clean
    for det in MOD:
        anchor("clean", World(), det, [f"no_{det}_attack"])
    # each single attack lights exactly one detector
    anchor("breaker-all", World(breaker=ALL), 'breaker',
           ['breaker_attack1', 'breaker_attack2', 'breaker_attack3', 'breaker_attack4',
            'breaker_override'])
    anchor("breaker-all", World(breaker=ALL), 'market', ['no_market_attack'])
    anchor("breaker-all", World(breaker=ALL), 'mitm', ['no_mitm_attack'])
    # market attack targets bidder loads -> mg1-3 only; MG4 (generator) excluded
    anchor("market-all (no mg4)", World(market=ALL), 'market',
           ['market_attack1', 'market_attack2', 'market_attack3', 'market_spoof'])
    anchor("market-all", World(market=ALL), 'breaker', ['no_breaker_attack'])
    anchor("mitm-all", World(mitm=ALL), 'mitm',
           ['mitm_attack1', 'mitm_attack2', 'mitm_attack3', 'mitm_attack4'])
    anchor("mitm-all", World(mitm=ALL), 'breaker', ['no_breaker_attack'])
    anchor("historian-all", World(historian=ALL), 'historian',
           ['historian_attack1', 'historian_attack2', 'historian_attack3',
            'historian_attack4'])
    # THE false-positive case: legitimate shed on mg3 -> market clean
    anchor("legit_shed mg3", World(legit_shed=('mg3',)), 'market', ['no_market_attack'])
    # market attack sweeps up a co-incident legit shed (both flagged, spoof present)
    anchor("market mg1 + legit mg3", World(market=('mg1',), legit_shed=('mg3',)), 'market',
           ['market_attack1', 'market_attack3', 'market_spoof'])
    # mitm blinded subset + unreachable subset
    anchor("mitm mg1,mg2 + unreachable mg3,mg4",
           World(mitm=('mg1', 'mg2'), unreachable=('mg3', 'mg4')), 'mitm',
           ['mitm_attack1', 'mitm_attack2', 'mitm_unknown3', 'mitm_unknown4'])
    # market opens mg4 gen (SCADA-visible) but does NOT cut Point Links -> breaker clean
    anchor("market mg4 -> breaker clean", World(market=('mg4',)), 'breaker',
           ['no_breaker_attack'])
    # breaker single mg
    anchor("breaker mg2", World(breaker=('mg2',)), 'breaker',
           ['breaker_attack2', 'breaker_override'])
    # scope subset
    anchor("scope mg1,mg3 breaker-all", World(breaker=ALL), 'breaker',
           ['breaker_attack1', 'breaker_attack3', 'breaker_override'],
           targets=['mg1', 'mg3'])


def main():
    anchors()
    subsets = [c for r in range(1, 5) for c in itertools.combinations(ALL, r)]

    # 1. Clean
    check("clean", World())

    # 2. Every single-family attack across every non-empty MG subset
    for fam in ('breaker', 'market', 'mitm', 'historian'):
        for sub in subsets:
            check(f"{fam}:{'+'.join(sub)}", World(**{fam: sub}))

    # 3. Legitimate market clearing (shed w/o register spoof) — must stay clean
    for sub in subsets:
        check(f"legit_shed:{'+'.join(sub)}", World(legit_shed=sub))

    # 4. MITM unreachable PLCs (unknown) and blinded+unreachable mix
    for sub in subsets:
        check(f"unreachable:{'+'.join(sub)}", World(unreachable=sub))
    check("mitm mg1,mg2 + unreachable mg3,mg4",
          World(mitm=('mg1', 'mg2'), unreachable=('mg3', 'mg4')))

    # 5. All 2^4 family on/off combinations (each active family = all MGs)
    fams = ('breaker', 'market', 'mitm', 'historian')
    for bits in itertools.product([0, 1], repeat=4):
        kw = {f: ALL for f, b in zip(fams, bits) if b}
        check("combo:" + '+'.join(f for f, b in zip(fams, bits) if b) or "combo:none",
              World(**kw))

    # 6. Targeted overlaps
    check("breaker mg1 + market mg4", World(breaker=('mg1',), market=('mg4',)))
    check("market attack + legit_shed on other MG",
          World(market=('mg1',), legit_shed=('mg3',)))
    check("breaker mg1 + mitm mg1 (same MG, two vectors)",
          World(breaker=('mg1',), mitm=('mg1',)))
    check("historian all + breaker all (independent domains)",
          World(historian=ALL, breaker=ALL))

    # 7. Scope subset (--mg): attack all, but only report on a subset
    check("scope mg1,mg3 under breaker-all", World(breaker=ALL), targets=['mg1', 'mg3'])
    check("scope mg4 under market-all", World(market=ALL), targets=['mg4'])

    # ---- report ----
    fails = [c for c in CASES if not c[2]]
    print(f"\n[anchors] hand-verified literal checks: "
          f"PASS {13 * 0 + (17 - len(ANCHOR_FAILS))}  FAIL {len(ANCHOR_FAILS)}")
    for name, det, got, exp in ANCHOR_FAILS:
        print(f"  ANCHOR FAIL [{det}] {name}: got {sorted(got)} want {sorted(exp)}")
    print(f"[oracle]  Ran {len(CASES)} detector-checks across "
          f"{len({c[0] for c in CASES})} worlds: "
          f"PASS {len(CASES) - len(fails)}  FAIL {len(fails)}")
    for name, det, ok, got, exp in fails:
        print(f"\n  FAIL [{det}] {name}")
        print(f"     got : {sorted(got)}")
        print(f"     want: {sorted(exp)}")
    return 0 if not fails and not ANCHOR_FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
