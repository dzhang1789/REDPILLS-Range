#!/usr/bin/env python3
"""
Blue Team Defence: Detect & Restore Market Manipulation Attacks
================================================================
Counter-action for scada_market_attack.py false-scarcity attack.

Detection (S2 — sensing):
  - Checks Operator_Mode on SCADA Gateway (coil 12)
  - Checks shed recommendation coils (bidder shed, override, fixed shed)
  - Checks market register anomalies (surplus=0, generation=0, price spike)
  - Checks PLC Market_Control overrides

Recovery (D2 — defence):
  1. Clear Operator Mode on SCADA Gateway
  2. Clear all shed recommendation coils
  3. Close breakers on PLCs, then clear Market_Control overrides (return to AUTO mode)
  4. Verify market state is restored

Usage:
    # Detection only (no changes) — S2 sensing
    python attacks/scada_market_recovery.py --detect

    # Detect + restore all microgrids — D2 defence (one-shot)
    python attacks/scada_market_recovery.py --restore

    # Continuous detect + auto-restore loop — D2 defence (continuous)
    python attacks/scada_market_recovery.py --restore --interval 5

MITRE ATT&CK ICS: D3-PSA (Process State Awareness), D3-ORA (Operational Risk Assessment)
"""

import argparse
import os
import socket
import struct
import sys
import time

# Default env file location: prod.env sits one directory above this script
# on deployed VMs (e.g., /opt/powergrid/prod.env, with scripts in /opt/powergrid/attacks/).
DEFAULT_ENV_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'prod.env'
)

# =============================================================================
# Modbus constants
# =============================================================================
FC_READ_COILS = 0x01
FC_READ_HOLDING_REGISTERS = 0x03
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
COIL_ON = 0xFF00
COIL_OFF = 0x0000

# SCADA Gateway
GATEWAY_PORT = 5020
GATEWAY_UNIT_ID = 10

# PLC addresses (overridden by --env-file)
PLC_HOSTS = {'mg1': 'localhost', 'mg2': 'localhost', 'mg3': 'localhost', 'mg4': 'localhost'}
PLC_PORTS = {'mg1': 502, 'mg2': 503, 'mg3': 504, 'mg4': 505}
PLC_UNIT_ID = 1

# Gateway register layout (unit 10)
REG_ALLOC_MG1 = 0
REG_ALLOC_MG2 = 1
REG_ALLOC_MG3 = 2
REG_ALLOC_MG4 = 3
REG_BID_QTY_MG1 = 4
REG_BID_QTY_MG2 = 5
REG_BID_QTY_MG3 = 6
REG_BID_QTY_MG4 = 7
REG_CLEARING_PRICE = 8
REG_SURPLUS = 9
REG_GENERATION = 10
REG_FIXED_MG1 = 11
REG_FIXED_MG2 = 12
REG_FIXED_MG3 = 13
REG_FIXED_MG4 = 14

# Gateway coil layout (unit 10)
COIL_BIDDER_SHED = {'mg1': 0, 'mg2': 1, 'mg3': 2, 'mg4': 3}
COIL_OVERRIDE = {'mg1': 4, 'mg2': 5, 'mg3': 6, 'mg4': 7}
COIL_FIXED_SHED = {'mg1': 8, 'mg2': 9, 'mg3': 10, 'mg4': 11}
COIL_OPERATOR_MODE = 12

# PLC coil layout (unit 1) -- Load PLCs (MG1-3)
LOAD_PLC_COILS = {
    'Market_Control': 3,
    'Main_Cmd_Input': 4,
    'Load_Cmd_Input': 5,
    'Bidder_Cmd_Input': 6,
}
# Generator PLC (MG4)
GEN_PLC_COILS = {
    'Market_Control': 2,
    'Main_Cmd_Input': 3,
    'Gen_Cmd_Input': 4,
}

# Microgrid bid prices (from feeder config)
MG_BID_PRICES = {'mg1': 55, 'mg2': 52, 'mg3': 48, 'mg4': 35}

# Detection thresholds
PRICE_SPIKE_THRESHOLD = 80.0  # $/MWh — prices above this are suspicious


# =============================================================================
# Raw Modbus TCP client
# =============================================================================
class ModbusClient:
    """Raw Modbus TCP client supporting configurable unit ID."""

    def __init__(self, host, port, unit_id=1):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.sock = None
        self.txn_id = 0

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3.0)
            self.sock.connect((self.host, self.port))
            return True
        except socket.error:
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _next_txn(self):
        self.txn_id = (self.txn_id + 1) % 65536
        return self.txn_id

    def write_coil(self, address, value):
        """Write Single Coil (FC 0x05)."""
        txn = self._next_txn()
        coil_val = COIL_ON if value else COIL_OFF
        pdu = struct.pack('>BHH', FC_WRITE_SINGLE_COIL, address, coil_val)
        header = struct.pack('>HHHB', txn, 0, len(pdu) + 1, self.unit_id)
        try:
            self.sock.sendall(header + pdu)
            resp = self.sock.recv(256)
            return resp and len(resp) >= 12 and not (resp[7] & 0x80)
        except socket.error:
            return False

    def write_register(self, address, value):
        """Write Single Register (FC 0x06)."""
        txn = self._next_txn()
        pdu = struct.pack('>BHH', FC_WRITE_SINGLE_REGISTER, address, value & 0xFFFF)
        header = struct.pack('>HHHB', txn, 0, len(pdu) + 1, self.unit_id)
        try:
            self.sock.sendall(header + pdu)
            resp = self.sock.recv(256)
            return resp and len(resp) >= 12 and not (resp[7] & 0x80)
        except socket.error:
            return False

    def read_coils(self, start, count):
        """Read Coils (FC 0x01)."""
        txn = self._next_txn()
        pdu = struct.pack('>BHH', FC_READ_COILS, start, count)
        header = struct.pack('>HHHB', txn, 0, len(pdu) + 1, self.unit_id)
        try:
            self.sock.sendall(header + pdu)
            resp = self.sock.recv(256)
            if not resp or len(resp) < 10 or (resp[7] & 0x80):
                return None
            cb = resp[9:9 + resp[8]]
            return [bool(cb[i // 8] & (1 << (i % 8))) for i in range(count)]
        except socket.error:
            return None

    def read_registers(self, start, count):
        """Read Holding Registers (FC 0x03)."""
        txn = self._next_txn()
        pdu = struct.pack('>BHH', FC_READ_HOLDING_REGISTERS, start, count)
        header = struct.pack('>HHHB', txn, 0, len(pdu) + 1, self.unit_id)
        try:
            self.sock.sendall(header + pdu)
            resp = self.sock.recv(256)
            if not resp or len(resp) < 9 or (resp[7] & 0x80):
                return None
            regs = []
            for i in range(count):
                offset = 9 + i * 2
                if offset + 2 <= len(resp):
                    regs.append(struct.unpack('>H', resp[offset:offset + 2])[0])
                else:
                    regs.append(0)
            return regs
        except socket.error:
            return None


# =============================================================================
# Market state reading
# =============================================================================
def read_market_state(gw):
    """Read current market state from SCADA gateway."""
    regs = gw.read_registers(0, 15)
    coils = gw.read_coils(0, 13)
    if not regs or not coils:
        return None

    state = {
        'alloc_mg1': regs[0], 'alloc_mg2': regs[1],
        'alloc_mg3': regs[2], 'alloc_mg4': regs[3],
        'bid_mg1': regs[4], 'bid_mg2': regs[5],
        'bid_mg3': regs[6], 'bid_mg4': regs[7],
        'clearing_price': regs[8] / 100.0,
        'surplus': regs[9], 'generation': regs[10],
        'fixed_mg1': regs[11], 'fixed_mg2': regs[12],
        'fixed_mg3': regs[13], 'fixed_mg4': regs[14],
        'bidder_shed': {
            'mg1': coils[0], 'mg2': coils[1],
            'mg3': coils[2], 'mg4': coils[3],
        },
        'override': {
            'mg1': coils[4], 'mg2': coils[5],
            'mg3': coils[6], 'mg4': coils[7],
        },
        'fixed_shed': {
            'mg1': coils[8], 'mg2': coils[9],
            'mg3': coils[10], 'mg4': coils[11],
        },
        'operator_mode': coils[12],
    }
    return state


def print_market_state(state, label="Market State"):
    """Pretty-print market state."""
    print(f"  {label}:")
    print(f"    Clearing Price: ${state['clearing_price']:.2f}/MWh")
    print(f"    Surplus:    {state['surplus']} kW")
    print(f"    Generation: {state['generation']} kW")
    print()
    print(f"    {'MG':<5} {'Alloc':>6} {'Bid Qty':>8} {'Bid $':>6} "
          f"{'Fixed':>6} {'B.Shed':>7} {'F.Shed':>7} {'Override':>9}")
    print(f"    {'----':<5} {'-----':>6} {'-------':>8} {'-----':>6} "
          f"{'-----':>6} {'------':>7} {'------':>7} {'--------':>9}")
    for mg in ['mg1', 'mg2', 'mg3', 'mg4']:
        alloc = state[f'alloc_{mg}']
        bid_q = state[f'bid_{mg}']
        bid_p = MG_BID_PRICES[mg]
        fixed = state[f'fixed_{mg}']
        b_shed = state['bidder_shed'][mg]
        f_shed = state['fixed_shed'][mg]
        ovr = state['override'][mg]
        print(f"    {mg.upper():<5} {alloc:>5}kW {bid_q:>6}kW "
              f"${bid_p:>4}/MWh {fixed:>5}kW "
              f"{'YES' if b_shed else 'no':>7} "
              f"{'YES' if f_shed else 'no':>7} "
              f"{'TRUE' if ovr else 'false':>9}")
    print(f"    Operator Mode: {'ENABLED' if state['operator_mode'] else 'disabled'}")


# =============================================================================
# Detection
# =============================================================================
def detect(gw, targets):
    """Scan for market manipulation attack indicators.

    Returns dict with:
      - alerts: list of string descriptions
      - operator_mode: bool
      - shed_active: dict of MG -> list of active shed types
      - plc_overrides: dict of MG -> bool (Market_Control forced)
      - market_state: full state dict (or None)
    """
    findings = {
        'alerts': [],
        'operator_mode': False,
        'shed_active': {},
        'plc_overrides': {},
        'market_state': None,
    }

    # Read gateway state
    state = read_market_state(gw)
    if not state:
        findings['alerts'].append("Cannot read gateway registers")
        return findings

    findings['market_state'] = state

    # Check Operator Mode
    if state['operator_mode']:
        findings['operator_mode'] = True
        findings['alerts'].append("Operator Mode ENABLED on gateway")

    # Check market register anomalies
    if state['surplus'] == 0 and state['generation'] == 0:
        findings['alerts'].append(
            f"Surplus=0 AND Generation=0 — likely spoofed (false scarcity)")

    if state['clearing_price'] >= PRICE_SPIKE_THRESHOLD:
        findings['alerts'].append(
            f"Clearing price ${state['clearing_price']:.2f}/MWh — "
            f"above ${PRICE_SPIKE_THRESHOLD}/MWh threshold")

    # Check shed coils per MG
    # Note: market_control (coils 4-7, labelled 'override' in coil layout) is
    # normally TRUE for load MGs (MG1-3) — the gateway sets it so SCADA can
    # control breakers.  Only flag it as suspicious when combined with actual
    # shed recommendations or operator_mode being enabled.
    for mg in targets:
        active_sheds = []
        if state['bidder_shed'][mg]:
            active_sheds.append('bidder_shed')
        if state['fixed_shed'][mg]:
            active_sheds.append('fixed_shed')
        # market_control/override is normal for load MGs — only alert if
        # it's set on MG4 (generator, normally False) or if shed coils are
        # also active (indicating an attack pushed override + shed together).
        if state['override'][mg]:
            is_load_mg = mg in ('mg1', 'mg2', 'mg3')
            if not is_load_mg or active_sheds or state['operator_mode']:
                active_sheds.append('override')

        findings['shed_active'][mg] = active_sheds
        if active_sheds:
            findings['alerts'].append(
                f"{mg.upper()}: shed coils active — {', '.join(active_sheds)}")

    # Check zero allocations (only suspicious if combined with other indicators)
    for mg in targets:
        if state[f'alloc_{mg}'] == 0 and state[f'bid_{mg}'] > 0:
            findings['alerts'].append(
                f"{mg.upper()}: allocation=0 but bid_qty={state[f'bid_{mg}']}kW — "
                f"possible spoofing")

    # Check PLC Market_Control overrides
    # Note: Market_Control=TRUE is NORMAL for MG1-3 (gateway always controls
    # bidder breakers via market). Only MG4 Market_Control=TRUE is suspicious.
    for mg in targets:
        port = PLC_PORTS[mg]
        plc = ModbusClient(PLC_HOSTS[mg], port, PLC_UNIT_ID)
        if plc.connect():
            coils = GEN_PLC_COILS if mg == 'mg4' else LOAD_PLC_COILS
            plc_coils = plc.read_coils(coils['Market_Control'], 1)
            plc.close()
            if plc_coils and plc_coils[0]:
                findings['plc_overrides'][mg] = True
            else:
                findings['plc_overrides'][mg] = False
        else:
            findings['plc_overrides'][mg] = None  # unreachable

    return findings


def print_findings(findings, targets):
    """Print detection results."""
    state = findings['market_state']

    if state:
        print()
        print_market_state(state, "Current Market State")

    print()
    op_status = "ENABLED (ALERT)" if findings['operator_mode'] else "disabled (normal)"
    print(f"  Operator_Mode: {op_status}")
    print()

    for mg in targets:
        sheds = findings['shed_active'].get(mg, [])
        plc_ovr = findings['plc_overrides'].get(mg)

        shed_str = ', '.join(sheds) if sheds else 'none'
        # Market_Control=TRUE is normal for MG1-3, only suspicious for MG4
        if plc_ovr is True:
            if mg == 'mg4':
                ovr_str = "TRUE (ALERT — normally FALSE for generator)"
            else:
                ovr_str = "TRUE (normal for load MGs)"
        elif plc_ovr is False:
            ovr_str = "false"
        else:
            ovr_str = "unreachable"

        # Only flag as compromised based on shed coils + MG4 override
        mg_compromised = bool(sheds) or (mg == 'mg4' and plc_ovr is True)
        tag = "[ALERT]" if mg_compromised else "[OK]"
        print(f"  {mg.upper()} {tag}")
        print(f"    Shed coils active: {shed_str}")
        print(f"    PLC Market_Control: {ovr_str}")

    print()
    if findings['alerts']:
        print(f"  ALERTS ({len(findings['alerts'])}):")
        for alert in findings['alerts']:
            print(f"    - {alert}")
    else:
        print("  No attack indicators detected — market operating normally")


def is_compromised(findings, targets):
    """Return True if any target MG shows attack indicators."""
    if findings['operator_mode']:
        return True
    for mg in targets:
        if findings['shed_active'].get(mg):
            return True
        # Market_Control=TRUE is normal for MG1-3 (gateway always controls bidder breakers)
        # Only flag as compromised for MG4 (where it's normally FALSE)
        if mg == 'mg4' and findings['plc_overrides'].get(mg) is True:
            return True

    # Check register-level spoofing (persists after attack Phase 6 cleanup)
    state = findings.get('market_state')
    if state:
        # Price spike above threshold
        if state['clearing_price'] >= PRICE_SPIKE_THRESHOLD:
            return True
        # Zero allocations while bids exist (false scarcity signature)
        for mg in targets:
            if state[f'alloc_{mg}'] == 0 and state[f'bid_{mg}'] > 0:
                return True

    return False


# =============================================================================
# Recovery
# =============================================================================
def restore(gw, targets):
    """Restore market state after a false-scarcity attack."""

    # Phase 1: Clear Operator Mode
    print("[+] Phase 1: Clearing Operator Mode...")
    ok = gw.write_coil(COIL_OPERATOR_MODE, False)
    status = "OK" if ok else "FAIL"
    print(f"    [{status}] Operator Mode = FALSE")

    # Phase 2: Clear shed coils
    print()
    print("[+] Phase 2: Clearing shed coils for target MGs...")
    for mg in targets:
        gw.write_coil(COIL_BIDDER_SHED[mg], False)
        gw.write_coil(COIL_OVERRIDE[mg], False)
        gw.write_coil(COIL_FIXED_SHED[mg], False)
        print(f"    [OK] {mg.upper()}: bidder_shed=FALSE, override=FALSE, fixed_shed=FALSE")

    # Phase 3: Close breakers and clear PLC Market_Control overrides
    print()
    print("[+] Phase 3: Closing breakers and clearing PLC overrides...")
    for mg in targets:
        port = PLC_PORTS[mg]
        coils = GEN_PLC_COILS if mg == 'mg4' else LOAD_PLC_COILS
        brk_name = "Gen_Cmd_Input" if mg == 'mg4' else "Bidder_Cmd_Input"
        brk_coil = coils[brk_name]

        ok_brk = False
        ok_ovr = False
        for attempt in range(2):
            plc = ModbusClient(PLC_HOSTS[mg], port, PLC_UNIT_ID)
            if not plc.connect():
                if attempt == 0:
                    time.sleep(0.5)
                    continue
                print(f"    [FAIL] {mg.upper()} — PLC unreachable on port {port}")
                break
            # Close breaker first (while override may still be active)
            ok_brk = plc.write_coil(brk_coil, True)
            time.sleep(0.05)
            # Then disable override
            ok_ovr = plc.write_coil(coils['Market_Control'], False)
            plc.close()
            if ok_brk and ok_ovr:
                break
            time.sleep(0.5)

        if ok_brk or ok_ovr:
            print(f"    [{'OK' if ok_brk else 'FAIL'}] {mg.upper()} {brk_name} = TRUE (CLOSE)")
            print(f"    [{'OK' if ok_ovr else 'FAIL'}] {mg.upper()} Market_Control = FALSE")

    # Phase 3b: Restore gateway market registers
    print()
    print("[+] Phase 3b: Restoring gateway market registers...")
    state = read_market_state(gw)
    if state:
        # Bid quantities and fixed loads are NOT spoofed by the attack —
        # use them to estimate real market values
        total_bid = sum(state[f'bid_{mg}'] for mg in ['mg1', 'mg2', 'mg3', 'mg4'])
        total_fixed = sum(state[f'fixed_{mg}'] for mg in ['mg1', 'mg2', 'mg3', 'mg4'])
        est_gen = total_fixed + total_bid
        est_surplus = est_gen - total_fixed

        # Restore allocations to match bid quantities (normal market clears all bids)
        alloc_regs = {
            'mg1': REG_ALLOC_MG1, 'mg2': REG_ALLOC_MG2,
            'mg3': REG_ALLOC_MG3, 'mg4': REG_ALLOC_MG4,
        }
        for mg in ['mg1', 'mg2', 'mg3', 'mg4']:
            gw.write_register(alloc_regs[mg], state[f'bid_{mg}'])

        # Restore price to median bid price (reasonable estimate)
        bid_prices = sorted(MG_BID_PRICES.values())
        est_price = bid_prices[len(bid_prices) // 2]
        gw.write_register(REG_CLEARING_PRICE, est_price * 100)

        # Restore surplus and generation
        gw.write_register(REG_SURPLUS, est_surplus)
        gw.write_register(REG_GENERATION, est_gen)

        print(f"    [OK] Allocations restored (alloc = bid qty)")
        print(f"    [OK] Price ≈ ${est_price}/MWh (estimated from bid prices)")
        print(f"    [OK] Generation ≈ {est_gen} kW, Surplus ≈ {est_surplus} kW")
        print(f"    Note: HELICS will overwrite with exact values within ~60s")
    else:
        print(f"    [WARN] Cannot read gateway — registers will restore on next HELICS cycle (~60s)")

    # Wait for gateway to process
    time.sleep(2)

    # Phase 4: Verify
    print()
    print("[+] Phase 4: Verifying recovery...")
    findings = detect(gw, targets)
    print_findings(findings, targets)

    if is_compromised(findings, targets):
        print()
        print("  WARNING: Some indicators still active — manual intervention may be needed")
        return False
    else:
        print()
        print("  Recovery successful — market operating normally")
        return True


# =============================================================================
# Main
# =============================================================================
def stop_attacker():
    """Kill the local attack process — SIM-ONLY convenience.

    The market attack re-injects its spoof/breaker-open every ~1s, so while it
    runs a one-shot restore is overwritten within a cycle. This pkills the local
    scada_market_attack.py so restore can stick.

    NOTE: this is only meaningful in the test/sim harness. A real blue team
    cannot kill the adversary's process — it would isolate the injection path
    (block the gateway Modbus port / disable the compromised channel) instead.
    """
    import subprocess
    script = 'scada_market_attack.py'
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
        description="Blue Team: Detect & restore market manipulation attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
    --detect      Sensing only (S2) — scan and report, no changes
    --restore     Defence (D2) — detect then restore
                  Add --interval N for continuous loop

Examples:
    # S2: Detect across all microgrids (sensing only)
    python attacks/scada_market_recovery.py --detect

    # D2: One-shot detect + restore all microgrids
    python attacks/scada_market_recovery.py --restore

    # D2: Continuous detect + auto-restore (every 5s)
    python attacks/scada_market_recovery.py --restore --interval 5
        """
    )
    parser.add_argument('--detect', action='store_true',
                        help='Sensing only (S2) — scan and report, no restore')
    parser.add_argument('--restore', action='store_true',
                        help='Detect + auto-restore (D2). Add --interval for continuous loop')
    parser.add_argument('--stop-attacker', action='store_true',
                        help='Kill the local attack process first (SIM-ONLY) so a live '
                             'attack does not overwrite the restore')
    parser.add_argument('--interval', type=int, default=0,
                        help='Continuous loop interval in seconds (0 = one-shot)')
    parser.add_argument('--gateway-host', default='localhost',
                        help='SCADA gateway host')
    parser.add_argument('--gateway-port', type=int, default=GATEWAY_PORT,
                        help=f'SCADA gateway Modbus port (default: {GATEWAY_PORT})')
    parser.add_argument('--plc-host', default='localhost',
                        help='PLC host (default: localhost)')
    parser.add_argument('--env-file', default=DEFAULT_ENV_FILE,
                        help=f'Load service addresses from env file (default: {DEFAULT_ENV_FILE})')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # Override defaults from env file (explicit CLI args take priority).
    # Silently skip if the default path doesn't exist (e.g., running from dev tree).
    if args.env_file and os.path.isfile(args.env_file):
        from env_loader import load_env_file, resolve_addresses
        addrs = resolve_addresses(load_env_file(args.env_file))
        if args.gateway_host == 'localhost':
            args.gateway_host = addrs['gateway_host']
        if args.gateway_port == GATEWAY_PORT:
            args.gateway_port = addrs['gateway_port']
        for mg, (host, port) in addrs['plc_hosts'].items():
            PLC_HOSTS[mg] = host
            PLC_PORTS[mg] = port
    elif args.plc_host != 'localhost':
        for mg in PLC_HOSTS:
            PLC_HOSTS[mg] = args.plc_host

    if not args.detect and not args.restore and not args.stop_attacker:
        parser.print_help()
        sys.exit(1)

    # Stop the local attack process first (sim-only) so a live continuous attack
    # doesn't overwrite the restore. Runs before detect/restore.
    if args.stop_attacker:
        print("[+] Stopping local attack process (sim-only)...")
        stop_attacker()
        print()
        if not args.detect and not args.restore:
            sys.exit(0)

    # Always cover all microgrids (no per-MG targeting)
    targets = ['mg1', 'mg2', 'mg3', 'mg4']

    # Determine mode
    if args.detect:
        mode = "Detect (S2 — sensing only)"
    elif args.interval > 0:
        mode = f"Restore (D2 — continuous, every {args.interval}s)"
    else:
        mode = "Restore (D2 — one-shot)"

    print("=" * 60)
    print("  Blue Team: Market Attack Detection & Recovery")
    print("=" * 60)
    print(f"  Gateway: {args.gateway_host}:{args.gateway_port} (unit {GATEWAY_UNIT_ID})")
    print(f"  Mode: {mode}")
    print(f"  Scope: {', '.join(t.upper() for t in targets)}")
    print()

    # Connect to gateway
    gw = ModbusClient(args.gateway_host, args.gateway_port, GATEWAY_UNIT_ID)
    if not gw.connect():
        print(f"[-] Cannot connect to SCADA gateway "
              f"at {args.gateway_host}:{args.gateway_port}")
        sys.exit(1)

    # -- --detect: Sensing only (S2) --
    if args.detect:
        print("[+] Scanning for market attack indicators...")
        findings = detect(gw, targets)
        print_findings(findings, targets)
        gw.close()
        sys.exit(0)

    # -- --restore: Detect + auto-restore (D2) --
    if args.interval > 0:
        # Continuous loop
        print(f"[+] Continuous restore every {args.interval}s (Ctrl+C to stop)...")
        print()
        try:
            while True:
                findings = detect(gw, targets)
                ts = time.strftime('%H:%M:%S')
                if is_compromised(findings, targets):
                    alerts = len(findings['alerts'])
                    print(f"  [{ts}] ALERT: {alerts} indicator(s) — restoring...",
                          flush=True)
                    restore(gw, targets)
                    print()
                else:
                    print(f"  [{ts}] OK — market operating normally", flush=True)

                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n  Restore loop stopped.")
            gw.close()
            sys.exit(0)
    else:
        # One-shot
        print("[+] Scanning for market attack indicators...")
        findings = detect(gw, targets)
        print_findings(findings, targets)

        if not is_compromised(findings, targets):
            print()
            print("  No attack detected — nothing to restore")
            gw.close()
            sys.exit(0)

        print()
        print(f"[+] Restoring market state...")
        print()
        ok = restore(gw, targets)
        gw.close()
        print()
        print("=" * 60)
        print(f"  Recovery {'complete' if ok else 'incomplete — check logs'}")
        print("=" * 60)


if __name__ == '__main__':
    main()
