#!/usr/bin/env python3
"""
Blue Team Defence: Detect & Restore MITM Attacks
==================================================
Counter-action for scada_mitm_attack.py. Detects both the blinding variant
(PLC data sources disabled) and any data-source redirection (proxy) that
remains visible in the ScadaLTS configuration.

Detection (S3 — sensing):
  - Checks PLC data source status (disabled = blinding attack)
  - Checks MG1_PLC data source host/port (redirected = proxy attack)
  - Checks breaker states via direct Modbus read (open = compromised)
  - Checks Market_Control overrides on PLCs
  - Checks Operator Mode on SCADA Gateway

Recovery (D3 — defence):
  1. Re-enable disabled PLC data sources (unblind SCADA)
  2. Restore redirected data source to original PLC address
  3. Close breakers (clear Market_Control + set Cmd_Input = TRUE)
  4. Clear Operator Mode on SCADA Gateway
  5. Verify restoration

Usage:
    # Detection only (no changes) — S3 sensing
    python attacks/scada_mitm_recovery.py --detect

    # Detect + restore all microgrids — D3 defence (one-shot)
    python attacks/scada_mitm_recovery.py --restore

    # Continuous detect + auto-restore loop — D3 defence (continuous)
    python attacks/scada_mitm_recovery.py --restore --interval 5

MITRE ATT&CK ICS: D3-PSA (Process State Awareness), D3-ORA (Operational Risk Assessment)
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
# Constants
# =============================================================================
FC_READ_COILS = 0x01
FC_WRITE_SINGLE_COIL = 0x05
COIL_ON = 0xFF00
COIL_OFF = 0x0000
MODBUS_UNIT_ID = 1

# PLC coil maps
LOAD_PLC_COILS = {
    'Main_Breaker_Closed': 0,
    'Load_Breaker_Closed': 1,
    'Bidder_Breaker_Closed': 2,
    'Market_Control': 3,
    'Main_Cmd_Input': 4,
    'Load_Cmd_Input': 5,
    'Bidder_Cmd_Input': 6,
}
GEN_PLC_COILS = {
    'Main_Breaker_Closed': 0,
    'Gen_Online': 1,
    'Market_Control': 2,
    'Main_Cmd_Input': 3,
    'Gen_Cmd_Input': 4,
}

# PLC addresses (overridden by --env-file)
PLC_HOSTS = {'mg1': 'localhost', 'mg2': 'localhost', 'mg3': 'localhost', 'mg4': 'localhost'}
PLC_PORTS = {'mg1': 502, 'mg2': 503, 'mg3': 504, 'mg4': 505}

# SCADA Gateway
GATEWAY_HOST = 'localhost'
GATEWAY_PORT = 5020
GATEWAY_UNIT_ID = 10
GATEWAY_OPERATOR_MODE_COIL = 12

# Expected original data source hosts (Docker internal names)
EXPECTED_DS_HOSTS = {
    'MG1_PLC': 'mg1_plc',
    'MG2_PLC': 'mg2_plc',
    'MG3_PLC': 'mg3_plc',
    'MG4_PLC': 'mg4_plc',
}
EXPECTED_DS_PORT = 502


# =============================================================================
# Raw Modbus TCP client
# =============================================================================
class ModbusClient:
    """Minimal raw Modbus TCP client."""

    def __init__(self, host, port, unit_id=MODBUS_UNIT_ID):
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

    def write_coil(self, address, value):
        self.txn_id = (self.txn_id + 1) % 65536
        coil_val = COIL_ON if value else COIL_OFF
        pdu = struct.pack('>BHH', FC_WRITE_SINGLE_COIL, address, coil_val)
        header = struct.pack('>HHHB', self.txn_id, 0, len(pdu) + 1, self.unit_id)
        try:
            self.sock.sendall(header + pdu)
            resp = self.sock.recv(256)
            return resp and len(resp) >= 12 and not (resp[7] & 0x80)
        except socket.error:
            return False

    def read_coils(self, start, count):
        self.txn_id = (self.txn_id + 1) % 65536
        pdu = struct.pack('>BHH', FC_READ_COILS, start, count)
        header = struct.pack('>HHHB', self.txn_id, 0, len(pdu) + 1, self.unit_id)
        try:
            self.sock.sendall(header + pdu)
            resp = self.sock.recv(256)
            if not resp or len(resp) < 10 or (resp[7] & 0x80):
                return None
            cb = resp[9:9 + resp[8]]
            return [bool(cb[i // 8] & (1 << (i % 8))) for i in range(count)]
        except socket.error:
            return None


# =============================================================================
# ScadaLTS interaction
# =============================================================================
class ScadaClient:
    """ScadaLTS client for data source management and detection."""

    def __init__(self, scada_url, verbose=False):
        self.base = scada_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })
        self.verbose = verbose
        self.jsession = ''
        self.ds_map = {}  # name -> {id, enabled, ...}
        self.batch_id = 0

    def log(self, msg):
        if self.verbose:
            print(f"  [*] {msg}")

    def login(self):
        """Authenticate to ScadaLTS."""
        print("[+] Authenticating to ScadaLTS...")
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
                print("    [OK] Authenticated as admin")
                return True
        except requests.RequestException as e:
            print(f"    [FAIL] Connection error: {e}")
        print("    [FAIL] Authentication failed")
        return False

    def discover_datasources(self):
        """Get all data sources with full details."""
        try:
            resp = self.session.get(
                f"{self.base}/api/datasource/getAll", timeout=5)
            if resp.status_code == 200:
                for ds in resp.json():
                    self.ds_map[ds['name']] = {
                        'id': ds['id'],
                        'enabled': ds.get('enabled', True),
                        'connection': ds.get('connection', {}),
                    }
                return True
        except Exception:
            pass
        return False

    def toggle_datasource(self, ds_id):
        """Toggle data source enabled/disabled via DWR."""
        self.batch_id += 1
        dwr_data = (
            f"callCount=1\n"
            f"page=/Scada-LTS/data_sources.shtm\n"
            f"httpSessionId={self.jsession}\n"
            f"scriptSessionId=\n"
            f"c0-scriptName=DataSourceListDwr\n"
            f"c0-methodName=toggleDataSource\n"
            f"c0-id=0\n"
            f"c0-param0=number:{ds_id}\n"
            f"batchId={self.batch_id}\n"
        )
        try:
            resp = self.session.post(
                f"{self.base}/dwr/call/plaincall/"
                f"DataSourceListDwr.toggleDataSource.dwr",
                data=dwr_data,
                headers={'Content-Type': 'text/plain'},
                timeout=10,
            )
            return 'remoteHandleCallback' in resp.text
        except Exception:
            return False

    def save_datasource_address(self, ds_id, name, host, port):
        """Restore data source host/port via DWR (for proxy attack recovery)."""
        self.session.get(
            f"{self.base}/data_source_edit.shtm?dsid={ds_id}", timeout=10)
        self.jsession = self.session.cookies.get('JSESSIONID', '')

        self.batch_id += 1
        dwr_data = (
            f"callCount=1\n"
            f"page=/Scada-LTS/data_source_edit.shtm?dsid={ds_id}\n"
            f"httpSessionId={self.jsession}\n"
            f"scriptSessionId=\n"
            f"c0-scriptName=DataSourceEditDwr\n"
            f"c0-methodName=saveModbusIpDataSource\n"
            f"c0-id=0\n"
            f"c0-param0=string:{name}\n"
            f"c0-param1=string:DS_{name}\n"
            f"c0-param2=number:1\n"
            f"c0-param3=number:1\n"
            f"c0-param4=boolean:false\n"
            f"c0-param5=number:500\n"
            f"c0-param6=number:2\n"
            f"c0-param7=boolean:false\n"
            f"c0-param8=boolean:false\n"
            f"c0-param9=number:2000\n"
            f"c0-param10=number:125\n"
            f"c0-param11=number:120\n"
            f"c0-param12=string:TCP\n"
            f"c0-param13=string:{host}\n"
            f"c0-param14=number:{port}\n"
            f"c0-param15=boolean:false\n"
            f"c0-param16=boolean:false\n"
            f"batchId={self.batch_id}\n"
        )
        try:
            resp = self.session.post(
                f"{self.base}/dwr/call/plaincall/"
                f"DataSourceEditDwr.saveModbusIpDataSource.dwr",
                data=dwr_data,
                headers={'Content-Type': 'text/plain'},
                timeout=10,
            )
            return 'remoteHandleCallback' in resp.text
        except Exception:
            return False

    def read_point(self, xid):
        try:
            resp = self.session.get(
                f"{self.base}/api/point_value/getValue/{xid}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get('value')
        except Exception:
            pass
        return None


# =============================================================================
# Detection
# =============================================================================
def detect(scada, targets):
    """Scan for MITM attack indicators.

    Returns dict with:
      - alerts: list of string descriptions
      - disabled_ds: list of disabled data source names
      - redirected_ds: list of {name, current_host, current_port, expected_host}
      - open_breakers: dict of MG -> list of open breaker names
      - plc_overrides: dict of MG -> bool
      - operator_mode: bool or None
    """
    findings = {
        'alerts': [],
        'disabled_ds': [],
        'redirected_ds': [],
        'open_breakers': {},
        'plc_overrides': {},
        'operator_mode': None,
    }

    # Check data sources
    for mg_id in targets:
        ds_name = f"{mg_id.upper()}_PLC"
        ds = scada.ds_map.get(ds_name)
        if not ds:
            continue

        # Check if disabled (blinding attack)
        if not ds['enabled']:
            findings['disabled_ds'].append(ds_name)
            findings['alerts'].append(
                f"{ds_name} data source DISABLED — SCADA blinded")

        # Check if redirected (proxy attack)
        conn = ds.get('connection', {})
        ds_host = conn.get('host', '')
        ds_port = conn.get('port', 0)
        expected_host = EXPECTED_DS_HOSTS.get(ds_name, '')

        if expected_host and ds_host and ds_host != expected_host:
            findings['redirected_ds'].append({
                'name': ds_name, 'id': ds['id'],
                'current_host': ds_host, 'current_port': ds_port,
                'expected_host': expected_host,
            })
            findings['alerts'].append(
                f"{ds_name} REDIRECTED to {ds_host}:{ds_port} "
                f"(expected {expected_host}:{EXPECTED_DS_PORT})")

    # Check breakers via direct Modbus to PLCs
    for mg_id in targets:
        port = PLC_PORTS[mg_id]

        # Retry connection (OpenPLC can drop connections under rapid access)
        plc = None
        for attempt in range(2):
            plc = ModbusClient(PLC_HOSTS[mg_id], port)
            if plc.connect():
                break
            plc = None
            if attempt == 0:
                time.sleep(0.5)

        if plc is None:
            findings['open_breakers'][mg_id] = None
            findings['plc_overrides'][mg_id] = None
            continue

        if mg_id == 'mg4':
            coils_map = GEN_PLC_COILS
            num_coils = 5
        else:
            coils_map = LOAD_PLC_COILS
            num_coils = 7

        coil_states = plc.read_coils(0, num_coils)
        plc.close()

        if not coil_states:
            findings['open_breakers'][mg_id] = None
            findings['plc_overrides'][mg_id] = None
            continue

        # Check breakers
        open_list = []
        if not coil_states[coils_map['Main_Breaker_Closed']]:
            open_list.append('main')
        if mg_id == 'mg4':
            if not coil_states[coils_map['Gen_Online']]:
                open_list.append('gen')
        else:
            if not coil_states[coils_map['Load_Breaker_Closed']]:
                open_list.append('load')
            if not coil_states[coils_map['Bidder_Breaker_Closed']]:
                open_list.append('bidder')

        findings['open_breakers'][mg_id] = open_list
        if open_list:
            findings['alerts'].append(
                f"{mg_id.upper()}: breakers OPEN — {', '.join(open_list)}")

        # Check Market_Control override
        override = coil_states[coils_map['Market_Control']]
        findings['plc_overrides'][mg_id] = override

    # Check Operator Mode on gateway
    gw = ModbusClient(GATEWAY_HOST, GATEWAY_PORT, GATEWAY_UNIT_ID)
    if gw.connect():
        gw_coils = gw.read_coils(GATEWAY_OPERATOR_MODE_COIL, 1)
        gw.close()
        if gw_coils:
            findings['operator_mode'] = gw_coils[0]
            if gw_coils[0]:
                findings['alerts'].append("SCADA Gateway Operator Mode ENABLED")
    else:
        findings['operator_mode'] = None

    return findings


def print_findings(findings, targets):
    """Print detection results."""
    # Data sources
    if findings['disabled_ds']:
        print(f"  Data Sources DISABLED (ALERT): {', '.join(findings['disabled_ds'])}")
    else:
        print(f"  Data Sources: all enabled (normal)")

    if findings['redirected_ds']:
        for rd in findings['redirected_ds']:
            print(f"  Data Source REDIRECTED (ALERT): {rd['name']} -> "
                  f"{rd['current_host']}:{rd['current_port']} "
                  f"(should be {rd['expected_host']}:{EXPECTED_DS_PORT})")

    # Operator Mode
    if findings['operator_mode'] is True:
        print(f"  Gateway Operator_Mode: ENABLED (ALERT)")
    elif findings['operator_mode'] is False:
        print(f"  Gateway Operator_Mode: disabled (normal)")
    else:
        print(f"  Gateway Operator_Mode: unreachable")
    print()

    # Per-MG state
    for mg_id in targets:
        open_brk = findings['open_breakers'].get(mg_id)
        plc_ovr = findings['plc_overrides'].get(mg_id)

        if open_brk is None:
            print(f"  {mg_id.upper()} [UNREACHABLE]")
            continue

        open_str = ', '.join(open_brk) if open_brk else 'none'
        # Market_Control=TRUE is normal for MG1-3 (gateway always controls bidder
        # breakers via Point Links).  Only MG4 Market_Control=TRUE is suspicious
        # (generator PLC is normally in AUTO mode).
        if plc_ovr is True:
            if mg_id == 'mg4':
                ovr_str = "TRUE (ALERT — normally FALSE for generator)"
            else:
                ovr_str = "TRUE (normal for load MGs)"
        elif plc_ovr is False:
            ovr_str = "false (normal)"
        else:
            ovr_str = "unknown"

        compromised = bool(open_brk) or (mg_id == 'mg4' and plc_ovr is True)
        tag = "[COMPROMISED]" if compromised else "[OK]"
        print(f"  {mg_id.upper()} {tag}")
        print(f"    Open breakers: {open_str}")
        print(f"    Market_Control: {ovr_str}")

    print()
    if findings['alerts']:
        print(f"  ALERTS ({len(findings['alerts'])}):")
        for alert in findings['alerts']:
            print(f"    - {alert}")
    else:
        print("  No attack indicators detected — grid operating normally")


def is_compromised(findings):
    """Return True if any attack indicators are present."""
    # Check data source level indicators
    if findings['disabled_ds'] or findings['redirected_ds']:
        return True
    if findings['operator_mode'] is True:
        return True
    # Check per-MG breaker/override indicators
    for mg_id, open_brk in findings['open_breakers'].items():
        if open_brk:  # non-empty list = breakers open
            return True
    # Market_Control=TRUE is only suspicious for MG4
    if findings['plc_overrides'].get('mg4') is True:
        return True
    return False


# =============================================================================
# Recovery
# =============================================================================
def restore(scada, targets):
    """Restore grid after a MITM attack."""

    # Phase 1: Re-enable disabled data sources
    if findings_cache.get('disabled_ds'):
        print("[+] Phase 1: Re-enabling disabled PLC data sources...")
        for ds_name in findings_cache['disabled_ds']:
            ds = scada.ds_map.get(ds_name)
            if ds:
                ok = scada.toggle_datasource(ds['id'])
                status = "OK" if ok else "FAIL"
                print(f"    [{status}] {ds_name} (id={ds['id']}) -> ENABLED")
                time.sleep(0.3)
    else:
        print("[+] Phase 1: No disabled data sources to re-enable")

    # Phase 2: Restore redirected data sources
    if findings_cache.get('redirected_ds'):
        print()
        print("[+] Phase 2: Restoring redirected data sources...")
        for rd in findings_cache['redirected_ds']:
            ds = scada.ds_map.get(rd['name'])
            if not ds:
                continue
            # Disable, save original address, re-enable
            if ds['enabled']:
                scada.toggle_datasource(ds['id'])
                time.sleep(0.5)
            ok = scada.save_datasource_address(
                ds['id'], rd['name'], rd['expected_host'], EXPECTED_DS_PORT)
            status = "OK" if ok else "FAIL"
            print(f"    [{status}] {rd['name']} -> {rd['expected_host']}:{EXPECTED_DS_PORT}")
            scada.toggle_datasource(ds['id'])
            time.sleep(0.5)
    else:
        print()
        print("[+] Phase 2: No redirected data sources to restore")

    # Phase 3: Close breakers (clear Market_Control + set Cmd_Input TRUE)
    print()
    print("[+] Phase 3: Closing breakers on target PLCs...")
    for mg_id in targets:
        port = PLC_PORTS[mg_id]

        # Retry connection (OpenPLC can drop connections under rapid access)
        plc = None
        for attempt in range(2):
            plc = ModbusClient(PLC_HOSTS[mg_id], port)
            if plc.connect():
                break
            plc = None
            if attempt == 0:
                time.sleep(0.5)

        if plc is None:
            print(f"    [FAIL] {mg_id.upper()} — PLC unreachable on port {port}")
            continue

        if mg_id == 'mg4':
            coils_map = GEN_PLC_COILS
            cmd_keys = ['Main_Cmd_Input', 'Gen_Cmd_Input']
        else:
            coils_map = LOAD_PLC_COILS
            cmd_keys = ['Main_Cmd_Input', 'Load_Cmd_Input', 'Bidder_Cmd_Input']

        # Close all breakers FIRST (while Market_Control is still TRUE,
        # so the PLC actually obeys Cmd_Input).  If we clear Market_Control
        # first, the PLC switches to AUTO mode and ignores Cmd_Input writes.
        for key in cmd_keys:
            plc.write_coil(coils_map[key], True)
            time.sleep(0.05)

        # Now clear Market_Control override (PLC returns to AUTO mode,
        # but breakers are already in the right state).
        # Note: for MG1-3, ScadaLTS Point Links will restore Market_Control=TRUE
        # within ~1-2s (normal operating state), which is fine since Cmd_Input
        # is already TRUE.
        plc.write_coil(coils_map['Market_Control'], False)

        plc.close()
        cmds = ', '.join(k.replace('_Cmd_Input', '') for k in cmd_keys)
        print(f"    [OK] {mg_id.upper()}: {cmds}=CLOSE, Market_Control=FALSE")

    # Phase 4: Clear Operator Mode on gateway
    print()
    print("[+] Phase 4: Clearing Operator Mode on SCADA Gateway...")
    gw = ModbusClient(GATEWAY_HOST, GATEWAY_PORT, GATEWAY_UNIT_ID)
    if gw.connect():
        ok = gw.write_coil(GATEWAY_OPERATOR_MODE_COIL, False)
        gw.close()
        status = "OK" if ok else "FAIL"
        print(f"    [{status}] Operator Mode = FALSE")
    else:
        print("    [FAIL] Cannot connect to SCADA gateway")

    # Wait for SCADA to poll fresh values
    time.sleep(3)

    # Phase 5: Verify
    print()
    print("[+] Phase 5: Verifying recovery...")
    # Re-discover data sources (state may have changed)
    scada.discover_datasources()
    findings = detect(scada, targets)
    print_findings(findings, targets)

    if is_compromised(findings):
        print()
        print("  WARNING: Some indicators still active — manual intervention may be needed")
        return False
    else:
        print()
        print("  Recovery successful — grid operating normally")
        return True


# Global to pass findings from detect to restore
findings_cache = {}


# =============================================================================
# Main
# =============================================================================
def stop_attacker():
    """Kill the local attack process — SIM-ONLY convenience.

    The MITM attack re-injects every ~0.5 s (its Phase-6 loop) to beat the
    gateway's overwrite cycle, so a bare --restore is overwritten before it
    sticks; this stops the attack first. No-op if it isn't running. Real
    incidents can't kill the adversary — they isolate the injection path
    (block the PLC/gateway Modbus path) instead."""
    import subprocess
    script = 'scada_mitm_attack.py'
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
    global findings_cache

    parser = argparse.ArgumentParser(
        description="Blue Team: Detect & restore MITM attacks (blinding + proxy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
    --detect      Sensing only (S3) — scan and report, no changes
    --restore     Defence (D3) — detect then restore
                  Add --interval N for continuous loop

Detects both MITM variants:
    1. Blinding — disabled PLC data sources (scada_mitm_attack.py)
    2. Proxy — redirected PLC data source (any in-flight Modbus proxy)

Examples:
    # S3: Detect across all microgrids (sensing only)
    python attacks/scada_mitm_recovery.py --detect

    # D3: One-shot detect + restore all microgrids
    python attacks/scada_mitm_recovery.py --restore

    # D3: Continuous detect + auto-restore (every 5s)
    python attacks/scada_mitm_recovery.py --restore --interval 5
        """
    )
    parser.add_argument('--detect', action='store_true',
                        help='Sensing only (S3) — scan and report, no restore')
    parser.add_argument('--restore', action='store_true',
                        help='Detect + auto-restore (D3). Add --interval for continuous loop')
    parser.add_argument('--stop-attacker', action='store_true',
                        help='Kill the local attack process first (SIM-ONLY) before restore')
    parser.add_argument('--interval', type=int, default=0,
                        help='Continuous loop interval in seconds (0 = one-shot)')
    parser.add_argument('--plc-host', default='localhost',
                        help='PLC host (default: localhost)')
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
    elif args.plc_host != 'localhost':
        for mg in PLC_HOSTS:
            PLC_HOSTS[mg] = args.plc_host

    if not args.detect and not args.restore and not args.stop_attacker:
        parser.print_help()
        sys.exit(1)

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
        mode = "Detect (S3 — sensing only)"
    elif args.interval > 0:
        mode = f"Restore (D3 — continuous, every {args.interval}s)"
    else:
        mode = "Restore (D3 — one-shot)"

    print("=" * 60)
    print("  Blue Team: MITM Attack Detection & Recovery")
    print("=" * 60)
    print(f"  SCADA: {args.scada_url}")
    print(f"  Mode: {mode}")
    print(f"  Scope: {', '.join(t.upper() for t in targets)}")
    print()

    scada = ScadaClient(args.scada_url, verbose=args.verbose)

    if not scada.login():
        sys.exit(1)

    print()
    print("[+] Discovering SCADA data sources...")
    if not scada.discover_datasources():
        print("    [-] Failed to enumerate data sources")
        sys.exit(1)
    for name, info in scada.ds_map.items():
        state = "enabled" if info['enabled'] else "DISABLED"
        print(f"    {name} (id={info['id']}) [{state}]")
    print()

    # -- --detect: Sensing only (S3) --
    if args.detect:
        print("[+] Scanning for MITM attack indicators...")
        print()
        findings = detect(scada, targets)
        print_findings(findings, targets)
        sys.exit(0)

    # -- --restore: Detect + auto-restore (D3) --
    if args.interval > 0:
        # Continuous loop
        print(f"[+] Continuous restore every {args.interval}s (Ctrl+C to stop)...")
        print()
        try:
            while True:
                scada.discover_datasources()
                findings = detect(scada, targets)
                findings_cache = findings
                ts = time.strftime('%H:%M:%S')
                if is_compromised(findings):
                    alerts = len(findings['alerts'])
                    print(f"  [{ts}] ALERT: {alerts} indicator(s) — restoring...",
                          flush=True)
                    restore(scada, targets)
                    print()
                else:
                    print(f"  [{ts}] OK — no MITM indicators detected", flush=True)

                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n  Restore loop stopped.")
            sys.exit(0)
    else:
        # One-shot
        print("[+] Scanning for MITM attack indicators...")
        print()
        findings = detect(scada, targets)
        findings_cache = findings
        print_findings(findings, targets)

        if not is_compromised(findings):
            print()
            print("  No attack detected — nothing to restore")
            sys.exit(0)

        print()
        print(f"[+] Restoring grid state...")
        print()
        ok = restore(scada, targets)
        print()
        print("=" * 60)
        print(f"  Recovery {'complete' if ok else 'incomplete — check logs'}")
        print("=" * 60)


if __name__ == '__main__':
    main()
