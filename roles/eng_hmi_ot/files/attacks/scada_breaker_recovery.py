#!/usr/bin/env python3
"""
Blue Team Defence: Restore Breakers & Detect Override Attacks
=============================================================
Counter-action for scada_breaker_attack.py SCADA-path attack. Single
configuration for testing across all microgrids (MG1-MG4).

Detection:
  - Checks Operator_Mode on SCADA Gateway
  - Checks Market_Control on each PLC
  - Checks breaker states (main or downstream open = compromised)
  - Checks Point Links (disabled = attacker cut the SCADA→PLC path)

Recovery:
  1. Re-enable disabled Point Links (restores SCADA→PLC control path)
  2. Close every open breaker (set Cmd_Input = TRUE). main is the upstream
     breaker, so if it is open recovery closes main too — closing the
     downstream breaker alone while main is open would leave the microgrid
     disconnected. Downstream breaker is LOAD on mg1-3, GEN on mg4.
  3. Disable Operator Mode on SCADA Gateway
  4. Verify breakers restored

Usage:
    # Detection only (no changes) — S1 sensing
    python attacks/scada_breaker_recovery.py --detect

    # Detect + restore — D1 defence (one-shot)
    python attacks/scada_breaker_recovery.py --restore

    # Continuous detect + auto-restore loop — D1 defence (continuous)
    python attacks/scada_breaker_recovery.py --restore --interval 5

    # Remote cluster
    python attacks/scada_breaker_recovery.py --restore --env-file deployment/prod.env

MITRE ATT&CK ICS: D3-PSA (Process State Awareness), D3-ORA (Operational Risk Assessment)
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time
import requests

# Default env file location: prod.env sits one directory above this script
# on deployed VMs (e.g., /opt/powergrid/prod.env, with scripts in /opt/powergrid/attacks/).
# The env file only supplies service addresses (ScadaLTS host/port, gateway,
# PLCs); without it (or on localhost) the scripts fall back to localhost defaults.
DEFAULT_ENV_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'prod.env'
)

# Microgrids covered by this test recovery (all four).
TARGETS = ['mg1', 'mg2', 'mg3', 'mg4']

# =============================================================================
# ScadaLTS Data Point IDs (must match scada_breaker_attack.py)
# =============================================================================
SCADA_POINTS = {
    'operator_mode': {'id': 99, 'xid': 'DP_Operator_Mode'},
    'mg1': {
        'market_control': {'xid': 'DP_MG1_PLC_Market_Control'},
        'main_cmd': {'xid': 'DP_MG1_PLC_Main_Cmd_Input'},
        'load_cmd': {'xid': 'DP_MG1_PLC_Load_Cmd_Input'},
        'main_breaker': {'xid': 'DP_MG1_PLC_Main_Breaker_Closed'},
        'load_breaker': {'xid': 'DP_MG1_PLC_Load_Breaker_Closed'},
    },
    'mg2': {
        'market_control': {'xid': 'DP_MG2_PLC_Market_Control'},
        'main_cmd': {'xid': 'DP_MG2_PLC_Main_Cmd_Input'},
        'load_cmd': {'xid': 'DP_MG2_PLC_Load_Cmd_Input'},
        'main_breaker': {'xid': 'DP_MG2_PLC_Main_Breaker_Closed'},
        'load_breaker': {'xid': 'DP_MG2_PLC_Load_Breaker_Closed'},
    },
    'mg3': {
        'market_control': {'xid': 'DP_MG3_PLC_Market_Control'},
        'main_cmd': {'xid': 'DP_MG3_PLC_Main_Cmd_Input'},
        'load_cmd': {'xid': 'DP_MG3_PLC_Load_Cmd_Input'},
        'main_breaker': {'xid': 'DP_MG3_PLC_Main_Breaker_Closed'},
        'load_breaker': {'xid': 'DP_MG3_PLC_Load_Breaker_Closed'},
    },
    'mg4': {
        'market_control': {'xid': 'DP_MG4_PLC_Market_Control'},
        'main_cmd': {'xid': 'DP_MG4_PLC_Main_Cmd_Input'},
        'gen_cmd': {'xid': 'DP_MG4_PLC_Gen_Cmd_Input'},
        'main_breaker': {'xid': 'DP_MG4_PLC_Main_Breaker_Closed'},
        'gen_online': {'xid': 'DP_MG4_PLC_Gen_Online'},
    },
}

# SCADA Gateway Modbus coil layout (unit 10, port 5020)
# The gateway exposes market data on its own Modbus server.
# Point Links in ScadaLTS copy gateway coil values → PLC data points.
GATEWAY_COIL_MARKET_CTRL = {'mg1': 4, 'mg2': 5, 'mg3': 6, 'mg4': 7}
GATEWAY_UNIT_ID = 10


def mg_breakers(mg_id):
    """Breakers on an MG as (name, state_key, cmd_key), main-first.

    main is listed first so recovery always closes the upstream breaker before
    the downstream one. The downstream breaker is LOAD on load microgrids
    (mg1-3) and GEN on the generator microgrid (mg4).
    """
    main = ('main', 'main_breaker', 'main_cmd')
    if mg_id == 'mg4':
        return [main, ('gen', 'gen_online', 'gen_cmd')]
    return [main, ('load', 'load_breaker', 'load_cmd')]


class ScadaDefender:
    """Blue team: detect and restore PLC breaker attacks via ScadaLTS."""

    def __init__(self, scada_url, gateway_host='localhost', gateway_port=5020,
                 verbose=False):
        self.base = scada_url.rstrip('/')
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })
        self.verbose = verbose
        self.jsession = ''

    def log(self, msg):
        if self.verbose:
            print(f"  [*] {msg}")

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def login(self):
        """Login to ScadaLTS with known credentials."""
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

    # ------------------------------------------------------------------
    # Point read/write
    # ------------------------------------------------------------------
    def read_point(self, xid):
        try:
            resp = self.session.get(
                f"{self.base}/api/point_value/getValue/{xid}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get('value')
        except Exception:
            pass
        return None

    def set_point_true(self, xid):
        try:
            resp = self.session.post(
                f"{self.base}/api/point_value/setValue/{xid}/1",
                headers={'Content-Type': 'application/json'},
                data='1', timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def resolve_point_id(self, xid):
        """Resolve a data point's numeric ID from its XID via the getValue API."""
        try:
            resp = self.session.get(
                f"{self.base}/api/point_value/getValue/{xid}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get('id')
        except Exception:
            pass
        return None

    def resolve_all_point_ids(self):
        """Resolve numeric point IDs from XIDs at runtime.

        ScadaLTS point IDs drift every time the config is re-imported, so any
        hardcoded ID in SCADA_POINTS will break DWR setPoint calls with a
        NullPointerException. Populate/overwrite the 'id' field for every
        entry that has an 'xid' using the live getValue response.
        """
        missing = []
        for key, val in SCADA_POINTS.items():
            if isinstance(val, dict) and 'xid' in val:
                pid = self.resolve_point_id(val['xid'])
                if pid is not None:
                    val['id'] = pid
                else:
                    missing.append(val['xid'])
            elif isinstance(val, dict):
                for sub_key, sub_val in val.items():
                    if isinstance(sub_val, dict) and 'xid' in sub_val:
                        pid = self.resolve_point_id(sub_val['xid'])
                        if pid is not None:
                            sub_val['id'] = pid
                        else:
                            missing.append(sub_val['xid'])
        if missing:
            print(f"    [-] Could not resolve IDs for: {', '.join(missing)}")
            return False
        return True

    def set_point_false(self, point_id):
        dwr_data = (
            f"callCount=1\n"
            f"page=/Scada-LTS/watch_list.shtm\n"
            f"httpSessionId={self.jsession}\n"
            f"scriptSessionId=\n"
            f"c0-scriptName=WatchListDwr\n"
            f"c0-methodName=setPoint\n"
            f"c0-id=0\n"
            f"c0-param0=number:{point_id}\n"
            f"c0-param1=string:0\n"
            f"c0-param2=number:0\n"
            f"batchId=1\n"
        )
        try:
            resp = self.session.post(
                f"{self.base}/dwr/call/plaincall/WatchListDwr.setPoint.dwr",
                data=dwr_data,
                headers={'Content-Type': 'text/plain'},
                timeout=10,
            )
            return 'remoteHandleCallback' in resp.text
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Point Link management
    # ------------------------------------------------------------------
    def get_point_links(self):
        """Get all Point Links from ScadaLTS database."""
        try:
            result = subprocess.run(
                ['docker', 'exec', 'scada_database', 'mysql', '-u', 'root', '-proot', 'scadalts',
                 '-e', 'SELECT id, xid, disabled FROM pointLinks;', '-N'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []
            links = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        links.append({'id': int(parts[0]), 'xid': parts[1],
                                      'disabled': parts[2].upper() == 'Y'})
            return links
        except Exception as e:
            self.log(f"Error querying Point Links: {e}")
            return []

    def get_point_link_details(self, link_id):
        """Get full Point Link details needed for DWR savePointLink call."""
        try:
            result = subprocess.run(
                ['docker', 'exec', 'scada_database', 'mysql', '-u', 'root', '-proot', 'scadalts',
                 '-e', f'SELECT sourcePointId, targetPointId, script, eventType FROM pointLinks WHERE id={link_id};', '-N'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split('\t')
                if len(parts) >= 4:
                    return {'sourcePointId': int(parts[0]), 'targetPointId': int(parts[1]),
                            'script': parts[2] if parts[2] != 'NULL' else '', 'eventType': int(parts[3])}
        except Exception:
            pass
        return None

    def set_point_link_disabled(self, link, disabled):
        """Enable or disable a single Point Link via DWR API."""
        details = self.get_point_link_details(link['id'])
        if not details:
            return False

        self.session.get(f"{self.base}/point_links.shtm", timeout=5)
        disabled_str = "true" if disabled else "false"
        save_data = (
            f"callCount=1\n"
            f"page=/Scada-LTS/point_links.shtm\n"
            f"httpSessionId={self.jsession}\n"
            f"scriptSessionId=\n"
            f"c0-scriptName=PointLinksDwr\n"
            f"c0-methodName=savePointLink\n"
            f"c0-id=0\n"
            f"c0-param0=number:{link['id']}\n"
            f"c0-param1=string:{link['xid']}\n"
            f"c0-param2=number:{details['sourcePointId']}\n"
            f"c0-param3=number:{details['targetPointId']}\n"
            f"c0-param4=string:{details['script']}\n"
            f"c0-param5=number:{details['eventType']}\n"
            f"c0-param6=boolean:{disabled_str}\n"
            f"batchId={link['id']}\n"
        )
        try:
            resp = self.session.post(
                f"{self.base}/dwr/call/plaincall/PointLinksDwr.savePointLink.dwr",
                data=save_data, headers={"Content-Type": "text/plain"}, timeout=10)
            return "exception" not in resp.text.lower()
        except Exception:
            return False

    def enable_all_point_links(self):
        """Re-enable all disabled Point Links (restore SCADA→PLC path)."""
        links = self.get_point_links()
        if not links:
            print("    [-] Cannot query Point Links (database unreachable)")
            return False

        disabled_links = [l for l in links if l['disabled']]
        if not disabled_links:
            print("    All Point Links already enabled")
            return True

        success = 0
        for link in disabled_links:
            ok = self.set_point_link_disabled(link, disabled=False)
            status = "OK" if ok else "FAIL"
            print(f"    [{status}] {link['xid']} ENABLED")
            if ok:
                success += 1

        return success == len(disabled_links)

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    def open_breakers(self, mg_id):
        """Return names of breakers currently open on an MG, main-first."""
        mg = SCADA_POINTS[mg_id]
        return [name for name, state_key, _ in mg_breakers(mg_id)
                if self.read_point(mg[state_key]['xid']) == 'false']

    def detect(self):
        """Scan grid for attack indicators. Returns dict of findings."""
        findings = {'compromised': [], 'operator_mode': False, 'disabled_links': [],
                    'system_alerts': [], 'details': {}}

        # Check Operator Mode
        op = self.read_point(SCADA_POINTS['operator_mode']['xid'])
        findings['operator_mode'] = (op == 'true')
        if findings['operator_mode']:
            findings['system_alerts'].append(
                'Operator_Mode is TRUE — attacker may have enabled manual override')

        # Check Point Links
        links = self.get_point_links()
        findings['disabled_links'] = [l['xid'] for l in links if l['disabled']]
        if findings['disabled_links']:
            findings['system_alerts'].append(
                f"{len(findings['disabled_links'])} Point Link(s) DISABLED — "
                "attacker may have cut SCADA-to-PLC auto-restore path")

        for mg_id in TARGETS:
            mg = SCADA_POINTS[mg_id]
            detail = {'market_control': False, 'open_breakers': []}

            # Check Market Control
            mkt_ctrl = self.read_point(mg['market_control']['xid'])
            detail['market_control'] = (mkt_ctrl == 'true')

            # Check breakers
            detail['open_breakers'] = self.open_breakers(mg_id)
            if detail['open_breakers']:
                findings['compromised'].append(mg_id)

            findings['details'][mg_id] = detail

        return findings

    def print_findings(self, findings):
        """Print detection results."""
        op_status = "TRUE (ALERT)" if findings['operator_mode'] else "false (normal)"
        print(f"  Operator_Mode: {op_status}")

        if findings['disabled_links']:
            names = ', '.join(findings['disabled_links'])
            print(f"  Point Links DISABLED (ALERT): {names}")
        else:
            print(f"  Point Links: all enabled (normal)")
        print()

        for mg_id, detail in findings['details'].items():
            mkt_str = "true" if detail['market_control'] else "FALSE (AUTO)"
            open_str = ', '.join(detail['open_breakers']) if detail['open_breakers'] else 'none'

            if mg_id in findings['compromised']:
                print(f"  {mg_id.upper()} [COMPROMISED]")
            else:
                print(f"  {mg_id.upper()} [OK]")
            print(f"    Market/Super_Control: {mkt_str}")
            print(f"    Open breakers: {open_str}")
            print()

        if findings['system_alerts']:
            for alert in findings['system_alerts']:
                print(f"  SYSTEM ALERT: {alert}")
            print()

        if findings['compromised']:
            count = len(findings['compromised'])
            names = ', '.join(mg.upper() for mg in findings['compromised'])
            print(f"  ALERT: {count} microgrid(s) compromised: {names}")
        elif findings['system_alerts']:
            print("  Breakers OK but system-level attack indicators present")
        else:
            print("  All microgrids operational — no attack detected")

    # ------------------------------------------------------------------
    # Gateway Modbus direct write (raw TCP)
    # ------------------------------------------------------------------
    @staticmethod
    def _modbus_write_coil(host, port, unit_id, address, value):
        """Write a single Modbus coil via raw TCP (FC=5)."""
        coil_val = 0xFF00 if value else 0x0000
        pdu = struct.pack('>BHH', 5, address, coil_val)
        header = struct.pack('>HHHB', 1, 0, len(pdu) + 1, unit_id)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((host, port))
            s.sendall(header + pdu)
            resp = s.recv(256)
            s.close()
            return resp and len(resp) >= 12 and not (resp[7] & 0x80)
        except socket.error:
            return False

    def _force_gateway_market_control(self, gw_host, gw_port):
        """Force Market_Control=TRUE on the SCADA Gateway's Modbus coils.

        The gateway's external_control mechanism preserves externally-written
        coil values, so this write sticks until the next Operator_Mode
        transition. Point Links then propagate TRUE to PLCs.
        """
        for mg_id in TARGETS:
            coil = GATEWAY_COIL_MARKET_CTRL[mg_id]
            ok = self._modbus_write_coil(gw_host, gw_port, GATEWAY_UNIT_ID,
                                         coil, True)
            status = "OK" if ok else "FAIL"
            print(f"    [{status}] Gateway {mg_id.upper()} Market_Ctrl = TRUE (coil {coil})")

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------
    def restore(self, targets):
        """Restore breakers on target microgrids.

        Closes every breaker currently open on each target — main-first, so the
        upstream breaker comes back before the downstream one. That means
        main+downstream when main was opened, and downstream only when just the
        downstream breaker was shed (the attack's default).
        """
        print("[+] Phase 1: Re-enabling Point Links (restore SCADA→PLC path)...")
        self.enable_all_point_links()

        print()
        print("[+] Phase 2: Ensuring Market/Super Control is active...")
        # Without Market_Control = TRUE, the PLC runs in AUTO mode and ignores
        # Cmd_Input writes entirely — breaker closes in Phase 3 won't take effect.
        #
        # Writing via ScadaLTS alone doesn't stick: Point Links continuously copy
        # the gateway's Market_Control coils to PLC data points, overwriting our
        # write within seconds. Instead, we force Market_Control=TRUE directly on
        # the SCADA Gateway's Modbus coils. The gateway's external_control mechanism
        # detects the external write and preserves it, so Point Links propagate
        # TRUE to PLCs and they switch to MARKET mode.
        self._force_gateway_market_control(self.gateway_host, self.gateway_port)
        # Wait for ScadaLTS to poll the gateway and Point Links to propagate
        print("    Waiting for Point Link propagation...")
        time.sleep(5)

        print()
        print("[+] Phase 3: Closing breakers...")
        for mg_id in targets:
            mg = SCADA_POINTS[mg_id]
            cmd_of = {name: cmd_key for name, _, cmd_key in mg_breakers(mg_id)}
            # Re-read state post point-link restore — close whatever is still
            # open. main-first ordering brings the upstream breaker back first.
            to_close = self.open_breakers(mg_id)
            if not to_close:
                print(f"    {mg_id.upper()}: no open breakers to close")
                continue
            for breaker in to_close:
                ok = self.set_point_true(mg[cmd_of[breaker]]['xid'])
                status = "OK" if ok else "FAIL"
                print(f"    [{status}] {mg_id.upper()} {breaker}_cmd = 1 (CLOSE)")
            time.sleep(0.3)

        print()
        print("[+] Phase 4: Disabling Operator Mode...")
        # Use the live-resolved point ID (resolve_all_point_ids ran after login).
        ok = self.set_point_false(SCADA_POINTS['operator_mode']['id'])
        status = "OK" if ok else "FAIL"
        print(f"    [{status}] Operator_Mode = 0")

        # Wait for PLCs to process
        time.sleep(3)

        # Verify
        print()
        print("[+] Phase 5: Verifying recovery...")
        findings = self.detect()
        self.print_findings(findings)

        still_bad = findings['compromised'] or findings['system_alerts']
        if still_bad:
            print("  WARNING: Some indicators still active — manual intervention needed")
            return False
        else:
            print("  Recovery successful — all microgrids operational")
            return True


def stop_attacker():
    """Kill the local attack process — SIM-ONLY convenience so restore isn't
    overwritten by a live attack. No-op if no such process is running. Real
    incidents can't kill the adversary — they isolate the injection path
    instead (most relevant for the continuous market attack)."""
    import subprocess
    script = 'scada_breaker_attack.py'
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
        description="Blue Team: Detect & restore breaker attacks via ScadaLTS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
    --detect      Sensing only (S1) — scan and report, no changes
    --restore     Defence (D1) — detect then restore compromised MGs
                  Add --interval N for continuous loop

Examples:
    # S1: Detect across all microgrids (sensing only)
    python attacks/scada_breaker_recovery.py --detect

    # D1: One-shot detect + restore
    python attacks/scada_breaker_recovery.py --restore

    # D1: Continuous detect + auto-restore (every 5s)
    python attacks/scada_breaker_recovery.py --restore --interval 5
        """
    )
    parser.add_argument('--detect', action='store_true',
                        help='Sensing only (S1) — scan and report, no restore')
    parser.add_argument('--restore', action='store_true',
                        help='Detect + auto-restore (D1). Add --interval for continuous loop')
    parser.add_argument('--stop-attacker', action='store_true',
                        help='Kill the local attack process first (SIM-ONLY) before restore')
    parser.add_argument('--interval', type=int, default=0,
                        help='Continuous loop interval in seconds (0 = one-shot)')
    parser.add_argument('--scada-url', default='http://localhost:8080/Scada-LTS',
                        help='ScadaLTS base URL')
    parser.add_argument('--env-file', default=DEFAULT_ENV_FILE,
                        help=f'Load service addresses from env file (default: {DEFAULT_ENV_FILE})')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # Override defaults from env file (explicit CLI args take priority).
    # Silently skip if the default path doesn't exist (e.g., running from dev tree).
    gateway_host = 'localhost'
    gateway_port = 5020
    if args.env_file and os.path.isfile(args.env_file):
        from env_loader import load_env_file, resolve_addresses
        addrs = resolve_addresses(load_env_file(args.env_file))
        if args.scada_url == 'http://localhost:8080/Scada-LTS':
            args.scada_url = addrs['scada_url']
        gateway_host = addrs.get('gateway_host', 'localhost')
        gateway_port = addrs.get('gateway_port', 5020)

    if not args.detect and not args.restore and not args.stop_attacker:
        parser.print_help()
        sys.exit(1)

    if args.stop_attacker:
        print("[+] Stopping local attack process (sim-only)...")
        stop_attacker()
        print()
        if not args.detect and not args.restore:
            sys.exit(0)

    # Determine mode
    if args.detect:
        mode = "Detect (S1 — sensing only)"
    elif args.interval > 0:
        mode = f"Restore (D1 — continuous, every {args.interval}s)"
    else:
        mode = "Restore (D1 — one-shot)"

    print("=" * 60)
    print("  Blue Team: Breaker Attack Detection & Recovery")
    print("=" * 60)
    print(f"  Target: {args.scada_url}")
    print(f"  Mode: {mode}")
    print(f"  Scope: {', '.join(t.upper() for t in TARGETS)}")
    print()

    defender = ScadaDefender(args.scada_url, gateway_host=gateway_host,
                             gateway_port=gateway_port, verbose=args.verbose)

    if not defender.login():
        sys.exit(1)

    # Resolve point IDs from XIDs (stale hardcoded IDs would break DWR writes).
    if not defender.resolve_all_point_ids():
        print("    [!] Some point IDs could not be resolved; writes may fail")

    # ── --detect: Sensing only (S1) ──────────────────────────────
    if args.detect:
        print()
        print("[+] Scanning for attack indicators...")
        print()
        findings = defender.detect()
        defender.print_findings(findings)
        sys.exit(0)

    # ── --restore: Detect + auto-restore (D1) ─────────────────────
    if args.interval > 0:
        # Continuous loop
        print()
        print(f"[+] Continuous restore every {args.interval}s (Ctrl+C to stop)...")
        print()
        try:
            while True:
                findings = defender.detect()
                ts = time.strftime('%H:%M:%S')
                if findings['compromised']:
                    names = ', '.join(mg.upper() for mg in findings['compromised'])
                    print(f"  [{ts}] ALERT: {names} compromised — restoring...", flush=True)
                    defender.restore(findings['compromised'])
                    print()
                else:
                    print(f"  [{ts}] OK — all microgrids operational", flush=True)

                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n  Restore loop stopped.")
            sys.exit(0)
    else:
        # One-shot
        print()
        print("[+] Scanning for attack indicators...")
        print()
        findings = defender.detect()
        defender.print_findings(findings)

        has_attack = findings['compromised'] or findings['system_alerts']
        if not has_attack:
            print("  No attack detected — nothing to restore")
            sys.exit(0)

        print()
        if findings['compromised']:
            print(f"[+] Restoring {len(findings['compromised'])} compromised microgrid(s)...")
        else:
            print("[+] Restoring system-level attack indicators...")
        print()
        # Restore compromised MGs; if none, still pass all targets so system-level
        # indicators (Operator_Mode, Point Links) get cleared.
        restore_targets = findings['compromised'] if findings['compromised'] else TARGETS
        ok = defender.restore(restore_targets)
        print()
        print("=" * 60)
        print(f"  Recovery {'complete' if ok else 'incomplete — check logs'}")
        print("=" * 60)


if __name__ == '__main__':
    main()
