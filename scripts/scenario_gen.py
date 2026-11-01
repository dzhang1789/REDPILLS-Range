#!/usr/bin/env python3
"""scenario_gen.py.

Reads a bailey-generated Ludus range config YAML and produces:
  - scenario.yml             Ansible playbook with flags/CVEs baked in
  - manifest.json            Answer key (what flag/CVE is on what host).
                              Phishing is out of scope here -- it's set up
                              by a separate Ludus role at range deploy time.
  - scenario-inventory.ini   Ansible inventory derived from the config

Usage:
    python3 scenario_gen.py goad-daniel-bailey.yml --seed 1234 --range-prefix 10.26
    python3 scenario_gen.py goad-daniel-bailey.yml --seed 1234 --range-prefix 10.26 \
        --flags 2 --vulns-per-host 1 --percent 50 --no-vulns

Input format: bailey-generated Ludus range config (the .yml bailey writes to
--out). NOT the bailey topology format. Pass the file from artifacts/ or the
rendered config.

IP addresses are derived as: <range-prefix>.<vlan>.<ip_last_octet>
e.g. prefix=10.26, vlan=30, octet=11 -> 10.26.30.11
"""

import argparse
import hashlib
import json
import math
import random
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

# ---------------------------------------------------------------------------
# CVE pool - Vulhub paths for available CVEs
# ---------------------------------------------------------------------------
CVE_POOL = [
    {
        "cve": "CVE-2024-36401",
        "path": "geoserver/CVE-2024-36401",
        "port": 8080,
        "service": "GeoServer",
        "proto": "http",
    },
    {
        "cve": "CVE-2025-3248",
        "path": "langflow/CVE-2025-3248",
        "port": 7860,
        "service": "Langflow",
        "proto": "http",
    },
    {
        "cve": "CVE-2026-34197",
        "path": "activemq/CVE-2026-34197",
        "port": 8161,
        "service": "Apache ActiveMQ (Jolokia)",
        "proto": "http",
    },
    # Add more CVEs here as they become available on the range
]

WINRM_USER = "localuser"
WINRM_PASS = "password"
LINUX_USERS = {
    "kali-x64-desktop-template": ("kali", "kali"),
}


# ---------------------------------------------------------------------------
# Template -> role classification
# ---------------------------------------------------------------------------
def classify_template(template: str, is_linux: bool) -> str:
    """Infer host role from template name."""
    lowered = template.lower()
    if "kali" in lowered:
        return "attacker"
    if "win2022" in lowered or "win2019" in lowered:
        return "server"
    if "win10" in lowered or "win11" in lowered:
        return "workstation"
    if is_linux or "debian" in lowered or "ubuntu" in lowered:
        return "linux-host"
    return "unknown"


# ---------------------------------------------------------------------------
# Segment role inference from network rules
# ---------------------------------------------------------------------------
def infer_segment_roles(rules: list) -> dict:
    """Return a dict mapping VLAN number -> segment role name.

    bailey names rules like "entry to plant", "build to ad", "dept-01 to ad"
    - parse the role directly from the rule name, which is more reliable
    than topology inference.
    Roles: ad, entry, plant, build, dept, attacker
    """
    known = {"ad", "entry", "plant", "build", "attacker"}
    roles = {}

    for rule in rules:
        name = rule.get("name", "")
        match = re.match(r"^([\w-]+)\s+to\s+([\w-]+)$", name)
        if not match:
            continue
        src_raw, dst_raw = match.group(1), match.group(2)
        # Normalise dept-01 -> dept, but keep known roles intact
        src_role = re.sub(r"-\d+$", "", src_raw)
        dst_role = re.sub(r"-\d+$", "", dst_raw)

        src_vlan = rule.get("vlan_src")
        dst_vlan = rule.get("vlan_dst")

        if src_role in known and src_vlan:
            roles[src_vlan] = src_role
        elif src_vlan and src_vlan not in roles and src_role not in (
            "external",
            "public",
        ):
            roles[src_vlan] = "dept"  # fallback for dept-01, dept-02, etc.

        if dst_role in known and dst_vlan and dst_vlan != "public":
            roles[dst_vlan] = dst_role
        elif dst_vlan and dst_vlan not in roles and dst_role not in (
            "external",
            "public",
        ):
            roles[dst_vlan] = "dept"

    return roles


# ---------------------------------------------------------------------------
# Load and parse the Ludus config
# ---------------------------------------------------------------------------
def load_config(path: str) -> dict:
    """Load the bailey-generated Ludus range config, stripping Jinja2."""
    content = Path(path).read_text()
    # Strip Jinja2 so PyYAML can parse - replace with placeholders
    content = re.sub(r"\{\{\s*range_id\s*\}}-", "RANGE-", content)
    content = re.sub(r"\{\{\s*range_second_octet\s*\}\}", "XX", content)
    return yaml.safe_load(content)


def get_ip(host: dict, range_prefix: str) -> str:
    """Build the host's IP address from its VLAN and last octet."""
    vlan = host["vlan"]
    octet = host["ip_last_octet"]
    return f"{range_prefix}.{vlan}.{octet}"


def parse_hosts(config: dict, range_prefix: str) -> list:
    """Return a list of host dicts with normalised fields.

    Fields: hostname, ip, vlan, template, role, os, domain
    """
    rules = config.get("network", {}).get("rules", [])
    seg_roles = infer_segment_roles(rules)
    hosts = []

    for host in config.get("ludus", []):
        template = host.get("template", "")
        is_linux = host.get("linux", False) or (
            "debian" in template.lower()
            or "ubuntu" in template.lower()
            or "kali" in template.lower()
        )
        role = classify_template(template, is_linux)
        vlan = host.get("vlan")
        seg_role = seg_roles.get(vlan, "unknown")
        domain = host.get("domain", {}).get("fqdn", "")

        hosts.append(
            {
                "hostname": host.get("hostname"),
                "vm_name": host.get("vm_name", ""),
                "ip": get_ip(host, range_prefix),
                "vlan": vlan,
                "seg_role": seg_role,
                "template": template,
                "role": role,
                "os": "linux" if is_linux else "windows",
                "domain": domain,
            }
        )

    return hosts


# ---------------------------------------------------------------------------
# Pivot and attacker detection
# ---------------------------------------------------------------------------
def find_pivot(hosts: list) -> dict | None:
    """The pivot is on the entry segment."""
    for host in hosts:
        if host["seg_role"] == "entry":
            return host
    return None


def find_attacker(hosts: list) -> dict | None:
    """The attacker is the kali host."""
    for host in hosts:
        if host["role"] == "attacker":
            return host
    return None


# ---------------------------------------------------------------------------
# Flag and CVE helpers
# ---------------------------------------------------------------------------
def make_flag(seed: int, hostname: str) -> str:
    """Derive a deterministic flag value from the seed and hostname."""
    raw = hashlib.sha256(f"{seed}:{hostname}".encode()).hexdigest()[:16]
    return f"FLAG{{{raw}}}"


def assign_scenario(
    hosts: list,
    seed: int,
    num_flags: int,
    vulns_per_host: int,
    percent: int = 100,
) -> dict:
    """Return assignments dict keyed by IP.

    CVE-eligible: linux-host on plant or dept segments (not attacker, not
    jenkins/build).
    Flag-eligible: workstations + linux-hosts (not attacker, not build).
    """
    rng = random.Random(seed)

    pivot = find_pivot(hosts)
    attacker = find_attacker(hosts)
    pivot_ips = {pivot["ip"]} if pivot else set()
    attacker_ips = {attacker["ip"]} if attacker else set()
    skip_ips = pivot_ips | attacker_ips

    # Classify hosts
    cve_eligible = [
        host
        for host in hosts
        if host["os"] == "linux"
        and host["seg_role"] in ("plant", "dept")
        and host["ip"] not in skip_ips
    ]

    flag_eligible = [
        host
        for host in hosts
        if host["seg_role"] in ("plant", "dept", "ad")
        and host["ip"] not in skip_ips
        and host["role"] != "server"  # skip DCs/servers
    ]

    # Apply --percent subsampling
    if percent < 100:
        n_cve = max(1, math.ceil(len(cve_eligible) * percent / 100))
        n_flag = max(1, math.ceil(len(flag_eligible) * percent / 100))
        rng.shuffle(cve_eligible)
        rng.shuffle(flag_eligible)
        cve_eligible = cve_eligible[:n_cve]
        flag_eligible = flag_eligible[:n_flag]

    # Build assignments
    all_ips = {host["ip"] for host in cve_eligible}
    all_ips |= {host["ip"] for host in flag_eligible}

    assignments = {}
    for host in hosts:
        if host["ip"] in all_ips:
            assignments[host["ip"]] = {
                "hostname": host["hostname"],
                "role": host["role"],
                "os": host["os"],
                "seg_role": host["seg_role"],
                "flag": None,
                "vulns": [],
            }

    # Assign CVEs
    for host in cve_eligible:
        host_rng = random.Random(f"{seed}:{host['hostname']}")
        pool = CVE_POOL.copy()
        host_rng.shuffle(pool)
        assignments[host["ip"]]["vulns"] = pool[:vulns_per_host]

    # Assign flags
    flag_ips = rng.sample(
        [host["ip"] for host in flag_eligible if host["ip"] in assignments],
        min(num_flags, len(flag_eligible)),
    )
    for ip in flag_ips:
        assignments[ip]["flag"] = make_flag(seed, assignments[ip]["hostname"])

    return assignments


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
def build_inventory(assignments: dict, hosts: list) -> str:
    """Render an Ansible inventory from the scenario assignments."""
    host_map = {host["ip"]: host for host in hosts}
    linux_lines, windows_lines = [], []

    for ip, assignment in assignments.items():
        host = host_map.get(ip, {})
        template = host.get("template", "")
        user, passwd = LINUX_USERS.get(template, ("debian", "debian"))
        comment = f"  # {assignment['hostname']} ({assignment['role']}, " \
                  f"{assignment['seg_role']})"

        if assignment["os"] == "linux":
            linux_lines.append(
                f"{ip} ansible_user={user} ansible_password={passwd} "
                f"ansible_become_password={passwd} "
                # UserKnownHostsFile=/dev/null is required alongside
                # StrictHostKeyChecking=no -- the range reuses the same IPs
                # across resets with a NEW host key each time, which SSH
                # treats as a changed-key warning (a hard refusal) rather
                # than an unknown-host prompt; StrictHostKeyChecking=no
                # alone only suppresses the latter.
                f"ansible_ssh_common_args='-o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null'"
                f"{comment}"
            )
        else:
            windows_lines.append(
                f"{ip} ansible_user={WINRM_USER} ansible_password={WINRM_PASS} "
                f"ansible_connection=winrm ansible_winrm_transport=ntlm "
                f"ansible_winrm_scheme=https "
                f"ansible_winrm_server_cert_validation=ignore "
                f"ansible_port=5986"
                f"{comment}"
            )

    lines = []
    if linux_lines:
        lines += ["[linux_hosts]"] + linux_lines + [""]
    if windows_lines:
        lines += ["[windows_hosts]"] + windows_lines + [""]
    lines += ["[scenario_hosts:children]"]
    if linux_lines:
        lines.append("linux_hosts")
    if windows_lines:
        lines.append("windows_hosts")
    return "\n".join(lines) + "\n"


def build_manifest(assignments, hosts, seed, range_prefix, config):
    """Build the manifest (answer key) dict for this scenario."""
    pivot = find_pivot(hosts)
    attacker = find_attacker(hosts)

    ext = config.get("ludus_extensions", {}).get("castle_bailey", {})
    return {
        "seed": seed,
        "range_prefix": range_prefix,
        "spec_hash": ext.get("spec_hash", ""),
        "generator": ext.get("generator_version", ""),
        "pivot": pivot,
        "attacker": attacker,
        "hosts": assignments,
    }


def build_playbook(manifest: dict) -> str:
    """Render the scenario Ansible playbook (linux + windows plays)."""
    manifest_json = json.dumps(manifest)

    linux_play = {
        "hosts": "linux_hosts",
        "become": True,
        "ignore_unreachable": True,
        "vars": {"scenario_manifest_raw": manifest_json},
        "tasks": [
            {
                "name": "Parse manifest",
                "set_fact": {
                    "scenario_manifest": "{{ scenario_manifest_raw | from_json }}"
                },
            },
            {
                "name": "Get host assignment",
                "set_fact": {
                    "host_assignment": (
                        "{{ scenario_manifest.hosts[inventory_hostname] | "
                        "default({'flag': none, 'vulns': []}) }}"
                    )
                },
            },
            # Vulhub CVE containers -- docker/docker-compose/git/apparmor AND
            # a clone of the Vulhub repo itself are already guaranteed
            # present on these hosts by their own provisioning role
            # (linux_workstation_setup for pla01/pla02, eng_hmi_ot for
            # eng-hmi), which runs before the range's final network-policy
            # lockdown. The plant VLAN (30) has NO internet egress once that
            # lockdown is applied -- confirmed live (apt and a direct
            # `curl https://github.com` both get connection-refused from
            # pla01) -- and that isolation is deliberate per the bailey
            # spec's policy block ("the real range declares no outbound
            # rules at all" for plant). So this playbook no longer tries to
            # install docker or clone/update Vulhub at episode-run time -- it
            # just assumes /opt/vulhub is already there from provisioning,
            # and only decides, per seed, WHICH already-present CVE
            # directory's docker-compose to start. That per-episode choice is
            # what stays random; nothing about pre-staging the repo once
            # removes that.
            # Scoped to CVE_POOL's paths specifically -- NOT a glob over
            # /opt/vulhub/*/*. The cloned repo has hundreds of CVE
            # directories; globbing all of them runs a separate
            # `docker-compose down` (daemon round-trip + compose-file parse)
            # against every single one every episode, almost all of which
            # never had anything running -- observed live 2026-11-01 taking
            # 15+ minutes for what should be a few seconds across 3 known
            # paths. Only directories this script ever starts anything in
            # need stopping.
            {
                "name": "Stop previous containers",
                "shell": (
                    "docker-compose -f /opt/vulhub/{{ item }}/docker-compose.yml "
                    "down 2>/dev/null || true"
                ),
                "loop": [cve["path"] for cve in CVE_POOL],
                "loop_control": {"label": "{{ item }}"},
                "when": "(host_assignment.vulns | default([])) | length > 0",
                "ignore_errors": True,
            },
            # "Stop previous containers" above only tears down containers it
            # can find BY COMPOSE PROJECT (docker-compose down under each
            # /opt/vulhub/*/* dir). A container that got left behind some
            # other way -- e.g. one Docker partially created during an
            # episode that failed mid-pull, before this host's clone/pull
            # was pre-staged -- isn't tied to a live compose project and
            # that sweep won't find it, but it can still be holding the
            # port (observed live 2026-11-01: pla02 failed to start
            # CVE-2024-36401 with "port is already allocated" despite the
            # sweep above reporting success). So free this episode's
            # specific port(s) directly by whatever container holds them,
            # compose-managed or not, right before starting.
            {
                "name": "Free this episode's CVE port(s), whatever's holding them",
                "shell": (
                    "docker ps -q --filter 'publish={{ item.port }}' "
                    "| xargs -r docker rm -f"
                ),
                "loop": "{{ host_assignment.vulns | default([]) }}",
                "loop_control": {"label": "{{ item.cve }} (port {{ item.port }})"},
                "when": "(host_assignment.vulns | default([])) | length > 0",
                "ignore_errors": True,
            },
            {
                "name": "Start CVE containers",
                "shell": "cd /opt/vulhub/{{ item.path }} && docker-compose up -d",
                "loop": "{{ host_assignment.vulns | default([]) }}",
                "loop_control": {"label": "{{ item.cve }}"},
            },
            # Flag
            {
                "name": "Ensure /opt/range exists",
                "file": {
                    "path": "/opt/range",
                    "state": "directory",
                    "mode": "0755",
                },
            },
            {
                "name": "Plant flag",
                "copy": {
                    "content": "{{ host_assignment.flag }}\n",
                    "dest": "/opt/range/flag.txt",
                    "mode": "0644",
                },
                "when": (
                    "host_assignment.flag is not none and "
                    "host_assignment.flag | length > 0"
                ),
            },
            {
                "name": "Write manifest",
                "copy": {
                    "content": "{{ host_assignment | to_nice_yaml }}",
                    "dest": "/opt/range/manifest.yml",
                    "mode": "0644",
                },
            },
            {
                "name": "Print assignment",
                "debug": {
                    "msg": (
                        "{{ inventory_hostname }} "
                        "({{ host_assignment.hostname }}): "
                        "vulns={{ host_assignment.vulns | default([]) | "
                        "map(attribute='cve') | list }}, "
                        "flag={{ host_assignment.flag | default('none') }}"
                    )
                },
            },
        ],
    }

    windows_play = {
        "hosts": "windows_hosts",
        "ignore_unreachable": True,
        "vars": {"scenario_manifest_raw": manifest_json},
        "tasks": [
            {
                "name": "Parse manifest",
                "set_fact": {
                    "scenario_manifest": "{{ scenario_manifest_raw | from_json }}"
                },
            },
            {
                "name": "Get host assignment",
                "set_fact": {
                    "host_assignment": (
                        "{{ scenario_manifest.hosts[inventory_hostname] | "
                        "default({'flag': none, 'vulns': []}) }}"
                    )
                },
            },
            # Flag
            #
            # WinRM read-timeouts here are a known transient failure (seen
            # live 2026-11-01 on leg01: "Read timed out (read timeout=30)")
            # -- `ignore_unreachable: True` on this play keeps it from
            # killing the whole run, but that also means the timeout was
            # silently swallowing the flag-plant itself: the manifest says
            # the flag was placed, but it never actually reached disk.
            # Retrying a few times before giving up catches the transient
            # case without masking a real, persistent WinRM problem.
            {
                "name": "Plant flag (Windows)",
                "win_copy": {
                    "content": "{{ host_assignment.flag }}\n",
                    "dest": "C:\\Users\\Public\\flag.txt",
                },
                "when": (
                    "host_assignment.flag is not none and "
                    "host_assignment.flag | length > 0"
                ),
                "retries": 3,
                "delay": 15,
                "register": "_flag_plant_result",
                "until": "_flag_plant_result is succeeded",
            },
            # Phishing is out of scope for scenario_gen.py entirely -- it's
            # set up by a separate Ludus role at range deploy time, not
            # per-episode here.
            {
                "name": "Print assignment (Windows)",
                "debug": {
                    "msg": (
                        "{{ inventory_hostname }} "
                        "({{ host_assignment.hostname }}): "
                        "flag={{ host_assignment.flag | default('none') }}"
                    )
                },
            },
        ],
    }

    return yaml.dump(
        [linux_play, windows_play],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def print_summary(
    hosts: list, manifest: dict, seed: int, range_prefix: str, percent: int
) -> None:
    """Print a human-readable summary of the generated scenario."""
    pivot = find_pivot(hosts)
    attacker = find_attacker(hosts)

    print(f"\n[scenario_gen] seed={seed}  prefix={range_prefix}  "
          f"percent={percent}%")
    if pivot:
        print(f"[scenario_gen] pivot     -> {pivot['hostname']} @ {pivot['ip']}")
    if attacker:
        print(f"[scenario_gen] attacker  -> {attacker['hostname']} "
              f"@ {attacker['ip']}")

    header = (
        f"\n{'IP':<18} {'hostname':<16} {'role':<14} {'seg':<8} "
        f"{'vulns':<36} {'flag':<22}"
    )
    print(header)
    print("-" * 114)
    for ip, assignment in sorted(manifest["hosts"].items()):
        cves = ", ".join(v["cve"] for v in assignment.get("vulns", [])) or "-"
        flag = assignment.get("flag") or "-"
        print(
            f"{ip:<18} {assignment['hostname']:<16} {assignment['role']:<14} "
            f"{assignment['seg_role']:<8} {cves:<36} {flag:<22}"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate scenario.yml + manifest.json from a bailey-generated "
            "Ludus range config"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 scenario_gen.py artifacts/goad-daniel-bailey.yml --seed 1234 \\
        --range-prefix 10.26
    python3 scenario_gen.py artifacts/goad-daniel-bailey.yml --seed 1234 \\
        --range-prefix 10.26 --percent 50 --flags 2 --no-vulns
        """,
    )
    parser.add_argument(
        "config", help="Path to bailey-generated Ludus range config YAML"
    )
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--range-prefix", default="10.26", help="Range IP prefix (default: 10.26)"
    )
    parser.add_argument(
        "--flags", type=int, default=2, help="Number of flags to plant (default: 2)"
    )
    parser.add_argument(
        "--vulns-per-host",
        type=int,
        default=1,
        help="CVEs per eligible host (default: 1)",
    )
    parser.add_argument(
        "--percent",
        type=int,
        default=100,
        help="Percentage of eligible hosts (default: 100)",
    )
    parser.add_argument(
        "--no-vulns", action="store_true", help="Skip CVE assignment"
    )
    parser.add_argument("--out-playbook", default="scenario.yml")
    parser.add_argument("--out-manifest", default="manifest.json")
    parser.add_argument("--out-inventory", default="scenario-inventory.ini")
    args = parser.parse_args()

    if not 1 <= args.percent <= 100:
        parser.error("--percent must be between 1 and 100")

    return args


def main() -> None:
    """Generate scenario.yml, manifest.json, and inventory."""
    args = parse_args()

    config = load_config(args.config)
    hosts = parse_hosts(config, args.range_prefix)
    assignments = assign_scenario(
        hosts,
        args.seed,
        num_flags=args.flags,
        vulns_per_host=0 if args.no_vulns else args.vulns_per_host,
        percent=args.percent,
    )
    manifest = build_manifest(
        assignments, hosts, args.seed, args.range_prefix, config
    )

    # Dropper delivery (writing dropper.ps1, scheduling it) is handled by a
    # separate mechanism now -- this script only records the foothold
    # assignment in manifest.json for that mechanism to consume.

    Path(args.out_manifest).write_text(json.dumps(manifest, indent=2))
    print(f"[scenario_gen] manifest  -> {args.out_manifest}")

    Path(args.out_inventory).write_text(build_inventory(assignments, hosts))
    print(f"[scenario_gen] inventory -> {args.out_inventory}")

    Path(args.out_playbook).write_text(build_playbook(manifest))
    print(f"[scenario_gen] playbook  -> {args.out_playbook}")

    print_summary(hosts, manifest, args.seed, args.range_prefix, args.percent)


if __name__ == "__main__":
    main()