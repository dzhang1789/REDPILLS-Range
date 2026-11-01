#!/usr/bin/env python3
"""validate_episode.py.

Walks actions/step_*/metadata.json, loads each action's paired output_file,
and cross-checks the agent's self-reported `success` flag against a set of
text-pattern verifiers.

Usage:
    python3 validate_episode.py ~/episodes/<episode-id>/ --out-json report.json --out-csv report.csv
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


def _has_vulnerabilities(node) -> bool:
    """Recursively search a parsed JSON structure for a non-empty
    "Vulnerabilities" entry (certipy-ad prefixes it "[!] Vulnerabilities").
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if "vulnerabilities" in key.lower() and value:
                return True
            if _has_vulnerabilities(value):
                return True
        return False
    if isinstance(node, list):
        return any(_has_vulnerabilities(item) for item in node)
    return False


def verify_find_vulnerable_templates(out: str) -> bool:
    """certipy-ad find -json emits structured JSON, not prose -- the word
    "vulnerable" never appears, only the JSON key "[!] Vulnerabilities".
    Parse the JSON and look for that key directly; fall back to a plain
    text heuristic for non-JSON certipy output.
    """
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        data = None

    if data is not None:
        return _has_vulnerabilities(data)

    return bool(re.search(r"vulnerab\w*", out, re.IGNORECASE)) and bool(
        re.search(r"\bESC\d+\b", out, re.IGNORECASE)
    )


# ---------------------------------------------------------------------------
# Text-pattern verifiers, keyed by substring match against the action name
# or the command string. First match wins. Each verifier takes the raw
# output text and returns True/False/None (None = inconclusive, keep
# self-reported value but flag for review).
# ---------------------------------------------------------------------------
VERIFIERS = [
    (
        "clearev",
        lambda out: bool(re.search(r"Wiping \d+ records", out)),
    ),
    (
        "esc1_exploit",
        lambda out: "certificate was issued" in out.lower()
        or "requested certificate was issued" in out.lower(),
    ),
    (
        # Must precede "add_user" below -- "add_user" is a substring of
        # this action name, so checking the longer/more specific key
        # first avoids misrouting group-membership adds to the
        # domain-join verifier.
        "add_user_to_group",
        lambda out: "successfully added user to group" in out.lower(),
    ),
    (
        "add_group_user",
        lambda out: "successfully added user to group" in out.lower(),
    ),
    (
        "add_user",
        lambda out: bool(re.search(r"was added to the \w+ domain", out, re.IGNORECASE))
        or "was added to the group" in out.lower(),
    ),
    (
        "enum_ad_computers",
        lambda out: None if "post module execution completed" in out.lower() else False,
    ),
    (
        "enum_domain",
        lambda out: None if "post module execution completed" in out.lower() else False,
    ),
    (
        "getsystem",
        lambda out: "got system" in out.lower()
        or "already running as system" in out.lower(),
    ),
    (
        "find_vulnerable_templates",
        verify_find_vulnerable_templates,
    ),
]

STALL_THRESHOLD = 3  # identical (action, command) repeated >= this many times
MAJOR_STALL_THRESHOLD = 10  # repeated >= this many times -> "major" severity


def load_steps(episode_dir: Path) -> list:
    """Load all actions across every step_* dir, in chronological order."""
    actions_dir = episode_dir / "actions"
    if not actions_dir.is_dir():
        sys.exit(f"No actions/ directory found under {episode_dir}")

    records = []
    for step_dir in sorted(actions_dir.glob("step_*")):
        meta_path = step_dir / "metadata.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text())
        step_num = meta.get("step")
        hostname = meta.get("hostname", "")
        for action in meta.get("actions", []):
            output_file = step_dir / action.get("output_file", "")
            output_text = (
                output_file.read_text(errors="replace") if output_file.exists() else ""
            )
            records.append(
                {
                    "step": step_num,
                    "hostname": hostname,
                    "timestamp": action.get("timestamp"),
                    "action": action.get("action", ""),
                    "shell": action.get("shell", ""),
                    "command": action.get("command", ""),
                    "duration": action.get("duration"),
                    "self_reported_success": action.get("success"),
                    "mitre": action.get("mitre", ""),
                    "output_file": str(output_file),
                    "output_text": output_text,
                }
            )
    records.sort(key=lambda r: (r["timestamp"] or 0))
    return records


def verify_action(record: dict) -> tuple:
    """Return (verified_success, verifier_used)."""
    haystack = f"{record['action']} {record['command']}".lower()
    for key, fn in VERIFIERS:
        if key in haystack:
            try:
                result = fn(record["output_text"])
            except (re.error, TypeError, AttributeError):
                result = None
            return result, key
    return None, None


def detect_stalls(records: list) -> list:
    """Flag runs of >= STALL_THRESHOLD consecutive identical (action, cmd)."""
    stalls = []
    i = 0
    n = len(records)
    while i < n:
        j = i + 1
        key = (records[i]["action"], records[i]["command"])
        while j < n and (records[j]["action"], records[j]["command"]) == key:
            j += 1
        run_len = j - i
        if run_len >= STALL_THRESHOLD:
            span = (records[j - 1]["timestamp"] or 0) - (records[i]["timestamp"] or 0)
            severity = "major" if run_len >= MAJOR_STALL_THRESHOLD else "minor"
            stalls.append(
                {
                    "action": records[i]["action"],
                    "command": records[i]["command"],
                    "repeat_count": run_len,
                    "span_seconds": round(span, 1),
                    "severity": severity,
                    "first_index": i,
                    "last_index": j - 1,
                }
            )
        i = j
    return stalls


def build_report(records: list) -> dict:
    mismatches = []
    unverified = []
    for idx, record in enumerate(records):
        verified, verifier = verify_action(record)
        record["verified_success"] = verified
        record["verifier_used"] = verifier
        if verifier is None:
            unverified.append(idx)
        elif verified is not None and verified != record["self_reported_success"]:
            mismatches.append(idx)

    stalls = detect_stalls(records)

    summary = {
        "total_actions": len(records),
        "self_reported_success_count": sum(
            1 for r in records if r["self_reported_success"]
        ),
        "verified_count": sum(1 for r in records if r["verifier_used"]),
        "mismatch_count": len(mismatches),
        "unverified_count": len(unverified),
        "stall_count": len(stalls),
        "major_stall_count": sum(1 for s in stalls if s["severity"] == "major"),
        "stalled_actions_total": sum(s["repeat_count"] for s in stalls),
    }

    return {
        "summary": summary,
        "mismatches": [records[i] for i in mismatches],
        "stalls": stalls,
        "actions": records,
    }


def write_csv(report: dict, path: Path) -> None:
    fields = [
        "step",
        "hostname",
        "timestamp",
        "action",
        "mitre",
        "command",
        "self_reported_success",
        "verified_success",
        "verifier_used",
        "duration",
    ]
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for record in report["actions"]:
            writer.writerow(record)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("episode_dir", help="Path to a single episode directory")
    parser.add_argument("--out-json", default="validation_report.json")
    parser.add_argument("--out-csv", default="validation_report.csv")
    args = parser.parse_args()

    episode_dir = Path(args.episode_dir).expanduser()
    records = load_steps(episode_dir)
    report = build_report(records)

    # Strip raw output text before dumping JSON (keep CSV/terminal lean;
    # full text stays accessible via output_file path if needed)
    json_report = json.loads(json.dumps(report))
    for action in json_report["actions"]:
        action.pop("output_text", None)
    for mismatch in json_report["mismatches"]:
        mismatch.pop("output_text", None)

    Path(args.out_json).write_text(json.dumps(json_report, indent=2))
    write_csv(report, Path(args.out_csv))

    summary = report["summary"]
    print(f"\n[validate_episode] {episode_dir}")
    print(f"  total actions        : {summary['total_actions']}")
    print(f"  self-reported success: {summary['self_reported_success_count']}")
    print(f"  text-verified actions: {summary['verified_count']}")
    print(f"  mismatches found     : {summary['mismatch_count']}")
    print(f"  unverified (no rule) : {summary['unverified_count']}")
    print(
        f"  stalls detected      : {summary['stall_count']} "
        f"({summary['major_stall_count']} major, "
        f"{summary['stalled_actions_total']} actions wasted)"
    )

    if report["mismatches"]:
        print("\n  Mismatches (self-reported vs text-verified):")
        for m in report["mismatches"]:
            print(
                f"    step {m['step']:>3}  {m['action']:<24} "
                f"self={m['self_reported_success']!s:<5} "
                f"verified={m['verified_success']!s:<5} "
                f"({m['verifier_used']})"
            )

    if report["stalls"]:
        print("\n  Stalls:")
        for s in report["stalls"]:
            print(
                f"    [{s['severity']:<5}] {s['action']:<24} "
                f"repeated {s['repeat_count']}x over {s['span_seconds']}s"
            )

    print(f"\n  Full report: {args.out_json}, {args.out_csv}\n")


if __name__ == "__main__":
    main()