#!/usr/bin/env python3
"""Read-only local security review for Linux systems.

This tool reports indicators for human review. It does not establish who used a
machine or prove that a system is compromised.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
BASELINE_VERSION = 1
REVIEW_DAYS = 7


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_time(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds")


def run_command(args: list[str], timeout: int = 8) -> dict[str, Any]:
    """Run a fixed local read-only command without invoking a shell."""
    if not shutil.which(args[0]):
        return {"available": False, "returncode": None, "stdout": "", "stderr": f"{args[0]} is not installed"}
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "available": True,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "returncode": None, "stdout": "", "stderr": f"Timed out after {timeout}s"}
    except OSError as exc:
        return {"available": True, "returncode": None, "stdout": "", "stderr": str(exc)}


def add_finding(report: dict[str, Any], severity: str, category: str, title: str,
                evidence: str, recommendation: str) -> None:
    report["findings"].append({
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def collect_accounts() -> tuple[list[dict[str, Any]], list[str]]:
    accounts: list[dict[str, Any]] = []
    uid_zero: list[str] = []
    for entry in pwd.getpwall():
        if entry.pw_uid == 0:
            uid_zero.append(entry.pw_name)
        if entry.pw_uid >= 1000 or entry.pw_uid == 0:
            accounts.append({
                "name": entry.pw_name,
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "home": entry.pw_dir,
                "shell": entry.pw_shell,
            })
    return accounts, sorted(uid_zero)


def collect_admins() -> list[str]:
    admins = {"root"}
    try:
        for group in __import__("grp").getgrall():
            if group.gr_name in {"sudo", "wheel"}:
                admins.update(group.gr_mem)
                for entry in pwd.getpwall():
                    if entry.pw_gid == group.gr_gid:
                        admins.add(entry.pw_name)
    except OSError:
        pass
    return sorted(admins)


def _key_type_and_blob(line: str) -> tuple[str, str] | None:
    parts = line.strip().split()
    prefixes = ("ssh-", "ecdsa-", "sk-")
    for index, part in enumerate(parts[:-1]):
        if part.startswith(prefixes):
            return part, parts[index + 1]
    return None


def collect_authorized_keys() -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    try:
        users = pwd.getpwall()
    except Exception:
        return found
    seen: set[str] = set()
    for user in users:
        home = Path(user.pw_dir) if user.pw_dir else None
        if not home or str(home) in seen:
            continue
        seen.add(str(home))
        key_file = home / ".ssh" / "authorized_keys"
        try:
            lines = key_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            parsed = _key_type_and_blob(line)
            if not parsed:
                continue
            key_type, blob = parsed
            try:
                digest = hashlib.sha256(__import__("base64").b64decode(blob.encode(), validate=True)).digest()
            except Exception:
                continue
            import base64
            fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
            found.append({"user": user.pw_name, "path": str(key_file), "type": key_type, "fingerprint": fingerprint})
    return found


def _systemd_enabled() -> list[str]:
    result = run_command(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"])
    units: list[str] = []
    if result["returncode"] == 0:
        for line in result["stdout"].splitlines():
            parts = line.split()
            if parts:
                units.append(parts[0])
    return sorted(set(units))


def _listening_ports() -> list[str]:
    result = run_command(["ss", "-H", "-lntu"])
    ports: set[str] = set()
    if result["returncode"] == 0:
        for line in result["stdout"].splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            proto, local = parts[0].lower(), parts[3]
            port = local.rsplit(":", 1)[-1]
            if port.isdigit():
                ports.add(f"{proto}/{local}")
    return sorted(ports)


def _cron_files() -> list[str]:
    candidates = [Path("/etc/crontab")]
    for directory in (Path("/etc/cron.d"), Path("/etc/cron.hourly"), Path("/etc/cron.daily"),
                      Path("/etc/cron.weekly"), Path("/etc/cron.monthly"),
                      Path("/var/spool/cron/crontabs"), Path("/var/spool/cron")):
        try:
            candidates.extend(p for p in directory.iterdir() if p.is_file())
        except OSError:
            pass
    return sorted({str(p) for p in candidates if p.is_file()})


def collect_state() -> dict[str, Any]:
    accounts, uid_zero = collect_accounts()
    return {
        "admins": collect_admins(),
        "uid_zero_accounts": uid_zero,
        "ssh_keys": collect_authorized_keys(),
        "enabled_services": _systemd_enabled(),
        "listening_ports": _listening_ports(),
        "scheduled_task_files": _cron_files(),
        "accounts": accounts,
    }


def _recent_login_evidence() -> dict[str, Any]:
    successful = run_command(["last", "-F", "-i", "-n", "30"], timeout=10)
    failed = run_command(["lastb", "-F", "-i", "-n", "30"], timeout=10)
    return {
        "recent_logins": successful["stdout"].splitlines()[:30] if successful["returncode"] == 0 else [],
        "recent_failed_logins": failed["stdout"].splitlines()[:30] if failed["returncode"] == 0 else [],
        "last_status": successful["stderr"] if successful["returncode"] != 0 else "available",
        "lastb_status": failed["stderr"] if failed["returncode"] != 0 else "available",
    }


def _active_sessions() -> dict[str, Any]:
    who = run_command(["who", "--ips"])
    return {"sessions": who["stdout"].splitlines() if who["returncode"] == 0 else [],
            "status": who["stderr"] if who["returncode"] != 0 else "available"}


def _recent_sensitive_changes(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [
        Path("/etc/passwd"), Path("/etc/group"), Path("/etc/shadow"), Path("/etc/sudoers"),
        Path("/etc/ssh/sshd_config"), Path("/etc/ssh/sshd_config.d"), Path("/etc/hosts"),
        Path("/etc/crontab"), Path("/etc/cron.d"), Path("/etc/systemd/system"),
    ]
    cutoff = utc_now() - dt.timedelta(days=REVIEW_DAYS)
    changed: list[dict[str, Any]] = []
    for path in candidates:
        paths = [path]
        if path.is_dir():
            try:
                paths = [p for p in path.iterdir() if p.is_file() or p.is_symlink()]
            except OSError:
                paths = []
        for item in paths:
            try:
                stat = item.lstat()
                modified = dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc)
                if modified >= cutoff:
                    changed.append({"path": str(item), "modified_utc": iso_time(modified)})
            except OSError:
                continue
    changed.sort(key=lambda x: x["modified_utc"], reverse=True)
    if changed:
        add_finding(report, "review", "configuration", "Sensitive configuration changed recently",
                    "; ".join(f"{x['path']} ({x['modified_utc']})" for x in changed[:12]),
                    "Confirm each change matches an update or action you recognize.")
    return changed


def _persistence_integrity(report: dict[str, Any]) -> list[dict[str, Any]]:
    directories = [Path("/etc/systemd/system"), Path("/usr/local/lib/systemd/system"), Path("/etc/cron.d")]
    issues: list[dict[str, Any]] = []
    for directory in directories:
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for path in entries:
            if not (path.is_file() or path.is_symlink()):
                continue
            try:
                stat = path.lstat()
            except OSError:
                continue
            mode = stat.st_mode
            reasons = []
            if mode & 0o002:
                reasons.append("world-writable")
            if stat.st_uid != 0:
                reasons.append(f"owned by uid {stat.st_uid}, not root")
            if reasons:
                issues.append({"path": str(path), "issue": ", ".join(reasons)})
    for issue in issues:
        add_finding(report, "high", "persistence", "Unusual permissions or ownership on startup file",
                    f"{issue['path']}: {issue['issue']}",
                    "Review the file and its ownership before changing it; confirm whether it is expected.")
    return issues


def compare_baseline(report: dict[str, Any], state: dict[str, Any], baseline: dict[str, Any]) -> None:
    keys = (
        ("admins", "administrator accounts"),
        ("uid_zero_accounts", "UID 0 accounts"),
        ("enabled_services", "enabled system services"),
        ("listening_ports", "listening sockets"),
        ("scheduled_task_files", "scheduled-task files"),
    )
    for key, label in keys:
        old = set(baseline.get("state", {}).get(key, []))
        current = set(state.get(key, []))
        added = sorted(current - old)
        removed = sorted(old - current)
        for item in added:
            add_finding(report, "review", "baseline", f"New {label} since baseline", str(item),
                        "Check whether this change was expected and authorized.")
        for item in removed:
            add_finding(report, "info", "baseline", f"{label.capitalize()} no longer present", str(item),
                        "Confirm the removal was intentional if the change was unexpected.")
    old_keys = {item.get("fingerprint") for item in baseline.get("state", {}).get("ssh_keys", [])}
    for item in state.get("ssh_keys", []):
        if item.get("fingerprint") not in old_keys:
            add_finding(report, "review", "baseline", "SSH authorized key not in baseline",
                        f"{item['user']} · {item['path']} · {item['fingerprint']} ({item['type']})",
                        "Verify that this public key belongs to someone you authorized.")


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    state = collect_state()
    os_release = read_os_release()
    report: dict[str, Any] = {
        "tool": "amialone",
        "version": VERSION,
        "generated_utc": iso_time(),
        "host": socket.gethostname(),
        "run_as": {"name": os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name,
                    "effective_uid": os.geteuid()},
        "system": {"name": os_release.get("PRETTY_NAME", "Linux"), "kernel": os.uname().release},
        "limitations": [
            "Findings are indicators for review, not proof of compromise or attribution.",
            "A baseline is needed to identify changes relative to a prior known-good state.",
            "Read access and log retention affect what this scan can see.",
        ],
        "findings": [],
        "checks": {},
        "state_summary": {},
    }
    report["checks"]["active_sessions"] = _active_sessions()
    report["checks"]["login_history"] = _recent_login_evidence()
    report["checks"]["recent_sensitive_changes"] = _recent_sensitive_changes(report)
    report["checks"]["startup_file_permissions"] = _persistence_integrity(report)
    report["checks"]["system_state"] = state
    report["state_summary"] = {
        "admins": state["admins"],
        "uid_zero_accounts": state["uid_zero_accounts"],
        "authorized_ssh_keys": len(state["ssh_keys"]),
        "enabled_services": len(state["enabled_services"]),
        "listening_sockets": state["listening_ports"],
        "scheduled_task_files": state["scheduled_task_files"],
    }

    for account in state["uid_zero_accounts"]:
        if account != "root":
            add_finding(report, "high", "accounts", "Additional account has UID 0", account,
                        "Confirm this account is expected; UID 0 accounts have root-equivalent privileges.")
    if state["ssh_keys"]:
        add_finding(report, "info", "ssh", "SSH authorized keys are present",
                    "; ".join(f"{item['user']}: {item['fingerprint']}" for item in state["ssh_keys"][:20]),
                    "Compare the listed fingerprints with keys you intentionally installed.")
    if state["listening_ports"]:
        add_finding(report, "info", "network", "Local services are listening for connections",
                    ", ".join(state["listening_ports"]),
                    "Check whether each service and bind address is needed on this machine.")

    baseline_path = args.baseline
    if baseline_path:
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            if baseline.get("baseline_version") != BASELINE_VERSION:
                raise ValueError("unsupported or missing baseline_version")
            compare_baseline(report, state, baseline)
            report["baseline"] = {"path": str(baseline_path), "created_utc": baseline.get("created_utc"), "compared": True}
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Could not read baseline {baseline_path}: {exc}") from exc
    else:
        report["baseline"] = {"compared": False, "note": "No baseline supplied; new or unknown items cannot be distinguished."}

    return report, state


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def print_report(report: dict[str, Any]) -> None:
    print(f"Am I Alone? — local security review {report['version']}")
    print(f"Host: {report['host']}  |  System: {report['system']['name']}  |  Generated: {report['generated_utc']}")
    run_as = report["run_as"]
    print(f"Run as: {run_as['name']} (effective UID {run_as['effective_uid']})")
    print("\nSummary")
    for key, value in report["state_summary"].items():
        print(f"  {key.replace('_', ' ').capitalize()}: {value}")
    findings = report["findings"]
    print(f"\nFindings: {len(findings)}")
    if not findings:
        print("  No review indicators were found by these checks.")
    for item in findings:
        print(f"  [{item['severity'].upper()}] {item['title']} ({item['category']})")
        print(f"    Evidence: {item['evidence']}")
        print(f"    Next step: {item['recommendation']}")
    baseline = report["baseline"]
    if not baseline["compared"]:
        print(f"\nBaseline: {baseline['note']}")
    print("\nThis report is not proof that the system is clean or compromised.")
    print("Run with sudo for fuller access to authentication logs and protected files.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="amialone.py",
        description="Read-only local security checks for Linux; reports indicators for human review.",
        epilog="No network requests are made and no system changes are performed.",
    )
    parser.add_argument("--version", action="version", version=f"amialone {VERSION}")
    parser.add_argument("--baseline", type=Path, help="compare the current scan with a saved known-good baseline")
    parser.add_argument("--save-baseline", type=Path, help="save current account, SSH key, service, socket, and scheduled-task state")
    parser.add_argument("--output", type=Path, help="write the full scan report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.baseline and args.save_baseline:
        parser.error("--baseline and --save-baseline cannot be used together")
    try:
        report, state = build_report(args)
        if args.save_baseline:
            baseline = {
                "baseline_version": BASELINE_VERSION,
                "tool_version": VERSION,
                "created_utc": iso_time(),
                "host": socket.gethostname(),
                "system": report["system"],
                "state": state,
                "note": "Create this baseline only after reviewing the system and deciding it is in a trusted state.",
            }
            write_json(args.save_baseline, baseline)
            print(f"Saved baseline to {args.save_baseline}")
        print_report(report)
        if args.output:
            write_json(args.output, report)
            print(f"\nSaved JSON report to {args.output}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
