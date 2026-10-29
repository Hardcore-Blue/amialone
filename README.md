# Am I Alone?

`amialone.py` is a dependency-free, read-only local security review script for Linux, with Kali Linux as the primary target. It gathers host-local evidence and presents indicators for a person to review. It does not prove compromise, identify an intruder, connect to a remote service, or make changes to the machine.

## Requirements

- Python 3.10+
- Linux utilities where available: `who`, `last`, `lastb`, `systemctl`, and `ss`
- Run with `sudo` for the broadest access to logs, account data, and protected configuration. Without it, the report may be incomplete.

## Run

```sh
python3 amialone.py
sudo python3 amialone.py --output amialone-report.json
```

Create a baseline only after reviewing the machine and deciding it is in a trusted state:

```sh
sudo python3 amialone.py --save-baseline known-good.json
```

Compare a later scan with that baseline:

```sh
sudo python3 amialone.py --baseline known-good.json --output latest-report.json
```

The baseline records accounts with administrative or UID 0 access, SSH authorized-key fingerprints, enabled system services, listening sockets, and scheduled-task file paths. New entries are reported for review. A baseline is just a comparison snapshot; if it is created on an already-compromised machine, it can normalize malicious state.

## Checks

- Current login sessions and recent successful/failed login history when system tools and permissions allow it.
- Local accounts, UID 0 accounts, and members of `sudo`/`wheel` groups.
- SSH `authorized_keys` presence and public-key fingerprints; key contents are not included in the report.
- Enabled systemd services, listening TCP/UDP sockets, and scheduled-task files.
- Recent modification times for selected sensitive configuration files.
- Ownership and world-writable permissions on selected systemd and cron startup files.
- Optional baseline comparison for new or removed state.

## Reading findings

`high`, `review`, and `info` describe the priority for human attention, not certainty that an incident occurred. For example, a listening SSH service or an authorized key may be expected. Compare evidence with your own known changes and trusted records. A missing finding does not demonstrate that the system is clean: logs may have rotated, been altered, or be unreadable, and this script checks only a limited set of local evidence.

The script makes no network requests, invokes only fixed local commands without a shell, and does not delete files, kill processes, change configuration, or attempt remediation. Preserve relevant evidence and seek incident-response help if you suspect an active compromise.
