#!/usr/bin/env python3
"""
Synthetic auth-log dataset generator for SIEM-Lite ML training.

Generates labeled log lines that mimic real /var/log/auth.log entries.
Each line is labeled as one of:
    normal, ssh_brute_force, privilege_escalation, after_hours_login,
    new_user_created, root_login, su_failure

Usage:
    python data/generate_dataset.py --num-lines 50000 --output data/auth_logs_labeled.csv
    python data/generate_dataset.py --num-lines 50000 --output data/auth_logs_labeled.csv --attack-ratio 0.3
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve", "frank", "grace"]
ATTACK_USERS = ["hacker", "intruder", "scanner", "botnet"]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
ATTACK_IPS = [
    "45.33.32.156", "185.220.101.34", "23.129.64.210",
    "103.253.41.98", "91.240.118.172", "198.51.100.77",
]
SERVICES = ["sshd", "systemd-logind", "cron", "su", "sudo"]
HOSTNAMES = ["webserver01", "dbserver02", "appserver03"]


def _random_ts(base: datetime, offset_hours: int = 0) -> str:
    """Return a syslog-style timestamp."""
    ts = base + timedelta(
        hours=offset_hours,
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return ts.strftime("%b %d %H:%M:%S")


def _host() -> str:
    return random.choice(HOSTNAMES)


# ---------------------------------------------------------------------------
# Log-line generators — each returns (log_line, label)
# ---------------------------------------------------------------------------
def gen_normal_accepted(base: datetime) -> tuple[str, str]:
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    hour = random.randint(6, 22)  # business hours
    ts = _random_ts(base, hour)
    port = random.randint(40000, 65535)
    line = (
        f"{ts} {_host()} sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )
    return line, "normal"


def gen_normal_session(base: datetime) -> tuple[str, str]:
    user = random.choice(NORMAL_USERS)
    hour = random.randint(6, 22)
    ts = _random_ts(base, hour)
    action = random.choice([
        f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
        f"pam_unix(sshd:session): session closed for user {user}",
        f"systemd-logind[{random.randint(100,999)}]: New session {random.randint(1,500)} of user {user}.",
        f"CRON[{random.randint(1000,9999)}]: pam_unix(cron:session): session opened for user {user}(uid=1000) by (uid=0)",
    ])
    line = f"{ts} {_host()} {action}"
    return line, "normal"


def gen_ssh_brute_force(base: datetime) -> tuple[str, str]:
    ip = random.choice(ATTACK_IPS)
    user = random.choice(ATTACK_USERS + ["root", "admin", "test"])
    hour = random.randint(0, 23)
    ts = _random_ts(base, hour)
    line = (
        f"{ts} {_host()} sshd[{random.randint(1000,9999)}]: "
        f"Failed password for {'invalid user ' if random.random() > 0.5 else ''}"
        f"{user} from {ip} port {random.randint(40000,65535)} ssh2"
    )
    return line, "ssh_brute_force"


def gen_privilege_escalation(base: datetime) -> tuple[str, str]:
    user = random.choice(ATTACK_USERS)
    hour = random.randint(0, 23)
    ts = _random_ts(base, hour)
    cmd = random.choice([
        "/bin/bash", "/usr/bin/passwd", "/usr/sbin/useradd hacker2",
        "/usr/bin/cat /etc/shadow", "/usr/bin/chmod 777 /etc/passwd",
    ])
    line = (
        f"{ts} {_host()} sudo: {user} : TTY=pts/0 ; "
        f"PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    )
    return line, "privilege_escalation"


def gen_after_hours_login(base: datetime) -> tuple[str, str]:
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS + ATTACK_IPS)
    hour = random.choice([23, 0, 1, 2, 3, 4])  # 23:00–04:59
    ts = _random_ts(base, hour)
    port = random.randint(40000, 65535)
    line = (
        f"{ts} {_host()} sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )
    return line, "after_hours_login"


def gen_new_user_created(base: datetime) -> tuple[str, str]:
    new_user = random.choice(["backdoor", "tempuser", "svc_acct", "testadmin"])
    hour = random.randint(0, 23)
    ts = _random_ts(base, hour)
    cmd = random.choice(["useradd", "adduser"])
    line = (
        f"{ts} {_host()} {cmd}[{random.randint(1000,9999)}]: "
        f"new user: name={new_user}, UID={random.randint(1001,65534)}, "
        f"GID={random.randint(1001,65534)}, home=/home/{new_user}, shell=/bin/bash"
    )
    return line, "new_user_created"


def gen_root_login(base: datetime) -> tuple[str, str]:
    ip = random.choice(ATTACK_IPS)
    hour = random.randint(0, 23)
    ts = _random_ts(base, hour)
    port = random.randint(40000, 65535)
    line = (
        f"{ts} {_host()} sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for root from {ip} port {port} ssh2"
    )
    return line, "root_login"


def gen_su_failure(base: datetime) -> tuple[str, str]:
    user = random.choice(ATTACK_USERS + NORMAL_USERS)
    hour = random.randint(0, 23)
    ts = _random_ts(base, hour)
    line = (
        f"{ts} {_host()} su[{random.randint(1000,9999)}]: "
        f"FAILED su for root by {user}"
    )
    return line, "su_failure"


# ---------------------------------------------------------------------------
# Master generator
# ---------------------------------------------------------------------------
ATTACK_GENERATORS = [
    gen_ssh_brute_force,
    gen_privilege_escalation,
    gen_after_hours_login,
    gen_new_user_created,
    gen_root_login,
    gen_su_failure,
]

NORMAL_GENERATORS = [
    gen_normal_accepted,
    gen_normal_session,
]


def generate_dataset(
    num_lines: int = 50000,
    attack_ratio: float = 0.25,
    seed: int = 42,
) -> list[tuple[str, str]]:
    """Generate a labeled log dataset.

    Returns list of (log_line, label) tuples.
    """
    random.seed(seed)
    base = datetime(2026, 4, 1)
    rows: list[tuple[str, str]] = []

    num_attack = int(num_lines * attack_ratio)
    num_normal = num_lines - num_attack

    for _ in range(num_normal):
        gen = random.choice(NORMAL_GENERATORS)
        rows.append(gen(base))

    for _ in range(num_attack):
        gen = random.choice(ATTACK_GENERATORS)
        rows.append(gen(base))

    random.shuffle(rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate labeled auth-log dataset")
    parser.add_argument("--num-lines", type=int, default=50000)
    parser.add_argument("--attack-ratio", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="data/auth_logs_labeled.csv")
    args = parser.parse_args()

    rows = generate_dataset(args.num_lines, args.attack_ratio, args.seed)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["log_line", "label"])
        writer.writerows(rows)

    # Print class distribution
    from collections import Counter
    dist = Counter(label for _, label in rows)
    print(f"Generated {len(rows)} lines -> {out}")
    for label, count in sorted(dist.items()):
        print(f"  {label:25s}: {count:6d} ({100*count/len(rows):.1f}%)")


if __name__ == "__main__":
    main()
