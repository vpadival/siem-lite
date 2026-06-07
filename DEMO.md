# SIEM-Lite: Live SSH Attack Demo Guide

## Overview

This guide demonstrates SIEM-Lite detecting real SSH events between two machines
on the same network. The setup used here is:

| Machine | OS | Role |
|---|---|---|
| **Target** | Parrot OS | Runs SIEM-Lite, SSH server |
| **Attacker** | Kali Linux | Sends SSH login attempts |

Any two Linux machines on the same network work — Ubuntu↔Kali, Ubuntu↔Parrot,
VM↔Host, etc. Both machines just need network visibility to each other.

---

## Part 1 — Setup on Parrot OS (Target)

### 1.1 Install rsyslog (if not already running)

Parrot OS ships without rsyslog enabled. Without it, SSH events don't appear
in `/var/log/auth.log`.

```bash
sudo apt install -y rsyslog
sudo systemctl enable --now rsyslog
sudo systemctl status rsyslog     # confirm it says "active (running)"
```

### 1.2 Make auth.log readable by your user

```bash
sudo chmod o+r /var/log/auth.log
# Verify — this should print recent SSH lines
tail -5 /var/log/auth.log
```

### 1.3 Enable and start the SSH server on Parrot

```bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo systemctl status ssh          # should say "active (running)"
```

Find Parrot's IP — you'll need this on Kali:

```bash
ip addr show | grep "inet " | grep -v 127
# e.g. inet 192.168.1.42/24
```

### 1.4 Clone and set up SIEM-Lite

```bash
cd ~
git clone https://github.com/vpadival/siem-lite.git
cd siem-lite
make install      # creates venv, installs all deps
```

If models are already trained (ml/models/ present):

```bash
# Start the unified scorer — detects rules + ML + brute-force
source venv/bin/activate
python scripts/unified_scorer.py --debug
```

If you want rule-only mode (no ML needed):

```bash
python scripts/alert_scorer.py --brute-threshold 3 --brute-window 30 --debug
```

Leave this running in a terminal. You will see alerts appear here in real time.

---

## Part 2 — Attacks from Kali Linux (Attacker)

Open a terminal on Kali. Replace `PARROT_IP` with the IP found in step 1.3.

### Demo 1 — Single successful SSH login

```bash
ssh your_username@PARROT_IP
```

**What SIEM-Lite fires on Parrot:**
- If login happens between 23:00–04:59 → `After-hours login` alert (severity: LOW)
- If you log in as root → `Direct root login via SSH` alert (severity: CRITICAL)

Expected output on Parrot:
```
ALERT  score=1    severity=LOW      rule=After-hours login  msg=[ALERT] After-hours login at 23:xx by alice from 192.168.1.55.
```

---

### Demo 2 — SSH brute-force (wrong password, repeated)

The unified scorer tracks failures per-IP over a 60-second sliding window.
Five failures from the same Kali IP fires a single consolidated alert.

```bash
# Try wrong passwords 5 times quickly (Ctrl-C after each rejection)
for i in 1 2 3 4 5; do
  ssh -o ConnectTimeout=5 wronguser@PARROT_IP
done
```

**What SIEM-Lite fires:**
```
BRUTE-FORCE  score=10   severity=HIGH   rule=SSH brute force
msg=[ALERT] 5 failed SSH logins from 192.168.1.55 within 60s window.
```

To lower the threshold for demo purposes (fire after 3 failures):

```bash
# Restart scorer on Parrot with custom threshold
python scripts/unified_scorer.py --brute-threshold 3 --brute-window 30 --debug
```

---

### Demo 3 — Direct root SSH login

On Parrot, temporarily enable root SSH (demo only — disable after):

```bash
sudo nano /etc/ssh/sshd_config
# Change: PermitRootLogin no  ->  PermitRootLogin yes
sudo systemctl restart ssh
```

From Kali:

```bash
ssh root@PARROT_IP
```

**What SIEM-Lite fires:**
```
ALERT  score=10   severity=CRITICAL   rule=Direct root login via SSH
msg=[ALERT] Direct root SSH login from IP 192.168.1.55.
```

Re-disable after demo:

```bash
sudo nano /etc/ssh/sshd_config   # set PermitRootLogin back to no
sudo systemctl restart ssh
```

---

### Demo 4 — Privilege escalation (after login)

Log into Parrot from Kali with a valid account, then run sudo:

```bash
ssh your_username@PARROT_IP
# Once inside Parrot:
sudo cat /etc/shadow
```

**What SIEM-Lite fires:**
```
ALERT  score=3    severity=MEDIUM     rule=Privilege escalation
msg=[ALERT] Privilege escalation: your_username ran sudo command: /bin/cat /etc/shadow
```

---

### Demo 5 — New user creation

On Parrot (via SSH or local terminal):

```bash
sudo useradd backdoor
```

**What SIEM-Lite fires:**
```
ALERT  score=3    severity=MEDIUM     rule=New user created
msg=[ALERT] New user created: backdoor.
```

Clean up:

```bash
sudo userdel backdoor
```

---

## Part 3 — Viewing in Grafana (Optional)

Start the PLG stack on Parrot alongside the scorer:

```bash
# Terminal 1
make up   # starts Grafana + Loki + Promtail

# Terminal 2
python scripts/unified_scorer.py --push-to-loki http://localhost:3100 --debug
```

Open `http://localhost:3000` in a browser on Parrot.
- Login: admin / changeme_in_production (or whatever you set in .env)
- Go to **Explore** → select **Loki** datasource
- Query: `{job="siem_ml_alerts"}` for ML alerts
- Query: `{job="siem_unified"}` for brute-force events

---

## Part 4 — Hydra Brute-Force (Advanced Demo)

Kali has `hydra` pre-installed. This fires many failures rapidly and clearly
demonstrates the sliding-window counter working at scale.

```bash
# On Kali — generates a burst of SSH failures
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  -t 4 -f ssh://PARROT_IP

# Stop with Ctrl-C after the SIEM fires the brute-force alert on Parrot
```

> ⚠️ Only do this on machines you own or have explicit permission to test.

---

## Expected Alert Summary

| Scenario | Rule | Severity | Score |
|---|---|---|---|
| SSH login at night | After-hours login | LOW | 1 |
| Root SSH login | Direct root login via SSH | CRITICAL | 10 |
| 5+ failed logins from same IP | SSH brute force (sliding window) | HIGH | 10 |
| sudo command run | Privilege escalation | MEDIUM | 3 |
| useradd/adduser | New user created | MEDIUM | 3 |
| Failed su attempts | Repeated su failures | HIGH | 5 |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No alerts appearing | Check `tail -f /var/log/auth.log` — are SSH events being logged? |
| `No log files found` | Run `sudo systemctl start rsyslog` on Parrot |
| SSH refused from Kali | Run `sudo systemctl start ssh` on Parrot |
| Permission denied on auth.log | `sudo chmod o+r /var/log/auth.log` |
| Brute-force not firing | Lower `--brute-threshold` or do more rapid attempts |
| ML models missing | Run `make train` before using unified_scorer |
