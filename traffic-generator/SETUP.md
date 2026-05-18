# SentinelOne Traffic Generator — Setup & Usage Guide

Simulates realistic endpoint activity for validating SentinelOne agent
detection coverage. Runs two categories of activity on a configurable schedule:

- **Normal traffic** — web browsing, DNS lookups, file I/O, SMTP probes
- **Attack simulations** — clearly labeled `[TEST-ATTACK]` behaviors that
  mirror real attacker techniques: recon bursts, credential file access,
  encoded commands, persistence attempts, and more

Automatically detects the host OS at startup and loads only the attacks
relevant to that platform — no PowerShell on Linux, no bash cradles on Windows.

**Supported platforms:** Windows 10/11 · RHEL / CentOS / Rocky · Debian / Ubuntu / Kali · macOS

---

## What You Need

| Requirement | Notes |
|---|---|
| Python 3.10 – 3.12 | 3.13 is **not** recommended (library compatibility) |
| `traffic_generator.py` | The simulator script |
| Network access | Used for web browse and DNS simulation |
| No extra packages | All dependencies are Python standard library |

---

## Setup

### Windows

1. Download and install Python 3.11 from **python.org/downloads**.  
   Check **"Add python.exe to PATH"** during installation.

2. Open Command Prompt and verify:
   ```
   python --version
   ```

3. Run the script directly — no packages to install:
   ```
   python traffic_generator.py
   ```

### Linux (RHEL / CentOS / Debian / Kali / Ubuntu)

Most distributions ship with Python 3. Verify:

```bash
python3 --version
```

If missing, install it:

```bash
# RHEL / CentOS / Rocky
sudo dnf install python3

# Debian / Ubuntu / Kali
sudo apt install python3
```

Run the script:

```bash
python3 traffic_generator.py
```

### macOS

macOS ships with Python 3 via Xcode Command Line Tools. If needed:

```bash
xcode-select --install
```

Run the script:

```bash
python3 traffic_generator.py
```

---

## Quick Start

```bash
# Default: normal event every 30s, attack window every 5 min, 40% chance of attack
python3 traffic_generator.py

# Aggressive: attack every 2 min, guaranteed to fire
python3 traffic_generator.py --normal-interval 15 --attack-interval 120 --attack-prob 1.0

# Normal traffic only, no attack simulations
python3 traffic_generator.py --attack-prob 0

# Run for 1 hour and save logs to file
python3 traffic_generator.py --runtime 3600 --log-file sim.log
```

---

## All Options

| Option | Default | Description |
|---|---|---|
| `--normal-interval SEC` | `30` | Seconds between normal traffic events |
| `--attack-interval SEC` | `300` | Seconds between attack simulation windows |
| `--attack-prob 0-1` | `0.4` | Probability an attack fires each window (0 = never, 1 = always) |
| `--runtime SEC` | *(run forever)* | Stop automatically after this many seconds |
| `--log-file PATH` | *(stdout only)* | Also write logs to this file |
| `--verbose` | — | Show DEBUG-level output |

---

## OS Detection

The script reads `/etc/os-release` on Linux to identify the distribution,
then prints the detected profile at startup:

```
OS profile      : rhel  (Linux-5.14.0-x86_64-with-glibc2.28)
Attack pool     : 13 actions
```

| Detected value | Covers |
|---|---|
| `windows` | Windows 10, 11, Server |
| `rhel` | RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora |
| `debian` | Debian, Ubuntu, Kali Linux, Parrot OS, Mint |
| `macos` | macOS (any version) |
| `linux` | Any other Linux distribution |

---

## What It Simulates

### Normal Traffic (all platforms)

| Action | What it does |
|---|---|
| Web browse | HTTP GET to real news/reference sites with a browser User-Agent |
| DNS lookup | Resolves mail, CDN, and update hostnames |
| File I/O | Writes, reads, and deletes a temp document file |
| SMTP probe | EHLO handshake to smtp.gmail.com:587 — like an email client connecting |
| Local info | OS-appropriate system info commands (`hostname`, `uname`, `sw_vers`, `ver`) |

### Attack Simulations

All attack events are tagged `[TEST-ATTACK]` and logged at WARNING level
so they are easy to filter in a SIEM or log file.

#### Common to all platforms

| Simulation | Technique |
|---|---|
| EICAR drop | Writes the industry-standard AV test string to disk, waits 2s, deletes it |
| Recon burst | Runs 2–4 enumeration commands in quick succession (OS-specific list) |
| Port scan | Rapid SYN sweep of 20 random localhost ports |
| Credential file access | Stat-checks well-known credential paths (SAM, shadow, SSH keys, browser stores) |
| C2-like connection | TCP connect attempt to ports 4444, 1337, 31337, 8080, 6666 |
| Script-in-temp | Writes a `.bat` or `.sh` to the temp directory and executes it from there |

#### Windows only

| Simulation | Technique |
|---|---|
| PowerShell encoded command | `powershell -EncodedCommand <base64>` — common obfuscation technique |
| PowerShell download cradle | `(New-Object Net.WebClient).DownloadString(url)` — stage-2 retrieval simulation |
| certutil LOLBAS | Uses `certutil -urlcache -split -f` to download a file — Living off the Land |
| Registry enumeration | Queries credential-adjacent keys (Winlogon, PuTTY sessions, OpenSSH, RDP history) |

#### RHEL / CentOS

| Simulation | Technique |
|---|---|
| Bash encoded command | `bash -c "$(echo <base64> \| base64 -d)"` — Linux obfuscation equivalent |
| curl/wget download cradle | Downloads from a safe echo endpoint to simulate payload retrieval |
| SUID binary search | `find /usr -perm -4000` — standard privilege escalation recon |
| Cron persistence | Writes a test crontab entry then removes it immediately |
| Directory traversal | Lists `/etc`, `/var/log`, `/root`, `~/.ssh`, `/tmp` |
| rpm -Va integrity check | Verifies package file integrity — used to find tampered binaries |
| yum/dnf package recon | Lists all installed packages via yum or dnf |

#### Debian / Kali

Same as RHEL, plus:

| Simulation | Technique |
|---|---|
| dpkg recon | Lists all installed packages via dpkg |
| Offensive tool probe | Checks for nmap, hydra, sqlmap, hashcat, gobuster, etc. |

#### macOS

| Simulation | Technique |
|---|---|
| Bash encoded command | Same base64 decode+exec technique as Linux |
| curl download cradle | Simulates payload retrieval |
| SUID binary search | Scans `/usr` for setuid binaries |
| Directory traversal | Lists sensitive directories |
| Keychain access | `security list-keychains` and `find-generic-password` |
| LaunchAgent persistence | Writes and loads a test `.plist`, then immediately unloads and deletes it |
| macOS-specific recon | `dscl`, `networksetup`, `system_profiler`, `defaults read` |

---

## Reading the Logs

```
2026-05-18 12:22:44  INFO      [NORMAL] Web browse → https://www.bbc.com
2026-05-18 12:22:48  INFO      [NORMAL]  ← 52411 bytes
2026-05-18 12:22:52  WARNING   ------------------------------------------------------------
2026-05-18 12:22:52  WARNING     ATTACK SIMULATION — attack_recon_commands
2026-05-18 12:22:52  WARNING   ------------------------------------------------------------
2026-05-18 12:22:52  WARNING   [TEST-ATTACK] Recon burst (3 commands) — post-exploitation enum
2026-05-18 12:22:52  WARNING   [TEST-ATTACK]  exec: id
2026-05-18 12:22:52  WARNING   [TEST-ATTACK]  rc=0  out=uid=1000(user) gid=1000(user) groups=...
```

- `[NORMAL]` lines are INFO level — routine background activity
- `[TEST-ATTACK]` lines are WARNING level — attack simulation events
- Attack windows are separated by a dashed divider and include the function name

To filter only attack events:

```bash
grep "TEST-ATTACK" sim.log
```

---

## Tuning for Your Environment

**Light background noise, rare attacks** (default — blends in, tests passive detection):
```bash
python3 traffic_generator.py --normal-interval 30 --attack-interval 300 --attack-prob 0.4
```

**Moderate load, frequent attacks** (active detection testing):
```bash
python3 traffic_generator.py --normal-interval 20 --attack-interval 120 --attack-prob 0.7
```

**Attack-heavy** (stress-test detection rules, guaranteed fire every window):
```bash
python3 traffic_generator.py --normal-interval 15 --attack-interval 60 --attack-prob 1.0
```

**Normal traffic only** (baseline telemetry, no detections expected):
```bash
python3 traffic_generator.py --attack-prob 0
```

---

## Troubleshooting

**"command not found: python3"**  
Install Python 3 for your distribution (see Setup section above).

**Attack simulations fire but SentinelOne doesn't alert**  
Some attacks require specific policy settings to be enabled in the SentinelOne
console. Check that Detection and Prevention policies are active for the relevant
categories (Behavioral AI, Static AI, Indicators of Attack).

**EICAR drop doesn't trigger an alert**  
Ensure real-time protection is enabled in the SentinelOne agent. The EICAR
string must be written as a `.com` file — the script does this by default.

**cron persistence attempt shows `rc=127`**  
`crontab` is not installed or the user doesn't have permission. This is expected
on minimal container images; the script logs it as blocked and moves on.

**Script runs but no network events appear in SentinelOne**  
Network visibility may require the Full Visibility or Network Control add-on.
Check your license and agent configuration in the management console.
