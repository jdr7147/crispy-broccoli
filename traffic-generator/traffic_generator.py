"""
traffic_generator.py — Endpoint traffic simulator for SentinelOne agent testing.

Generates two categories of activity:
  NORMAL       — realistic background traffic (web browsing, DNS, file I/O, SMTP)
  [TEST-ATTACK] — clearly labeled simulated attack behaviors for detection validation

OS-aware: detects Windows / RHEL/CentOS / Debian/Kali / macOS at startup and
runs only the attacks and recon commands relevant to that platform.

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import logging
import os
import platform
import random
import smtplib
import socket
import subprocess
import tempfile
import time
import urllib.request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FMT = "%(asctime)s  %(levelname)-8s  %(message)s"
logging.basicConfig(format=LOG_FMT, datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)
log = logging.getLogger("traffic-gen")

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: windows | rhel | debian | macos | linux"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        try:
            with open("/etc/os-release") as f:
                text = f.read().lower()
            if any(x in text for x in ("centos", "rhel", "fedora", "rocky", "almalinux")):
                return "rhel"
            if any(x in text for x in ("kali", "debian", "ubuntu", "mint", "parrot")):
                return "debian"
        except OSError:
            pass
        return "linux"
    return "linux"


OS = detect_os()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BENIGN_URLS = [
    "https://www.wikipedia.org",
    "https://www.bbc.com",
    "https://www.weather.gov",
    "https://www.python.org",
    "https://www.nist.gov",
    "https://www.cnn.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://news.ycombinator.com",
    "https://www.reuters.com",
]

DNS_TARGETS = [
    "www.google.com",
    "mail.google.com",
    "smtp.office365.com",
    "imap.gmail.com",
    "windowsupdate.microsoft.com",
    "api.github.com",
    "pypi.org",
]

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# ---------------------------------------------------------------------------
# Per-OS recon command tables
# ---------------------------------------------------------------------------

_RECON = {
    "windows": [
        ["whoami"],
        ["whoami", "/all"],
        ["ipconfig", "/all"],
        ["net", "user"],
        ["net", "localgroup", "administrators"],
        ["net", "share"],
        ["netstat", "-an"],
        ["tasklist"],
        ["systeminfo"],
        ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"],
        ["reg", "query", r"HKCU\Software\Microsoft\Internet Explorer\Main"],
        ["wmic", "process", "list", "brief"],
        ["wmic", "useraccount", "list"],
        ["dir", r"C:\Users"],
        ["schtasks", "/query"],
        ["arp", "-a"],
        ["route", "print"],
    ],
    "rhel": [
        ["whoami"],
        ["id"],
        ["uname", "-a"],
        ["ip", "addr"],
        ["ip", "route"],
        ["ss", "-tulnp"],
        ["ps", "aux"],
        ["cat", "/etc/passwd"],
        ["cat", "/etc/hosts"],
        ["ls", "/home"],
        ["env"],
        ["crontab", "-l"],
        ["arp", "-n"],
        ["rpm", "-qa"],
        ["systemctl", "list-units", "--type=service", "--state=running"],
        ["last"],
        ["w"],
        ["find", "/etc/cron.d", "-type", "f"],
    ],
    "debian": [
        ["whoami"],
        ["id"],
        ["uname", "-a"],
        ["ip", "addr"],
        ["ip", "route"],
        ["ss", "-tulnp"],
        ["ps", "aux"],
        ["cat", "/etc/passwd"],
        ["cat", "/etc/hosts"],
        ["ls", "/home"],
        ["env"],
        ["crontab", "-l"],
        ["arp", "-n"],
        ["dpkg", "-l"],
        ["systemctl", "list-units", "--type=service", "--state=running"],
        ["last"],
        ["w"],
        ["find", "/etc/cron.d", "-type", "f"],
    ],
    "macos": [
        ["whoami"],
        ["id"],
        ["uname", "-a"],
        ["ifconfig"],
        ["netstat", "-an"],
        ["ps", "aux"],
        ["ls", "/Users"],
        ["env"],
        ["crontab", "-l"],
        ["arp", "-an"],
        ["launchctl", "list"],
        ["sw_vers"],
        ["last"],
        ["w"],
        ["dscl", ".", "-list", "/Users"],
    ],
    "linux": [
        ["whoami"],
        ["id"],
        ["uname", "-a"],
        ["ip", "addr"],
        ["ss", "-tulnp"],
        ["ps", "aux"],
        ["cat", "/etc/passwd"],
        ["cat", "/etc/hosts"],
        ["ls", "/home"],
        ["env"],
        ["crontab", "-l"],
    ],
}

# ---------------------------------------------------------------------------
# Per-OS credential file targets
# ---------------------------------------------------------------------------

_CRED_TARGETS = {
    "windows": [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SYSTEM",
        r"C:\Users\Default\NTUSER.DAT",
        os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles"),
        os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
        os.path.expanduser(r"~\AppData\Local\Microsoft\Credentials"),
    ],
    "rhel": [
        "/etc/shadow",
        "/etc/sudoers",
        "/var/log/secure",
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.bash_history"),
        "/root/.bash_history",
        "/root/.ssh/authorized_keys",
    ],
    "debian": [
        "/etc/shadow",
        "/etc/sudoers",
        "/var/log/auth.log",
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.bash_history"),
        "/root/.bash_history",
        "/root/.ssh/authorized_keys",
    ],
    "macos": [
        "/etc/master.passwd",
        "/etc/sudoers",
        os.path.expanduser("~/Library/Keychains"),
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
        "/var/log/system.log",
    ],
    "linux": [
        "/etc/shadow",
        "/etc/sudoers",
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.bash_history"),
        "/root/.bash_history",
    ],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tag(label: str) -> str:
    return f"[{label}]"


def run_cmd(args: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        snippet = (result.stdout or "").strip()[:200]
        return result.returncode, snippet
    except FileNotFoundError:
        return -1, f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as exc:
        return -1, str(exc)


def _which(cmd: str) -> bool:
    """Return True if cmd is available on PATH."""
    rc, _ = run_cmd(["which", cmd] if OS != "windows" else ["where", cmd], timeout=5)
    return rc == 0

# ---------------------------------------------------------------------------
# Normal traffic — cross-platform
# ---------------------------------------------------------------------------

def normal_web_browse():
    url = random.choice(BENIGN_URLS)
    log.info("%s Web browse → %s", _tag("NORMAL"), url)
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (compatible; EndpointSim/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            size = len(resp.read(65536))
        log.info("%s  ← %d bytes", _tag("NORMAL"), size)
    except Exception as exc:
        log.debug("%s  browse error: %s", _tag("NORMAL"), exc)


def normal_dns_lookup():
    host = random.choice(DNS_TARGETS)
    log.info("%s DNS lookup → %s", _tag("NORMAL"), host)
    try:
        ip = socket.gethostbyname(host)
        log.info("%s  ← %s", _tag("NORMAL"), ip)
    except Exception as exc:
        log.debug("%s  DNS error: %s", _tag("NORMAL"), exc)


def normal_file_operations():
    tmpdir = tempfile.gettempdir()
    fname = os.path.join(tmpdir, f"sim_doc_{random.randint(1000, 9999)}.txt")
    content = f"Meeting notes {datetime.datetime.now()}\n" + "Lorem ipsum " * 20
    log.info("%s File I/O → write %s", _tag("NORMAL"), fname)
    try:
        with open(fname, "w") as f:
            f.write(content)
        with open(fname, "r") as f:
            _ = f.read()
        os.remove(fname)
    except Exception as exc:
        log.debug("%s  file I/O error: %s", _tag("NORMAL"), exc)


def normal_smtp_probe():
    log.info("%s SMTP probe → %s:%d", _tag("NORMAL"), SMTP_HOST, SMTP_PORT)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as s:
            banner = s.ehlo()[1].decode(errors="replace")[:80]
        log.info("%s  ← EHLO OK: %s", _tag("NORMAL"), banner)
    except Exception as exc:
        log.debug("%s  SMTP error: %s", _tag("NORMAL"), exc)


def normal_local_info():
    """Run a couple of benign system-info commands appropriate for the OS."""
    cmds = {
        "windows": [["hostname"], ["ver"]],
        "rhel":    [["hostname"], ["uname", "-r"], ["hostnamectl"]],
        "debian":  [["hostname"], ["uname", "-r"], ["hostnamectl"]],
        "macos":   [["hostname"], ["sw_vers"]],
        "linux":   [["hostname"], ["uname", "-r"]],
    }
    cmd = random.choice(cmds.get(OS, [["hostname"]]))
    log.info("%s Local info → %s", _tag("NORMAL"), " ".join(cmd))
    _, out = run_cmd(cmd)
    log.info("%s  ← %s", _tag("NORMAL"), out[:100] if out else "(empty)")


NORMAL_ACTIONS = [
    (normal_web_browse,     4),
    (normal_dns_lookup,     3),
    (normal_file_operations, 3),
    (normal_smtp_probe,     1),
    (normal_local_info,     2),
]


def pick_normal() -> callable:
    population, weights = zip(*NORMAL_ACTIONS)
    return random.choices(population, weights=weights, k=1)[0]

# ---------------------------------------------------------------------------
# Attack simulations — common to all platforms
# ---------------------------------------------------------------------------

def attack_eicar_drop():
    fname = os.path.join(tempfile.gettempdir(), "EICAR_TEST.com")
    log.warning("%s Dropping EICAR test file → %s", _tag("TEST-ATTACK"), fname)
    try:
        with open(fname, "w") as f:
            f.write(EICAR_STRING)
        log.warning("%s  EICAR written — expecting AV/EDR alert", _tag("TEST-ATTACK"))
        time.sleep(2)
        os.remove(fname)
        log.warning("%s  EICAR removed", _tag("TEST-ATTACK"))
    except Exception as exc:
        log.debug("%s  EICAR error: %s", _tag("TEST-ATTACK"), exc)


def attack_recon_commands():
    cmds = _RECON.get(OS, _RECON["linux"])
    burst = random.randint(2, 4)
    log.warning(
        "%s Recon burst (%d commands) — post-exploitation enum", _tag("TEST-ATTACK"), burst
    )
    for _ in range(burst):
        cmd = random.choice(cmds)
        log.warning("%s  exec: %s", _tag("TEST-ATTACK"), " ".join(cmd))
        rc, out = run_cmd(cmd)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80] if out else "(empty)")
        time.sleep(random.uniform(0.3, 1.0))


def attack_port_scan_localhost():
    ports = random.sample(range(1, 1025), 20)
    log.warning("%s Port scan — localhost:%s", _tag("TEST-ATTACK"), sorted(ports))
    open_ports = []
    for port in sorted(ports):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            open_ports.append(port)
        s.close()
    log.warning("%s  scan done — open ports: %s", _tag("TEST-ATTACK"), open_ports or "none")


def attack_credential_file_access():
    targets = _CRED_TARGETS.get(OS, _CRED_TARGETS["linux"])
    sample = random.sample(targets, min(3, len(targets)))
    log.warning("%s Credential file access — simulating harvesting", _tag("TEST-ATTACK"))
    for path in sample:
        log.warning("%s  stat: %s", _tag("TEST-ATTACK"), path)
        try:
            exists = os.path.exists(path)
            log.warning("%s    → %s", _tag("TEST-ATTACK"), "EXISTS" if exists else "not found")
        except Exception as exc:
            log.warning("%s    → error: %s", _tag("TEST-ATTACK"), exc)


def attack_suspicious_network_connection():
    port = random.choice([4444, 8080, 1337, 31337, 6666])
    host = "127.0.0.1"
    log.warning(
        "%s Suspicious outbound connection — %s:%d (C2-like port)",
        _tag("TEST-ATTACK"), host, port,
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    rc = s.connect_ex((host, port))
    s.close()
    log.warning(
        "%s  result: %s", _tag("TEST-ATTACK"),
        "open" if rc == 0 else f"refused/filtered (rc={rc})",
    )


def attack_script_in_temp():
    tmpdir = tempfile.gettempdir()
    if OS == "windows":
        fname = os.path.join(tmpdir, "test_payload.bat")
        content = '@echo [TEST-ATTACK] Script-in-temp execution test\r\n@echo SentinelOne simulation\r\n'
        runner = ["cmd.exe", "/c", fname]
    else:
        fname = os.path.join(tmpdir, "test_payload.sh")
        content = '#!/bin/sh\necho "[TEST-ATTACK] Script-in-temp execution test"\necho "SentinelOne simulation"\n'
        runner = ["sh", fname]

    log.warning("%s Script-in-temp — write+exec %s", _tag("TEST-ATTACK"), fname)
    try:
        with open(fname, "w") as f:
            f.write(content)
        if OS != "windows":
            os.chmod(fname, 0o755)
        rc, out = run_cmd(runner, timeout=10)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out)
        os.remove(fname)
    except Exception as exc:
        log.debug("%s  error: %s", _tag("TEST-ATTACK"), exc)

# ---------------------------------------------------------------------------
# Attack simulations — Windows
# ---------------------------------------------------------------------------

def attack_powershell_encoded():
    payload = '[System.Console]::WriteLine("[TEST-ATTACK] SentinelOne encoded PS test")'
    encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
    log.warning("%s PowerShell encoded command — base64 payload exec", _tag("TEST-ATTACK"))
    rc, out = run_cmd(
        ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded], timeout=15
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_powershell_download_cradle():
    url = "https://httpbin.org/get"
    script = (
        f'(New-Object Net.WebClient).DownloadString("{url}") | Out-Null; '
        'Write-Output "[TEST-ATTACK] cradle complete"'
    )
    log.warning("%s PowerShell download cradle → %s", _tag("TEST-ATTACK"), url)
    rc, out = run_cmd(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=20,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_lolbas_certutil():
    """certutil used as a downloader — a classic LOLBAS technique."""
    url = "https://httpbin.org/get"
    outfile = os.path.join(tempfile.gettempdir(), "test_certutil.tmp")
    log.warning("%s LOLBAS certutil download → %s", _tag("TEST-ATTACK"), url)
    rc, out = run_cmd(
        ["certutil", "-urlcache", "-split", "-f", url, outfile], timeout=20
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])
    try:
        os.remove(outfile)
    except OSError:
        pass


def attack_windows_registry_enum():
    """Enumerate sensitive registry keys — common credential/config harvesting path."""
    keys = [
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"HKCU\Software\SimonTatham\PuTTY\Sessions",
        r"HKLM\SOFTWARE\OpenSSH",
        r"HKCU\Software\Microsoft\Terminal Server Client\Servers",
    ]
    log.warning("%s Registry enumeration — credential/config keys", _tag("TEST-ATTACK"))
    for key in random.sample(keys, 2):
        log.warning("%s  reg query: %s", _tag("TEST-ATTACK"), key)
        rc, out = run_cmd(["reg", "query", key], timeout=8)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80] if out else "(empty)")

# ---------------------------------------------------------------------------
# Attack simulations — Linux (all flavors)
# ---------------------------------------------------------------------------

def attack_bash_encoded():
    """base64-encoded bash one-liner — Linux equivalent of PS -EncodedCommand."""
    payload = 'echo "[TEST-ATTACK] SentinelOne bash encoded command test"'
    encoded = base64.b64encode(payload.encode()).decode()
    log.warning("%s Bash encoded command — base64 decode+exec", _tag("TEST-ATTACK"))
    rc, out = run_cmd(
        ["bash", "-c", f"echo {encoded} | base64 -d | bash"], timeout=10
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_curl_download_cradle():
    """curl/wget to a safe endpoint — simulates stage-2 retrieval."""
    url = "https://httpbin.org/get"
    tool = "curl" if _which("curl") else "wget"
    log.warning("%s %s download cradle → %s", _tag("TEST-ATTACK"), tool, url)
    if tool == "curl":
        rc, out = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=15)
    else:
        rc, out = run_cmd(["wget", "-q", "-O", "/dev/null", url], timeout=15)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80])


def attack_suid_search():
    """Find SUID binaries — standard Linux privilege escalation recon."""
    log.warning("%s SUID binary search — privilege escalation recon", _tag("TEST-ATTACK"))
    rc, out = run_cmd(
        ["find", "/usr", "-perm", "-4000", "-type", "f"], timeout=15
    )
    count = len(out.splitlines()) if out else 0
    log.warning("%s  rc=%d  found %d entries", _tag("TEST-ATTACK"), rc, count)


def attack_cron_persistence_attempt():
    """Attempt to write a crontab entry — simulates persistence establishment."""
    log.warning("%s Cron persistence attempt — write test entry", _tag("TEST-ATTACK"))
    marker = "# [TEST-ATTACK] SentinelOne persistence simulation"
    rc, out = run_cmd(
        ["bash", "-c", f'(crontab -l 2>/dev/null; echo "{marker}") | crontab -'],
        timeout=10,
    )
    log.warning("%s  rc=%d  %s", _tag("TEST-ATTACK"), rc, "entry written" if rc == 0 else "blocked/failed")
    if rc == 0:
        # clean it back out immediately
        run_cmd(
            ["bash", "-c", f"crontab -l | grep -v '{marker}' | crontab -"],
            timeout=10,
        )
        log.warning("%s  test entry removed", _tag("TEST-ATTACK"))


def attack_sensitive_dir_traversal():
    """Walk directories commonly targeted for sensitive data."""
    dirs = ["/etc", "/var/log", "/root", os.path.expanduser("~/.ssh"), "/tmp"]
    target = random.choice(dirs)
    log.warning("%s Directory traversal → %s", _tag("TEST-ATTACK"), target)
    rc, out = run_cmd(["ls", "-la", target], timeout=8)
    count = len(out.splitlines()) if out else 0
    log.warning("%s  rc=%d  %d entries listed", _tag("TEST-ATTACK"), rc, count)

# ---------------------------------------------------------------------------
# Attack simulations — RHEL/CentOS specific
# ---------------------------------------------------------------------------

def attack_rpm_verify():
    """rpm -Va checks package file integrity — used to detect tampered binaries."""
    log.warning("%s rpm -Va — package integrity check (tamper detection recon)", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["rpm", "-Va", "--nodeps"], timeout=20)
    lines = len(out.splitlines()) if out else 0
    log.warning("%s  rc=%d  %d discrepancies found", _tag("TEST-ATTACK"), rc, lines)


def attack_yum_recon():
    """Enumerate installed packages and repos via yum/dnf."""
    tool = "dnf" if _which("dnf") else "yum"
    log.warning("%s %s recon — installed package enumeration", _tag("TEST-ATTACK"), tool)
    rc, out = run_cmd([tool, "list", "installed"], timeout=20)
    lines = len(out.splitlines()) if out else 0
    log.warning("%s  rc=%d  %d packages listed", _tag("TEST-ATTACK"), rc, lines)

# ---------------------------------------------------------------------------
# Attack simulations — Debian/Kali specific
# ---------------------------------------------------------------------------

def attack_dpkg_recon():
    """Enumerate installed packages via dpkg — common post-compromise inventory."""
    log.warning("%s dpkg recon — installed package enumeration", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["dpkg", "-l"], timeout=15)
    lines = len(out.splitlines()) if out else 0
    log.warning("%s  rc=%d  %d packages listed", _tag("TEST-ATTACK"), rc, lines)


def attack_kali_tool_probe():
    """Check for common offensive tools — simulates attacker tooling inventory."""
    tools = ["nmap", "metasploit", "msfconsole", "hydra", "john", "hashcat",
             "sqlmap", "burpsuite", "aircrack-ng", "nikto", "gobuster"]
    sample = random.sample(tools, 4)
    log.warning("%s Offensive tool probe — checking for: %s", _tag("TEST-ATTACK"), sample)
    for tool in sample:
        found = _which(tool)
        log.warning("%s  %s → %s", _tag("TEST-ATTACK"), tool, "FOUND" if found else "not present")

# ---------------------------------------------------------------------------
# Attack simulations — macOS specific
# ---------------------------------------------------------------------------

def attack_keychain_access():
    """Attempt to list keychain entries — credential harvesting simulation."""
    log.warning("%s Keychain access — credential harvesting simulation", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["security", "list-keychains"], timeout=8)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120] if out else "(empty)")
    rc2, out2 = run_cmd(
        ["security", "find-generic-password", "-s", "com.apple.terminal"],
        timeout=8,
    )
    log.warning("%s  find-generic-password rc=%d", _tag("TEST-ATTACK"), rc2)


def attack_launchd_persistence():
    """Write and load a LaunchAgent plist — macOS persistence simulation."""
    plist_path = os.path.expanduser(
        "~/Library/LaunchAgents/com.test.sentinelone.simulation.plist"
    )
    plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.test.sentinelone.simulation</string>
  <key>ProgramArguments</key><array><string>/bin/echo</string><string>[TEST-ATTACK] LaunchAgent</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>"""
    log.warning(
        "%s LaunchAgent persistence — write+load %s", _tag("TEST-ATTACK"), plist_path
    )
    try:
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        with open(plist_path, "w") as f:
            f.write(plist_content)
        rc, out = run_cmd(["launchctl", "load", plist_path], timeout=10)
        log.warning("%s  load rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80])
        run_cmd(["launchctl", "unload", plist_path], timeout=10)
        os.remove(plist_path)
        log.warning("%s  plist removed", _tag("TEST-ATTACK"))
    except Exception as exc:
        log.debug("%s  error: %s", _tag("TEST-ATTACK"), exc)


def attack_macos_recon():
    """macOS-specific enumeration: users, network, security settings."""
    cmds = [
        ["dscl", ".", "-list", "/Users"],
        ["networksetup", "-listallnetworkservices"],
        ["system_profiler", "SPSoftwareDataType"],
        ["defaults", "read", "/Library/Preferences/com.apple.loginwindow"],
    ]
    cmd = random.choice(cmds)
    log.warning("%s macOS recon — %s", _tag("TEST-ATTACK"), " ".join(cmd))
    rc, out = run_cmd(cmd, timeout=10)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120] if out else "(empty)")

# ---------------------------------------------------------------------------
# Build OS-appropriate attack list
# ---------------------------------------------------------------------------

_ATTACKS_COMMON = [
    attack_eicar_drop,
    attack_recon_commands,
    attack_port_scan_localhost,
    attack_credential_file_access,
    attack_suspicious_network_connection,
    attack_script_in_temp,
]

_ATTACKS_BY_OS = {
    "windows": [
        attack_powershell_encoded,
        attack_powershell_download_cradle,
        attack_lolbas_certutil,
        attack_windows_registry_enum,
    ],
    "rhel": [
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_suid_search,
        attack_cron_persistence_attempt,
        attack_sensitive_dir_traversal,
        attack_rpm_verify,
        attack_yum_recon,
    ],
    "debian": [
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_suid_search,
        attack_cron_persistence_attempt,
        attack_sensitive_dir_traversal,
        attack_dpkg_recon,
        attack_kali_tool_probe,
    ],
    "macos": [
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_suid_search,
        attack_sensitive_dir_traversal,
        attack_keychain_access,
        attack_launchd_persistence,
        attack_macos_recon,
    ],
    "linux": [
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_suid_search,
        attack_cron_persistence_attempt,
        attack_sensitive_dir_traversal,
    ],
}

ATTACK_ACTIONS = _ATTACKS_COMMON + _ATTACKS_BY_OS.get(OS, [])

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def jitter(seconds: float, pct: float = 0.3) -> float:
    delta = seconds * pct
    return max(1.0, seconds + random.uniform(-delta, delta))


def run_loop(
    normal_interval: float,
    attack_interval: float,
    attack_probability: float,
    max_runtime: float | None,
):
    start = time.monotonic()
    cycle = 0

    log.info("=" * 70)
    log.info("  SentinelOne Traffic Generator — SIMULATION STARTED")
    log.info("  OS profile      : %s  (%s)", OS, platform.platform())
    log.info("  Normal interval : %.0fs  Attack interval : %.0fs", normal_interval, attack_interval)
    log.info("  Attack probability per window : %.0f%%", attack_probability * 100)
    log.info("  Attack pool : %d actions", len(ATTACK_ACTIONS))
    log.info("=" * 70)

    next_normal = time.monotonic()
    next_attack = time.monotonic() + attack_interval

    try:
        while True:
            now = time.monotonic()

            if max_runtime and (now - start) >= max_runtime:
                log.info("Max runtime reached — stopping.")
                break

            if now >= next_normal:
                action = pick_normal()
                try:
                    action()
                except Exception as exc:
                    log.debug("Normal action error: %s", exc)
                next_normal = now + jitter(normal_interval)

            if now >= next_attack:
                if random.random() < attack_probability:
                    action = random.choice(ATTACK_ACTIONS)
                    log.warning("-" * 60)
                    log.warning("  ATTACK SIMULATION — %s", action.__name__)
                    log.warning("-" * 60)
                    try:
                        action()
                    except Exception as exc:
                        log.debug("Attack action error: %s", exc)
                else:
                    log.info("%s Attack window — no attack this cycle", _tag("NORMAL"))
                next_attack = now + jitter(attack_interval)

            cycle += 1
            time.sleep(0.5)

    except KeyboardInterrupt:
        log.info("Interrupted — stopping.")

    log.info("=" * 70)
    log.info("  Traffic Generator STOPPED after %d cycles", cycle)
    log.info("=" * 70)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="OS-aware endpoint traffic simulator for SentinelOne agent testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: normal traffic every 30s, attack window every 5 min, 40% attack rate
  python traffic_generator.py

  # Aggressive: normal every 15s, attack every 2 min, always attack
  python traffic_generator.py --normal-interval 15 --attack-interval 120 --attack-prob 1.0

  # Normal traffic only, no attacks
  python traffic_generator.py --attack-prob 0

  # Run for 1 hour, log to file
  python traffic_generator.py --runtime 3600 --log-file sim.log
""",
    )
    parser.add_argument(
        "--normal-interval", type=float, default=30.0, metavar="SEC",
        help="Seconds between normal traffic events (default: 30)",
    )
    parser.add_argument(
        "--attack-interval", type=float, default=300.0, metavar="SEC",
        help="Seconds between attack simulation windows (default: 300)",
    )
    parser.add_argument(
        "--attack-prob", type=float, default=0.4, metavar="0-1",
        help="Probability [0–1] of an attack firing each window (default: 0.4)",
    )
    parser.add_argument(
        "--runtime", type=float, default=None, metavar="SEC",
        help="Total seconds to run before exiting (default: run forever)",
    )
    parser.add_argument("--verbose", action="store_true", help="Show DEBUG-level output")
    parser.add_argument("--log-file", metavar="PATH", help="Also write logs to this file")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setFormatter(logging.Formatter(LOG_FMT, datefmt="%Y-%m-%d %H:%M:%S"))
        logging.getLogger().addHandler(fh)
        log.info("Logging to file: %s", args.log_file)

    if not (0.0 <= args.attack_prob <= 1.0):
        parser.error("--attack-prob must be between 0 and 1")

    run_loop(
        normal_interval=args.normal_interval,
        attack_interval=args.attack_interval,
        attack_probability=args.attack_prob,
        max_runtime=args.runtime,
    )


if __name__ == "__main__":
    main()
