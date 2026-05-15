"""
traffic_generator.py — Endpoint traffic simulator for SentinelOne agent testing.

Generates two categories of activity:
  NORMAL  — realistic background traffic (web browsing, DNS, file I/O, email-like SMTP)
  [TEST-ATTACK] — clearly labeled simulated attack behaviors for detection validation

Run with --help for all options.
"""

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
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FMT = "%(asctime)s  %(levelname)-8s  %(message)s"
logging.basicConfig(format=LOG_FMT, datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)
log = logging.getLogger("traffic-gen")

WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# Configuration
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

# Recon commands that look like post-compromise enumeration
RECON_COMMANDS_WINDOWS = [
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
    ["dir", r"C:\Program Files"],
    ["schtasks", "/query"],
    ["arp", "-a"],
    ["route", "print"],
]

RECON_COMMANDS_UNIX = [
    ["whoami"],
    ["id"],
    ["uname", "-a"],
    ["ifconfig"] if WINDOWS is False else ["ip", "addr"],
    ["ps", "aux"],
    ["netstat", "-an"],
    ["cat", "/etc/passwd"],
    ["cat", "/etc/hosts"],
    ["ls", "/home"],
    ["ls", "/tmp"],
    ["env"],
    ["crontab", "-l"],
    ["ss", "-tulnp"],
    ["arp", "-n"],
]

RECON_COMMANDS = RECON_COMMANDS_WINDOWS if WINDOWS else RECON_COMMANDS_UNIX

# EICAR standard test string (safe, not a real virus)
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tag(label: str) -> str:
    return f"[{label}]"


def run_cmd(args: list[str], timeout: int = 10) -> tuple[int, str]:
    """Run a subprocess, return (returncode, stdout_snippet)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        snippet = (result.stdout or "").strip()[:200]
        return result.returncode, snippet
    except FileNotFoundError:
        return -1, f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as exc:
        return -1, str(exc)


# ---------------------------------------------------------------------------
# Normal traffic actions
# ---------------------------------------------------------------------------

def normal_web_browse():
    url = random.choice(BENIGN_URLS)
    log.info("%s Web browse → %s", _tag("NORMAL"), url)
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; EndpointSim/1.0)"},
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
    """Simulate reading config files, writing logs, opening documents."""
    tmpdir = tempfile.gettempdir()
    fname = os.path.join(tmpdir, f"sim_doc_{random.randint(1000,9999)}.txt")
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
    """Simulate an email client greeting an SMTP server (no credentials needed)."""
    log.info("%s SMTP probe → %s:%d", _tag("NORMAL"), SMTP_HOST, SMTP_PORT)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as s:
            banner = s.ehlo()[1].decode(errors="replace")[:80]
        log.info("%s  ← EHLO OK: %s", _tag("NORMAL"), banner)
    except Exception as exc:
        log.debug("%s  SMTP error: %s", _tag("NORMAL"), exc)


def normal_local_recon():
    """Benign commands a normal user process might run (hostname, OS info)."""
    cmds = (
        [["hostname"], ["ver" if WINDOWS else "uname", "-r"]]
        if WINDOWS
        else [["hostname"], ["uname", "-r"]]
    )
    cmd = random.choice(cmds)
    log.info("%s Local info → %s", _tag("NORMAL"), " ".join(cmd))
    _, out = run_cmd(cmd)
    log.info("%s  ← %s", _tag("NORMAL"), out[:100] if out else "(empty)")


NORMAL_ACTIONS = [
    (normal_web_browse,    4),   # weight
    (normal_dns_lookup,    3),
    (normal_file_operations, 3),
    (normal_smtp_probe,    1),
    (normal_local_recon,   2),
]


def pick_normal() -> callable:
    population, weights = zip(*NORMAL_ACTIONS)
    return random.choices(population, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Attack simulation actions  (all labeled [TEST-ATTACK])
# ---------------------------------------------------------------------------

def attack_eicar_drop():
    """Write the EICAR test file to disk, then delete it."""
    fname = os.path.join(tempfile.gettempdir(), "EICAR_TEST.com")
    log.warning(
        "%s Dropping EICAR test file → %s",
        _tag("TEST-ATTACK"),
        fname,
    )
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
    """Run a burst of post-compromise enumeration commands."""
    burst = random.randint(2, 4)
    log.warning(
        "%s Recon burst (%d commands) — simulating post-exploitation enum",
        _tag("TEST-ATTACK"),
        burst,
    )
    for _ in range(burst):
        cmd = random.choice(RECON_COMMANDS)
        log.warning("%s  exec: %s", _tag("TEST-ATTACK"), " ".join(cmd))
        rc, out = run_cmd(cmd)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:80] if out else "(empty)")
        time.sleep(random.uniform(0.3, 1.0))


def attack_powershell_encoded():
    """Execute a clearly labeled encoded PowerShell command (Windows only)."""
    if not WINDOWS:
        log.warning(
            "%s Skipping PowerShell encoded cmd (not Windows)", _tag("TEST-ATTACK")
        )
        return
    payload = '[System.Console]::WriteLine("[TEST-ATTACK] SentinelOne encoded PS test")'
    encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
    log.warning(
        "%s PowerShell encoded command — base64 payload exec test",
        _tag("TEST-ATTACK"),
    )
    rc, out = run_cmd(
        ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded],
        timeout=15,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_powershell_download_cradle():
    """Simulate a PowerShell download cradle to a safe echo endpoint (Windows only)."""
    if not WINDOWS:
        log.warning(
            "%s Skipping PS download cradle (not Windows)", _tag("TEST-ATTACK")
        )
        return
    url = "https://httpbin.org/get"  # safe, public echo service
    script = f'(New-Object Net.WebClient).DownloadString("{url}") | Out-Null; Write-Output "[TEST-ATTACK] cradle complete"'
    log.warning(
        "%s PowerShell download cradle → %s", _tag("TEST-ATTACK"), url
    )
    rc, out = run_cmd(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=20,
    )
    log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out[:120])


def attack_port_scan_localhost():
    """Scan a small range of localhost ports — simulates internal network recon."""
    ports = random.sample(range(1, 1025), 20)
    log.warning(
        "%s Port scan — localhost:%s", _tag("TEST-ATTACK"), sorted(ports)
    )
    open_ports = []
    for port in sorted(ports):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            open_ports.append(port)
        s.close()
    log.warning(
        "%s  scan done — open ports: %s", _tag("TEST-ATTACK"), open_ports or "none"
    )


def attack_credential_file_access():
    """Attempt to read well-known credential/config paths — simulates cred harvesting."""
    targets = []
    if WINDOWS:
        targets = [
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Users\Default\NTUSER.DAT",
            os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles"),
            os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
        ]
    else:
        targets = [
            "/etc/shadow",
            "/etc/sudoers",
            os.path.expanduser("~/.ssh/id_rsa"),
            os.path.expanduser("~/.bash_history"),
            "/var/log/auth.log",
        ]

    sample = random.sample(targets, min(3, len(targets)))
    log.warning(
        "%s Credential file access attempt — simulating harvesting",
        _tag("TEST-ATTACK"),
    )
    for path in sample:
        log.warning("%s  stat: %s", _tag("TEST-ATTACK"), path)
        try:
            exists = os.path.exists(path)
            log.warning(
                "%s    → %s", _tag("TEST-ATTACK"), "EXISTS" if exists else "not found"
            )
        except Exception as exc:
            log.warning("%s    → error: %s", _tag("TEST-ATTACK"), exc)


def attack_suspicious_network_connection():
    """Attempt a connection to a port commonly used by C2 frameworks."""
    c2_like_ports = [4444, 8080, 1337, 31337, 6666]
    port = random.choice(c2_like_ports)
    host = "127.0.0.1"
    log.warning(
        "%s Suspicious outbound connection — %s:%d (C2-like port)",
        _tag("TEST-ATTACK"),
        host,
        port,
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    rc = s.connect_ex((host, port))
    s.close()
    log.warning(
        "%s  connect result: %s",
        _tag("TEST-ATTACK"),
        "open" if rc == 0 else f"refused/filtered (rc={rc})",
    )


def attack_script_in_temp():
    """Write and execute a script from %TEMP% — common malware staging behavior."""
    tmpdir = tempfile.gettempdir()
    if WINDOWS:
        fname = os.path.join(tmpdir, "test_payload.bat")
        content = '@echo [TEST-ATTACK] Script-in-temp execution test\r\n@echo This is a SentinelOne test simulation\r\n'
        runner = ["cmd.exe", "/c", fname]
    else:
        fname = os.path.join(tmpdir, "test_payload.sh")
        content = '#!/bin/sh\necho "[TEST-ATTACK] Script-in-temp execution test"\necho "SentinelOne simulation"\n'
        runner = ["sh", fname]

    log.warning(
        "%s Script-in-temp — write+exec %s", _tag("TEST-ATTACK"), fname
    )
    try:
        with open(fname, "w") as f:
            f.write(content)
        if not WINDOWS:
            os.chmod(fname, 0o755)
        rc, out = run_cmd(runner, timeout=10)
        log.warning("%s  rc=%d  out=%s", _tag("TEST-ATTACK"), rc, out)
        os.remove(fname)
    except Exception as exc:
        log.debug("%s  error: %s", _tag("TEST-ATTACK"), exc)


ATTACK_ACTIONS = [
    attack_eicar_drop,
    attack_recon_commands,
    attack_powershell_encoded,
    attack_powershell_download_cradle,
    attack_port_scan_localhost,
    attack_credential_file_access,
    attack_suspicious_network_connection,
    attack_script_in_temp,
]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def jitter(seconds: float, pct: float = 0.3) -> float:
    """Return `seconds` with ±pct random jitter."""
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
    log.info("  Normal interval : %.0fs  Attack interval : %.0fs", normal_interval, attack_interval)
    log.info("  Attack probability per attack window : %.0f%%", attack_probability * 100)
    log.info("  OS : %s", platform.platform())
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
        description="Endpoint traffic simulator for SentinelOne agent testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default: normal traffic every 30s, attack window every 5 min, 40% attack rate
  python traffic_generator.py

  # Aggressive testing: normal every 15s, attack every 2 min, always attack
  python traffic_generator.py --normal-interval 15 --attack-interval 120 --attack-prob 1.0

  # Quiet normal traffic only, no attacks
  python traffic_generator.py --attack-prob 0

  # Run for 1 hour then stop
  python traffic_generator.py --runtime 3600
""",
    )
    parser.add_argument(
        "--normal-interval",
        type=float,
        default=30.0,
        metavar="SEC",
        help="Seconds between normal traffic events (default: 30)",
    )
    parser.add_argument(
        "--attack-interval",
        type=float,
        default=300.0,
        metavar="SEC",
        help="Seconds between attack simulation windows (default: 300)",
    )
    parser.add_argument(
        "--attack-prob",
        type=float,
        default=0.4,
        metavar="0-1",
        help="Probability [0–1] of an attack firing each window (default: 0.4)",
    )
    parser.add_argument(
        "--runtime",
        type=float,
        default=None,
        metavar="SEC",
        help="Total seconds to run before exiting (default: run forever)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show DEBUG-level output",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="Also write logs to this file",
    )

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
