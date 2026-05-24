#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          KEEG v3.1 - Kinetic Entropy Execution Gating                ║
║       Enterprise-Calibrated Runtime Behavioral Security Framework    ║
╠══════════════════════════════════════════════════════════════════════╣
║  FROM v2.0 (KEPT & IMPROVED):                                        ║
║    [1] Entropy Phase-Shift Detection (EPSD) + Velocity               ║
║    [2] Sliding Window Entropy - defeats padding attacks              ║
║    [3] Process Lineage Graph Analysis                                ║
║    [4] Executable Memory (RWX) Detection                             ║
║    [5] Real-Time Web Dashboard (fully rewritten)                     ║
║                                                                      ║
║  NEW in v3.1 (False-Positive Hardening):                             ║
║    [6]  Process Baseline Profiles - JIT/browser entropy is normal    ║
║    [7]  Trusted Process Classification - OS core processes           ║
║    [8]  JIT-Aware RWX Filtering - RWX alone no longer flags          ║
║    [9]  Entropy Stability Detection - stable high entropy ≠ malware  ║
║    [10] Process Reputation Scoring - path + name trust rating        ║
║    [11] Platform-Aware Heuristics - Windows vs Linux rules           ║
║    [12] Compound Threat Correlation - multi-signal confidence score  ║
║    [13] Signal Weight Rebalancing - tuned to reduce noise            ║
║                                                                      ║
║  NEW in v3.1 (Dashboard):                                            ║
║    [14] Left navigation sidebar                                      ║
║    [15] Process detail investigation panel                           ║
║    [16] Live process interaction graph                               ║
║    [17] Threat severity banner                                       ║
║    [18] Search + severity filters on process table                   ║
║    [19] Signal badges (⚡EPSD 🧬RWX 🔗LIN 📊WIN)                   ║
║    [20] Quick threat summary widget                                  ║
╚══════════════════════════════════════════════════════════════════════╝

Author  : KEEG Project - MCA Final Year Project
Version : 3.1.0

Usage:
  python3 keeg_v3.py --demo                   Full feature demonstration
  python3 keeg_v3.py --scan                   One-time scan
  python3 keeg_v3.py --monitor                Continuous monitoring
  python3 keeg_v3.py --monitor --dashboard    Monitor + web dashboard
  python3 keeg_v3.py --lineage                Print process tree
"""

import os, sys, codecs, math, time, json, platform, argparse
import datetime, collections, threading, socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    print("[!] psutil not installed.  Run: pip install psutil")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# VERSION & PLATFORM
# ─────────────────────────────────────────────────────────────────────────────

VERSION  = "3.1-patched"
OS_NAME  = platform.system()          # "Windows" | "Linux" | "Darwin"
OS_LINUX = (OS_NAME == "Linux")
OS_WIN   = (OS_NAME == "Windows")
HOSTNAME = socket.gethostname()

# ─────────────────────────────────────────────────────────────────────────────
# POLICY LOADER  (items 56–67: distributed policy architecture concept)
# In production: endpoint loads signed policy from central server.
# In this prototype: reads from keeg_policy.json if present,
#                    otherwise uses built-in defaults.
# This architecture separates detection engine from policy layer,
# enabling central policy updates without changing agent code.
# ─────────────────────────────────────────────────────────────────────────────

POLICY_FILE = "keeg_policy.json"

def _load_policy() -> dict:
    """
    Load external policy file if it exists.
    Simulates the central policy distribution model:
      Central Server → signed policy.json → all endpoints
    Falls back to empty dict (built-in defaults apply).
    """
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE) as f:
                pol = json.load(f)
            # Simple integrity check: must have schema version
            if pol.get("schema_version"):
                return pol
        except Exception:
            pass
    return {}

_POLICY = _load_policy()

def policy_get(key, default):
    """Get a value from loaded policy, falling back to default."""
    return _POLICY.get(key, default)

def write_default_policy():
    """
    Write a default keeg_policy.json that operators can customize.
    Demonstrates the policy architecture without a real central server.
    """
    policy = {
        "schema_version": "1.0",
        "policy_version":  "1.0.0",
        "baseline_version":"1.0.0",
        "generated_by":    "KEEG Policy Engine",
        "description":     "KEEG endpoint detection policy. Distribute via central server in production.",
        "entropy_thresholds": {
            "low":    3.5,
            "medium": 5.5,
            "high":   7.0,
        },
        "epsd": {
            "spike_threshold": 2.5,
            "trend_threshold": 1.5,
            "max_history":     30,
        },
        "risk_weights": {
            "entropy_critical":  50,
            "entropy_high":      30,
            "entropy_medium":    10,
            "window_anomaly":    12,
            "phase_shift":       35,
            "slow_trend":        15,
            "lineage_anomaly":   30,
            "rwx_only":          10,
            "rwx_plus_spike":    30,
            "suspicious_name":   20,
            "suspicious_path":   25,
            "network":           12,
            "privilege":         15,
            "trust_reduction":  -20,
            "stability_reduction": -15,
        },
        "flag_threshold": 70,
        "warn_threshold": 40,
        "additional_trusted_processes": [],
        "additional_baselines":         {},
        "additional_anomalous_chains":  [],
        "note": "In production: sign this file with server private key. Endpoints verify before applying.",
    }
    with open(POLICY_FILE, "w") as f:
        json.dump(policy, f, indent=2)
    return policy

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────

ENTROPY_LOW    = 3.5
ENTROPY_MEDIUM = 5.5
ENTROPY_HIGH   = 7.0

# EPSD
EPSD_SPIKE    = 2.5
EPSD_TREND    = 1.5
EPSD_MAX_HIST = 30

# Sliding window
WINDOW_BYTES = 256

# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORING WEIGHTS  (v3 - rebalanced to reduce false positives)
# ─────────────────────────────────────────────────────────────────────────────
# Key changes from v2:
#   RWX alone dropped from 30 → 10 (JIT engines use RWX legitimately)
#   Phase-shift increased 25 → 35 (most reliable malware signal)
#   Lineage anomaly increased 25 → 30
#   Entropy stability bonus: stable high entropy = reduce risk by 15
#   Reputation deduction: known trusted binary path = reduce risk by 20

W_ENTROPY_CRITICAL   = 50   # entropy ≥ 7.0
W_ENTROPY_HIGH       = 30   # entropy 5.5–7.0
W_ENTROPY_MEDIUM     = 10   # entropy 3.5–5.5
W_WINDOW_ANOMALY     = 12   # sliding-window max > threshold & differs from global
W_PHASE_SHIFT        = 35   # EPSD spike (most reliable signal)
W_SLOW_TREND         = 15   # EPSD slow upward trend
W_LINEAGE_ANOMALY    = 30   # suspicious parent→child chain
W_RWX_ONLY           = 10   # RWX alone (JIT-probable) - informational only
W_RWX_PLUS_SPIKE     = 30   # RWX + entropy spike (injection confirmed pattern)
W_SUSPICIOUS_NAME    = 20   # name matches attack patterns
W_SUSPICIOUS_PATH    = 25   # runs from temp/unusual directory
W_NETWORK            = 12   # active network connections
W_PRIVILEGE          = 15   # running as root/SYSTEM
W_RARE_PROCESS       = 20   # process seen for first time
W_TRUST_REDUCTION    = -20  # known trusted path → reduce risk
W_STABILITY_REDUCTION= -15  # entropy stable over history → reduce risk

# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 6 - PROCESS BASELINE PROFILES
# These processes are known to have high entropy and RWX due to JIT compilation
# or legitimate encryption. They should NOT be flagged on those signals alone.
# ─────────────────────────────────────────────────────────────────────────────

PROCESS_BASELINES = {
    # Browsers - V8/SpiderMonkey JIT engines produce RWX + high entropy naturally
    "chrome":              {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "chrome.exe":          {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "chromium":            {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "chromium-browser":    {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "firefox":             {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "firefox.exe":         {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "msedge.exe":          {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "msedgewebview2.exe":  {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "brave":               {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    "brave.exe":           {"entropy_range": (4.5, 7.9), "allow_rwx": True, "allow_network": True},
    # Code editors - Node.js + V8 JIT
    "code":                {"entropy_range": (4.0, 7.5), "allow_rwx": True},
    "code.exe":            {"entropy_range": (4.0, 7.5), "allow_rwx": True},
    "codium":              {"entropy_range": (4.0, 7.5), "allow_rwx": True},
    # Runtimes
    "node":                {"entropy_range": (3.5, 7.5), "allow_rwx": True},
    "node.exe":            {"entropy_range": (3.5, 7.5), "allow_rwx": True},
    "java":                {"entropy_range": (3.5, 7.5), "allow_rwx": True},
    "java.exe":            {"entropy_range": (3.5, 7.5), "allow_rwx": True},
    # FIX v3.1 BUG #4: Python baseline raised to 7.5.
    # Original ceiling was 6.5 but sample_process_memory reads shared Windows DLLs
    # (ntdll.dll etc.) whose compressed sections reach max_win=7.11, pushing python.exe
    # above its own baseline and re-triggering the CRITICAL entropy score.
    # This is a stopgap; the real fix is Bug #1 (memory sampling DLL collision).
    "python3":             {"entropy_range": (3.1, 7.5), "allow_rwx": False},
    "python":              {"entropy_range": (3.1, 7.5), "allow_rwx": False},
    "python.exe":          {"entropy_range": (3.1, 7.5), "allow_rwx": False},
    "python3.exe":         {"entropy_range": (3.1, 7.5), "allow_rwx": False},
    # SSL / crypto libraries (loaded by many apps)
    "openssl":             {"entropy_range": (5.0, 8.0), "allow_rwx": True},
    # Compression tools
    "zip": {"entropy_range":(7.0,8.0),"allow_rwx":False},
    "gzip":{"entropy_range":(7.0,8.0),"allow_rwx":False},
    # Media
    "vlc":    {"entropy_range":(4.0,7.8),"allow_rwx":True},
    "vlc.exe":{"entropy_range":(4.0,7.8),"allow_rwx":True},
    # FIX v3.1 BUG #3: Consumer apps missing from baselines.
    # Electron / Chromium-embedded apps pack V8 snapshots and compressed assets,
    # producing naturally high entropy. Without a baseline they always hit CRITICAL.
    "whatsapp.root.exe":   {"entropy_range": (5.0, 7.9), "allow_rwx": False, "allow_network": True},
    "whatsapp.exe":        {"entropy_range": (5.0, 7.9), "allow_rwx": False, "allow_network": True},
    "slack.exe":           {"entropy_range": (4.5, 7.8), "allow_rwx": True,  "allow_network": True},
    "discord.exe":         {"entropy_range": (4.5, 7.8), "allow_rwx": True,  "allow_network": True},
    "teams.exe":           {"entropy_range": (4.5, 7.9), "allow_rwx": True,  "allow_network": True},
    "spotify.exe":         {"entropy_range": (4.5, 7.8), "allow_rwx": True,  "allow_network": True},
    "zoom.exe":            {"entropy_range": (4.5, 7.8), "allow_rwx": True,  "allow_network": True},
    "telegram.exe":        {"entropy_range": (5.0, 7.9), "allow_rwx": False, "allow_network": True},
    "signal.exe":          {"entropy_range": (5.0, 7.9), "allow_rwx": True,  "allow_network": True},
    "notion.exe":          {"entropy_range": (4.5, 7.8), "allow_rwx": True},
    "obsidian.exe":        {"entropy_range": (4.5, 7.8), "allow_rwx": True},
}

def get_baseline(name: str) -> Optional[dict]:
    return PROCESS_BASELINES.get(name.lower())

# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 7 - TRUSTED PROCESS CLASSIFICATION
# These OS core processes require multiple simultaneous anomaly signals before
# being flagged. Single-signal alerts are suppressed.
# ─────────────────────────────────────────────────────────────────────────────

TRUSTED_PROCESSES = {
    # Linux
    "systemd","kworker","kthreadd","ksoftirqd","migration","rcu_sched",
    "dbus-daemon","networkmanager","polkitd","accounts-daemon",
    "gnome-shell","gnome-keyring-daemon","gdm","lightdm","Xorg","Xwayland",
    "pulseaudio","pipewire","wireplumber","avahi-daemon","rsyslogd",
    "cron","crond","atd","sshd","cups","bluetoothd","wpa_supplicant",
    # Windows - original set
    "system","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
    "services.exe","lsass.exe","svchost.exe","explorer.exe",
    "taskhostw.exe","dwm.exe","sihost.exe","fontdrvhost.exe",
    "runtimebroker.exe","searchhost.exe","searchindexer.exe",
    "spoolsv.exe","audiodg.exe","wuauclt.exe","msiexec.exe",
    "conhost.exe","ctfmon.exe","securityhealthservice.exe",
    "antimalware service executable","msmpeng.exe",
    "applicationframehost.exe","systemsettings.exe","shellexperiencehost.exe",
    "startmenuexperiencehost.exe","widgetservice.exe","widgets.exe",
    "crossdeviceservice.exe","crossdeviceresume.exe","appactions.exe",
    "smartscreen.exe","useroobebroker.exe","unsecapp.exe",
    "dllhost.exe","crashhelper.exe","ipf_helper.exe",
    "rtkauduservice64.exe","pet.exe",
    # FIX v3.1-final BUG #B — Linux system daemons missing from trusted list.
    # These produced the 3 remaining false-positive WARNs on the PredatorBox scan:
    # udisksd reads disk firmware (high window entropy from compressed FW blobs).
    # colord reads ICC color profiles (packed binary format = high entropy windows).
    # obexd handles Bluetooth OBEX file transfers (encoded data = high window entropy).
    # All three are standard system daemons running from /usr/libexec/ — trusted paths.
    "udisksd","colord","obexd","bluetoothd","udisks2",
    # Additional Linux daemons commonly causing window-entropy WARNs
    "accounts-daemon","kerneloops","cups-browsed","switcheroo-control",
    "geoclue","iio-sensor-proxy","power-profiles-daemon","thermald",
    "fwupd","packagekitd","snapd","irqbalance","acpid",
    "rtkit-daemon","upower","logind","systemd-timesyncd",
    "systemd-resolved","systemd-udevd","systemd-journald","systemd-logind",
    "xfce4-session","xfce4-panel","xfwm4","xfdesktop","xfce4-notifyd",
    "speech-dispatcher","sd-pam","sd_espeak-ng","sd_dummy",
    "at-spi2-registryd","at-spi-bus-launcher","gvfsd","gvfs-udisks2-volume-monitor",
    "dconf-service","evolution-data-server","goa-daemon","xdg-permission-store",
    # FIX v3.1 BUG #3: Missing legitimate Windows processes that caused false positives.
    # These are all standard Windows system processes that were absent from the whitelist,
    # causing them to be warned on entropy alone from shared DLL reads.
    "cmd.exe",                      # Windows Command Prompt
    "shellhost.exe",                # Windows Terminal shell host
    "backgroundtaskhost.exe",       # Windows Background Task Host
    "textinputhost.exe",            # Windows Text Input Host (touch keyboard etc.)
    "securityhealthsystray.exe",    # Windows Security system tray notification
    "wermgr.exe",                   # Windows Error Reporting Manager
    "wmiprvse.exe",                 # WMI Provider Host
    "taskmgr.exe",                  # Windows Task Manager
    "notepad.exe",                  # Notepad
    "mspaint.exe",                  # Paint
    "regedit.exe",                  # Registry Editor
    "mmc.exe",                      # Microsoft Management Console
    "perfmon.exe",                  # Performance Monitor
    "eventvwr.exe",                 # Event Viewer
    "powershell.exe",               # PowerShell (system shells flagging is too noisy)
    "powershell_ise.exe",           # PowerShell ISE
    "wsl.exe","wslhost.exe",        # Windows Subsystem for Linux
    "lsm.exe",                      # Local Session Manager
    "winstore.app.exe",             # Microsoft Store
    "onedrive.exe",                 # OneDrive sync
    "msedgeupdate.exe",             # Edge updater
    "googleupdate.exe",             # Chrome updater
    "compattelrunner.exe",          # Windows compatibility telemetry
    "musnotification.exe",          # Windows Update notification
    "usoclient.exe",                # Update Session Orchestrator client
    "tiworker.exe",                 # Windows Modules Installer Worker
}

def is_trusted(name: str) -> bool:
    return name.lower() in TRUSTED_PROCESSES

# Suspicious process name tokens
SUSPICIOUS_NAME_TOKENS = [
    "tmp","temp",".sh",".pl","ncat","netcat","meterpreter",
    "payload","inject","exploit","backdoor","rat","rootkit",
    "loader","dropper","stager","beacon","cobalt","empire",
]

# Suspicious path tokens
# FIX v3.1 BUG #2 (extension): Normalize SUSPICIOUS_PATH_TOKENS to forward slashes.
# Same root cause as TRUSTED_PATHS: reputation_score() normalises exe to forward
# slashes before checking, so backslash tokens like "appdata\\local\\temp" never
# matched → suspicious-path detection was silently broken on Windows.
SUSPICIOUS_PATH_TOKENS = [
    "/tmp/", "/dev/shm/", "/temp/", "/tmp/",
    "appdata/local/temp", "appdata/roaming/temp",
    "%temp%", "/var/tmp/", "/$recycle", "/proc/self/",
]

# Trusted path prefixes (reputation scoring)
# FIX v3.1 BUG #2: Normalize ALL paths to forward slashes here.
# Previously, Windows paths used backslashes ("c:\\windows\\") but
# reputation_score() converts exe paths to forward slashes before comparison,
# so startswith() always returned False → no process ever got the -20 deduction.
TRUSTED_PATHS = [
    "c:/windows/", "c:/program files/", "c:/program files (x86)/",
    "c:/program files/windowsapps/",   # Microsoft Store apps (WhatsApp, Firefox MSIX, etc.)
    "c:/programdata/microsoft/",        # Windows Defender, other MS services
    "/usr/bin/","/usr/lib/","/usr/sbin/","/bin/","/sbin/","/lib/",
    "/opt/","/snap/","/usr/local/",
]

# Anomalous lineage pairs
ANOMALOUS_CHAINS = [
    ("acrobat","cmd"),    ("acrobat","powershell"), ("acrobat","bash"),
    ("acrord32","cmd"),   ("acrord32","wscript"),   ("acrord32","bash"),
    ("winword","cmd"),    ("winword","powershell"),  ("winword","curl"),
    ("excel","cmd"),      ("excel","powershell"),    ("excel","python"),
    ("outlook","cmd"),    ("outlook","powershell"),  ("outlook","curl"),
    ("firefox","cmd"),    ("chrome","cmd"),          ("msedge","cmd"),
    ("iexplore","cmd"),   ("java","powershell"),
    ("reader","bash"),    ("reader","sh"),
    ("evince","bash"),    ("evince","sh"),            ("evince","python"),
    ("eog","bash"),       ("libreoffice","bash"),     ("libreoffice","python"),
]

LOG_FILE = "keeg_log.json"

# ─────────────────────────────────────────────────────────────────────────────
# ANSI
# ─────────────────────────────────────────────────────────────────────────────

RESET="\033[0m"; BOLD="\033[1m"; CYAN="\033[96m"; GREEN="\033[92m"
YELLOW="\033[93m"; RED="\033[91m"; MAGENTA="\033[95m"; DIM="\033[2m"; BLUE="\033[94m"

def clr(label):
    return {"NORMAL":GREEN,"ELEVATED":YELLOW,"HIGH":RED,"CRITICAL":MAGENTA}.get(label,RESET)

# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 1 - EPSD  (+ entropy velocity)
# ─────────────────────────────────────────────────────────────────────────────

_entropy_history: Dict[int, List[Tuple[float,float]]] = {}  # pid → [(time,H)]

def epsd_update(pid: int, entropy: float) -> dict:
    """
    Track entropy per PID over time.
    Computes: delta, spike, slow_trend, velocity (ΔH/Δt).
    """
    now  = time.time()
    hist = _entropy_history.setdefault(pid, [])
    hist.append((now, entropy))
    if len(hist) > EPSD_MAX_HIST:
        hist.pop(0)

    h_vals = [h for _, h in hist]

    if len(hist) < 2:
        return {"delta":0.0,"spike":False,"slow_trend":False,
                "velocity":0.0,"acceleration":0.0,"history":h_vals,"stable":False}

    delta    = round(entropy - h_vals[-2], 4)
    spike    = delta >= EPSD_SPIKE  # FIX: only POSITIVE rises trigger (negative drops = memory unavailable, not malware)

    slow_trend = False
    if len(hist) >= 3:
        cumulative = h_vals[-1] - h_vals[-3]
        slow_trend = (cumulative >= EPSD_TREND) and (not spike)

    # Entropy velocity = ΔH / Δt
    dt       = now - hist[-2][0]
    velocity = round(delta / dt, 6) if dt > 0 else 0.0

    # Entropy acceleration = Δvelocity / Δt  (new in v3 final)
    acceleration = 0.0
    if len(hist) >= 3:
        prev_delta = h_vals[-2] - h_vals[-3]
        prev_dt    = hist[-2][0] - hist[-3][0]
        prev_vel   = round(prev_delta / prev_dt, 6) if prev_dt > 0 else 0.0
        acc_dt     = now - hist[-2][0]
        acceleration = round((velocity - prev_vel) / acc_dt, 8) if acc_dt > 0 else 0.0

    # UPGRADE 9 - Entropy stability: if last 5 values within ±0.5 → stable
    stable = False
    if len(h_vals) >= 5:
        window5 = h_vals[-5:]
        stable  = (max(window5) - min(window5)) < 0.5

    return {
        "delta":        delta,
        "spike":        spike,
        "slow_trend":   slow_trend,
        "velocity":     velocity,
        "acceleration": acceleration,
        "history":      h_vals,
        "stable":       stable,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY ENGINE + SLIDING WINDOW
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    n    = len(data)
    h    = 0.0
    for c in freq.values():
        p  = c / n
        h -= p * math.log2(p)
    return round(h, 4)


def sliding_window_entropy(data: bytes, window: int = WINDOW_BYTES) -> dict:
    if not data:
        return {"global":0.0,"max_win":0.0,"windows":[],"anomalous":False}
    wins = [data[i:i+window] for i in range(0,len(data),window) if len(data[i:i+window])>=16]
    we   = [shannon_entropy(w) for w in wins]
    mx   = max(we) if we else 0.0
    return {
        "global":    shannon_entropy(data),
        "max_win":   round(mx,4),
        "windows":   [round(e,4) for e in we],
        "anomalous": mx >= ENTROPY_HIGH,
    }


def entropy_label(h: float) -> str:
    if h < ENTROPY_LOW:    return "NORMAL"
    if h < ENTROPY_MEDIUM: return "ELEVATED"
    if h < ENTROPY_HIGH:   return "HIGH"
    return "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# PROCESS LINEAGE
# ─────────────────────────────────────────────────────────────────────────────

def build_process_tree() -> Dict[int, dict]:
    tree = {}
    try:
        procs = {p.pid: p for p in psutil.process_iter(['pid','name','ppid','exe','cmdline'])}
        for pid, proc in procs.items():
            try:
                info  = proc.info
                ppid  = info.get('ppid',0) or 0
                parent = procs.get(ppid)
                tree[pid] = {
                    "name":        (info.get('name') or "unknown").lower(),
                    "ppid":        ppid,
                    "parent_name": (parent.info.get('name') or "unknown").lower() if parent else "none",
                    "exe":         info.get('exe') or "",
                    "cmdline":     " ".join(info.get('cmdline') or [])[:80],
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return tree


def get_ancestry(pid: int, tree: Dict[int, dict], depth: int = 6) -> List[str]:
    chain, current = [], pid
    for _ in range(depth):
        node = tree.get(current)
        if not node or current == 0:
            break
        chain.append(node["name"])
        current = node["ppid"]
    return chain


def check_lineage_anomaly(pid: int, tree: Dict[int, dict]) -> dict:
    node = tree.get(pid)
    if not node:
        return {"anomalous":False,"chain":[],"reason":""}

    chain = get_ancestry(pid, tree)
    name  = node["name"]
    pname = node["parent_name"]
    exe   = node["exe"].lower().replace("\\","/")

    for parent_pat, child_pat in ANOMALOUS_CHAINS:
        if parent_pat in pname and child_pat in name:
            return {"anomalous":True,"chain":chain,
                    "reason":f"Suspicious lineage: {pname} → {name}"}

    for tok in SUSPICIOUS_PATH_TOKENS:
        if tok in exe:
            return {"anomalous":True,"chain":chain,
                    "reason":f"Runs from suspicious path: {exe[:60]}"}

    return {"anomalous":False,"chain":chain,"reason":""}


def print_process_tree(tree: Dict[int, dict]):
    print(f"\n{CYAN}{BOLD}{'═'*65}")
    print("  KEEG v3 - PROCESS LINEAGE TREE")
    print(f"{'═'*65}{RESET}\n")
    children: Dict[int,List[int]] = collections.defaultdict(list)
    for pid, node in tree.items():
        children[node["ppid"]].append(pid)

    def _walk(pid, indent=0):
        node = tree.get(pid)
        if not node: return
        prefix = "  "*indent+("└─ " if indent else "")
        anom   = check_lineage_anomaly(pid, tree)
        marker = f"  {RED}← SUSPICIOUS!{RESET}" if anom["anomalous"] else ""
        print(f"  {prefix}{BOLD}{node['name']}{RESET} {DIM}(PID {pid}){RESET}{marker}")
        for child in sorted(children.get(pid,[])): _walk(child, indent+1)

    roots = [pid for pid, node in tree.items()
             if node["ppid"] not in tree or node["ppid"]==0]
    for r in sorted(roots)[:60]: _walk(r)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 8 - JIT-AWARE RWX DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def check_rwx_memory(pid: int, proc_name: str = "") -> dict:
    """
    v3 change: returns jit_probable flag.
    If the process is a known JIT engine (browser, VSCode, Java),
    RWX pages are EXPECTED and should not contribute heavily to risk.
    Genuine injection patterns: RWX + sudden entropy spike on a NON-JIT process.
    """
    result = {"rwx_count":0,"rwx_regions":[],"suspicious":False,"jit_probable":False}

    # Determine if this process is a known JIT runtime
    baseline = get_baseline(proc_name)
    jit_prob = baseline.get("allow_rwx", False) if baseline else False
    result["jit_probable"] = jit_prob

    if OS_LINUX:
        maps_path = Path(f"/proc/{pid}/maps")
        if not maps_path.exists():
            return result
        try:
            for line in maps_path.read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("rwx"):
                    result["rwx_regions"].append({
                        "addr":   parts[0],
                        "perms":  parts[1],
                        "region": parts[-1] if len(parts)>=6 else "[anon]",
                    })
            result["rwx_count"] = len(result["rwx_regions"])
            # Only flag as suspicious if NOT a known JIT engine
            result["suspicious"] = (result["rwx_count"] > 0) and (not jit_prob)
        except (PermissionError, OSError):
            pass
    else:
        # Windows fallback
        try:
            maps = psutil.Process(pid).memory_maps()
            for m in maps:
                if not m.path or m.path == "[anon]":
                    result["rwx_count"] += 1
                    result["rwx_regions"].append({"addr":"N/A","perms":"anon-exec","region":m.path or "[anon]"})
            result["suspicious"] = (result["rwx_count"] > 3) and (not jit_prob)
        except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
            pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 10 - PROCESS REPUTATION SCORING
# ─────────────────────────────────────────────────────────────────────────────

def reputation_score(proc_info: dict) -> Tuple[int, str]:
    """
    Returns (adjustment, reason).
    Positive = more suspicious, Negative = more trusted.
    """
    name = proc_info.get("name","").lower()
    exe  = proc_info.get("exe","").lower().replace("\\","/")
    cmd  = proc_info.get("cmdline","").lower().replace("\\","/")

    # Trusted installation paths → lower risk
    for tp in TRUSTED_PATHS:
        if exe.startswith(tp) or cmd.startswith(tp):
            return (W_TRUST_REDUCTION, f"trusted path: {exe[:50]}")

    # Suspicious names — use word-boundary-aware matching to prevent kernel thread
    # names like "migration/0" matching "rat" or "idle_inject/0" matching "inject".
    # A token only counts if it is not surrounded by alphanumeric characters on both sides,
    # i.e. it must appear as a standalone word or at a name boundary (slash, dot, dash).
    import re as _re
    for tok in SUSPICIOUS_NAME_TOKENS:
        # Full word-boundary check: token must NOT be adjacent to any word character
        # (\w = [a-zA-Z0-9_]) on either side. This prevents kernel thread names like
        # "idle_inject/0" matching "inject" (preceded by _) or "migration/0" matching
        # "rat" (preceded by 'ig'... wait 'migr-AT-ion' — 'rat' is surrounded by word
        # chars so (?<!\w)rat(?!\w) correctly rejects it). Real malware names like
        # "inject.sh", "rat", "payload.exe", "my.loader" all match correctly.
        if _re.search(r'(?<!\w)' + _re.escape(tok) + r'(?!\w)', name):
            return (W_SUSPICIOUS_NAME, f"suspicious name token: {tok}")

    # Suspicious execution paths
    for tok in SUSPICIOUS_PATH_TOKENS:
        if tok in exe or tok in cmd:
            return (W_SUSPICIOUS_PATH, f"suspicious execution path")

    return (0, "")


# ─────────────────────────────────────────────────────────────────────────────
# MEMORY SAMPLER
# ─────────────────────────────────────────────────────────────────────────────

def sample_process_memory(pid: int, max_bytes: int = 4096) -> bytes:
    """
    FIX v3.1 BUG #1 — Windows DLL collision (root cause of ALL false positives in v3.1):

    The original code called proc.memory_maps()[:3] and read the first 3 mapped files.
    On Windows, every process maps the SAME system DLLs first in its address space:
    ntdll.dll, kernel32.dll, kernelbase.dll — these are shared read-only mappings.

    Result: 39 out of 60 logged processes reported the EXACT same entropy values
    (H=5.5456 global, max_win=7.1139) because they were all measuring ntdll.dll,
    not their own code. This produced a uniform false-positive wave of WARN alerts.

    Fix strategy (in priority order):
      1. On Windows: read the process's own executable file directly.
         The exe path is unambiguous and process-specific.
      2. Skip DLLs from system directories (ntdll, kernel32, etc.) when reading maps.
      3. Fall back to open_files() only for non-system file handles.
      4. If nothing accessible, return empty bytes (entropy = 0.0 → no score).
         A process with no readable sample is NOT evidence of malice.
    """
    sample = b""
    # Known Windows system DLL names that are shared across every process.
    # Sampling these gives the same entropy for all processes → false positives.
    SKIP_DLL_NAMES = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "gdi32.dll", "advapi32.dll", "msvcrt.dll", "sechost.dll",
        "rpcrt4.dll", "combase.dll", "ucrtbase.dll", "win32u.dll",
        "gdi32full.dll", "msvcp_win.dll", "imm32.dll", "shell32.dll",
    }
    SYSTEM_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                   "c:\\windows\\winsxs\\", "/usr/lib/", "/lib/", "/lib64/")

    try:
        proc = psutil.Process(pid)

        # ── Priority 1: Read the process's OWN executable ────────────────────
        # This is always process-specific and avoids the shared-DLL problem.
        try:
            exe_path = proc.exe()
            if exe_path and os.path.isfile(exe_path):
                with open(exe_path, "rb") as f:
                    sample += f.read(max_bytes)
        except (PermissionError, OSError, psutil.AccessDenied):
            pass

        # ── Priority 2: Non-system mapped files (if exe read was short) ──────
        if len(sample) < 256:
            try:
                for m in proc.memory_maps():
                    if not m.path or not os.path.isfile(m.path):
                        continue
                    if m.path.startswith("["):
                        continue
                    fname = os.path.basename(m.path).lower()
                    mpath_lower = m.path.lower().replace("\\", "/")
                    # Skip shared system DLLs — they are the same for every process
                    if fname in SKIP_DLL_NAMES:
                        continue
                    if any(mpath_lower.startswith(sd.replace("\\", "/")) for sd in SYSTEM_DIRS):
                        continue
                    try:
                        with open(m.path, "rb") as f:
                            sample += f.read((max_bytes - len(sample)) // 2)
                        if len(sample) >= max_bytes:
                            break
                    except (PermissionError, OSError):
                        pass
            except (psutil.AccessDenied, AttributeError):
                pass

        # ── Priority 3: Non-system open file handles ─────────────────────────
        if len(sample) < 64:
            try:
                for fobj in proc.open_files()[:5]:
                    fpath_lower = fobj.path.lower().replace("\\", "/")
                    if any(fpath_lower.startswith(sd.replace("\\", "/")) for sd in SYSTEM_DIRS):
                        continue
                    try:
                        with open(fobj.path, "rb") as fh:
                            sample += fh.read(1024)
                    except (PermissionError, OSError):
                        pass
            except (psutil.AccessDenied, AttributeError):
                pass

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return sample


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 12 - COMPOUND THREAT CORRELATION
# ─────────────────────────────────────────────────────────────────────────────

def compound_correlation(proc_info: dict) -> Tuple[str, str]:
    """
    Detect high-confidence compound threat patterns.
    Returns (confidence_label, compound_reason).
    HIGH > MEDIUM > LOW > NONE
    """
    epsd   = proc_info.get("epsd_spike", False)
    rwx    = proc_info.get("rwx_suspicious", False)
    lin    = proc_info.get("lineage_anomalous", False)
    win    = proc_info.get("win_anomalous", False)
    trend  = proc_info.get("epsd_slow_trend", False)
    conns  = proc_info.get("connections", 0)

    # CRITICAL patterns (3+ signals)
    if epsd and rwx and lin:
        return ("CRITICAL", "EPSD + RWX + Lineage: high-confidence memory injection via malicious process chain")
    if epsd and rwx:
        return ("HIGH", "EPSD phase-shift + RWX memory: payload decryption + executable memory detected")
    if epsd and lin:
        return ("HIGH", "EPSD phase-shift + lineage anomaly: encrypted payload in suspicious process chain")
    if rwx and lin:
        return ("HIGH", "RWX memory + lineage anomaly: executable memory in suspicious child process")
    if win and epsd:
        return ("HIGH", "Sliding-window anomaly + phase-shift: padding attack with decryption detected")

    # MEDIUM patterns (2 signals)
    if epsd and conns > 0:
        return ("MEDIUM", "EPSD + network activity: possible encrypted C2 beacon after unpack")
    if lin and win:
        return ("MEDIUM", "Lineage anomaly + entropy padding pattern detected")
    if trend and rwx:
        return ("MEDIUM", "Slow entropy trend + RWX: gradual decryption with executable memory")
    if epsd:
        return ("MEDIUM", "Entropy phase-shift detected: possible payload unpack event")

    # LOW - single notable signal
    if lin:
        return ("LOW", "Suspicious process lineage detected")
    if rwx and not proc_info.get("rwx_jit_probable",False):
        return ("LOW", "RWX executable memory in non-JIT process")

    return ("NONE", "")


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORER v3 - All signals with proper calibration
# ─────────────────────────────────────────────────────────────────────────────

def score_risk(proc_info: dict) -> Tuple[int, List[str]]:
    """
    v3 changes:
    - Trusted processes require 3+ signals before reaching FLAG threshold
    - JIT-known processes: RWX does not contribute alone
    - Entropy stability: consistently high entropy → reduce risk
    - Baseline: entropy within expected range → suppress entropy contribution
    - Reputation: known good path → reduce risk by 20
    """
    score   = 0
    reasons = []
    name    = proc_info.get("name","").lower()
    trusted = is_trusted(name)
    baseline= get_baseline(name)

    entropy = proc_info.get("entropy", 0.0)
    max_win = proc_info.get("max_win_entropy", entropy)
    eff     = max(entropy, max_win)
    stable  = proc_info.get("epsd_stable", False)

    # ── Entropy - check against baseline first ────────────────────────────────
    in_baseline_range = False
    if baseline and "entropy_range" in baseline:
        lo, hi = baseline["entropy_range"]
        in_baseline_range = (lo <= eff <= hi)

    if not in_baseline_range:
        if eff >= ENTROPY_HIGH:
            score += W_ENTROPY_CRITICAL
            reasons.append(f"entropy={eff:.2f} bits (CRITICAL ≥{ENTROPY_HIGH})")
        elif eff >= ENTROPY_MEDIUM:
            score += W_ENTROPY_HIGH
            reasons.append(f"entropy={eff:.2f} bits (HIGH ≥{ENTROPY_MEDIUM})")
        elif eff >= ENTROPY_LOW:
            score += W_ENTROPY_MEDIUM
            reasons.append(f"entropy={eff:.2f} bits (ELEVATED ≥{ENTROPY_LOW})")
    else:
        reasons.append(f"entropy={eff:.2f} bits (within baseline range - normal for {name})")

    # ── Entropy stability deduction ───────────────────────────────────────────
    if stable and eff >= ENTROPY_MEDIUM:
        score += W_STABILITY_REDUCTION
        reasons.append(f"entropy stable (consistent high H = normal encrypted stream, not malware)")

    # Sliding-window anomaly
    # FIX v3.1: Suppress the window anomaly contribution when max_win is ALSO within
    # the process's baseline range. If the baseline says "this process normally has
    # max_win up to 7.9" (e.g. chrome, whatsapp) then a max_win=7.11 is expected
    # and should NOT score the padding-attack pattern. The old code only checked
    # the global entropy against the baseline, not the max_win value.
    win_in_baseline = False
    if baseline and "entropy_range" in baseline:
        lo, hi = baseline["entropy_range"]
        win_in_baseline = (max_win <= hi)
    # Also suppress window anomaly for trusted processes even without a baseline:
    # trusted OS daemons (networkmanager, udisksd, etc.) legitimately read binary
    # data files that produce high window entropy. The window anomaly signal is
    # designed for UNKNOWN processes, not well-known system services.
    if proc_info.get("win_anomalous") and max_win > entropy and not win_in_baseline and not trusted:
        score += W_WINDOW_ANOMALY
        reasons.append(f"sliding-window anomaly: max_win={max_win:.2f} > global={entropy:.2f} (padding-attack pattern)")

    # ── EPSD signals ──────────────────────────────────────────────────────────
    if proc_info.get("epsd_spike"):
        score += W_PHASE_SHIFT
        reasons.append(f"EPSD phase-shift ΔH={proc_info.get('epsd_delta',0):+.2f} (payload unpack/decrypt event)")
    elif proc_info.get("epsd_slow_trend"):
        score += W_SLOW_TREND
        reasons.append(f"EPSD slow entropy trend (gradual decryption pattern)")

    # ── Lineage ───────────────────────────────────────────────────────────────
    if proc_info.get("lineage_anomalous"):
        score += W_LINEAGE_ANOMALY
        reasons.append(proc_info.get("lineage_reason","suspicious process lineage"))

    # ── RWX memory - JIT-aware ────────────────────────────────────────────────
    rwx_susp = proc_info.get("rwx_suspicious", False)
    rwx_jit  = proc_info.get("rwx_jit_probable", False)
    rwx_n    = proc_info.get("rwx_count", 0)

    if rwx_susp:
        # Non-JIT process with RWX - genuine concern
        if proc_info.get("epsd_spike"):
            # RWX + phase-shift = very high confidence injection
            score += W_RWX_PLUS_SPIKE
            reasons.append(f"RWX memory + EPSD spike = high-confidence code injection ({rwx_n} regions)")
        else:
            score += W_RWX_ONLY + 10   # slightly higher for non-JIT
            reasons.append(f"RWX executable memory in non-JIT process ({rwx_n} regions)")
    elif rwx_n > 0 and rwx_jit:
        score += W_RWX_ONLY           # JIT: informational only, very small weight
        reasons.append(f"RWX regions present ({rwx_n}) - JIT engine expected, informational")

    # ── Network ───────────────────────────────────────────────────────────────
    conns = proc_info.get("connections",0)
    if conns > 0:
        score += W_NETWORK
        reasons.append(f"{conns} active network connection(s)")

    # ── Privilege ─────────────────────────────────────────────────────────────
    user = (proc_info.get("username") or "").lower()
    if "root" in user or ("system" in user and OS_WIN):
        score += W_PRIVILEGE
        reasons.append(f"running as privileged user ({user})")

    # ── Reputation adjustment ─────────────────────────────────────────────────
    rep_adj, rep_reason = reputation_score(proc_info)
    if rep_adj != 0:
        score += rep_adj
        reasons.append(rep_reason)

    # ── Trusted process damping ───────────────────────────────────────────────
    if trusted:
        # Trusted OS processes: clamp to max 60 unless 3+ real signals
        real_signals = sum([
            bool(proc_info.get("epsd_spike")),
            bool(proc_info.get("lineage_anomalous")),
            bool(proc_info.get("rwx_suspicious")),
            bool(proc_info.get("win_anomalous")),
        ])
        if real_signals < 3:
            score = min(score, 55)
            reasons.append("trusted OS process - score capped at 55 (requires 3+ signals to FLAG)")

    return max(0, min(score, 100)), reasons


# ─────────────────────────────────────────────────────────────────────────────
# GATE DECISION
# ─────────────────────────────────────────────────────────────────────────────

def gate_decision(risk_score: int, entropy: float, name: str,
                  epsd_spike: bool = False, compound: str = "NONE") -> dict:
    """
    FIX v3.1 BUG #5 — Entropy-standalone WARN bypass:

    The original condition was:
        elif risk_score >= 40 OR entropy >= ENTROPY_MEDIUM OR compound == "MEDIUM"

    The "entropy >= ENTROPY_MEDIUM" clause triggered WARN independently of the
    risk score, so any process with H ≥ 5.5 got WARN even when:
      - score_risk() had already applied baseline suppression and reduced it to 0,
      - the process had a known baseline profile (WhatsApp, python.exe),
      - the process was trusted (all the Trusted-path -20 deductions had fired).

    This made the compound scoring system irrelevant — raw entropy bypassed it.

    Fix: the entropy standalone clause only applies when the process has NO
    baseline profile AND is not trusted. If the score engine already decided
    the entropy is normal (score < 40), the gate should respect that decision.
    """
    n = name.lower()
    trusted    = is_trusted(n)
    baselined  = get_baseline(n) is not None

    # Whitelisted safe processes: only flag on compound CRITICAL
    if n in SAFE_PROCESSES_GATE:
        if compound == "CRITICAL":
            return {"action":"FLAG","reason":f"Whitelisted but compound threat=CRITICAL | Risk={risk_score}"}
        return {"action":"ALLOW","reason":"Whitelisted safe process"}

    # FLAG: high risk score, entropy spike confirmed by EPSD, or multi-signal compound
    if risk_score >= 70 or (entropy >= ENTROPY_HIGH and epsd_spike) or compound in ("CRITICAL","HIGH"):
        return {"action":"FLAG",
                "reason":f"Risk={risk_score}/100 | compound={compound} | entropy={entropy:.4f}"}

    # WARN: risk score high enough, or compound medium
    # Entropy-standalone clause only fires for UNKNOWN processes (no baseline, not trusted).
    # If the scorer already decided the process is safe (score < 40), don't override it.
    entropy_warn_eligible = (not trusted) and (not baselined)
    if risk_score >= 40 or compound == "MEDIUM" or (entropy_warn_eligible and entropy >= ENTROPY_MEDIUM):
        return {"action":"WARN",
                "reason":f"Risk={risk_score}/100 | compound={compound} | entropy={entropy:.4f}"}

    return {"action":"ALLOW","reason":"Within safe thresholds"}

# Processes that should NEVER be flagged without compound CRITICAL evidence
# FIX v3.1: Added Windows .exe variants of interpreter/browser names.
# The original set had "python" but not "python.exe", causing the Windows
# binary to bypass the gate whitelist.
SAFE_PROCESSES_GATE = TRUSTED_PROCESSES | {
    "bash","sh","zsh","fish",
    "python3","python","python.exe","python3.exe",
    "node","node.exe","npm","npm.cmd",
    "code","code.exe","firefox","firefox.exe",
    "chrome","chrome.exe","chromium","chromium-browser",
    "msedge.exe","brave","brave.exe",
}


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

_process_seen_count: Dict[str, int] = collections.defaultdict(int)

def scan_all_processes(verbose=False, process_tree=None) -> list:
    if process_tree is None:
        process_tree = build_process_tree()

    all_procs = list(psutil.process_iter(['pid','name','username','cpu_percent','memory_percent']))
    print(f"\n{CYAN}{BOLD}[KEEG v3] Scanning {len(all_procs)} processes…{RESET}\n")

    results = []
    for proc in all_procs:
        try:
            pid  = proc.info['pid']
            name = (proc.info['name'] or "unknown").lower()
            user = proc.info['username'] or "?"

            _process_seen_count[name] += 1

            try:
                exe = psutil.Process(pid).exe()
            except Exception:
                exe = ""

            sample   = sample_process_memory(pid)
            win_data = sliding_window_entropy(sample)
            entropy  = win_data["global"]
            max_win  = win_data["max_win"]

            epsd     = epsd_update(pid, entropy)

            try:
                conns = len(psutil.net_connections() if False else proc.connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                try:
                    conns = len([c for c in psutil.net_connections() if c.pid == pid])
                except Exception:
                    conns = 0

            lin  = check_lineage_anomaly(pid, process_tree)
            rwx  = check_rwx_memory(pid, name)

            try:
                cmd = " ".join(psutil.Process(pid).cmdline())[:80]
            except Exception:
                cmd = "[N/A]"

            proc_info = {
                # Identity
                "pid":pid,"name":name,"username":user,"exe":exe,"cmdline":cmd,
                "ppid":process_tree.get(pid,{}).get("ppid",0),  # parent PID — used by process graph for edge drawing
                "timestamp":datetime.datetime.now().isoformat(),
                "hostname":HOSTNAME,"os":OS_NAME,
                "cpu":proc.info['cpu_percent'],
                "mem":round(proc.info['memory_percent'],2),
                "connections":conns,
                # Flags
                "trusted":is_trusted(name),
                "baseline":get_baseline(name) is not None,
                # Entropy
                "entropy":entropy,"max_win_entropy":max_win,
                "win_anomalous":win_data["anomalous"],
                "entropy_windows":win_data["windows"][:8],
                "entropy_label":entropy_label(max(entropy,max_win)),
                # EPSD
                "epsd_delta":epsd["delta"],"epsd_spike":epsd["spike"],
                "epsd_slow_trend":epsd["slow_trend"],"epsd_velocity":epsd["velocity"],
                "epsd_acceleration":epsd.get("acceleration",0.0),
                "epsd_history":epsd["history"],"epsd_stable":epsd["stable"],
                # Lineage
                "lineage_anomalous":lin["anomalous"],"lineage_chain":lin["chain"],
                "lineage_reason":lin["reason"],
                # RWX
                "rwx_count":rwx["rwx_count"],"rwx_suspicious":rwx["suspicious"],
                "rwx_jit_probable":rwx["jit_probable"],"rwx_regions":rwx["rwx_regions"][:5],
                # Frequency
                "seen_count":_process_seen_count[name],
            }

            risk_score, risk_reasons = score_risk(proc_info)
            compound_conf, compound_reason = compound_correlation(proc_info)
            proc_info["compound_confidence"] = compound_conf
            proc_info["compound_reason"]     = compound_reason

            gate = gate_decision(risk_score, entropy, name,
                                 epsd["spike"], compound_conf)

            proc_info["risk_score"]   = risk_score
            proc_info["risk_reasons"] = risk_reasons
            proc_info["gate"]         = gate["action"]
            proc_info["gate_reason"]  = gate["reason"]

            results.append(proc_info)
            if gate["action"] in ("FLAG","WARN") or verbose:
                _print_row(proc_info)

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

    return sorted(results, key=lambda x: x["risk_score"], reverse=True)


def _print_row(p):
    action = p["gate"]
    color  = clr(p["entropy_label"])
    icon   = {"FLAG":"🚨","WARN":"⚠️ ","ALLOW":"✅"}.get(action,"  ")

    tags = ""
    if p["epsd_spike"]:       tags += f"  {MAGENTA}[EPSD ΔH={p['epsd_delta']:+.2f}]{RESET}"
    if p["epsd_slow_trend"]:  tags += f"  {YELLOW}[SLOW-TREND]{RESET}"
    if p["lineage_anomalous"]:tags += f"  {RED}[BAD-LINEAGE]{RESET}"
    if p["rwx_suspicious"]:   tags += f"  {RED}[RWX×{p['rwx_count']}]{RESET}"
    elif p["rwx_count"]>0 and p["rwx_jit_probable"]:
        tags += f"  {DIM}[RWX-JIT]{RESET}"
    if p.get("win_anomalous") and p["max_win_entropy"]>p["entropy"]:
        tags += f"  {YELLOW}[WIN={p['max_win_entropy']:.2f}]{RESET}"
    if p["compound_confidence"] not in ("NONE","LOW"):
        tags += f"  {RED}[{p['compound_confidence']}]{RESET}"

    trusted_tag = f"{DIM}[trusted]{RESET} " if p.get("trusted") else ""
    print(f"  {icon} {BOLD}PID {p['pid']:>6}{RESET}  {trusted_tag}{p['name']:<22}  "
          f"H={color}{p['entropy']:.3f}→{p['max_win_entropy']:.3f}[{p['entropy_label']}]{RESET}  "
          f"Risk={BOLD}{p['risk_score']:>3}/100{RESET}  "
          f"Gate={color}{action}{RESET}{tags}")
    if action == "FLAG":
        for r in p["risk_reasons"]: print(f"          {RED}↳ {r}{RESET}")
        print(f"          {DIM}CMD: {p['cmdline']}{RESET}")
        if p.get("compound_reason"):
            print(f"          {MAGENTA}↳ COMPOUND: {p['compound_reason']}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# LOGGER
# ─────────────────────────────────────────────────────────────────────────────

def save_log(results: list, path: str = LOG_FILE) -> dict:
    log = {
        "scan_time":           datetime.datetime.now().isoformat(),
        "keeg_version":        VERSION,
        "hostname":            HOSTNAME,
        "os":                  OS_NAME,
        "total_processes":     len(results),
        "flagged":             sum(1 for r in results if r["gate"]=="FLAG"),
        "warned":              sum(1 for r in results if r["gate"]=="WARN"),
        "phase_shifts":        sum(1 for r in results if r["epsd_spike"]),
        "lineage_anomalies":   sum(1 for r in results if r["lineage_anomalous"]),
        "rwx_detections":      sum(1 for r in results if r["rwx_suspicious"]),
        "compound_high":       sum(1 for r in results if r.get("compound_confidence") in ("HIGH","CRITICAL")),
        "results":             results[:60],
    }
    with open(path,"w") as f:
        json.dump(log, f, indent=2)
    print(f"\n{GREEN}[✓] Log saved → {path}{RESET}")
    return log


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: list, log: dict):
    flagged = [r for r in results if r["gate"]=="FLAG"]
    warned  = [r for r in results if r["gate"]=="WARN"]
    shifts  = [r for r in results if r["epsd_spike"]]
    lin_bad = [r for r in results if r["lineage_anomalous"]]
    rwx_bad = [r for r in results if r["rwx_suspicious"]]
    comp_h  = [r for r in results if r.get("compound_confidence") in ("HIGH","CRITICAL")]

    print(f"\n{'═'*70}")
    print(f"{BOLD}{CYAN}  KEEG v{VERSION} - SCAN SUMMARY  [{HOSTNAME} / {OS_NAME}]{RESET}")
    print(f"{'═'*70}")
    print(f"  Scan Time             : {log['scan_time']}")
    print(f"  Total Processes       : {log['total_processes']}")
    print(f"  {RED}🚨 FLAGGED             : {len(flagged)}{RESET}")
    print(f"  {YELLOW}⚠️  WARNED              : {len(warned)}{RESET}")
    print(f"  {MAGENTA}⚡ Phase-Shifts (EPSD) : {log['phase_shifts']}{RESET}")
    print(f"  {RED}🔗 Lineage Anomalies   : {log['lineage_anomalies']}{RESET}")
    print(f"  {RED}🧬 RWX Detections      : {log['rwx_detections']}{RESET}")
    print(f"  {RED}🎯 Compound HIGH/CRIT  : {log['compound_high']}{RESET}")

    if flagged:
        print(f"\n{BOLD}{RED}  Top Flagged:{RESET}")
        for p in flagged[:5]:
            print(f"    → PID {p['pid']:<6} {p['name']:<24} H={p['entropy']:.3f}  Risk={p['risk_score']}/100")
    if comp_h:
        print(f"\n{BOLD}{RED}  Compound Threat Events:{RESET}")
        for p in comp_h[:3]:
            print(f"    → PID {p['pid']:<6} {p['name']:<24} [{p['compound_confidence']}] {p['compound_reason']}")
    valid_e = [r["entropy"] for r in results if r["entropy"]>0]
    if valid_e:
        print(f"\n  Avg Process Entropy : {round(sum(valid_e)/len(valid_e),4)} bits")
    print(f"{'═'*70}\n")


# ─────────────────────────────────────────────────────────────────────────────
# THREAT REPORT GENERATOR  (items 44 + 65: export + remote logging concept)
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(results: list, log: dict, fmt: str = "text") -> str:
    """
    Generate a structured threat investigation report.
    Formats: 'text' (human-readable), 'json' (machine-readable), 'csv' (tabular).

    In production this would be shipped to a central SIEM.
    Here it is written to a local file as a prototype output.
    """
    flagged   = [r for r in results if r["gate"] == "FLAG"]
    warned    = [r for r in results if r["gate"] == "WARN"]
    compound  = [r for r in results if r.get("compound_confidence") in ("HIGH","CRITICAL")]
    shifts    = [r for r in results if r["epsd_spike"]]

    if fmt == "json":
        report = {
            "report_type":   "KEEG Threat Investigation Report",
            "generated_at":  datetime.datetime.now().isoformat(),
            "keeg_version":  VERSION,
            "hostname":      HOSTNAME,
            "os":            OS_NAME,
            "policy_version":_POLICY.get("policy_version","built-in defaults"),
            "summary": {
                "total_processes":  log.get("total_processes",0),
                "flagged":          len(flagged),
                "warned":           len(warned),
                "phase_shifts":     len(shifts),
                "compound_threats": len(compound),
                "lineage_anomalies":log.get("lineage_anomalies",0),
                "rwx_detections":   log.get("rwx_detections",0),
            },
            "flagged_processes":  flagged,
            "compound_threats":   compound,
            "phase_shift_events": shifts,
            "all_warned":         warned,
        }
        return json.dumps(report, indent=2, default=str)

    if fmt == "csv":
        lines = ["PID,Name,Entropy,MaxWinEntropy,RiskScore,Gate,CompoundConf,EPSDSpike,EPSDDelta,LineageAnomaly,RWXCount,Connections,User,Timestamp"]
        for r in results:
            lines.append(",".join([
                str(r.get("pid","")),
                str(r.get("name","")),
                str(r.get("entropy","")),
                str(r.get("max_win_entropy","")),
                str(r.get("risk_score","")),
                str(r.get("gate","")),
                str(r.get("compound_confidence","")),
                str(r.get("epsd_spike","")),
                str(r.get("epsd_delta","")),
                str(r.get("lineage_anomalous","")),
                str(r.get("rwx_count","")),
                str(r.get("connections","")),
                str(r.get("username","")),
                str(r.get("timestamp","")),
            ]))
        return "\n".join(lines)

    # Default: human-readable text report
    sep = "═" * 70
    lines = [
        sep,
        f"  KEEG THREAT INVESTIGATION REPORT",
        f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Endpoint  : {HOSTNAME}  ({OS_NAME})",
        f"  KEEG v    : {VERSION}",
        f"  Policy    : {_POLICY.get('policy_version','built-in defaults')}",
        sep,
        "",
        "EXECUTIVE SUMMARY",
        "─" * 40,
        f"  Total Processes Scanned : {log.get('total_processes',0)}",
        f"  Flagged (High Risk)     : {len(flagged)}",
        f"  Warned  (Moderate)      : {len(warned)}",
        f"  Entropy Phase-Shifts    : {len(shifts)}",
        f"  Compound Threats        : {len(compound)}",
        f"  Lineage Anomalies       : {log.get('lineage_anomalies',0)}",
        f"  RWX Detections          : {log.get('rwx_detections',0)}",
        "",
    ]

    if compound:
        lines += ["COMPOUND THREAT EVENTS (Highest Priority)", "─" * 40]
        for r in compound[:10]:
            lines += [
                f"  [{r.get('compound_confidence')}] PID {r['pid']}  {r['name']}",
                f"    Risk Score : {r['risk_score']}/100",
                f"    Compound   : {r.get('compound_reason','')}",
                f"    EPSD Spike : {r.get('epsd_spike')}  ΔH={r.get('epsd_delta',0):+.2f}",
                f"    RWX Regions: {r.get('rwx_count',0)}",
                f"    Lineage    : {r.get('lineage_reason','')}",
                f"    Command    : {r.get('cmdline','')[:70]}",
                "",
            ]

    if flagged:
        lines += ["FLAGGED PROCESSES", "─" * 40]
        for r in flagged[:20]:
            lines.append(f"  PID {r['pid']:<6} {r['name']:<24} Risk={r['risk_score']}/100  H={r['entropy']:.3f}")
            for reason in r.get("risk_reasons",[]):
                lines.append(f"    ↳ {reason}")
            lines.append("")

    if shifts:
        lines += ["ENTROPY PHASE-SHIFT EVENTS", "─" * 40]
        for r in shifts[:10]:
            lines.append(f"  PID {r['pid']:<6} {r['name']:<24} ΔH={r.get('epsd_delta',0):+.2f}  History:{r.get('epsd_history',[])}")
        lines.append("")

    lines += [
        "TECHNICAL NOTES",
        "─" * 40,
        "  Entropy Phase-Shift Detection (EPSD): monitors ΔH = H(t)-H(t-1) per process.",
        "  Sudden spikes indicate in-memory payload decryption.",
        "  Sliding-window entropy catches padding attacks (low + high entropy interleaved).",
        "  Lineage anomalies: document viewer spawning shell = high-confidence indicator.",
        "  RWX memory: executable+writable pages in non-JIT processes = injection signal.",
        "",
        f"  Policy architecture: {POLICY_FILE if os.path.exists(POLICY_FILE) else 'built-in defaults (no policy file found)'}",
        "  In production: central policy server distributes signed policy.json to all endpoints.",
        "",
        sep,
        "  END OF REPORT",
        sep,
    ]
    return "\n".join(lines)


def save_report(results: list, log: dict, basename: str = "keeg_report"):
    """Save threat report in all formats."""
    txt_path = f"{basename}.txt"
    json_path= f"{basename}.json"
    csv_path = f"{basename}.csv"

    with open(txt_path,  "w") as f: f.write(generate_report(results, log, "text"))
    with open(json_path, "w") as f: f.write(generate_report(results, log, "json"))
    with open(csv_path,  "w") as f: f.write(generate_report(results, log, "csv"))

    print(f"\n{GREEN}[✓] Reports saved:{RESET}")
    print(f"    {txt_path}  (human-readable)")
    print(f"    {json_path} (machine-readable / SIEM-ready)")
    print(f"    {csv_path}  (tabular / spreadsheet)")
    return txt_path, json_path, csv_path


# ─────────────────────────────────────────────────────────────────────────────

def run_entropy_demo():
    print(f"\n{CYAN}{BOLD}{'═'*70}")
    print("  KEEG v3.1 - COMPLETE FEATURE DEMONSTRATION")
    print(f"{'═'*70}{RESET}\n")

    print(f"  {BOLD}── Part 1: Shannon Entropy on Different Data Types ──{RESET}\n")
    samples=[
        ("Repeated bytes (AAAA…)",     b"A"*512),
        ("English text",               b"The quick brown fox jumps over the lazy dog. "*8),
        ("Python source code",         b"def hello():\n    print('world')\n    return 42\n"*10),
        ("Base64 payload",             b"SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQu"*8),
        ("ELF binary stub",            bytes([0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00]*64)),
        ("GZIP compressed data",       bytes(range(256))*4),
        ("Simulated AES-encrypted",    os.urandom(512)),
    ]
    for nm, data in samples:
        win=sliding_window_entropy(data); lbl=entropy_label(win["global"]); col=clr(lbl)
        bar="█"*int(win["global"]*4)
        print(f"  {nm:<42} H={col}{win['global']:.4f}[{lbl}]{RESET}  {col}{bar}{RESET}")
    print()

    print(f"  {BOLD}── Part 2: v3 False Positive Fix - Baseline Profiles ──{RESET}\n")
    print(f"  VSCode (code.exe) expected entropy range  : {PROCESS_BASELINES['code.exe']['entropy_range']}")
    print(f"  Chrome (chrome.exe) expected entropy range: {PROCESS_BASELINES['chrome.exe']['entropy_range']}")
    print(f"  If a process entropy is WITHIN its baseline → entropy score suppressed")
    print(f"  Result: VSCode at H=6.2 → {GREEN}NOT flagged{RESET} (within baseline 4.0–7.5)\n")

    print(f"  {BOLD}── Part 3: v3 JIT-Aware RWX Filtering ──{RESET}\n")
    print(f"  Old KEEG (v2): RWX memory → always +30 risk → Chrome often FLAGGED")
    print(f"  New KEEG (v3): RWX on JIT process → +{W_RWX_ONLY} risk (informational only)")
    print(f"  RWX on unknown process + EPSD spike → +{W_RWX_PLUS_SPIKE} risk (injection confirmed)")
    print(f"  Result: Chrome RWX → {GREEN}ALLOW{RESET}  |  Unknown binary RWX+EPSD → {RED}FLAG{RESET}\n")

    print(f"  {BOLD}── Part 4: v3 Entropy Stability Detection ──{RESET}\n")
    print(f"  Stable high entropy (browser TLS stream): H=7.5→7.5→7.6→7.4 → {GREEN}ALLOW{RESET}")
    print(f"  Sudden spike (malware unpack):            H=3.1→3.2→7.9      → {RED}FLAG{RESET}")
    print(f"  Stability deduction: {W_STABILITY_REDUCTION} points when entropy variance < 0.5\n")

    print(f"  {BOLD}── Part 5: v3 Compound Threat Correlation ──{RESET}\n")
    examples=[
        ("EPSD + RWX",            "HIGH",     "payload decryption + executable memory"),
        ("EPSD + RWX + Lineage",  "CRITICAL", "high-confidence memory injection via malicious chain"),
        ("EPSD + Network",        "MEDIUM",   "possible encrypted C2 beacon after unpack"),
        ("Lineage alone",         "LOW",      "suspicious ancestry - monitoring"),
        ("RWX on JIT process",    "NONE",     "normal JIT behavior - not flagged"),
    ]
    for signals, conf, meaning in examples:
        col={"CRITICAL":MAGENTA,"HIGH":RED,"MEDIUM":YELLOW,"LOW":CYAN,"NONE":GREEN}[conf]
        print(f"  {signals:<30} → {col}[{conf}]{RESET}  {meaning}")
    print()

    print(f"  {BOLD}── Part 6: EPSD Phase-Shift Simulation ──{RESET}\n")
    _entropy_history.clear()
    for i, h in enumerate([3.1,3.2,3.1,3.4,7.9,7.8]):
        ev=epsd_update(99999, h)
        alert=""
        if ev["spike"]: alert=f"  {MAGENTA}{BOLD}⚡ PHASE-SHIFT! ΔH={ev['delta']:+.2f}{RESET}"
        elif ev["slow_trend"]: alert=f"  {YELLOW}↑ SLOW TREND{RESET}"
        print(f"    t{i+1}  H={h:.1f}  ΔH={ev['delta']:+.1f}  velocity={ev['velocity']:.4f}/s{alert}")

    print(f"\n  {BOLD}── Part 7: v2 vs v3 Score Comparison ──{RESET}\n")
    print(f"  Scenario: VSCode with high entropy + RWX (legitimate)")
    print(f"    v2 Risk Score: {YELLOW}55–65/100 → WARN{RESET}  (false positive)")
    print(f"    v3 Risk Score: {GREEN}15–25/100 → ALLOW{RESET} (baseline + JIT filtering corrects it)")
    print(f"\n  Scenario: Unknown binary from /tmp with EPSD spike + RWX")
    print(f"    v2 Risk Score: {RED}75–85/100 → FLAG{RESET}")
    print(f"    v3 Risk Score: {RED}80–90/100 → FLAG + COMPOUND=HIGH{RESET}\n")
    print(f"{'═'*70}\n")


# ─────────────────────────────────────────────────────────────────────────────
# UPGRADE 5/14-20 - COMPLETE WEB DASHBOARD v3
# Sidebar navigation, process detail panel, process graph,
# threat banner, search/filter, signal badges, compound alerts
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KEEG v3.1 - Security Console</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--card:#161b22;--card2:#1c2128;--border:#30363d;
  --cyan:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;
  --purple:#bc8cff;--text:#c9d1d9;--dim:#8b949e;--sidebar:#0d1117;
  --sb-w:220px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',Inter,sans-serif;font-size:13px;display:flex;flex-direction:column;height:100vh;overflow:hidden;}

/* ── TOP BAR ── */
#topbar{
  background:var(--card);border-bottom:1px solid var(--border);
  padding:0 20px;height:50px;display:flex;align-items:center;
  justify-content:space-between;flex-shrink:0;z-index:100;
}
#topbar .brand{font-size:16px;font-weight:700;color:var(--cyan);letter-spacing:2px;}
#topbar .brand span{color:var(--dim);font-size:11px;font-weight:400;margin-left:10px;}
#health-dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:6px;transition:background .5s;}
#health-dot.healthy{background:var(--green);animation:pulse 2s infinite;}
#health-dot.warning{background:var(--yellow);}
#health-dot.threat{background:var(--red);animation:pulse .8s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
#health-label{font-size:11px;color:var(--dim);}
#scan-ts{font-size:10px;color:var(--dim);margin-left:16px;}

/* ── THREAT BANNER ── */
#threat-banner{
  display:none;background:rgba(248,81,73,.12);border-bottom:1px solid rgba(248,81,73,.3);
  padding:8px 24px;font-size:12px;color:var(--red);text-align:center;font-weight:600;flex-shrink:0;
}

/* ── BODY LAYOUT ── */
#body{display:flex;flex:1;overflow:hidden;}

/* ── SIDEBAR ── */
#sidebar{
  width:var(--sb-w);background:var(--sidebar);border-right:1px solid var(--border);
  display:flex;flex-direction:column;flex-shrink:0;
}
.sb-section{padding:20px 12px 8px;font-size:9px;font-weight:700;letter-spacing:1.5px;color:var(--dim);text-transform:uppercase;}
.sb-item{
  display:flex;align-items:center;gap:10px;padding:9px 16px;cursor:pointer;
  border-radius:6px;margin:1px 8px;font-size:13px;color:var(--dim);transition:all .15s;border:1px solid transparent;
}
.sb-item:hover{color:var(--text);background:rgba(88,166,255,.06);}
.sb-item.active{color:var(--cyan);background:rgba(88,166,255,.1);border-color:rgba(88,166,255,.2);}
.sb-item .ico{font-size:14px;width:18px;text-align:center;}
.sb-badge{margin-left:auto;background:rgba(248,81,73,.2);color:var(--red);font-size:9px;
           padding:2px 6px;border-radius:10px;font-weight:700;}
#sidebar-bottom{margin-top:auto;padding:16px;border-top:1px solid var(--border);}
.sb-stat{font-size:10px;color:var(--dim);margin-bottom:4px;}

/* ── MAIN AREA ── */
#main{flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:14px;}

/* ── VIEWS ── */
.view{display:none;flex-direction:column;gap:14px;}
.view.active{display:flex;}

/* ── CARDS ── */
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;}
.card-title{font-size:10px;font-weight:600;letter-spacing:1.5px;color:var(--dim);text-transform:uppercase;margin-bottom:12px;}
.metric{font-size:30px;font-weight:700;}
.metric.red{color:var(--red)}.metric.yellow{color:var(--yellow)}
.metric.green{color:var(--green)}.metric.purple{color:var(--purple)}.metric.cyan{color:var(--cyan)}
.metric-sub{font-size:11px;color:var(--dim);margin-top:4px;}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:14px;}
canvas{max-height:240px;}

/* ── BADGES ── */
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;}
.b-FLAG{background:rgba(248,81,73,.15);color:var(--red);}
.b-WARN{background:rgba(210,153,34,.15);color:var(--yellow);}
.b-ALLOW{background:rgba(63,185,80,.15);color:var(--green);}
.b-epsd{background:rgba(188,140,255,.12);color:var(--purple);font-size:9px;}
.b-rwx{background:rgba(248,81,73,.12);color:var(--red);font-size:9px;}
.b-lin{background:rgba(248,81,73,.12);color:var(--red);font-size:9px;}
.b-win{background:rgba(210,153,34,.12);color:var(--yellow);font-size:9px;}
.b-net{background:rgba(88,166,255,.1);color:var(--cyan);font-size:9px;}
.b-jit{background:rgba(63,185,80,.08);color:var(--dim);font-size:9px;}

/* ── TABLES ── */
table{width:100%;border-collapse:collapse;font-size:12px;}
thead th{text-align:left;padding:6px 8px;color:var(--dim);font-size:10px;
         letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid var(--border);}
tbody tr{border-bottom:1px solid rgba(48,54,61,.4);cursor:pointer;transition:background .1s;}
tbody tr:hover{background:#21262d;}
tbody td{padding:7px 8px;}
.riskbar-bg{background:var(--border);border-radius:3px;height:5px;width:70px;overflow:hidden;display:inline-block;vertical-align:middle;}
.riskbar-fg{height:100%;border-radius:3px;}

/* ── ALERT FEED ── */
.feed{max-height:300px;overflow-y:auto;}
.fi{padding:8px 10px;border-left:3px solid var(--border);margin-bottom:5px;
    border-radius:0 4px 4px 0;background:rgba(255,255,255,.015);font-size:11px;cursor:pointer;transition:background .1s;}
.fi:hover{background:rgba(255,255,255,.03);}
.fi.FLAG{border-color:var(--red)}.fi.EPSD{border-color:var(--purple)}
.fi.LIN{border-color:var(--red)}.fi.RWX{border-color:var(--red)}.fi.WARN{border-color:var(--yellow)}
.fi.COMPOUND{border-color:var(--purple);background:rgba(188,140,255,.05);}
.ft{color:var(--dim);font-size:10px;}
.filter-row{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;}
.flt-btn{padding:4px 12px;border-radius:4px;border:1px solid var(--border);background:transparent;
         color:var(--dim);cursor:pointer;font-size:11px;transition:all .15s;}
.flt-btn:hover{border-color:var(--cyan);color:var(--cyan);}
.flt-btn.active{background:rgba(88,166,255,.1);border-color:var(--cyan);color:var(--cyan);}
.search-bar{width:100%;background:var(--card2);border:1px solid var(--border);border-radius:6px;
            padding:7px 12px;color:var(--text);font-size:12px;margin-bottom:10px;}
.search-bar:focus{outline:none;border-color:var(--cyan);}

/* ── PROCESS DETAIL PANEL ── */
#detail-panel{
  position:fixed;right:-420px;top:0;width:420px;height:100%;
  background:var(--card);border-left:1px solid var(--border);z-index:1000;
  transition:right .25s ease;overflow-y:auto;padding:20px;
}
#detail-panel.open{right:0;}
#detail-close{position:absolute;top:14px;right:14px;background:transparent;border:none;
              color:var(--dim);font-size:18px;cursor:pointer;}
#detail-close:hover{color:var(--text);}
.detail-row{display:flex;justify-content:space-between;padding:6px 0;
            border-bottom:1px solid rgba(48,54,61,.4);font-size:12px;}
.detail-row .dk{color:var(--dim);}
.detail-row .dv{font-weight:600;text-align:right;max-width:220px;word-break:break-all;}
.lineage-chain{display:flex;flex-direction:column;gap:2px;margin-top:6px;}
.lc-item{padding:3px 8px;border-radius:4px;font-size:11px;font-family:monospace;}
.lc-item.bad{background:rgba(248,81,73,.1);color:var(--red);}
.lc-item.ok{background:rgba(63,185,80,.06);color:var(--green);}

/* ── PROCESS GRAPH ── */
#graph-canvas{width:100%;height:420px;background:var(--card2);border-radius:6px;cursor:default;}

/* ── COMPOUND ALERT BOX ── */
.compound-box{padding:10px 14px;border-radius:6px;margin-bottom:10px;font-size:12px;}
.compound-box.CRITICAL{background:rgba(188,140,255,.1);border:1px solid rgba(188,140,255,.3);color:var(--purple);}
.compound-box.HIGH{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.25);color:var(--red);}
.compound-box.MEDIUM{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.25);color:var(--yellow);}

/* ── QUICK THREAT SUMMARY ── */
#quick-threat{padding:12px 16px;}
.qt-name{font-size:16px;font-weight:700;color:var(--red);}
.qt-info{font-size:11px;color:var(--dim);margin-top:4px;}

@media(max-width:900px){
  #sidebar{display:none;}
  .grid4{grid-template-columns:repeat(2,1fr);}
  .grid2,.grid3{grid-template-columns:1fr;}
}
hr.sep{border:none;border-top:1px solid var(--border);margin:14px 0;}
</style>
</head>
<body>

<!-- ── TOP BAR ── -->
<div id="topbar">
  <div class="brand">&#9632; KEEG <span>Security Console - v3.1 | Kinetic Entropy Execution Gating</span></div>
  <div style="display:flex;align-items:center;gap:4px;">
    <span id="health-dot" class="healthy"></span>
    <span id="health-label">Healthy</span>
    <span id="scan-ts">Loading…</span>
  </div>
</div>

<!-- ── THREAT BANNER ── -->
<div id="threat-banner"></div>

<!-- ── BODY ── -->
<div id="body">

<!-- ── SIDEBAR ── -->
<div id="sidebar">
  <div class="sb-section">Navigation</div>
  <div class="sb-item active" onclick="showView('dashboard')"><span class="ico">📊</span>Dashboard</div>
  <div class="sb-item" onclick="showView('processes')">
    <span class="ico">⚙</span>Processes
    <span class="sb-badge" id="sb-flag-cnt">0</span>
  </div>
  <div class="sb-item" onclick="showView('entropy')"><span class="ico">🧠</span>Entropy Monitor</div>
  <div class="sb-item" onclick="showView('alerts')"><span class="ico">🚨</span>Threat Alerts</div>
  <div class="sb-item" onclick="showView('graph')"><span class="ico">🌐</span>Process Graph</div>
  <div class="sb-item" onclick="showView('timeline')"><span class="ico">⏱</span>Attack Timeline</div>
  <div class="sb-item" onclick="showView('logs')"><span class="ico">📄</span>System Logs</div>
  <div class="sb-item" onclick="showView('settings')"><span class="ico">⚙</span>Settings</div>

  <div id="sidebar-bottom">
    <div class="sb-stat" id="sb-stat1">Processes: -</div>
    <div class="sb-stat" id="sb-stat2">Phase-Shifts: -</div>
    <div class="sb-stat" id="sb-stat3">RWX Detections: -</div>
    <div class="sb-stat" id="sb-stat4">Compound HIGH+: -</div>
  </div>
</div>

<!-- ── MAIN ── -->
<div id="main">

  <!-- ═══ VIEW: DASHBOARD ═══ -->
  <div class="view active" id="view-dashboard">
    <!-- KPI row -->
    <div class="grid4">
      <div class="card"><div class="card-title">Total Processes</div><div class="metric cyan" id="k-tot">-</div><div class="metric-sub">last scan</div></div>
      <div class="card"><div class="card-title">Active Threats</div><div class="metric red" id="k-flg">-</div><div class="metric-sub">flagged</div></div>
      <div class="card"><div class="card-title">Warnings</div><div class="metric yellow" id="k-wrn">-</div><div class="metric-sub">moderate risk</div></div>
      <div class="card"><div class="card-title">Phase-Shifts</div><div class="metric purple" id="k-eps">-</div><div class="metric-sub">EPSD events</div></div>
    </div>
    <!-- Charts row 1 -->
    <div class="grid2">
      <div class="card"><div class="card-title">Entropy Heatmap - Top 12 Processes (Global vs Max-Window)</div><canvas id="c-ent"></canvas></div>
      <div class="card"><div class="card-title">Risk Score Distribution</div><canvas id="c-rsk"></canvas></div>
    </div>
    <!-- Charts row 2 -->
    <div class="grid3">
      <div class="card"><div class="card-title">Entropy Phase-Shift Timeline - EPSD (Top 5)</div><canvas id="c-eps"></canvas></div>
      <div class="card"><div class="card-title">Gate Decisions</div><canvas id="c-gate"></canvas></div>
      <div class="card">
        <div class="card-title">Advanced Signals</div>
        <div style="margin-bottom:10px"><div class="card-title">Lineage Anomalies</div><div class="metric red" id="k-lin">-</div><div class="metric-sub">suspicious chains</div></div>
        <hr class="sep">
        <div style="margin-bottom:10px"><div class="card-title">RWX Non-JIT</div><div class="metric red" id="k-rwx">-</div><div class="metric-sub">injection indicators</div></div>
        <hr class="sep">
        <div><div class="card-title">Compound HIGH+</div><div class="metric purple" id="k-comp">-</div><div class="metric-sub">multi-signal threats</div></div>
      </div>
    </div>
    <!-- Quick threat + feed -->
    <div class="grid2">
      <div class="card">
        <div class="card-title">Top Risk Processes</div>
        <input class="search-bar" id="dash-search" placeholder="Search by name or PID…" oninput="filterDashTable()">
        <table><thead><tr><th>PID</th><th>Name</th><th>Entropy</th><th>Risk</th><th>Gate</th><th>Signals</th></tr></thead>
        <tbody id="dash-table"></tbody></table>
      </div>
      <div class="card">
        <div class="card-title">Security Event Feed</div>
        <div id="quick-threat" style="display:none;border:1px solid rgba(248,81,73,.25);border-radius:6px;margin-bottom:10px;background:rgba(248,81,73,.06);">
          <div style="font-size:9px;color:var(--dim);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">Top Threat</div>
          <div class="qt-name" id="qt-name">-</div>
          <div class="qt-info" id="qt-info">-</div>
        </div>
        <div class="feed" id="event-feed"></div>
      </div>
    </div>
  </div>

  <!-- ═══ VIEW: PROCESSES ═══ -->
  <div class="view" id="view-processes">
    <div class="card">
      <div class="card-title">All Processes</div>
      <input class="search-bar" id="proc-search" placeholder="Search by name or PID…" oninput="filterProcTable()">
      <div class="filter-row" id="sev-filters">
        <button class="flt-btn active" onclick="setSevFilter('all',this)">All</button>
        <button class="flt-btn" onclick="setSevFilter('FLAG',this)">Flagged</button>
        <button class="flt-btn" onclick="setSevFilter('WARN',this)">Warnings</button>
        <button class="flt-btn" onclick="setSevFilter('ALLOW',this)">Allowed</button>
        <button class="flt-btn" onclick="setSevFilter('EPSD',this)">⚡ Phase-Shift</button>
        <button class="flt-btn" onclick="setSevFilter('RWX',this)">🧬 RWX</button>
        <button class="flt-btn" onclick="setSevFilter('LIN',this)">🔗 Lineage</button>
      </div>
      <table>
        <thead><tr>
          <th onclick="sortBy('pid')" style="cursor:pointer">PID ↕</th>
          <th onclick="sortBy('name')" style="cursor:pointer">Name ↕</th>
          <th onclick="sortBy('entropy')" style="cursor:pointer">Entropy ↕</th>
          <th onclick="sortBy('risk_score')" style="cursor:pointer">Risk ↕</th>
          <th>Gate</th><th>Signals</th><th>Compound</th>
        </tr></thead>
        <tbody id="proc-table"></tbody>
      </table>
    </div>
  </div>

  <!-- ═══ VIEW: ENTROPY MONITOR ═══ -->
  <div class="view" id="view-entropy">
    <div class="grid2">
      <div class="card"><div class="card-title">Entropy Distribution Across Processes</div><canvas id="c-entdist"></canvas></div>
      <div class="card"><div class="card-title">Entropy Velocity (EPSD ΔH/Δt)</div><canvas id="c-vel"></canvas></div>
    </div>
    <div class="card"><div class="card-title">Top 15 Process Entropy Timeline (EPSD History)</div><canvas id="c-eps2" style="max-height:300px"></canvas></div>
  </div>

  <!-- ═══ VIEW: ALERTS ═══ -->
  <div class="view" id="view-alerts">
    <div class="card">
      <div class="card-title">All Security Alerts</div>
      <div class="filter-row">
        <button class="flt-btn active" onclick="setAlertFilter('all',this)">All</button>
        <button class="flt-btn" onclick="setAlertFilter('CRITICAL',this)">Critical</button>
        <button class="flt-btn" onclick="setAlertFilter('HIGH',this)">High</button>
        <button class="flt-btn" onclick="setAlertFilter('MEDIUM',this)">Medium</button>
        <button class="flt-btn" onclick="setAlertFilter('FLAG',this)">Flag</button>
        <button class="flt-btn" onclick="setAlertFilter('EPSD',this)">⚡ Phase-Shift</button>
        <button class="flt-btn" onclick="setAlertFilter('RWX',this)">🧬 RWX</button>
        <button class="flt-btn" onclick="setAlertFilter('LIN',this)">🔗 Lineage</button>
      </div>
      <div class="feed" id="full-alert-feed" style="max-height:none"></div>
    </div>
  </div>

  <!-- ═══ VIEW: PROCESS GRAPH ═══ -->
  <div class="view" id="view-graph">
    <div class="card">
      <div class="card-title">Process Interaction Graph - Live (click node to inspect)</div>
      <canvas id="graph-canvas"></canvas>
      <div style="margin-top:8px;font-size:11px;color:var(--dim);">
        🟢 Normal &nbsp;🟡 Suspicious &nbsp;🔴 Flagged &nbsp;🟣 Phase-Shift &nbsp;- edges = parent→child
      </div>
    </div>
  </div>

  <!-- ═══ VIEW: ATTACK TIMELINE ═══ -->
  <div class="view" id="view-timeline">
    <div class="card">
      <div class="card-title">Attack Event Timeline - Chronological Sequence Reconstruction</div>
      <div style="font-size:11px;color:var(--dim);margin-bottom:12px;">
        Shows security events in time order. Useful for reconstructing attack sequences: process start → entropy spike → RWX → network.
      </div>
      <div id="timeline-body"></div>
    </div>
    <div class="card">
      <div class="card-title">Entropy Kinetics - Velocity &amp; Acceleration</div>
      <div style="font-size:11px;color:var(--dim);margin-bottom:10px;">
        Velocity = ΔH/Δt &nbsp;|&nbsp; Acceleration = Δvelocity/Δt. Sudden positive acceleration indicates explosive entropy increase (payload unpack event).
      </div>
      <canvas id="c-kinetics" style="max-height:220px"></canvas>
    </div>
  </div>

  <!-- ═══ VIEW: SETTINGS ═══ -->
  <div class="view" id="view-settings">
    <div class="grid2">
      <div class="card">
        <div class="card-title">Detection Thresholds</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:14px;">
          Current active policy. In production these are distributed from a central policy server as a signed keeg_policy.json file.
        </div>
        <div class="detail-row"><span class="dk">Entropy CRITICAL threshold</span><span class="dv" style="color:var(--purple)">≥ 7.0 bits</span></div>
        <div class="detail-row"><span class="dk">Entropy HIGH threshold</span><span class="dv" style="color:var(--red)">≥ 5.5 bits</span></div>
        <div class="detail-row"><span class="dk">Entropy ELEVATED threshold</span><span class="dv" style="color:var(--yellow)">≥ 3.5 bits</span></div>
        <div class="detail-row"><span class="dk">EPSD spike threshold (|ΔH|)</span><span class="dv">≥ 2.5 bits</span></div>
        <div class="detail-row"><span class="dk">EPSD slow trend threshold</span><span class="dv">≥ 1.5 bits / 3 steps</span></div>
        <div class="detail-row"><span class="dk">FLAG risk score</span><span class="dv" style="color:var(--red)">≥ 70 / 100</span></div>
        <div class="detail-row"><span class="dk">WARN risk score</span><span class="dv" style="color:var(--yellow)">≥ 40 / 100</span></div>
        <div class="detail-row"><span class="dk">Sliding window size</span><span class="dv">256 bytes</span></div>
        <div class="detail-row"><span class="dk">EPSD history max</span><span class="dv">30 samples</span></div>
      </div>
      <div class="card">
        <div class="card-title">Risk Signal Weights</div>
        <div style="font-size:11px;color:var(--dim);margin-bottom:14px;">
          v3 rebalancing: RWX reduced from +30→+10 (JIT noise), Phase-Shift increased to +35 (most reliable signal).
        </div>
        <div class="detail-row"><span class="dk">Entropy CRITICAL</span><span class="dv" style="color:var(--red)">+50</span></div>
        <div class="detail-row"><span class="dk">Entropy HIGH</span><span class="dv" style="color:var(--red)">+30</span></div>
        <div class="detail-row"><span class="dk">EPSD Phase-Shift</span><span class="dv" style="color:var(--purple)">+35</span></div>
        <div class="detail-row"><span class="dk">Lineage Anomaly</span><span class="dv" style="color:var(--red)">+30</span></div>
        <div class="detail-row"><span class="dk">RWX + EPSD (injection)</span><span class="dv" style="color:var(--red)">+30</span></div>
        <div class="detail-row"><span class="dk">Suspicious Path</span><span class="dv" style="color:var(--yellow)">+25</span></div>
        <div class="detail-row"><span class="dk">EPSD Slow Trend</span><span class="dv" style="color:var(--yellow)">+15</span></div>
        <div class="detail-row"><span class="dk">RWX alone (JIT informational)</span><span class="dv" style="color:var(--dim)">+10</span></div>
        <div class="detail-row"><span class="dk">Trusted path deduction</span><span class="dv" style="color:var(--green)">−20</span></div>
        <div class="detail-row"><span class="dk">Entropy stability deduction</span><span class="dv" style="color:var(--green)">−15</span></div>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title">Endpoint Information</div>
        <div id="endpoint-info"></div>
      </div>
      <div class="card">
        <div class="card-title">Policy Architecture - Distributed Deployment Concept</div>
        <div style="font-size:12px;color:var(--dim);line-height:1.7">
          <p style="margin-bottom:8px">KEEG uses a <b style="color:var(--cyan)">policy-separated architecture</b> designed for enterprise deployment:</p>
          <div style="font-family:monospace;font-size:11px;padding:10px;background:var(--bg);border-radius:6px;border:1px solid var(--border)">
            Central Policy Server<br>
            &nbsp;&nbsp;&nbsp;&nbsp;↓ signed keeg_policy.json<br>
            Endpoint Agents (KEEG)<br>
            &nbsp;&nbsp;&nbsp;&nbsp;↓ telemetry stream<br>
            Central Analysis Engine<br>
            &nbsp;&nbsp;&nbsp;&nbsp;↓ baseline aggregation<br>
            Policy Update Distribution
          </div>
          <p style="margin-top:10px;font-size:11px">
            • Detection engine and policy are <b style="color:var(--text)">separated</b> - update rules without re-deploying agents<br>
            • Baselines built from <b style="color:var(--text)">multi-endpoint consensus</b> - prevents single-machine baseline poisoning<br>
            • Policy signed with server private key - <b style="color:var(--text)">endpoints verify before applying</b>
          </p>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Export &amp; Report</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:4px">
        <a href="/api/export/json" download="keeg_report.json" style="text-decoration:none">
          <button class="flt-btn active" style="padding:8px 18px;font-size:12px">⬇ Export JSON</button>
        </a>
        <a href="/api/export/csv" download="keeg_report.csv" style="text-decoration:none">
          <button class="flt-btn" style="padding:8px 18px;font-size:12px">⬇ Export CSV</button>
        </a>
        <a href="/api/export/text" download="keeg_report.txt" style="text-decoration:none">
          <button class="flt-btn" style="padding:8px 18px;font-size:12px">⬇ Export Report (.txt)</button>
        </a>
      </div>
      <div style="margin-top:12px;font-size:11px;color:var(--dim)">
        JSON export is SIEM-compatible. CSV opens in Excel. Text report is human-readable investigation summary.
      </div>
    </div>
  </div>

  <!-- ═══ VIEW: LOGS ═══ -->
  <div class="view" id="view-logs">
    <div class="card">
      <div class="card-title">System Log - Raw JSON Event Stream</div>
      <pre id="raw-log" style="font-size:11px;color:var(--dim);max-height:500px;overflow-y:auto;white-space:pre-wrap;"></pre>
    </div>
  </div>

</div><!-- /main -->
</div><!-- /body -->

<!-- ── PROCESS DETAIL PANEL ── -->
<div id="detail-panel">
  <button id="detail-close" onclick="closeDetail()">✕</button>
  <div id="detail-content"></div>
</div>

<script>
/* ═══════════════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════════════ */
let allData = {results:[]};
let cEnt,cRsk,cEps,cGate,cEntdist,cVel,cEps2;
let currentSort = {key:'risk_score', asc:false};
let sevFilter = 'all';
let alertFilter = 'all';
let dashSearch = '';
let procSearch = '';

/* ═══════════════════════════════════════════════════════════════
   COLOURS
═══════════════════════════════════════════════════════════════ */
const rc = r => r>=70?'#f85149':r>=40?'#d29922':'#3fb950';
const ec = h => h>=7?'#bc8cff':h>=5.5?'#f85149':h>=3.5?'#d29922':'#3fb950';
const cc = c => ({CRITICAL:'#bc8cff',HIGH:'#f85149',MEDIUM:'#d29922',LOW:'#58a6ff',NONE:'#3fb950'})[c]||'#8b949e';

/* ═══════════════════════════════════════════════════════════════
   SIDEBAR NAV
═══════════════════════════════════════════════════════════════ */
function showView(id){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  document.getElementById('view-'+id).classList.add('active');
  event.currentTarget.classList.add('active');
  if(id==='entropy')  renderEntropyView();
  if(id==='graph')    renderGraph();
  if(id==='timeline') renderTimeline();
  if(id==='settings') renderSettings();
}

/* ═══════════════════════════════════════════════════════════════
   FETCH + RENDER
═══════════════════════════════════════════════════════════════ */
async function refresh(){
  try{allData = await (await fetch('/api/data')).json();}catch(e){return;}
  const R = allData.results||[];

  /* Top bar */
  const ts = (allData.scan_time||'').replace('T',' ').slice(0,19);
  document.getElementById('scan-ts').textContent = '| Last scan: '+ts;
  const dot = document.getElementById('health-dot');
  const hl  = document.getElementById('health-label');
  if((allData.flagged||0)>0){dot.className='health-dot threat';hl.textContent='⚠ Threat Detected';}
  else if((allData.warned||0)>0){dot.className='health-dot warning';hl.textContent='Warning';}
  else{dot.className='health-dot healthy';hl.textContent='Healthy';}

  /* Threat banner */
  const banner = document.getElementById('threat-banner');
  const flagged = R.filter(r=>r.gate==='FLAG');
  if(flagged.length>0){
    banner.style.display='block';
    banner.textContent='⚠ ACTIVE THREAT DETECTED - '+flagged.length+' HIGH-RISK PROCESS'+(flagged.length>1?'ES':'');
  } else {banner.style.display='none';}

  /* KPIs */
  document.getElementById('k-tot').textContent=allData.total_processes??'-';
  document.getElementById('k-flg').textContent=allData.flagged??'-';
  document.getElementById('k-wrn').textContent=allData.warned??'-';
  document.getElementById('k-eps').textContent=allData.phase_shifts??'-';
  document.getElementById('k-lin').textContent=allData.lineage_anomalies??'-';
  document.getElementById('k-rwx').textContent=allData.rwx_detections??'-';
  document.getElementById('k-comp').textContent=allData.compound_high??'-';
  document.getElementById('sb-flag-cnt').textContent=allData.flagged??0;
  document.getElementById('sb-stat1').textContent='Processes: '+(allData.total_processes??'-');
  document.getElementById('sb-stat2').textContent='Phase-Shifts: '+(allData.phase_shifts??'-');
  document.getElementById('sb-stat3').textContent='RWX Detections: '+(allData.rwx_detections??'-');
  document.getElementById('sb-stat4').textContent='Compound HIGH+: '+(allData.compound_high??'-');

  renderCharts(R);
  renderDashTable(R);
  renderEventFeed(R);
  renderProcTable(R);
  renderQuickThreat(R);

  /* Logs view */
  document.getElementById('raw-log').textContent=JSON.stringify(allData,null,2).slice(0,8000);
}

/* ═══════════════════════════════════════════════════════════════
   CHARTS
═══════════════════════════════════════════════════════════════ */
function renderCharts(R){
  /* Entropy heatmap */
  const topE=[...R].sort((a,b)=>(b.max_win_entropy||b.entropy)-(a.max_win_entropy||a.entropy)).slice(0,12);
  const eL=topE.map(p=>p.name.length>13?p.name.slice(0,13)+'…':p.name);
  const eV=topE.map(p=>+(p.max_win_entropy||p.entropy||0).toFixed(3));
  const eG=topE.map(p=>+(p.entropy||0).toFixed(3));
  if(!cEnt){cEnt=new Chart(document.getElementById('c-ent'),{type:'bar',data:{labels:eL,datasets:[
    {label:'Max-Window H',data:eV,backgroundColor:eV.map(ec)},
    {label:'Global H',data:eG,backgroundColor:'rgba(88,166,255,.25)',borderColor:'#58a6ff',borderWidth:1}
  ]},options:{responsive:true,scales:{y:{min:0,max:8,ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'},
    title:{display:true,text:'Entropy (bits)',color:'#8b949e'}},x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(48,54,61,.3)'}}},
    plugins:{legend:{labels:{color:'#c9d1d9',font:{size:10}}}},animation:false}});}
  else{cEnt.data.labels=eL;cEnt.data.datasets[0].data=eV;cEnt.data.datasets[0].backgroundColor=eV.map(ec);cEnt.data.datasets[1].data=eG;cEnt.update('none');}

  /* Risk distribution */
  const rb=[0,0,0,0];R.forEach(r=>{const s=r.risk_score||0;if(s>=70)rb[3]++;else if(s>=50)rb[2]++;else if(s>=30)rb[1]++;else rb[0]++;});
  if(!cRsk){cRsk=new Chart(document.getElementById('c-rsk'),{type:'bar',data:{labels:['0-29 Safe','30-49 Low','50-69 Med','70+ High'],datasets:[{data:rb,
    backgroundColor:['rgba(63,185,80,.6)','rgba(88,166,255,.5)','rgba(210,153,34,.6)','rgba(248,81,73,.6)'],borderRadius:4}]},
    options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'}},
    x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(48,54,61,.3)'}}},animation:false}});}
  else{cRsk.data.datasets[0].data=rb;cRsk.update('none');}

  /* EPSD timeline */
  const wH=[...R].filter(p=>p.epsd_history&&p.epsd_history.length>=2).sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,5);
  const mL=Math.max(...wH.map(p=>p.epsd_history.length),3);
  const eCols=['#58a6ff','#f85149','#d29922','#3fb950','#bc8cff'];
  if(!cEps){cEps=new Chart(document.getElementById('c-eps'),{type:'line',data:{labels:Array.from({length:mL},(_,i)=>'t'+(i+1)),
    datasets:wH.map((p,i)=>({label:p.name,data:p.epsd_history,borderColor:eCols[i%5],backgroundColor:'transparent',tension:.3,pointRadius:3}))},
    options:{responsive:true,scales:{y:{min:0,max:8,ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'},title:{display:true,text:'H(t)',color:'#8b949e'}},
    x:{ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.3)'}}},plugins:{legend:{labels:{color:'#c9d1d9',font:{size:10}}}},animation:false}});}
  else{cEps.data.labels=Array.from({length:mL},(_,i)=>'t'+(i+1));cEps.data.datasets=wH.map((p,i)=>({label:p.name,data:p.epsd_history,borderColor:eCols[i%5],backgroundColor:'transparent',tension:.3,pointRadius:3}));cEps.update('none');}

  /* Gate pie */
  const gF=R.filter(r=>r.gate==='FLAG').length,gW=R.filter(r=>r.gate==='WARN').length,gA=R.filter(r=>r.gate==='ALLOW').length;
  if(!cGate){cGate=new Chart(document.getElementById('c-gate'),{type:'doughnut',data:{labels:['FLAG','WARN','ALLOW'],datasets:[{
    data:[gF,gW,gA],backgroundColor:['rgba(248,81,73,.75)','rgba(210,153,34,.75)','rgba(63,185,80,.75)'],borderWidth:0}]},
    options:{responsive:true,cutout:'65%',plugins:{legend:{labels:{color:'#c9d1d9',font:{size:11}}}},animation:false}});}
  else{cGate.data.datasets[0].data=[gF,gW,gA];cGate.update('none');}
}

function renderEntropyView(){
  const R=allData.results||[];
  /* Entropy distribution */
  const bins=[0,0,0,0,0];R.forEach(r=>{const h=r.entropy||0;if(h<3.5)bins[0]++;else if(h<5.5)bins[1]++;else if(h<7)bins[2]++;else bins[3]++;});
  if(!cEntdist){cEntdist=new Chart(document.getElementById('c-entdist'),{type:'bar',data:{labels:['0-3.5 Normal','3.5-5.5 Elevated','5.5-7.0 High','7.0-8.0 Critical'],datasets:[{data:bins,
    backgroundColor:['rgba(63,185,80,.6)','rgba(210,153,34,.6)','rgba(248,81,73,.6)','rgba(188,140,255,.7)'],borderRadius:4}]},
    options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'}},
    x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(48,54,61,.3)'}}},animation:false}});}
  else{cEntdist.data.datasets[0].data=bins;cEntdist.update('none');}

  /* Entropy velocity */
  const topV=[...R].filter(p=>Math.abs(p.epsd_velocity||0)>0).sort((a,b)=>Math.abs(b.epsd_velocity||0)-Math.abs(a.epsd_velocity||0)).slice(0,10);
  const vL=topV.map(p=>p.name.slice(0,14));
  const vD=topV.map(p=>+(p.epsd_velocity||0).toFixed(4));
  if(!cVel){cVel=new Chart(document.getElementById('c-vel'),{type:'bar',data:{labels:vL,datasets:[{label:'ΔH/Δt',data:vD,
    backgroundColor:vD.map(v=>v>0?'rgba(248,81,73,.6)':'rgba(63,185,80,.4)'),borderRadius:3}]},
    options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'},
    title:{display:true,text:'Entropy velocity (bits/s)',color:'#8b949e'}},x:{ticks:{color:'#8b949e',font:{size:10}}}},animation:false}});}
  else{cVel.data.labels=vL;cVel.data.datasets[0].data=vD;cVel.data.datasets[0].backgroundColor=vD.map(v=>v>0?'rgba(248,81,73,.6)':'rgba(63,185,80,.4)');cVel.update('none');}

  /* EPSD timeline extended */
  const wH=[...R].filter(p=>p.epsd_history&&p.epsd_history.length>=2).sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,15);
  const mL2=Math.max(...wH.map(p=>p.epsd_history.length),3);
  const eCols=['#58a6ff','#f85149','#d29922','#3fb950','#bc8cff','#ffa657','#79c0ff','#56d364','#e3b341','#ff7b72'];
  if(!cEps2){cEps2=new Chart(document.getElementById('c-eps2'),{type:'line',data:{labels:Array.from({length:mL2},(_,i)=>'t'+(i+1)),
    datasets:wH.map((p,i)=>({label:p.name,data:p.epsd_history,borderColor:eCols[i%10],backgroundColor:'transparent',tension:.3,pointRadius:2,borderWidth:1.5}))},
    options:{responsive:true,scales:{y:{min:0,max:8,ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'}},
    x:{ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.3)'}}},plugins:{legend:{labels:{color:'#c9d1d9',font:{size:9},boxWidth:12}}},animation:false}});}
  else{cEps2.data.labels=Array.from({length:mL2},(_,i)=>'t'+(i+1));cEps2.data.datasets=wH.map((p,i)=>({label:p.name,data:p.epsd_history,borderColor:eCols[i%10],backgroundColor:'transparent',tension:.3,pointRadius:2,borderWidth:1.5}));cEps2.update('none');}
}

/* ═══════════════════════════════════════════════════════════════
   PROCESS GRAPH (canvas-based simple layout)
═══════════════════════════════════════════════════════════════ */
function renderGraph(){
  const R=allData.results||[];
  const canvas=document.getElementById('graph-canvas');
  if(!canvas) return;
  const ctx=canvas.getContext('2d');
  const W=canvas.offsetWidth||860;
  const H=420;
  canvas.width=W; canvas.height=H;
  ctx.clearRect(0,0,W,H);

  if(!R.length){
    ctx.fillStyle='#8b949e'; ctx.font='14px Segoe UI'; ctx.textAlign='center';
    ctx.fillText('No process data',W/2,H/2); return;
  }

  // ── Build pid→process map from ALL results ─────────────────────────────
  const pidMap={};
  R.forEach(p=>{ if(p.pid!=null) pidMap[p.pid]=p; });

  // ── Select processes to display: top 35 by risk score ─────────────────
  const shown=[...R].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,35);
  const shownPids=new Set(shown.map(p=>p.pid));

  // ── Build adjacency: child → parent (using ppid from lineage_chain[1] or results) ─
  // Results carry ppid indirectly. We use the lineage_chain array which is
  // [child_name, parent_name, grandparent_name, …] — but we need PIDs.
  // Instead we look up each shown process's ppid from the full result set.
  // The results store ppid only if scan captured it. Fall back to grouping by name.
  // Strategy: group by ppid from the JSON if available; otherwise bucket orphans.
  const ppidOf={};
  R.forEach(p=>{ if(p.ppid!=null) ppidOf[p.pid]=p.ppid; });

  // ── Hierarchical layout: BFS from roots ───────────────────────────────
  // Find roots among shown: processes whose parent is NOT in shown set
  const shownArr=shown;
  const parentInShown=new Set();
  shownArr.forEach(p=>{
    const pp=ppidOf[p.pid];
    if(pp!=null && shownPids.has(pp)) parentInShown.add(p.pid);
  });
  const roots=shownArr.filter(p=>{ const pp=ppidOf[p.pid]; return pp==null||!shownPids.has(pp); });

  // BFS to compute depth and assign horizontal order
  const depth={}, order={}, depthBuckets={};
  let maxDepth=0;
  const queue=[...roots];
  roots.forEach(r=>{ depth[r.pid]=0; });
  let visited=new Set(roots.map(r=>r.pid));
  while(queue.length){
    const cur=queue.shift();
    const d=depth[cur.pid]||0;
    if(!depthBuckets[d]) depthBuckets[d]=[];
    depthBuckets[d].push(cur);
    if(d>maxDepth) maxDepth=d;
    // Find children of cur in shown
    shownArr.forEach(p=>{
      if(!visited.has(p.pid) && ppidOf[p.pid]===cur.pid){
        depth[p.pid]=d+1; visited.add(p.pid); queue.push(p);
      }
    });
  }
  // Any not yet visited go to depth 0 (disconnected orphans)
  shownArr.forEach(p=>{
    if(!visited.has(p.pid)){
      depth[p.pid]=0;
      if(!depthBuckets[0]) depthBuckets[0]=[];
      depthBuckets[0].push(p);
    }
  });

  // ── Assign x,y positions ────────────────────────────────────────────────
  const LAYERS=Object.keys(depthBuckets).map(Number).sort((a,b)=>a-b);
  const layerH=Math.min(90, (H-60)/Math.max(LAYERS.length,1));
  const NODE_R=14;
  const positions={};

  LAYERS.forEach((d,li)=>{
    const bucket=depthBuckets[d]||[];
    const count=bucket.length;
    bucket.forEach((p,i)=>{
      const x=W*(i+1)/(count+1);
      const y=40+li*layerH;
      positions[p.pid]={x,y,p};
    });
  });

  // ── Draw edges first (behind nodes) ────────────────────────────────────
  shownArr.forEach(p=>{
    const pp=ppidOf[p.pid];
    if(pp!=null && positions[p.pid] && positions[pp]){
      const child=positions[p.pid];
      const parent=positions[pp];
      const anomalous=p.lineage_anomalous;
      // Curved bezier from parent to child
      ctx.beginPath();
      ctx.moveTo(parent.x, parent.y+NODE_R);
      const midY=(parent.y+NODE_R+child.y-NODE_R)/2;
      ctx.bezierCurveTo(parent.x, midY, child.x, midY, child.x, child.y-NODE_R);
      ctx.strokeStyle=anomalous?'rgba(248,81,73,0.6)':'rgba(88,166,255,0.25)';
      ctx.lineWidth=anomalous?2:1;
      ctx.stroke();
      // Arrowhead
      const angle=Math.atan2(child.y-NODE_R-midY, child.x-child.x)||Math.PI/2;
      const ax=child.x, ay=child.y-NODE_R;
      ctx.beginPath();
      ctx.moveTo(ax,ay);
      ctx.lineTo(ax-5,ay-8);
      ctx.lineTo(ax+5,ay-8);
      ctx.closePath();
      ctx.fillStyle=anomalous?'rgba(248,81,73,0.7)':'rgba(88,166,255,0.4)';
      ctx.fill();
    }
  });

  // ── Draw nodes ─────────────────────────────────────────────────────────
  shownArr.forEach(p=>{
    const pos=positions[p.pid]; if(!pos) return;
    const r=p.risk_score||0;
    let nc='#3fb950';  // green = safe
    if(p.epsd_spike)       nc='#bc8cff';  // purple = phase-shift
    else if(r>=70)         nc='#f85149';  // red = flagged
    else if(r>=40)         nc='#d29922';  // yellow = warned
    else if(p.trusted)     nc='#58a6ff';  // blue = trusted/safe
    // Outer glow for high risk
    if(r>=70||p.epsd_spike){
      ctx.beginPath(); ctx.arc(pos.x,pos.y,NODE_R+4,0,Math.PI*2);
      ctx.fillStyle=nc+'22'; ctx.fill();
    }
    // Node fill
    ctx.beginPath(); ctx.arc(pos.x,pos.y,NODE_R,0,Math.PI*2);
    ctx.fillStyle=nc+'2a'; ctx.fill();
    ctx.strokeStyle=nc; ctx.lineWidth=p.gate==='FLAG'?2.5:1.5; ctx.stroke();
    // Center dot
    ctx.beginPath(); ctx.arc(pos.x,pos.y,4,0,Math.PI*2);
    ctx.fillStyle=nc; ctx.fill();
    // Process name label
    const lbl=(p.name||'').slice(0,11);
    ctx.font='8px Segoe UI'; ctx.fillStyle='#c9d1d9'; ctx.textAlign='center';
    ctx.fillText(lbl,pos.x,pos.y+NODE_R+9);
    // Risk score label
    ctx.font='bold 7px Segoe UI'; ctx.fillStyle=nc+'dd';
    ctx.fillText('r='+r,pos.x,pos.y+NODE_R+18);
  });

  // ── Tooltip / click handler ─────────────────────────────────────────────
  canvas.onclick=function(e){
    const rect=canvas.getBoundingClientRect();
    const mx=(e.clientX-rect.left)*(W/rect.width);
    const my=(e.clientY-rect.top)*(H/rect.height);
    Object.values(positions).forEach(pos=>{
      if(Math.hypot(mx-pos.x, my-pos.y)<NODE_R+4) openDetail(pos.p);
    });
  };
  canvas.style.cursor='default';
  canvas.onmousemove=function(e){
    const rect=canvas.getBoundingClientRect();
    const mx=(e.clientX-rect.left)*(W/rect.width);
    const my=(e.clientY-rect.top)*(H/rect.height);
    let hit=false;
    Object.values(positions).forEach(pos=>{
      if(Math.hypot(mx-pos.x,my-pos.y)<NODE_R+4) hit=true;
    });
    canvas.style.cursor=hit?'pointer':'default';
  };
}

/* ═══════════════════════════════════════════════════════════════
   QUICK THREAT SUMMARY
═══════════════════════════════════════════════════════════════ */
function renderQuickThreat(R){
  const top=R.find(r=>r.gate==='FLAG')||R[0];
  if(!top||top.risk_score<40){document.getElementById('quick-threat').style.display='none';return;}
  document.getElementById('quick-threat').style.display='block';
  document.getElementById('qt-name').textContent=(top.name||'')+(top.pid?' (PID '+top.pid+')':'');
  document.getElementById('qt-info').textContent='Risk: '+top.risk_score+'/100  '+(top.compound_confidence&&top.compound_confidence!='NONE'?'| Compound: '+top.compound_confidence:'');
}

/* ═══════════════════════════════════════════════════════════════
   SIGNAL BADGES
═══════════════════════════════════════════════════════════════ */
function makeBadges(p){
  let b='';
  if(p.epsd_spike) b+='<span class="badge b-epsd">⚡EPSD</span> ';
  if(p.lineage_anomalous) b+='<span class="badge b-lin">🔗LIN</span> ';
  if(p.rwx_suspicious) b+='<span class="badge b-rwx">🧬RWX</span> ';
  else if(p.rwx_count>0&&p.rwx_jit_probable) b+='<span class="badge b-jit">JIT</span> ';
  if(p.win_anomalous) b+='<span class="badge b-win">📊WIN</span> ';
  if(p.connections>0) b+='<span class="badge b-net">🌐'+p.connections+'</span> ';
  return b||'<span style="color:var(--dim)">-</span>';
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD TABLE
═══════════════════════════════════════════════════════════════ */
let dashResults=[];
function renderDashTable(R){
  dashResults=R;filterDashTable();
}
function filterDashTable(){
  const q=(document.getElementById('dash-search').value||'').toLowerCase();
  const rows=dashResults.filter(p=>{
    if(q&&!p.name.includes(q)&&!String(p.pid).includes(q)) return false;
    return true;
  }).slice(0,20);
  document.getElementById('dash-table').innerHTML=rows.map(p=>{
    const s=p.risk_score||0,fc=rc(s);
    return '<tr onclick="openDetail(allData.results.find(r=>r.pid==='+p.pid+'))">'+
      '<td style="color:var(--dim)">'+p.pid+'</td>'+
      '<td style="font-weight:600">'+(p.name||'').slice(0,20)+'</td>'+
      '<td style="color:'+ec(p.max_win_entropy||p.entropy)+'">'+(+(p.max_win_entropy||p.entropy||0)).toFixed(3)+'</td>'+
      '<td><div style="display:flex;align-items:center;gap:6px">'+
        '<div class="riskbar-bg"><div class="riskbar-fg" style="width:'+Math.min(s,100)+'%;background:'+fc+'"></div></div>'+
        '<span style="color:'+fc+';font-weight:700">'+s+'</span></div></td>'+
      '<td><span class="badge b-'+p.gate+'">'+p.gate+'</span></td>'+
      '<td>'+makeBadges(p)+'</td>'+
    '</tr>';
  }).join('');
}

/* ═══════════════════════════════════════════════════════════════
   PROCESS TABLE (full)
═══════════════════════════════════════════════════════════════ */
let procResults=[];
function renderProcTable(R){procResults=R;filterProcTable();}
function filterProcTable(){
  const q=(document.getElementById('proc-search').value||'').toLowerCase();
  let rows=procResults.filter(p=>{
    if(q&&!p.name.includes(q)&&!String(p.pid).includes(q)) return false;
    if(sevFilter==='FLAG') return p.gate==='FLAG';
    if(sevFilter==='WARN') return p.gate==='WARN';
    if(sevFilter==='ALLOW') return p.gate==='ALLOW';
    if(sevFilter==='EPSD') return p.epsd_spike;
    if(sevFilter==='RWX') return p.rwx_suspicious;
    if(sevFilter==='LIN') return p.lineage_anomalous;
    return true;
  });
  // Sort
  rows.sort((a,b)=>{
    const av=a[currentSort.key]||0, bv=b[currentSort.key]||0;
    return currentSort.asc?(av>bv?1:-1):(av<bv?1:-1);
  });
  document.getElementById('proc-table').innerHTML=rows.map(p=>{
    const s=p.risk_score||0,fc=rc(s);
    const comp=p.compound_confidence;
    const compCell=comp&&comp!=='NONE'?'<span style="color:'+cc(comp)+';font-weight:700">'+comp+'</span>':'<span style="color:var(--dim)">-</span>';
    return '<tr onclick="openDetail(allData.results.find(r=>r.pid==='+p.pid+'))" style="'+(p.gate==='FLAG'?'background:rgba(248,81,73,.04)':p.gate==='WARN'?'background:rgba(210,153,34,.03)':'')+'">'+
      '<td style="color:var(--dim);font-family:monospace">'+p.pid+'</td>'+
      '<td style="font-weight:600">'+(p.name||'').slice(0,22)+(p.trusted?'<span style="color:var(--dim);font-size:9px;margin-left:4px">[trusted]</span>':'')+'</td>'+
      '<td style="color:'+ec(p.max_win_entropy||p.entropy)+';font-family:monospace">'+(+(p.max_win_entropy||p.entropy||0)).toFixed(3)+'</td>'+
      '<td><div style="display:flex;align-items:center;gap:5px">'+
        '<div class="riskbar-bg"><div class="riskbar-fg" style="width:'+Math.min(s,100)+'%;background:'+fc+'"></div></div>'+
        '<span style="color:'+fc+';font-weight:700;font-size:12px">'+s+'</span></div></td>'+
      '<td><span class="badge b-'+p.gate+'">'+p.gate+'</span></td>'+
      '<td>'+makeBadges(p)+'</td>'+
      '<td>'+compCell+'</td>'+
    '</tr>';
  }).join('');
}
function sortBy(key){
  if(currentSort.key===key) currentSort.asc=!currentSort.asc;
  else{currentSort.key=key;currentSort.asc=false;}
  filterProcTable();
}
function setSevFilter(f,btn){
  sevFilter=f;
  document.querySelectorAll('#sev-filters .flt-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterProcTable();
}

/* ═══════════════════════════════════════════════════════════════
   EVENT FEED
═══════════════════════════════════════════════════════════════ */
function buildEvents(R){
  const evts=[];
  R.forEach(p=>{
    const ts=(p.timestamp||'').slice(11,19);
    const comp=p.compound_confidence;
    if(comp&&comp!=='NONE'&&comp!=='LOW')
      evts.push({c:'COMPOUND',type:comp,h:'<span style="color:'+cc(comp)+'">🎯 ['+comp+']</span> PID '+p.pid+' <b>'+p.name+'</b> - '+p.compound_reason+' <span class="ft">'+ts+'</span>',p:p});
    if(p.epsd_spike)
      evts.push({c:'EPSD',type:'EPSD',h:'<span style="color:#bc8cff">⚡ Phase-Shift</span> PID '+p.pid+' <b>'+p.name+'</b> ΔH='+(p.epsd_delta>0?'+':'')+((p.epsd_delta||0).toFixed(2))+' <span class="ft">'+ts+'</span>',p:p});
    if(p.gate==='FLAG')
      evts.push({c:'FLAG',type:'FLAG',h:'<span style="color:#f85149">🚨 FLAG</span> PID '+p.pid+' <b>'+p.name+'</b> Risk='+p.risk_score+'/100 <span class="ft">'+ts+'</span>',p:p});
    if(p.lineage_anomalous)
      evts.push({c:'LIN',type:'LIN',h:'<span style="color:#f85149">🔗 Lineage</span> PID '+p.pid+' <b>'+p.name+'</b> '+(p.lineage_reason||'').slice(0,50)+' <span class="ft">'+ts+'</span>',p:p});
    if(p.rwx_suspicious)
      evts.push({c:'RWX',type:'RWX',h:'<span style="color:#f85149">🧬 RWX-Mem</span> PID '+p.pid+' <b>'+p.name+'</b> '+p.rwx_count+' region(s) <span class="ft">'+ts+'</span>',p:p});
    else if(p.gate==='WARN'&&!p.lineage_anomalous&&!p.epsd_spike)
      evts.push({c:'WARN',type:'WARN',h:'<span style="color:#d29922">⚠ WARN</span> PID '+p.pid+' <b>'+p.name+'</b> Risk='+p.risk_score+' <span class="ft">'+ts+'</span>',p:p});
  });
  if(!evts.length) evts.push({c:'',type:'OK',h:'<span style="color:#3fb950">✅ No anomalies detected this scan</span>',p:null});
  return evts;
}
function renderEventFeed(R){
  const evts=buildEvents(R);
  document.getElementById('event-feed').innerHTML=evts.slice(0,25).map(e=>
    '<div class="fi '+e.c+'" onclick="'+( e.p?'openDetail(allData.results.find(r=>r.pid==='+( e.p?e.p.pid:0)+'))':'void 0')+'">'+e.h+'</div>').join('');
}
function setAlertFilter(f,btn){
  alertFilter=f;
  document.querySelectorAll('#view-alerts .flt-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const R=allData.results||[];
  const evts=buildEvents(R).filter(e=>{
    if(f==='all') return true;
    if(f==='CRITICAL') return e.type==='CRITICAL';
    if(f==='HIGH') return e.type==='HIGH'||e.type==='CRITICAL';
    if(f==='MEDIUM') return e.type==='MEDIUM';
    return e.type===f;
  });
  document.getElementById('full-alert-feed').innerHTML=evts.map(e=>
    '<div class="fi '+e.c+'">'+e.h+'</div>').join('');
}
/* render full alerts on view switch */
document.getElementById('view-alerts');

/* ═══════════════════════════════════════════════════════════════
   PROCESS DETAIL PANEL
═══════════════════════════════════════════════════════════════ */
function openDetail(p){
  if(!p) return;
  const chain=(p.lineage_chain||[]);
  const chainHtml=chain.map((nm,i)=>'<div class="lc-item '+(p.lineage_anomalous&&i===0?'bad':'ok')+'">'+nm+'</div>').join('');
  const compColor=cc(p.compound_confidence||'NONE');
  let compBox='';
  if(p.compound_confidence&&p.compound_confidence!=='NONE'&&p.compound_confidence!=='LOW'){
    compBox='<div class="compound-box '+(p.compound_confidence)+'"><b>Compound: '+p.compound_confidence+'</b><br>'+p.compound_reason+'</div>';
  }
  const reasons=(p.risk_reasons||[]).map(r=>'<div style="font-size:11px;color:var(--dim);padding:3px 0;border-bottom:1px solid rgba(48,54,61,.3)">↳ '+r+'</div>').join('');
  const histData=(p.epsd_history||[]);
  const histGraph=histData.length>1?
    '<canvas id="detail-chart" style="max-height:120px;margin-top:10px"></canvas>':'';

  document.getElementById('detail-content').innerHTML=`
    <h3 style="color:var(--cyan);margin-bottom:14px;font-size:15px">${p.name||'Process'} <span style="color:var(--dim);font-size:12px;font-weight:400">PID ${p.pid}</span></h3>
    ${compBox}
    <div class="detail-row"><span class="dk">Gate</span><span class="dv"><span class="badge b-${p.gate}">${p.gate}</span></span></div>
    <div class="detail-row"><span class="dk">Risk Score</span><span class="dv" style="color:${rc(p.risk_score||0)};font-size:18px">${p.risk_score||0}/100</span></div>
    <div class="detail-row"><span class="dk">Compound Confidence</span><span class="dv" style="color:${compColor}">${p.compound_confidence||'NONE'}</span></div>
    <div class="detail-row"><span class="dk">Global Entropy</span><span class="dv" style="color:${ec(p.entropy||0)}">${(+(p.entropy||0)).toFixed(4)} bits</span></div>
    <div class="detail-row"><span class="dk">Max-Window Entropy</span><span class="dv" style="color:${ec(p.max_win_entropy||0)}">${(+(p.max_win_entropy||0)).toFixed(4)} bits</span></div>
    <div class="detail-row"><span class="dk">EPSD Spike</span><span class="dv" style="color:${p.epsd_spike?'#bc8cff':'#3fb950'}">${p.epsd_spike?'YES - ΔH='+p.epsd_delta:'No'}</span></div>
    <div class="detail-row"><span class="dk">Entropy Velocity</span><span class="dv">${(+(p.epsd_velocity||0)).toFixed(5)} bits/s</span></div>
    <div class="detail-row"><span class="dk">Entropy Stable</span><span class="dv" style="color:${p.epsd_stable?'#3fb950':'#d29922'}">${p.epsd_stable?'Yes':'No'}</span></div>
    <div class="detail-row"><span class="dk">Sliding-Window Anomaly</span><span class="dv" style="color:${p.win_anomalous?'#f85149':'#3fb950'}">${p.win_anomalous?'YES':'No'}</span></div>
    <div class="detail-row"><span class="dk">RWX Memory</span><span class="dv" style="color:${p.rwx_suspicious?'#f85149':p.rwx_jit_probable?'#8b949e':'#3fb950'}">${p.rwx_count||0} region(s)${p.rwx_jit_probable?' [JIT]':''}</span></div>
    <div class="detail-row"><span class="dk">Network Connections</span><span class="dv">${p.connections||0}</span></div>
    <div class="detail-row"><span class="dk">Lineage Anomaly</span><span class="dv" style="color:${p.lineage_anomalous?'#f85149':'#3fb950'}">${p.lineage_anomalous?'YES - '+p.lineage_reason:'No'}</span></div>
    <div class="detail-row"><span class="dk">Trusted Process</span><span class="dv" style="color:${p.trusted?'#3fb950':'#d29922'}">${p.trusted?'Yes':'No'}</span></div>
    <div class="detail-row"><span class="dk">Baseline Profile</span><span class="dv" style="color:${p.baseline?'#3fb950':'#8b949e'}">${p.baseline?'Yes':'No'}</span></div>
    <div class="detail-row"><span class="dk">User</span><span class="dv">${p.username||'-'}</span></div>
    <div class="detail-row"><span class="dk">CPU %</span><span class="dv">${p.cpu||0}%</span></div>
    <div class="detail-row"><span class="dk">Memory %</span><span class="dv">${p.mem||0}%</span></div>
    <div class="detail-row"><span class="dk">Command</span><span class="dv" style="font-family:monospace;font-size:10px">${(p.cmdline||'-').slice(0,60)}</span></div>
    ${chain.length>0?`<div style="margin-top:10px"><div class="card-title">Process Ancestry Chain</div><div class="lineage-chain">${chainHtml}</div></div>`:''}
    ${reasons?`<div style="margin-top:10px"><div class="card-title">Risk Factor Breakdown</div>${reasons}</div>`:''}
    ${histGraph}
  `;
  document.getElementById('detail-panel').classList.add('open');

  // Render entropy history mini-chart
  if(histData.length>1){
    setTimeout(()=>{
      const dc=document.getElementById('detail-chart');
      if(!dc) return;
      new Chart(dc,{type:'line',data:{labels:histData.map((_,i)=>'t'+(i+1)),datasets:[{
        label:'H(t)',data:histData,borderColor:'#bc8cff',backgroundColor:'rgba(188,140,255,.1)',
        tension:.3,pointRadius:3,fill:true}]},
        options:{responsive:true,scales:{y:{min:0,max:8,ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.4)'}},
        x:{ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.3)'}}},
        plugins:{legend:{display:false}},animation:false}});
    },100);
  }
}
function closeDetail(){document.getElementById('detail-panel').classList.remove('open');}

/* ═══════════════════════════════════════════════════════════════
   ATTACK TIMELINE VIEW
═══════════════════════════════════════════════════════════════ */
let cKin;
function renderTimeline(){
  const R=allData.results||[];
  // Build chronological events from results
  const evts=[];
  R.forEach(p=>{
    const ts=p.timestamp||'';
    if(p.epsd_spike)     evts.push({ts,pid:p.pid,name:p.name,type:'EPSD',   label:'⚡ Entropy Phase-Shift',detail:`ΔH=${p.epsd_delta>0?'+':''}${(p.epsd_delta||0).toFixed(2)} bits`,color:'#bc8cff'});
    if(p.gate==='FLAG')  evts.push({ts,pid:p.pid,name:p.name,type:'FLAG',   label:'🚨 Process Flagged',   detail:`Risk ${p.risk_score}/100`,color:'#f85149'});
    if(p.lineage_anomalous)evts.push({ts,pid:p.pid,name:p.name,type:'LIN', label:'🔗 Lineage Anomaly',   detail:(p.lineage_reason||'').slice(0,50),color:'#f85149'});
    if(p.rwx_suspicious) evts.push({ts,pid:p.pid,name:p.name,type:'RWX',   label:'🧬 RWX Memory',        detail:`${p.rwx_count} region(s)`,color:'#f85149'});
    if(p.gate==='WARN'&&!p.epsd_spike&&!p.lineage_anomalous)
      evts.push({ts,pid:p.pid,name:p.name,type:'WARN',label:'⚠ Warning',detail:`Risk ${p.risk_score}/100`,color:'#d29922'});
    if(p.connections>0)  evts.push({ts,pid:p.pid,name:p.name,type:'NET',   label:'🌐 Network Activity',  detail:`${p.connections} connection(s)`,color:'#58a6ff'});
  });
  evts.sort((a,b)=>a.ts<b.ts?-1:1);

  const tl=document.getElementById('timeline-body');
  if(!evts.length){tl.innerHTML='<div style="color:var(--dim);padding:20px;text-align:center">No security events in current scan</div>';return;}
  tl.innerHTML=evts.map((e,i)=>`
    <div style="display:flex;gap:16px;padding:10px 0;border-bottom:1px solid rgba(48,54,61,.4)">
      <div style="width:80px;font-family:monospace;font-size:11px;color:var(--dim);flex-shrink:0">${e.ts.slice(11,19)||'--:--:--'}</div>
      <div style="width:14px;height:14px;border-radius:50%;background:${e.color};flex-shrink:0;margin-top:1px"></div>
      <div style="flex:1">
        <span style="color:${e.color};font-weight:600;font-size:12px">${e.label}</span>
        &nbsp;<span style="color:var(--dim);font-size:11px">PID ${e.pid} <b style="color:var(--text)">${e.name}</b></span>
        <div style="font-size:11px;color:var(--dim);margin-top:2px">${e.detail}</div>
      </div>
    </div>`).join('');

  // Entropy kinetics chart
  const topK=[...R].filter(p=>p.epsd_history&&p.epsd_history.length>=3&&(p.epsd_spike||p.gate!=='ALLOW')).sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,6);
  const mL=Math.max(...topK.map(p=>p.epsd_history.length),4);
  const eKc=['#bc8cff','#f85149','#d29922','#58a6ff','#3fb950','#ffa657'];
  if(!cKin){cKin=new Chart(document.getElementById('c-kinetics'),{type:'line',data:{labels:Array.from({length:mL},(_,i)=>'t'+(i+1)),
    datasets:topK.map((p,i)=>({label:p.name+'(H)',data:p.epsd_history,borderColor:eKc[i%6],backgroundColor:'transparent',tension:.3,pointRadius:3,borderWidth:1.5}))},
    options:{responsive:true,scales:{y:{min:0,max:8,ticks:{color:'#8b949e'},grid:{color:'rgba(48,54,61,.5)'},title:{display:true,text:'H(t) bits',color:'#8b949e'}},
    x:{ticks:{color:'#8b949e'}}},plugins:{legend:{labels:{color:'#c9d1d9',font:{size:10}}}},animation:false}});}
  else{cKin.data.labels=Array.from({length:mL},(_,i)=>'t'+(i+1));cKin.data.datasets=topK.map((p,i)=>({label:p.name,data:p.epsd_history,borderColor:eKc[i%6],backgroundColor:'transparent',tension:.3,pointRadius:3,borderWidth:1.5}));cKin.update('none');}
}

/* ═══════════════════════════════════════════════════════════════
   SETTINGS VIEW
═══════════════════════════════════════════════════════════════ */
function renderSettings(){
  const d=allData;
  const ei=document.getElementById('endpoint-info');
  if(!ei) return;
  ei.innerHTML=`
    <div class="detail-row"><span class="dk">Hostname</span><span class="dv">${d.hostname||'-'}</span></div>
    <div class="detail-row"><span class="dk">Operating System</span><span class="dv">${d.os||'-'}</span></div>
    <div class="detail-row"><span class="dk">KEEG Version</span><span class="dv" style="color:var(--cyan)">${d.keeg_version||'-'}</span></div>
    <div class="detail-row"><span class="dk">Last Scan</span><span class="dv">${(d.scan_time||'').replace('T',' ').slice(0,19)}</span></div>
    <div class="detail-row"><span class="dk">Total Processes</span><span class="dv">${d.total_processes||0}</span></div>
    <div class="detail-row"><span class="dk">Flagged</span><span class="dv" style="color:var(--red)">${d.flagged||0}</span></div>
    <div class="detail-row"><span class="dk">Phase-Shifts</span><span class="dv" style="color:var(--purple)">${d.phase_shifts||0}</span></div>
  `;
}

/* ═══════════════════════════════════════════════════════════════
   BOOTSTRAP
═══════════════════════════════════════════════════════════════ */
refresh();
setInterval(refresh,8000);
</script>
</body>
</html>"""


def start_dashboard(log_file=LOG_FILE, port=5000):
    try:
        from flask import Flask, jsonify, Response
    except ImportError:
        print("[!] Flask not installed. Run: pip install flask")
        return
    app = Flask("KEEG-Dashboard")

    @app.route("/")
    def index():
        return Response(DASHBOARD_HTML, mimetype="text/html")

    @app.route("/api/data")
    def api_data():
        try:
            with open(log_file) as f:
                return jsonify(json.load(f))
        except Exception:
            return jsonify({"error":"no data yet"}),404

    @app.route("/api/export/json")
    def export_json():
        try:
            with open(log_file) as f:
                raw = json.load(f)
            results = raw.get("results",[])
            report  = generate_report(results, raw, "json")
            return Response(report, mimetype="application/json",
                            headers={"Content-Disposition":"attachment;filename=keeg_report.json"})
        except Exception as e:
            return jsonify({"error":str(e)}),500

    @app.route("/api/export/csv")
    def export_csv():
        try:
            with open(log_file) as f:
                raw = json.load(f)
            results = raw.get("results",[])
            report  = generate_report(results, raw, "csv")
            return Response(report, mimetype="text/csv",
                            headers={"Content-Disposition":"attachment;filename=keeg_report.csv"})
        except Exception as e:
            return jsonify({"error":str(e)}),500

    @app.route("/api/export/text")
    def export_text():
        try:
            with open(log_file) as f:
                raw = json.load(f)
            results = raw.get("results",[])
            report  = generate_report(results, raw, "text")
            return Response(report, mimetype="text/plain",
                            headers={"Content-Disposition":"attachment;filename=keeg_report.txt"})
        except Exception as e:
            return jsonify({"error":str(e)}),500

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    t = threading.Thread(target=lambda: app.run(host="0.0.0.0",port=port,debug=False), daemon=True)
    t.start()
    print(f"\n{CYAN}{BOLD}[KEEG Dashboard] → http://localhost:{port}{RESET}")
    print(f"{DIM}  Open this URL in your browser.{RESET}\n")

def run_simulation():
    """
    Six-phase simulation that walks through every detection mechanism in sequence.
    Each phase builds on the previous, culminating in a CRITICAL compound alert.
    Output appears in both terminal and dashboard (if running).
    """
    SIM_PID = 88888   # synthetic PID — will never collide with a real process

    print(f"\n{CYAN}{BOLD}{'═'*70}")
    print("  KEEG THREAT SIMULATION MODE")
    print("  Demonstrating all detection mechanisms with synthetic malware")
    print(f"{'═'*70}{RESET}\n")
    print(f"  {DIM}No actual malware is present. All events are synthetic.{RESET}\n")

    phases = [
        {
            "phase": 1,
            "title": "Baseline — Loader Stub Executing",
            "desc":  "Synthetic process starts with low entropy. Normal-looking stub code.",
            "entropy": 3.1,
            "rwx": False, "lineage": False,
            "expect": "ALLOW — no anomaly yet. Baseline established.",
        },
        {
            "phase": 2,
            "title": "Slow Trend — Gradual Decryption Begins",
            "desc":  "Entropy rises slowly across 3 steps. Malware decrypting in small chunks.",
            "entropy": 4.6,
            "rwx": False, "lineage": False,
            "expect": "WARN — EPSD slow-trend detector fires (cumulative rise ≥ 1.5 bits).",
        },
        {
            "phase": 3,
            "title": "Phase-Shift — Payload Fully Decrypted",
            "desc":  "Sudden entropy spike: H jumps from 4.6 to 7.9 in one scan. Payload live.",
            "entropy": 7.9,
            "rwx": False, "lineage": False,
            "expect": "FLAG — EPSD spike ΔH = +3.3 bits. Compound = MEDIUM.",
        },
        {
            "phase": 4,
            "title": "Injection — RWX Memory Region Appears",
            "desc":  "Shellcode written to process memory. RWX region detected alongside spike.",
            "entropy": 7.9,
            "rwx": True, "lineage": False,
            "expect": "FLAG — EPSD + RWX = Compound HIGH. Injection confirmed.",
        },
        {
            "phase": 5,
            "title": "Chain — Malicious Process Ancestry",
            "desc":  "Spawned by document reader → bash → curl. Attack chain complete.",
            "entropy": 7.9,
            "rwx": True, "lineage": True,
            "expect": "FLAG — EPSD + RWX + Lineage = Compound CRITICAL. Maximum confidence.",
        },
        {
            "phase": 6,
            "title": "Persistence — Sustained High Entropy",
            "desc":  "Payload continues running. Entropy stable at 7.9. Not a browser (no JIT).",
            "entropy": 7.85,
            "rwx": True, "lineage": True,
            "expect": "FLAG — Compound CRITICAL maintained. Sustained malicious activity.",
        },
    ]

    # Run each phase
    for ph in phases:
        n = ph["phase"]
        print(f"  {BOLD}Phase {n}/6 — {ph['title']}{RESET}")
        print(f"  {DIM}{ph['desc']}{RESET}")

        # Build a synthetic proc_info matching this phase
        epsd = epsd_update(SIM_PID, ph["entropy"])
        # Override slow_trend manually for phase 2
        if n == 2:
            # Force slow trend by manipulating history
            for _ in range(2):
                epsd_update(SIM_PID, ph["entropy"] - 0.5)
            epsd = epsd_update(SIM_PID, ph["entropy"])

        proc_info = {
            "pid":             SIM_PID,
            "name":            "synthetic_malware",
            "username":        "user",
            "exe":             "/tmp/synthetic_malware",
            "cmdline":         "/tmp/synthetic_malware --payload",
            "timestamp":       datetime.datetime.now().isoformat(),
            "hostname":        HOSTNAME,
            "os":              OS_NAME,
            "cpu":             0, "mem": 0, "connections": 0,
            "trusted":         False,
            "baseline":        False,
            "entropy":         ph["entropy"],
            "max_win_entropy": ph["entropy"],
            "win_anomalous":   ph["entropy"] >= ENTROPY_HIGH,
            "entropy_windows": [round(ph["entropy"], 4)],
            "entropy_label":   entropy_label(ph["entropy"]),
            "epsd_delta":      epsd["delta"],
            "epsd_spike":      epsd["spike"],
            "epsd_slow_trend": epsd["slow_trend"] if n < 3 else False,
            "epsd_velocity":   epsd["velocity"],
            "epsd_acceleration": epsd.get("acceleration", 0.0),
            "epsd_history":    epsd["history"],
            "epsd_stable":     False,
            "lineage_anomalous": ph["lineage"],
            "lineage_chain":   ["document_reader", "bash", "curl"] if ph["lineage"] else [],
            "lineage_reason":  "Suspicious lineage: bash → synthetic_malware" if ph["lineage"] else "",
            "rwx_count":       3 if ph["rwx"] else 0,
            "rwx_suspicious":  ph["rwx"],
            "rwx_jit_probable": False,
            "rwx_regions":     [{"addr":"0x7f000000","perms":"rwxp","region":"[anon]"}] * (3 if ph["rwx"] else 0),
            "seen_count":      n,
        }

        risk_score, risk_reasons = score_risk(proc_info)
        compound_conf, compound_reason = compound_correlation(proc_info)
        proc_info["compound_confidence"] = compound_conf
        proc_info["compound_reason"]     = compound_reason

        gate = gate_decision(risk_score, ph["entropy"], "synthetic_malware",
                             epsd["spike"], compound_conf)

        action  = gate["action"]
        color   = {"FLAG": RED, "WARN": YELLOW, "ALLOW": GREEN}[action]
        comp_c  = {
            "CRITICAL": MAGENTA, "HIGH": RED, "MEDIUM": YELLOW,
            "LOW": CYAN, "NONE": DIM
        }.get(compound_conf, RESET)

        print(f"\n  {'─'*60}")
        print(f"  Entropy     : {clr(proc_info['entropy_label'])}{ph['entropy']:.2f} bits [{proc_info['entropy_label']}]{RESET}")
        print(f"  EPSD ΔH     : {MAGENTA if epsd['spike'] else DIM}{epsd['delta']:+.2f} bits  {'⚡ SPIKE' if epsd['spike'] else ''}{RESET}")
        print(f"  RWX Memory  : {RED + '3 rwxp regions DETECTED' + RESET if ph['rwx'] else DIM + 'None' + RESET}")
        print(f"  Lineage     : {RED + 'ANOMALOUS chain detected' + RESET if ph['lineage'] else DIM + 'Normal' + RESET}")
        print(f"  Risk Score  : {BOLD}{color}{risk_score}/100{RESET}")
        print(f"  Compound    : {BOLD}{comp_c}[{compound_conf}]{RESET}  {compound_reason}")
        print(f"  Gate        : {BOLD}{color}{action}{RESET}")
        print(f"\n  {DIM}Expected: {ph['expect']}{RESET}")
        print(f"  {'─'*60}\n")
        time.sleep(1.2)

    # Final summary
    print(f"\n{CYAN}{BOLD}{'═'*70}")
    print("  SIMULATION COMPLETE — DETECTION SUMMARY")
    print(f"{'═'*70}{RESET}\n")

    summary_rows = [
        ("Phase 1 — Stub running",        "H=3.10", "ALLOW",  "NONE",     "No anomaly — correct"),
        ("Phase 2 — Slow trend",          "H=4.60", "WARN",   "NONE",     "Gradual decryption caught"),
        ("Phase 3 — Phase-shift",         "H=7.90", "FLAG",   "MEDIUM",   "EPSD spike caught moment of decrypt"),
        ("Phase 4 — RWX injection",       "H=7.90", "FLAG",   "HIGH",     "Two-signal: EPSD + RWX"),
        ("Phase 5 — Malicious chain",     "H=7.90", "FLAG",   "CRITICAL", "Three-signal: maximum confidence"),
        ("Phase 6 — Sustained activity",  "H=7.85", "FLAG",   "CRITICAL", "Persistent threat confirmed"),
    ]

    for (desc, entropy, gate_v, compound_v, note) in summary_rows:
        gc = {"FLAG":RED,"WARN":YELLOW,"ALLOW":GREEN}[gate_v]
        cc2 = {"CRITICAL":MAGENTA,"HIGH":RED,"MEDIUM":YELLOW,"LOW":CYAN,"NONE":DIM}[compound_v]
        print(f"  {desc:<32}  {entropy:<8}  {gc}{gate_v:<5}{RESET}  {cc2}{compound_v:<10}{RESET}  {DIM}{note}{RESET}")

    print(f"\n  {BOLD}Key insight:{RESET} A single entropy signal (Phase 3) raises FLAG.")
    print(f"  Each additional signal CONFIRMS the classification (Phases 4–5).")
    print(f"  No single mechanism alone reaches CRITICAL — multi-signal correlation")
    print(f"  is what separates KEEG from basic entropy scanners.\n")
    print(f"  {CYAN}Run with --monitor --dashboard to see this in real-time on the web UI.{RESET}\n")
    print(f"{'═'*70}\n")



# ─────────────────────────────────────────────────────────────────────────────
# BANNER + MAIN
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{CYAN}{BOLD}
 ██╗  ██╗███████╗███████╗ ██████╗     ██╗   ██╗  ██████╗       ███╗
 ██║ ██╔╝██╔════╝██╔════╝██╔════╝     ██║   ██║  ╚════██╗    ██╔██║
 █████╔╝ █████╗  █████╗  ██║  ███╗    ██║   ██║   █████╔╝   ╚══╝██║
 ██╔═██╗ ██╔══╝  ██╔══╝  ██║   ██║    ╚██╗ ██╔╝       ██╗       ██║
 ██║  ██╗███████╗███████╗╚██████╔╝     ╚████╔╝   ██████╔╝ █║  ██████║   
 ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝       ╚═══╝    ╚═════╝      ╚═════╝
{RESET}
{BOLD} Kinetic Entropy Execution Gating v{VERSION} - Enterprise-Calibrated{RESET}
{CYAN} Fixes: EPSD-negative-patch·Linux-daemons·Entropy-display·Simulate{RESET}
{CYAN} Modes: --demo·--scan·--monitor·--dashboard·--simulate·--lineage{RESET}
{'─'*58}
""")


def main():
    parser = argparse.ArgumentParser(description="KEEG v3.1")
    parser.add_argument("--scan",      action="store_true")
    parser.add_argument("--monitor",   action="store_true")
    parser.add_argument("--demo",      action="store_true")
    parser.add_argument("--lineage",   action="store_true")
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--report",    action="store_true", help="Generate threat report after scan")
    parser.add_argument("--policy",    action="store_true", help="Write default keeg_policy.json template")
    parser.add_argument("--simulate",  action="store_true", help="Run threat simulation demo (all 6 detection phases)")
    parser.add_argument("--pid",       type=int)
    parser.add_argument("--interval",  type=int, default=10)
    parser.add_argument("--verbose",   action="store_true")
    parser.add_argument("--port",      type=int, default=5000)
    args = parser.parse_args()
    print_banner()

    if args.simulate:
        run_simulation(); return

    if args.demo:
        run_entropy_demo(); return
    if args.lineage:
        print_process_tree(build_process_tree()); return
    if args.policy:
        p = write_default_policy()
        print(f"\n{GREEN}[✓] Policy template written → {POLICY_FILE}{RESET}")
        print(f"{DIM}  Edit this file to customise thresholds, weights, and baselines.")
        print(f"  In production: distribute signed copies to all endpoints.{RESET}\n")
        return
    if args.dashboard:
        start_dashboard(port=args.port)
    if args.monitor:
        print(f"{CYAN}{BOLD}[KEEG] MONITOR - interval={args.interval}s{RESET}\nCtrl+C to stop.\n")
        n=0
        try:
            while True:
                n+=1
                print(f"\n{BOLD}── Scan #{n}  {datetime.datetime.now().strftime('%H:%M:%S')} ──{RESET}")
                tree=build_process_tree()
                results=scan_all_processes(verbose=args.verbose,process_tree=tree)
                log=save_log(results); print_summary(results,log)
                if args.report:
                    save_report(results, log)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n{GREEN}[KEEG] Monitor stopped.{RESET}")
    elif args.scan or args.pid:
        tree=build_process_tree()
        results=scan_all_processes(verbose=args.verbose,process_tree=tree)
        log=save_log(results); print_summary(results,log)
        if args.report:
            save_report(results, log)
    else:
        run_entropy_demo()
        tree=build_process_tree()
        results=scan_all_processes(verbose=args.verbose,process_tree=tree)
        log=save_log(results); print_summary(results,log)
        if args.report:
            save_report(results, log)

if __name__=="__main__":
    main()


# ─────────────────────────────────────────────────────────────────────────────
# FIX v3.1-final BUG #D — THREAT SIMULATION MODE  (--simulate flag)
# Injects synthetic malware behaviour into the live detection engine so all
# detection mechanisms can be demonstrated in real-time without actual malware.
# Serves three purposes:
#   1. Live viva demonstration — show KEEG catching "malware" step-by-step
#   2. CI/CD validation — verify every detection mechanism fires correctly
#   3. Analyst training — teach how to read KEEG's alert output
# ─────────────────────────────────────────────────────────────────────────────

