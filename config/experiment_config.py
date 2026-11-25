"""
Shared Experiment Configuration and Team Interface Contract.

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Authors: Ismail Nooruddin, Hassaan Ul Qadir, Munir Tariq, Rayyan Alvi

Purpose:
--------
This module acts as the central "rulebook" shared across all four project roles:
  - Member A (Attacker, Decoy Sandbox, Benign Activity)
  - Member B (Lightweight inotify + SIGSTOP Defender)
  - Member C (Synthetic CPU Workload, Linux Scheduler/cgroup Setups, Runner)
  - Member D (Measurements Aggregation, Plots, Summary Tables)

By importing paths, thresholds, scheduler profile names, and CSV schemas from
this single file, all four modules remain strictly compatible without hardcoded
magic numbers or mismatched file paths.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple


# ==============================================================================
# 1. REPOSITORY & RESULTS DIRECTORY PATHS
# ==============================================================================

# Root directory of the git repository (resolved dynamically relative to this file)
REPO_ROOT: Path = Path(__file__).resolve().parent.parent

# Main directory where all experiment outputs are saved
RESULTS_DIR: Path = REPO_ROOT / "results"

# Subdirectories for raw trial logs, aggregated summary tables, and final figures
RAW_RESULTS_DIR: Path = RESULTS_DIR / "raw"
PROCESSED_RESULTS_DIR: Path = RESULTS_DIR / "processed"
FIGURES_DIR: Path = RESULTS_DIR / "figures"

# Standard output CSV path where Member C's runner appends trial rows
# and from which Member D's analysis scripts read experimental data
RAW_TRIALS_CSV: Path = RAW_RESULTS_DIR / "trials.csv"


# ==============================================================================
# 2. ISOLATED RUNTIME SANDBOX & TELEMETRY PATHS (NATIVE LINUX /tmp)
# ==============================================================================
# IMPORTANT: On WSL2, the sandbox MUST live on the native Linux filesystem (/tmp)
# rather than /mnt/c/ (Windows NTFS). Native ext4 ensures accurate inotify kernel
# events, realistic Linux disk I/O speed, and zero interference with OneDrive.

# Top-level isolated directory for all decoy files and per-trial telemetry.
# On Linux/WSL2 (`os.name == "posix"`), this is strictly `/tmp/os_defense_sandbox`.
# On Windows (`os.name == "nt"`), it falls back to the OS temp directory so unit tests can also run locally.
SANDBOX_ROOT: Path = (
    Path("/tmp/os_defense_sandbox")
    if os.name != "nt"
    else Path(tempfile.gettempdir()) / "os_defense_sandbox"
)

# Directory containing the dummy decoy files watched by Member B's defender
# and targeted by Member A's XOR ransomware simulator
SANDBOX_FILES_DIR: Path = SANDBOX_ROOT / "files"

# JSON manifest storing baseline SHA-256 hashes of clean decoy files
# used to verify and count exact file damage after each trial
SANDBOX_MANIFEST_PATH: Path = SANDBOX_ROOT / "manifest.json"

# Directory where processes write structured per-trial timing/status JSON files
TELEMETRY_DIR: Path = SANDBOX_ROOT / "telemetry"

# Individual telemetry JSON files written during each trial
ATTACKER_TELEMETRY_PATH: Path = TELEMETRY_DIR / "attacker_telemetry.json"
DEFENDER_TELEMETRY_PATH: Path = TELEMETRY_DIR / "defender_telemetry.json"
WORKLOAD_TELEMETRY_PATH: Path = TELEMETRY_DIR / "workload_telemetry.json"
BENIGN_TELEMETRY_PATH: Path = TELEMETRY_DIR / "benign_telemetry.json"

# Flag file created by the defender as soon as its inotify watch is active,
# signaling to the runner that it is safe to launch the attacker
DEFENDER_READY_FLAG: Path = TELEMETRY_DIR / "defender_ready.flag"


# ==============================================================================
# 3. DECOY SANDBOX & ATTACK SIMULATOR SETTINGS (MEMBER A)
# ==============================================================================

# Number of dummy decoy files created inside SANDBOX_FILES_DIR before each trial.
# 300 files is small enough to reset in <0.2s, yet large enough that an unprotected
# system suffers heavy damage while a fast defender stops the attack after a few files.
DECOY_FILE_COUNT: int = 300

# Size of each decoy file in bytes (64 KB -> ~19.2 MB total sandbox size in /tmp)
DECOY_FILE_SIZE_BYTES: int = 64 * 1024

# Naming convention for decoy files: decoy_0000.dat ... decoy_0299.dat
DECOY_FILE_PREFIX: str = "decoy_"
DECOY_FILE_EXT: str = ".dat"

# Known magic header placed at the start of every clean decoy file.
# If this header is altered (or the file's SHA-256 changes), the file is damaged.
DECOY_MAGIC_HEADER: bytes = b"OS_DECOY_CLEAN_V1\n"

# Single-byte XOR key (0xAA = 10101010 in binary) used by ransomware_sim.py
# to scramble decoy file contents in place
XOR_KEY: int = 0xAA

# Small delay (in seconds) between consecutive file scrambles in ransomware_sim.py.
# 2 ms (0.002s) spreads 300 files across ~0.6s+ of wall-clock time, giving clear
# resolution between fast and delayed defender wakeups under heavy CPU load.
ATTACK_INTER_FILE_DELAY_S: float = 0.002

# Parameters for benign_activity.py (normal user/app file activity simulator)
# Edits 1 harmless file every 0.75s for 6.0s -> well below the burst threshold,
# ensuring a healthy defender triggers 0 false alarms.
BENIGN_INTERVAL_S: float = 0.75
BENIGN_DURATION_S: float = 6.0
BENIGN_FILE_PREFIX: str = "benign_note_"


# ==============================================================================
# 4. LIGHTWEIGHT DEFENDER SETTINGS (MEMBER B)
# ==============================================================================

# Sliding-window burst detection rule:
# If at least BURST_EVENT_THRESHOLD distinct files are modified within
# BURST_WINDOW_MS milliseconds, the defender declares an attack and sends SIGSTOP.
BURST_EVENT_THRESHOLD: int = 5
BURST_WINDOW_MS: int = 500

# Poll interval / timeout (in milliseconds) when reading inotify events
DEFENDER_POLL_TIMEOUT_MS: int = 50


# ==============================================================================
# 5. SYNTHETIC CPU WORKLOAD & TRIAL SAFETY SETTINGS (MEMBER C)
# ==============================================================================

# Number of inner math/hash loop iterations constituting 1 "work unit" in cpu_stress.py.
# Workers count completed work units so throughput (units/sec) is directly comparable.
WORKLOAD_CHUNK_ITERATIONS: int = 50_000

# Hard watchdog time limit (in seconds) for any single trial.
# CRITICAL SAFETY FEATURE: Prevents a real-time (chrt) task or frozen process
# from ever hanging the terminal or WSL2 session.
TRIAL_TIMEOUT_S: float = 15.0

# Maximum time (in seconds) the runner waits for DEFENDER_READY_FLAG before aborting
DEFENDER_READY_TIMEOUT_S: float = 5.0


# ==============================================================================
# 6. LINUX SCHEDULER SETUPS & PARAMETERS (MEMBERS C & D)
# ==============================================================================

# Number of repeated trials per scheduler configuration (averaged during analysis)
TRIALS_PER_SETUP: int = 20

# Canonical setup identifiers used across runner.py, trials.csv, and plot_results.py
SCHEDULER_SETUPS: Tuple[str, ...] = (
    "baseline_no_load",       # Reference: Defender + Attacker with NO heavy CPU workload
    "baseline_workload_solo", # Reference: Heavy CPU workload running alone (0% slowdown baseline)
    "default",                # Setup 1: Standard Linux CFS (no priority/cgroup/affinity tweaks)
    "nice",                   # Setup 2: CFS nice priority (Defender -20, Workload +19)
    "chrt",                   # Setup 3: POSIX real-time scheduling (Defender SCHED_FIFO prio 50)
    "cgroup_weight",          # Setup 4: cgroup v2 proportional shares (Defender 1000 vs Workload 100)
    "cgroup_max",             # Setup 5: cgroup v2 hard CPU bandwidth quota on Workload (50% cap)
    "taskset",                # Setup 6: CPU core affinity pinning (Defender Core 0, Workload Cores 1..N-1)
)

# Detailed configuration dictionary for each scheduler setup
SCHEDULER_PARAMS: Dict[str, Dict[str, Any]] = {
    "baseline_no_load": {
        "description": "Defender and attacker without competing CPU workload",
        "run_workload": False,
        "run_defender": True,
    },
    "baseline_workload_solo": {
        "description": "Synthetic CPU workload running alone to establish 100% throughput",
        "run_workload": True,
        "run_defender": False,
    },
    "default": {
        "description": "Default Linux Completely Fair Scheduler (CFS) with equal nice=0",
        "defender_nice": 0,
        "workload_nice": 0,
    },
    "nice": {
        "description": "High CFS priority for defender (nice -20) and low for workload (nice +19)",
        "defender_nice": -20,
        "workload_nice": 19,
    },
    "chrt": {
        "description": "Real-time SCHED_FIFO priority 50 for defender",
        "defender_rt_policy": "fifo",  # Used with `chrt --fifo 50`
        "defender_rt_priority": 50,
    },
    "cgroup_weight": {
        "description": "cgroup v2 cpu.weight favouring defender (1000) over workload (100)",
        "defender_cgroup_name": "os_proj_defender",
        "workload_cgroup_name": "os_proj_workload",
        "defender_cpu_weight": 1000,
        "workload_cpu_weight": 100,
    },
    "cgroup_max": {
        "description": "cgroup v2 cpu.max capping heavy workload at 50% total CPU capacity",
        "defender_cgroup_name": "os_proj_defender",
        "workload_cgroup_name": "os_proj_workload",
        "workload_cpu_quota_pct": 50,   # 50% of all logical CPU cores
        "cgroup_period_us": 100_000,    # Standard 100ms (100,000 us) cgroup period
    },
    "taskset": {
        "description": "Pin defender to Core 0 and heavy workload to remaining cores (1..N-1)",
        "defender_cores": "0",
        "workload_cores": f"1-{max(1, (os.cpu_count() or 2) - 1)}",
    },
}


# ==============================================================================
# 7. SHARED CSV & TELEMETRY SCHEMAS (CONTRACT FOR ALL 4 MEMBERS)
# ==============================================================================

# Exact column order for results/raw/trials.csv
RAW_CSV_COLUMNS: Tuple[str, ...] = (
    "setup",                # One of SCHEDULER_SETUPS (e.g., "default", "nice", "chrt")
    "trial_id",             # Integer trial index (1 .. TRIALS_PER_SETUP)
    "mode",                 # Trial type: "attack" (ransomware_sim), "benign" (false alarm check), or "solo"
    "detected",             # Boolean: True if defender detected a burst and sent SIGSTOP
    "false_alarm",          # Boolean: True if defender triggered SIGSTOP during a "benign" trial
    "detection_delay_ms",   # Float: (freeze_time_ns - attack_start_ns) / 1e6 (or None/NaN if not applicable)
    "files_damaged",        # Integer: Exact count of decoy files modified/scrambled before freeze
    "total_decoy_files",    # Integer: Total decoy files in sandbox at trial start (DECOY_FILE_COUNT)
    "workload_throughput",  # Float: Total work units per second achieved by cpu_stress.py
    "timed_out",            # Boolean: True if trial hit TRIAL_TIMEOUT_S safety watchdog
    "notes",                # Optional string note or error diagnostic
)


# ==============================================================================
# 8. SAFETY & DIRECTORY HELPER FUNCTIONS
# ==============================================================================

def is_safe_sandbox_path(
    target_path: Path | str,
    sandbox_root: Path | str = SANDBOX_ROOT,
) -> bool:
    """
    Verify that `target_path` resolves strictly inside an isolated `/tmp/.../os_defense_sandbox` root.

    Why this exists:
    ----------------
    Member A's attack simulator scrambles files using XOR. This safety check guarantees
    that the simulator can NEVER accidentally modify or delete files outside the
    designated `/tmp/os_defense_sandbox` directory, even if a wrong path is passed.

    Parameters
    ----------
    target_path : Path | str
        The directory or file path to validate before reading/writing/deleting.
    sandbox_root : Path | str, optional
        The allowed sandbox root directory (defaults to `SANDBOX_ROOT`).

    Returns
    -------
    bool
        True if `sandbox_root` is safely inside `/tmp` (or system temp) with
        `"os_defense_sandbox"` in its path and `target_path` resolves inside it;
        False otherwise.
    """
    try:
        resolved_root = Path(sandbox_root).resolve()
        resolved_target = Path(target_path).resolve()

        # Check 1: The sandbox root directory must explicitly contain "os_defense_sandbox"
        # so an accidental root like "/" or "/tmp" is never accepted.
        if "os_defense_sandbox" not in resolved_root.parts:
            return False

        # Check 2: The sandbox root must live under /tmp or the OS temporary directory,
        # and NEVER inside /home, /mnt/c, or OneDrive.
        posix_root = resolved_root.as_posix()
        if "/mnt/c/" in posix_root or "OneDrive" in posix_root:
            return False

        sys_temp_posix = Path(tempfile.gettempdir()).resolve().as_posix()
        in_tmp = (
            posix_root.startswith("/tmp/")
            or "/tmp/os_defense_sandbox" in posix_root
            or posix_root.startswith(sys_temp_posix + "/")
        )
        if not in_tmp:
            return False

        # Check 3: Target path must be the sandbox root itself or a child path inside it
        return (
            resolved_target == resolved_root
            or resolved_root in resolved_target.parents
        )
    except (OSError, RuntimeError, ValueError):
        return False


def ensure_results_dirs() -> None:
    """
    Create `results/raw`, `results/processed`, and `results/figures` if they do not exist.
    Safe to call at the start of any runner or analysis script.
    """
    RAW_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
