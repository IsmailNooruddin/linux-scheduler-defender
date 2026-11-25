"""
Automated Trial Runner and Batch Orchestrator (Member C).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Munir Tariq (Member C)

Overview:
---------
This module runs the whole experiment. One *trial* is:

    1. Reset the decoy sandbox                          (Member A: sandbox_setup)
    2. Start the synthetic CPU workload under the setup's control   (cpu_stress + profiles)
    3. Start the defender under the setup's control, wait for its "ready" flag (Member B)
    4. Launch the attacker (or the benign script)       (Member A)
    5. Wait until the attacker is frozen (SIGSTOP), finishes, or the safety timeout hits
    6. Keep the workload running to a minimum measurement window, then stop everything
    7. Compute the metrics and append ONE row to results/raw/trials.csv

Trial types (`mode` column):
    attack : ransomware simulator vs defender  -> detection delay, files damaged
    benign : harmless file activity vs defender -> false-alarm rate
    solo   : workload alone, no defender        -> baseline throughput for slowdown %

Experimental-design decisions (good viva material):
---------------------------------------------------
  * Interleaved + shuffled order. Instead of "20 trials of setup A, then 20 of B ...",
    each *round* runs one trial of every setup in a random order. Slow drift (laptop
    heating up, background Windows activity, battery saver) then spreads evenly over all
    setups instead of silently favouring whichever ran first. The shuffle is seeded
    (`--seed`) so a run is reproducible.
  * Same measurement window everywhere. The workload always runs for at least
    `MIN_WORKLOAD_WINDOW_S` seconds, including the solo baseline, so throughput numbers
    are comparable. It is started *before* the defender and attacker so the defender has
    to wake up and react while the CPU is already saturated.
  * Infrastructure failures are not data. If a process cannot start, a scheduler control
    did not take effect, or the defender never becomes ready, the trial is retried and is
    never written as a "defender failed" row. Only real experimental outcomes (detected /
    not detected / timed out) reach the CSV.

Safety:
-------
  * Hard per-trial deadline (`TRIAL_TIMEOUT_S`) and, for the real-time `chrt` setup, an
    independent SCHED_FIFO-99 watchdog that SIGKILLs the defender (see profiles.py).
  * Every child runs in its own process group and is always cleaned up in a `finally`
    block (SIGKILL for frozen/stuck processes, then `wait()` so no zombies remain).
  * Ctrl+C / SIGTERM trigger the same cleanup, then remove the cgroups and the sandbox.

Command-Line Usage (needs root for nice/chrt/cgroups; use scripts/run_all_experiments.sh):
-------------------------------------------------------------------------------------------
  sudo "$(which python)" -m src.scheduler.runner --quick                 # 2-round smoke test
  sudo "$(which python)" -m src.scheduler.runner --fresh                 # full benchmark
  sudo "$(which python)" -m src.scheduler.runner --setups default chrt --trials 5
  python -m src.scheduler.runner --dry-run                               # show the schedule only
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Tuple

import psutil

from config.experiment_config import (
    ATTACKER_TELEMETRY_PATH,
    BENIGN_TELEMETRY_PATH,
    DEFENDER_READY_FLAG,
    DEFENDER_READY_TIMEOUT_S,
    DEFENDER_TELEMETRY_PATH,
    RAW_CSV_COLUMNS,
    RAW_TRIALS_CSV,
    REPO_ROOT,
    SCHEDULER_PARAMS,
    SCHEDULER_SETUPS,
    TRIAL_TIMEOUT_S,
    TRIALS_PER_SETUP,
    WORKLOAD_TELEMETRY_PATH,
    ensure_results_dirs,
)
from src.attacker.sandbox_setup import cleanup_sandbox, count_damaged_files, reset_sandbox
from src.scheduler import profiles
from src.scheduler.profiles import ROLE_DEFENDER, ROLE_WORKLOAD, ProfileError


# ==============================================================================
# 1. RUNNER SETTINGS
# ==============================================================================

# Benign (false-alarm) trials per setup. Each lasts ~BENIGN_DURATION_S, so a handful is enough
# to show whether any setup makes the defender trigger on normal activity.
BENIGN_TRIALS_PER_SETUP: int = 5

# The workload runs at least this long in EVERY trial (attack, benign and solo) so that
# throughput is measured over a comparable window.
MIN_WORKLOAD_WINDOW_S: float = 3.0

# Pause after the workload reports "running", so it reaches steady state (all cores busy)
# before the defender and attacker start.
WORKLOAD_WARMUP_S: float = 0.5

# How long to wait for the workload to publish its "running" telemetry.
WORKLOAD_START_TIMEOUT_S: float = 10.0

# After the attacker is seen frozen, how long to wait for the defender to write its telemetry.
DEFENDER_TELEMETRY_GRACE_S: float = 1.0

# Grace period between SIGTERM and SIGKILL when stopping a process politely.
TERMINATE_GRACE_S: float = 3.0

# The real-time watchdog fires this many seconds after TRIAL_TIMEOUT_S (last line of defence).
WATCHDOG_MARGIN_S: float = 5.0

# Poll interval of the wait loops (seconds).
POLL_INTERVAL_S: float = 0.005

# Failed infrastructure attempts per trial before the whole run is aborted.
MAX_INFRA_RETRIES: int = 2

# Default RNG seed for the shuffled trial order (printed at start-up for reproducibility).
DEFAULT_SEED: int = 4242

# Module names used to spot leftover processes from an earlier crashed run.
_PROJECT_MODULES: Tuple[str, ...] = (
    "src.workload.cpu_stress",
    "src.attacker.ransomware_sim",
    "src.attacker.benign_activity",
    "src.defender.defender",
)

MODE_ATTACK, MODE_BENIGN, MODE_SOLO = "attack", "benign", "solo"


class TrialInfrastructureError(RuntimeError):
    """The test harness (not the defender) failed; the trial must be retried, not recorded."""


# ==============================================================================
# 2. SMALL HELPERS
# ==============================================================================

def log(message: str) -> None:
    """Print a progress line immediately (stdout may be a pipe)."""
    print(message, flush=True)


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    """Read a telemetry JSON file; None if missing or momentarily unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _proc_state(pid: int) -> Optional[str]:
    """
    Kernel state letter of `pid` from `/proc/<pid>/stat` (`R`, `S`, `T` = stopped, `Z` = zombie ...).

    Returns None if the process no longer exists.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # The command name may contain spaces/parentheses, so split after the LAST ')'.
    return stat.rsplit(")", 1)[1].split()[0]


def _is_stopped(pid: int) -> bool:
    """True if the process is in the SIGSTOP-ed state (`T`) or tracing-stop (`t`)."""
    return _proc_state(pid) in ("T", "t")


def _kill_group(proc: Optional[subprocess.Popen], sig: int = signal.SIGKILL) -> None:
    """Send `sig` to the whole process group of `proc` (each child runs in its own session)."""
    if proc is None:
        return
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _stop_process(proc: Optional[subprocess.Popen], grace_s: float = TERMINATE_GRACE_S) -> None:
    """SIGTERM the process group, wait `grace_s`, then SIGKILL; always reaps the child (no zombies)."""
    if proc is None:
        return
    if proc.poll() is None:
        _kill_group(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            pass
    _kill_group(proc, signal.SIGKILL)  # also reaps any stragglers left in the group
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass


def _fmt(value: Any, digits: int = 2) -> str:
    """Compact formatting for progress lines."""
    if value is None or value == "":
        return "-"
    return f"{value:.{digits}f}" if isinstance(value, float) else str(value)


def find_stale_project_processes() -> List[Tuple[int, str]]:
    """Return `(pid, cmdline)` of project processes that are NOT children of this runner."""
    me = os.getpid()
    stale: List[Tuple[int, str]] = []
    for proc in psutil.process_iter(["pid", "ppid", "cmdline"]):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            if proc.info["pid"] != me and any(module in cmdline for module in _PROJECT_MODULES):
                stale.append((proc.info["pid"], cmdline))
        except (psutil.Error, TypeError):
            continue
    return stale


def kill_runner_descendants() -> int:
    """SIGKILL (and reap) every process still descended from this runner. Returns how many were killed."""
    killed = 0
    for child in psutil.Process(os.getpid()).children(recursive=True):
        try:
            child.kill()
            killed += 1
        except psutil.Error:
            pass
    psutil.wait_procs(psutil.Process(os.getpid()).children(recursive=True), timeout=2.0)
    return killed


# ==============================================================================
# 3. PROCESS BOOKKEEPING FOR ONE TRIAL
# ==============================================================================

@dataclass
class TrialProcesses:
    """Tracks every child started by one trial so that cleanup can never miss one."""

    procs: Dict[str, subprocess.Popen] = field(default_factory=dict)
    logs: Dict[str, IO[bytes]] = field(default_factory=dict)
    watchdog: Optional[subprocess.Popen] = None

    def spawn(self, name: str, cmd: List[str], setup: Optional[str] = None, role: Optional[str] = None) -> subprocess.Popen:
        """Start `cmd` (under `setup`/`role` control if given) with stdout+stderr captured to a temp file."""
        log_file = tempfile.TemporaryFile()
        self.logs[name] = log_file
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
        kwargs: Dict[str, Any] = dict(
            cwd=str(REPO_ROOT), env=env, stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
        )
        if setup is not None and role is not None:
            proc = profiles.spawn_with_profile(cmd, setup, role, **kwargs)
        else:
            proc = subprocess.Popen(cmd, start_new_session=True, **kwargs)
        self.procs[name] = proc
        return proc

    def output_tail(self, name: str, max_chars: int = 600) -> str:
        """Last `max_chars` characters the process printed (for error messages)."""
        log_file = self.logs.get(name)
        if log_file is None:
            return ""
        try:
            log_file.seek(0)
            return log_file.read().decode("utf-8", errors="replace")[-max_chars:].strip()
        except (OSError, ValueError):
            return ""

    def cleanup(self) -> None:
        """Kill and reap everything: watchdog, then every child's whole process group."""
        profiles.stop_watchdog(self.watchdog)
        self.watchdog = None
        for proc in self.procs.values():
            _kill_group(proc, signal.SIGKILL)
        for proc in self.procs.values():
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                pass
        for log_file in self.logs.values():
            try:
                log_file.close()
            except OSError:
                pass


# ==============================================================================
# 4. CSV OUTPUT
# ==============================================================================

def _blank_row(setup: str, trial_id: int, mode: str) -> Dict[str, Any]:
    """A row with every schema column present; blank (None) means 'not applicable'."""
    row: Dict[str, Any] = {col: None for col in RAW_CSV_COLUMNS}
    row.update(setup=setup, trial_id=trial_id, mode=mode, detected=False, false_alarm=False, timed_out=False, notes="")
    return row


def append_row(csv_path: Path, row: Dict[str, Any]) -> None:
    """
    Append one row to `csv_path` (header written if the file is new) and force it to disk.

    `fsync` after every row means a crash or Ctrl+C mid-benchmark never loses finished trials.
    Booleans are written as `True`/`False` and "not applicable" values as empty cells, which
    `pandas.read_csv` loads as real booleans and NaN.
    """
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = (not csv_path.exists()) or csv_path.stat().st_size == 0
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(RAW_CSV_COLUMNS), extrasaction="raise", lineterminator="\n")
        if write_header:
            writer.writeheader()
        writer.writerow({col: ("" if row.get(col) is None else row[col]) for col in RAW_CSV_COLUMNS})
        f.flush()
        os.fsync(f.fileno())


def archive_existing_csv(csv_path: Path) -> Optional[Path]:
    """Move an existing CSV aside (timestamped) so a fresh run never mixes with old data."""
    csv_path = Path(csv_path)
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return None
    backup = csv_path.with_name(f"{csv_path.stem}_backup_{time.strftime('%Y%m%d_%H%M%S')}{csv_path.suffix}")
    os.replace(csv_path, backup)
    return backup


# ==============================================================================
# 5. THE STAGES OF A TRIAL
# ==============================================================================

def _start_workload(procs: TrialProcesses, setup: str) -> int:
    """
    Start the CPU workload under `setup`'s workload control; return its window-start timestamp (ns).

    Waits for the workload's "running" telemetry, then verifies that the scheduler control
    really applies to the main process *and* its worker children.
    """
    proc = procs.spawn(
        "workload",
        [sys.executable, "-m", "src.workload.cpu_stress"],
        setup=setup,
        role=ROLE_WORKLOAD,
    )
    deadline = time.monotonic() + WORKLOAD_START_TIMEOUT_S
    telemetry: Optional[Dict[str, Any]] = None
    while time.monotonic() < deadline:
        telemetry = _read_json(WORKLOAD_TELEMETRY_PATH)
        if telemetry and telemetry.get("status") == "running":
            break
        if proc.poll() is not None:
            raise TrialInfrastructureError(
                f"workload exited early (rc={proc.returncode}): {procs.output_tail('workload')}"
            )
        time.sleep(POLL_INTERVAL_S)
    else:
        raise TrialInfrastructureError("workload did not report 'running' in time")

    problems = profiles.verify_profile(setup, ROLE_WORKLOAD, proc.pid, include_children=True)
    if problems:
        raise TrialInfrastructureError("scheduler control not applied to workload: " + "; ".join(problems))
    return int(telemetry["start_ns"])


def _start_defender(procs: TrialProcesses, setup: str, defender_cmd: List[str]) -> subprocess.Popen:
    """Start the defender under `setup`'s defender control and wait until it signals ready."""
    proc = procs.spawn("defender", defender_cmd, setup=setup, role=ROLE_DEFENDER)
    if setup == "chrt":  # real-time safety net: an independent SCHED_FIFO-99 killer
        procs.watchdog = profiles.start_watchdog([proc.pid], TRIAL_TIMEOUT_S + WATCHDOG_MARGIN_S)

    deadline = time.monotonic() + DEFENDER_READY_TIMEOUT_S
    while not DEFENDER_READY_FLAG.exists():
        if proc.poll() is not None:
            raise TrialInfrastructureError(
                f"defender exited before becoming ready (rc={proc.returncode}): {procs.output_tail('defender')}"
            )
        if time.monotonic() > deadline:
            raise TrialInfrastructureError(
                f"defender not ready after {DEFENDER_READY_TIMEOUT_S:.0f}s: {procs.output_tail('defender')}"
            )
        time.sleep(POLL_INTERVAL_S)

    problems = profiles.verify_profile(setup, ROLE_DEFENDER, proc.pid)
    if problems:
        raise TrialInfrastructureError("scheduler control not applied to defender: " + "; ".join(problems))
    return proc


def _wait_for_outcome(
    procs: TrialProcesses,
    actor: subprocess.Popen,
    defender: Optional[subprocess.Popen],
    deadline: float,
) -> str:
    """
    Wait until the attacker/benign process is frozen, has finished, or the deadline passes.

    Returns `"frozen"`, `"finished"` or `"timeout"`. Raises TrialInfrastructureError if the
    defender died without having frozen anything (a broken defender is not an experimental result).
    """
    while True:
        if _is_stopped(actor.pid):
            return "frozen"
        if actor.poll() is not None:
            return "finished"
        if time.monotonic() > deadline:
            return "timeout"
        if defender is not None and defender.poll() is not None:
            time.sleep(0.2)  # a defender that exits right after freezing is fine; give the state time to settle
            if _is_stopped(actor.pid):
                return "frozen"
            if actor.poll() is not None:
                return "finished"
            tel = _read_json(DEFENDER_TELEMETRY_PATH) or {}
            if not tel.get("triggered"):
                raise TrialInfrastructureError(
                    f"defender exited (rc={defender.returncode}) without freezing anything: "
                    f"{procs.output_tail('defender')}"
                )
        time.sleep(POLL_INTERVAL_S)


def _await_defender_telemetry(deadline_s: float) -> Optional[Dict[str, Any]]:
    """Poll up to `deadline_s` for a defender telemetry file that already contains `freeze_time_ns`."""
    end = time.monotonic() + deadline_s
    while True:
        tel = _read_json(DEFENDER_TELEMETRY_PATH)
        if tel and tel.get("freeze_time_ns") is not None:
            return tel
        if time.monotonic() >= end:
            return tel
        time.sleep(0.01)


def _wait_for_measurement_window(window_start_ns: int) -> None:
    """Block until the workload has been running at least `MIN_WORKLOAD_WINDOW_S` seconds."""
    remaining_s = MIN_WORKLOAD_WINDOW_S - (time.monotonic_ns() - window_start_ns) / 1e9
    if remaining_s > 0:
        time.sleep(remaining_s)


def _collect_workload_throughput(procs: TrialProcesses, notes: List[str]) -> Optional[float]:
    """Stop the workload politely (SIGTERM so it writes its totals) and return work units/sec."""
    proc = procs.procs.get("workload")
    _stop_process(proc, grace_s=5.0)
    tel = _read_json(WORKLOAD_TELEMETRY_PATH)
    if not tel or tel.get("status") != "completed":
        notes.append("workload telemetry missing")
        return None
    return float(tel["work_units_per_sec"])


# ==============================================================================
# 6. ONE COMPLETE TRIAL
# ==============================================================================

def _run_trial_once(setup: str, trial_id: int, mode: str, defender_cmd: List[str]) -> Dict[str, Any]:
    """Run one trial start-to-finish and return its CSV row (raises TrialInfrastructureError on harness failure)."""
    params = SCHEDULER_PARAMS[setup]
    use_workload = bool(params.get("run_workload", True))
    use_defender = bool(params.get("run_defender", True))
    notes: List[str] = []
    row = _blank_row(setup, trial_id, mode)

    # Step 0: kernel-side configuration (cgroup limits) + preflight checks.
    try:
        notes_cfg = profiles.prepare_setup(setup)
    except ProfileError as exc:
        raise TrialInfrastructureError(f"setup '{setup}' not available: {exc}") from exc

    procs = TrialProcesses()
    trial_deadline = time.monotonic() + TRIAL_TIMEOUT_S
    try:
        # Step 1: clean sandbox (also wipes old telemetry, so this must come before any process starts).
        reset_sandbox()

        # Step 2: CPU workload.
        window_start_ns = _start_workload(procs, setup) if use_workload else None
        if use_workload:
            time.sleep(WORKLOAD_WARMUP_S)

        # Solo baseline: nothing else to do but measure.
        if mode == MODE_SOLO:
            _wait_for_measurement_window(window_start_ns)
            row["workload_throughput"] = _collect_workload_throughput(procs, notes)
            row["notes"] = "; ".join(notes)
            return row

        # Step 3: defender.
        defender = _start_defender(procs, setup, defender_cmd) if use_defender else None

        # Step 4: attacker or benign activity (plain processes, never under a scheduler control).
        if mode == MODE_ATTACK:
            actor_module, actor_telemetry = "src.attacker.ransomware_sim", ATTACKER_TELEMETRY_PATH
        else:
            actor_module, actor_telemetry = "src.attacker.benign_activity", BENIGN_TELEMETRY_PATH
        actor = procs.spawn("actor", [sys.executable, "-m", actor_module])

        # Step 5: wait for the outcome.
        outcome = _wait_for_outcome(procs, actor, defender, trial_deadline)
        row["timed_out"] = outcome == "timeout"
        if outcome == "timeout":
            notes.append(f"hit {TRIAL_TIMEOUT_S:.0f}s trial timeout")

        defender_tel: Dict[str, Any] = {}
        if outcome == "frozen":
            defender_tel = _await_defender_telemetry(DEFENDER_TELEMETRY_GRACE_S) or {}
        actor_tel = _read_json(actor_telemetry) or {}

        # Step 6: finish the measurement window, then stop everything (workload first, so the
        # damage check below runs on an idle machine).
        if use_workload:
            _wait_for_measurement_window(window_start_ns)
        _kill_group(actor, signal.SIGKILL)  # frozen or finished: either way it must not survive
        try:
            actor.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            notes.append("actor did not die after SIGKILL")
        if use_workload:
            row["workload_throughput"] = _collect_workload_throughput(procs, notes)
        if defender is not None:
            _stop_process(defender, grace_s=2.0)
            final_tel = _read_json(DEFENDER_TELEMETRY_PATH) or {}
            if final_tel.get("freeze_time_ns") is not None or not defender_tel:
                defender_tel = final_tel
        profiles.stop_watchdog(procs.watchdog)
        procs.watchdog = None

        # Step 7: metrics.
        damage = count_damaged_files()
        row["files_damaged"] = damage["damaged_files"]
        row["total_decoy_files"] = damage["total_files"]

        triggered = bool(defender_tel.get("triggered")) or outcome == "frozen"
        frozen_pid = defender_tel.get("frozen_pid")
        if frozen_pid is not None and int(frozen_pid) != actor.pid:
            notes.append(f"defender froze PID {frozen_pid}, expected {actor.pid}")
            _undo_wrong_freeze(int(frozen_pid), procs)
            triggered = outcome == "frozen"  # only count it if our process really was stopped
        if outcome == "frozen" and not defender_tel.get("triggered"):
            notes.append("actor frozen but defender telemetry missing")

        if mode == MODE_ATTACK:
            row["detected"] = triggered
            attack_start_ns = actor_tel.get("attack_start_ns")
            freeze_ns = defender_tel.get("freeze_time_ns")
            if triggered and attack_start_ns is not None and freeze_ns is not None:
                row["detection_delay_ms"] = round((int(freeze_ns) - int(attack_start_ns)) / 1e6, 3)
                if row["detection_delay_ms"] < 0:
                    notes.append("negative detection delay (clock mismatch?)")
            elif triggered:
                notes.append("detected but timestamps missing")
            if not triggered:
                notes.append(f"attack {actor_tel.get('status', 'unknown')} after "
                             f"{actor_tel.get('files_scrambled', '?')} files, undetected")
        else:  # benign
            row["detected"] = triggered
            row["false_alarm"] = triggered
            if triggered:
                notes.append("FALSE ALARM: defender froze the benign process")

        if notes_cfg and mode == MODE_ATTACK and trial_id == 1:
            notes.append("cfg " + ", ".join(f"{k}={v}" for k, v in notes_cfg.items()))
        row["notes"] = "; ".join(notes)
        return row
    finally:
        procs.cleanup()


def _undo_wrong_freeze(pid: int, procs: TrialProcesses) -> None:
    """
    If the defender froze a process that is not ours (a bug), resume it with SIGCONT.

    This protects the user's machine: a defender that mis-identifies its target could otherwise
    freeze a terminal or a system service for good.
    """
    if pid in {p.pid for p in procs.procs.values()} or pid == os.getpid() or pid <= 1:
        return
    try:
        if _is_stopped(pid):
            os.kill(pid, signal.SIGCONT)
    except OSError:
        pass


def run_trial(setup: str, trial_id: int, mode: str, defender_cmd: List[str]) -> Dict[str, Any]:
    """`_run_trial_once` with retries for harness failures (never retries real experimental outcomes)."""
    last_error: Optional[TrialInfrastructureError] = None
    for attempt in range(1, MAX_INFRA_RETRIES + 2):
        try:
            return _run_trial_once(setup, trial_id, mode, defender_cmd)
        except TrialInfrastructureError as exc:
            last_error = exc
            log(f"    ! harness problem (attempt {attempt}/{MAX_INFRA_RETRIES + 1}): {exc}")
            kill_runner_descendants()
            time.sleep(0.5)
    assert last_error is not None
    raise last_error


# ==============================================================================
# 7. SCHEDULE AND BATCH LOOP
# ==============================================================================

def valid_modes(setup: str) -> List[str]:
    """Trial modes that make sense for `setup`."""
    if not SCHEDULER_PARAMS[setup].get("run_defender", True):
        return [MODE_SOLO]
    return [MODE_ATTACK, MODE_BENIGN]


def build_schedule(
    setups: List[str],
    trials: int,
    benign_trials: int,
    seed: int,
) -> List[Tuple[str, int, str]]:
    """
    Build the interleaved, shuffled list of `(setup, trial_id, mode)` to execute.

    Round r (1..trials) contains one attack trial for every defender setup, one solo trial
    (if the solo baseline is selected) and, for r <= `benign_trials`, one benign trial for every
    defender setup. Each round is shuffled with a seeded RNG.
    """
    rng = random.Random(seed)
    schedule: List[Tuple[str, int, str]] = []
    for round_id in range(1, max(trials, benign_trials) + 1):
        items: List[Tuple[str, int, str]] = []
        for setup in setups:
            for mode in valid_modes(setup):
                if mode == MODE_BENIGN and round_id > benign_trials:
                    continue
                if mode != MODE_BENIGN and round_id > trials:
                    continue
                items.append((setup, round_id, mode))
        rng.shuffle(items)
        schedule.extend(items)
    return schedule


def _raise_keyboard_interrupt(_signum: int, _frame: Any) -> None:
    """SIGTERM handler: behave exactly like Ctrl+C so cleanup in `finally` blocks always runs."""
    raise KeyboardInterrupt


def _restore_ownership(*paths: Path) -> None:
    """When started with sudo, give result files back to the invoking user (not root)."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid is None or gid is None or os.geteuid() != 0:
        return
    for path in paths:
        try:
            targets = [path] + (list(path.rglob("*")) if path.is_dir() else [])
            for target in targets:
                os.chown(target, int(uid), int(gid))
        except OSError:
            pass


def run_all(
    setups: List[str],
    trials: int,
    benign_trials: int,
    output_csv: Path,
    seed: int,
    defender_cmd: List[str],
) -> int:
    """
    Execute the whole schedule and append every finished trial to `output_csv`.

    Returns
    -------
    int
        Process exit code: 0 = all done, 2 = some setups were skipped as unavailable.
    """
    # Make sure each selected setup can run on this machine; skip (and report) the rest.
    skipped: Dict[str, str] = {}
    runnable: List[str] = []
    for setup in setups:
        try:
            profiles.preflight(setup)
            runnable.append(setup)
        except ProfileError as exc:
            skipped[setup] = str(exc)
            log(f"[SKIP] {setup}: {exc}")

    schedule = build_schedule(runnable, trials, benign_trials, seed)
    log(f"[RUNNER] {len(schedule)} trials over {len(runnable)} setups | seed={seed} | output={output_csv}")

    started = time.monotonic()
    try:
        for index, (setup, trial_id, mode) in enumerate(schedule, start=1):
            t0 = time.monotonic()
            row = run_trial(setup, trial_id, mode, defender_cmd)
            append_row(output_csv, row)

            elapsed = time.monotonic() - started
            eta_s = elapsed / index * (len(schedule) - index)
            log(
                f"[{index:>3}/{len(schedule)}] {setup:<22} {mode:<6} #{trial_id:<2} "
                f"detected={str(row['detected']):<5} delay_ms={_fmt(row['detection_delay_ms']):>8} "
                f"damaged={_fmt(row['files_damaged']):>3} thr={_fmt(row['workload_throughput'], 1):>7} "
                f"timeout={str(row['timed_out']):<5} ({time.monotonic() - t0:.1f}s, ETA {eta_s / 60:.1f} min)"
            )
    finally:
        # Cleanup runs on success, error, Ctrl+C and SIGTERM alike.
        leftovers = kill_runner_descendants()
        if leftovers:
            log(f"[CLEANUP] killed {leftovers} leftover child process(es)")
        profiles.cleanup_cgroups()
        try:
            cleanup_sandbox()
        except Exception:  # noqa: BLE001 - cleanup must never mask the real error
            pass
        _restore_ownership(output_csv.parent)

    if skipped:
        log(f"[RUNNER] finished, but {len(skipped)} setup(s) were skipped: {', '.join(skipped)}")
        return 2
    log("[RUNNER] all trials finished.")
    return 0


# ==============================================================================
# 8. COMMAND-LINE INTERFACE
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the scheduler-control experiment and append trial rows to results/raw/trials.csv."
    )
    parser.add_argument("--setups", nargs="+", choices=SCHEDULER_SETUPS, default=list(SCHEDULER_SETUPS),
                        help="Setups to run (default: all).")
    parser.add_argument("--trials", type=int, default=TRIALS_PER_SETUP,
                        help=f"Attack trials per setup (default: {TRIALS_PER_SETUP}); also the number of solo baseline runs.")
    parser.add_argument("--benign-trials", type=int, default=BENIGN_TRIALS_PER_SETUP,
                        help=f"False-alarm (benign) trials per setup (default: {BENIGN_TRIALS_PER_SETUP}).")
    parser.add_argument("--output", type=Path, default=RAW_TRIALS_CSV, help=f"CSV to append to (default: {RAW_TRIALS_CSV}).")
    parser.add_argument("--fresh", action="store_true", help="Archive any existing output CSV first and start a new one.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"Seed for the shuffled trial order (default: {DEFAULT_SEED}).")
    parser.add_argument("--quick", action="store_true", help="Smoke test: 2 attack trials and 1 benign trial per setup.")
    parser.add_argument("--dry-run", action="store_true", help="Print the schedule and exit without running anything.")
    parser.add_argument("--defender-cmd", default=f"{shlex.quote(sys.executable)} -m src.defender.defender",
                        help="Command that starts the defender (default: python -m src.defender.defender).")
    return parser


def main() -> int:
    """Entry point for `python -m src.scheduler.runner`."""
    args = _build_arg_parser().parse_args()
    trials, benign_trials = (2, 1) if args.quick else (args.trials, args.benign_trials)
    if trials < 1 or benign_trials < 0:
        log("--trials must be >= 1 and --benign-trials >= 0")
        return 1

    if args.dry_run:
        schedule = build_schedule(args.setups, trials, benign_trials, args.seed)
        for i, (setup, trial_id, mode) in enumerate(schedule, start=1):
            log(f"{i:>3}. {setup:<22} {mode:<6} #{trial_id}")
        log(f"{len(schedule)} trials in total (seed={args.seed}).")
        return 0

    if sys.platform != "linux":
        log("The experiment must run on Linux (WSL2 Ubuntu).")
        return 1

    stale = find_stale_project_processes()
    if stale:
        log("Leftover project processes from an earlier run are still alive and would distort the measurements:")
        for pid, cmdline in stale:
            log(f"   PID {pid}: {cmdline}")
        log("Stop them first, e.g.  sudo pkill -f 'src\\.(workload|attacker|defender)'")
        return 1

    # Turn SIGINT (Ctrl+C) and SIGTERM into one exception so `finally` cleanup always runs. SIGINT is
    # installed explicitly because shells start background jobs with it ignored.
    signal.signal(signal.SIGINT, _raise_keyboard_interrupt)
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    ensure_results_dirs()
    if args.fresh:
        backup = archive_existing_csv(args.output)
        if backup:
            log(f"[RUNNER] previous results archived to {backup}")

    try:
        return run_all(args.setups, trials, benign_trials, args.output, args.seed, shlex.split(args.defender_cmd))
    except KeyboardInterrupt:
        log("\n[RUNNER] interrupted; cleaned up. Rows written so far are kept in the CSV.")
        return 130
    except TrialInfrastructureError as exc:
        log(f"[RUNNER] ABORTED: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
