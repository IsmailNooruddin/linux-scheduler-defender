"""
Lightweight Real-Time Defender: Burst Detection -> PID Discovery -> SIGSTOP (Member B).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4

Overview:
---------
This is the "security guard". One run of the defender does the following:

  1. Validate the sandbox path (safety lock) and make sure `files/` exists.
  2. Start the inotify watch on `<sandbox_root>/files/` (see `monitor.py`).
  3. Write initial telemetry, then create the READY FLAG file
     (`DEFENDER_READY_FLAG`) so Member C's runner knows it may launch the attacker.
  4. Sleep in the kernel until a ransomware-style burst is detected.
  5. Find WHICH process is doing it (inotify only says which FILE changed).
  6. Freeze that process with `SIGSTOP`, write final telemetry JSON, and exit.

Finding the attacker's PID (the important Linux detail):
--------------------------------------------------------
inotify reports "decoy_0042.dat was modified" but NOT "by PID 1234".
So after a burst we look at the kernel's process table in `/proc`:

  Primary method  ("fd_scan"):
      For every process, list `/proc/<pid>/fd/*` (symlinks to the files that
      process has open). Any process that currently has a file inside
      `<sandbox_root>/files/` open is a suspect. The attacker opens each decoy
      file only for microseconds, so we re-scan in a tight loop for a short
      budget (`PID_SCAN_TIMEOUT_S`, 20 ms) hoping to catch it with a file open.

  Fallback method ("cmdline_fallback"):
      If the fd scan finds nothing in time, match `/proc/<pid>/cmdline`
      against known attacker signatures (like a signature-based AV rule).
      The method actually used is recorded in telemetry as `pid_method`.

  Never targeted: this defender's own PID, its parent PID, PID 1, and any
  PID passed via `--whitelist-pid`.

Why SIGSTOP?
------------
SIGSTOP cannot be caught, blocked or ignored by the target. The kernel
immediately pauses the process (state `T`, stopped) so it scrambles no more
files, but it is not destroyed - the runner can still read its state and then
clean it up with SIGKILL.

Telemetry JSON (`<sandbox_root>/telemetry/defender_telemetry.json`):
--------------------------------------------------------------------
Required fields (contract with Member C):
  detection_time_ns : time.monotonic_ns() when the burst was declared (or null)
  freeze_time_ns    : time.monotonic_ns() right after SIGSTOP returned (or null)
  frozen_pid        : PID that was frozen (or null)
  events_seen       : number of inotify MODIFY/CLOSE_WRITE events processed
  triggered         : true if a burst was declared (false = no attack seen)
Extra diagnostic fields: status, defender_pid, ready_time_ns, pid_method,
  pid_scans, frozen_pids, freeze_error, distinct_files_in_window,
  trigger_file, overflow, threshold, window_ms.

Clock note: `time.monotonic_ns()` (CLOCK_MONOTONIC) is shared by all processes
on the machine, so `freeze_time_ns - attack_start_ns` (from the attacker's own
telemetry) is a valid cross-process delay.

Command-Line Usage:
-------------------
  python -m src.defender.defender
  python -m src.defender.defender --max-runtime 15 --json
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from config.experiment_config import (
    BURST_EVENT_THRESHOLD,
    BURST_WINDOW_MS,
    DEFENDER_POLL_TIMEOUT_MS,
    DEFENDER_READY_FLAG,
    DEFENDER_TELEMETRY_PATH,
    SANDBOX_ROOT,
    is_safe_sandbox_path,
)
from src.defender.monitor import BurstResult, SandboxMonitor


# ==============================================================================
# 0. DEFENDER-LOCAL SETTINGS
# ==============================================================================

# How long (seconds) to keep re-scanning /proc for the attacker's open file
# descriptors after a burst is declared, before using the fallback.
# Kept SHORT on purpose: the attacker only holds a decoy file open for a few
# microseconds between sleeps, so a hit usually happens on the first scans or
# not at all. Every extra millisecond spent here is more files damaged, so we
# fall back to the command-line signature quickly.
PID_SCAN_TIMEOUT_S: float = 0.02

# Substrings searched for in /proc/<pid>/cmdline by the fallback method.
CMDLINE_SIGNATURES: Tuple[str, ...] = ("ransomware_sim",)


# ==============================================================================
# 1. SMALL HELPERS
# ==============================================================================

def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    """
    Write JSON via a temp file + `os.replace()` so readers (Member C's runner)
    never see a half-written file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp_path, path)


def _protected_pids(extra: Iterable[int] = ()) -> Set[int]:
    """PIDs the defender must NEVER signal: itself, its parent, init, and extras."""
    return {0, 1, os.getpid(), os.getppid(), *extra}


# ==============================================================================
# 2. PID DISCOVERY VIA /proc
# ==============================================================================

def scan_proc_for_sandbox_fds(files_dir: Path | str, exclude_pids: Set[int]) -> Dict[int, int]:
    """
    Find processes that currently hold a file inside `files_dir` open.

    Walks `/proc/<pid>/fd/`: each entry is a symlink whose target is the path of
    the open file. Processes we may not inspect (other users, already exited)
    raise OSError and are skipped.

    Returns
    -------
    Dict[int, int]
        Mapping pid -> number of open descriptors inside the sandbox files dir.
    """
    prefix = str(Path(files_dir).resolve()) + os.sep
    hits: Dict[int, int] = {}

    try:
        proc_entries = os.listdir("/proc")
    except OSError:
        return hits

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in exclude_pids:
            continue

        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:  # exited, or permission denied
            continue

        count = 0
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:  # fd closed between listdir and readlink
                continue
            if target.startswith(prefix):
                count += 1
        if count:
            hits[pid] = count

    return hits


def scan_proc_for_cmdline(signatures: Iterable[str], exclude_pids: Set[int]) -> List[int]:
    """Fallback: PIDs whose command line contains any of `signatures`."""
    matches: List[int] = []
    try:
        proc_entries = os.listdir("/proc")
    except OSError:
        return matches

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in exclude_pids:
            continue
        try:
            # Only match actual Python interpreters. A wrapper such as `sh -c "python -m ..."`,
            # `sudo` or `timeout` also has the signature in its cmdline, but freezing it
            # would be the WRONG process (and its PID is not the attacker's PID).
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                if not f.read().strip().startswith("python"):
                    continue
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\0", b" ").decode("utf-8", errors="replace")
        except OSError:
            continue
        if any(sig in cmdline for sig in signatures):
            matches.append(pid)
    return sorted(matches)


def identify_attacker(
    files_dir: Path | str,
    exclude_pids: Set[int],
    timeout_s: float = PID_SCAN_TIMEOUT_S,
) -> Tuple[List[int], str, int]:
    """
    Identify the process (or processes) writing into the sandbox.

    Returns
    -------
    (pids, method, scans)
        `pids`   : candidate PIDs, best first (most open sandbox fds first)
        `method` : "fd_scan", "cmdline_fallback" or "none"
        `scans`  : how many /proc fd scans were performed
    """
    deadline = time.monotonic() + timeout_s
    scans = 0

    while True:
        hits = scan_proc_for_sandbox_fds(files_dir, exclude_pids)
        scans += 1
        if hits:
            ranked = sorted(hits, key=lambda p: (-hits[p], p))
            return ranked, "fd_scan", scans
        if time.monotonic() >= deadline:
            break

    fallback = scan_proc_for_cmdline(CMDLINE_SIGNATURES, exclude_pids)
    if fallback:
        return fallback, "cmdline_fallback", scans
    return [], "none", scans


# ==============================================================================
# 3. CONTAINMENT
# ==============================================================================

def freeze_processes(
    pids: List[int],
    protected: Set[int],
) -> Tuple[List[int], Optional[int], Optional[str]]:
    """
    Send SIGSTOP to the best candidate PID (never to a protected one).
    Candidates are tried in ranked order until ONE freeze succeeds; no other
    process is ever signalled.

    Returns
    -------
    (frozen_pids, freeze_time_ns, error)
        `freeze_time_ns` is taken right after the successful os.kill().
    """
    frozen: List[int] = []
    freeze_time_ns: Optional[int] = None
    errors: List[str] = []

    for pid in pids:
        if pid in protected:
            continue
        try:
            os.kill(pid, signal.SIGSTOP)
        except ProcessLookupError:
            errors.append(f"{pid}: already exited")
        except PermissionError:
            errors.append(f"{pid}: permission denied")
        else:
            freeze_time_ns = time.monotonic_ns()
            frozen.append(pid)
            break  # freeze exactly ONE process: the best candidate. Never collateral damage.

    return frozen, freeze_time_ns, ("; ".join(errors) if errors else None)


# ==============================================================================
# 4. MAIN DEFENDER ROUTINE
# ==============================================================================

def run_defender(
    sandbox_root: Path | str = SANDBOX_ROOT,
    threshold: int = BURST_EVENT_THRESHOLD,
    window_ms: float = BURST_WINDOW_MS,
    poll_timeout_ms: int = DEFENDER_POLL_TIMEOUT_MS,
    max_runtime_s: Optional[float] = None,
    extra_whitelist: Iterable[int] = (),
    install_signal_handlers: bool = True,
) -> Dict[str, Any]:
    """
    Run one defender session and return its final telemetry dictionary.

    The session ends when (a) a burst was detected and the attacker was frozen,
    (b) SIGTERM/SIGINT arrives (the runner ends a benign trial this way), or
    (c) `max_runtime_s` elapses.

    Parameters
    ----------
    sandbox_root : Path | str
        Sandbox root (must pass the safety lock).
    threshold, window_ms : int, float
        Burst rule K and W (defaults from config).
    poll_timeout_ms : int
        inotify read timeout; bounds how fast stop requests are noticed.
    max_runtime_s : float | None
        Optional self-destruct timer (None = run until signalled).
    extra_whitelist : Iterable[int]
        Additional PIDs that must never be frozen.
    install_signal_handlers : bool
        Install SIGTERM/SIGINT handlers (only possible in the main thread).
    """
    root = Path(sandbox_root)
    if not is_safe_sandbox_path(root, sandbox_root=root):
        raise ValueError(
            f"SAFETY LOCK ENGAGED: Refusing to watch unsafe path '{root}'. "
            f"The sandbox must be '/tmp/.../os_defense_sandbox'."
        )
    root = root.resolve()
    files_dir = root / "files"
    telemetry_dir = root / "telemetry"
    telemetry_path = telemetry_dir / DEFENDER_TELEMETRY_PATH.name
    ready_path = telemetry_dir / DEFENDER_READY_FLAG.name

    if not files_dir.is_dir():
        raise FileNotFoundError(
            f"Sandbox files directory not found at '{files_dir}'. "
            f"Run `python -m src.attacker.sandbox_setup --reset` first."
        )

    telemetry_dir.mkdir(parents=True, exist_ok=True)
    # Remove leftovers from a previous trial so the runner cannot read stale data.
    for stale in (ready_path, telemetry_path):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    stop_requested = False

    def _handle_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    if install_signal_handlers:
        signal.signal(signal.SIGTERM, _handle_stop)
        signal.signal(signal.SIGINT, _handle_stop)

    protected = _protected_pids(extra_whitelist)

    telemetry: Dict[str, Any] = {
        "triggered": False,
        "status": "running",
        "detection_time_ns": None,
        "freeze_time_ns": None,
        "frozen_pid": None,
        "events_seen": 0,
        "defender_pid": os.getpid(),
        "ready_time_ns": None,
        "pid_method": None,
        "pid_scans": 0,
        "frozen_pids": [],
        "freeze_error": None,
        "distinct_files_in_window": 0,
        "trigger_file": None,
        "overflow": False,
        "threshold": threshold,
        "window_ms": window_ms,
    }

    monitor = SandboxMonitor(
        files_dir,
        threshold=threshold,
        window_ms=window_ms,
        poll_timeout_ms=poll_timeout_ms,
    )

    try:
        # 1) The inotify watch becomes ACTIVE here.
        monitor.start()

        # 2) Only now announce readiness: telemetry first, then the flag file.
        telemetry["ready_time_ns"] = time.monotonic_ns()
        _write_json_atomic(telemetry_path, telemetry)
        _write_json_atomic(
            ready_path,
            {"pid": os.getpid(), "ready_time_ns": telemetry["ready_time_ns"]},
        )

        deadline_ns = (
            time.monotonic_ns() + int(max_runtime_s * 1e9)
            if max_runtime_s is not None
            else None
        )

        # 3) Sleep in the kernel until a burst, a stop request, or the deadline.
        burst: Optional[BurstResult] = monitor.wait_for_burst(
            should_stop=lambda: stop_requested,
            deadline_ns=deadline_ns,
        )

        telemetry["events_seen"] = monitor.events_seen

        if burst is None:
            telemetry["status"] = "stopped_by_signal" if stop_requested else "max_runtime_reached"
        else:
            telemetry["triggered"] = True
            telemetry["detection_time_ns"] = burst.detection_time_ns
            telemetry["events_seen"] = burst.events_seen
            telemetry["distinct_files_in_window"] = burst.distinct_files
            telemetry["trigger_file"] = burst.trigger_file
            telemetry["overflow"] = burst.overflow

            # 4) Who is doing it?  5) Freeze them.
            pids, method, scans = identify_attacker(files_dir, protected)
            telemetry["pid_method"] = method
            telemetry["pid_scans"] = scans

            frozen, freeze_ns, error = freeze_processes(pids, protected)
            telemetry["freeze_time_ns"] = freeze_ns
            telemetry["frozen_pids"] = frozen
            telemetry["frozen_pid"] = frozen[0] if frozen else None
            telemetry["freeze_error"] = error
            telemetry["status"] = "frozen_attacker" if frozen else "burst_no_target"

        _write_json_atomic(telemetry_path, telemetry)
        return telemetry

    finally:
        monitor.close()


# ==============================================================================
# 5. COMMAND-LINE INTERFACE
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the lightweight inotify + SIGSTOP ransomware defender."
    )
    parser.add_argument("--sandbox-root", type=Path, default=SANDBOX_ROOT,
                        help=f"Sandbox root directory (default: {SANDBOX_ROOT}).")
    parser.add_argument("--threshold", type=int, default=BURST_EVENT_THRESHOLD,
                        help=f"Distinct files K that make a burst (default: {BURST_EVENT_THRESHOLD}).")
    parser.add_argument("--window-ms", type=float, default=BURST_WINDOW_MS,
                        help=f"Sliding window W in ms (default: {BURST_WINDOW_MS}).")
    parser.add_argument("--poll-timeout-ms", type=int, default=DEFENDER_POLL_TIMEOUT_MS,
                        help=f"inotify read timeout in ms (default: {DEFENDER_POLL_TIMEOUT_MS}).")
    parser.add_argument("--max-runtime", type=float, default=None,
                        help="Exit by itself after this many seconds (default: run until SIGTERM).")
    parser.add_argument("--whitelist-pid", type=int, action="append", default=[],
                        help="PID that must never be frozen (repeatable).")
    parser.add_argument("--json", action="store_true",
                        help="Print final telemetry as JSON.")
    return parser


def main() -> None:
    """Entry point for `python -m src.defender.defender`."""
    args = _build_arg_parser().parse_args()
    print(f"[DEFENDER] PID={os.getpid()} starting on '{args.sandbox_root}' "
          f"(K={args.threshold}, W={args.window_ms} ms)...", flush=True)

    result = run_defender(
        sandbox_root=args.sandbox_root,
        threshold=args.threshold,
        window_ms=args.window_ms,
        poll_timeout_ms=args.poll_timeout_ms,
        max_runtime_s=args.max_runtime,
        extra_whitelist=args.whitelist_pid,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"[DEFENDER] Status={result['status']} | triggered={result['triggered']} | "
            f"frozen_pid={result['frozen_pid']} | events_seen={result['events_seen']}"
        )


if __name__ == "__main__":
    main()
