"""
Benign / Normal File Activity Generator for False-Alarm Testing (Member A).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Ismail Nooruddin (Member A)

Overview:
---------
To evaluate a security defender properly, we must verify not only that it stops
real attacks quickly, but also that it does NOT freeze innocent programs performing
ordinary file operations (the **false alarm** metric in our proposal).

This module simulates a harmless user or background application slowly creating
and updating small text notes (`benign_note_0000.txt`, ...) inside the watched
`<sandbox_root>/files/` directory:
  - Pacing: By default, it performs 1 file write every `0.75s` for `6.0s`
    (~8 total writes). Because Member B's defender triggers on bursts of >=5 file
    modifications within a `500 ms` sliding window, this gentle activity stays
    well below the burst threshold and should produce **0 false alarms**.
  - Zero Decoy Damage: It never modifies `decoy_*.dat` files, so running
    `count_damaged_files()` after `benign_activity.py` always reports 0 damaged
    decoy files.
  - Pre-Write Atomic Telemetry: Just like `ransomware_sim.py`, it writes its PID
    and timestamps atomically to `telemetry/benign_telemetry.json` right at startup
    so Member C's runner can detect if the defender ever mistakenly sends `SIGSTOP`
    to this benign process.

Command-Line Usage:
-------------------
  python -m src.attacker.benign_activity
  python -m src.attacker.benign_activity --duration 3.0 --interval 0.5
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path
from typing import Any, Dict, Optional

from config.experiment_config import (
    BENIGN_DURATION_S,
    BENIGN_FILE_PREFIX,
    BENIGN_INTERVAL_S,
    SANDBOX_ROOT,
    is_safe_sandbox_path,
)
from src.attacker.sandbox_setup import assert_safe_sandbox


# ==============================================================================
# 1. ATOMIC TELEMETRY & SAFE WRITE HELPERS
# ==============================================================================

def _write_telemetry_atomic(telemetry_path: Path, payload: Dict[str, Any]) -> None:
    """
    Atomically write `payload` as JSON to `telemetry_path` via a `.tmp` swap.

    Guarantees valid JSON on disk even if a faulty defender sends `SIGSTOP`
    (a false alarm) while this benign process is running.
    """
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = telemetry_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp_path, telemetry_path)


def write_benign_note(
    files_dir: Path,
    sandbox_root: Path,
    step_index: int,
) -> Path:
    """
    Create or update a single harmless text note inside `<sandbox_root>/files/`.

    Writes a small human-readable log entry and flushes it to disk so that Linux
    `inotify` delivers a real file-write event to Member B's defender.

    Parameters
    ----------
    files_dir : Path
        Path to `<sandbox_root>/files/`.
    sandbox_root : Path
        Validated sandbox root directory.
    step_index : int
        Zero-based index of the benign write operation.

    Returns
    -------
    Path
        Path to the created/updated benign note file.

    Raises
    ------
    ValueError
        If the target path fails the sandbox safety lock.
    """
    filename = f"{BENIGN_FILE_PREFIX}{step_index:04d}.txt"
    note_path = files_dir / filename

    if not is_safe_sandbox_path(note_path, sandbox_root=sandbox_root):
        raise ValueError(
            f"SAFETY LOCK: Refusing to write benign note outside sandbox: '{note_path}'"
        )

    content = (
        f"BENIGN_USER_ACTIVITY_LOG\n"
        f"step={step_index}\n"
        f"timestamp_epoch_s={time.time():.6f}\n"
        f"message=Normal background document save (harmless operation).\n"
    ).encode("utf-8")

    with note_path.open("wb") as f:
        f.write(content)
        f.flush()

    return note_path


# ==============================================================================
# 2. MAIN BENIGN ACTIVITY LOOP
# ==============================================================================

def run_benign_activity(
    sandbox_root: Path | str = SANDBOX_ROOT,
    interval_s: float = BENIGN_INTERVAL_S,
    duration_s: float = BENIGN_DURATION_S,
    max_writes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run paced, harmless file writes inside `<sandbox_root>/files/`.

    Workflow:
      1. Validate `sandbox_root` via `assert_safe_sandbox()`.
      2. Flush initial telemetry (`pid`, `start_ns`, `status="running"`) to
         `<sandbox_root>/telemetry/benign_telemetry.json`.
      3. Periodically write harmless `benign_note_XXXX.txt` files separated by
         `interval_s` seconds until `duration_s` (or `max_writes`) is reached.
      4. Record final telemetry (`status="completed"`, `files_written`, `elapsed_ms`).

    Parameters
    ----------
    sandbox_root : Path | str, optional
        Root path of the isolated sandbox (defaults to `SANDBOX_ROOT`).
    interval_s : float, optional
        Pause in seconds between consecutive benign file writes (defaults to `0.75`).
    duration_s : float, optional
        Total duration in seconds to run benign activity (defaults to `6.0`).
    max_writes : int | None, optional
        Optional cap on number of benign files written (None = bounded by `duration_s`).

    Returns
    -------
    Dict[str, Any]
        Final telemetry dictionary summarizing the benign session.
    """
    if interval_s < 0:
        raise ValueError(f"interval_s must be non-negative (got {interval_s}).")
    if duration_s < 0:
        raise ValueError(f"duration_s must be non-negative (got {duration_s}).")

    safe_root = assert_safe_sandbox(sandbox_root)
    files_dir = safe_root / "files"
    telemetry_path = safe_root / "telemetry" / "benign_telemetry.json"

    if not files_dir.exists():
        raise FileNotFoundError(
            f"Sandbox files directory not found at '{files_dir}'. "
            f"Run `python -m src.attacker.sandbox_setup --reset` first."
        )

    stop_requested = False

    def _handle_stop_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    pid = os.getpid()
    start_epoch_s = time.time()
    start_ns = time.monotonic_ns()
    deadline_ns = start_ns + int(duration_s * 1e9)

    telemetry: Dict[str, Any] = {
        "pid": pid,
        "status": "running",
        "sandbox_root": str(safe_root),
        "files_dir": str(files_dir),
        "interval_s": interval_s,
        "target_duration_s": duration_s,
        "files_written": 0,
        "start_ns": start_ns,
        "start_epoch_s": start_epoch_s,
        "last_write_ns": None,
        "end_ns": None,
        "elapsed_ms": 0.0,
    }

    # Flush initial telemetry immediately so the runner knows our PID and start time
    _write_telemetry_atomic(telemetry_path, telemetry)

    step_idx = 0
    while not stop_requested:
        now_ns = time.monotonic_ns()
        if step_idx > 0 and now_ns >= deadline_ns:
            break
        if max_writes is not None and step_idx >= max_writes:
            break

        write_benign_note(
            files_dir=files_dir,
            sandbox_root=safe_root,
            step_index=step_idx,
        )

        step_idx += 1
        write_ns = time.monotonic_ns()
        telemetry["files_written"] = step_idx
        telemetry["last_write_ns"] = write_ns
        telemetry["elapsed_ms"] = round((write_ns - start_ns) / 1e6, 3)
        _write_telemetry_atomic(telemetry_path, telemetry)

        # Check stopping conditions before sleeping
        if max_writes is not None and step_idx >= max_writes:
            break
        if time.monotonic_ns() >= deadline_ns:
            break

        # Sleep in small slices up to `interval_s` so SIGTERM remains responsive
        if interval_s > 0:
            sleep_end_ns = min(deadline_ns, time.monotonic_ns() + int(interval_s * 1e9))
            while not stop_requested and time.monotonic_ns() < sleep_end_ns:
                remaining_s = (sleep_end_ns - time.monotonic_ns()) / 1e9
                if remaining_s <= 0:
                    break
                time.sleep(min(0.05, remaining_s))

    telemetry["status"] = "terminated_by_signal" if stop_requested else "completed"
    end_ns = time.monotonic_ns()
    telemetry["end_ns"] = end_ns
    telemetry["elapsed_ms"] = round((end_ns - start_ns) / 1e6, 3)
    _write_telemetry_atomic(telemetry_path, telemetry)

    return telemetry


# ==============================================================================
# 3. COMMAND-LINE INTERFACE
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for standalone benign activity testing."""
    parser = argparse.ArgumentParser(
        description="Run harmless normal file activity inside the sandbox for false-alarm testing."
    )
    parser.add_argument(
        "--sandbox-root",
        type=Path,
        default=SANDBOX_ROOT,
        help=f"Sandbox root directory (default: {SANDBOX_ROOT}).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=BENIGN_INTERVAL_S,
        help=f"Seconds between benign file writes (default: {BENIGN_INTERVAL_S}).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=BENIGN_DURATION_S,
        help=f"Total duration in seconds (default: {BENIGN_DURATION_S}).",
    )
    parser.add_argument(
        "--max-writes",
        type=int,
        default=None,
        help="Optional cap on total benign files written.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print final telemetry as JSON.",
    )
    return parser


def main() -> None:
    """Entry point for `python -m src.attacker.benign_activity`."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    result = run_benign_activity(
        sandbox_root=args.sandbox_root,
        interval_s=args.interval,
        duration_s=args.duration,
        max_writes=args.max_writes,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"[BENIGN SIM] PID={result['pid']} | Status={result['status']} | "
            f"Wrote {result['files_written']} harmless note(s) "
            f"(interval={result['interval_s']}s) in {result['elapsed_ms']:.2f} ms."
        )


if __name__ == "__main__":
    main()
