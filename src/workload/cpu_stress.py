"""
Synthetic Multi-Process CPU Workload (Member C).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Munir Tariq (Member C)

Overview:
---------
This module is the "traffic jam" of our experiment. It stands in for a heavy
local AI inference job (e.g. Ollama on a CPU-only laptop) without needing a real
model, a GPU, or any unpredictable network/disk behaviour.

How it works:
  - The parent process spawns one worker process per logical CPU core
    (`os.cpu_count()`), so every core is fully busy.
  - Each worker repeats a fixed-size, pure-CPU math loop. One run of that loop
    (`WORKLOAD_CHUNK_ITERATIONS` iterations) is exactly 1 "work unit".
  - Every worker owns one slot in a shared-memory counter array and bumps it
    after each finished work unit. No locks are involved, so a worker can never
    block another worker (or be blocked by a frozen process holding a lock).
  - When the run ends (fixed `--duration`, or `SIGTERM`/`SIGINT`), the parent
    sums all counters and writes `work_units_completed`, `elapsed_s` and
    `work_units_per_sec` to `WORKLOAD_TELEMETRY_PATH`.

Why throughput is the metric:
  Member D computes workload slowdown (%) as
      (baseline_throughput - setup_throughput) / baseline_throughput * 100
  so this module only has to report an honest, repeatable work-units-per-second.

OS notes (useful for the viva):
  - Scheduler controls (nice / chrt / cgroup / taskset) are applied by
    `src/scheduler/profiles.py` *before* this process starts. Linux children
    inherit nice value, scheduling policy, CPU affinity and cgroup membership
    from their parent at `fork()`, so all workers automatically obey the control.
  - The measurement window starts only after every worker is alive and has
    passed a start gate, so process start-up cost never pollutes throughput.
  - Workers exit by themselves if the parent dies (`os.getppid()` check), so a
    crashed runner can never leave CPU hogs behind.

Command-Line Usage:
-------------------
  python -m src.workload.cpu_stress --duration 3
  python -m src.workload.cpu_stress --duration 3 --workers 2 --json
  python -m src.workload.cpu_stress            # runs until SIGTERM / Ctrl+C
"""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.experiment_config import (
    TRIAL_TIMEOUT_S,
    WORKLOAD_CHUNK_ITERATIONS,
    WORKLOAD_TELEMETRY_PATH,
)


# Safety net: even if nobody ever sends SIGTERM, an open-ended run stops itself
# after this many seconds so a forgotten workload can never hog the CPU forever.
HARD_MAX_RUNTIME_S: float = TRIAL_TIMEOUT_S + 15.0

# Longest time the parent waits for all workers to come alive before giving up.
WORKER_STARTUP_TIMEOUT_S: float = 15.0

# Workers re-check "should I stop?" after every work unit (cheap shared-memory
# read) and re-check "is my parent still alive?" every this many units.
_PARENT_CHECK_EVERY_UNITS: int = 16


# ==============================================================================
# 1. THE UNIT OF WORK
# ==============================================================================

def do_work_unit(iterations: int = WORKLOAD_CHUNK_ITERATIONS, seed: int = 12345) -> float:
    """
    Execute exactly one "work unit": a fixed-size, CPU-bound math loop.

    The loop mixes 64-bit integer arithmetic (a linear congruential generator)
    with floating-point `sqrt`, so it keeps the integer and floating-point
    units busy, never sleeps, never touches the disk and never allocates much
    memory. Every call does the same amount of work, which is what makes
    "work units per second" a fair throughput measure across scheduler setups.

    Parameters
    ----------
    iterations : int
        Loop iterations that make up one unit (`WORKLOAD_CHUNK_ITERATIONS`).
    seed : int
        Starting value of the generator (only changes the numbers, not the cost).

    Returns
    -------
    float
        A checksum of the loop. Returning it stops the work from looking
        "useless" and makes unit tests able to verify determinism.
    """
    state = seed & 0xFFFFFFFFFFFFFFFF
    acc = 0.0
    sqrt = math.sqrt
    for _ in range(iterations):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        acc += sqrt((state >> 11) & 0xFFFFF)
    return acc


# ==============================================================================
# 2. WORKER PROCESS
# ==============================================================================

def _worker_main(
    index: int,
    counters: Any,
    ready: Any,
    go_event: Any,
    stop_flag: Any,
    parent_pid: int,
    iterations: int,
) -> None:
    """
    Body of one worker process: wait at the start gate, then burn CPU until told to stop.

    Parameters
    ----------
    index : int
        This worker's slot in the shared `counters` / `ready` arrays.
    counters : multiprocessing.Array('Q')
        One unsigned 64-bit completed-unit counter per worker (single writer each).
    ready : multiprocessing.Array('b')
        `ready[index] = 1` tells the parent this worker is alive.
    go_event : multiprocessing.Event
        Set by the parent when the measurement window opens.
    stop_flag : multiprocessing.Value('b')
        Set to 1 by the parent when the run is over.
    parent_pid : int
        PID of the parent; the worker quits if the parent disappears.
    iterations : int
        Iterations per work unit.
    """
    # The parent owns shutdown. If a whole process group gets SIGINT/SIGTERM
    # (e.g. Ctrl+C), workers must not die mid-unit and lose their counters;
    # they stop when the parent raises `stop_flag`.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    ready[index] = 1
    # Start gate: poll in short sleeps so that waiting costs ~0 CPU.
    while not go_event.wait(timeout=0.05):
        if stop_flag.value or os.getppid() != parent_pid:
            return

    units_since_parent_check = 0
    seed = 1000 + index
    while not stop_flag.value:
        do_work_unit(iterations, seed)
        counters[index] += 1  # single writer per slot -> no lock needed

        units_since_parent_check += 1
        if units_since_parent_check >= _PARENT_CHECK_EVERY_UNITS:
            units_since_parent_check = 0
            if os.getppid() != parent_pid:
                return


# ==============================================================================
# 3. TELEMETRY HELPER
# ==============================================================================

def _write_telemetry_atomic(telemetry_path: Path, payload: Dict[str, Any]) -> None:
    """
    Write `payload` as JSON via a temporary file + `os.replace()`.

    The runner polls this file while the workload is running, so it must always
    contain complete, valid JSON (never a half-written file).
    """
    telemetry_path = Path(telemetry_path)
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = telemetry_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp_path, telemetry_path)


# ==============================================================================
# 4. MAIN WORKLOAD RUNNER
# ==============================================================================

def run_workload(
    duration_s: Optional[float] = None,
    workers: Optional[int] = None,
    iterations: int = WORKLOAD_CHUNK_ITERATIONS,
    telemetry_path: Path | str = WORKLOAD_TELEMETRY_PATH,
) -> Dict[str, Any]:
    """
    Run the synthetic CPU workload and return (and save) its throughput telemetry.

    Workflow:
      1. Spawn `workers` processes (default: one per logical CPU core).
      2. Wait until every worker reports ready, then open the start gate and
         write a `"status": "running"` telemetry file (the runner waits for it).
      3. Keep running until `duration_s` elapses, `SIGTERM`/`SIGINT` arrives,
         or `HARD_MAX_RUNTIME_S` is reached.
      4. Raise the stop flag, join all workers, sum the counters, and write the
         final telemetry (`"status": "completed"`).

    Parameters
    ----------
    duration_s : float | None
        Fixed run time in seconds, or None to run until signalled.
    workers : int | None
        Number of worker processes (None = `os.cpu_count()`).
    iterations : int
        Iterations per work unit.
    telemetry_path : Path | str
        Where to write the JSON telemetry.

    Returns
    -------
    Dict[str, Any]
        Final telemetry with `work_units_completed`, `elapsed_s`,
        `work_units_per_sec`, per-worker counts and run metadata.
    """
    if duration_s is not None and duration_s <= 0:
        raise ValueError(f"duration_s must be positive (got {duration_s}).")
    if iterations <= 0:
        raise ValueError(f"iterations must be positive (got {iterations}).")

    telemetry_path = Path(telemetry_path)
    num_workers = workers if workers is not None else (os.cpu_count() or 1)
    if num_workers <= 0:
        raise ValueError(f"workers must be positive (got {num_workers}).")

    pid = os.getpid()
    stop_reason = "duration_elapsed"
    stop_requested = False

    def _handle_stop_signal(signum: int, _frame: Any) -> None:
        nonlocal stop_requested, stop_reason
        stop_requested = True
        stop_reason = "signal_" + signal.Signals(signum).name.lower()

    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    # "fork" keeps worker start-up fast and lets children inherit the scheduler
    # control (nice / policy / affinity / cgroup) that profiles.py applied to us.
    ctx = mp.get_context("fork")
    counters = ctx.Array("Q", num_workers, lock=False)
    ready = ctx.Array("b", num_workers, lock=False)
    go_event = ctx.Event()
    stop_flag = ctx.Value("b", 0, lock=False)

    procs: List[Any] = []
    for idx in range(num_workers):
        p = ctx.Process(
            target=_worker_main,
            args=(idx, counters, ready, go_event, stop_flag, pid, iterations),
            name=f"cpu_stress_worker_{idx}",
            daemon=True,
        )
        p.start()
        procs.append(p)

    def _shutdown_workers() -> None:
        stop_flag.value = 1
        go_event.set()  # release any worker still waiting at the gate
        for proc in procs:
            proc.join(timeout=5.0)
        for proc in procs:  # last resort: a worker that ignored the stop flag
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=2.0)

    try:
        # Wait for every worker to come alive (they poll at the gate, ~0% CPU).
        startup_deadline = time.monotonic() + WORKER_STARTUP_TIMEOUT_S
        while not all(ready[i] for i in range(num_workers)):
            if stop_requested or time.monotonic() > startup_deadline:
                break
            time.sleep(0.005)

        # Open the measurement window.
        start_ns = time.monotonic_ns()
        start_epoch_s = time.time()
        go_event.set()

        _write_telemetry_atomic(
            telemetry_path,
            {
                "pid": pid,
                "status": "running",
                "workers": num_workers,
                "cpu_count": os.cpu_count(),
                "chunk_iterations": iterations,
                "start_ns": start_ns,
                "start_epoch_s": start_epoch_s,
            },
        )

        # Main wait loop: short sleeps so signals are handled within ~20 ms.
        planned_s = duration_s if duration_s is not None else HARD_MAX_RUNTIME_S
        if duration_s is None:
            stop_reason = "hard_max_runtime"
        deadline_ns = start_ns + int(planned_s * 1e9)
        while not stop_requested and time.monotonic_ns() < deadline_ns:
            time.sleep(0.02)
            if not any(p.is_alive() for p in procs):
                stop_reason = "all_workers_exited"
                break

        # Close the measurement window *before* joining workers, so the join
        # time is not counted as run time.
        stop_flag.value = 1
        end_ns = time.monotonic_ns()
    finally:
        _shutdown_workers()

    per_worker_units = [int(counters[i]) for i in range(num_workers)]
    total_units = sum(per_worker_units)
    elapsed_s = max((end_ns - start_ns) / 1e9, 1e-9)

    telemetry: Dict[str, Any] = {
        "pid": pid,
        "status": "completed",
        "stop_reason": stop_reason,
        "workers": num_workers,
        "cpu_count": os.cpu_count(),
        "chunk_iterations": iterations,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "work_units_completed": total_units,
        "elapsed_s": round(elapsed_s, 6),
        "work_units_per_sec": round(total_units / elapsed_s, 4),
        "per_worker_units": per_worker_units,
    }
    _write_telemetry_atomic(telemetry_path, telemetry)
    return telemetry


# ==============================================================================
# 5. COMMAND-LINE INTERFACE
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for standalone workload runs."""
    parser = argparse.ArgumentParser(
        description="Synthetic CPU workload: one busy worker process per core, reports work units/sec."
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Run time in seconds (default: run until SIGTERM/Ctrl+C, capped at "
        f"{HARD_MAX_RUNTIME_S:.0f}s for safety).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker processes (default: one per logical CPU core).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=WORKLOAD_CHUNK_ITERATIONS,
        help=f"Loop iterations per work unit (default: {WORKLOAD_CHUNK_ITERATIONS}).",
    )
    parser.add_argument(
        "--telemetry-path",
        type=Path,
        default=WORKLOAD_TELEMETRY_PATH,
        help=f"Where to write telemetry JSON (default: {WORKLOAD_TELEMETRY_PATH}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print final telemetry as JSON.",
    )
    return parser


def main() -> int:
    """Entry point for `python -m src.workload.cpu_stress`."""
    args = _build_arg_parser().parse_args()
    result = run_workload(
        duration_s=args.duration,
        workers=args.workers,
        iterations=args.iterations,
        telemetry_path=args.telemetry_path,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"[CPU STRESS] workers={result['workers']} | "
            f"units={result['work_units_completed']} | "
            f"elapsed={result['elapsed_s']:.2f}s | "
            f"throughput={result['work_units_per_sec']:.2f} units/s | "
            f"stopped by {result['stop_reason']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
