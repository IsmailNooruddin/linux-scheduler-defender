"""
Verification tests for the synthetic CPU workload (Member C).

Module under test: src/workload/cpu_stress.py

What these tests prove:
  1. One work unit is deterministic and does real work.
  2. By default the workload launches exactly one worker process per logical CPU core.
  3. It runs for the requested duration and writes valid throughput telemetry
     (`work_units_completed`, `elapsed_s`, `work_units_per_sec`).
  4. It terminates cleanly on SIGTERM (exit code 0, final telemetry written, no leftover workers).
  5. If the parent is killed hard (SIGKILL), the workers notice and exit by themselves,
     so a crashed runner can never leave CPU hogs behind.
  6. Invalid arguments are rejected.

Run:  pytest -v tests/test_workload.py
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import pytest

from config.experiment_config import REPO_ROOT, WORKLOAD_CHUNK_ITERATIONS
from src.workload.cpu_stress import do_work_unit

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Workload tests need Linux (run them in WSL2).")


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _start_workload(telemetry_path: Path, *extra_args: str) -> subprocess.Popen:
    """Start `python -m src.workload.cpu_stress` with an isolated telemetry file."""
    return subprocess.Popen(
        [sys.executable, "-m", "src.workload.cpu_stress", "--telemetry-path", str(telemetry_path), *extra_args],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _wait_for_status(telemetry_path: Path, status: str, timeout_s: float = 15.0) -> Dict[str, Any]:
    """Poll the telemetry file until it reports `status`."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            data = json.loads(telemetry_path.read_text())
            if data.get("status") == status:
                return data
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
    raise AssertionError(f"telemetry never reached status '{status}' within {timeout_s}s")


def _wait_until_gone(pids: List[int], timeout_s: float = 10.0) -> List[int]:
    """Return the PIDs (of `pids`) that are still alive (not zombie) after `timeout_s`."""
    deadline = time.monotonic() + timeout_s
    alive = list(pids)
    while alive and time.monotonic() < deadline:
        alive = [
            pid for pid in alive
            if psutil.pid_exists(pid) and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
        ]
        if alive:
            time.sleep(0.05)
    return alive


# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

def test_work_unit_is_deterministic_and_does_real_work() -> None:
    first = do_work_unit(2_000, seed=7)
    second = do_work_unit(2_000, seed=7)
    assert first == second, "the same unit of work must always produce the same checksum"
    assert first > 0.0
    assert do_work_unit(2_000, seed=8) != first, "a different seed must change the numbers"

    # Cost scales with iterations (a unit of 20x the size takes clearly longer).
    t0 = time.perf_counter()
    do_work_unit(2_000)
    small = time.perf_counter() - t0
    t0 = time.perf_counter()
    do_work_unit(40_000)
    large = time.perf_counter() - t0
    assert large > small * 4


def test_default_workers_equal_cpu_count_and_telemetry_is_valid(tmp_path: Path) -> None:
    telemetry_path = tmp_path / "workload.json"
    proc = _start_workload(telemetry_path, "--duration", "1.0", "--json")
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 0, out

    telemetry = json.loads(telemetry_path.read_text())
    cpu_count = os.cpu_count() or 1
    assert telemetry["status"] == "completed"
    assert telemetry["stop_reason"] == "duration_elapsed"
    assert telemetry["workers"] == cpu_count
    assert len(telemetry["per_worker_units"]) == cpu_count
    assert all(units > 0 for units in telemetry["per_worker_units"]), "every worker must have done work"

    assert telemetry["work_units_completed"] == sum(telemetry["per_worker_units"])
    assert 0.9 <= telemetry["elapsed_s"] <= 3.0
    assert telemetry["work_units_per_sec"] > 0
    expected = telemetry["work_units_completed"] / telemetry["elapsed_s"]
    assert telemetry["work_units_per_sec"] == pytest.approx(expected, rel=0.01)
    assert telemetry["chunk_iterations"] == WORKLOAD_CHUNK_ITERATIONS


def test_one_worker_process_per_requested_worker_while_running(tmp_path: Path) -> None:
    telemetry_path = tmp_path / "workload.json"
    proc = _start_workload(telemetry_path, "--workers", "3", "--duration", "5")
    try:
        running = _wait_for_status(telemetry_path, "running")
        assert running["workers"] == 3
        children = psutil.Process(proc.pid).children(recursive=True)
        assert len(children) == 3, f"expected 3 worker processes, found {len(children)}"
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=15)


def test_sigterm_stops_cleanly_and_writes_final_telemetry(tmp_path: Path) -> None:
    telemetry_path = tmp_path / "workload.json"
    proc = _start_workload(telemetry_path, "--workers", "2")  # no --duration: runs until signalled
    _wait_for_status(telemetry_path, "running")
    time.sleep(0.5)
    worker_pids = [c.pid for c in psutil.Process(proc.pid).children(recursive=True)]
    assert len(worker_pids) == 2

    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=15)
    assert proc.returncode == 0, f"SIGTERM must give a clean exit, got {proc.returncode}: {out}"

    telemetry = json.loads(telemetry_path.read_text())
    assert telemetry["status"] == "completed"
    assert telemetry["stop_reason"] == "signal_sigterm"
    assert telemetry["work_units_completed"] > 0
    assert telemetry["work_units_per_sec"] > 0
    assert _wait_until_gone(worker_pids) == [], "worker processes must not outlive the parent"


def test_workers_exit_by_themselves_if_parent_is_killed(tmp_path: Path) -> None:
    telemetry_path = tmp_path / "workload.json"
    proc = _start_workload(telemetry_path, "--workers", "2")
    _wait_for_status(telemetry_path, "running")
    worker_pids = [c.pid for c in psutil.Process(proc.pid).children(recursive=True)]
    assert len(worker_pids) == 2

    proc.kill()  # SIGKILL: the parent cannot clean anything up
    proc.communicate(timeout=15)

    still_alive = _wait_until_gone(worker_pids, timeout_s=10.0)
    for pid in still_alive:  # never leave a CPU hog behind, even when the assertion fails
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    assert still_alive == [], f"orphaned workers kept burning CPU: {still_alive}"


@pytest.mark.parametrize("bad_args", [["--duration", "0"], ["--duration", "-1"], ["--workers", "0"], ["--iterations", "0"]])
def test_invalid_arguments_are_rejected(tmp_path: Path, bad_args: List[str]) -> None:
    proc = _start_workload(tmp_path / "workload.json", *bad_args)
    out, _ = proc.communicate(timeout=15)
    assert proc.returncode != 0, out
