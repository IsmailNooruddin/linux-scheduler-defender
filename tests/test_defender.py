"""
Verification Tests for the Lightweight Defender (Member B).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4

What these tests prove:
-----------------------
  Unit tests (any OS, no kernel features needed)
    - BurstDetector fires on >= K DISTINCT files within W ms, and ONLY then
      (slow edits, repeated edits of one file, and expired events never fire).
    - /proc fd-scan finds a process holding a sandbox file open, and respects
      the exclusion list.
    - The defender never signals protected PIDs (itself, its parent, init).
    - The safety lock and missing-sandbox errors work.

  Integration tests (Linux/WSL2 + `inotify-simple` required, run real processes)
    - Attack scenario: Member A's ransomware_sim.py is detected, the attacker
      PID is found and frozen with SIGSTOP (/proc state "T"), only a minority
      of decoy files are damaged, and the telemetry JSON has the agreed fields.
    - Benign scenario: Member A's benign_activity.py runs next to the defender
      and produces ZERO false alarms (nothing frozen, 0 damaged decoys).

How to run (from the repo root, inside WSL2 / Ubuntu, venv active):
    python -m pytest tests/test_defender.py -v

Each integration test builds its own throw-away sandbox at
`<pytest tmp dir>/os_defense_sandbox` (the safety lock requires that exact
folder name under /tmp), so it never touches your real `/tmp/os_defense_sandbox`.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

# Make `config` and `src` importable even if pytest was started as plain `pytest`.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config.experiment_config import (  # noqa: E402
    ATTACKER_TELEMETRY_PATH,
    BURST_EVENT_THRESHOLD,
    BURST_WINDOW_MS,
    DEFENDER_READY_FLAG,
    DEFENDER_TELEMETRY_PATH,
)
from src.attacker.sandbox_setup import count_damaged_files, reset_sandbox  # noqa: E402
from src.defender import defender as defender_mod  # noqa: E402
from src.defender.monitor import BurstDetector  # noqa: E402

MS = 1_000_000  # nanoseconds per millisecond

# Small sandbox keeps the integration tests fast.
TEST_FILE_COUNT = 200
TEST_FILE_SIZE = 4096

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="needs Linux /proc and inotify (run inside WSL2/Ubuntu)",
)


# ==============================================================================
# HELPERS
# ==============================================================================

def _require_inotify() -> None:
    pytest.importorskip("inotify_simple", reason="run `pip install -r requirements.txt`")


def _make_sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "os_defense_sandbox"
    reset_sandbox(root, file_count=TEST_FILE_COUNT, file_size=TEST_FILE_SIZE)
    return root


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _start_defender(root: Path, max_runtime_s: float = 25.0) -> subprocess.Popen:
    """Launch the defender as a separate process and wait for its READY flag."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.defender.defender",
         "--sandbox-root", str(root), "--max-runtime", str(max_runtime_s)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready_flag = root / "telemetry" / DEFENDER_READY_FLAG.name
    deadline = time.monotonic() + 10.0
    while not ready_flag.exists():
        if proc.poll() is not None:
            _out, err = proc.communicate()
            pytest.fail(f"Defender exited before becoming ready:\n{err}")
        if time.monotonic() > deadline:
            proc.kill()
            pytest.fail("Defender never created its ready flag within 10 s.")
        time.sleep(0.01)
    return proc


def _process_state(pid: int) -> Optional[str]:
    """Return the one-letter state from /proc/<pid>/stat ('T' = stopped), or None."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # Format: "pid (comm) S ..." - comm may contain spaces, so split after the last ')'.
    return stat.rsplit(")", 1)[1].split()[0]


def _wait_for_state(pid: int, state: str, timeout_s: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _process_state(pid) == state:
            return True
        time.sleep(0.01)
    return False


def _cleanup(*procs: subprocess.Popen) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.kill()  # SIGKILL also works on SIGSTOPped processes
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


# ==============================================================================
# UNIT TESTS - BurstDetector (pure logic)
# ==============================================================================

def test_burst_detector_fires_on_k_distinct_files_within_window():
    detector = BurstDetector(threshold=5, window_ms=500)
    results = [detector.record(f"decoy_{i:04d}.dat", i * 100 * MS) for i in range(5)]
    # 5 files, 100 ms apart -> 400 ms span < 500 ms window: fires on the 5th.
    assert results == [False, False, False, False, True]


def test_burst_detector_ignores_slow_benign_pace():
    detector = BurstDetector(threshold=5, window_ms=500)
    # benign_activity.py default pace: 1 new file every 750 ms.
    for i in range(20):
        assert detector.record(f"benign_note_{i:04d}.txt", i * 750 * MS) is False
        assert detector.distinct_files == 1


def test_burst_detector_counts_distinct_files_not_raw_events():
    detector = BurstDetector(threshold=5, window_ms=500)
    # One file producing 100 events (MODIFY + CLOSE_WRITE, rewrites...) is NOT a burst.
    for i in range(100):
        assert detector.record("decoy_0000.dat", i * MS) is False
    assert detector.distinct_files == 1


def test_burst_detector_expires_old_events():
    detector = BurstDetector(threshold=5, window_ms=500)
    # 150 ms apart: any 5 consecutive files span 600 ms > 500 ms -> never 5 in window.
    for i in range(30):
        assert detector.record(f"decoy_{i:04d}.dat", i * 150 * MS) is False
    assert detector.distinct_files <= 4


def test_burst_detector_rejects_invalid_parameters():
    with pytest.raises(ValueError):
        BurstDetector(threshold=0, window_ms=500)
    with pytest.raises(ValueError):
        BurstDetector(threshold=5, window_ms=0)


def test_burst_detector_uses_config_defaults():
    detector = BurstDetector()
    assert detector.threshold == BURST_EVENT_THRESHOLD
    assert detector.window_ns == BURST_WINDOW_MS * MS


# ==============================================================================
# UNIT TESTS - /proc PID discovery, safety rules
# ==============================================================================

@linux_only
def test_fd_scan_finds_process_with_open_sandbox_file(tmp_path: Path):
    files_dir = tmp_path / "os_defense_sandbox" / "files"
    files_dir.mkdir(parents=True)
    target = files_dir / "decoy_0000.dat"
    target.write_bytes(b"x")

    with target.open("rb"):
        assert os.getpid() in defender_mod.scan_proc_for_sandbox_fds(files_dir, set())
        # The exclusion list must be honoured.
        assert os.getpid() not in defender_mod.scan_proc_for_sandbox_fds(files_dir, {os.getpid()})

    # File closed again -> no longer a suspect.
    assert os.getpid() not in defender_mod.scan_proc_for_sandbox_fds(files_dir, set())


@linux_only
def test_defender_never_signals_protected_pids():
    protected = defender_mod._protected_pids()
    assert {0, 1, os.getpid(), os.getppid()} <= protected

    frozen, freeze_ns, error = defender_mod.freeze_processes([os.getpid(), os.getppid(), 1], protected)
    assert frozen == [] and freeze_ns is None and error is None


def test_defender_refuses_unsafe_sandbox_path():
    with pytest.raises(ValueError):
        defender_mod.run_defender(sandbox_root="/home/definitely_not_a_sandbox",
                                  install_signal_handlers=False)


def test_defender_requires_existing_files_dir(tmp_path: Path):
    root = tmp_path / "os_defense_sandbox"  # safe path, but never created
    with pytest.raises(FileNotFoundError):
        defender_mod.run_defender(sandbox_root=root, install_signal_handlers=False)


# ==============================================================================
# INTEGRATION TEST 1 - real attack is detected and frozen
# ==============================================================================

@linux_only
def test_defender_detects_and_freezes_ransomware_sim(tmp_path: Path):
    _require_inotify()
    root = _make_sandbox(tmp_path)
    telemetry_path = root / "telemetry" / DEFENDER_TELEMETRY_PATH.name

    defender = _start_defender(root)
    attacker = subprocess.Popen(
        [sys.executable, "-m", "src.attacker.ransomware_sim", "--sandbox-root", str(root)],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # The defender exits by itself once it has frozen the attacker.
        defender.wait(timeout=20)
        tel = _read_json(telemetry_path)

        # --- telemetry contract (Member C reads these exact fields) ---
        for field in ("detection_time_ns", "freeze_time_ns", "frozen_pid", "events_seen", "triggered"):
            assert field in tel, f"missing telemetry field: {field}"
        assert tel["triggered"] is True
        assert tel["status"] == "frozen_attacker"
        assert tel["events_seen"] >= BURST_EVENT_THRESHOLD
        assert 0 < tel["detection_time_ns"] <= tel["freeze_time_ns"]

        # --- the RIGHT process was frozen, and it is really stopped ---
        assert tel["frozen_pid"] == attacker.pid
        assert _wait_for_state(attacker.pid, "T"), "attacker is not in SIGSTOP state 'T'"
        assert attacker.poll() is None, "attacker finished on its own before being frozen"

        # --- detection delay measured the way Member C's runner will ---
        attack_tel = _read_json(root / "telemetry" / ATTACKER_TELEMETRY_PATH.name)
        assert attack_tel["pid"] == attacker.pid
        delay_ms = (tel["freeze_time_ns"] - attack_tel["attack_start_ns"]) / 1e6
        assert 0 < delay_ms < 2000, f"unreasonable detection delay: {delay_ms} ms"

        # --- damage was contained: attack stopped long before finishing ---
        damage = count_damaged_files(root)
        assert damage["damaged_files"] >= BURST_EVENT_THRESHOLD - 1
        assert damage["damaged_files"] <= TEST_FILE_COUNT // 2, (
            f"too much damage: {damage['damaged_files']} / {TEST_FILE_COUNT}"
        )
    finally:
        _cleanup(attacker, defender)


# ==============================================================================
# INTEGRATION TEST 2 - benign activity causes ZERO false alarms
# ==============================================================================

@linux_only
def test_defender_has_zero_false_alarms_on_benign_activity(tmp_path: Path):
    _require_inotify()
    root = _make_sandbox(tmp_path)
    telemetry_path = root / "telemetry" / DEFENDER_TELEMETRY_PATH.name

    defender = _start_defender(root)
    try:
        benign = subprocess.run(
            [sys.executable, "-m", "src.attacker.benign_activity",
             "--sandbox-root", str(root), "--duration", "4.0"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert benign.returncode == 0, benign.stderr

        # Benign trials end by the runner sending SIGTERM to the defender.
        assert defender.poll() is None, "defender exited/froze something during benign activity"
        defender.send_signal(signal.SIGTERM)
        defender.wait(timeout=10)

        tel = _read_json(telemetry_path)
        benign_tel = _read_json(root / "telemetry" / "benign_telemetry.json")

        assert tel["triggered"] is False
        assert tel["frozen_pid"] is None
        assert tel["freeze_time_ns"] is None
        assert tel["status"] == "stopped_by_signal"
        # The defender was really awake and watching (not just asleep):
        assert tel["events_seen"] > 0
        # The benign process was never frozen and finished normally:
        assert benign_tel["status"] == "completed"
        # And no decoy file was touched.
        assert count_damaged_files(root)["damaged_files"] == 0
    finally:
        _cleanup(defender)
