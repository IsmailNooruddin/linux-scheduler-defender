"""
Automated Verification Test Suite for Member A (Attacker & Sandbox Module).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Ismail Nooruddin (Member A)

Overview:
---------
This test suite verifies the correctness, safety locks, and telemetry contracts
of Member A's components (`config/experiment_config.py`, `sandbox_setup.py`,
`ransomware_sim.py`, and `benign_activity.py`):
  1. Sandbox safety locks reject any path outside `/tmp/.../os_defense_sandbox`.
  2. `reset_sandbox()` creates deterministic decoy files and a valid SHA-256 manifest.
  3. `xor_buffer()` scrambles bytes and is 100% reversible.
  4. `run_attack()` scrambles the exact requested number of files, writes atomic
     nanosecond telemetry, and `count_damaged_files()` reports exact damage.
  5. `count_damaged_files()` detects both modified and deleted decoy files.
  6. `scramble_single_file()` refuses to touch non-decoy files or files outside the sandbox.
  7. `run_benign_activity()` creates harmless user notes while causing 0 decoy damage.
  8. On Linux/WSL2, sending `SIGSTOP` to a live `ransomware_sim.py` process freezes it
     mid-attack while preserving valid `attack_start_ns` telemetry on disk.

Run Command (inside WSL2):
--------------------------
  pytest -v tests/test_attacker.py
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Generator

import pytest

from config.experiment_config import (
    DECOY_MAGIC_HEADER,
    REPO_ROOT,
    XOR_KEY,
    is_safe_sandbox_path,
)
from src.attacker.benign_activity import run_benign_activity
from src.attacker.ransomware_sim import run_attack, scramble_single_file, xor_buffer
from src.attacker.sandbox_setup import (
    assert_safe_sandbox,
    cleanup_sandbox,
    count_damaged_files,
    reset_sandbox,
)


# ==============================================================================
# FIXTURE: ISOLATED PER-TEST SANDBOX DIRECTORY
# ==============================================================================

@pytest.fixture()
def isolated_sandbox() -> Generator[Path, None, None]:
    """
    Provide a dedicated `/tmp/.../os_defense_sandbox` directory for each test
    and guarantee cleanup after the test finishes.
    """
    base_tmp = Path("/tmp") if os.name != "nt" else Path(tempfile.gettempdir())
    test_root = base_tmp / "os_defense_sandbox"

    cleanup_sandbox(test_root)
    yield test_root
    cleanup_sandbox(test_root)


# ==============================================================================
# 1. SAFETY LOCK TESTS
# ==============================================================================

def test_safety_guard_blocks_unsafe_paths(isolated_sandbox: Path) -> None:
    """Verify that the safety lock accepts valid sandbox paths and rejects unsafe paths."""
    # Valid sandbox root and child path must pass
    assert is_safe_sandbox_path(isolated_sandbox, sandbox_root=isolated_sandbox) is True
    assert is_safe_sandbox_path(isolated_sandbox / "files" / "decoy_0000.dat", sandbox_root=isolated_sandbox) is True
    assert assert_safe_sandbox(isolated_sandbox) == isolated_sandbox.resolve()

    # Repository root, root filesystem, home directory, and parent traversal must fail
    assert is_safe_sandbox_path(REPO_ROOT, sandbox_root=isolated_sandbox) is False
    assert is_safe_sandbox_path(Path("/"), sandbox_root=isolated_sandbox) is False
    assert is_safe_sandbox_path(Path.home(), sandbox_root=isolated_sandbox) is False
    assert is_safe_sandbox_path(isolated_sandbox / ".." / "outside.txt", sandbox_root=isolated_sandbox) is False

    # Passing an unsafe directory directly to assert_safe_sandbox must raise ValueError
    with pytest.raises(ValueError, match="SAFETY LOCK"):
        assert_safe_sandbox(REPO_ROOT)

    with pytest.raises(ValueError, match="SAFETY LOCK"):
        assert_safe_sandbox(Path("/tmp/not_a_valid_root_name"))


# ==============================================================================
# 2. SANDBOX INITIALIZATION & MANIFEST TESTS
# ==============================================================================

def test_reset_sandbox_creates_clean_decoys_and_manifest(isolated_sandbox: Path) -> None:
    """Verify that `reset_sandbox()` creates clean decoy files and a valid manifest."""
    info = reset_sandbox(sandbox_root=isolated_sandbox, file_count=15, file_size=2048)

    files_dir = Path(info["files_dir"])
    manifest_path = Path(info["manifest_path"])

    assert files_dir.is_dir()
    assert manifest_path.is_file()

    # Check that exactly 15 decoy files exist with expected size and magic header
    decoy_files = sorted(files_dir.glob("decoy_*.dat"))
    assert len(decoy_files) == 15
    for decoy in decoy_files:
        raw = decoy.read_bytes()
        assert len(raw) == 2048
        assert raw.startswith(DECOY_MAGIC_HEADER)

    # Fresh sandbox must report 0 damaged files
    report = count_damaged_files(sandbox_root=isolated_sandbox)
    assert report["total_files"] == 15
    assert report["damaged_files"] == 0
    assert report["intact_files"] == 15
    assert report["modified_files"] == 0
    assert report["missing_files"] == 0
    assert report["damage_pct"] == 0.0


# ==============================================================================
# 3. XOR SCRAMBLING & ATTACK SIMULATOR TESTS
# ==============================================================================

def test_xor_buffer_is_reversible_and_changes_bytes() -> None:
    """Verify that `xor_buffer()` scrambles data and restores it when applied twice."""
    original = DECOY_MAGIC_HEADER + b"Sample payload bytes 1234567890"
    scrambled = xor_buffer(original, xor_key=XOR_KEY)

    assert scrambled != original
    assert len(scrambled) == len(original)

    # Applying XOR a second time with the same key must recover the exact original bytes
    restored = xor_buffer(scrambled, xor_key=XOR_KEY)
    assert restored == original


def test_ransomware_sim_scrambles_files_and_writes_telemetry(isolated_sandbox: Path) -> None:
    """Verify partial attack execution, telemetry JSON fields, and exact damage count."""
    reset_sandbox(sandbox_root=isolated_sandbox, file_count=20, file_size=4096)

    telemetry = run_attack(
        sandbox_root=isolated_sandbox,
        inter_file_delay_s=0.001,
        max_files=8,
    )

    # Check returned telemetry structure
    assert telemetry["status"] == "completed"
    assert telemetry["files_scrambled"] == 8
    assert telemetry["bytes_scrambled"] == 8 * 4096
    assert isinstance(telemetry["attack_start_ns"], int)
    assert telemetry["first_file_ns"] is not None

    # Check persisted telemetry JSON on disk
    telemetry_file = isolated_sandbox / "telemetry" / "attacker_telemetry.json"
    assert telemetry_file.is_file()
    saved_telemetry = json.loads(telemetry_file.read_text(encoding="utf-8"))
    assert saved_telemetry["files_scrambled"] == 8
    assert saved_telemetry["pid"] == os.getpid()

    # Verify ground-truth damage count matches exactly
    report = count_damaged_files(sandbox_root=isolated_sandbox)
    assert report["total_files"] == 20
    assert report["damaged_files"] == 8
    assert report["modified_files"] == 8
    assert report["intact_files"] == 12
    assert report["missing_files"] == 0
    assert report["damage_pct"] == 40.0


def test_count_damaged_files_detects_missing_files(isolated_sandbox: Path) -> None:
    """Verify that deleted decoy files are also counted toward `damaged_files`."""
    info = reset_sandbox(sandbox_root=isolated_sandbox, file_count=10, file_size=1024)
    files_dir = Path(info["files_dir"])

    # Scramble 2 files and delete 1 file
    run_attack(sandbox_root=isolated_sandbox, inter_file_delay_s=0.0, max_files=2)
    (files_dir / "decoy_0009.dat").unlink()

    report = count_damaged_files(sandbox_root=isolated_sandbox)
    assert report["total_files"] == 10
    assert report["modified_files"] == 2
    assert report["missing_files"] == 1
    assert report["damaged_files"] == 3
    assert report["intact_files"] == 7


def test_scramble_single_file_rejects_non_decoy_and_outside_files(isolated_sandbox: Path) -> None:
    """Verify per-file safety guard refuses non-decoy filenames and outside paths."""
    info = reset_sandbox(sandbox_root=isolated_sandbox, file_count=5, file_size=1024)
    files_dir = Path(info["files_dir"])

    # Create a non-decoy file inside files_dir
    note_file = files_dir / "benign_note_0000.txt"
    note_file.write_text("harmless note", encoding="utf-8")

    with pytest.raises(ValueError, match="non-decoy"):
        scramble_single_file(note_file, sandbox_root=isolated_sandbox)

    with pytest.raises(ValueError, match="outside sandbox"):
        scramble_single_file(REPO_ROOT / "README.md", sandbox_root=isolated_sandbox)


# ==============================================================================
# 4. BENIGN NORMAL-ACTIVITY TESTS (FALSE-ALARM BASELINE)
# ==============================================================================

def test_benign_activity_writes_notes_with_zero_decoy_damage(isolated_sandbox: Path) -> None:
    """Verify that `run_benign_activity()` writes notes without damaging any decoy files."""
    info = reset_sandbox(sandbox_root=isolated_sandbox, file_count=12, file_size=1024)
    files_dir = Path(info["files_dir"])

    benign_result = run_benign_activity(
        sandbox_root=isolated_sandbox,
        interval_s=0.02,
        duration_s=1.0,
        max_writes=4,
    )

    assert benign_result["status"] == "completed"
    assert benign_result["files_written"] == 4

    # Verify benign note files exist on disk
    benign_notes = sorted(files_dir.glob("benign_note_*.txt"))
    assert len(benign_notes) == 4

    # Verify benign telemetry JSON exists
    telemetry_file = isolated_sandbox / "telemetry" / "benign_telemetry.json"
    assert telemetry_file.is_file()

    # CRITICAL: Zero decoy files may be damaged by benign activity
    report = count_damaged_files(sandbox_root=isolated_sandbox)
    assert report["damaged_files"] == 0
    assert report["intact_files"] == 12


# ==============================================================================
# 5. LINUX / WSL2 SIGSTOP MID-ATTACK FREEZE TEST
# ==============================================================================

@pytest.mark.skipif(
    not hasattr(signal, "SIGSTOP"),
    reason="SIGSTOP process freezing is a POSIX/Linux kernel signal (runs on WSL2/Linux).",
)
def test_sigstop_freezes_attacker_mid_run_and_preserves_telemetry(isolated_sandbox: Path) -> None:
    """
    Simulate Member B's defender freezing the attacker mid-run with `SIGSTOP`.

    Verifies that:
      1. `attacker_telemetry.json` already exists on disk with `attack_start_ns`
         even when the process is suddenly suspended by `SIGSTOP`.
      2. Only a partial subset of decoy files are damaged before the freeze.
    """
    reset_sandbox(sandbox_root=isolated_sandbox, file_count=80, file_size=4096)
    telemetry_file = isolated_sandbox / "telemetry" / "attacker_telemetry.json"

    # Spawn ransomware_sim as a child process with 10ms delay per file (~800ms total run)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "src.attacker.ransomware_sim",
            "--sandbox-root",
            str(isolated_sandbox),
            "--delay",
            "0.01",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    first_decoy = isolated_sandbox / "files" / "decoy_0000.dat"

    try:
        # Wait until the attacker starts, writes initial telemetry, and scrambles File #1
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if (
                telemetry_file.exists()
                and first_decoy.exists()
                and not first_decoy.read_bytes().startswith(DECOY_MAGIC_HEADER)
            ):
                break
            time.sleep(0.005)

        # Let it scramble a couple more files, then freeze it cold with SIGSTOP
        time.sleep(0.03)
        os.kill(proc.pid, signal.SIGSTOP)

        # Verify telemetry exists and contains a valid nanosecond start timestamp
        assert telemetry_file.is_file()
        telemetry_data = json.loads(telemetry_file.read_text(encoding="utf-8"))
        assert isinstance(telemetry_data["attack_start_ns"], int)
        assert telemetry_data["pid"] == proc.pid

        # Verify that the attack was stopped mid-way (some files damaged, most still intact)
        report = count_damaged_files(sandbox_root=isolated_sandbox)
        assert 1 <= report["damaged_files"] < 80
        assert report["intact_files"] == 80 - report["damaged_files"]

    finally:
        # Always clean up the frozen child process with SIGKILL so no zombie remains
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3.0)
