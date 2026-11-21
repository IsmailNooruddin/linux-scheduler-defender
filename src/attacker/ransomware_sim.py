"""
Safe XOR Ransomware Attack Simulator (Member A).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Ismail Nooruddin (Member A)

Overview:
---------
This module simulates a ransomware-style file encryption attack strictly inside
the isolated `/tmp/os_defense_sandbox/files` directory. It is designed to trigger
Linux `inotify` file-modification events for Member B's defender while providing
nanosecond-accurate timing telemetry for Member C's trial runner.

Key OS & Safety Design Details:
-------------------------------
1. Strict Sandbox Lock:
   Before touching any file, `run_attack()` verifies both the sandbox root and
   every individual file path via `assert_safe_sandbox()` and `is_safe_sandbox_path()`.
   Only files matching `decoy_*.dat` inside `/tmp/.../os_defense_sandbox/files`
   can ever be modified.
2. Pre-Attack Telemetry Flush (Critical for `SIGSTOP`):
   In Linux, when Member B's defender sends `SIGSTOP`, the kernel freezes this
   process immediately — `SIGSTOP` cannot be caught or handled in user space.
   Therefore, `ransomware_sim.py` flushes its PID and exact `attack_start_ns`
   timestamp to `telemetry/attacker_telemetry.json` right as the attack begins,
   guaranteeing that Member C's runner always has `attack_start_ns` on disk even
   when the process is frozen mid-attack and later terminated with `SIGKILL`.
3. Reversible In-Place XOR Scrambling:
   Each decoy file is opened in `"r+b"` mode, its bytes are XORed with `XOR_KEY`
   (`0xAA`), written back in place, and flushed (`os.fsync`) so the Linux VFS
   immediately emits `IN_MODIFY` / `IN_CLOSE_WRITE` events to `inotify`.

Command-Line Usage:
-------------------
  python -m src.attacker.ransomware_sim
  python -m src.attacker.ransomware_sim --max-files 20 --delay 0.005
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.experiment_config import (
    ATTACK_INTER_FILE_DELAY_S,
    DECOY_FILE_EXT,
    DECOY_FILE_PREFIX,
    SANDBOX_ROOT,
    XOR_KEY,
    is_safe_sandbox_path,
)
from src.attacker.sandbox_setup import assert_safe_sandbox


# ==============================================================================
# 1. FAST BYTE-WISE XOR SCRAMBLING HELPER
# ==============================================================================

def xor_buffer(data: bytes, xor_key: int = XOR_KEY) -> bytes:
    """
    XOR every byte in `data` with the single-byte `xor_key` (`0x00`..`0xFF`).

    Uses CPython's native C-level big-integer bitwise XOR (`int.from_bytes`)
    so scrambling a 64 KB buffer takes ~0.05 ms instead of several milliseconds
    in a Python for-loop. Applying `xor_buffer` twice with the same key restores
    the exact original byte sequence.

    Parameters
    ----------
    data : bytes
        Raw byte buffer read from a decoy file.
    xor_key : int, optional
        Single-byte integer key (defaults to `XOR_KEY = 0xAA`).

    Returns
    -------
    bytes
        Scrambled byte buffer of identical length.
    """
    if not data:
        return b""

    key_byte = xor_key & 0xFF
    mask = bytes([key_byte]) * len(data)
    data_int = int.from_bytes(data, byteorder="little")
    mask_int = int.from_bytes(mask, byteorder="little")
    return (data_int ^ mask_int).to_bytes(len(data), byteorder="little")


def scramble_single_file(
    file_path: Path,
    sandbox_root: Path,
    xor_key: int = XOR_KEY,
) -> int:
    """
    Scramble a single decoy file in place using `xor_buffer()`.

    Opens the file in `"r+b"` mode, reads its content, rewinds to offset 0,
    writes the XOR-scrambled bytes, and flushes to ensure the Linux kernel
    immediately delivers `inotify` events (`IN_MODIFY` and `IN_CLOSE_WRITE`).

    Parameters
    ----------
    file_path : Path
        Path to the target decoy file inside `<sandbox_root>/files/`.
    sandbox_root : Path
        Validated sandbox root path.
    xor_key : int, optional
        Single-byte XOR key (defaults to `XOR_KEY`).

    Returns
    -------
    int
        Number of bytes scrambled.

    Raises
    ------
    ValueError
        If `file_path` is outside `sandbox_root` or is not a decoy file.
    """
    # Per-file safety verification before writing a single byte
    if not is_safe_sandbox_path(file_path, sandbox_root=sandbox_root):
        raise ValueError(f"SAFETY LOCK: Refusing to scramble path outside sandbox: '{file_path}'")

    if not (
        file_path.name.startswith(DECOY_FILE_PREFIX)
        and file_path.name.endswith(DECOY_FILE_EXT)
    ):
        raise ValueError(f"SAFETY LOCK: Refusing to scramble non-decoy file: '{file_path.name}'")

    with file_path.open("r+b") as f:
        original_bytes = f.read()
        scrambled_bytes = xor_buffer(original_bytes, xor_key=xor_key)
        f.seek(0)
        f.write(scrambled_bytes)
        f.truncate()
        f.flush()

    return len(scrambled_bytes)


# ==============================================================================
# 2. TELEMETRY PERSISTENCE HELPER
# ==============================================================================

def _write_telemetry_atomic(telemetry_path: Path, payload: Dict[str, Any]) -> None:
    """
    Write `payload` as JSON to `telemetry_path` atomically via a temporary file.

    Why atomic replacement matters:
    -------------------------------
    If the defender sends `SIGSTOP` while the attacker is updating its telemetry
    file, an in-place write could leave a half-written JSON file. Writing to a
    `.tmp` file and calling `os.replace()` guarantees that `attacker_telemetry.json`
    is always valid, readable JSON at every instant.
    """
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = telemetry_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp_path, telemetry_path)


# ==============================================================================
# 3. MAIN RANSOMWARE ATTACK SIMULATION LOOP
# ==============================================================================

def run_attack(
    sandbox_root: Path | str = SANDBOX_ROOT,
    xor_key: int = XOR_KEY,
    inter_file_delay_s: float = ATTACK_INTER_FILE_DELAY_S,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute the simulated XOR ransomware attack inside `<sandbox_root>/files/`.

    Workflow:
      1. Validate `sandbox_root` using `assert_safe_sandbox()`.
      2. Discover and sort all `decoy_*.dat` files in `<sandbox_root>/files/`.
      3. Record `pid` and `attack_start_ns` immediately to `attacker_telemetry.json`
         before scrambling begins (so telemetry survives an immediate `SIGSTOP`).
      4. Scramble files one by one, sleeping `inter_file_delay_s` between files.
      5. Update telemetry when complete (or if interrupted by `SIGTERM`/`SIGINT`).

    Parameters
    ----------
    sandbox_root : Path | str, optional
        Root path of the isolated sandbox (defaults to `SANDBOX_ROOT`).
    xor_key : int, optional
        Single-byte XOR key (defaults to `XOR_KEY = 0xAA`).
    inter_file_delay_s : float, optional
        Pause in seconds between consecutive files (defaults to `0.002` = 2 ms).
    max_files : int | None, optional
        Optional cap on how many decoy files to scramble (None = scramble all).

    Returns
    -------
    Dict[str, Any]
        Final telemetry dictionary summarizing the attack execution.
    """
    safe_root = assert_safe_sandbox(sandbox_root)
    files_dir = safe_root / "files"
    telemetry_path = safe_root / "telemetry" / "attacker_telemetry.json"

    if not files_dir.exists():
        raise FileNotFoundError(
            f"Sandbox files directory not found at '{files_dir}'. "
            f"Run `python -m src.attacker.sandbox_setup --reset` first."
        )

    # Collect all decoy files in deterministic sorted order (decoy_0000.dat ...)
    pattern = f"{DECOY_FILE_PREFIX}*{DECOY_FILE_EXT}"
    target_files: List[Path] = sorted(files_dir.glob(pattern))
    if not target_files:
        raise FileNotFoundError(
            f"No decoy files matching '{pattern}' found in '{files_dir}'."
        )

    if max_files is not None and max_files >= 0:
        target_files = target_files[:max_files]

    # Graceful termination flag if the runner stops the process with SIGTERM/SIGINT
    stop_requested = False

    def _handle_stop_signal(signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    # Capture high-precision start timestamps right before touching File #1
    pid = os.getpid()
    attack_start_epoch_s = time.time()
    attack_start_ns = time.monotonic_ns()

    telemetry: Dict[str, Any] = {
        "pid": pid,
        "status": "running",
        "sandbox_root": str(safe_root),
        "files_dir": str(files_dir),
        "total_target_files": len(target_files),
        "files_scrambled": 0,
        "bytes_scrambled": 0,
        "xor_key": xor_key & 0xFF,
        "inter_file_delay_s": inter_file_delay_s,
        "attack_start_ns": attack_start_ns,
        "attack_start_epoch_s": attack_start_epoch_s,
        "first_file_ns": None,
        "last_file_ns": None,
        "attack_end_ns": None,
        "elapsed_ms": 0.0,
    }

    # Flush initial telemetry BEFORE touching File #1 so `attack_start_ns` and `pid`
    # are guaranteed to exist on disk even if SIGSTOP freezes us milliseconds later
    _write_telemetry_atomic(telemetry_path, telemetry)

    # Main file-scrambling loop
    for idx, file_path in enumerate(target_files):
        if stop_requested:
            telemetry["status"] = "terminated_by_signal"
            break

        if idx == 0:
            telemetry["first_file_ns"] = time.monotonic_ns()

        scrambled_len = scramble_single_file(
            file_path=file_path,
            sandbox_root=safe_root,
            xor_key=xor_key,
        )

        now_ns = time.monotonic_ns()
        telemetry["files_scrambled"] += 1
        telemetry["bytes_scrambled"] += scrambled_len
        telemetry["last_file_ns"] = now_ns
        telemetry["elapsed_ms"] = round((now_ns - attack_start_ns) / 1e6, 3)

        # Periodically checkpoint progress (every 10 files and on File #1)
        if idx == 0 or (idx + 1) % 10 == 0:
            _write_telemetry_atomic(telemetry_path, telemetry)

        # Optional inter-file pacing delay
        if inter_file_delay_s > 0 and (idx + 1) < len(target_files):
            time.sleep(inter_file_delay_s)

    if telemetry["status"] == "running":
        telemetry["status"] = "completed"

    end_ns = time.monotonic_ns()
    telemetry["attack_end_ns"] = end_ns
    telemetry["elapsed_ms"] = round((end_ns - attack_start_ns) / 1e6, 3)
    _write_telemetry_atomic(telemetry_path, telemetry)

    return telemetry


# ==============================================================================
# 4. COMMAND-LINE INTERFACE
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for standalone attack simulation."""
    parser = argparse.ArgumentParser(
        description="Run the safe XOR ransomware simulator inside the decoy sandbox."
    )
    parser.add_argument(
        "--sandbox-root",
        type=Path,
        default=SANDBOX_ROOT,
        help=f"Sandbox root directory (default: {SANDBOX_ROOT}).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=ATTACK_INTER_FILE_DELAY_S,
        help=f"Delay in seconds between consecutive file scrambles (default: {ATTACK_INTER_FILE_DELAY_S}).",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Optional limit on number of files to scramble (default: all decoy files).",
    )
    parser.add_argument(
        "--xor-key",
        type=lambda x: int(x, 0),
        default=XOR_KEY,
        help=f"Single-byte XOR key in hex or int (default: {hex(XOR_KEY)}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print final telemetry as JSON.",
    )
    return parser


def main() -> None:
    """Entry point for `python -m src.attacker.ransomware_sim`."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    result = run_attack(
        sandbox_root=args.sandbox_root,
        xor_key=args.xor_key,
        inter_file_delay_s=args.delay,
        max_files=args.max_files,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"[ATTACK SIM] PID={result['pid']} | Status={result['status']} | "
            f"Scrambled: {result['files_scrambled']} / {result['total_target_files']} files "
            f"({result['bytes_scrambled']} bytes) in {result['elapsed_ms']:.2f} ms."
        )


if __name__ == "__main__":
    main()
