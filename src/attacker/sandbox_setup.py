"""
Isolated Decoy Sandbox Manager and File-Damage Verifier (Member A).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Ismail Nooruddin (Member A)

Overview:
---------
This module manages the disposable test folder (`/tmp/os_defense_sandbox`) used
in every experimental trial. It performs four core tasks:
  1. Safety Enforcement (`assert_safe_sandbox`):
     Verifies that all operations occur strictly inside `/tmp/.../os_defense_sandbox`
     and refuses to touch any user or system directory outside `/tmp`.
  2. Sandbox Initialization & Reset (`reset_sandbox`):
     Wipes any previous trial state, recreates `files/` and `telemetry/` folders,
     and generates deterministic dummy decoy files (`decoy_0000.dat` ...).
  3. Baseline Fingerprinting (`manifest.json`):
     Computes and stores the original SHA-256 hash of every clean decoy file.
  4. Ground-Truth Damage Counting (`count_damaged_files`):
     Compares the post-trial sandbox against `manifest.json` to report the exact
     number of decoy files scrambled or deleted before the defender froze the attack.

Command-Line Usage:
-------------------
  python -m src.attacker.sandbox_setup --reset
  python -m src.attacker.sandbox_setup --verify
  python -m src.attacker.sandbox_setup --clean
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from config.experiment_config import (
    DECOY_FILE_COUNT,
    DECOY_FILE_EXT,
    DECOY_FILE_PREFIX,
    DECOY_FILE_SIZE_BYTES,
    DECOY_MAGIC_HEADER,
    SANDBOX_ROOT,
    is_safe_sandbox_path,
)


# ==============================================================================
# 1. SAFETY GUARD & CRYPTOGRAPHIC HASHING HELPERS
# ==============================================================================

def assert_safe_sandbox(sandbox_root: Path | str = SANDBOX_ROOT) -> Path:
    """
    Validate that `sandbox_root` is a safe, isolated `/tmp/.../os_defense_sandbox` directory.

    Parameters
    ----------
    sandbox_root : Path | str, optional
        Target root directory for the sandbox (defaults to `SANDBOX_ROOT`).

    Returns
    -------
    Path
        The resolved `Path` object if validation passes.

    Raises
    ------
    ValueError
        If `sandbox_root` fails `is_safe_sandbox_path()`, protecting non-sandbox
        folders from ever being modified or deleted.
    """
    root_path = Path(sandbox_root)
    if not is_safe_sandbox_path(root_path, sandbox_root=root_path):
        raise ValueError(
            f"SAFETY LOCK ENGAGED: Refusing to operate on unsafe path '{root_path}'. "
            f"All sandbox operations must reside strictly inside '/tmp/.../os_defense_sandbox'."
        )
    return root_path.resolve()


def compute_sha256(file_path: Path) -> str:
    """
    Compute the SHA-256 hex digest of a file on disk.

    Reads in 64 KB chunks so memory usage remains constant regardless of file size.

    Parameters
    ----------
    file_path : Path
        Path to the file to hash.

    Returns
    -------
    str
        Lowercase 64-character hexadecimal SHA-256 digest string.
    """
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_decoy_payload(
    file_index: int,
    file_size: int = DECOY_FILE_SIZE_BYTES,
) -> bytes:
    """
    Construct deterministic dummy content for a single clean decoy file.

    Every clean decoy file begins with `DECOY_MAGIC_HEADER` (`b"OS_DECOY_CLEAN_V1\\n"`)
    followed by a unique file index tag and a deterministic repeating byte pattern
    sized to `file_size` bytes. Using unique index tags ensures every decoy file
    has a distinct SHA-256 fingerprint in `manifest.json`.

    Parameters
    ----------
    file_index : int
        Zero-based index of the decoy file (`0` .. `file_count - 1`).
    file_size : int, optional
        Target size of the file in bytes (defaults to `DECOY_FILE_SIZE_BYTES`).

    Returns
    -------
    bytes
        Byte buffer of length `max(len(header), file_size)`.
    """
    index_line = f"FILE_INDEX={file_index:04d}\n".encode("ascii")
    prefix = DECOY_MAGIC_HEADER + index_line

    if file_size <= len(prefix):
        return prefix

    # Fill the remainder with a deterministic 64-byte pattern unique to this file index
    remaining = file_size - len(prefix)
    seed_block = hashlib.sha256(prefix).digest() + hashlib.md5(prefix).digest()  # 48 bytes
    repeats = (remaining // len(seed_block)) + 1
    body = (seed_block * repeats)[:remaining]
    return prefix + body


# ==============================================================================
# 2. SANDBOX CREATION, RESET & MANIFEST GENERATION
# ==============================================================================

def reset_sandbox(
    sandbox_root: Path | str = SANDBOX_ROOT,
    file_count: int = DECOY_FILE_COUNT,
    file_size: int = DECOY_FILE_SIZE_BYTES,
) -> Dict[str, Any]:
    """
    Wipe and recreate the isolated decoy sandbox before an experimental trial.

    Steps performed:
      1. Verify `sandbox_root` passes the safety lock.
      2. Remove any existing files/telemetry inside `sandbox_root`.
      3. Create `<sandbox_root>/files/` and `<sandbox_root>/telemetry/`.
      4. Populate `files/` with `file_count` clean decoy files (`decoy_0000.dat` ...).
      5. Save each file's baseline SHA-256 hash into `<sandbox_root>/manifest.json`.

    Parameters
    ----------
    sandbox_root : Path | str, optional
        Root path for the sandbox (defaults to `SANDBOX_ROOT`).
    file_count : int, optional
        Number of decoy files to create (defaults to `DECOY_FILE_COUNT`).
    file_size : int, optional
        Size in bytes of each decoy file (defaults to `DECOY_FILE_SIZE_BYTES`).

    Returns
    -------
    Dict[str, Any]
        Metadata dictionary describing the initialized sandbox.
    """
    if file_count <= 0:
        raise ValueError(f"file_count must be positive (got {file_count}).")
    if file_size <= 0:
        raise ValueError(f"file_size must be positive (got {file_size}).")

    safe_root = assert_safe_sandbox(sandbox_root)
    start_ns = time.monotonic_ns()

    # Step 1: Cleanly remove any leftover state from a previous trial
    if safe_root.exists():
        shutil.rmtree(safe_root)

    # Step 2: Recreate the directory structure
    files_dir = safe_root / "files"
    telemetry_dir = safe_root / "telemetry"
    manifest_path = safe_root / "manifest.json"

    files_dir.mkdir(parents=True, exist_ok=True)
    telemetry_dir.mkdir(parents=True, exist_ok=True)

    # Step 3: Create decoy files and record their baseline SHA-256 hashes
    file_hashes: Dict[str, str] = {}
    for idx in range(file_count):
        filename = f"{DECOY_FILE_PREFIX}{idx:04d}{DECOY_FILE_EXT}"
        file_path = files_dir / filename

        payload = generate_decoy_payload(file_index=idx, file_size=file_size)
        file_path.write_bytes(payload)

        # Compute SHA-256 directly from payload in memory (faster than re-reading disk)
        file_hashes[filename] = hashlib.sha256(payload).hexdigest()

    elapsed_ms = (time.monotonic_ns() - start_ns) / 1e6

    # Step 4: Write the baseline manifest file used later by count_damaged_files()
    manifest_data: Dict[str, Any] = {
        "sandbox_root": str(safe_root),
        "files_dir": str(files_dir),
        "file_count": file_count,
        "file_size_bytes": file_size,
        "magic_header_ascii": DECOY_MAGIC_HEADER.decode("ascii", errors="replace").strip(),
        "created_at_epoch_s": time.time(),
        "setup_elapsed_ms": round(elapsed_ms, 2),
        "files": file_hashes,
    }
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    return {
        "sandbox_root": str(safe_root),
        "files_dir": str(files_dir),
        "telemetry_dir": str(telemetry_dir),
        "manifest_path": str(manifest_path),
        "file_count": file_count,
        "file_size_bytes": file_size,
        "setup_elapsed_ms": round(elapsed_ms, 2),
    }


# ==============================================================================
# 3. GROUND-TRUTH FILE DAMAGE VERIFIER
# ==============================================================================

def count_damaged_files(sandbox_root: Path | str = SANDBOX_ROOT) -> Dict[str, Any]:
    """
    Compare current decoy files against `manifest.json` to count exact file damage.

    A decoy file is counted as **damaged** if:
      - It has been deleted / is missing from `<sandbox_root>/files/`, OR
      - Its current SHA-256 digest differs from its baseline digest in `manifest.json`
        (e.g., XOR-scrambled wholly or partially before `SIGSTOP` froze the attacker).

     Note: Any extra files created by `benign_activity.py` (such as `benign_note_*.txt`)
    are NOT listed in `manifest.json` and therefore never distort the decoy damage count.

    Parameters
    ----------
    sandbox_root : Path | str, optional
        Root path of the sandbox to inspect (defaults to `SANDBOX_ROOT`).

    Returns
    -------
    Dict[str, Any]
        Dictionary containing:
          - `total_files`       : Total decoy files recorded in manifest
          - `damaged_files`     : `modified_files + missing_files` (primary metric for CSV)
          - `intact_files`      : Files whose SHA-256 still matches the clean baseline
          - `modified_files`    : Files present on disk whose content/hash changed
          - `missing_files`     : Files listed in manifest that no longer exist on disk
          - `damage_pct`        : Percentage of decoy files damaged (`0.0` .. `100.0`)
          - `damaged_file_list` : Sorted list of damaged filenames (useful for debugging)
    """
    safe_root = assert_safe_sandbox(sandbox_root)
    manifest_path = safe_root / "manifest.json"
    files_dir = safe_root / "files"

    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Sandbox manifest not found at '{manifest_path}'. "
            f"Run `reset_sandbox()` before verifying damage."
        )

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_hashes: Dict[str, str] = manifest_data.get("files", {})
    total_files = len(expected_hashes)

    intact_files = 0
    modified_files = 0
    missing_files = 0
    damaged_file_list: List[str] = []

    for filename, expected_sha256 in expected_hashes.items():
        candidate_path = files_dir / filename
        if not candidate_path.exists():
            missing_files += 1
            damaged_file_list.append(filename)
            continue

        current_sha256 = compute_sha256(candidate_path)
        if current_sha256 != expected_sha256:
            modified_files += 1
            damaged_file_list.append(filename)
        else:
            intact_files += 1

    damaged_files = modified_files + missing_files
    damage_pct = round((damaged_files / total_files) * 100.0, 2) if total_files > 0 else 0.0

    return {
        "total_files": total_files,
        "damaged_files": damaged_files,
        "intact_files": intact_files,
        "modified_files": modified_files,
        "missing_files": missing_files,
        "damage_pct": damage_pct,
        "damaged_file_list": damaged_file_list,
    }


# ==============================================================================
# 4. SANDBOX CLEANUP
# ==============================================================================

def cleanup_sandbox(sandbox_root: Path | str = SANDBOX_ROOT) -> bool:
    """
    Safely delete the sandbox directory after experiments complete.

    Parameters
    ----------
    sandbox_root : Path | str, optional
        Root path of the sandbox to remove (defaults to `SANDBOX_ROOT`).

    Returns
    -------
    bool
        True if the directory existed and was removed; False if it did not exist.
    """
    safe_root = assert_safe_sandbox(sandbox_root)
    if safe_root.exists():
        shutil.rmtree(safe_root)
        return True
    return False


# ==============================================================================
# 5. COMMAND-LINE INTERFACE (FOR MANUAL TESTING & SHELL SCRIPTS)
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for standalone sandbox management."""
    parser = argparse.ArgumentParser(
        description="Manage the isolated decoy sandbox and inspect file damage."
    )
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--reset",
        action="store_true",
        help="Wipe and recreate the decoy sandbox with fresh dummy files.",
    )
    action_group.add_argument(
        "--verify",
        action="store_true",
        help="Compare sandbox files against manifest.json and report damaged file counts.",
    )
    action_group.add_argument(
        "--clean",
        action="store_true",
        help="Delete the sandbox directory completely.",
    )

    parser.add_argument(
        "--sandbox-root",
        type=Path,
        default=SANDBOX_ROOT,
        help=f"Sandbox root directory (default: {SANDBOX_ROOT}).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DECOY_FILE_COUNT,
        help=f"Number of decoy files to create on --reset (default: {DECOY_FILE_COUNT}).",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=DECOY_FILE_SIZE_BYTES,
        help=f"Size per decoy file in bytes on --reset (default: {DECOY_FILE_SIZE_BYTES}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print output as machine-readable JSON.",
    )
    return parser


def main() -> None:
    """Entry point for `python -m src.attacker.sandbox_setup`."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.reset:
        info = reset_sandbox(
            sandbox_root=args.sandbox_root,
            file_count=args.count,
            file_size=args.size,
        )
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            print(
                f"[SANDBOX RESET] Created {info['file_count']} clean decoy files "
                f"({info['file_size_bytes']} bytes each) at '{info['files_dir']}' "
                f"in {info['setup_elapsed_ms']:.2f} ms."
            )

    elif args.verify:
        report = count_damaged_files(sandbox_root=args.sandbox_root)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(
                f"[SANDBOX VERIFY] Damaged: {report['damaged_files']} / {report['total_files']} "
                f"({report['damage_pct']:.2f}%) | Intact: {report['intact_files']} | "
                f"Modified: {report['modified_files']} | Missing: {report['missing_files']}"
            )

    elif args.clean:
        removed = cleanup_sandbox(sandbox_root=args.sandbox_root)
        if args.json:
            print(json.dumps({"sandbox_root": str(args.sandbox_root), "removed": removed}))
        else:
            status = "Removed" if removed else "Already clean (not found)"
            print(f"[SANDBOX CLEAN] {status}: '{args.sandbox_root}'")


if __name__ == "__main__":
    main()
