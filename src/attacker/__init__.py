"""
Attacker & Sandbox Package (Member A — Ismail Nooruddin).

Modules in this package:
  - sandbox_setup.py   : Isolated decoy sandbox creation, reset, cleanup, and SHA-256 damage verification
  - ransomware_sim.py  : Safe XOR file-scrambling attack simulator with nanosecond telemetry (Step 4)
  - benign_activity.py : Harmless normal file-activity generator for false-alarm testing (Step 5)
"""

from src.attacker.sandbox_setup import (
    assert_safe_sandbox,
    cleanup_sandbox,
    compute_sha256,
    count_damaged_files,
    generate_decoy_payload,
    reset_sandbox,
)

__all__ = [
    "assert_safe_sandbox",
    "compute_sha256",
    "generate_decoy_payload",
    "reset_sandbox",
    "count_damaged_files",
    "cleanup_sandbox",
]
