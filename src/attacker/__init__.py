"""
Attacker & Sandbox Package (Member A — Ismail Nooruddin).

Modules in this package:
  - sandbox_setup.py   : Isolated decoy sandbox creation, reset, cleanup, and SHA-256 damage verification
  - ransomware_sim.py  : Safe XOR file-scrambling attack simulator with nanosecond telemetry
  - benign_activity.py : Harmless normal file-activity generator for false-alarm testing (Step 5)

Note: Submodules are intentionally not pre-imported here so that running any module
directly via `python -m src.attacker.<module>` executes cleanly without Python
`runpy` RuntimeWarnings.
"""
