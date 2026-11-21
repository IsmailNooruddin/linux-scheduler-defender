# Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?

**Course:** Operating Systems (Term Project — Part 4)  
**Section:** L4  
**Group Members:** Ismail Nooruddin, Hassaan Ul Qadir, Munir Tariq, Rayyan Alvi  

---

## Overview

When a CPU-intensive local AI-style workload competes with a ransomware-like attack for CPU time, how do Linux scheduling controls (`nice` priority, `chrt` real-time scheduling classes, `cgroup v2` `cpu.weight` and `cpu.max`, and `taskset` CPU core pinning) affect:

1. **Detection & freeze delay (ms)** of a lightweight `inotify`-based defender (`SIGSTOP`)
2. **Files damaged** before the attacker is frozen
3. **Workload slowdown (%)** imposed on the competing CPU-heavy workload
4. **False alarm rate (%)** on normal, benign file activity

**Core OS Areas:** Scheduling (primary), Persistence/I/O, Security.

---

## Repository Structure

```text
linux-scheduler-defender/
├── README.md                        # Project documentation, setup, and usage guide
├── requirements.txt                 # Shared Python dependencies
├── pytest.ini                       # Pytest path configuration
├── .gitignore                       # Git ignore rules
│
├── config/                          # [Member A — Ismail Nooruddin] Shared team contract
│   ├── __init__.py
│   └── experiment_config.py         # Sandbox paths, thresholds, scheduler setups, CSV schema
│
├── src/
│   ├── __init__.py
│   │
│   ├── attacker/                    # [Member A — Ismail Nooruddin] (Completed)
│   │   ├── __init__.py
│   │   ├── sandbox_setup.py         # Decoy sandbox reset, cleanup, and SHA-256 damage counter
│   │   ├── ransomware_sim.py        # Safe XOR file-scrambling simulator with atomic telemetry
│   │   └── benign_activity.py       # Harmless normal file writer for false-alarm testing
│   │
│   ├── defender/                    # [Member B — Hassaan Ul Qadir]
│   │   ├── __init__.py
│   │   ├── monitor.py               # inotify file-event watcher and sliding-window burst detector
│   │   └── defender.py              # Identifies attacker PID on burst and freezes via SIGSTOP
│   │
│   ├── workload/                    # [Member C — Munir Tariq]
│   │   ├── __init__.py
│   │   └── cpu_stress.py            # Synthetic multi-process CPU load (1 worker per core)
│   │
│   ├── scheduler/                   # [Member C — Munir Tariq]
│   │   ├── __init__.py
│   │   ├── profiles.py              # Linux scheduler wrappers (default, nice, chrt, cgroup v2, taskset)
│   │   └── runner.py                # Automated single-trial and 20-trial batch orchestrator
│   │
│   └── analysis/                    # [Member D — Rayyan Alvi]
│       ├── __init__.py
│       ├── summarize.py             # Aggregates raw trial CSVs into statistical summary tables
│       └── plot_results.py          # Generates comparative figures for report and slides
│
├── scripts/                         # [Member C — Munir Tariq] WSL2/Linux helper shell scripts
│   ├── check_env.sh                 # Verifies WSL2 kernel, cgroup v2, chrt/taskset/nice, Python deps
│   ├── setup_cgroups.sh             # Configures cgroup v2 directories and enables +cpu controller
│   └── run_all_experiments.sh       # One-command full benchmark suite runner
│
├── tests/                           # Automated module verification tests
│   ├── test_attacker.py             # [Member A — Ismail Nooruddin] Safety, XOR, benign & SIGSTOP tests
│   ├── test_defender.py             # [Member B — Hassaan Ul Qadir] Burst detection & false-alarm tests
│   └── test_workload.py             # [Member C — Munir Tariq] CPU load & throughput tests
│
├── results/                         # [Member D — Rayyan Alvi] Experiment outputs
│   ├── raw/                         # Per-trial raw CSV logs (results/raw/trials.csv)
│   ├── processed/                   # Aggregated summary tables (CSV & Markdown)
│   └── figures/                     # Generated plots (PNG) for report & presentation
│
└── docs/                            # Project proposal, report drafts, and presentation slides
```

---

## Team Division

| Role | Team Member | Responsibilities & Owned Paths |
| :--- | :--- | :--- |
| **Member A** | **Ismail Nooruddin** | Shared configuration contract, isolated decoy sandbox & SHA-256 damage verifier, safe XOR ransomware simulator, benign normal-activity generator, and attacker test suite (`config/`, `src/attacker/`, `tests/test_attacker.py`). |
| **Member B** | **Hassaan Ul Qadir** | Lightweight `inotify` folder monitor, sliding-window burst detector, PID lookup, and `SIGSTOP` containment (`src/defender/`, `tests/test_defender.py`). |
| **Member C** | **Munir Tariq** | Synthetic CPU-heavy workload, Linux scheduler / `cgroup v2` profile wrappers, environment/cgroup scripts, and automated 20-trial experiment runner (`src/workload/`, `src/scheduler/`, `scripts/`, `tests/test_workload.py`). |
| **Member D** | **Rayyan Alvi** | Raw CSV aggregation, statistical summaries, comparative graphs, and final documentation polish (`src/analysis/`, `results/`, `README.md`). |
| **All Members** | **Entire Team** | Experimental analysis, final report, presentation slides, and viva preparation. |

---

## Environment Requirements & Setup (WSL2 / Linux)

All components run on **WSL2 (Ubuntu Linux)** so native Linux scheduling (`nice`, `chrt`, `taskset`, `cgroup v2`), kernel file events (`inotify`), and signals (`SIGSTOP`) operate identically to a real Linux host.

```bash
# 1. Create and activate a virtual environment in your Linux home directory
mkdir -p ~/venvs
python3 -m venv ~/venvs/linux-scheduler-defender
source ~/venvs/linux-scheduler-defender/bin/activate

# 2. Install project dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Usage & Verification

### 1. Decoy Sandbox & Attack Simulator (Member A — Completed)

All decoy files and telemetry live strictly inside native Linux `/tmp/os_defense_sandbox` (enforced by a hard safety lock in `is_safe_sandbox_path()` and `assert_safe_sandbox()`).

```bash
# 1. Reset the sandbox (creates 300 clean 64 KB decoy files + SHA-256 manifest.json)
python -m src.attacker.sandbox_setup --reset

# 2. Run the safe XOR ransomware simulator (e.g., scramble 15 files or omit --max-files for all 300)
python -m src.attacker.ransomware_sim --max-files 15

# 3. Verify exact ground-truth file damage against manifest.json
python -m src.attacker.sandbox_setup --verify

# 4. Run harmless normal file activity (for false-alarm testing — causes 0% decoy damage)
python -m src.attacker.benign_activity --duration 2.0 --interval 0.5
python -m src.attacker.sandbox_setup --verify

# 5. Clean up /tmp/os_defense_sandbox when finished
python -m src.attacker.sandbox_setup --clean
```

Run the automated test suite (8 tests covering safety locks, manifest hashing, XOR reversibility, partial attack telemetry, benign activity, and live Linux `SIGSTOP` mid-attack freezing):

```bash
pytest -v tests/test_attacker.py
```

### 2. Integration Contract for Members B, C, and D

All shared constants and file paths are imported from `config/experiment_config.py`:

- **Watched Directory (for Member B's `inotify` monitor):**
  - `SANDBOX_FILES_DIR` (`/tmp/os_defense_sandbox/files`)
  - Burst thresholds: `BURST_EVENT_THRESHOLD = 5` files within `BURST_WINDOW_MS = 500` ms
  - Ready handshake flag: `DEFENDER_READY_FLAG` (`/tmp/os_defense_sandbox/telemetry/defender_ready.flag`)
- **Per-Trial Telemetry Files (written to `/tmp/os_defense_sandbox/telemetry/`):**
  - `ATTACKER_TELEMETRY_PATH` (`attacker_telemetry.json`): contains `pid`, `attack_start_ns` (flushed atomically *before* File #1 is scrambled so it survives `SIGSTOP`), `first_file_ns`, `files_scrambled`, `status`.
  - `BENIGN_TELEMETRY_PATH` (`benign_telemetry.json`): contains `pid`, `start_ns`, `files_written`, `status`.
  - `DEFENDER_TELEMETRY_PATH` (`defender_telemetry.json`): Member B writes `detection_time_ns`, `freeze_time_ns`, `frozen_pid`, `triggered`.
  - `WORKLOAD_TELEMETRY_PATH` (`workload_telemetry.json`): Member C writes `work_units_completed`, `elapsed_s`, `work_units_per_sec`.
- **Ground-Truth Damage Function (for Member C's `runner.py`):**
  - Call `from src.attacker.sandbox_setup import reset_sandbox, count_damaged_files, cleanup_sandbox`
  - `count_damaged_files()["damaged_files"]` returns the exact integer count of scrambled/missing decoy files.
- **Raw Trial Output Schema (for Member C & Member D):**
  - Path: `RAW_TRIALS_CSV` (`results/raw/trials.csv`)
  - Columns: `RAW_CSV_COLUMNS` (`setup`, `trial_id`, `mode`, `detected`, `false_alarm`, `detection_delay_ms`, `files_damaged`, `total_decoy_files`, `workload_throughput`, `timed_out`, `notes`)

---

## Results

> *Summary tables and graphs will be added under `results/processed/` and `results/figures/` once the 20-trial benchmark suite across all scheduler setups is executed.*
