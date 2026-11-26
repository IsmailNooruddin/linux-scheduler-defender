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
├── .gitattributes                   # Keeps shell scripts on LF line endings (needed on WSL2)
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
│   ├── defender/                    # [Member B — Hassaan Ul Qadir] (Completed)
│   │   ├── __init__.py
│   │   ├── monitor.py               # inotify file-event watcher and sliding-window burst detector
│   │   └── defender.py              # Identifies attacker PID on burst and freezes via SIGSTOP
│   │
│   ├── workload/                    # [Member C — Munir Tariq] (Completed)
│   │   ├── __init__.py
│   │   └── cpu_stress.py            # Synthetic multi-process CPU load (1 worker per core)
│   │
│   ├── scheduler/                   # [Member C — Munir Tariq] (Completed)
│   │   ├── __init__.py
│   │   ├── profiles.py              # Linux scheduler wrappers (default, nice, chrt, cgroup v2, taskset)
│   │   └── runner.py                # Automated single-trial and 20-trial batch orchestrator
│   │
│   └── analysis/                    # [Member D — Rayyan Alvi] (Completed)
│       ├── __init__.py
│       ├── summarize.py             # Aggregates raw trial CSVs into statistical summary tables
│       └── plot_results.py          # Generates comparative figures for report and slides
│
├── scripts/                         # [Member C — Munir Tariq] (Completed) WSL2/Linux helper shell scripts
│   ├── check_env.sh                 # Verifies WSL2 kernel, cgroup v2, chrt/taskset/nice, Python deps
│   ├── setup_cgroups.sh             # Configures cgroup v2 directories and enables +cpu controller
│   └── run_all_experiments.sh       # One-command full benchmark suite runner
│
├── tests/                           # Automated module verification tests
│   ├── test_attacker.py             # [Member A — Ismail Nooruddin] Safety, XOR, benign & SIGSTOP tests
│   ├── test_defender.py             # [Member B — Hassaan Ul Qadir] Burst detection & false-alarm tests
│   ├── test_workload.py             # [Member C — Munir Tariq] CPU load & throughput tests
│   └── test_scheduler.py            # [Member C — Munir Tariq] Scheduler profile & trial runner tests
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
| **Member C** | **Munir Tariq** | Synthetic CPU-heavy workload, Linux scheduler / `cgroup v2` profile wrappers, environment/cgroup scripts, and automated 20-trial experiment runner (`src/workload/`, `src/scheduler/`, `scripts/`, `tests/test_workload.py`, `tests/test_scheduler.py`). |
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

### 2. Lightweight Real-Time Defender (Member B — Completed)

The defender watches `/tmp/os_defense_sandbox/files` via Linux `inotify` (`inotify_simple`), counts **distinct** modified files inside a `500 ms` sliding window (`BURST_EVENT_THRESHOLD = 5`), discovers the offending process through `/proc/<pid>/fd` (with a fast `/proc/<pid>/cmdline` fallback), and freezes it immediately with `SIGSTOP`. Protected PIDs (`0`, `1`, self, parent, and `--whitelist-pid`) are never signalled.

```bash
# Run unit tests (BurstDetector logic, /proc fd scan, protected PIDs) + live WSL2 attack & benign integration tests
pytest -v tests/test_defender.py

# Run the defender standalone (after `sandbox_setup --reset`)
python -m src.defender.defender --max-runtime 15 --json
```

### 3. Workload, Scheduler Profiles & Trial Runner (Member C — Completed)

**One-time WSL2 requirement: cgroup v2 with the `cpu` controller.** Check with `scripts/check_env.sh`. If it reports that
`/sys/fs/cgroup` is not `cgroup2fs`, add this to `%UserProfile%\.wslconfig` on Windows, run `wsl --shutdown` in PowerShell, and reopen Ubuntu:

```ini
[wsl2]
kernelCommandLine = cgroup_no_v1=all
```

```bash
# 0. Check the environment (WSL2 kernel, cgroup v2, nice/chrt/taskset, sudo, RT safety, Python packages)
scripts/check_env.sh

# 1. Unit tests for workload, profiles and runner (root-only checks are skipped without sudo)
pytest -v tests/test_workload.py tests/test_scheduler.py

# 2. Try the pieces by hand
python -m src.workload.cpu_stress --duration 3          # one busy worker per core, prints work units/sec
python -m src.scheduler.profiles --list                 # what every setup does to defender and workload
python -m src.scheduler.profiles --check chrt           # can this setup run on this machine right now?
python -m src.scheduler.runner --dry-run                # print the shuffled trial schedule, run nothing

# 3. Smoke test (about 2 minutes), then the full benchmark (about 15-20 minutes, writes results/raw/trials.csv)
scripts/run_all_experiments.sh --quick
scripts/run_all_experiments.sh
```

`run_all_experiments.sh` runs the environment check, creates the cgroups, runs the runner as root via `sudo` (it asks for your password once and keeps the
virtual environment), always removes the cgroups at the end (even on Ctrl+C), and then calls Member D's `summarize` and `plot_results`.
Extra options go to the runner, for example `--trials 5 --setups default chrt`, `--benign-trials 3`, `--seed 7`, `--no-analysis`.

**How one trial works:** reset sandbox, start the CPU workload under the setup's control, start the defender under its control and wait for
`DEFENDER_READY_FLAG`, launch the attacker (or `benign_activity`), wait until it is frozen / finished / timed out, keep the workload running for at
least 3 s so throughput is measured over the same window everywhere, stop everything, count damaged files, append one row to `trials.csv`.

**Design decisions:**
- Controls are applied between `fork()` and `exec()`, so the defender is already under its control when it starts and every workload worker inherits
  nice value, policy, affinity and cgroup membership. `verify_profile()` reads the real state back from the kernel and a trial whose control did not take effect is retried, never recorded.
- Trials run in shuffled rounds (one trial of every setup per round, seeded with `--seed`), so slow drift such as laptop heat spreads evenly over all setups.
- Real-time safety: the runner refuses `chrt` if kernel RT throttling is off, every trial has a 15 s deadline, and `chrt` trials also get a SCHED_FIFO-99 watchdog that SIGKILLs the defender.
- A harness failure (defender crashes, never gets ready, control not applied) is retried and finally aborts the run. It is never written as a "defender missed the attack" row.

**What the runner expects from the defender (Member B):**
- Started as `python -m src.defender.defender` with no arguments (override with `--defender-cmd`), run from the repository root.
- Creates `DEFENDER_READY_FLAG` once its inotify watch is active, and keeps running until it freezes the attacker or receives `SIGTERM` (then exits with code 0).
- Writes `DEFENDER_TELEMETRY_PATH` (JSON) with `detection_time_ns`, `freeze_time_ns`, `frozen_pid`, `events_seen`, `triggered`, using `time.monotonic_ns()` (same clock as the attacker's `attack_start_ns`).
- `detection_delay_ms = (freeze_time_ns - attack_start_ns) / 1e6`. If `frozen_pid` is not the attacker's PID the attack counts as undetected and the stray process is resumed with `SIGCONT`.

**`results/raw/trials.csv` for Member D:** one row per trial in the column order of `RAW_CSV_COLUMNS`. Empty cells mean "not applicable" (pandas reads them as NaN).

| `mode` | Setups | Use it for |
| :--- | :--- | :--- |
| `attack` | `baseline_no_load`, `default`, `nice`, `chrt`, `cgroup_weight`, `cgroup_max`, `taskset` | detection delay, files damaged, detection rate, workload throughput under that setup |
| `benign` | same as above | false-alarm rate (`false_alarm` column) |
| `solo` | `baseline_workload_solo` | baseline throughput: `slowdown % = (baseline - setup) / baseline * 100` |

Setups that cannot run on the current machine (for example `taskset` with one visible core) are skipped with a `[SKIP]` message and exit code 2.

### 4. Results Analysis & Plotting (Member D — Completed)

Aggregate raw per-trial results (`results/raw/trials.csv`) into statistical summary tables and generate the four comparative figures:

```bash
# 1. Compute per-setup summary statistics (writes results/processed/summary_table.csv & .md)
python -m src.analysis.summarize

# 2. Generate all four comparative figures (writes results/figures/fig1..fig4.png)
python -m src.analysis.plot_results

# Optional: reproducible sensitivity check excluding initial round(s)
python -m src.analysis.summarize --skip-warmup-rounds 1
```

### 5. Shared Telemetry & Integration Contract

All modules import shared constants and paths from `config/experiment_config.py`:

- **Watched Directory:** `SANDBOX_FILES_DIR` (`/tmp/os_defense_sandbox/files`), burst rule `BURST_EVENT_THRESHOLD = 5` distinct files within `BURST_WINDOW_MS = 500` ms, readiness flag `DEFENDER_READY_FLAG`.
- **Per-Trial Telemetry (`/tmp/os_defense_sandbox/telemetry/`):**
  - `attacker_telemetry.json`: `pid`, `attack_start_ns` (flushed atomically before File #1 so it survives `SIGSTOP`), `first_file_ns`, `files_scrambled`, `status`.
  - `benign_telemetry.json`: `pid`, `start_ns`, `files_written`, `status`.
  - `defender_telemetry.json`: `detection_time_ns`, `freeze_time_ns`, `frozen_pid`, `events_seen`, `triggered`, `pid_method`, `status`.
  - `workload_telemetry.json`: `work_units_completed`, `elapsed_s`, `work_units_per_sec`.
- **Ground-Truth Damage Function:** `count_damaged_files()["damaged_files"]` from `src/attacker/sandbox_setup.py`.
- **Raw Output CSV:** `results/raw/trials.csv` with exact column order `RAW_CSV_COLUMNS` (`setup`, `trial_id`, `mode`, `detected`, `false_alarm`, `detection_delay_ms`, `files_damaged`, `total_decoy_files`, `workload_throughput`, `timed_out`, `notes`).

---

## Results

Summary of `195` raw trials (`20` attack trials and `5` benign trials per defender setup, plus `20` solo workload baseline trials) from `results/raw/trials.csv` (see also [summary_table.md](results/processed/summary_table.md) and [summary_table.csv](results/processed/summary_table.csv)):

| Scheduler Setup | Attack Trials | Detected (%) | Delay Mean (ms) | Delay Median (ms) | Delay SD (ms) | Delay P95 (ms) | Files Damaged (Mean / Med / SD) | Throughput Mean / Med (units/s) | Slowdown Mean (%) | Slowdown Median (%) | Benign Trials | False Alarm (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Baseline (No Load) | 20 | 20/20 (100.0%) | 13.27 | 13.54 | 0.70 | 14.14 | 5.65 / 6.0 / 0.49 | — | — | — | 5 | 0/5 (0.0%) |
| Baseline (Workload Solo) | 0 | — | — | — | — | — | — | 518.8 / 523.9 | +0.00% | +0.00% | 0 | — |
| Default (CFS) | 20 | 20/20 (100.0%) | 29.46 | 28.87 | 7.66 | 39.52 | 7.10 / 7.0 / 1.62 | 539.4 / 515.5 | -3.97% | +1.61% | 5 | 0/5 (0.0%) |
| Nice (-20 / +19) | 20 | 20/20 (100.0%) | 20.89 | 21.58 | 2.30 | 23.17 | 6.35 / 6.0 / 0.75 | 531.1 / 517.1 | -2.36% | +1.31% | 5 | 0/5 (0.0%) |
| Real-Time (SCHED_FIFO 50) | 20 | 20/20 (100.0%) | 25.34 | 25.70 | 5.11 | 31.08 | 6.25 / 6.0 / 0.72 | 544.5 / 516.3 | -4.96% | +1.45% | 5 | 0/5 (0.0%) |
| cgroup v2 (cpu.weight) | 20 | 20/20 (100.0%) | 22.68 | 22.15 | 2.88 | 28.97 | 6.50 / 7.0 / 0.89 | 506.5 / 512.9 | +2.37% | +2.10% | 5 | 0/5 (0.0%) |
| cgroup v2 (cpu.max 50%) | 20 | 20/20 (100.0%) | 17.11 | 15.05 | 3.88 | 24.92 | 6.20 / 6.0 / 0.70 | 315.2 / 316.5 | +39.25% | +39.59% | 5 | 0/5 (0.0%) |
| CPU Pinning (taskset) | 20 | 20/20 (100.0%) | 24.29 | 25.67 | 4.09 | 29.08 | 6.40 / 7.0 / 1.35 | 494.8 / 498.5 | +4.64% | +4.85% | 5 | 0/5 (0.0%) |

### Key Findings (Hypotheses H1–H3)

- **H1 (Priority controls reduce latency & damage):** Raising defender priority via `nice` (`-20` vs `+19`), `cgroup_weight` (`1000` vs `100`), or `chrt` (`SCHED_FIFO 50`) cut mean detection delay from `29.46 ms` (`default`) down to `20.89–25.34 ms` and reduced mean files damaged (`6.25–6.50` vs `7.10`), while imposing minimal steady-state workload slowdown (`+1.31%` to `+2.10%` median).
- **H2 (Bandwidth capping protects fastest, at a steep throughput cost):** `cgroup_max` (`50%` CPU cap) achieved the lowest loaded detection delay (`17.11 ms` mean, `15.05 ms` median) and lowest loaded file damage (`6.20` files), but cut competing workload throughput by `+39.59%` (median).
- **H3 (Core pinning alone helps less than priority or caps):** `taskset` (`24.29 ms` mean, `+4.85%` median slowdown) improved on `default` (`29.46 ms`), yet trailed `cgroup_max`, `nice`, and `cgroup_weight` in responsiveness while sacrificing one dedicated core's capacity.
- **Reliability:** Across all `195` trials, the defender achieved `100%` attack detection (`140/140`), `0%` false alarms (`0/35` benign trials), and `0` timeouts.

### Methodology & Data-Cleaning Treatment

- **Standard deviation:** Sample standard deviation (`ddof=1`, Bessel's correction); 95th percentile (`P95`) uses linear interpolation (`numpy.percentile(..., 95)`).
- **Warm-up / throughput spike treatment:** Round-level inspection shows `9` transient high-throughput spikes (`> 1.15x` steady-state median of `515.9 units/s`) across unconstrained setups — `6` in Round 1 and `3` in later rounds (Round 2 `chrt` attack: `817.8`, Round 3 `default` benign: `638.8`, Round 6 `default` attack: `810.5`). Because these spikes persist beyond Round 1 (consistent with intermittent host CPU turbo-boost rather than a pure Round-1 warm-up artifact), **all `195` valid trials are retained without discarding data**. Both mean-based slowdown (which honestly reflects the negative values on `default`, `nice`, and `chrt` caused by turbo spikes) and median-based slowdown (which is spike-resistant, ranging from `+1.31%` to `+39.59%`) are reported.

### Generated Figures

- **Detection & Freeze Delay:** [fig1_detection_delay.png](results/figures/fig1_detection_delay.png)
- **Decoy Files Damaged:** [fig2_files_damaged.png](results/figures/fig2_files_damaged.png)
- **Workload Slowdown (%):** [fig3_workload_slowdown.png](results/figures/fig3_workload_slowdown.png)
- **Protection vs. Workload Cost Trade-Off:** [fig4_tradeoff_scatter.png](results/figures/fig4_tradeoff_scatter.png)
