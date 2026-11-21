# Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?

**Course:** Operating Systems (Term Project — Part 4)  
**Section:** L4  
**Group Members:** Ismail Nooruddin, Hassaan Ul Qadir, Munir Tariq, Rayyan Alvi  

---

## Overview

When a CPU-intensive local AI-style workload competes with a ransomware-like attack for CPU time, how do Linux scheduling controls (`nice`, `chrt` real-time scheduling classes, `cgroup v2` `cpu.weight` and `cpu.max`, and `taskset` CPU core pinning) affect:

1. **Detection & freeze delay** of a lightweight `inotify`-based defender (`SIGSTOP`)
2. **Files damaged** before the attacker is stopped
3. **Workload slowdown** imposed on the competing CPU-heavy workload
4. **False alarm rate** on normal, benign file activity

**Core OS Areas:** Scheduling (primary), Persistence/I/O, Security.

---

## Repository Structure

```text
linux-scheduler-defender/
├── README.md                 # Project documentation, setup, and run instructions
├── requirements.txt          # Python dependencies
├── .gitignore                # Git ignore rules
├── config/                   # Shared experiment paths, constants, and data schemas
├── src/
│   ├── attacker/             # [Member A] Isolated decoy sandbox, XOR attack simulator, benign activity
│   ├── defender/             # [Member B] inotify file monitor, burst detector, SIGSTOP freezer
│   ├── workload/             # [Member C] Synthetic multi-process CPU workload (AI stand-in)
│   ├── scheduler/            # [Member C] Linux scheduler/cgroup wrappers and trial runner
│   └── analysis/             # [Member D] Raw trial aggregation, statistics, and figure generation
├── scripts/                  # WSL2/Linux environment check, cgroup setup, and experiment runner scripts
├── tests/                    # Standalone verification tests for each module
├── results/
│   ├── raw/                  # Per-trial raw CSV logs
│   ├── processed/            # Aggregated summary tables
│   └── figures/              # Final plots for report and presentation
└── docs/                     # Proposal, report drafts, and presentation materials
```

---

## Team Division

- **Member A (Ismail Nooruddin):** Isolated decoy sandbox, safe XOR ransomware simulator, benign file activity generator, shared config contract (`config/`, `src/attacker/`, `tests/`).
- **Member B:** Lightweight `inotify` + `SIGSTOP` defender (`src/defender/`, `tests/`).
- **Member C:** Synthetic CPU-heavy workload, Linux scheduling / `cgroup v2` setups, and automated trial runner (`src/workload/`, `src/scheduler/`, `scripts/`, `tests/`).
- **Member D:** Measurement aggregation, statistical summaries, graphs, and final README polish (`src/analysis/`, `results/`, `README.md`).
- **All Members:** Joint analysis, report writing, presentation, and viva preparation.

---

## Environment Requirements

> *To be finalized once modules are implemented.*

- Linux / WSL2 (native Linux filesystem such as `/tmp` must be used for the runtime sandbox)
- Python 3.10+
- Linux scheduling utilities (`nice`, `chrt`, `taskset`) and `cgroup v2` support

---

## Setup & Usage

> *Detailed step-by-step commands for each module and full experiment reproduction will be added as each component is completed.*

---

## Results

> *Summary tables and graphs will be added under `results/processed/` and `results/figures/` after running the ~20-trial benchmark suite across all scheduler setups.*
