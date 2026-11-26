# Experimental Results Summary

Aggregated from `195` raw trial rows (`results/raw/trials.csv`). All valid trials retained (no warm-up rounds excluded).

## Per-Setup Summary Table

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

## Statistical Methodology

- **Standard Deviation (`SD`):** Sample standard deviation with Bessel's correction (`ddof=1`). Undefined (`—`) when sample size `n < 2`.
- **95th Percentile (`P95`):** Computed with linear interpolation (`numpy.percentile(..., 95)`) over detected attack trials.
- **Workload Slowdown (%):** `((baseline_throughput - setup_throughput) / baseline_throughput) * 100`, comparing each setup's **attack-mode** workload throughput against `baseline_workload_solo` (`mode == "solo"`). Positive values indicate slowdown; negative values indicate higher measured throughput than the solo baseline.
- **False Alarm Rate (%):** `(benign trials with false_alarm == True) / (total benign trials) * 100`, computed strictly on `mode == "benign"` rows.

## Data Quality & Round-Level Throughput Investigation

- **Steady-state unconstrained throughput median (rounds 2–20):** `515.9 units/s` (transient spike threshold `> 1.15x` median = `593.3 units/s`).
- **Transient high-throughput spikes detected:** `9` total (`6` in Round 1, `3` in later rounds).
- **Spikes after Round 1:** round 2 chrt (attack): 817.8; round 3 default (benign): 638.8; round 6 default (attack): 810.5.
- **Treatment decision:** Because elevated throughput readings occur in both Round 1 and later rounds (consistent with intermittent host CPU turbo-boost / frequency scaling rather than a purely Round-1 warm-up artifact), **no rounds are silently discarded**. All valid trials are retained, and **both mean-based and median-based slowdown (%)** are reported: mean slowdown honestly reflects the turbo-boost outliers (yielding negative values on `default`, `nice`, and `chrt`), while median slowdown provides a spike-resistant comparison (`+1.31%` to `+39.59%`). Reproducible sensitivity checks can be run via `python -m src.analysis.summarize --skip-warmup-rounds 1`.

## Validation Warnings

- None. All expected scheduler setups and metrics had complete, valid data.
