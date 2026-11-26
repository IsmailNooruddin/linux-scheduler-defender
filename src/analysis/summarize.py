"""
Trial Results Aggregation & Statistical Summary Generator (Member D).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Rayyan Alvi (Member D)

Overview:
---------
Reads raw per-trial logs from `results/raw/trials.csv` (written by Member C's
runner) and produces:
  1. `results/processed/summary_table.csv` : Machine-readable summary metrics
  2. `results/processed/summary_table.md`  : Human-readable Markdown report with
     statistical conventions, round-level throughput diagnostics, and warnings

Statistical Conventions:
------------------------
  - Standard deviation: Sample standard deviation (ddof=1, Bessel's correction).
    Undefined (NaN) when sample size n < 2.
  - 95th percentile: Linear interpolation (`numpy.percentile(..., 95)`).
  - Workload slowdown (%):
        (baseline_throughput - setup_throughput) / baseline_throughput * 100
    where `baseline_throughput` comes from `setup == "baseline_workload_solo"`
    (`mode == "solo"`), and `setup_throughput` comes from `mode == "attack"`
    trials for each competing-load setup.
    Both mean-based and median-based slowdown percentages are reported so that
    transient CPU turbo-boost spikes are visible without discarding valid data.
  - False alarm rate (%):
        (benign trials with false_alarm == True) / (total benign trials) * 100

Command-Line Usage:
-------------------
  python -m src.analysis.summarize
  python -m src.analysis.summarize --skip-warmup-rounds 1
  python -m src.analysis.summarize --input results/raw/trials.csv --output-dir results/processed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config.experiment_config import (
    PROCESSED_RESULTS_DIR,
    RAW_CSV_COLUMNS,
    RAW_TRIALS_CSV,
    SCHEDULER_SETUPS,
    ensure_results_dirs,
)

# Setups whose workload is NOT artificially capped or pinned to fewer cores;
# used for the round-level throughput / turbo-boost diagnostic.
_UNCONSTRAINED_WORKLOAD_SETUPS: Tuple[str, ...] = (
    "baseline_workload_solo",
    "default",
    "nice",
    "chrt",
    "cgroup_weight",
)

# Canonical column order for results/processed/summary_table.csv
SUMMARY_CSV_COLUMNS: Tuple[str, ...] = (
    "setup",
    "attack_trials",
    "detected_trials",
    "detection_rate_pct",
    "timed_out_trials",
    "delay_mean_ms",
    "delay_median_ms",
    "delay_std_ms",
    "delay_p95_ms",
    "files_damaged_mean",
    "files_damaged_median",
    "files_damaged_std",
    "workload_throughput_mean",
    "workload_throughput_median",
    "workload_throughput_std",
    "workload_slowdown_mean_pct",
    "workload_slowdown_median_pct",
    "benign_trials",
    "false_alarms",
    "false_alarm_rate_pct",
)

SETUP_DISPLAY_NAMES: Dict[str, str] = {
    "baseline_no_load": "Baseline (No Load)",
    "baseline_workload_solo": "Baseline (Workload Solo)",
    "default": "Default (CFS)",
    "nice": "Nice (-20 / +19)",
    "chrt": "Real-Time (SCHED_FIFO 50)",
    "cgroup_weight": "cgroup v2 (cpu.weight)",
    "cgroup_max": "cgroup v2 (cpu.max 50%)",
    "taskset": "CPU Pinning (taskset)",
}


# ==============================================================================
# 1. LOADING & VALIDATION
# ==============================================================================

def _parse_bool_series(series: pd.Series, col_name: str, warnings: List[str]) -> pd.Series:
    """Parse a CSV boolean column strictly into True/False/pd.NA, warning on invalid values."""
    mapping = {"true": True, "false": False}
    parsed: List[Any] = []
    invalid_count = 0

    for val in series:
        if pd.isna(val) or str(val).strip() == "":
            parsed.append(pd.NA)
            continue
        if isinstance(val, (bool, np.bool_)):
            parsed.append(bool(val))
            continue
        key = str(val).strip().lower()
        if key in mapping:
            parsed.append(mapping[key])
        else:
            parsed.append(pd.NA)
            invalid_count += 1

    if invalid_count > 0:
        warnings.append(
            f"Column '{col_name}' contained {invalid_count} invalid boolean value(s); treated as missing."
        )
    return pd.Series(parsed, index=series.index, dtype="boolean")


def _parse_numeric_series(
    series: pd.Series,
    col_name: str,
    warnings: List[str],
    allow_negative: bool = False,
) -> pd.Series:
    """Coerce a CSV numeric column to float, warning on unparseable or invalid negative values."""
    non_empty = series.notna() & (series.astype(str).str.strip() != "")
    numeric = pd.to_numeric(series, errors="coerce")

    bad_parse = int((non_empty & numeric.isna()).sum())
    if bad_parse > 0:
        warnings.append(
            f"Column '{col_name}' contained {bad_parse} non-numeric value(s); treated as NaN."
        )

    if not allow_negative:
        neg_mask = numeric < 0
        neg_count = int(neg_mask.sum())
        if neg_count > 0:
            warnings.append(
                f"Column '{col_name}' contained {neg_count} negative value(s); excluded as invalid."
            )
            numeric = numeric.mask(neg_mask, np.nan)

    return numeric


def load_and_validate_trials(csv_path: Path) -> Tuple[pd.DataFrame, List[str]]:
    """
    Load `trials.csv`, verify schema compliance, normalize types, and collect warnings.
    """
    warnings: List[str] = []
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(
            f"Raw trials CSV not found at '{csv_path}'. "
            "Run the experiment suite first (e.g. `scripts/run_all_experiments.sh`)."
        )

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    if df.empty:
        raise ValueError(f"Raw trials CSV '{csv_path}' contains no trial rows.")

    missing_cols = [c for c in RAW_CSV_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(
            f"Raw trials CSV '{csv_path}' is missing required column(s): {missing_cols}"
        )

    df["setup"] = df["setup"].astype(str).str.strip()
    df["mode"] = df["mode"].astype(str).str.strip().str.lower()

    # Validate setup names and modes
    unknown_setups = sorted(set(df["setup"]) - set(SCHEDULER_SETUPS))
    if unknown_setups:
        warnings.append(f"Unexpected setup name(s) found in CSV: {unknown_setups}")

    valid_modes = {"attack", "benign", "solo"}
    invalid_mode_mask = ~df["mode"].isin(valid_modes)
    if invalid_mode_mask.any():
        bad_modes = sorted(set(df.loc[invalid_mode_mask, "mode"]))
        warnings.append(
            f"Excluded {int(invalid_mode_mask.sum())} row(s) with unrecognized mode(s): {bad_modes}"
        )
        df = df.loc[~invalid_mode_mask].copy()

    # Normalize booleans and numerics
    for bcol in ("detected", "false_alarm", "timed_out"):
        df[bcol] = _parse_bool_series(df[bcol], bcol, warnings)

    df["trial_id"] = _parse_numeric_series(df["trial_id"], "trial_id", warnings)
    df["detection_delay_ms"] = _parse_numeric_series(
        df["detection_delay_ms"], "detection_delay_ms", warnings
    )
    df["files_damaged"] = _parse_numeric_series(df["files_damaged"], "files_damaged", warnings)
    df["total_decoy_files"] = _parse_numeric_series(
        df["total_decoy_files"], "total_decoy_files", warnings
    )
    df["workload_throughput"] = _parse_numeric_series(
        df["workload_throughput"], "workload_throughput", warnings
    )

    timed_out_n = int((df["timed_out"] == True).sum())  # noqa: E712
    if timed_out_n > 0:
        warnings.append(
            f"{timed_out_n} trial(s) hit the safety timeout (`timed_out == True`); "
            "they are retained in counts and reflected in detection/damage metrics."
        )

    return df, warnings


# ==============================================================================
# 2. ROUND-LEVEL THROUGHPUT / WARM-UP DIAGNOSTIC
# ==============================================================================

def analyze_throughput_rounds(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Inspect unconstrained workload throughput across rounds to evaluate whether
    elevated readings are a pure Round-1 warm-up effect or intermittent turbo-boost.
    """
    sub = df[
        df["setup"].isin(_UNCONSTRAINED_WORKLOAD_SETUPS) & df["workload_throughput"].notna()
    ].copy()

    if sub.empty:
        return {"available": False}

    # Use steady-state median (rounds >= 2, or all rounds if only 1 round exists)
    r2_plus = sub[sub["trial_id"] >= 2]["workload_throughput"]
    ref_vals = r2_plus if not r2_plus.empty else sub["workload_throughput"]
    steady_median = float(np.median(ref_vals))
    # Flag readings > 15% above steady-state median as transient high-frequency spikes
    spike_threshold = steady_median * 1.15

    spikes_df = sub[sub["workload_throughput"] > spike_threshold]
    r1_spikes = spikes_df[spikes_df["trial_id"] == 1]
    later_spikes = spikes_df[spikes_df["trial_id"] > 1]

    round_stats: List[Dict[str, Any]] = []
    for rnd, grp in sub.groupby("trial_id", sort=True):
        vals = grp["workload_throughput"].to_numpy(dtype=float)
        round_stats.append(
            {
                "round": int(rnd),
                "n": int(len(vals)),
                "mean": float(np.mean(vals)),
                "median": float(np.median(vals)),
                "max": float(np.max(vals)),
                "spikes": int(np.sum(vals > spike_threshold)),
            }
        )

    later_details = [
        f"round {int(row['trial_id'])} {row['setup']} ({row['mode']}): {row['workload_throughput']:.1f}"
        for _, row in later_spikes.iterrows()
    ]

    return {
        "available": True,
        "steady_median": steady_median,
        "spike_threshold": spike_threshold,
        "total_spikes": int(len(spikes_df)),
        "round1_spikes": int(len(r1_spikes)),
        "later_spikes": int(len(later_spikes)),
        "later_spike_details": later_details,
        "round1_mean": round_stats[0]["mean"] if round_stats and round_stats[0]["round"] == 1 else None,
        "round_stats": round_stats,
    }


# ==============================================================================
# 3. SUMMARY COMPUTATION
# ==============================================================================

def _safe_stats(
    values: pd.Series,
    metric_label: str,
    setup: str,
    warnings: List[str],
    include_p95: bool = False,
) -> Dict[str, float]:
    """Compute mean, median, sample std (ddof=1), and optionally 95th percentile."""
    clean = values.dropna().to_numpy(dtype=float)
    n = len(clean)
    if n == 0:
        out = {"mean": np.nan, "median": np.nan, "std": np.nan}
        if include_p95:
            out["p95"] = np.nan
        return out

    std_val = float(np.std(clean, ddof=1)) if n >= 2 else np.nan
    if n < 2:
        warnings.append(
            f"Setup '{setup}': only {n} observation for {metric_label}; sample std (ddof=1) is NaN."
        )

    out = {
        "mean": float(np.mean(clean)),
        "median": float(np.median(clean)),
        "std": std_val,
    }
    if include_p95:
        out["p95"] = float(np.percentile(clean, 95))
    return out


def compute_summary(
    df: pd.DataFrame,
    warnings: List[str],
    skip_warmup_rounds: int = 0,
) -> pd.DataFrame:
    """
    Aggregate per-setup metrics from validated trial rows.

    Parameters
    ----------
    df : pd.DataFrame
        Validated trial data from `load_and_validate_trials()`.
    warnings : List[str]
        Mutable list to append data-quality or insufficiency warnings to.
    skip_warmup_rounds : int, optional
        Number of initial rounds (`trial_id <= skip_warmup_rounds`) to exclude.
        Defaults to 0 (retain all valid trials).
    """
    if skip_warmup_rounds < 0:
        raise ValueError(f"skip_warmup_rounds must be >= 0 (got {skip_warmup_rounds}).")

    working = df.copy()
    if skip_warmup_rounds > 0:
        before = len(working)
        working = working[working["trial_id"] > skip_warmup_rounds].copy()
        dropped = before - len(working)
        warnings.append(
            f"Explicit warm-up exclusion active: dropped {dropped} row(s) with trial_id <= {skip_warmup_rounds}."
        )
        if working.empty:
            raise ValueError(
                f"No rows remain after excluding trial_id <= {skip_warmup_rounds}."
            )

    # Establish solo workload baseline for slowdown %
    solo_rows = working[
        (working["setup"] == "baseline_workload_solo") & (working["mode"] == "solo")
    ]
    solo_thr = solo_rows["workload_throughput"].dropna().to_numpy(dtype=float)
    if len(solo_thr) == 0:
        warnings.append(
            "No valid `baseline_workload_solo` (mode='solo') throughput rows found; "
            "workload slowdown (%) cannot be computed."
        )
        baseline_mean = np.nan
        baseline_median = np.nan
    else:
        baseline_mean = float(np.mean(solo_thr))
        baseline_median = float(np.median(solo_thr))
        if baseline_mean <= 0 or baseline_median <= 0:
            warnings.append("Solo baseline throughput is <= 0; slowdown (%) set to NaN.")
            baseline_mean = np.nan
            baseline_median = np.nan

    # Canonical setup order + any unexpected setups at the end
    extra_setups = [s for s in working["setup"].unique() if s not in SCHEDULER_SETUPS]
    ordered_setups = list(SCHEDULER_SETUPS) + sorted(extra_setups)

    records: List[Dict[str, Any]] = []
    for setup in ordered_setups:
        grp = working[working["setup"] == setup]
        if grp.empty:
            warnings.append(f"Setup '{setup}' has no rows in the dataset.")
            continue

        attack_df = grp[grp["mode"] == "attack"]
        benign_df = grp[grp["mode"] == "benign"]
        solo_df = grp[grp["mode"] == "solo"]

        # --- Attack metrics ---
        attack_trials = int(len(attack_df))
        detected_trials = int((attack_df["detected"] == True).sum()) if attack_trials > 0 else 0  # noqa: E712
        timed_out_trials = int((grp["timed_out"] == True).sum())  # noqa: E712
        detection_rate_pct = (
            (detected_trials / attack_trials) * 100.0 if attack_trials > 0 else np.nan
        )

        # Detection delay applies to detected attack trials
        detected_attack = attack_df[attack_df["detected"] == True]  # noqa: E712
        if attack_trials > 0 and detected_attack["detection_delay_ms"].dropna().empty:
            warnings.append(
                f"Setup '{setup}': {attack_trials} attack trial(s) but 0 valid detection_delay_ms values."
            )
        delay_stats = _safe_stats(
            detected_attack["detection_delay_ms"],
            "detection_delay_ms",
            setup,
            warnings,
            include_p95=True,
        )

        dmg_stats = _safe_stats(
            attack_df["files_damaged"],
            "files_damaged",
            setup,
            warnings,
            include_p95=False,
        )

        # --- Workload throughput & slowdown (%) ---
        # Compare attack-mode workload throughput against solo baseline (and solo for solo setup).
        if setup == "baseline_workload_solo":
            thr_source = solo_df["workload_throughput"]
        else:
            thr_source = attack_df["workload_throughput"]

        thr_stats = _safe_stats(
            thr_source,
            "workload_throughput",
            setup,
            warnings,
            include_p95=False,
        )

        if pd.notna(thr_stats["mean"]) and pd.notna(baseline_mean):
            if setup == "baseline_workload_solo":
                slowdown_mean = 0.0
                slowdown_median = 0.0
            else:
                slowdown_mean = (baseline_mean - thr_stats["mean"]) / baseline_mean * 100.0
                slowdown_median = (
                    (baseline_median - thr_stats["median"]) / baseline_median * 100.0
                )
        else:
            slowdown_mean = np.nan
            slowdown_median = np.nan

        # --- Benign / false-alarm metrics ---
        benign_trials = int(len(benign_df))
        false_alarms = int((benign_df["false_alarm"] == True).sum()) if benign_trials > 0 else 0  # noqa: E712
        false_alarm_rate_pct = (
            (false_alarms / benign_trials) * 100.0 if benign_trials > 0 else np.nan
        )
        if setup != "baseline_workload_solo" and benign_trials == 0:
            warnings.append(
                f"Setup '{setup}': 0 benign trials found; false alarm rate is NaN."
            )

        records.append(
            {
                "setup": setup,
                "attack_trials": attack_trials,
                "detected_trials": detected_trials,
                "detection_rate_pct": detection_rate_pct,
                "timed_out_trials": timed_out_trials,
                "delay_mean_ms": delay_stats["mean"],
                "delay_median_ms": delay_stats["median"],
                "delay_std_ms": delay_stats["std"],
                "delay_p95_ms": delay_stats["p95"],
                "files_damaged_mean": dmg_stats["mean"],
                "files_damaged_median": dmg_stats["median"],
                "files_damaged_std": dmg_stats["std"],
                "workload_throughput_mean": thr_stats["mean"],
                "workload_throughput_median": thr_stats["median"],
                "workload_throughput_std": thr_stats["std"],
                "workload_slowdown_mean_pct": slowdown_mean,
                "workload_slowdown_median_pct": slowdown_median,
                "benign_trials": benign_trials,
                "false_alarms": false_alarms,
                "false_alarm_rate_pct": false_alarm_rate_pct,
            }
        )

    summary_df = pd.DataFrame(records, columns=list(SUMMARY_CSV_COLUMNS))
    return summary_df


# ==============================================================================
# 4. OUTPUT WRITERS (CSV & MARKDOWN)
# ==============================================================================

def _fmt_num(val: Any, decimals: int = 2, signed: bool = False, suffix: str = "") -> str:
    """Format a numeric value for Markdown tables, returning '—' for NaN."""
    if pd.isna(val):
        return "—"
    sign = "+" if signed else ""
    return f"{float(val):{sign}.{decimals}f}{suffix}"


def _fmt_int(val: Any) -> str:
    """Format an integer count for Markdown tables."""
    if pd.isna(val):
        return "—"
    return str(int(val))


def write_summary_csv(summary_df: pd.DataFrame, output_path: Path) -> None:
    """Save the summary table to CSV with consistent rounding and LF line endings."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rounded = summary_df.copy()
    float_cols = [
        c
        for c in SUMMARY_CSV_COLUMNS
        if c not in ("setup", "attack_trials", "detected_trials", "timed_out_trials", "benign_trials", "false_alarms")
    ]
    for col in float_cols:
        rounded[col] = rounded[col].round(4)

    rounded.to_csv(output_path, index=False, lineterminator="\n")


def render_summary_markdown(
    summary_df: pd.DataFrame,
    raw_row_count: int,
    round_diag: Dict[str, Any],
    warnings: List[str],
    skip_warmup_rounds: int = 0,
) -> str:
    """Render the complete Markdown summary report for `results/processed/summary_table.md`."""
    lines: List[str] = [
        "# Experimental Results Summary",
        "",
        f"Aggregated from `{raw_row_count}` raw trial rows (`results/raw/trials.csv`). "
        + (
            "All valid trials retained (no warm-up rounds excluded)."
            if skip_warmup_rounds == 0
            else f"Explicit warm-up exclusion applied: `trial_id <= {skip_warmup_rounds}` excluded."
        ),
        "",
        "## Per-Setup Summary Table",
        "",
        "| Scheduler Setup | Attack Trials | Detected (%) | Delay Mean (ms) | Delay Median (ms) | Delay SD (ms) | Delay P95 (ms) | Files Damaged (Mean / Med / SD) | Throughput Mean / Med (units/s) | Slowdown Mean (%) | Slowdown Median (%) | Benign Trials | False Alarm (%) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for _, row in summary_df.iterrows():
        setup_key = str(row["setup"])
        label = SETUP_DISPLAY_NAMES.get(setup_key, setup_key)

        if int(row["attack_trials"]) > 0:
            det_cell = f"{int(row['detected_trials'])}/{int(row['attack_trials'])} ({_fmt_num(row['detection_rate_pct'], 1, suffix='%')})"
            dmg_cell = (
                f"{_fmt_num(row['files_damaged_mean'], 2)} / "
                f"{_fmt_num(row['files_damaged_median'], 1)} / "
                f"{_fmt_num(row['files_damaged_std'], 2)}"
            )
        else:
            det_cell = "—"
            dmg_cell = "—"

        if pd.notna(row["workload_throughput_mean"]):
            thr_cell = (
                f"{_fmt_num(row['workload_throughput_mean'], 1)} / "
                f"{_fmt_num(row['workload_throughput_median'], 1)}"
            )
        else:
            thr_cell = "—"

        ben_n = int(row["benign_trials"])
        fa_cell = (
            f"{int(row['false_alarms'])}/{ben_n} ({_fmt_num(row['false_alarm_rate_pct'], 1, suffix='%')})"
            if ben_n > 0
            else "—"
        )

        lines.append(
            f"| {label} | {_fmt_int(row['attack_trials'])} | {det_cell} | "
            f"{_fmt_num(row['delay_mean_ms'], 2)} | {_fmt_num(row['delay_median_ms'], 2)} | "
            f"{_fmt_num(row['delay_std_ms'], 2)} | {_fmt_num(row['delay_p95_ms'], 2)} | "
            f"{dmg_cell} | {thr_cell} | "
            f"{_fmt_num(row['workload_slowdown_mean_pct'], 2, signed=True, suffix='%')} | "
            f"{_fmt_num(row['workload_slowdown_median_pct'], 2, signed=True, suffix='%')} | "
            f"{_fmt_int(ben_n)} | {fa_cell} |"
        )

    lines.extend(
        [
            "",
            "## Statistical Methodology",
            "",
            "- **Standard Deviation (`SD`):** Sample standard deviation with Bessel's correction (`ddof=1`). Undefined (`—`) when sample size `n < 2`.",
            "- **95th Percentile (`P95`):** Computed with linear interpolation (`numpy.percentile(..., 95)`) over detected attack trials.",
            "- **Workload Slowdown (%):** `((baseline_throughput - setup_throughput) / baseline_throughput) * 100`, comparing each setup's **attack-mode** workload throughput against `baseline_workload_solo` (`mode == \"solo\"`). Positive values indicate slowdown; negative values indicate higher measured throughput than the solo baseline.",
            "- **False Alarm Rate (%):** `(benign trials with false_alarm == True) / (total benign trials) * 100`, computed strictly on `mode == \"benign\"` rows.",
            "",
            "## Data Quality & Round-Level Throughput Investigation",
            "",
        ]
    )

    if round_diag.get("available"):
        round_stats = round_diag.get("round_stats", [])
        max_round = max((int(r["round"]) for r in round_stats), default=1)
        round_range_label = f"rounds 2–{max_round}" if max_round >= 2 else "all rounds"

        loaded = summary_df[
            (summary_df["setup"] != "baseline_workload_solo")
            & summary_df["workload_slowdown_median_pct"].notna()
        ]
        neg_mean_setups = [
            f"`{row['setup']}`"
            for _, row in loaded.iterrows()
            if pd.notna(row["workload_slowdown_mean_pct"])
            and float(row["workload_slowdown_mean_pct"]) < 0
        ]
        med_vals = loaded["workload_slowdown_median_pct"].dropna().to_numpy(dtype=float)
        if len(med_vals) > 0:
            med_range_text = f"`{med_vals.min():+.2f}%` to `{med_vals.max():+.2f}%`"
        else:
            med_range_text = "`N/A`"

        if len(neg_mean_setups) > 2:
            neg_list_text = ", ".join(neg_mean_setups[:-1]) + f", and {neg_mean_setups[-1]}"
        elif len(neg_mean_setups) == 2:
            neg_list_text = f"{neg_mean_setups[0]} and {neg_mean_setups[1]}"
        elif len(neg_mean_setups) == 1:
            neg_list_text = neg_mean_setups[0]
        else:
            neg_list_text = ""

        if len(neg_mean_setups) > 1:
            neg_clause = f" (yielding negative values on {neg_list_text})"
        elif len(neg_mean_setups) == 1:
            neg_clause = f" (yielding a negative value on {neg_list_text})"
        else:
            neg_clause = ""

        lines.append(
            f"- **Steady-state unconstrained throughput median ({round_range_label}):** "
            f"`{round_diag['steady_median']:.1f} units/s` (transient spike threshold `> 1.15x` median = `{round_diag['spike_threshold']:.1f} units/s`)."
        )
        lines.append(
            f"- **Transient high-throughput spikes detected:** `{round_diag['total_spikes']}` total "
            f"(`{round_diag['round1_spikes']}` in Round 1, `{round_diag['later_spikes']}` in later rounds)."
        )
        if round_diag["later_spike_details"]:
            lines.append(
                "- **Spikes after Round 1:** " + "; ".join(round_diag["later_spike_details"]) + "."
            )
        if skip_warmup_rounds == 0:
            lines.append(
                "- **Treatment decision:** Because elevated throughput readings occur in Round 1 and/or later rounds "
                "(consistent with intermittent host CPU turbo-boost / frequency scaling rather than a purely Round-1 warm-up artifact), "
                "**no rounds are silently discarded**. All valid trials are retained, and **both mean-based and median-based slowdown (%)** "
                f"are reported: mean slowdown honestly reflects any turbo-boost outliers{neg_clause}, "
                f"while median slowdown provides a spike-resistant comparison ({med_range_text}). "
                "Reproducible sensitivity checks can be run via `python -m src.analysis.summarize --skip-warmup-rounds 1`."
            )
        else:
            lines.append(
                f"- **Treatment decision:** Explicit warm-up exclusion applied via `--skip-warmup-rounds {skip_warmup_rounds}` "
                f"(`trial_id <= {skip_warmup_rounds}` dropped). Across the remaining rounds, median-based slowdown spans {med_range_text}"
                + (
                    f", while negative mean slowdowns remain on {neg_list_text}."
                    if neg_list_text
                    else "."
                )
            )
    else:
        lines.append("- Round-level unconstrained throughput diagnostic was not applicable for this dataset.")

    lines.extend(["", "## Validation Warnings", ""])
    if warnings:
        for w in warnings:
            lines.append(f"- {w}")
    else:
        lines.append("- None. All expected scheduler setups and metrics had complete, valid data.")

    lines.append("")
    return "\n".join(lines)


def write_summary_markdown(markdown_text: str, output_path: Path) -> None:
    """Write the Markdown summary report with LF line endings."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown_text, encoding="utf-8", newline="\n")


# ==============================================================================
# 5. CLI ENTRY POINT
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate raw trial logs into statistical summary CSV and Markdown tables."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=RAW_TRIALS_CSV,
        help=f"Path to raw trials CSV (default: {RAW_TRIALS_CSV}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROCESSED_RESULTS_DIR,
        help=f"Directory for summary_table.csv and summary_table.md (default: {PROCESSED_RESULTS_DIR}).",
    )
    parser.add_argument(
        "--skip-warmup-rounds",
        type=int,
        default=0,
        help="Optional number of initial rounds (trial_id <= N) to exclude (default: 0, retain all).",
    )
    return parser


def main() -> int:
    """Entry point for `python -m src.analysis.summarize`."""
    args = _build_arg_parser().parse_args()
    ensure_results_dirs()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    df, warnings = load_and_validate_trials(args.input)
    round_diag = analyze_throughput_rounds(df)
    summary_df = compute_summary(
        df,
        warnings=warnings,
        skip_warmup_rounds=args.skip_warmup_rounds,
    )

    csv_out = args.output_dir / "summary_table.csv"
    md_out = args.output_dir / "summary_table.md"

    write_summary_csv(summary_df, csv_out)
    md_text = render_summary_markdown(
        summary_df=summary_df,
        raw_row_count=len(df),
        round_diag=round_diag,
        warnings=warnings,
        skip_warmup_rounds=args.skip_warmup_rounds,
    )
    write_summary_markdown(md_text, md_out)

    print(f"[SUMMARIZE] Processed {len(df)} rows across {len(summary_df)} setups.")
    print(f"[SUMMARIZE] Wrote {csv_out}")
    print(f"[SUMMARIZE] Wrote {md_out}")
    if warnings:
        print(f"[SUMMARIZE] {len(warnings)} warning(s):", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
