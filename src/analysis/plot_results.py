"""
Comparative Results Plotting & Figure Generator (Member D).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Rayyan Alvi (Member D)

Overview:
---------
Reads processed summary statistics (`results/processed/summary_table.csv`) and
raw trial distributions (`results/raw/trials.csv`) to generate four publication-
quality comparative figures in `results/figures/`:

  1. `fig1_detection_delay.png`  : Detection & freeze delay distribution (ms) per setup
  2. `fig2_files_damaged.png`    : Files damaged (mean ± SD + per-trial dots) per setup
  3. `fig3_workload_slowdown.png`: Workload slowdown (%) vs. solo baseline (mean & median)
  4. `fig4_tradeoff_scatter.png` : Protection (detection delay) vs. cost (workload slowdown)

Command-Line Usage:
-------------------
  python -m src.analysis.plot_results
  python -m src.analysis.plot_results --summary results/processed/summary_table.csv --output-dir results/figures
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("Agg")  # Headless-safe backend for WSL2 / Linux terminals

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from config.experiment_config import (
    BURST_EVENT_THRESHOLD,
    FIGURES_DIR,
    PROCESSED_RESULTS_DIR,
    RAW_TRIALS_CSV,
    ensure_results_dirs,
)

# Readable multi-line labels for x-axes and concise single-line labels for scatter annotations
AXIS_LABELS: Dict[str, str] = {
    "baseline_no_load": "No Load\n(Baseline)",
    "baseline_workload_solo": "Workload Solo\n(Baseline)",
    "default": "Default\n(CFS)",
    "nice": "Nice\n(-20 / +19)",
    "chrt": "Real-Time\n(SCHED_FIFO)",
    "cgroup_weight": "cgroup v2\n(cpu.weight)",
    "cgroup_max": "cgroup v2\n(cpu.max 50%)",
    "taskset": "CPU Pinning\n(taskset)",
}

SHORT_LABELS: Dict[str, str] = {
    "baseline_no_load": "No Load",
    "baseline_workload_solo": "Workload Solo",
    "default": "Default (CFS)",
    "nice": "Nice (-20/+19)",
    "chrt": "Real-Time (SCHED_FIFO)",
    "cgroup_weight": "cgroup v2 (cpu.weight)",
    "cgroup_max": "cgroup v2 (cpu.max 50%)",
    "taskset": "CPU Pinning (taskset)",
}

# Colorblind-friendly Okabe-Ito-inspired palette per setup
SETUP_COLORS: Dict[str, str] = {
    "baseline_no_load": "#6C757D",   # neutral slate gray
    "baseline_workload_solo": "#ADB5BD",
    "default": "#D55E00",            # vermilion
    "nice": "#0072B2",               # strong blue
    "chrt": "#CC79A7",               # reddish purple
    "cgroup_weight": "#009E73",      # bluish green
    "cgroup_max": "#E69F00",         # orange
    "taskset": "#56B4E9",            # sky blue
}

# Canonical order for attack/defender comparison plots
DEFENDER_SETUP_ORDER: Tuple[str, ...] = (
    "baseline_no_load",
    "default",
    "nice",
    "chrt",
    "cgroup_weight",
    "cgroup_max",
    "taskset",
)

# Canonical order for loaded setups (excluding no-load & solo baselines)
LOADED_SETUP_ORDER: Tuple[str, ...] = (
    "default",
    "nice",
    "chrt",
    "cgroup_weight",
    "cgroup_max",
    "taskset",
)


def _configure_style() -> None:
    """Apply clean, publication-ready matplotlib defaults."""
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 13,
            "axes.titleweight": "bold",
            "axes.labelsize": 11,
            "axes.edgecolor": "#333333",
            "axes.linewidth": 0.9,
            "xtick.labelsize": 9.5,
            "ytick.labelsize": 9.5,
            "legend.fontsize": 9.5,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.dpi": 300,
        }
    )


def _ordered_subset(summary_df: pd.DataFrame, order: Tuple[str, ...]) -> pd.DataFrame:
    """Filter summary_df to setups in `order`, preserving canonical ordering."""
    present = [s for s in order if s in set(summary_df["setup"])]
    return summary_df.set_index("setup").loc[present].reset_index()


def _load_raw_attacks(raw_csv: Optional[Path]) -> Optional[pd.DataFrame]:
    """Load attack-mode rows from raw trials.csv if available."""
    if raw_csv is None or not Path(raw_csv).is_file():
        return None
    raw = pd.read_csv(raw_csv)
    if "mode" not in raw.columns or "setup" not in raw.columns:
        return None
    attacks = raw[raw["mode"].astype(str).str.strip().str.lower() == "attack"].copy()
    for col in ("detection_delay_ms", "files_damaged", "workload_throughput"):
        if col in attacks.columns:
            attacks[col] = pd.to_numeric(attacks[col], errors="coerce")
    return attacks


# ==============================================================================
# FIGURE 1: DETECTION & FREEZE DELAY
# ==============================================================================

def plot_detection_delay(
    summary_df: pd.DataFrame,
    raw_attacks: Optional[pd.DataFrame],
    out_path: Path,
) -> bool:
    """Plot detection & freeze delay (ms) by scheduler setup with distributions."""
    sub = _ordered_subset(summary_df, DEFENDER_SETUP_ORDER)
    sub = sub[sub["delay_mean_ms"].notna()]
    if sub.empty:
        print("[PLOT] Skipping fig1_detection_delay.png: no valid detection delay data.", file=sys.stderr)
        return False

    setups = list(sub["setup"])
    labels = [AXIS_LABELS.get(s, s) for s in setups]
    colors = [SETUP_COLORS.get(s, "#4C72B0") for s in setups]

    fig, ax = plt.subplots(figsize=(10.5, 5.8))
    positions = np.arange(1, len(setups) + 1)

    has_raw = (
        raw_attacks is not None
        and "detection_delay_ms" in raw_attacks.columns
        and any(raw_attacks.loc[raw_attacks["setup"] == s, "detection_delay_ms"].dropna().shape[0] > 0 for s in setups)
    )

    if has_raw and raw_attacks is not None:
        rng = np.random.default_rng(42)
        series_list = [
            raw_attacks.loc[raw_attacks["setup"] == s, "detection_delay_ms"].dropna().to_numpy(dtype=float)
            for s in setups
        ]
        bp = ax.boxplot(
            series_list,
            positions=positions,
            widths=0.52,
            patch_artist=True,
            showfliers=False,
            medianprops={"color": "#111111", "linewidth": 1.8},
            whiskerprops={"color": "#444444", "linewidth": 1.1},
            capprops={"color": "#444444", "linewidth": 1.1},
            boxprops={"linewidth": 1.1, "edgecolor": "#333333"},
        )
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.55)

        # Overlay jittered individual trial observations
        for pos, vals, color in zip(positions, series_list, colors):
            if len(vals) == 0:
                continue
            jitter = rng.uniform(-0.14, 0.14, size=len(vals))
            ax.scatter(
                np.full(len(vals), pos) + jitter,
                vals,
                color=color,
                edgecolor="#222222",
                linewidth=0.45,
                s=22,
                alpha=0.82,
                zorder=3,
            )

        # Overlay mean markers
        means = sub["delay_mean_ms"].to_numpy(dtype=float)
        ax.scatter(
            positions,
            means,
            marker="D",
            s=48,
            color="white",
            edgecolor="#111111",
            linewidth=1.3,
            zorder=4,
            label="Mean",
        )
        ax.plot([], [], color="#111111", linewidth=1.8, label="Median")
        ax.scatter([], [], color="#555555", s=22, alpha=0.8, label="Individual trial")

        # Annotate mean and P95 cleanly above each column
        y_max = max(float(np.max(v)) for v in series_list if len(v) > 0)
        for pos, row, vals in zip(positions, sub.itertuples(), series_list):
            top = float(np.max(vals)) if len(vals) > 0 else float(row.delay_mean_ms)
            ax.text(
                pos,
                top + y_max * 0.025,
                f"μ={row.delay_mean_ms:.1f}\nP95={row.delay_p95_ms:.1f}",
                ha="center",
                va="bottom",
                fontsize=8.2,
                color="#222222",
            )
        ax.set_ylim(0, y_max * 1.18)
    else:
        means = sub["delay_mean_ms"].to_numpy(dtype=float)
        stds = sub["delay_std_ms"].fillna(0.0).to_numpy(dtype=float)
        ax.bar(positions, means, yerr=stds, capsize=5, color=colors, edgecolor="#333333", alpha=0.85)
        ax.set_ylim(0, float(np.max(means + stds)) * 1.2)

    ax.set_xticks(positions)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Detection & Freeze Delay (ms)")
    ax.set_title("Defender Detection & Freeze Delay Across Linux Scheduler Controls", pad=12)
    ax.yaxis.grid(True, linestyle="--", alpha=0.45)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#CCCCCC")

    fig.text(
        0.5,
        0.01,
        "Lower is better. Boxes show IQR (25th–75th percentile); whiskers extend to 1.5x IQR; annotations show mean (μ) and 95th percentile (P95) in ms.",
        ha="center",
        fontsize=8.5,
        color="#555555",
    )
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out_path)
    plt.close(fig)
    return True


# ==============================================================================
# FIGURE 2: FILES DAMAGED BEFORE FREEZE
# ==============================================================================

def plot_files_damaged(
    summary_df: pd.DataFrame,
    raw_attacks: Optional[pd.DataFrame],
    out_path: Path,
) -> bool:
    """Plot mean files damaged (± 1 sample SD) and individual trial counts per setup."""
    sub = _ordered_subset(summary_df, DEFENDER_SETUP_ORDER)
    sub = sub[sub["files_damaged_mean"].notna()]
    if sub.empty:
        print("[PLOT] Skipping fig2_files_damaged.png: no valid files damaged data.", file=sys.stderr)
        return False

    setups = list(sub["setup"])
    labels = [AXIS_LABELS.get(s, s) for s in setups]
    colors = [SETUP_COLORS.get(s, "#4C72B0") for s in setups]
    means = sub["files_damaged_mean"].to_numpy(dtype=float)
    stds = sub["files_damaged_std"].fillna(0.0).to_numpy(dtype=float)

    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    x = np.arange(len(setups))

    ax.bar(
        x,
        means,
        width=0.58,
        color=colors,
        edgecolor="#333333",
        linewidth=0.9,
        alpha=0.72,
        yerr=stds,
        capsize=5,
        error_kw={"ecolor": "#222222", "elinewidth": 1.2, "capthick": 1.2},
        label="Mean ± 1 SD (ddof=1)",
    )

    y_top_obs = float(np.max(means + stds))
    per_setup_max: List[float] = [float(m + sd) for m, sd in zip(means, stds)]
    if raw_attacks is not None and "files_damaged" in raw_attacks.columns:
        rng = np.random.default_rng(42)
        for idx, s in enumerate(setups):
            vals = raw_attacks.loc[raw_attacks["setup"] == s, "files_damaged"].dropna().to_numpy(dtype=float)
            if len(vals) == 0:
                continue
            col_max = float(np.max(vals))
            per_setup_max[idx] = max(per_setup_max[idx], col_max)
            y_top_obs = max(y_top_obs, col_max)
            jitter = rng.uniform(-0.14, 0.14, size=len(vals))
            ax.scatter(
                np.full(len(vals), idx) + jitter,
                vals,
                color="#222222",
                s=18,
                alpha=0.55,
                zorder=3,
                label="Individual trial" if idx == 0 else None,
            )

    # Burst threshold reference line
    ax.axhline(
        BURST_EVENT_THRESHOLD,
        color="#B22222",
        linestyle="--",
        linewidth=1.2,
        label=f"Burst threshold (K = {BURST_EVENT_THRESHOLD} distinct files)",
    )

    # Annotate mean ± SD cleanly above each column's highest bar/dot
    for idx, (m, sd, col_top) in enumerate(zip(means, stds, per_setup_max)):
        ax.text(
            idx,
            col_top + 0.38,
            f"{m:.2f} ± {sd:.2f}",
            ha="center",
            va="bottom",
            fontsize=8.8,
            fontweight="bold",
            color="#222222",
        )

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Decoy Files Damaged (out of 300)")
    ax.set_title("Decoy Files Damaged Before Attacker Freeze (SIGSTOP)", pad=12)
    ax.set_ylim(0, max(y_top_obs, float(np.max(means + stds))) + 2.2)
    ax.yaxis.grid(True, linestyle="--", alpha=0.45)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#CCCCCC")

    fig.text(
        0.5,
        0.01,
        "Lower is better. Ground-truth SHA-256 damage count across 300 decoy files per trial; error bars represent sample standard deviation (ddof=1).",
        ha="center",
        fontsize=8.5,
        color="#555555",
    )
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out_path)
    plt.close(fig)
    return True


# ==============================================================================
# FIGURE 3: WORKLOAD SLOWDOWN (%)
# ==============================================================================

def plot_workload_slowdown(summary_df: pd.DataFrame, out_path: Path) -> bool:
    """Plot mean-based and median-based workload slowdown (%) with zero line clearly visible."""
    sub = _ordered_subset(summary_df, LOADED_SETUP_ORDER)
    sub = sub[sub["workload_slowdown_mean_pct"].notna() | sub["workload_slowdown_median_pct"].notna()]
    if sub.empty:
        print("[PLOT] Skipping fig3_workload_slowdown.png: no valid slowdown data.", file=sys.stderr)
        return False

    setups = list(sub["setup"])
    labels = [AXIS_LABELS.get(s, s) for s in setups]
    mean_vals = sub["workload_slowdown_mean_pct"].to_numpy(dtype=float)
    med_vals = sub["workload_slowdown_median_pct"].to_numpy(dtype=float)

    fig, ax = plt.subplots(figsize=(10.5, 5.8))
    x = np.arange(len(setups))
    width = 0.36

    bars_mean = ax.bar(
        x - width / 2,
        mean_vals,
        width=width,
        color="#4C72B0",
        edgecolor="#222222",
        linewidth=0.85,
        alpha=0.85,
        label="Mean-based slowdown (%)",
    )
    bars_med = ax.bar(
        x + width / 2,
        med_vals,
        width=width,
        color="#DD8452",
        edgecolor="#222222",
        linewidth=0.85,
        alpha=0.90,
        label="Median-based slowdown (%)",
    )

    # Prominent zero reference line so negative values are unmistakable
    ax.axhline(0.0, color="#111111", linewidth=1.3, zorder=3)

    all_vals = np.concatenate([mean_vals[~np.isnan(mean_vals)], med_vals[~np.isnan(med_vals)]])
    y_min = min(0.0, float(np.min(all_vals)))
    y_max = max(0.0, float(np.max(all_vals)))
    span = max(y_max - y_min, 10.0)

    for bars in (bars_mean, bars_med):
        for bar in bars:
            val = bar.get_height()
            if np.isnan(val):
                continue
            offset = span * 0.02
            va = "bottom" if val >= 0 else "top"
            y_pos = val + offset if val >= 0 else val - offset
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                y_pos,
                f"{val:+.1f}%",
                ha="center",
                va=va,
                fontsize=8.4,
                fontweight="bold",
                color="#222222",
            )

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Workload Slowdown vs. Solo Baseline (%)")
    ax.set_title("Competing CPU Workload Slowdown Across Scheduler Controls", pad=12)
    ax.set_ylim(y_min - span * 0.16, y_max + span * 0.16)
    ax.yaxis.grid(True, linestyle="--", alpha=0.45)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="#CCCCCC")

    fig.text(
        0.5,
        0.01,
        "Slowdown = (Solo − Setup) / Solo × 100. Negative mean slowdowns reflect transient CPU turbo-boost spikes in unconstrained setups; median slowdown is spike-resistant.",
        ha="center",
        fontsize=8.3,
        color="#555555",
    )
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out_path)
    plt.close(fig)
    return True


# ==============================================================================
# FIGURE 4: PROTECTION VS. WORKLOAD COST TRADE-OFF SCATTER
# ==============================================================================

def plot_tradeoff_scatter(summary_df: pd.DataFrame, out_path: Path) -> bool:
    """Plot detection delay (protection) vs. median workload slowdown (cost) per setup."""
    sub = _ordered_subset(summary_df, LOADED_SETUP_ORDER)
    sub = sub[sub["delay_mean_ms"].notna() & sub["workload_slowdown_median_pct"].notna()]
    if sub.empty:
        print("[PLOT] Skipping fig4_tradeoff_scatter.png: insufficient data for trade-off plot.", file=sys.stderr)
        return False

    fig, ax = plt.subplots(figsize=(9.8, 6.0))

    # Optional no-load baseline horizontal reference
    no_load = summary_df[summary_df["setup"] == "baseline_no_load"]
    no_load_delay: Optional[float] = None
    if not no_load.empty and pd.notna(no_load.iloc[0]["delay_mean_ms"]):
        no_load_delay = float(no_load.iloc[0]["delay_mean_ms"])
        ax.axhline(
            no_load_delay,
            color="#6C757D",
            linestyle="--",
            linewidth=1.2,
            label=f"No-load baseline delay ({no_load_delay:.2f} ms)",
        )

    ax.axvline(0.0, color="#888888", linestyle=":", linewidth=1.1, label="0% workload slowdown")

    # Hand-tuned offsets (in points) so no two labels collide on the actual dataset
    label_offsets: Dict[str, Tuple[int, int]] = {
        "default": (14, 4),
        "chrt": (14, 14),
        "taskset": (22, -4),
        "cgroup_weight": (18, -22),
        "nice": (14, -34),
        "cgroup_max": (-135, 14),
    }

    xs = sub["workload_slowdown_median_pct"].to_numpy(dtype=float)
    ys = sub["delay_mean_ms"].to_numpy(dtype=float)

    for row in sub.itertuples():
        setup = str(row.setup)
        color = SETUP_COLORS.get(setup, "#0072B2")
        dmg = row.files_damaged_mean
        ax.scatter(
            row.workload_slowdown_median_pct,
            row.delay_mean_ms,
            s=130,
            color=color,
            edgecolor="#111111",
            linewidth=1.2,
            zorder=4,
        )
        dx, dy = label_offsets.get(setup, (8, 6))
        dmg_str = f"{dmg:.2f} files" if pd.notna(dmg) else "N/A"
        ax.annotate(
            f"{SHORT_LABELS.get(setup, setup)}\n({row.delay_mean_ms:.1f} ms, {row.workload_slowdown_median_pct:+.1f}%, {dmg_str})",
            xy=(row.workload_slowdown_median_pct, row.delay_mean_ms),
            xytext=(dx, dy),
            textcoords="offset points",
            fontsize=8.6,
            color="#111111",
            bbox={"boxstyle": "round,pad=0.25", "facecolor": "white", "edgecolor": "#CCCCCC", "alpha": 0.9},
            arrowprops={"arrowstyle": "-", "color": "#888888", "linewidth": 0.8},
            zorder=5,
        )

    x_min = min(0.0, float(np.min(xs))) - 3.0
    x_max = float(np.max(xs)) + 6.5
    y_min = (min(no_load_delay, float(np.min(ys))) if no_load_delay is not None else float(np.min(ys))) - 2.5
    y_max = float(np.max(ys)) + 3.5

    ax.set_xlim(x_min, x_max)
    ax.set_ylim(max(0.0, y_min), y_max)
    ax.set_xlabel("Workload Slowdown vs. Solo Baseline (%, Median-Based)")
    ax.set_ylabel("Mean Detection & Freeze Delay (ms)")
    ax.set_title("Protection vs. Workload Cost Trade-Off by Scheduler Setup", pad=12)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#CCCCCC")

    # Subtle directional cue
    ax.text(
        0.02,
        0.04,
        "↙ Ideal region: lower delay & lower workload cost",
        transform=ax.transAxes,
        fontsize=9,
        fontweight="bold",
        color="#2E7D32",
        bbox={"boxstyle": "round,pad=0.3", "facecolor": "#E8F5E9", "edgecolor": "#A5D6A7"},
    )

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    return True


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate comparative matplotlib figures from processed trial summaries."
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=PROCESSED_RESULTS_DIR / "summary_table.csv",
        help="Path to processed summary_table.csv.",
    )
    parser.add_argument(
        "--raw",
        type=Path,
        default=RAW_TRIALS_CSV,
        help="Path to raw trials.csv (for distribution overlays).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=FIGURES_DIR,
        help=f"Directory where PNG figures are saved (default: {FIGURES_DIR}).",
    )
    return parser


def main() -> int:
    """Entry point for `python -m src.analysis.plot_results`."""
    args = _build_arg_parser().parse_args()
    ensure_results_dirs()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.summary.is_file():
        print(
            f"[PLOT] ERROR: Summary CSV not found at '{args.summary}'. "
            "Run `python -m src.analysis.summarize` first.",
            file=sys.stderr,
        )
        return 1

    summary_df = pd.read_csv(args.summary)
    raw_attacks = _load_raw_attacks(args.raw)
    _configure_style()

    outputs = [
        ("fig1_detection_delay.png", plot_detection_delay(summary_df, raw_attacks, args.output_dir / "fig1_detection_delay.png")),
        ("fig2_files_damaged.png", plot_files_damaged(summary_df, raw_attacks, args.output_dir / "fig2_files_damaged.png")),
        ("fig3_workload_slowdown.png", plot_workload_slowdown(summary_df, args.output_dir / "fig3_workload_slowdown.png")),
        ("fig4_tradeoff_scatter.png", plot_tradeoff_scatter(summary_df, args.output_dir / "fig4_tradeoff_scatter.png")),
    ]

    generated = [name for name, ok in outputs if ok]
    for name in generated:
        print(f"[PLOT] Saved {args.output_dir / name}")

    if not generated:
        print("[PLOT] WARNING: No figures were generated.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
