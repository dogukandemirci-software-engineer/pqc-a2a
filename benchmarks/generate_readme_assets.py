"""Generate README metrics from the checked-in benchmark/formal summaries."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
summary = json.loads((ROOT / "benchmarks" / "analysis_summary.json").read_text())
formal = json.loads((ROOT / "formal" / "verification_summary.json").read_text())
rows = summary["rows"]
x = np.array([row["payload_bytes"] for row in rows])
labels = ["256 B", "4 KiB", "16 KiB"]

plt.style.use("seaborn-v0_8-whitegrid")
fig, axes = plt.subplots(2, 3, figsize=(18, 9), constrained_layout=True)
fig.suptitle("PQC-A2A production-readiness metrics", fontsize=18, fontweight="bold")

ax = axes[0, 0]
ax.plot(labels, [r["pqc_roundtrip_median_ms"] for r in rows], marker="o", label="Hybrid PQC")
ax.plot(labels, [r["classical_roundtrip_median_ms"] for r in rows], marker="o", label="Classical baseline")
ax.set_title("Round-trip median")
ax.set_ylabel("milliseconds")
ax.legend()

ax = axes[0, 1]
ax.plot(labels, [r["pqc_roundtrip_median_ms"] for r in rows], marker="o", label="PQC median")
ax.plot(labels, [r["pqc_roundtrip_median_ms"] + r["pqc_roundtrip_ci95_ms"] for r in rows], marker="x", linestyle="--", label="PQC +95% CI")
ax.plot(labels, [r["pqc_seal_p95_ms"] + r["pqc_open_p95_ms"] for r in rows], marker="s", label="PQC seal p95 + open p95")
ax.set_title("Tail latency and uncertainty")
ax.set_ylabel("milliseconds")
ax.legend(fontsize=8)

ax = axes[0, 2]
width = 0.36
indices = np.arange(len(labels))
pqc_overhead = [r["pqc_absolute_overhead_bytes"] for r in rows]
classical_overhead = [r["classical_absolute_overhead_bytes"] for r in rows]
ax.bar(indices - width / 2, pqc_overhead, width, label="PQC")
ax.bar(indices + width / 2, classical_overhead, width, label="Classical")
ax.set_xticks(indices, labels)
ax.set_title("Absolute envelope overhead")
ax.set_ylabel("bytes")
ax.legend()

ax = axes[1, 0]
ax.plot(labels, [r["pqc_expansion_factor"] for r in rows], marker="o", label="PQC")
ax.plot(labels, [r["classical_expansion_factor"] for r in rows], marker="o", label="Classical")
ax.set_title("Envelope expansion factor")
ax.set_ylabel("envelope / payload")
ax.legend()

ax = axes[1, 1]
ax.plot(labels, [r["pqc_vs_classical_latency_ratio"] for r in rows], marker="o", color="#b44")
ax.axhline(1.0, color="black", linewidth=1, linestyle="--")
ax.set_title("PQC latency ratio vs baseline")
ax.set_ylabel("times")

ax = axes[1, 2]
formal_labels = ["Generated", "Distinct", "Invariant violations"]
formal_values = [formal["states_generated"], formal["distinct_states"], formal["invariant_violations"]]
colors = ["#4c72b0", "#55a868", "#c44e52"]
bars = ax.bar(formal_labels, formal_values, color=colors)
ax.set_title("TLA+/TLC finite-state check")
ax.set_ylabel("count")
ax.set_ylim(0, max(formal_values) * 1.2 + 1)
ax.tick_params(axis="x", rotation=20)
for bar, value in zip(bars, formal_values):
    ax.text(bar.get_x() + bar.get_width() / 2, value + 0.5, str(value), ha="center", fontweight="bold")

for axis in axes.flat:
    axis.spines[["top", "right"]].set_visible(False)
    axis.tick_params(labelsize=9)

out = ROOT / "benchmarks" / "readme_metrics.png"
fig.savefig(out, dpi=180, bbox_inches="tight")
print(out)
print({"payloads": x.tolist(), "formal": formal})
