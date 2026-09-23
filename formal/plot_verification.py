"""Plot structured TLC verification results."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).parent
result = json.loads((ROOT / "verification_summary.json").read_text(encoding="utf-8"))
labels = ["Generated", "Distinct", "Invariant\nviolations"]
values = [result["states_generated"], result["distinct_states"], result["invariant_violations"]]
colors = ["#4c72b0", "#55a868", "#c44e52"]

plt.style.use("seaborn-v0_8-whitegrid")
fig, ax = plt.subplots(figsize=(7.2, 4.2))
bars = ax.bar(labels, values, color=colors)
ax.set_title("TLA+ / TLC finite-state verification")
ax.set_ylabel("Count")
ax.set_ylim(0, max(values[:2]) * 1.2)
for bar, value in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width() / 2, value + 0.5, str(value), ha="center", va="bottom", fontweight="bold")
ax.text(0.02, 0.96, f"Depth: {result['complete_graph_depth']} | Queue: {result['states_left_on_queue']}", transform=ax.transAxes, va="top")
fig.tight_layout()
fig.savefig(ROOT / "verification.png", dpi=180)
plt.close(fig)
