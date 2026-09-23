"""Analyze raw hybrid-PQC versus classical baseline benchmark results."""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).parent
INPUT, SUMMARY, PLOT = ROOT / "results.csv", ROOT / "analysis_summary.json", ROOT / "analysis.png"


def load_rows() -> list[dict[str, float]]:
    with INPUT.open(newline="") as handle:
        return [{key: float(value) for key, value in row.items()} for row in csv.DictReader(handle)]


def ci95(stdev: float, samples: float) -> float:
    return 1.96 * stdev / math.sqrt(samples) if samples > 1 else 0.0


def analyze(rows: list[dict[str, float]]) -> dict:
    derived = []
    for row in rows:
        samples = row.get("samples", 50.0)
        item = {
            **row,
            "pqc_absolute_overhead_bytes": row["pqc_envelope_bytes"] - row["payload_bytes"],
            "classical_absolute_overhead_bytes": row["classical_envelope_bytes"] - row["payload_bytes"],
            "pqc_expansion_factor": row["pqc_envelope_bytes"] / row["payload_bytes"],
            "classical_expansion_factor": row["classical_envelope_bytes"] / row["payload_bytes"],
            "pqc_vs_classical_latency_ratio": row["pqc_roundtrip_median_ms"] / row["classical_roundtrip_median_ms"],
            "pqc_roundtrip_ci95_ms": ci95(row.get("pqc_roundtrip_stdev_ms", 0), samples),
            "classical_roundtrip_ci95_ms": ci95(row.get("classical_roundtrip_stdev_ms", 0), samples),
        }
        derived.append(item)
    monotonic = lambda values: all(a <= b for a, b in zip(values, values[1:]))
    checks = {
        "row_count": len(rows),
        "all_positive_latencies": all(r["pqc_roundtrip_median_ms"] > 0 and r["classical_roundtrip_median_ms"] > 0 for r in rows),
        "payload_monotonic": monotonic([r["payload_bytes"] for r in rows]),
        "pqc_envelope_monotonic": monotonic([r["pqc_envelope_bytes"] for r in rows]),
        "classical_envelope_monotonic": monotonic([r["classical_envelope_bytes"] for r in rows]),
        "pqc_overhead_positive": all(r["pqc_absolute_overhead_bytes"] > 0 for r in derived),
        "classical_overhead_positive": all(r["classical_absolute_overhead_bytes"] > 0 for r in derived),
    }
    return {"source": INPUT.name, "method": "median, p95, sample standard deviation, 95% normal CI", "rows": derived, "checks": checks}


def make_plot(result: dict) -> None:
    rows = result["rows"]
    labels = [f"{int(r['payload_bytes'] / 1024)} KiB" if r["payload_bytes"] >= 1024 else f"{int(r['payload_bytes'])} B" for r in rows]
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), constrained_layout=True)
    axes[0].plot(labels, [r["pqc_roundtrip_median_ms"] for r in rows], "o-", label="Hybrid PQC")
    axes[0].plot(labels, [r["classical_roundtrip_median_ms"] for r in rows], "o-", label="X25519 + Ed25519")
    axes[0].set_title("Round-trip median"); axes[0].set_ylabel("ms"); axes[0].legend()
    axes[1].bar(labels, [r["pqc_expansion_factor"] for r in rows], label="PQC")
    axes[1].plot(labels, [r["classical_expansion_factor"] for r in rows], "o-", color="#4c72b0", label="Classical")
    axes[1].set_title("Envelope expansion"); axes[1].set_ylabel("factor"); axes[1].legend()
    axes[2].plot(labels, [r["pqc_roundtrip_ci95_ms"] for r in rows], "o-", label="PQC CI95")
    axes[2].plot(labels, [r["classical_roundtrip_ci95_ms"] for r in rows], "o-", label="Classical CI95")
    axes[2].set_title("95% confidence interval"); axes[2].set_ylabel("ms"); axes[2].legend()
    fig.suptitle("PQC-A2A: hybrid and classical baseline")
    fig.savefig(PLOT, dpi=180); plt.close(fig)


if __name__ == "__main__":
    result = analyze(load_rows())
    SUMMARY.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    make_plot(result)
    print(json.dumps(result, indent=2))
