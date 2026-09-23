"""Analyze benchmark results without generating or imputing observations.

Usage: python benchmarks/analyze_results.py
Outputs analysis_summary.json and analysis.png next to results.csv.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).parent
INPUT = ROOT / "results.csv"
SUMMARY = ROOT / "analysis_summary.json"
PLOT = ROOT / "analysis.png"


def load_rows() -> list[dict[str, float]]:
    with INPUT.open(newline="") as handle:
        return [{key: float(value) for key, value in row.items()} for row in csv.DictReader(handle)]


def analyze(rows: list[dict[str, float]]) -> dict:
    derived = []
    for row in rows:
        payload = row["payload_bytes"]
        envelope = row["envelope_bytes"]
        roundtrip = row["roundtrip_ms_median"]
        encrypt = row["encrypt_ms_median"]
        decrypt = row["decrypt_ms_median"]
        derived.append({
            **row,
            "absolute_overhead_bytes": envelope - payload,
            "overhead_ratio": (envelope - payload) / payload,
            "expansion_factor": envelope / payload,
            "effective_payload_mib_s": payload / (roundtrip / 1000) / (1024 * 1024),
            "encrypt_share": encrypt / roundtrip,
            "decrypt_share": decrypt / roundtrip,
            "roundtrip_sum_error_ms": roundtrip - encrypt - decrypt,
        })

    def monotonic(values: list[float]) -> bool:
        return all(left <= right for left, right in zip(values, values[1:]))

    checks = {
        "row_count": len(rows),
        "all_positive_latencies": all(r["roundtrip_ms_median"] > 0 for r in rows),
        "payload_monotonic": monotonic([r["payload_bytes"] for r in rows]),
        "roundtrip_monotonic": monotonic([r["roundtrip_ms_median"] for r in rows]),
        "envelope_monotonic": monotonic([r["envelope_bytes"] for r in rows]),
        "overhead_positive": all(r["absolute_overhead_bytes"] > 0 for r in derived),
        "roundtrip_median_sum_error_max_ms": max(abs(r["roundtrip_sum_error_ms"]) for r in derived),
    }
    return {"source": str(INPUT.name), "rows": derived, "checks": checks}


def make_plot(result: dict) -> None:
    rows = result["rows"]
    x = [r["payload_bytes"] for r in rows]
    labels = [f"{int(v / 1024)} KiB" if v >= 1024 else f"{int(v)} B" for v in x]
    plt.style.use("seaborn-v0_8-whitegrid")
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), constrained_layout=True)

    axes[0].plot(labels, [r["encrypt_ms_median"] for r in rows], "o-", label="Seal")
    axes[0].plot(labels, [r["decrypt_ms_median"] for r in rows], "o-", label="Open")
    axes[0].plot(labels, [r["roundtrip_ms_median"] for r in rows], "o-", label="Round-trip")
    axes[0].set_title("Medyan gecikme")
    axes[0].set_ylabel("ms")
    axes[0].legend()

    axes[1].bar(labels, [r["absolute_overhead_bytes"] for r in rows], color="#c44e52")
    axes[1].set_title("Envelope overhead")
    axes[1].set_ylabel("byte")
    for index, row in enumerate(rows):
        axes[1].text(index, row["absolute_overhead_bytes"], f"{row['overhead_ratio']:.1%}", ha="center", va="bottom", fontsize=9)

    axes[2].plot(labels, [r["effective_payload_mib_s"] for r in rows], "o-", color="#4c72b0")
    axes[2].set_title("Effective payload throughput")
    axes[2].set_ylabel("MiB/s")

    fig.suptitle("PQC-A2A: ham benchmark verisinden türetilen metrikler")
    fig.savefig(PLOT, dpi=180)
    plt.close(fig)


if __name__ == "__main__":
    result = analyze(load_rows())
    SUMMARY.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    make_plot(result)
    print(json.dumps(result, indent=2))
