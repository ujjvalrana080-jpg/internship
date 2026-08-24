"""
scripts/run_correlation.py

Day 16 — Runs the correlation engine against forensics.db and
writes correlated_logs.json.
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import fetch_all_logs
from analysis.correlation import correlate_logs, summarize_correlation


def main(output_path: str = "correlated_logs.json"):
    print("=== Day 16: Log Correlation Engine ===")
    logs = fetch_all_logs()
    if not logs:
        print("[correlation] No logs found. Run scripts/ingest.py first.")
        return

    clusters = correlate_logs(logs)
    summary = summarize_correlation(clusters)

    output = {"summary": summary, "clusters": clusters}

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"[correlation] {summary['total_clusters']} clusters found, "
          f"{summary['flagged_clusters']} flagged as anomalous.")
    print(f"[correlation] Written to {output_path}")


if __name__ == "__main__":
    main()
