"""
scripts/run_analysis.py

Day 18 — Runs AI-assisted forensic classification against forensics.db
and writes ai_analysis.json.
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import fetch_all_logs
from analysis.ai_analysis import build_analysis_report


def main(output_path: str = "ai_analysis.json"):
    print("=== Day 18: AI-Assisted Forensic Analysis ===")
    logs = fetch_all_logs()
    if not logs:
        print("[ai_analysis] No logs found. Run scripts/ingest.py first.")
        return

    report = build_analysis_report(logs)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[ai_analysis] {report['counts']}")
    print(f"[ai_analysis] Summary: {report['summary']}")
    print(f"[ai_analysis] Written to {output_path}")


if __name__ == "__main__":
    main()
