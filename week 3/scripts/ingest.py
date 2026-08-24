"""
scripts/ingest.py

Day 15 — Parse raw logs and insert them into forensics.db.

Usage:
    python scripts/ingest.py [path_to_raw_log_file]
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.log_parser import parse_file
from database.db import init_db, clear_logs, insert_logs_bulk


def main(log_path: str = "data/sample_logs.txt"):
    print("=== Day 15: Database Ingestion ===")
    init_db()
    clear_logs()  # keep demo runs idempotent

    entries = parse_file(log_path)
    dict_entries = [e.to_dict() for e in entries]

    count = insert_logs_bulk(dict_entries)
    print(f"[ingest] Inserted {count} log records into forensics.db")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs.txt"
    main(path)
