"""
day8_log_analysis/log_analyzer.py

Day 8 — Log Analysis Engine

Reads a system/application log file, extracts timestamp, event type, and
message for each line, filters down to ERROR and WARNING entries, and
writes the structured result to logs.json.

Usage:
    python log_analyzer.py [path_to_log_file] [output_path]
"""

import re
import json
import sys
import os
from datetime import datetime

# Matches lines like:
# 2026-08-08 08:22:03 ERROR Database connection timeout after 30s
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<event_type>INFO|WARNING|ERROR)\s+"
    r"(?P<message>.+)$"
)

TARGET_LEVELS = {"ERROR", "WARNING"}


def parse_log_line(line: str):
    """Parse a single raw log line into a dict, or None if it doesn't match."""
    line = line.strip()
    if not line:
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Normalize timestamp to ISO 8601
    try:
        ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
        iso_ts = ts.isoformat()
    except ValueError:
        iso_ts = data["timestamp"]

    return {
        "timestamp": iso_ts,
        "event_type": data["event_type"],
        "message": data["message"],
    }


def analyze_log_file(log_path: str):
    """Reads the whole log file, parses every line, and filters to ERROR/WARNING."""
    all_entries = []
    skipped = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            entry = parse_log_line(line)
            if entry:
                all_entries.append(entry)
            elif line.strip():
                skipped += 1
                print(f"[log_analyzer] Skipped unrecognized line {line_no}: {line.strip()[:80]}")

    filtered = [e for e in all_entries if e["event_type"] in TARGET_LEVELS]

    print(f"[log_analyzer] Parsed {len(all_entries)} total lines "
          f"({skipped} skipped as malformed).")
    print(f"[log_analyzer] {len(filtered)} entries matched ERROR/WARNING filter.")

    return {
        "source_file": os.path.basename(log_path),
        "generated_at": datetime.now().isoformat(),
        "total_lines_parsed": len(all_entries),
        "filtered_count": len(filtered),
        "counts_by_level": {
            "ERROR": sum(1 for e in filtered if e["event_type"] == "ERROR"),
            "WARNING": sum(1 for e in filtered if e["event_type"] == "WARNING"),
        },
        "entries": filtered,
    }


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "../sample_data/system.log"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "logs.json"

    result = analyze_log_file(log_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[log_analyzer] Written to {output_path}")


if __name__ == "__main__":
    main()
