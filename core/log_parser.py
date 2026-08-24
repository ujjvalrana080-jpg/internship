"""
core/log_parser.py

Parses raw forensic log lines into structured records.

Expected raw line format (from Week 2 log collection):
2026-08-15 09:01:12 [WARNING] src=192.168.1.22 event=LOGIN_FAILURE user=admin msg="Failed login attempt for admin"
"""

import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<severity>\w+)\]\s+"
    r"src=(?P<src_ip>[\d\.]+)\s+"
    r"event=(?P<event_type>\w+)\s+"
    r"user=(?P<user>\S+)\s+"
    r'msg="(?P<message>[^"]*)"'
)

# Normalize/validate severities we accept from raw logs
VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}


@dataclass
class LogEntry:
    timestamp: str          # ISO 8601 string
    event_type: str
    message: str
    severity: str
    src_ip: Optional[str] = None
    user: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse a single raw log line into a LogEntry. Returns None if malformed."""
    line = line.strip()
    if not line:
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    severity = data["severity"].upper()
    if severity not in VALID_SEVERITIES:
        severity = "INFO"

    # Normalize timestamp to ISO format
    try:
        ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
        iso_ts = ts.isoformat()
    except ValueError:
        iso_ts = data["timestamp"]

    return LogEntry(
        timestamp=iso_ts,
        event_type=data["event_type"],
        message=data["message"],
        severity=severity,
        src_ip=data["src_ip"],
        user=data["user"],
    )


def parse_file(file_path: str) -> List[LogEntry]:
    """Parse an entire raw log file into a list of LogEntry objects."""
    entries: List[LogEntry] = []
    skipped = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            entry = parse_line(line)
            if entry:
                entries.append(entry)
            elif line.strip():
                skipped += 1
                print(f"[log_parser] Skipped malformed line {line_no}: {line.strip()[:80]}")

    print(f"[log_parser] Parsed {len(entries)} entries, skipped {skipped} malformed lines.")
    return entries


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs.txt"
    logs = parse_file(path)
    for log in logs[:5]:
        print(log.to_dict())
