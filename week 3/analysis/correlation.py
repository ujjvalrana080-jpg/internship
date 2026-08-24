"""
analysis/correlation.py

Day 16 — Log Correlation Engine.

Groups logs by (src_ip, event_type) within a rolling time window
(default 5 minutes) and flags known patterns:
    - repeated_failures: >=3 WARNING/failure-type events in one window
    - anomaly_burst: >=3 events of any type clustered tightly in time
    - suspicious_spike: escalation from WARNING to CRITICAL within the same window
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any

DEFAULT_WINDOW_MINUTES = 5
REPEAT_THRESHOLD = 3

FAILURE_KEYWORDS = ("FAILURE", "FAILED", "SUSPECTED", "SCAN", "INTRUSION", "ESCALATION", "EXFIL")


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _classify_pattern(events: List[Dict[str, Any]]) -> str:
    severities = [e["severity"] for e in events]
    event_types = [e["event_type"] for e in events]

    has_critical = "CRITICAL" in severities
    has_warning = "WARNING" in severities
    is_failure_like = any(any(k in et for k in FAILURE_KEYWORDS) for et in event_types)

    if has_critical and has_warning and is_failure_like:
        return "suspicious_spike"
    if is_failure_like and len(events) >= REPEAT_THRESHOLD:
        return "repeated_failures"
    if len(events) >= REPEAT_THRESHOLD:
        return "anomaly_burst"
    if has_critical:
        return "critical_event"
    return "normal_cluster"


def _severity_score(events: List[Dict[str, Any]]) -> int:
    """Simple weighted score: CRITICAL=3, WARNING=2, INFO=1, summed."""
    weights = {"CRITICAL": 3, "WARNING": 2, "INFO": 1}
    return sum(weights.get(e["severity"], 1) for e in events)


def correlate_logs(
    logs: List[Dict[str, Any]],
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> List[Dict[str, Any]]:
    """
    Groups logs by (src_ip, event_type), then clusters chronologically
    within `window_minutes` of each other. Returns a list of cluster dicts.
    """
    groups: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for log in logs:
        key = (log.get("src_ip") or "UNKNOWN", log.get("event_type"))
        groups[key].append(log)

    clusters = []
    cluster_counter = 0

    for (src_ip, event_type), group_logs in groups.items():
        group_logs.sort(key=lambda e: e["timestamp"])

        current_cluster: List[Dict[str, Any]] = []
        window_start = None

        def flush_cluster():
            nonlocal cluster_counter
            if not current_cluster:
                return
            cluster_counter += 1
            clusters.append({
                "cluster_id": f"C{cluster_counter:04d}",
                "src_ip": src_ip,
                "event_type": event_type,
                "window_start": current_cluster[0]["timestamp"],
                "window_end": current_cluster[-1]["timestamp"],
                "event_count": len(current_cluster),
                "pattern": _classify_pattern(current_cluster),
                "severity_score": _severity_score(current_cluster),
                "log_ids": [e["id"] for e in current_cluster],
            })

        for log in group_logs:
            ts = _parse_ts(log["timestamp"])
            if window_start is None:
                window_start = ts
                current_cluster = [log]
                continue

            if ts - window_start <= timedelta(minutes=window_minutes):
                current_cluster.append(log)
            else:
                flush_cluster()
                window_start = ts
                current_cluster = [log]

        flush_cluster()

    # Sort clusters chronologically, most severe first within ties
    clusters.sort(key=lambda c: (c["window_start"], -c["severity_score"]))
    return clusters


def summarize_correlation(clusters: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll up cluster-level stats for a quick top-level summary."""
    pattern_counts = defaultdict(int)
    for c in clusters:
        pattern_counts[c["pattern"]] += 1

    flagged = [c for c in clusters if c["pattern"] not in ("normal_cluster",)]

    return {
        "total_clusters": len(clusters),
        "flagged_clusters": len(flagged),
        "pattern_breakdown": dict(pattern_counts),
        "top_flagged_ips": sorted(
            {c["src_ip"] for c in flagged if c["src_ip"] != "UNKNOWN"}
        ),
    }


if __name__ == "__main__":
    import sys, os, json
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from database.db import fetch_all_logs

    logs = fetch_all_logs()
    result = correlate_logs(logs)
    summary = summarize_correlation(result)

    output = {"summary": summary, "clusters": result}
    print(json.dumps(output, indent=2))
