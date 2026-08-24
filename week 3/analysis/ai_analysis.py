"""
analysis/ai_analysis.py

Day 18 — AI-assisted forensic analysis (intro level).

Classifies each log entry as Normal / Suspicious / Critical using a
transparent rule-based scoring engine, then generates a short natural-
language "AI forensic summary" for the dataset.

Design note:
This module is intentionally rule-based rather than calling a live LLM
API, so the system is self-contained, reproducible, and free to run.
The `classify_with_llm()` function shows exactly where a real model
call (e.g. Anthropic/OpenAI chat completion) would plug in if an API
key were available — swap RULE_BASED for LLM_BASED in `classify_log`
to switch strategies without touching the rest of the pipeline.
"""

from typing import List, Dict, Any
from collections import defaultdict

CRITICAL_EVENTS = {
    "BRUTE_FORCE_SUSPECTED", "INTRUSION_ATTEMPT", "PRIVILEGE_ESCALATION",
    "DATA_EXFIL_CONFIRMED", "MALWARE_DETECTED", "RANSOMWARE_ACTIVITY",
}
SUSPICIOUS_EVENTS = {
    "LOGIN_FAILURE", "PORT_SCAN_DETECTED", "DATA_EXFIL_SUSPECTED",
    "UNUSUAL_LOGIN_TIME", "PERMISSION_DENIED",
}


def classify_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rule-based classifier producing a Normal / Suspicious / Critical
    verdict with a confidence score and a human-readable reason.
    """
    severity = log.get("severity", "INFO")
    event_type = log.get("event_type", "")

    if severity == "CRITICAL" or event_type in CRITICAL_EVENTS:
        return {
            "log_id": log["id"],
            "classification": "Critical",
            "confidence": 0.95,
            "reason": f"Event type '{event_type}' matches known critical indicators "
                      f"and/or was logged at CRITICAL severity.",
        }

    if severity == "WARNING" or event_type in SUSPICIOUS_EVENTS:
        return {
            "log_id": log["id"],
            "classification": "Suspicious",
            "confidence": 0.75,
            "reason": f"Event type '{event_type}' is associated with known suspicious "
                      f"activity patterns (e.g. failed auth, scanning, unusual transfer).",
        }

    return {
        "log_id": log["id"],
        "classification": "Normal",
        "confidence": 0.9,
        "reason": "No indicators of malicious or anomalous activity detected.",
    }


def classify_with_llm(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Placeholder showing where a real LLM call would go, e.g.:

        response = anthropic_client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=200,
            messages=[{
                "role": "user",
                "content": f"Classify this forensic log as Normal, Suspicious, "
                            f"or Critical and explain why in one sentence: {log}"
            }]
        )
        # parse response.content into classification/confidence/reason

    Not called by default — see module docstring.
    """
    raise NotImplementedError("Wire up an LLM client here if a live API key is available.")


def classify_dataset(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [classify_log(log) for log in logs]


def generate_summary(logs: List[Dict[str, Any]], classifications: List[Dict[str, Any]]) -> str:
    """Generates a short natural-language forensic summary of the dataset."""
    counts = defaultdict(int)
    for c in classifications:
        counts[c["classification"]] += 1

    critical_logs = [
        log for log, c in zip(logs, classifications) if c["classification"] == "Critical"
    ]
    top_ips = defaultdict(int)
    for log in critical_logs:
        if log.get("src_ip"):
            top_ips[log["src_ip"]] += 1

    lines = [
        f"Forensic AI summary: {len(logs)} log events analyzed. "
        f"{counts['Normal']} Normal, {counts['Suspicious']} Suspicious, "
        f"{counts['Critical']} Critical.",
    ]

    if top_ips:
        ip_list = ", ".join(f"{ip} ({n} critical events)" for ip, n in sorted(
            top_ips.items(), key=lambda x: -x[1]))
        lines.append(f"Highest-risk source IPs: {ip_list}.")
    else:
        lines.append("No source IPs were associated with Critical events.")

    if counts["Critical"] > 0:
        lines.append(
            "Recommendation: prioritize manual review of Critical-classified events "
            "and cross-reference with the correlation engine's flagged clusters."
        )
    else:
        lines.append("No immediate escalation required based on current dataset.")

    return " ".join(lines)


def build_analysis_report(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    classifications = classify_dataset(logs)
    summary = generate_summary(logs, classifications)

    return {
        "summary": summary,
        "counts": {
            "Normal": sum(1 for c in classifications if c["classification"] == "Normal"),
            "Suspicious": sum(1 for c in classifications if c["classification"] == "Suspicious"),
            "Critical": sum(1 for c in classifications if c["classification"] == "Critical"),
        },
        "classifications": classifications,
    }


if __name__ == "__main__":
    import sys, os, json
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from database.db import fetch_all_logs

    logs = fetch_all_logs()
    report = build_analysis_report(logs)
    print(json.dumps(report, indent=2))
