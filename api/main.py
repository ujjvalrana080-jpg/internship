"""
api/main.py

Day 17 — FastAPI Expansion (real backend system).
Day 19 — Wires ingestion + database + correlation + AI analysis into
         one end-to-end system.

Run with:
    uvicorn api.main:app --reload

Endpoints:
    GET  /                      -> health check / API info
    GET  /logs                  -> fetch all logs from the database
    GET  /logs/{severity}       -> filter logs by severity (INFO/WARNING/CRITICAL)
    GET  /correlation           -> return correlated event clusters
    GET  /analysis              -> return AI forensic classification + summary
    POST /ingest                -> re-run ingestion from data/sample_logs.txt
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException
from typing import List

from core.models import LogRecord
from core.log_parser import parse_file
from database.db import (
    init_db, fetch_all_logs, fetch_logs_by_severity,
    insert_logs_bulk, clear_logs,
)
from analysis.correlation import correlate_logs, summarize_correlation
from analysis.ai_analysis import build_analysis_report

app = FastAPI(
    title="Jagspire Forensic Investigation System",
    description="Mini forensic investigation API — log ingestion, correlation, "
                "and AI-assisted classification.",
    version="1.0.0",
)

VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", tags=["Health"])
def root():
    return {
        "system": "Jagspire Forensic Investigation System v1",
        "status": "online",
        "endpoints": ["/logs", "/logs/{severity}", "/correlation", "/analysis", "/ingest"],
    }


@app.get("/logs", response_model=List[LogRecord], tags=["Logs"])
def get_logs():
    """Fetch all logs currently stored in the database."""
    logs = fetch_all_logs()
    return logs


@app.get("/logs/{severity}", response_model=List[LogRecord], tags=["Logs"])
def get_logs_by_severity(severity: str):
    """Filter logs by severity: INFO, WARNING, or CRITICAL."""
    sev = severity.upper()
    if sev not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}.",
        )
    logs = fetch_logs_by_severity(sev)
    return logs


@app.get("/correlation", tags=["Analysis"])
def get_correlation():
    """Return correlated event clusters (IP / event type / time window)."""
    logs = fetch_all_logs()
    if not logs:
        raise HTTPException(status_code=404, detail="No logs in database. POST /ingest first.")
    clusters = correlate_logs(logs)
    summary = summarize_correlation(clusters)
    return {"summary": summary, "clusters": clusters}


@app.get("/analysis", tags=["Analysis"])
def get_analysis():
    """Return AI-assisted classification (Normal/Suspicious/Critical) + summary."""
    logs = fetch_all_logs()
    if not logs:
        raise HTTPException(status_code=404, detail="No logs in database. POST /ingest first.")
    report = build_analysis_report(logs)
    return report


@app.post("/ingest", tags=["Ingestion"])
def ingest_logs(log_path: str = "data/sample_logs.txt"):
    """Re-parse the raw log file and reload the database (demo/dev convenience)."""
    if not os.path.exists(log_path):
        raise HTTPException(status_code=400, detail=f"Log file not found: {log_path}")

    entries = parse_file(log_path)
    clear_logs()
    count = insert_logs_bulk([e.to_dict() for e in entries])
    return {"ingested": count, "source": log_path}
