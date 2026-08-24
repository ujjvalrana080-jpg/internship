"""
day13_mini_forensic_api/main.py

Day 13 — Mini Forensic API Project

Accepts log data (either an uploaded .log/.txt file or a JSON body of
pre-parsed entries) and returns structured counts: total events, error
count, warning count.

Endpoints:
    GET  /                  -> welcome / health check
    POST /analyze/file      -> upload a raw .log/.txt file, get counts back
    POST /analyze/json      -> POST a JSON list of log entries, get counts back

Run with:
    uvicorn main:app --reload
"""

import re
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Jagspire Forensics — Day 13 Mini Forensic API",
    description="Upload log data and get back structured error/warning/event counts.",
    version="1.0.0",
)

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<event_type>INFO|WARNING|ERROR)\s+"
    r"(?P<message>.+)$"
)


class LogEntry(BaseModel):
    timestamp: Optional[str] = None
    event_type: str
    message: Optional[str] = None


class AnalysisResult(BaseModel):
    total_events: int
    error_count: int
    warning_count: int
    info_count: int
    analyzed_at: str


def summarize_entries(event_types: List[str]) -> AnalysisResult:
    normalized = [e.upper() for e in event_types]
    return AnalysisResult(
        total_events=len(normalized),
        error_count=normalized.count("ERROR"),
        warning_count=normalized.count("WARNING"),
        info_count=normalized.count("INFO"),
        analyzed_at=datetime.now().isoformat(),
    )


@app.get("/")
def root():
    return {
        "message": "Jagspire Mini Forensic API — Day 13",
        "endpoints": ["/analyze/file (POST, multipart file upload)",
                      "/analyze/json (POST, JSON body)"],
    }


@app.post("/analyze/file", response_model=AnalysisResult)
async def analyze_file(file: UploadFile = File(...)):
    """Upload a raw .log/.txt file; each recognized line is counted by level."""
    content = (await file.read()).decode("utf-8", errors="ignore")

    event_types = []
    for line in content.splitlines():
        match = LOG_PATTERN.match(line.strip())
        if match:
            event_types.append(match.group("event_type"))

    if not event_types:
        raise HTTPException(status_code=400, detail="No recognizable log lines found in file.")

    return summarize_entries(event_types)


@app.post("/analyze/json", response_model=AnalysisResult)
def analyze_json(entries: List[LogEntry]):
    """Accept a JSON list of already-parsed log entries and return counts."""
    if not entries:
        raise HTTPException(status_code=400, detail="Entry list cannot be empty.")

    event_types = [e.event_type for e in entries]
    return summarize_entries(event_types)
