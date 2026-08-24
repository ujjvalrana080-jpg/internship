"""
day12_fastapi_intro/main.py

Day 12 — Introduction to FastAPI

A minimal FastAPI app with three endpoints:
    GET /          -> welcome message
    GET /status    -> system status
    GET /evidence  -> sample evidence JSON data

Run with:
    uvicorn main:app --reload
"""

from fastapi import FastAPI
from datetime import datetime

app = FastAPI(
    title="Jagspire Forensics — Day 12 Intro API",
    description="First FastAPI service built during the Digital Forensics internship.",
    version="0.1.0",
)


@app.get("/")
def welcome():
    return {"message": "Welcome to the Jagspire Digital Forensics API"}


@app.get("/status")
def status():
    return {
        "status": "online",
        "service": "Jagspire Forensics Day 12 Intro API",
        "checked_at": datetime.now().isoformat(),
    }


@app.get("/evidence")
def sample_evidence():
    return {
        "evidence_id": "EVID-2026-0812",
        "case_id": "CASE-2026-081",
        "file_name": "access.csv",
        "file_type": "csv",
        "collected_at": "2026-08-12T09:15:00",
        "hash_sha256": "163df7a83ebafa2862c81810e38d7d524082663a8607eebade94dbc2e8015ee3",
        "notes": "Sample evidence record for demonstration purposes.",
    }
