"""
core/models.py

Shared data models used across the API, database, and analysis layers.
"""

from pydantic import BaseModel
from typing import Optional, List


class LogRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str
    event_type: str
    message: str
    severity: str
    src_ip: Optional[str] = None
    user: Optional[str] = None


class CorrelatedCluster(BaseModel):
    cluster_id: str
    src_ip: Optional[str]
    event_type: str
    window_start: str
    window_end: str
    event_count: int
    pattern: str
    severity_score: int
    log_ids: List[int]


class AIAnalysisResult(BaseModel):
    log_id: int
    classification: str  # Normal | Suspicious | Critical
    confidence: float
    reason: str
