# Jagspire Forensic Investigation System v1
### Week 3 Mini Project — Digital Forensics Internship

An end-to-end mini forensic system: raw log ingestion → SQLite storage →
correlation engine → FastAPI backend → AI-assisted classification.

## Project Structure

```
forensic_system/
├── api/
│   ├── __init__.py
│   └── main.py            # FastAPI app: /logs, /logs/{severity}, /correlation, /analysis, /ingest
├── core/
│   ├── __init__.py
│   ├── log_parser.py       # Raw log -> structured LogEntry
│   └── models.py           # Shared Pydantic models
├── database/
│   ├── __init__.py
│   └── db.py                # SQLite schema, insert/query helpers
├── analysis/
│   ├── __init__.py
│   ├── correlation.py       # Day 16: IP/event/time-window clustering + pattern detection
│   └── ai_analysis.py       # Day 18: Normal/Suspicious/Critical classification + summary
├── scripts/
│   ├── ingest.py             # Day 15 runner -> populates forensics.db
│   ├── run_correlation.py    # Day 16 runner -> correlated_logs.json
│   └── run_analysis.py       # Day 18 runner -> ai_analysis.json
├── data/
│   └── sample_logs.txt       # Sample raw log dataset (21 events)
├── requirements.txt
├── demo_transcript.txt       # Live API call evidence (Day 20)
└── REPORT.md                 # Day 20 submission report
```

## Setup

```bash
pip install -r requirements.txt
```

## Running the Pipeline (in order)

```bash
# Day 15 — parse sample logs and load into SQLite
python scripts/ingest.py

# Day 16 — run correlation engine -> correlated_logs.json
python scripts/run_correlation.py

# Day 18 — run AI classification -> ai_analysis.json
python scripts/run_analysis.py

# Day 17/19 — start the API (serves all of the above live)
uvicorn api.main:app --reload
```

Then visit `http://127.0.0.1:8000/docs` for interactive Swagger UI.

## API Endpoints

| Method | Endpoint            | Description                                      |
|--------|----------------------|---------------------------------------------------|
| GET    | `/`                  | Health check + endpoint list                       |
| GET    | `/logs`              | All logs from the database                         |
| GET    | `/logs/{severity}`   | Logs filtered by INFO / WARNING / CRITICAL          |
| GET    | `/correlation`       | Correlated event clusters + summary                |
| GET    | `/analysis`          | AI classification per log + forensic summary        |
| POST   | `/ingest`            | Re-run ingestion from `data/sample_logs.txt`         |

## Database Schema (`forensics.db`, table `logs`)

| Column     | Type    |
|------------|---------|
| id         | INTEGER PRIMARY KEY |
| timestamp  | TEXT (ISO 8601) |
| event_type | TEXT |
| message    | TEXT |
| severity   | TEXT |
| src_ip     | TEXT |
| user       | TEXT |

## Notes on the AI Analysis Module

`analysis/ai_analysis.py` uses a transparent, rule-based classifier rather
than a live LLM API call, so the whole system runs offline and
reproducibly. `classify_with_llm()` shows exactly where a real model call
would be substituted if an API key were available — swapping the
classification strategy doesn't require touching the rest of the pipeline.
