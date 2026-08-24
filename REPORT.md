# Week 3 Submission Report
### Jagspire Digital Forensics Internship — Forensic Investigation System v1

## 1. System Architecture

```
 sample_logs.txt
       │
       ▼
 core/log_parser.py  ──►  structured LogEntry objects
       │
       ▼
 database/db.py (SQLite: forensics.db, table "logs")
       │
       ├──────────────► analysis/correlation.py  ──► correlated_logs.json
       │                 (IP + event_type + 5-min window clustering)
       │
       └──────────────► analysis/ai_analysis.py  ──► ai_analysis.json
                         (rule-based Normal/Suspicious/Critical classifier)

                    api/main.py (FastAPI)
       exposes all of the above as live HTTP endpoints:
       /logs  /logs/{severity}  /correlation  /analysis  /ingest
```

The system is layered so each concern is isolated and independently
testable: **core** (parsing/models) never touches the database; **database**
never knows about correlation or AI logic; **analysis** consumes plain
dicts from the database layer; **api** is a thin HTTP wrapper around all
three. Any layer can be swapped (e.g. SQLite → Postgres, rule-based → LLM
classifier) without touching the others.

## 2. What I Built

- **Day 15 — SQLite integration**: schema with `id, timestamp, event_type,
  message, severity, src_ip, user`, plus indexed columns for fast filtering.
  Ingestion script parses 21 sample raw log lines with zero malformed rows.
- **Day 16 — Correlation engine**: groups logs by `(src_ip, event_type)`
  and clusters chronologically within a 5-minute rolling window. Detects
  `repeated_failures`, `anomaly_burst`, `suspicious_spike` (severity
  escalation within a window), and flags standalone `critical_event`
  clusters. On the sample dataset: 15 clusters total, 5 flagged
  (a brute-force cluster on one IP plus 4 standalone critical events).
- **Day 17 — FastAPI backend**: `/logs`, `/logs/{severity}`, `/correlation`,
  plus `/analysis` and `/ingest` (added ahead of schedule during Day 19
  integration since they share the same router). Input validation returns
  a proper 400 for invalid severities.
- **Day 18 — AI-assisted analysis**: rule-based classifier scores each log
  as Normal / Suspicious / Critical based on severity and known event-type
  indicators, then generates a natural-language summary highlighting the
  highest-risk source IPs and a recommendation. On the sample dataset:
  7 Normal, 10 Suspicious, 4 Critical.
- **Day 19 — Integration**: all four layers wired into one FastAPI app
  with a clean `/api /database /analysis /core` package structure, plus a
  `/scripts` folder for the standalone day-by-day runners.

## 3. What Was Hardest

Getting the correlation window logic right was the trickiest part —
naively grouping by time bucket boundaries (e.g. floor to nearest 5-minute
mark) would split closely-spaced events that straddle a boundary into
separate clusters and miss the pattern. Switching to a rolling window
measured from the first event in each open cluster (rather than fixed
clock buckets) fixed this and produced correct results on the brute-force
scenario in the sample data.

## 4. What Was Improved From Week 2

- Week 2 scripts operated on data only in memory / flat files; Week 3
  persists everything in SQLite with proper indexing, so queries by
  severity or event type are fast and the data survives between runs.
- Week 2's tooling was single-purpose scripts; Week 3 is a modular package
  (`core/database/analysis/api`) that can be imported and reused, not just
  executed top-to-bottom.
- Week 2 had no API; Week 3 exposes the whole pipeline over HTTP with
  input validation and documented endpoints (auto-generated Swagger at
  `/docs`).
- Added a genuine analysis layer (correlation + classification) on top of
  raw log storage, moving from "collect logs" to "interpret logs."

## 5. Evidence

- `demo_transcript.txt` — live `curl` calls against every endpoint,
  including the 400 error path and the reachable Swagger UI.
- `correlated_logs.json` — full Day 16 output.
- `ai_analysis.json` — full Day 18 output.
- `forensics.db` — populated SQLite database.
