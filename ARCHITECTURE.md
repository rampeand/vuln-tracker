# Vulnerability Tracker — Architecture

## Overview

Vulnerability Tracker is a real-time security intelligence dashboard that aggregates CVE/advisory data from three authoritative public sources: the National Vulnerability Database (NVD), GitHub Security Advisories, and CISA's Known Exploited Vulnerabilities (KEV) catalog. It stores data in a local SQLite database that is refreshed hourly via a background scheduler, with on-demand refresh also available from the UI.

---

## System Architecture

```mermaid
graph TB
    subgraph Browser["Browser"]
        UI["React SPA\n(Vite / Tailwind CSS)"]
    end

    subgraph DockerCompose["Docker Compose"]
        subgraph FE["Frontend Container (Nginx:80)"]
            NGINX["Nginx\nServes static files\nProxies /api/* → backend:8000"]
        end

        subgraph BE["Backend Container (Uvicorn:8000)"]
            API["FastAPI Application"]
            CACHE["TTL Cache\n(in-memory, 15 min)"]
            SCHED["APScheduler\n(hourly background job)"]
            DB[("SQLite Database\nvulnerabilities.db")]
        end
    end

    subgraph External["External Data Sources"]
        NVD["NVD API 2.0\nnvd.nist.gov"]
        GH["GitHub Advisories API\napi.github.com"]
        CISA["CISA KEV Feed\ncisa.gov"]
    end

    UI -->|"HTTP GET /api/*"| NGINX
    NGINX -->|"Static HTML/JS/CSS"| UI
    NGINX -->|"Reverse proxy"| API

    API -->|"Cache hit → return"| CACHE
    API -->|"Cache miss → query"| DB
    DB -->|"Vulnerability rows"| API
    API -->|"Populate cache"| CACHE

    SCHED -->|"Every hour\n(asyncio.gather)"| NVD
    SCHED -->|"Every hour"| GH
    SCHED -->|"Every hour"| CISA
    NVD -->|"CVE JSON"| SCHED
    GH -->|"Advisory JSON"| SCHED
    CISA -->|"KEV JSON"| SCHED
    SCHED -->|"INSERT OR REPLACE"| DB
    SCHED -->|"cache.clear()"| CACHE
```

---

## Request / Response Flow

```mermaid
sequenceDiagram
    participant Browser
    participant Nginx
    participant FastAPI
    participant Cache
    participant SQLite
    participant Scheduler

    Note over Scheduler: Runs every hour (background)
    Scheduler->>NVD API: GET /rest/json/cves/2.0
    Scheduler->>GitHub API: GET /advisories
    Scheduler->>CISA: GET known_exploited_vulnerabilities.json
    Scheduler->>SQLite: INSERT OR REPLACE vulnerabilities
    Scheduler->>SQLite: UPDATE source_status (timestamp, count)
    Scheduler->>Cache: cache.clear()

    Browser->>Nginx: GET /api/vulnerabilities?days=7
    Nginx->>FastAPI: Proxy request
    FastAPI->>Cache: Check key "vulns_7"
    alt Cache hit
        Cache-->>FastAPI: Return cached list
    else Cache miss
        FastAPI->>SQLite: SELECT WHERE published_date >= cutoff
        SQLite-->>FastAPI: Vulnerability rows
        FastAPI->>Cache: Store result
    end
    FastAPI-->>Nginx: JSON response
    Nginx-->>Browser: JSON response

    Browser->>Nginx: GET /api/sources/status
    Nginx->>FastAPI: Proxy request
    FastAPI->>SQLite: SELECT source_status
    SQLite-->>FastAPI: last_updated, status, count per source
    FastAPI-->>Browser: SourcesStatusResponse JSON
```

---

## Component Breakdown

### Frontend (`src/`)

```
src/
├── App.jsx               # Root component — state management, data fetching, layout
├── main.jsx              # React entry point (ReactDOM.createRoot)
├── index.css             # Tailwind CSS directives + global resets
└── components/
    ├── FilterBar.jsx     # Time-range / severity / source / text-search controls
    ├── StatsPanel.jsx    # Summary cards (total, CRITICAL/HIGH/MEDIUM/LOW counts)
    ├── SourceStatus.jsx  # Per-source last-update timestamps + refresh buttons
    ├── VulnerabilityCard.jsx  # Expandable card for a single CVE/advisory
    └── LoadingSpinner.jsx     # Async loading indicator
```

| Component | Responsibility |
|-----------|---------------|
| `App.jsx` | Owns all state; fetches `/api/vulnerabilities`, `/api/stats`, `/api/sources/status`; wires up refresh callbacks |
| `FilterBar.jsx` | Emits filter changes that trigger re-fetches in `App` |
| `StatsPanel.jsx` | Displays aggregate counts; pure display component |
| `SourceStatus.jsx` | Shows health/timestamp per source; calls `POST /api/sources/refresh` per button click |
| `VulnerabilityCard.jsx` | Renders one vulnerability; expands on click to show full details, CWE links, references |

### Backend (`backend/`)

```
backend/
├── main.py           # FastAPI app, data-fetch functions, DB layer, scheduler
├── requirements.txt  # Python dependencies
├── Dockerfile        # Python 3.11-slim image
└── vulnerabilities.db  # SQLite database (auto-created at startup, gitignored)
```

| Layer | Implementation | Purpose |
|-------|---------------|---------|
| HTTP Server | Uvicorn (ASGI) | Serves FastAPI application |
| API Framework | FastAPI + Pydantic | Request routing, validation, OpenAPI docs |
| Scheduler | APScheduler `AsyncIOScheduler` | Hourly `refresh_all_sources()` background job |
| Cache | `cachetools.TTLCache` | 15-minute in-memory cache keyed by `days` param |
| Persistence | SQLite via `aiosqlite` | Stores all vulnerability + source status data |
| HTTP Client | `httpx.AsyncClient` | Async fetches from external APIs |

---

## Database Schema

```mermaid
erDiagram
    vulnerabilities {
        TEXT id PK "CVE-YYYY-NNNNN or GHSA-xxxx"
        TEXT title
        TEXT description
        TEXT severity "CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN"
        REAL cvss_score "nullable"
        TEXT published_date "ISO 8601"
        TEXT source "NVD / GitHub Advisory / CISA KEV"
        TEXT source_url
        TEXT affected_products "JSON array"
        TEXT remediation
        TEXT cwe_ids "JSON array"
        TEXT references "JSON array"
        TEXT last_seen "ISO 8601 — when last refreshed"
    }

    source_status {
        TEXT source PK "NVD / GitHub Advisory / CISA KEV"
        TEXT last_updated "ISO 8601 of last successful fetch"
        TEXT status "pending / updating / ok / error"
        INTEGER count "records from this source in DB"
        TEXT error_message "nullable — last error string"
    }
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/vulnerabilities` | Filtered, sorted vulnerability list (from DB + cache) |
| `GET` | `/api/stats` | Severity and source counts for current filter |
| `GET` | `/api/sources/status` | Per-source last-update timestamp, status, record count, next scheduled refresh |
| `POST` | `/api/sources/refresh` | Trigger immediate on-demand refresh (body: `{"source": "NVD"}` or `{}` for all) |
| `GET` | `/health` | Liveness probe (`{"status":"healthy"}`) |

Query parameters for `/api/vulnerabilities`:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `days` | int 1–30 | `2` | Look-back window |
| `severity` | string | — | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `source` | string | — | `NVD`, `GitHub`, `CISA` (substring match) |
| `search` | string | — | Free-text search in id/title/description |

---

## Data Sources

| Source | Endpoint | Data | Severity | Rate Limit |
|--------|----------|------|----------|------------|
| **NVD** | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE ID, CVSS, CWE, CPE products, references | Calculated from CVSS score | 5 req/30s (no key) |
| **GitHub Advisories** | `api.github.com/advisories` | GHSA/CVE ID, package ecosystem, CVSS | Mapped from CRITICAL/HIGH/MODERATE/LOW | 60 req/hr (no key) |
| **CISA KEV** | `cisa.gov/…/known_exploited_vulnerabilities.json` | CVE ID, vendor/product, required action, due date | Always CRITICAL | No limit (static JSON) |

---

## Deployment

```mermaid
graph LR
    subgraph Local["docker compose up"]
        FE["frontend:3000\nNginx + React"]
        BE["backend:8000\nUvicorn + FastAPI"]
        FE -->|"internal network\napi proxy"| BE
    end

    subgraph CICD["GitHub Actions (.github/workflows/docker-publish.yml)"]
        direction TB
        BUILD["Build & test both containers"]
        PUSH["Push to Docker Hub\nrampeand/vuln-tracker:backend\nrampeand/vuln-tracker:frontend"]
        BUILD --> PUSH
    end
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_URL` | `http://localhost:8000` | Backend URL (dev only; prod uses Nginx proxy) |
| `DB_PATH` | `vulnerabilities.db` | SQLite database file path (backend) |

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend framework | React | 19.2.0 |
| Build tool | Vite | 7.3.1 |
| CSS | Tailwind CSS | 4.2.1 |
| Backend framework | FastAPI | 0.115.0 |
| ASGI server | Uvicorn | 0.30.6 |
| Scheduler | APScheduler | 3.10.4 |
| Database | SQLite (aiosqlite) | stdlib + 0.20.0 |
| HTTP client | HTTPX | 0.27.2 |
| Data validation | Pydantic | 2.9.2 |
| Reverse proxy | Nginx | stable-alpine |
| Containerisation | Docker + Compose | — |
| CI/CD | GitHub Actions | — |
