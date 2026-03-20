<p align="center">
  <img src="https://img.shields.io/badge/security-vulnerability%20tracker-red?style=for-the-badge&logo=shield" alt="Security Badge"/>
</p>

<h1 align="center">
  <br>
  <sub>&#9888;</sub> Vulnerability Tracker
  <br>
</h1>

<p align="center">
  <strong>Real-time security intelligence at your fingertips</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React-19.2-61DAFB?style=flat-square&logo=react" alt="React"/>
  <img src="https://img.shields.io/badge/Vite-7.3-646CFF?style=flat-square&logo=vite" alt="Vite"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/Tailwind-4.2-06B6D4?style=flat-square&logo=tailwindcss" alt="Tailwind"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite" alt="SQLite"/>
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker"/>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#data-sources">Data Sources</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#api-reference">API Reference</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#license">License</a>
</p>

---

## Overview

**Vulnerability Tracker** aggregates security vulnerabilities from four authoritative public sources into a single, dark-themed dashboard. Stay ahead of threats with hourly data refreshes, severity-based filtering, and actionable remediation guidance.

```
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  ▲ VULNERABILITY TRACKER              Real-time security intel   ║
 ╠═══════════════════════════════════════════════════════════════════╣
 ║                                                                   ║
 ║   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         ║
 ║   │ CRITICAL │  │   HIGH   │  │  MEDIUM  │  │   LOW    │         ║
 ║   │    12    │  │    34    │  │    56    │  │    23    │         ║
 ║   └──────────┘  └──────────┘  └──────────┘  └──────────┘         ║
 ║                                                                   ║
 ║   [Last 2 days ▾]  [All Severities ▾]  [All Sources ▾]  [ Q ]   ║
 ║                                                                   ║
 ║   ┌───────────────────────────────────────────────────────────┐   ║
 ║   │  ● CVE-2026-XXXXX                         CRITICAL  9.8  │   ║
 ║   │    Remote code execution in ...                           │   ║
 ║   │    Source: NVD  ·  Products: Linux Kernel                 │   ║
 ║   └───────────────────────────────────────────────────────────┘   ║
 ║   ┌───────────────────────────────────────────────────────────┐   ║
 ║   │  ● GHSA-xxxx-xxxx-xxxx                       HIGH  8.1   │   ║
 ║   │    Dependency confusion in ...                            │   ║
 ║   │    Source: GitHub Advisory  ·  Ecosystem: npm             │   ║
 ║   └───────────────────────────────────────────────────────────┘   ║
 ║                                                                   ║
 ╚═══════════════════════════════════════════════════════════════════╝
```

---

## Features

<table>
<tr>
<td width="33%">

### Dashboard
- Real-time aggregation from 4 feeds
- Severity classification with color coding
- Smart filtering by severity, source, time
- Full-text search across IDs, titles, descriptions

</td>
<td width="33%">

### Intelligence
- CVSS v3.x scoring with auto severity
- CWE weakness mapping & categorization
- Affected products extracted from CPE
- Actionable remediation per CWE type

</td>
<td width="33%">

### Operations
- Hourly background refresh (APScheduler)
- On-demand per-source refresh from UI
- 15-minute TTL cache for fast reads
- Per-source health status & timestamps

</td>
</tr>
</table>

---

## Data Sources

```
                    ┌───────────────────────────────┐
                    ┌─────────────────────────────────┐
                    │      Vulnerability Tracker       │
                    │          (refreshes hourly)      │
                    └──┬─────────┬─────────┬─────────┬┘
                       │         │         │         │
          ┌────────────┘         │         │         └────────────┐
          ▼                      ▼         ▼                      ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│    NVD (NIST)   │  │ GitHub Advisory │  │   CISA KEV      │  │  CCCS (Canada)  │
│─────────────────│  │─────────────────│  │─────────────────│  │─────────────────│
│ CVE data, CVSS  │  │ GHSA advisories │  │ Known exploited │  │ Alerts &        │
│ CWE, CPE, refs  │  │ ecosystem pkgs  │  │ vulnerabilities │  │ advisories      │
│ 5 req / 30s     │  │ 60 req / hr     │  │ static JSON     │  │ Atom XML feed   │
└─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘
```

| Source | What it provides | Rate Limit |
|--------|-----------------|------------|
| **NVD** (NIST) | Comprehensive CVE data: CVSS scores, CWE IDs, CPE products, references | 5 req / 30 sec (no API key) |
| **GitHub Security Advisories** | Package-level advisories across ecosystems (npm, PyPI, Maven, etc.) | 60 req / hr (unauthenticated) |
| **CISA KEV** | Actively exploited vulnerabilities with federal remediation deadlines | No limit (static JSON file) |
| **CCCS** (Canadian Centre for Cyber Security) | Government alerts & advisories with CVE references, severity hints | No limit (Atom feed) |

---

## Quick Start

### Docker (Recommended)

Pre-built images are published to Docker Hub on every push to `main`.

**Production** &mdash; uses images from Docker Hub with persistent storage:

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

**Local development** &mdash; builds from source:

```bash
docker compose up -d --build
```

Both modes expose the dashboard at **`http://localhost:3000`**.

---

### Manual Setup

<details>
<summary><strong>Backend</strong> &mdash; Python 3.11+</summary>

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py                  # → http://localhost:8000
```

</details>

<details>
<summary><strong>Frontend</strong> &mdash; Node.js 18+</summary>

```bash
npm install
npm run dev                     # → http://localhost:3000
```

</details>

### Environment Variables

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `VITE_API_URL` | `http://localhost:8000` | Frontend (dev only) | Backend URL; production uses the Nginx proxy |
| `DB_PATH` | `vulnerabilities.db` | Backend | SQLite database file path |

---

## API Reference

### `GET /api/vulnerabilities`

Returns a filtered, sorted list of vulnerabilities from the local database.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | `2` | Look-back window (1 &ndash; 30) |
| `severity` | string | &mdash; | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `source` | string | &mdash; | Substring match: `NVD`, `GitHub`, `CISA`, `CCCS` |
| `search` | string | &mdash; | Free-text across ID, title, description |

<details>
<summary>Example response</summary>

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2026-XXXXX",
      "title": "Remote Code Execution in ...",
      "description": "A vulnerability allows ...",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "published_date": "2026-03-12T00:00:00",
      "source": "NVD",
      "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
      "affected_products": ["Linux Kernel"],
      "remediation": "CRITICAL: Immediate patching required ...",
      "cwe_ids": ["CWE-94"],
      "references": ["https://..."]
    }
  ],
  "total_count": 125,
  "sources_queried": ["NVD", "GitHub Advisory", "CISA KEV", "CCCS"],
  "query_time": "2026-03-14T12:00:00",
  "days_range": 2
}
```

</details>

### `GET /api/stats`

Aggregate severity and source counts for the current look-back window.

<details>
<summary>Example response</summary>

```json
{
  "total": 125,
  "by_severity": { "CRITICAL": 12, "HIGH": 34, "MEDIUM": 56, "LOW": 23 },
  "by_source": { "NVD": 100, "GitHub Advisory": 20, "CISA KEV": 5 },
  "days_range": 2
}
```

</details>

### `GET /api/sources/status`

Per-source health: last-update timestamp, record count, status (`pending` / `updating` / `ok` / `error`), and next scheduled refresh time.

### `POST /api/sources/refresh`

Trigger an immediate on-demand refresh. Send `{"source": "NVD"}` for one source, or `{}` for all.

### `GET /health`

Liveness probe &mdash; returns `{"status": "healthy"}` whenever the process is running.

---

## Architecture

```
vuln-tracker/
│
├── backend/
│   ├── main.py                 # FastAPI app: API + data fetchers + scheduler
│   ├── Dockerfile              # Python 3.11-slim container
│   └── requirements.txt        # Python dependencies
│
├── src/
│   ├── App.jsx                 # Root component: state, fetching, layout
│   ├── components/
│   │   ├── FilterBar.jsx       # Time / severity / source / search controls
│   │   ├── StatsPanel.jsx      # Severity breakdown cards
│   │   ├── SourceStatus.jsx    # Per-source health & on-demand refresh
│   │   ├── VulnerabilityCard.jsx   # Expandable CVE / advisory card
│   │   └── LoadingSpinner.jsx  # Async loading indicator
│   ├── index.css               # Tailwind CSS directives
│   └── main.jsx                # React entry point
│
├── nginx.conf                  # Reverse proxy: static files + /api/ → backend
├── Dockerfile                  # Multi-stage: Node build → Nginx runtime
├── docker-compose.yml          # Local dev (build from source)
├── docker-compose.prod.yml     # Production (Docker Hub images + volume)
├── vite.config.js              # Vite build configuration
└── package.json
```

### How requests flow

```
                             ┌──────────┐
                             │ Browser  │
                             └────┬─────┘
                                  │ GET /api/vulnerabilities?days=7
                                  ▼
                         ┌────────────────┐
                         │  Nginx (:80)   │──── static HTML/JS/CSS
                         └────────┬───────┘
                                  │ proxy_pass → backend:8000
                                  ▼
                         ┌────────────────┐
                         │  FastAPI       │
                         │  (Uvicorn)     │
                         └──┬─────────┬──┘
                            │         │
                    cache hit?    cache miss
                            │         │
                            ▼         ▼
                     ┌──────────┐  ┌──────────┐
                     │ TTL Cache│  │  SQLite   │
                     │ (15 min) │  │   DB      │
                     └──────────┘  └──────────┘
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 19, Vite 7, Tailwind CSS 4 |
| **Backend** | FastAPI 0.115, Pydantic 2.9, HTTPX 0.27 |
| **Scheduler** | APScheduler 3.10 (hourly background refresh) |
| **Database** | SQLite via aiosqlite, with 15-min in-memory TTL cache |
| **Proxy** | Nginx stable-alpine (static files + API reverse proxy) |
| **Data Sources** | NVD API 2.0, GitHub Advisory API, CISA KEV, CCCS Alerts |
| **CI/CD** | GitHub Actions &rarr; Docker Hub (`rampeand/vuln-tracker`) |

---

## Severity Levels

```
  CVSS Score    0         4.0       7.0       9.0        10
       ├─────────┼──────────┼─────────┼──────────┤
       │   LOW   │  MEDIUM  │  HIGH   │ CRITICAL │
       │  blue   │  yellow  │ orange  │   red    │
       └─────────┴──────────┴─────────┴──────────┘
```

| Level | CVSS Range | Recommended Action |
|-------|------------|-------------------|
| **CRITICAL** | 9.0 &ndash; 10.0 | Immediate patching required |
| **HIGH** | 7.0 &ndash; 8.9 | Patch within 24 &ndash; 48 hours |
| **MEDIUM** | 4.0 &ndash; 6.9 | Schedule for next maintenance window |
| **LOW** | 0.1 &ndash; 3.9 | Include in regular patch cycle |

---

## License

This project is distributed under the **BSD-3-Clause** License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with security in mind</sub>
</p>
