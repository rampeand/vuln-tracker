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
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-data-sources">Data Sources</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-api-reference">API</a> •
  <a href="#-architecture">Architecture</a>
</p>

---

## Overview

**Vulnerability Tracker** aggregates security vulnerabilities from multiple authoritative sources into a single, beautiful dashboard. Stay ahead of threats with real-time data, severity-based filtering, and actionable remediation guidance.

```
┌─────────────────────────────────────────────────────────────────┐
│  ▲ VULNERABILITY TRACKER           Real-time security intel    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │CRITICAL │  │  HIGH   │  │ MEDIUM  │  │   LOW   │            │
│  │   12    │  │   34    │  │   56    │  │   23    │            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
│                                                                 │
│  [Last 2 days ▾]  [All Severities ▾]  [All Sources ▾]  [🔍]   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ ● CVE-2024-XXXXX                          CRITICAL 9.8 │   │
│  │   Remote code execution in...                          │   │
│  │   Source: NVD | Products: Linux Kernel                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Dashboard
- **Real-time aggregation** from multiple security feeds
- **Severity classification** (Critical, High, Medium, Low)
- **Smart filtering** by severity, source, and time range
- **Full-text search** across CVE IDs, titles, and descriptions
- **Dark mode interface** optimized for security operations

### Intelligence
- **CVSS scoring** with automatic severity calculation
- **CWE mapping** for vulnerability categorization
- **Affected products** extraction from CPE data
- **Actionable remediation** guidance based on severity and CWE type

### Performance
- **15-minute caching** to respect API rate limits
- **Concurrent fetching** from all sources
- **Deduplication** across data sources
- **Responsive design** for desktop and mobile

---

## Data Sources

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| **NVD** | NIST National Vulnerability Database - comprehensive CVE data with CVSS scores | Real-time |
| **GitHub Security Advisories** | Vulnerabilities affecting open-source packages across ecosystems | Real-time |
| **CISA KEV** | Known Exploited Vulnerabilities - actively exploited in the wild | Daily |

---

## Quick Start

### Prerequisites

- Node.js 18+
- Python 3.11+

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the API server
python main.py
```

The API will be available at `http://localhost:8000`

### Frontend Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The dashboard will be available at `http://localhost:5173`

### Environment Variables

Create a `.env.local` file in the project root:

```env
VITE_API_URL=http://localhost:8000
```

### Running with Docker

You can easily run the application using the pre-built Docker images hosted on Docker Hub.

#### Using Docker Compose
Create a `docker-compose.yml` file:
```yaml
version: '3.8'
services:
  backend:
    image: rampeand/vuln-tracker:backend
    ports:
      - "8000:8000"
    restart: always

  frontend:
    image: rampeand/vuln-tracker:frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
    restart: always
```
Run the application:
```bash
docker compose up -d
```
The dashboard will be available at `http://localhost:3000` and the API at `http://localhost:8000`.

#### Using Docker CLI (Manual)
Run the backend:
```bash
docker run -d --name vuln-tracker-backend -p 8000:8000 rampeand/vuln-tracker:backend
```
Run the frontend:
```bash
docker run -d --name vuln-tracker-frontend -p 3000:80 rampeand/vuln-tracker:frontend
```

---


## API Reference

### Get Vulnerabilities

```http
GET /api/vulnerabilities
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 2 | Days to look back (1-30) |
| `severity` | string | - | Filter: CRITICAL, HIGH, MEDIUM, LOW |
| `source` | string | - | Filter: NVD, GitHub, CISA |
| `search` | string | - | Search in title/description |

**Response:**
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-XXXXX",
      "title": "Remote Code Execution in...",
      "description": "A vulnerability allows...",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "published_date": "2024-01-15T00:00:00",
      "source": "NVD",
      "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX",
      "affected_products": ["Linux Kernel"],
      "remediation": "CRITICAL: Immediate patching required...",
      "cwe_ids": ["CWE-94"],
      "references": ["https://..."]
    }
  ],
  "total_count": 125,
  "sources_queried": ["NVD", "GitHub Advisory", "CISA KEV"],
  "query_time": "2024-01-15T12:00:00",
  "days_range": 2
}
```

### Get Statistics

```http
GET /api/stats?days=2
```

**Response:**
```json
{
  "total": 125,
  "by_severity": {
    "CRITICAL": 12,
    "HIGH": 34,
    "MEDIUM": 56,
    "LOW": 23
  },
  "by_source": {
    "NVD": 100,
    "GitHub Advisory": 20,
    "CISA KEV": 5
  }
}
```

### Health Check

```http
GET /health
```

---

## Architecture

```
vuln-tracker/
├── backend/
│   ├── main.py              # FastAPI application
│   └── requirements.txt     # Python dependencies
├── src/
│   ├── App.jsx              # Main React component
│   ├── components/
│   │   ├── FilterBar.jsx    # Search and filter controls
│   │   ├── LoadingSpinner.jsx
│   │   ├── StatsPanel.jsx   # Severity statistics
│   │   └── VulnerabilityCard.jsx
│   ├── index.css            # Tailwind imports
│   └── main.jsx             # React entry point
├── package.json
└── vite.config.js
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 19, Vite 7, Tailwind CSS 4 |
| **Backend** | FastAPI, Pydantic, HTTPX |
| **Caching** | cachetools (TTL-based) |
| **Data Sources** | NVD API 2.0, GitHub API, CISA KEV |

---

## Severity Levels

| Level | CVSS Range | Color | Action |
|-------|------------|-------|--------|
| **CRITICAL** | 9.0 - 10.0 | Red | Immediate patching required |
| **HIGH** | 7.0 - 8.9 | Orange | Patch within 24-48 hours |
| **MEDIUM** | 4.0 - 6.9 | Yellow | Schedule for next maintenance window |
| **LOW** | 0.1 - 3.9 | Blue | Include in regular patch cycle |

---


---

<p align="center">
  <sub>Built with security in mind</sub>
</p>
