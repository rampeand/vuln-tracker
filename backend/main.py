"""
Vulnerability Aggregator API
=============================
A FastAPI backend that aggregates security vulnerability data from three
authoritative public sources and persists it to a local SQLite database.

Data Sources:
  - NVD  (National Vulnerability Database) — NIST CVE feed
  - GitHub Security Advisories             — ecosystem package advisories
  - CISA KEV (Known Exploited Vulnerabilities) — actively exploited CVEs

Architecture:
  - SQLite database  : persistent storage, survives container restarts
  - APScheduler      : hourly background job refreshes all three sources
  - TTL Cache        : 15-minute in-memory cache reduces DB reads
  - FastAPI / Pydantic: typed REST API with auto-generated OpenAPI docs

Endpoints:
  GET  /api/vulnerabilities      — filtered, sorted vulnerability list
  GET  /api/stats                — severity / source aggregate counts
  GET  /api/sources/status       — per-source last-update timestamps & health
  POST /api/sources/refresh      — on-demand refresh (all or single source)
  GET  /health                   — liveness probe

Data Flow (read path):
  Browser → Nginx → FastAPI → TTL Cache (hit) → Response
                                              ↓ miss
                                         SQLite DB → Response

Data Flow (write path / background):
  APScheduler (every hour) → fetch NVD + GitHub + CISA (concurrent)
                           → INSERT OR REPLACE into SQLite
                           → UPDATE source_status timestamps
                           → invalidate TTL cache
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

import httpx
import asyncio
import aiosqlite
import json
import os

from dateutil import parser as date_parser
from cachetools import TTLCache
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# SQLite database file path — override via DB_PATH environment variable
DB_PATH = os.environ.get("DB_PATH", "vulnerabilities.db")

# How many days of history to fetch during each background refresh.
# 30 days gives broad coverage without hitting API rate limits too hard.
REFRESH_DAYS = 30

# Canonical list of data source names used throughout the application
SOURCE_NAMES = ["NVD", "GitHub Advisory", "CISA KEV"]


# ---------------------------------------------------------------------------
# In-memory TTL cache
# Keyed by "vulns_{days}" so each look-back window is cached independently.
# TTL = 900 seconds (15 minutes); maxsize = 100 distinct cache entries.
# ---------------------------------------------------------------------------
cache = TTLCache(maxsize=100, ttl=900)


# ---------------------------------------------------------------------------
# Background scheduler — triggers hourly data refresh
# ---------------------------------------------------------------------------
scheduler = AsyncIOScheduler()

# Asyncio lock prevents two concurrent full-refresh tasks from running at once
_refresh_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class Vulnerability(BaseModel):
    """A single vulnerability record aggregated from one of the three sources."""
    id: str                             # CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx
    title: str                          # Human-readable title or advisory summary
    description: str                    # Vulnerability description (max 500 chars)
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss_score: Optional[float] = None  # CVSS base score (v3.x preferred, v2 fallback)
    published_date: str                 # ISO 8601 datetime string
    source: str                         # "NVD" | "GitHub Advisory" | "CISA KEV"
    source_url: str                     # Canonical link to the advisory
    affected_products: list[str] = []   # Extracted vendor/product names
    remediation: str                    # Generated remediation guidance
    cwe_ids: list[str] = []             # CWE-NNN weakness identifiers
    references: list[str] = []          # External reference URLs


class VulnerabilityResponse(BaseModel):
    """API response envelope for /api/vulnerabilities."""
    vulnerabilities: list[Vulnerability]
    total_count: int
    sources_queried: list[str]
    query_time: str
    days_range: int


class SourceStatus(BaseModel):
    """Status and freshness metadata for one data source."""
    source: str                           # Source name
    last_updated: Optional[str] = None    # ISO datetime of last successful fetch
    status: str = "pending"               # pending | updating | ok | error
    count: int = 0                        # Records from this source stored in DB
    error_message: Optional[str] = None   # Last error string if status == "error"


class SourcesStatusResponse(BaseModel):
    """API response for GET /api/sources/status."""
    sources: dict[str, SourceStatus]
    next_refresh: Optional[str] = None    # ISO datetime of next scheduled run


class RefreshRequest(BaseModel):
    """Optional request body for POST /api/sources/refresh."""
    # Omit or set to null to refresh all sources at once.
    # Accepts both canonical names ("GitHub Advisory") and short aliases ("github").
    source: Optional[str] = None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

async def init_db():
    """
    Initialize SQLite schema on first startup.

    Creates two tables:
      - vulnerabilities : stores all aggregated CVE/advisory records
      - source_status   : one row per data source, tracking refresh timestamps

    Safe to call on every startup (uses CREATE TABLE IF NOT EXISTS).
    """
    async with aiosqlite.connect(DB_PATH) as db:
        # Primary vulnerability store
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id                TEXT PRIMARY KEY,
                title             TEXT NOT NULL,
                description       TEXT,
                severity          TEXT,
                cvss_score        REAL,
                published_date    TEXT,   -- ISO 8601, used for date-range filtering
                source            TEXT,
                source_url        TEXT,
                affected_products TEXT,   -- JSON-encoded list[str]
                remediation       TEXT,
                cwe_ids           TEXT,   -- JSON-encoded list[str]
                references        TEXT,   -- JSON-encoded list[str]
                last_seen         TEXT    -- ISO 8601 of last refresh that included this row
            )
        """)

        # Per-source refresh metadata
        await db.execute("""
            CREATE TABLE IF NOT EXISTS source_status (
                source         TEXT PRIMARY KEY,
                last_updated   TEXT,            -- ISO 8601 of last successful fetch
                status         TEXT DEFAULT 'pending',
                count          INTEGER DEFAULT 0,
                error_message  TEXT             -- null when status != 'error'
            )
        """)

        # Seed a status row for each known source (no-op if already present)
        for source in SOURCE_NAMES:
            await db.execute(
                "INSERT OR IGNORE INTO source_status (source, status) VALUES (?, 'pending')",
                (source,)
            )

        await db.commit()


def _vuln_to_row(vuln: Vulnerability) -> tuple:
    """Serialise a Vulnerability model into a tuple for DB INSERT."""
    return (
        vuln.id,
        vuln.title,
        vuln.description,
        vuln.severity,
        vuln.cvss_score,
        vuln.published_date,
        vuln.source,
        vuln.source_url,
        json.dumps(vuln.affected_products),   # Stored as JSON string
        vuln.remediation,
        json.dumps(vuln.cwe_ids),             # Stored as JSON string
        json.dumps(vuln.references),          # Stored as JSON string
        datetime.utcnow().isoformat()         # last_seen timestamp
    )


def _row_to_vuln(row) -> Vulnerability:
    """Deserialise a SQLite row (from vulnerabilities SELECT *) into a Vulnerability model."""
    return Vulnerability(
        id=row[0],
        title=row[1],
        description=row[2] or "",
        severity=row[3] or "UNKNOWN",
        cvss_score=row[4],
        published_date=row[5] or "",
        source=row[6] or "",
        source_url=row[7] or "",
        affected_products=json.loads(row[8]) if row[8] else [],
        remediation=row[9] or "",
        cwe_ids=json.loads(row[10]) if row[10] else [],
        references=json.loads(row[11]) if row[11] else []
    )


async def _upsert_vulnerabilities(vulns: list[Vulnerability]):
    """
    Bulk-upsert a list of vulnerabilities into SQLite.

    Uses INSERT OR REPLACE so that:
      - New records are inserted.
      - Existing records (same id) are updated with the latest data.
    """
    if not vulns:
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            """INSERT OR REPLACE INTO vulnerabilities
               (id, title, description, severity, cvss_score, published_date,
                source, source_url, affected_products, remediation,
                cwe_ids, references, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [_vuln_to_row(v) for v in vulns]
        )
        await db.commit()


async def _get_source_status(source: str) -> SourceStatus:
    """Read the current status row for one data source from the DB."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT source, last_updated, status, count, error_message "
            "FROM source_status WHERE source = ?",
            (source,)
        ) as cursor:
            row = await cursor.fetchone()

    if row:
        return SourceStatus(
            source=row[0],
            last_updated=row[1],
            status=row[2],
            count=row[3] or 0,
            error_message=row[4]
        )
    return SourceStatus(source=source)  # Default/empty status if row is missing


async def _set_source_status(
    source: str,
    status: str,
    count: int = 0,
    error_message: Optional[str] = None
):
    """
    Persist the refresh outcome for a data source.

    - On success (status="ok"): records last_updated timestamp and count.
    - On failure (status="error"): records error_message; last_updated unchanged.
    - On start  (status="updating"): marks as in-progress.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        if status == "ok":
            await db.execute(
                """UPDATE source_status
                   SET last_updated = ?, status = ?, count = ?, error_message = NULL
                   WHERE source = ?""",
                (datetime.utcnow().isoformat(), status, count, source)
            )
        elif status == "updating":
            await db.execute(
                "UPDATE source_status SET status = 'updating' WHERE source = ?",
                (source,)
            )
        else:  # "error" or "pending"
            await db.execute(
                "UPDATE source_status SET status = ?, error_message = ? WHERE source = ?",
                (status, error_message, source)
            )
        await db.commit()


async def _read_vulnerabilities_from_db(days: int) -> list[Vulnerability]:
    """
    Query all vulnerabilities with published_date within the last `days` days.

    The cutoff is truncated to the start of the day (YYYY-MM-DD) because some
    records (CISA KEV) only store a date without a time component.
    Returns an empty list if the database is not yet populated.
    """
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                """SELECT id, title, description, severity, cvss_score,
                          published_date, source, source_url,
                          affected_products, remediation, cwe_ids, references
                   FROM vulnerabilities
                   WHERE published_date >= ?
                   ORDER BY cvss_score DESC, published_date DESC""",
                (cutoff,)
            ) as cursor:
                rows = await cursor.fetchall()
        return [_row_to_vuln(row) for row in rows]
    except Exception as e:
        print(f"[DB] Error reading vulnerabilities: {e}")
        return []


# ---------------------------------------------------------------------------
# Severity / remediation helpers
# ---------------------------------------------------------------------------

def calculate_severity(cvss_score: Optional[float]) -> str:
    """
    Map a CVSS base score to a severity category using standard thresholds.

    NVD / CVSS v3 severity bands:
      9.0 – 10.0  → CRITICAL
      7.0 –  8.9  → HIGH
      4.0 –  6.9  → MEDIUM
      0.1 –  3.9  → LOW
      None / 0.0  → UNKNOWN
    """
    if cvss_score is None:
        return "UNKNOWN"
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    return "NONE"


def generate_remediation(vuln_data: dict, source: str) -> str:
    """
    Generate actionable remediation guidance from vulnerability metadata.

    Combines four layers of advice:
      1. Urgency based on CVSS score
      2. Regulatory note for CISA KEV entries (federal mandate)
      3. Technique-specific hints derived from CWE IDs (first 2 only)
      4. Vendor advisory reference if patch/fix URLs found
    """
    remediation_parts = []

    # Layer 1: vendor advisory hint (if reference URLs mention patch/advisory/fix)
    if "references" in vuln_data:
        vendor_refs = [
            r for r in vuln_data.get("references", [])
            if any(tag in str(r).lower() for tag in ["patch", "vendor", "advisory", "fix"])
        ]
        if vendor_refs:
            remediation_parts.append("Check vendor advisories for official patches.")

    # Layer 2: CVSS-based urgency guidance
    cvss = vuln_data.get("cvss_score")
    if cvss and cvss >= 9.0:
        remediation_parts.append(
            "CRITICAL: Immediate patching required. "
            "Consider taking affected systems offline until patched."
        )
    elif cvss and cvss >= 7.0:
        remediation_parts.append(
            "HIGH: Prioritize patching within 24-48 hours. "
            "Implement compensating controls if immediate patching is not possible."
        )
    elif cvss and cvss >= 4.0:
        remediation_parts.append(
            "MEDIUM: Schedule patching within the next maintenance window. "
            "Monitor for exploitation attempts."
        )
    else:
        remediation_parts.append(
            "LOW: Include in regular patch cycle. "
            "Document risk acceptance if deferring."
        )

    # Layer 3: CISA KEV federal mandate note
    if source == "CISA KEV":
        remediation_parts.append(
            "This vulnerability is actively exploited in the wild. "
            "Federal agencies must remediate per CISA binding operational directive."
        )

    # Layer 4: CWE-specific technique guidance (cap at 2 to keep text concise)
    for cwe in vuln_data.get("cwe_ids", [])[:2]:
        cwe_lower = cwe.lower()
        if "injection" in cwe_lower or "79" in cwe:
            remediation_parts.append("Implement input validation and output encoding.")
        elif "buffer" in cwe_lower or "overflow" in cwe_lower:
            remediation_parts.append("Apply vendor patches and consider memory-safe alternatives.")
        elif "auth" in cwe_lower:
            remediation_parts.append(
                "Review authentication mechanisms and implement MFA where possible."
            )
        elif "deserial" in cwe_lower:
            remediation_parts.append(
                "Avoid deserializing untrusted data. Use allowlists for acceptable classes."
            )

    if not remediation_parts:
        remediation_parts.append(
            "Review vendor documentation for specific remediation steps. "
            "Apply available patches and updates."
        )

    return " ".join(remediation_parts)


def _normalize_date(date_str: str) -> str:
    """
    Normalize a date string to ISO 8601 format (YYYY-MM-DDTHH:MM:SS).

    Handles:
      - ISO 8601 with timezone (GitHub, NVD)  →  strip timezone, keep UTC
      - YYYY-MM-DD (CISA KEV)                 →  append T00:00:00
      - Any dateutil-parseable string

    Returns the original string unchanged if parsing fails, so callers
    always receive a non-null value.
    """
    if not date_str:
        return date_str
    try:
        parsed = date_parser.parse(date_str)
        return parsed.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return date_str


# ---------------------------------------------------------------------------
# Data source fetch functions
# Each function is responsible for ONE source.  They share the same
# httpx.AsyncClient, are called concurrently via asyncio.gather(), and
# re-raise exceptions so the caller can record them in source_status.
# ---------------------------------------------------------------------------

async def fetch_nvd_vulnerabilities(days: int, client: httpx.AsyncClient) -> list[Vulnerability]:
    """
    Fetch recent CVEs from the NVD API 2.0.

    Queries by pubStartDate / pubEndDate covering the last `days` days.
    Extracts:
      - CVSS score   : prefers v3.1 → v3.0 → v2.0
      - CWE IDs      : from the weaknesses array
      - Affected products : parsed from CPE 2.3 strings (vendor + product)
      - References   : up to 5 URLs

    NVD rate limit: ~5 requests per 30 seconds without an API key.
    Raises exception on fetch failure so the caller records the error.
    """
    vulnerabilities = []

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 100
    }

    response = await client.get(url, params=params, timeout=30.0)

    if response.status_code == 200:
        data = response.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Prefer English description; fall back to first available
            descriptions = cve.get("descriptions", [])
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                descriptions[0].get("value", "") if descriptions else "No description available"
            )

            # CVSS score waterfall: v3.1 → v3.0 → v2.0
            cvss_score = None
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

            # CWE IDs from the weaknesses array
            cwe_ids = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc["value"])

            # Affected products: parse CPE 2.3 strings
            # CPE format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
            # We extract index 3 (vendor) and 4 (product) after splitting on ':'
            affected_products = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        criteria = cpe_match.get("criteria", "")
                        if criteria:
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                affected_products.append(
                                    f"{vendor} {product}".replace("_", " ").title()
                                )

            references = [ref.get("url", "") for ref in cve.get("references", [])[:5]]
            published = _normalize_date(cve.get("published", ""))

            vuln_data = {
                "severity": calculate_severity(cvss_score),
                "cvss_score": cvss_score,
                "cwe_ids": cwe_ids,
                "references": references
            }

            vuln = Vulnerability(
                id=cve_id,
                title=cve_id,
                description=description[:500] + "..." if len(description) > 500 else description,
                severity=calculate_severity(cvss_score),
                cvss_score=cvss_score,
                published_date=published,
                source="NVD",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                affected_products=list(set(affected_products))[:10],
                remediation=generate_remediation(vuln_data, "NVD"),
                cwe_ids=cwe_ids,
                references=references
            )
            vulnerabilities.append(vuln)

    return vulnerabilities


async def fetch_github_advisories(days: int, client: httpx.AsyncClient) -> list[Vulnerability]:
    """
    Fetch security advisories from the GitHub Advisory Database API.

    Returns advisories published within the last `days` days.
    GitHub advisories frequently cover ecosystem packages (npm, PyPI, Maven, etc.)
    before they appear in NVD, making them a valuable early-warning source.

    Severity mapping:
      GitHub "MODERATE" → internal "MEDIUM"
      All other GitHub labels map 1-to-1.

    Rate limit: 60 requests/hour unauthenticated.
    Raises exception on fetch failure so the caller records the error.
    """
    vulnerabilities = []

    url = "https://api.github.com/advisories"
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    params = {
        "per_page": 100,
        "sort": "published",
        "direction": "desc"
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    response = await client.get(url, params=params, headers=headers, timeout=30.0)

    if response.status_code == 200:
        advisories = response.json()

        for advisory in advisories:
            # Filter to the requested time window client-side
            published = advisory.get("published_at", "")
            if published:
                pub_date = date_parser.parse(published).replace(tzinfo=None)
                if pub_date < start_date:
                    continue

            # Map GitHub severity to our internal format
            severity = advisory.get("severity", "unknown").upper()
            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MODERATE": "MEDIUM",   # GitHub-specific label
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "UNKNOWN": "UNKNOWN"
            }
            severity = severity_map.get(severity, "UNKNOWN")

            cvss = advisory.get("cvss", {})
            cvss_score = cvss.get("score") if cvss else None

            # Affected packages: "<ecosystem>: <package-name>" e.g. "npm: lodash"
            affected_products = []
            for vuln in advisory.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                if pkg:
                    ecosystem = pkg.get("ecosystem", "")
                    name = pkg.get("name", "")
                    affected_products.append(f"{ecosystem}: {name}")

            cwe_ids = [cwe.get("cwe_id", "") for cwe in advisory.get("cwes", [])]
            references = advisory.get("references", [])[:5]

            ghsa_id = advisory.get("ghsa_id", "")
            cve_id = advisory.get("cve_id", ghsa_id)
            desc = advisory.get("description", "")

            vuln_data = {
                "severity": severity,
                "cvss_score": cvss_score,
                "cwe_ids": cwe_ids,
                "references": references
            }

            vuln = Vulnerability(
                id=cve_id or ghsa_id,
                title=advisory.get("summary", cve_id or ghsa_id),
                description=desc[:500] + "..." if len(desc) > 500 else desc,
                severity=severity,
                cvss_score=cvss_score,
                published_date=_normalize_date(published),
                source="GitHub Advisory",
                source_url=advisory.get("html_url", f"https://github.com/advisories/{ghsa_id}"),
                affected_products=affected_products[:10],
                remediation=generate_remediation(vuln_data, "GitHub"),
                cwe_ids=cwe_ids,
                references=references
            )
            vulnerabilities.append(vuln)

    return vulnerabilities


async def fetch_cisa_kev(days: int, client: httpx.AsyncClient) -> list[Vulnerability]:
    """
    Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog.

    The KEV catalog lists vulnerabilities that are actively exploited in the wild.
    CISA mandates that federal agencies remediate these within specified deadlines.
    All KEV entries are treated as CRITICAL severity regardless of CVSS score.

    The catalog is a single ~1 MB JSON file; we download it in full and filter
    locally by dateAdded to respect the `days` window.

    Raises exception on fetch failure so the caller records the error.
    """
    vulnerabilities = []

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = await client.get(url, timeout=30.0)

    if response.status_code == 200:
        data = response.json()
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        for vuln_data in data.get("vulnerabilities", []):
            # Filter by dateAdded (YYYY-MM-DD format used by CISA)
            date_added = vuln_data.get("dateAdded", "")
            if date_added:
                try:
                    added_date = datetime.strptime(date_added, "%Y-%m-%d")
                    if added_date < start_date:
                        continue
                except ValueError:
                    continue  # Skip malformed dates

            cve_id = vuln_data.get("cveID", "")

            # CISA does not provide CVSS scores; use a synthetic 9.0 for remediation
            # guidance only — severity is always set to CRITICAL explicitly.
            vuln_info = {
                "severity": "CRITICAL",
                "cvss_score": 9.0,
                "cwe_ids": [],
                "references": []
            }

            # Append the CISA-specific required action and due date to remediation text
            required_action = vuln_data.get("requiredAction", "Apply vendor patches.")
            due_date = vuln_data.get("dueDate", "ASAP")

            vuln = Vulnerability(
                id=cve_id,
                title=f"{cve_id}: {vuln_data.get('vulnerabilityName', '')}",
                description=vuln_data.get("shortDescription", ""),
                severity="CRITICAL",
                cvss_score=None,   # CISA does not publish CVSS scores
                published_date=_normalize_date(date_added),
                source="CISA KEV",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                affected_products=[
                    f"{vuln_data.get('vendorProject', '')} {vuln_data.get('product', '')}"
                ],
                remediation=(
                    generate_remediation(vuln_info, "CISA KEV")
                    + f" Required action: {required_action} Due date: {due_date}"
                ),
                cwe_ids=[],
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
            )
            vulnerabilities.append(vuln)

    return vulnerabilities


# ---------------------------------------------------------------------------
# Background refresh logic
# ---------------------------------------------------------------------------

async def refresh_single_source(source_name: str):
    """
    Refresh data for one source: fetch → upsert DB → update status → clear cache.

    Marks the source as 'updating' before the fetch starts so the UI can show
    a spinner while the refresh is in progress.  Records 'ok' with a timestamp
    on success, or 'error' with the exception message on failure.

    Cache is cleared on every successful refresh so the next read reflects
    the freshest data without waiting for the 15-minute TTL to expire.
    """
    await _set_source_status(source_name, "updating")
    print(f"[{datetime.utcnow().isoformat()}] Refreshing {source_name}...")

    try:
        async with httpx.AsyncClient() as client:
            if source_name == "NVD":
                vulns = await fetch_nvd_vulnerabilities(REFRESH_DAYS, client)
            elif source_name == "GitHub Advisory":
                vulns = await fetch_github_advisories(REFRESH_DAYS, client)
            elif source_name == "CISA KEV":
                vulns = await fetch_cisa_kev(REFRESH_DAYS, client)
            else:
                raise ValueError(f"Unknown source: {source_name}")

        await _upsert_vulnerabilities(vulns)
        await _set_source_status(source_name, "ok", count=len(vulns))
        cache.clear()   # Invalidate all cached query results

        print(f"[{datetime.utcnow().isoformat()}] {source_name}: {len(vulns)} records updated")

    except Exception as e:
        error_msg = str(e)[:200]
        await _set_source_status(source_name, "error", error_message=error_msg)
        print(f"[{datetime.utcnow().isoformat()}] Error refreshing {source_name}: {e}")


async def refresh_all_sources():
    """
    Refresh all three data sources concurrently.

    Called by:
      - The APScheduler hourly job
      - POST /api/sources/refresh (no body)

    Uses _refresh_lock to prevent overlapping full-refresh tasks, which could
    cause race conditions when multiple on-demand requests arrive simultaneously.
    Exceptions within individual source fetches are handled inside
    refresh_single_source and do not block the other sources.
    """
    # If a refresh is already running, skip rather than queue another
    if _refresh_lock.locked():
        print(f"[{datetime.utcnow().isoformat()}] Refresh already in progress — skipping")
        return

    async with _refresh_lock:
        print(f"[{datetime.utcnow().isoformat()}] Starting full data refresh...")
        await asyncio.gather(
            refresh_single_source("NVD"),
            refresh_single_source("GitHub Advisory"),
            refresh_single_source("CISA KEV"),
            return_exceptions=True
        )
        print(f"[{datetime.utcnow().isoformat()}] Full data refresh complete")


# ---------------------------------------------------------------------------
# Application lifespan — startup and shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager (replaces deprecated on_event handlers).

    Startup sequence:
      1. Initialise SQLite schema (safe no-op if already exists)
      2. Kick off an initial data load in the background (non-blocking)
      3. Register and start the APScheduler hourly refresh job

    Shutdown sequence:
      4. Stop the scheduler gracefully (wait=False avoids blocking SIGTERM)
    """
    # Step 1: Ensure DB tables exist
    await init_db()

    # Step 2: Non-blocking initial data load so the container starts quickly.
    # The UI will show 'pending' status until this completes (~30–60 s).
    asyncio.create_task(refresh_all_sources())

    # Step 3: Schedule hourly refresh
    scheduler.add_job(
        refresh_all_sources,
        IntervalTrigger(hours=1),
        id="hourly_refresh",
        max_instances=1,       # Never allow two overlapping scheduler runs
        misfire_grace_time=300  # Allow up to 5 min late start before skipping
    )
    scheduler.start()
    print(f"[{datetime.utcnow().isoformat()}] Scheduler started — hourly refresh active")

    yield  # Application serves requests here

    # Step 4: Graceful shutdown
    scheduler.shutdown(wait=False)
    print(f"[{datetime.utcnow().isoformat()}] Scheduler stopped")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Vulnerability Aggregator API",
    description=(
        "Aggregates security vulnerabilities from NVD, GitHub Security Advisories, "
        "and CISA KEV. Data is persisted in SQLite and refreshed hourly."
    ),
    version="2.0.0",
    lifespan=lifespan
)

# Allow cross-origin requests from the React frontend during development.
# In production, the Nginx reverse proxy handles CORS at the network edge.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Shared read helper used by both /api/vulnerabilities and /api/stats
# ---------------------------------------------------------------------------

async def _fetch_all_vulnerabilities(days: int) -> list[Vulnerability]:
    """
    Return deduplicated vulnerabilities for the last `days` days.

    Read path:
      1. Check TTL cache (key = "vulns_{days}")
      2. On miss: query SQLite, deduplicate by id, populate cache

    Deduplication: If the same CVE appears in multiple sources (e.g. NVD and
    CISA KEV both reference the same CVE-YYYY-NNNNN), only the first occurrence
    (ordered by DB insertion) is kept.
    """
    cache_key = f"vulns_{days}"
    if cache_key in cache:
        return cache[cache_key]

    vulns = await _read_vulnerabilities_from_db(days)

    # Deduplicate: preserve order, keep first occurrence per id
    seen_ids: set[str] = set()
    unique_vulns: list[Vulnerability] = []
    for vuln in vulns:
        if vuln.id not in seen_ids:
            seen_ids.add(vuln.id)
            unique_vulns.append(vuln)

    cache[cache_key] = unique_vulns
    return unique_vulns


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/vulnerabilities", response_model=VulnerabilityResponse)
async def get_vulnerabilities(
    days: int = Query(
        default=2, ge=1, le=30,
        description="Number of days to look back (1–30)"
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"
    ),
    source: Optional[str] = Query(
        default=None,
        description="Filter by source: NVD, GitHub, CISA (substring match)"
    ),
    search: Optional[str] = Query(
        default=None,
        description="Free-text search across id, title, description"
    )
):
    """
    Return a filtered, sorted list of vulnerabilities from the local database.

    Data is refreshed from external sources every hour automatically, and
    cached in-memory for 15 minutes to keep response times fast.

    Use POST /api/sources/refresh to trigger an immediate out-of-cycle refresh.
    """
    all_vulnerabilities = await _fetch_all_vulnerabilities(days)
    filtered = all_vulnerabilities

    # Severity filter: exact case-insensitive match (CRITICAL, HIGH, MEDIUM, LOW)
    if severity:
        filtered = [v for v in filtered if v.severity.upper() == severity.upper()]

    # Source filter: substring match so "CISA" matches "CISA KEV"
    if source:
        filtered = [v for v in filtered if source.lower() in v.source.lower()]

    # Free-text search across id, title, and description
    if search:
        sl = search.lower()
        filtered = [
            v for v in filtered
            if sl in v.title.lower()
            or sl in v.description.lower()
            or sl in v.id.lower()
        ]

    # Sort by CVSS score descending (highest severity first);
    # vulnerabilities with no score (None) sort to the bottom
    filtered.sort(key=lambda v: -(v.cvss_score or 0))

    return VulnerabilityResponse(
        vulnerabilities=filtered,
        total_count=len(filtered),
        sources_queried=SOURCE_NAMES,
        query_time=datetime.utcnow().isoformat(),
        days_range=days
    )


@app.get("/api/stats")
async def get_stats(
    days: int = Query(default=2, ge=1, le=30)
):
    """
    Return aggregate counts for the current dataset.

    Provides:
      - total         : total unique vulnerability count
      - by_severity   : counts broken down by CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
      - by_source     : counts broken down by data source name
      - days_range    : the look-back window applied
    """
    vulns = await _fetch_all_vulnerabilities(days)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    source_counts: dict[str, int] = {}

    for vuln in vulns:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        source_counts[vuln.source] = source_counts.get(vuln.source, 0) + 1

    return {
        "total": len(vulns),
        "by_severity": severity_counts,
        "by_source": source_counts,
        "days_range": days
    }


@app.get("/api/sources/status", response_model=SourcesStatusResponse)
async def get_sources_status():
    """
    Return freshness metadata for each data source.

    Response includes, per source:
      - last_updated   : ISO 8601 timestamp of the last successful refresh
      - status         : pending | updating | ok | error
      - count          : number of records currently stored from this source
      - error_message  : last error string (null when status != 'error')

    Also includes next_refresh: the ISO 8601 datetime of the next scheduled run.
    """
    sources = {}
    for source_name in SOURCE_NAMES:
        sources[source_name] = await _get_source_status(source_name)

    # Ask APScheduler when the next hourly job is due
    next_refresh = None
    try:
        job = scheduler.get_job("hourly_refresh")
        if job and job.next_run_time:
            next_refresh = job.next_run_time.isoformat()
    except Exception:
        pass

    return SourcesStatusResponse(sources=sources, next_refresh=next_refresh)


@app.post("/api/sources/refresh")
async def trigger_refresh(request: RefreshRequest = RefreshRequest()):
    """
    Trigger an immediate on-demand refresh of one or all data sources.

    The refresh runs in the background; this endpoint returns immediately.
    Poll GET /api/sources/status to monitor progress (status will show 'updating',
    then 'ok' or 'error' when complete).

    Request body examples:
      {}                          — refresh all three sources
      {"source": "NVD"}           — NVD only
      {"source": "GitHub Advisory"} — GitHub only
      {"source": "CISA KEV"}      — CISA KEV only

    Short aliases are also accepted (case-insensitive):
      "github" → "GitHub Advisory"
      "cisa"   → "CISA KEV"
      "nvd"    → "NVD"
    """
    # Resolve short aliases to canonical source names
    source_aliases = {
        "github": "GitHub Advisory",
        "cisa": "CISA KEV",
        "nvd": "NVD",
    }

    if request.source:
        resolved = source_aliases.get(request.source.lower(), request.source)
        if resolved not in SOURCE_NAMES:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown source '{request.source}'. Valid sources: {SOURCE_NAMES}"
            )
        # Fire-and-forget: don't await so the HTTP response returns immediately
        asyncio.create_task(refresh_single_source(resolved))
        return {
            "message": f"Refresh triggered for {resolved}",
            "status": "updating",
            "check_status_at": "/api/sources/status"
        }

    # No source specified → refresh all
    asyncio.create_task(refresh_all_sources())
    return {
        "message": "Refresh triggered for all sources",
        "status": "updating",
        "check_status_at": "/api/sources/status"
    }


@app.get("/health")
async def health_check():
    """
    Liveness probe for container orchestration health checks.

    Returns 200 OK as long as the FastAPI process is running.
    Docker Compose and Kubernetes readiness probes poll this endpoint.
    """
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# ---------------------------------------------------------------------------
# Entry point — used when running directly (not via Docker CMD)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
