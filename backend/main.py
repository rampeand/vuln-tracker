"""
Vulnerability Aggregator API
Aggregates security vulnerabilities from multiple public sources:
- NVD (National Vulnerability Database)
- GitHub Security Advisories
- CISA Known Exploited Vulnerabilities
"""

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import httpx
import asyncio
from dateutil import parser as date_parser
from cachetools import TTLCache
import re

app = FastAPI(
    title="Vulnerability Aggregator API",
    description="Aggregates security vulnerabilities from multiple sources",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cache results for 15 minutes to avoid hammering APIs
cache = TTLCache(maxsize=100, ttl=900)


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    published_date: str
    source: str
    source_url: str
    affected_products: list[str] = []
    remediation: str
    cwe_ids: list[str] = []
    references: list[str] = []


class VulnerabilityResponse(BaseModel):
    vulnerabilities: list[Vulnerability]
    total_count: int
    sources_queried: list[str]
    query_time: str
    days_range: int


def calculate_severity(cvss_score: Optional[float]) -> str:
    """Calculate severity rating from CVSS score."""
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
    """Generate remediation guidance based on vulnerability data."""
    remediation_parts = []

    # Check for vendor advisories
    if "references" in vuln_data:
        vendor_refs = [r for r in vuln_data.get("references", [])
                      if any(tag in str(r).lower() for tag in ["patch", "vendor", "advisory", "fix"])]
        if vendor_refs:
            remediation_parts.append("Check vendor advisories for official patches.")

    # General remediation based on severity
    severity = vuln_data.get("severity", "").upper()
    cvss = vuln_data.get("cvss_score")

    if cvss and cvss >= 9.0:
        remediation_parts.append("CRITICAL: Immediate patching required. Consider taking affected systems offline until patched.")
    elif cvss and cvss >= 7.0:
        remediation_parts.append("HIGH: Prioritize patching within 24-48 hours. Implement compensating controls if immediate patching is not possible.")
    elif cvss and cvss >= 4.0:
        remediation_parts.append("MEDIUM: Schedule patching within the next maintenance window. Monitor for exploitation attempts.")
    else:
        remediation_parts.append("LOW: Include in regular patch cycle. Document risk acceptance if deferring.")

    # Add source-specific guidance
    if source == "CISA KEV":
        remediation_parts.append("This vulnerability is actively exploited in the wild. Federal agencies must remediate per CISA binding operational directive.")

    # CWE-based remediation hints
    cwe_ids = vuln_data.get("cwe_ids", [])
    for cwe in cwe_ids[:2]:  # Limit to first 2
        cwe_lower = cwe.lower()
        if "injection" in cwe_lower or "79" in cwe:
            remediation_parts.append("Implement input validation and output encoding.")
        elif "buffer" in cwe_lower or "overflow" in cwe_lower:
            remediation_parts.append("Apply vendor patches and consider memory-safe alternatives.")
        elif "auth" in cwe_lower:
            remediation_parts.append("Review authentication mechanisms and implement MFA where possible.")
        elif "deserial" in cwe_lower:
            remediation_parts.append("Avoid deserializing untrusted data. Use allowlists for acceptable classes.")

    if not remediation_parts:
        remediation_parts.append("Review vendor documentation for specific remediation steps. Apply available patches and updates.")

    return " ".join(remediation_parts)


async def fetch_nvd_vulnerabilities(days: int, client: httpx.AsyncClient) -> list[Vulnerability]:
    """Fetch vulnerabilities from NVD (National Vulnerability Database)."""
    vulnerabilities = []

    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # NVD API 2.0
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

                # Get description
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                    descriptions[0].get("value", "") if descriptions else "No description available"
                )

                # Get CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
                cvss_score = None
                metrics = cve.get("metrics", {})

                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")

                # Get CWE IDs
                cwe_ids = []
                weaknesses = cve.get("weaknesses", [])
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        if desc.get("value", "").startswith("CWE-"):
                            cwe_ids.append(desc.get("value"))

                # Get affected products
                affected_products = []
                configurations = cve.get("configurations", [])
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            criteria = cpe_match.get("criteria", "")
                            if criteria:
                                # Parse CPE to extract product name
                                parts = criteria.split(":")
                                if len(parts) >= 5:
                                    vendor = parts[3]
                                    product = parts[4]
                                    affected_products.append(f"{vendor} {product}".replace("_", " ").title())

                # Get references
                references = [ref.get("url", "") for ref in cve.get("references", [])[:5]]

                # Get published date
                published = cve.get("published", "")

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

    except Exception as e:
        print(f"Error fetching NVD data: {e}")

    return vulnerabilities


async def fetch_github_advisories(days: int, client: httpx.AsyncClient) -> list[Vulnerability]:
    """Fetch vulnerabilities from GitHub Security Advisories."""
    vulnerabilities = []

    try:
        # GitHub Security Advisories API
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
                published = advisory.get("published_at", "")
                if published:
                    pub_date = date_parser.parse(published).replace(tzinfo=None)
                    if pub_date < start_date:
                        continue

                # Get severity and CVSS
                severity = advisory.get("severity", "unknown").upper()
                cvss = advisory.get("cvss", {})
                cvss_score = cvss.get("score") if cvss else None

                # Map GitHub severity to our format
                severity_map = {
                    "CRITICAL": "CRITICAL",
                    "HIGH": "HIGH",
                    "MODERATE": "MEDIUM",
                    "MEDIUM": "MEDIUM",
                    "LOW": "LOW",
                    "UNKNOWN": "UNKNOWN"
                }
                severity = severity_map.get(severity, "UNKNOWN")

                # Get affected packages
                affected_products = []
                for vuln in advisory.get("vulnerabilities", []):
                    pkg = vuln.get("package", {})
                    if pkg:
                        ecosystem = pkg.get("ecosystem", "")
                        name = pkg.get("name", "")
                        affected_products.append(f"{ecosystem}: {name}")

                # Get CWE IDs
                cwe_ids = [cwe.get("cwe_id", "") for cwe in advisory.get("cwes", [])]

                # Get references
                references = advisory.get("references", [])[:5]

                ghsa_id = advisory.get("ghsa_id", "")
                cve_id = advisory.get("cve_id", ghsa_id)

                vuln_data = {
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cwe_ids": cwe_ids,
                    "references": references
                }

                vuln = Vulnerability(
                    id=cve_id or ghsa_id,
                    title=advisory.get("summary", cve_id or ghsa_id),
                    description=advisory.get("description", "")[:500] + "..." if len(advisory.get("description", "")) > 500 else advisory.get("description", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    published_date=published,
                    source="GitHub Advisory",
                    source_url=advisory.get("html_url", f"https://github.com/advisories/{ghsa_id}"),
                    affected_products=affected_products[:10],
                    remediation=generate_remediation(vuln_data, "GitHub"),
                    cwe_ids=cwe_ids,
                    references=references
                )
                vulnerabilities.append(vuln)

    except Exception as e:
        print(f"Error fetching GitHub advisories: {e}")

    return vulnerabilities


async def fetch_cisa_kev(days: int, client: httpx.AsyncClient) -> list[Vulnerability]:
    """Fetch from CISA Known Exploited Vulnerabilities catalog."""
    vulnerabilities = []

    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        response = await client.get(url, timeout=30.0)

        if response.status_code == 200:
            data = response.json()

            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)

            for vuln_data in data.get("vulnerabilities", []):
                date_added = vuln_data.get("dateAdded", "")
                if date_added:
                    try:
                        added_date = datetime.strptime(date_added, "%Y-%m-%d")
                        if added_date < start_date:
                            continue
                    except ValueError:
                        continue

                cve_id = vuln_data.get("cveID", "")

                # CISA KEV entries are always high severity since they're actively exploited
                vuln_info = {
                    "severity": "CRITICAL",
                    "cvss_score": 9.0,  # Default high score for actively exploited
                    "cwe_ids": [],
                    "references": []
                }

                vuln = Vulnerability(
                    id=cve_id,
                    title=f"{cve_id}: {vuln_data.get('vulnerabilityName', '')}",
                    description=vuln_data.get("shortDescription", ""),
                    severity="CRITICAL",  # All KEV entries are critical by nature
                    cvss_score=None,  # CISA doesn't provide CVSS
                    published_date=date_added,
                    source="CISA KEV",
                    source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    affected_products=[f"{vuln_data.get('vendorProject', '')} {vuln_data.get('product', '')}"],
                    remediation=generate_remediation(vuln_info, "CISA KEV") + f" Required action: {vuln_data.get('requiredAction', 'Apply vendor patches.')} Due date: {vuln_data.get('dueDate', 'ASAP')}",
                    cwe_ids=[],
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
                )
                vulnerabilities.append(vuln)

    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")

    return vulnerabilities


async def fetch_all_vulnerabilities(days: int) -> list[Vulnerability]:
    """Core function to fetch and cache vulnerabilities."""
    cache_key = f"vulns_{days}"

    if cache_key in cache:
        return cache[cache_key]

    async with httpx.AsyncClient() as client:
        # Fetch from all sources concurrently
        results = await asyncio.gather(
            fetch_nvd_vulnerabilities(days, client),
            fetch_github_advisories(days, client),
            fetch_cisa_kev(days, client),
            return_exceptions=True
        )

    all_vulnerabilities = []
    for result in results:
        if isinstance(result, list):
            all_vulnerabilities.extend(result)

    # Deduplicate by CVE ID
    seen_ids = set()
    unique_vulns = []
    for vuln in all_vulnerabilities:
        if vuln.id not in seen_ids:
            seen_ids.add(vuln.id)
            unique_vulns.append(vuln)

    cache[cache_key] = unique_vulns
    return unique_vulns


@app.get("/api/vulnerabilities", response_model=VulnerabilityResponse)
async def get_vulnerabilities(
    days: int = Query(default=2, ge=1, le=30, description="Number of days to look back"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    source: Optional[str] = Query(default=None, description="Filter by source: NVD, GitHub, CISA"),
    search: Optional[str] = Query(default=None, description="Search in title/description")
):
    """
    Get aggregated vulnerabilities from multiple sources.

    - **days**: Number of days to look back (1-30, default: 2)
    - **severity**: Optional filter by severity level
    - **source**: Optional filter by data source
    - **search**: Optional search term
    """

    all_vulnerabilities = await fetch_all_vulnerabilities(days)

    # Apply filters
    filtered = all_vulnerabilities

    if severity:
        filtered = [v for v in filtered if v.severity.upper() == severity.upper()]

    if source:
        filtered = [v for v in filtered if source.lower() in v.source.lower()]

    if search:
        search_lower = search.lower()
        filtered = [v for v in filtered
                   if search_lower in v.title.lower()
                   or search_lower in v.description.lower()
                   or search_lower in v.id.lower()]

    # Sort by CVSS score (highest first), then by date
    filtered.sort(key=lambda v: (
        -(v.cvss_score or 0),
        v.published_date
    ), reverse=False)
    filtered.sort(key=lambda v: -(v.cvss_score or 0))

    return VulnerabilityResponse(
        vulnerabilities=filtered,
        total_count=len(filtered),
        sources_queried=["NVD", "GitHub Advisory", "CISA KEV"],
        query_time=datetime.utcnow().isoformat(),
        days_range=days
    )


@app.get("/api/stats")
async def get_stats(days: int = Query(default=2, ge=1, le=30)):
    """Get vulnerability statistics."""

    vulns = await fetch_all_vulnerabilities(days)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    source_counts = {}

    for vuln in vulns:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        source_counts[vuln.source] = source_counts.get(vuln.source, 0) + 1

    return {
        "total": len(vulns),
        "by_severity": severity_counts,
        "by_source": source_counts,
        "days_range": days
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
