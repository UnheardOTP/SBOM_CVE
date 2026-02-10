from fastapi import Response, Depends, status, Form
from fastapi.responses import RedirectResponse, JSONResponse
import bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature
from typing import Any

# ─── Session Management ─────────────────────────────────────────────
SECRET_KEY = os.getenv("SESSION_SECRET", "change_this_secret")
SESSION_COOKIE = "sbom_session"
serializer = URLSafeTimedSerializer(SECRET_KEY)

def create_session_cookie(user_id: int) -> str:
    return serializer.dumps({"user_id": user_id})

def get_session_user_id(request: Request) -> int | None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None
    try:
        data = serializer.loads(cookie, max_age=60*60*24*7)  # 7 days
        return data.get("user_id")
    except BadSignature:
        return None

def require_auth(request: Request) -> int:
    user_id = get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user_id

# ─── User Auth Helpers ─────────────────────────────────────────────
def get_user_by_username(username: str) -> dict | None:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def get_user_by_id(user_id: int) -> dict | None:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def set_user_password(user_id: int, new_password: str):
    conn = get_db()
    cursor = conn.cursor()
    try:
        hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("UPDATE users SET password_hash=%s, force_password_change=0 WHERE id=%s", (hash, user_id))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

# ─── Auth Endpoints ───────────────────────────────────────────────
@app.post("/api/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = get_user_by_username(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return JSONResponse(status_code=401, content={"detail": "Invalid username or password"})
    cookie = create_session_cookie(user["id"])
    resp = JSONResponse({"success": True, "force_password_change": bool(user.get("force_password_change", 0))})
    resp.set_cookie(SESSION_COOKIE, cookie, httponly=True, max_age=60*60*24*7)
    return resp

@app.post("/api/logout")
async def logout(response: Response):
    resp = JSONResponse({"success": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.post("/api/change-password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...)):
    user_id = require_auth(request)
    user = get_user_by_id(user_id)
    if not user or not bcrypt.checkpw(old_password.encode(), user["password_hash"].encode()):
        return JSONResponse(status_code=401, content={"detail": "Invalid current password"})
    set_user_password(user_id, new_password)
    return {"success": True}

@app.get("/api/me")
async def get_me(request: Request):
    user_id = get_session_user_id(request)
    if not user_id:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    user = get_user_by_id(user_id)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    return {"id": user["id"], "username": user["username"], "force_password_change": bool(user.get("force_password_change", 0))}
"""
SBOM CVE Scanner - FastAPI Backend
Queries the NVD API v2 for CVEs matching components from a SBOM.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import httpx
import asyncio
import json
import xml.etree.ElementTree as ET
import csv
import io
import os
import logging
from typing import Optional
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI(title="SBOM CVE Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Static files & templates ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(FRONTEND_DIR, "templates"))

# ─── DB Connection ────────────────────────────────────────────────────────────
def get_db():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_USER", "sbomuser"),
            password=os.getenv("DB_PASSWORD", "sbompassword"),
            database=os.getenv("DB_NAME", "sbom_cve"),
            connection_timeout=10,
        )
        return conn
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {e}")


# ─── NVD API ─────────────────────────────────────────────────────────────────
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # Optional but recommended — gets higher rate limits

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


# ─── Pydantic Models ──────────────────────────────────────────────────────────
class Component(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None   # e.g. "npm", "pypi", "maven"


class SBOMComponents(BaseModel):
    components: list[Component]
    company_name: Optional[str] = "Unknown"


# ─── SBOM Parsers ─────────────────────────────────────────────────────────────
def parse_cyclonedx_json(content: bytes) -> list[dict]:
    """Parse CycloneDX JSON SBOM format."""
    data = json.loads(content)
    components = []
    for comp in data.get("components", []):
        components.append({
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "ecosystem": comp.get("type", ""),
        })
    return components


def parse_spdx_json(content: bytes) -> list[dict]:
    """Parse SPDX JSON SBOM format."""
    data = json.loads(content)
    components = []
    for pkg in data.get("packages", []):
        components.append({
            "name": pkg.get("name", ""),
            "version": pkg.get("versionInfo", ""),
            "ecosystem": "",
        })
    return components


def parse_cyclonedx_xml(content: bytes) -> list[dict]:
    """Parse CycloneDX XML SBOM format."""
    root = ET.fromstring(content)
    ns = {"cdx": "http://cyclonedx.org/schema/bom/1.4"}
    # Try multiple namespace versions
    namespaces_to_try = [
        "http://cyclonedx.org/schema/bom/1.4",
        "http://cyclonedx.org/schema/bom/1.3",
        "http://cyclonedx.org/schema/bom/1.2",
        "",
    ]
    components = []
    for ns_uri in namespaces_to_try:
        prefix = f"{{{ns_uri}}}" if ns_uri else ""
        comps = root.findall(f".//{prefix}component")
        if comps:
            for comp in comps:
                name_el = comp.find(f"{prefix}name")
                ver_el = comp.find(f"{prefix}version")
                components.append({
                    "name": name_el.text if name_el is not None else "",
                    "version": ver_el.text if ver_el is not None else "",
                    "ecosystem": comp.get("type", ""),
                })
            break
    return components


def parse_csv_sbom(content: bytes) -> list[dict]:
    """Parse simple CSV SBOM: name, version, ecosystem (headers optional)."""
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    components = []
    for row in reader:
        # Flexible header matching
        name = row.get("name") or row.get("Name") or row.get("component") or ""
        version = row.get("version") or row.get("Version") or row.get("ver") or ""
        eco = row.get("ecosystem") or row.get("Ecosystem") or row.get("type") or ""
        if name:
            components.append({"name": name.strip(), "version": version.strip(), "ecosystem": eco.strip()})
    return components


def auto_parse_sbom(filename: str, content: bytes) -> list[dict]:
    """Detect format and parse accordingly."""
    fname = filename.lower()
    if fname.endswith(".xml"):
        return parse_cyclonedx_xml(content)
    elif fname.endswith(".csv"):
        return parse_csv_sbom(content)
    elif fname.endswith(".json") or fname.endswith(".spdx.json"):
        data = json.loads(content)
        if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
            return parse_cyclonedx_json(content)
        elif "spdxVersion" in data or "packages" in data:
            return parse_spdx_json(content)
        else:
            return parse_cyclonedx_json(content)  # Default to CycloneDX
    raise ValueError(f"Unsupported file format: {filename}")


# ─── CVE Fetching ─────────────────────────────────────────────────────────────
async def fetch_cves_for_component(client: httpx.AsyncClient, name: str, version: Optional[str]) -> list[dict]:
    """
    Query NVD API v2 for CVEs matching a component name (and optionally version).
    Returns a list of enriched CVE dicts.
    """
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Build search query - keyword search doesn't work well with versions
    # Just search by component name and filter results afterward
    search_term = name
    
    params = {
        "keywordSearch": name,  # Don't include version in keyword search
        "resultsPerPage": 100,
    }

    try:
        logger.info(f"[NVD] Querying: keywordSearch='{search_term}', resultsPerPage=100")
        logger.info(f"[NVD] Has API key: {bool(NVD_API_KEY)}, Key length: {len(NVD_API_KEY) if NVD_API_KEY else 0}")
        resp = await client.get(NVD_BASE_URL, params=params, headers=headers, timeout=15.0)
        logger.info(f"[NVD] Response status: {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        
        # Log for debugging
        total_results = data.get("totalResults", 0)
        logger.info(f"[NVD] Searched '{search_term}' → {total_results} total results from API")
        
    except Exception as e:
        logger.error(f"[NVD] Error querying for '{search_term}': {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []

    # Normalize component name for matching (lowercase, remove common prefixes)
    name_normalized = name.lower().strip()
    name_variants = [name_normalized]
    
    # Add common variations (e.g. "log4j" -> also match "apache log4j", "log4j-core")
    if "-" not in name_normalized:
        name_variants.append(f"{name_normalized}-")
    
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # ── Relevance filtering ──────────────────────────────────────────────
        # NVD keyword search already returns mostly relevant results.
        # Accept all results from the API since user did a specific keyword search.
        # The search term acts as the relevance filter.
        is_relevant = True

        # CVSS score and severity
        score = None
        severity = "UNKNOWN"
        vector = ""
        metrics = cve.get("metrics", {})

        # Try CVSSv3.1 first, then v3.0, then v2
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                vector = cvss_data.get("vectorString", "")
                break

        # Affected versions
        affected_versions = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        ver_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                        ver_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                        ver_str = ""
                        if ver_start and ver_end:
                            ver_str = f"{ver_start} – {ver_end}"
                        elif ver_start:
                            ver_str = f">= {ver_start}"
                        elif ver_end:
                            ver_str = f"<= {ver_end}"
                        if ver_str:
                            affected_versions.append(ver_str)

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        # Published / Modified
        published = cve.get("published", "")[:10]
        modified = cve.get("lastModified", "")[:10]

        results.append({
            "cve_id": cve_id,
            "component": name,
            "component_version": version or "",
            "description": desc,
            "cvss_score": score,
            "severity": severity,
            "vector_string": vector,
            "affected_versions": affected_versions,
            "references": refs,
            "published": published,
            "last_modified": modified,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    logger.info(f"[NVD] '{name}' → Found {len(results)} CVEs in response")
    return results


async def scan_components(components: list[dict]) -> list[dict]:
    """Fetch CVEs for all components concurrently with rate limiting."""
    all_cves = []
    async with httpx.AsyncClient() as client:
        # NVD free tier: ~5 req/30s without API key, 50 req/30s with key
        chunk_size = 5 if not NVD_API_KEY else 15
        delay = 6 if not NVD_API_KEY else 2

        for i in range(0, len(components), chunk_size):
            chunk = components[i:i + chunk_size]
            tasks = [
                fetch_cves_for_component(client, c["name"], c.get("version"))
                for c in chunk
            ]
            results = await asyncio.gather(*tasks)
            for cve_list in results:
                all_cves.extend(cve_list)

            if i + chunk_size < len(components):
                await asyncio.sleep(delay)

    # Sort by severity
    all_cves.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 5), -(x["cvss_score"] or 0)))
    return all_cves


# ─── DB Helpers ───────────────────────────────────────────────────────────────
def save_scan(company_name: str, components: list[dict], cves: list[dict], user_id: int) -> int:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO scans (user_id, company_name, component_count, cve_count, scan_date) VALUES (%s, %s, %s, %s, %s)",
            (user_id, company_name, len(components), len(cves), datetime.now())
        )
        scan_id = cursor.lastrowid
        for comp in components:
            cursor.execute(
                "INSERT INTO scan_components (scan_id, name, version, ecosystem) VALUES (%s, %s, %s, %s)",
                (scan_id, comp["name"], comp.get("version", ""), comp.get("ecosystem", ""))
            )
        for cve in cves:
            cursor.execute(
                """INSERT INTO scan_cves
                   (scan_id, cve_id, component, component_version, description,
                    cvss_score, severity, vector_string, affected_versions,
                    nvd_url, published, last_modified)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    scan_id,
                    cve["cve_id"],
                    cve["component"],
                    cve["component_version"],
                    cve["description"],
                    cve["cvss_score"],
                    cve["severity"],
                    cve["vector_string"],
                    json.dumps(cve["affected_versions"]),
                    cve["nvd_url"],
                    cve["published"] or None,
                    cve["last_modified"] or None,
                )
            )
        conn.commit()
        return scan_id
    finally:
        cursor.close()
        conn.close()


def get_scan_history(user_id: int, limit: int = 20) -> list[dict]:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM scans WHERE user_id = %s ORDER BY scan_date DESC LIMIT %s", (user_id, limit)
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def get_scan_detail(scan_id: int) -> dict:
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        scan = cursor.fetchone()
        if not scan:
            return None

        cursor.execute("SELECT * FROM scan_components WHERE scan_id = %s", (scan_id,))
        components = cursor.fetchall()

        cursor.execute("SELECT * FROM scan_cves WHERE scan_id = %s ORDER BY cvss_score DESC", (scan_id,))
        cves = cursor.fetchall()
        for cve in cves:
            if isinstance(cve.get("affected_versions"), str):
                cve["affected_versions"] = json.loads(cve["affected_versions"])

        return {"scan": scan, "components": components, "cves": cves}
    finally:
        cursor.close()
        conn.close()


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/scan/upload")
async def scan_upload(request: Request, file: UploadFile = File(...), company_name: str = Form("Unknown")):
    user_id = require_auth(request)
    content = await file.read()
    try:
        components = auto_parse_sbom(file.filename, content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {e}")
    if not components:
        raise HTTPException(status_code=400, detail="No components found in SBOM file.")
    cves = await scan_components(components)
    scan_id = save_scan(company_name, components, cves, user_id)
    return {
        "scan_id": scan_id,
        "company_name": company_name,
        "component_count": len(components),
        "cve_count": len(cves),
        "components": components,
        "cves": cves,
    }


@app.post("/api/scan/manual")
async def scan_manual(request: Request, payload: SBOMComponents):
    user_id = require_auth(request)
    components = [c.dict() for c in payload.components]
    if not components:
        raise HTTPException(status_code=400, detail="No components provided.")
    cves = await scan_components(components)
    logger.info(f"[SCAN] scan_components returned {len(cves)} CVEs")
    logger.info(f"[SCAN] First CVE sample: {cves[0] if cves else 'None'}")
    scan_id = save_scan(payload.company_name, components, cves, user_id)
    return {
        "scan_id": scan_id,
        "company_name": payload.company_name,
        "component_count": len(components),
        "cve_count": len(cves),
        "components": components,
        "cves": cves,
    }


@app.get("/api/scans")
async def list_scans(request: Request):
    user_id = require_auth(request)
    scans = get_scan_history(user_id)
    for s in scans:
        if isinstance(s.get("scan_date"), datetime):
            s["scan_date"] = s["scan_date"].isoformat()
    return {"scans": scans}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int, request: Request):
    user_id = require_auth(request)
    detail = get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found.")
    scan = detail["scan"]
    if scan["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if isinstance(scan.get("scan_date"), datetime):
        scan["scan_date"] = scan["scan_date"].isoformat()
    return detail
