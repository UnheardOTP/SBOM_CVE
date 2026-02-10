# SBOM CVE Scanner

A security-focused web application that scans a company's Software Bill of Materials (SBOM) against the NIST National Vulnerability Database (NVD) to identify known CVEs.

**Self-contained Docker image** — MariaDB and FastAPI run together in a single container. No external database required.

---

## Quick Start (Docker)

```bash
# 1. Unzip / enter the project directory
cd sbom-cve-app

# 2. (Optional but recommended) set your NVD API key
export NVD_API_KEY=your_key_here

# 3. Build and start
docker compose up --build
```

App is live at **http://localhost:8002**

The database is created and the schema is seeded automatically on first boot (~10-15 seconds).

### Subsequent runs

```bash
docker compose up -d          # start in background (image already built)
docker compose down           # stop - scan history persists in named volume
docker compose down -v        # stop AND wipe all scan data
docker compose logs -f        # tail logs
```

### Override the DB password

```bash
DB_PASSWORD=mysecretpassword docker compose up --build
```

---

## Features

- **SBOM Upload** - CycloneDX JSON, CycloneDX XML, SPDX JSON, CSV
- **Manual Entry** - Add individual components by name, version, and ecosystem
- **Real-time CVE Lookup** - Queries the NVD API v2 for each component
- **Rich CVE Detail** - Severity badge, CVSS score, affected version ranges, NVD links
- **Scan History** - All scans stored in MariaDB, browsable by company
- **Filtering** - Filter by severity (Critical / High / Medium / Low) or search by CVE ID / component

---

## Tech Stack

| Layer    | Technology                       |
|----------|----------------------------------|
| Backend  | Python 3.12 / FastAPI            |
| Frontend | Vanilla HTML + CSS + JS (Jinja2) |
| Database | MariaDB (bundled in container)   |
| Process  | supervisord (DB + app)           |
| CVE Data | NIST NVD API v2                  |

---

## Project Structure

```
sbom-cve-app/
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── docker/
│   ├── entrypoint.sh        # Bootstraps MariaDB on first run, starts supervisord
│   ├── supervisord.conf     # Manages MariaDB + uvicorn processes
│   └── init-db.sh
├── backend/
│   ├── main.py              # FastAPI app - routes, SBOM parsers, NVD queries
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── templates/index.html
│   └── static/
│       ├── css/style.css
│       └── js/app.js
└── docs/
    └── schema.sql           # Loaded automatically on first boot
```

---

## NVD API Key

| Mode        | Rate limit           |
|-------------|----------------------|
| No API key  | 5 requests / 30 sec  |
| With API key| 50 requests / 30 sec |

Register free at: https://nvd.nist.gov/developers/request-an-api-key

```bash
NVD_API_KEY=your_key docker compose up
```

---

## Security Notes

- No auth enabled by default - add middleware before exposing publicly
- MariaDB only listens on 127.0.0.1 inside the container (not externally accessible)
- Change DB_PASSWORD from the default for anything beyond local dev
- .env is excluded by .gitignore and .dockerignore

---

## Roadmap

- [ ] IAM
- [ ] HTTPS support
- [ ] Export results as PDF or CSV
- [ ] Email alerts for Critical CVEs
- [ ] SBOM diff - compare two scans
- [ ] CPE-based matching for precise version filtering
- [ ] Multi-stage Docker build to reduce image size
