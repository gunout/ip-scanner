#!/usr/bin/env bash
# ============================================================
#  IP EXPERT SCANNER — Rose Fluo + SVG + URLs + SSL + Crawl + Screenshot
#  Port web : 9745
#  Usage    : sudo ./CREATE.SH
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
fail() { echo -e "${RED}[!]${NC} $1"; exit 1; }

APP_PORT=9745

log "Arrêt de l'ancien déploiement..."
docker compose down -v 2>/dev/null || true
sleep 1

log "Vérification des prérequis..."
[[ $EUID -eq 0 ]] || fail "Lancez avec sudo."
command -v docker &>/dev/null || fail "Docker requis."
docker compose version &>/dev/null || fail "Docker Compose v2 requis."
command -v nmap &>/dev/null || { log "Installation nmap..."; apt-get update -qq && apt-get install -y -qq nmap; }
if ss -tlnp 2>/dev/null | grep -q ":${APP_PORT} "; then
  fail "Port ${APP_PORT} occupé."
fi
ok "Prérequis OK."

mkdir -p backend frontend screenshots
ok "Dossiers créés."

# ---------- requirements ----------
cat > backend/requirements.txt <<'EOF'
fastapi==0.115.0
uvicorn[standard]==0.32.0
celery==5.4.0
redis==5.2.0
sqlalchemy==2.0.36
psycopg2-binary==2.9.10
python-nmap==0.7.1
pydantic==2.9.2
requests==2.32.3
dnspython==2.7.0
cryptography==43.0.3
beautifulsoup4==4.12.3
playwright==1.48.0
EOF

# ---------- Dockerfile ----------
cat > backend/Dockerfile <<'EOF'
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libpangocairo-1.0-0 \
    libx11-6 libx11-xcb1 libxcb1 libxext6 libxrender1 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium \
    && playwright install-deps chromium || true
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# ---------- database.py ----------
cat > backend/database.py <<'EOF'
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

DB_URL = os.getenv("DATABASE_URL", "postgresql://scanner:scanner@db:5432/scanner")
engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
EOF

# ---------- models.py ----------
cat > backend/models.py <<'EOF'
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index, Text
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    target_type = Column(String, default="ip")
    ports = Column(String, default="1-1000")
    mode = Column(String, default="balanced")
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    results = relationship("HostResult", back_populates="job",
                           cascade="all, delete-orphan")

class HostResult(Base):
    __tablename__ = "host_results"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    ip = Column(String, index=True)
    port = Column(Integer, index=True)
    protocol = Column(String)
    service = Column(String)
    version = Column(String)
    state = Column(String)
    # URL / HTTP
    url = Column(String, nullable=True)
    http_status = Column(Integer, nullable=True)
    server_header = Column(String, nullable=True)
    title = Column(String, nullable=True)
    redirect_to = Column(String, nullable=True)
    tls_version = Column(String, nullable=True)
    # Certificat SSL
    cert_subject = Column(String, nullable=True)
    cert_issuer = Column(String, nullable=True)
    cert_valid_from = Column(String, nullable=True)
    cert_valid_until = Column(String, nullable=True)
    cert_days_left = Column(Integer, nullable=True)
    cert_expired = Column(Integer, nullable=True)  # 0/1
    cert_san = Column(Text, nullable=True)         # JSON string
    # Crawl
    links_count = Column(Integer, nullable=True)
    links_json = Column(Text, nullable=True)       # JSON string
    # Screenshot
    screenshot = Column(String, nullable=True)     # filename
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    job = relationship("ScanJob", back_populates="results")

Index("ix_host_port", HostResult.ip, HostResult.port)
EOF

# ---------- scanner.py ----------
cat > backend/scanner.py <<'EOF'
import subprocess, json, socket, nmap, re
import requests
import dns.resolver
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
from bs4 import BeautifulSoup


def detect_target_type(target: str) -> str:
    t = target.strip()
    if t.startswith(("http://", "https://")) or \
       (re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", t) and not t.replace(".", "").isdigit()):
        return "url"
    if "/" in t:
        return "cidr"
    return "ip"


def resolve_target(target: str) -> dict:
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        hostname = parsed.hostname
        scheme = parsed.scheme
        url = target
    else:
        hostname = target
        scheme = "https"
        url = f"https://{target}"

    ips = []
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        ips = [str(r) for r in answers]
    except Exception:
        try:
            ips = [socket.gethostbyname(hostname)]
        except Exception:
            ips = []
    return {"hostname": hostname, "ips": ips, "url": url, "scheme": scheme}


# ============================================================
#  SSL CERTIFICATE
# ============================================================
def scan_certificate(hostname: str, port: int = 443) -> dict:
    result = {
        "subject": None, "issuer": None,
        "valid_from": None, "valid_until": None,
        "days_left": None, "expired": None,
        "san": [], "tls_version": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["tls_version"] = ssock.version()
                der = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        result["subject"] = cert.subject.rfc4514_string()[:200]
        result["issuer"] = cert.issuer.rfc4514_string()[:200]
        result["valid_from"] = cert.not_valid_before_utc.isoformat()
        result["valid_until"] = cert.not_valid_after_utc.isoformat()
        now = datetime.now(timezone.utc)
        delta = cert.not_valid_after_utc - now
        result["days_left"] = delta.days
        result["expired"] = 1 if delta.days < 0 else 0
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result["san"] = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            result["san"] = []
    except Exception as e:
        result["error"] = str(e)
    return result


# ============================================================
#  CRAWL LINKS
# ============================================================
def crawl_links(url: str, max_links: int = 50, same_domain: bool = True) -> list:
    links = []
    try:
        headers = {"User-Agent": "IPExpertScanner/1.0"}
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        base_domain = urlparse(url).netloc
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = urljoin(url, href)
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"):
                continue
            if same_domain and parsed.netloc != base_domain:
                continue
            links.append({
                "url": full,
                "text": a.get_text(strip=True)[:80],
                "domain": parsed.netloc,
            })
            if len(links) >= max_links:
                break
    except Exception as e:
        return [{"error": str(e)}]
    return links


# ============================================================
#  SCREENSHOT
# ============================================================
def capture_screenshot(url: str, filename: str) -> str | None:
    """Capture URL en PNG. Retourne le filename ou None."""
    import os
    SCREENSHOT_DIR = "/app/screenshots"
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    path = os.path.join(SCREENSHOT_DIR, filename)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, wait_until="networkidle", timeout=30000)
            page.screenshot(path=path, full_page=True)
            browser.close()
        return filename
    except Exception as e:
        print(f"Screenshot error: {e}")
        return None


# ============================================================
#  HTTP + SSL + CRAWL + SCREENSHOT (orchestré)
# ============================================================
def scan_url_full(url: str, ip: str = None, job_id: int = None, do_crawl=True, do_screenshot=True) -> dict:
    result = {
        "url": url, "http_status": None, "server_header": None,
        "title": None, "redirect_to": None, "tls_version": None,
        "cert_subject": None, "cert_issuer": None,
        "cert_valid_from": None, "cert_valid_until": None,
        "cert_days_left": None, "cert_expired": None, "cert_san": None,
        "links_count": None, "links_json": None, "screenshot": None,
    }
    headers = {"User-Agent": "IPExpertScanner/1.0"}

    # HTTP
    try:
        r = requests.get(url, headers=headers, timeout=8, allow_redirects=False, verify=False)
        result["http_status"] = r.status_code
        result["server_header"] = r.headers.get("Server", "")[:120]
        if r.is_redirect:
            result["redirect_to"] = r.headers.get("Location", "")[:200]
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:5000], re.IGNORECASE | re.DOTALL)
        if m:
            result["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:150]
    except requests.exceptions.SSLError:
        result["server_header"] = "SSL_ERROR"
    except requests.exceptions.ConnectionError:
        result["server_header"] = "CONNECTION_ERROR"
    except requests.exceptions.Timeout:
        result["server_header"] = "TIMEOUT"
    except Exception as e:
        result["server_header"] = f"ERROR: {type(e).__name__}"

    # SSL cert
    hostname = urlparse(url).hostname
    if url.startswith("https://") and hostname:
        cert = scan_certificate(hostname, 443)
        result["tls_version"] = cert.get("tls_version")
        result["cert_subject"] = cert.get("subject")
        result["cert_issuer"] = cert.get("issuer")
        result["cert_valid_from"] = cert.get("valid_from")
        result["cert_valid_until"] = cert.get("valid_until")
        result["cert_days_left"] = cert.get("days_left")
        result["cert_expired"] = cert.get("expired")
        result["cert_san"] = json.dumps(cert.get("san", []))[:2000]

    # Crawl
    if do_crawl:
        links = crawl_links(url, max_links=50)
        result["links_count"] = len(links)
        result["links_json"] = json.dumps(links)[:8000]

    # Screenshot
    if do_screenshot and job_id:
        fname = f"job{job_id}_{re.sub(r'[^a-zA-Z0-9]', '_', (ip or hostname or 'x'))[:20]}.png"
        shot = capture_screenshot(url, fname)
        result["screenshot"] = shot

    return result


# ============================================================
#  MASSCAN + NMAP (inchangé)
# ============================================================
def masscan_discover(target, ports="1-65535", rate=1000):
    cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}", "--open-only", "-oJ", "-"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return []
    open_ports = []
    for line in result.stdout.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
            ip = entry.get("ip")
            for p in entry.get("ports", []):
                if p.get("status") == "open":
                    open_ports.append((ip, p["port"]))
        except json.JSONDecodeError:
            continue
    return open_ports

def nmap_fingerprint(open_ports):
    if not open_ports:
        return []
    by_ip = {}
    for ip, port in open_ports:
        by_ip.setdefault(ip, []).append(port)
    results = []
    nm = nmap.PortScanner()
    for ip, ports in by_ip.items():
        port_str = ",".join(str(p) for p in sorted(set(ports)))
        try:
            nm.scan(hosts=ip, ports=port_str, arguments="-sV -T4")
        except Exception:
            continue
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto].keys():
                info = nm[ip][proto][port]
                results.append({
                    "ip": ip, "port": port, "protocol": proto,
                    "service": info.get("name", "unknown"),
                    "version": f"{info.get('product','')} {info.get('version','')}".strip(),
                    "state": info.get("state", "open"),
                })
    return results

def probe_unknown(ip, port):
    probes = {
        "http": b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
        "ssh":  b"SSH-2.0-Probe\r\n",
        "smtp": b"EHLO probe\r\n",
        "ftp":  b"USER anonymous\r\n",
    }
    for name, payload in probes.items():
        try:
            with socket.create_connection((ip, port), timeout=2) as s:
                s.sendall(payload)
                data = s.recv(256)
                if name == "http" and b"HTTP/" in data: return "http"
                if name == "ssh" and b"SSH-" in data:   return "ssh"
                if name == "smtp" and b"220" in data:   return "smtp"
                if name == "ftp" and b"220" in data:    return "ftp"
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return "unknown"


# ============================================================
#  ORCHESTRATEUR
# ============================================================
def scan_target(target, ports="1-1000", mode="balanced", prior_ips=None, job_id=None):
    ttype = detect_target_type(target)

    # ---------- URL ----------
    if ttype == "url":
        info = resolve_target(target)
        if not info["ips"]:
            return [{
                "ip": "0.0.0.0", "port": 0, "protocol": "tcp",
                "service": "dns_error", "version": "", "state": "error",
                "url": target, "http_status": None, "server_header": None,
                "title": None, "redirect_to": None, "tls_version": None,
                "cert_subject": None, "cert_issuer": None, "cert_valid_from": None,
                "cert_valid_until": None, "cert_days_left": None, "cert_expired": None,
                "cert_san": None, "links_count": None, "links_json": None,
                "screenshot": None,
            }]

        results = []
        for ip in info["ips"][:3]:
            full = scan_url_full(info["url"], ip=ip, job_id=job_id,
                                 do_crawl=True, do_screenshot=True)
            full.update({
                "ip": ip,
                "port": 443 if info["scheme"] == "https" else 80,
                "protocol": "tcp",
                "service": info["scheme"],
                "version": full.get("tls_version") or "",
                "state": "open",
            })
            results.append(full)

            # Scan ports web rapides
            web_ports = "80,443,8080,8443,3000,5000,8000"
            open_ports = masscan_discover(ip, web_ports, rate=500)
            if open_ports:
                fp = nmap_fingerprint(open_ports)
                for r in fp:
                    r.update({
                        "url": info["url"], "http_status": None,
                        "server_header": None, "title": None,
                        "redirect_to": None, "tls_version": None,
                        "cert_subject": None, "cert_issuer": None,
                        "cert_valid_from": None, "cert_valid_until": None,
                        "cert_days_left": None, "cert_expired": None,
                        "cert_san": None, "links_count": None,
                        "links_json": None, "screenshot": None,
                    })
                    results.append(r)
        return results

    # ---------- IP / CIDR ----------
    base_keys = {
        "url": None, "http_status": None, "server_header": None,
        "title": None, "redirect_to": None, "tls_version": None,
        "cert_subject": None, "cert_issuer": None, "cert_valid_from": None,
        "cert_valid_until": None, "cert_days_left": None, "cert_expired": None,
        "cert_san": None, "links_count": None, "links_json": None,
        "screenshot": None,
    }

    if mode == "fast":
        return [{**base_keys, "ip": ip, "port": p, "protocol": "tcp",
                 "service": "unknown", "version": "", "state": "open"}
                for ip, p in masscan_discover(target, ports, rate=2000)]

    if mode == "deep":
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments="-sV -T4 --open")
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info = nm[host][proto][port]
                    results.append({**base_keys,
                        "ip": host, "port": port, "protocol": proto,
                        "service": info.get("name", "unknown"),
                        "version": f"{info.get('product','')} {info.get('version','')}".strip(),
                        "state": info.get("state", "open"),
                    })
        return results

    rate = 1000 if mode == "balanced" else 3000
    open_ports = masscan_discover(target, ports, rate=rate)
    results = nmap_fingerprint(open_ports)
    for r in results:
        if r["service"] in ("unknown", "tcpwrapped", ""):
            detected = probe_unknown(r["ip"], r["port"])
            if detected != "unknown":
                r["service"] = detected
        r.update(base_keys)
    return results
EOF

# ---------- tasks.py ----------
cat > backend/tasks.py <<'EOF'
from celery import Celery
from scanner import scan_target, detect_target_type
from database import SessionLocal
from models import ScanJob, HostResult
from datetime import datetime, timedelta
import os

celery_app = Celery("scanner",
    broker=os.getenv("REDIS_URL", "redis://redis:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://redis:6379/0"))

def get_prior_ips(db):
    cutoff = datetime.utcnow() - timedelta(days=7)
    rows = (db.query(HostResult.ip)
              .filter(HostResult.last_seen > cutoff)
              .filter(HostResult.state == "open")
              .distinct().all())
    return [r[0] for r in rows]

@celery_app.task
def run_scan(job_id):
    db = SessionLocal()
    job = db.query(ScanJob).get(job_id)
    job.status = "running"; db.commit()
    try:
        prior = get_prior_ips(db) if job.mode == "smart" else None
        results = scan_target(job.target, job.ports, mode=job.mode,
                              prior_ips=prior, job_id=job.id)
        now = datetime.utcnow()
        for r in results:
            db.add(HostResult(job_id=job.id, last_seen=now, **r))
        job.status = "done"
    except Exception as e:
        job.status = "error"; print("Erreur:", e)
    finally:
        db.commit(); db.close()
EOF

# ---------- main.py ----------
cat > backend/main.py <<'EOF'
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from database import SessionLocal, engine
from models import Base, ScanJob, HostResult
from tasks import run_scan
from scanner import detect_target_type
import os

Base.metadata.create_all(bind=engine)
app = FastAPI(title="IP Expert Scanner")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    mode: str = "balanced"

@app.post("/api/scan")
def create_scan(req: ScanRequest):
    ttype = detect_target_type(req.target)
    mode = "url" if ttype == "url" else req.mode
    if mode not in ("fast", "balanced", "deep", "smart", "url"):
        raise HTTPException(400, "Mode invalide")
    db = SessionLocal()
    job = ScanJob(target=req.target, target_type=ttype, ports=req.ports, mode=mode)
    db.add(job); db.commit(); db.refresh(job)
    run_scan.delay(job.id)
    db.close()
    return {"job_id": job.id, "status": "pending",
            "mode": mode, "target_type": ttype}

@app.get("/api/jobs/{job_id}")
def get_job(job_id: int):
    db = SessionLocal()
    job = db.query(ScanJob).get(job_id)
    if not job: raise HTTPException(404, "Job introuvable")
    results = []
    for r in job.results:
        results.append({
            "ip": r.ip, "port": r.port, "service": r.service,
            "version": r.version, "state": r.state,
            "url": r.url, "http_status": r.http_status,
            "server_header": r.server_header, "title": r.title,
            "redirect_to": r.redirect_to, "tls_version": r.tls_version,
            "cert_subject": r.cert_subject, "cert_issuer": r.cert_issuer,
            "cert_valid_from": r.cert_valid_from,
            "cert_valid_until": r.cert_valid_until,
            "cert_days_left": r.cert_days_left, "cert_expired": r.cert_expired,
            "cert_san": r.cert_san,
            "links_count": r.links_count, "links_json": r.links_json,
            "screenshot": r.screenshot,
        })
    db.close()
    return {"id": job.id, "status": job.status,
            "target": job.target, "target_type": job.target_type,
            "mode": job.mode, "results": results}

# Sert les screenshots
if os.path.isdir("/app/screenshots"):
    app.mount("/screenshots", StaticFiles(directory="/app/screenshots"), name="screenshots")

if os.path.isdir("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
EOF

# ---------- docker-compose.yml ----------
cat > docker-compose.yml <<EOF
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: scanner
      POSTGRES_PASSWORD: scanner
      POSTGRES_DB: scanner
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U scanner"]
      interval: 5s
      retries: 5
  redis:
    image: redis:7
    ports: ["127.0.0.1:6379:6379"]
  api:
    build: ./backend
    ports: ["${APP_PORT}:8000"]
    volumes:
      - ./frontend:/app/static:ro
      - ./screenshots:/app/screenshots
    depends_on:
      db: {condition: service_healthy}
      redis: {condition: service_started}
    environment:
      DATABASE_URL: postgresql://scanner:scanner@db:5432/scanner
      REDIS_URL: redis://redis:6379/0
  worker:
    build: ./backend
    command: celery -A tasks worker --loglevel=info --concurrency=2
    cap_add: [NET_RAW, NET_ADMIN]
    shm_size: "2gb"
    volumes:
      - ./screenshots:/app/screenshots
    depends_on:
      db: {condition: service_healthy}
      redis: {condition: service_started}
    environment:
      DATABASE_URL: postgresql://scanner:scanner@db:5432/scanner
      REDIS_URL: redis://redis:6379/0
volumes:
  pgdata:
EOF

# ---------- FRONTEND ----------
cat > frontend/index.html <<'HTML'
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP EXPERT // Scanner — Rose Fluo</title>
<style>
  :root{
    --bg:#0d0221; --panel:#150a2e; --line:#3a1a5c;
    --pink:#ff2d95; --pink2:#ff006e; --pink3:#ff66b3;
    --ok:#00ff9d; --warn:#ffb800; --cyan:#00f0ff;
    --txt:#f0e6ff; --dim:#8a6ba8;
    --mono:'Roboto Mono',ui-monospace,monospace;
    --sans:'Inter',system-ui,sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{background:var(--bg);color:var(--txt);font-family:var(--sans);overflow-x:hidden;min-height:100vh}
  .bg-svg{position:fixed;inset:0;z-index:0;pointer-events:none;width:100%;height:100%}
  body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
    background:radial-gradient(circle at 50% 0%,rgba(255,45,149,.16),transparent 55%)}
  .wrap{position:relative;z-index:1;max-width:1400px;margin:0 auto;padding:32px 24px 80px}
  header{display:flex;align-items:center;justify-content:space-between;margin-bottom:48px;flex-wrap:wrap;gap:16px}
  .logo{display:flex;align-items:center;gap:14px}
  .logo-mark{width:56px;height:56px;display:grid;place-items:center}
  .logo-mark svg{width:56px;height:56px;filter:drop-shadow(0 0 14px rgba(255,45,149,.7))}
  .logo h1{font-family:var(--mono);font-size:20px;letter-spacing:3px;color:#fff;text-shadow:0 0 20px rgba(255,45,149,.7)}
  .logo h1 span{color:var(--pink);text-shadow:0 0 30px var(--pink),0 0 60px var(--pink2)}
  .status-badge{font-family:var(--mono);font-size:11px;letter-spacing:2px;padding:8px 14px 8px 10px;
    border:1px solid var(--pink);border-radius:20px;display:flex;align-items:center;gap:8px;
    color:var(--pink3);background:rgba(255,45,149,.06);box-shadow:0 0 20px rgba(255,45,149,.2)}
  .status-badge svg{width:14px;height:14px}
  .console{background:linear-gradient(180deg,rgba(21,10,46,.92),rgba(21,10,46,.6));
    border:1px solid var(--line);border-radius:16px;padding:24px;backdrop-filter:blur(10px);
    box-shadow:0 0 50px rgba(255,45,149,.12);margin-bottom:28px;position:relative;overflow:hidden}
  .scanline-svg{position:absolute;top:0;left:0;width:100%;height:3px;pointer-events:none}
  .console-title{font-family:var(--mono);font-size:11px;letter-spacing:3px;color:var(--pink3);
    margin-bottom:18px;display:flex;align-items:center;gap:10px;text-shadow:0 0 12px rgba(255,45,149,.5)}
  .console-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(255,45,149,.5),transparent)}
  .input-row{display:flex;gap:14px;flex-wrap:wrap}
  .field{flex:1;min-width:180px;position:relative}
  .field label{position:absolute;top:-9px;left:14px;padding:0 6px;background:var(--panel);
    font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--pink);text-transform:uppercase}
  .field input,.field select{width:100%;padding:16px 14px;background:rgba(13,2,33,.9);
    border:1px solid var(--line);border-radius:10px;color:#fff;font-family:var(--mono);font-size:14px;transition:all .25s}
  .field input:focus,.field select:focus{outline:none;border-color:var(--pink);
    box-shadow:0 0 0 1px var(--pink),0 0 30px rgba(255,45,149,.45)}
  .field input::placeholder{color:var(--dim)}
  .btn-scan{padding:16px 34px;border:none;border-radius:10px;cursor:pointer;
    font-family:var(--mono);font-size:13px;letter-spacing:3px;font-weight:700;color:#fff;
    background:linear-gradient(135deg,var(--pink),var(--pink2));
    box-shadow:0 0 30px rgba(255,45,149,.7);transition:all .2s;
    display:flex;align-items:center;gap:10px;justify-content:center}
  .btn-scan svg{width:16px;height:16px}
  .btn-scan:hover{transform:translateY(-2px);box-shadow:0 0 50px rgba(255,45,149,1)}
  .btn-scan:disabled{opacity:.5;cursor:not-allowed;transform:none}
  .progress{height:3px;background:var(--line);border-radius:2px;margin-top:20px;overflow:hidden;display:none}
  .progress.active{display:block}
  .progress-bar{height:100%;width:0;
    background:linear-gradient(90deg,var(--pink3),var(--pink),var(--pink2));
    transition:width .3s;box-shadow:0 0 16px var(--pink)}
  .status-line{font-family:var(--mono);font-size:12px;letter-spacing:1px;color:var(--dim);margin-top:14px;min-height:18px}
  .status-line .ok{color:var(--ok)} .status-line .err{color:var(--pink2)}
  .hint{font-family:var(--mono);font-size:10px;color:var(--dim);margin-top:10px;letter-spacing:1px}
  .hint code{color:var(--pink3);background:rgba(255,45,149,.08);padding:2px 6px;border-radius:4px}
  .results-panel{background:rgba(21,10,46,.75);border:1px solid var(--line);
    border-radius:16px;overflow:hidden;backdrop-filter:blur(10px);display:none;
    box-shadow:0 0 40px rgba(255,45,149,.1)}
  .results-panel.show{display:block;animation:fadeIn .4s ease}
  @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
  .results-head{display:flex;justify-content:space-between;align-items:center;padding:18px 24px;
    border-bottom:1px solid var(--line);font-family:var(--mono);font-size:12px;letter-spacing:2px;
    color:var(--pink);text-shadow:0 0 12px rgba(255,45,149,.6)}
  .results-head .count{color:var(--dim)}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{text-align:left;padding:12px 10px;font-family:var(--mono);font-size:10px;letter-spacing:1px;
    color:var(--pink3);text-transform:uppercase;background:rgba(13,2,33,.7);
    border-bottom:1px solid var(--line)}
  td{padding:12px 10px;border-bottom:1px solid rgba(58,26,92,.5);font-family:var(--mono);vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(255,45,149,.06)}
  .ip{color:var(--pink);font-weight:600;text-shadow:0 0 10px rgba(255,45,149,.5)}
  .port{color:var(--warn)}
  .svc{color:#fff}
  .ver{color:var(--dim);font-size:11px}
  .state{color:var(--ok);font-size:11px}
  .state .pill{padding:3px 10px;border-radius:20px;background:rgba(0,255,157,.1);
    border:1px solid rgba(0,255,157,.4);box-shadow:0 0 10px rgba(0,255,157,.2)}
  .url-cell{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--cyan);font-size:11px}
  .http-status{font-weight:700}
  .http-2xx{color:var(--ok)} .http-3xx{color:var(--warn)}
  .http-4xx{color:var(--pink2)} .http-5xx{color:var(--pink2)}
  .title-cell{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#fff;font-size:11px}
  .server-cell{color:var(--dim);font-size:10px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tls-cell{color:var(--cyan);font-size:10px}
  .cert-days{font-size:11px;font-weight:700}
  .cert-ok{color:var(--ok)} .cert-warn{color:var(--warn)} .cert-err{color:var(--pink2)}
  .cert-san{font-size:10px;color:var(--dim);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .links-badge{display:inline-block;padding:2px 8px;border-radius:10px;
    background:rgba(0,240,255,.1);border:1px solid rgba(0,240,255,.3);color:var(--cyan);
    font-size:10px;cursor:pointer;text-decoration:none}
  .links-badge:hover{background:rgba(0,240,255,.2)}
  .shot-thumb{width:60px;height:40px;object-fit:cover;border-radius:6px;
    border:1px solid var(--pink);box-shadow:0 0 10px rgba(255,45,149,.4);cursor:pointer}
  .shot-thumb:hover{transform:scale(1.1)}
  .empty{padding:60px 24px;text-align:center;font-family:var(--mono);color:var(--dim);font-size:13px}
  .empty .big{font-size:40px;margin-bottom:16px;opacity:.5;text-shadow:0 0 30px var(--pink)}
  .radar-spinner{width:32px;height:32px;display:none;margin:0 auto 12px}
  footer{margin-top:60px;text-align:center;font-family:var(--mono);font-size:11px;letter-spacing:2px;color:var(--dim)}
  footer .warn{color:var(--warn)}
  /* Modale */
  .modal{display:none;position:fixed;inset:0;z-index:100;background:rgba(13,2,33,.92);
    backdrop-filter:blur(8px);align-items:center;justify-content:center;padding:24px}
  .modal.show{display:flex;animation:fadeIn .3s}
  .modal-content{background:var(--panel);border:1px solid var(--pink);border-radius:16px;
    max-width:90vw;max-height:90vh;overflow:auto;padding:24px;box-shadow:0 0 60px rgba(255,45,149,.5)}
  .modal-content h3{font-family:var(--mono);color:var(--pink);margin-bottom:16px;letter-spacing:2px}
  .modal-content img{max-width:100%;border-radius:8px}
  .modal-content ul{font-family:var(--mono);font-size:12px;color:var(--txt);line-height:1.8;
    max-height:60vh;overflow:auto;padding-left:20px}
  .modal-content li a{color:var(--cyan);text-decoration:none;word-break:break-all}
  .modal-content li a:hover{text-decoration:underline}
  .modal-close{position:absolute;top:20px;right:24px;background:none;border:1px solid var(--pink);
    color:var(--pink);font-size:20px;width:40px;height:40px;border-radius:50%;cursor:pointer;
    display:grid;place-items:center}
  .modal-close:hover{background:var(--pink);color:#fff}
  @media(max-width:900px){ table{font-size:10px} th,td{padding:8px 6px} }
</style>
</head>
<body>

<svg class="bg-svg" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,45,149,.07)" stroke-width="1"/>
    </pattern>
    <radialGradient id="halo" cx="50%" cy="0%" r="70%">
      <stop offset="0%" stop-color="#ff2d95" stop-opacity=".15"/>
      <stop offset="100%" stop-color="#ff2d95" stop-opacity="0"/>
    </radialGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  <rect width="1440" height="900" fill="url(#halo)"/>
  <rect width="1440" height="900" fill="url(#grid-pattern)"/>
  <g filter="url(#glow)" opacity=".25">
    <circle cx="720" cy="450" r="80" fill="none" stroke="#ff2d95" stroke-width="1">
      <animate attributeName="r" values="80;400" dur="6s" repeatCount="indefinite"/>
      <animate attributeName="opacity" values=".6;0" dur="6s" repeatCount="indefinite"/>
    </circle>
    <circle cx="720" cy="450" r="80" fill="none" stroke="#ff006e" stroke-width="1">
      <animate attributeName="r" values="80;400" dur="6s" begin="2s" repeatCount="indefinite"/>
      <animate attributeName="opacity" values=".6;0" dur="6s" begin="2s" repeatCount="indefinite"/>
    </circle>
  </g>
  <g fill="#ff2d95" filter="url(#glow)">
    <circle cx="120" cy="200" r="2"><animate attributeName="cy" values="200;100;200" dur="8s" repeatCount="indefinite"/><animate attributeName="opacity" values=".3;1;.3" dur="8s" repeatCount="indefinite"/></circle>
    <circle cx="980" cy="300" r="2.5"><animate attributeName="cy" values="300;180;300" dur="7s" repeatCount="indefinite"/><animate attributeName="opacity" values=".4;1;.4" dur="7s" repeatCount="indefinite"/></circle>
    <circle cx="600" cy="120" r="2"><animate attributeName="cy" values="120;40;120" dur="11s" repeatCount="indefinite"/><animate attributeName="opacity" values=".2;1;.2" dur="11s" repeatCount="indefinite"/></circle>
  </g>
</svg>

<div class="wrap">
  <header>
    <div class="logo">
      <div class="logo-mark">
        <svg viewBox="0 0 56 56" xmlns="http://www.w3.org/2000/svg">
          <rect x="2" y="2" width="52" height="52" rx="12" fill="none" stroke="#ff2d95" stroke-width="2">
            <animate attributeName="stroke-opacity" values="1;.4;1" dur="2.5s" repeatCount="indefinite"/>
          </rect>
          <circle cx="28" cy="28" r="14" fill="none" stroke="#ff2d95" stroke-width="1" opacity=".4"/>
          <line x1="28" y1="28" x2="28" y2="14" stroke="#ff2d95" stroke-width="2" stroke-linecap="round">
            <animateTransform attributeName="transform" type="rotate" from="0 28 28" to="360 28 28" dur="2s" repeatCount="indefinite"/>
          </line>
          <circle cx="28" cy="28" r="3" fill="#ff2d95"><animate attributeName="r" values="3;5;3" dur="1.5s" repeatCount="indefinite"/></circle>
        </svg>
      </div>
      <h1>IP <span>EXPERT</span> // SCANNER</h1>
    </div>
    <div class="status-badge">
      <svg viewBox="0 0 14 14" xmlns="http://www.w3.org/2000/svg">
        <circle cx="7" cy="7" r="3" fill="#00ff9d"><animate attributeName="r" values="3;5;3" dur="1.6s" repeatCount="indefinite"/></circle>
      </svg>
      SYSTÈME EN LIGNE
    </div>
  </header>

  <section class="console">
    <svg class="scanline-svg" viewBox="0 0 1000 3" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
      <defs><linearGradient id="scan-grad" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#ff2d95" stop-opacity="0"/>
        <stop offset="50%" stop-color="#ff2d95" stop-opacity="1"/>
        <stop offset="100%" stop-color="#ff2d95" stop-opacity="0"/>
      </linearGradient></defs>
      <rect x="0" y="0" width="200" height="3" fill="url(#scan-grad)">
        <animate attributeName="x" values="-200;1000" dur="3s" repeatCount="indefinite"/>
      </rect>
    </svg>

    <div class="console-title">◆ TERMINAL DE RECONNAISSANCE</div>
    <div class="input-row">
      <div class="field">
        <label>Cible (IP, CIDR ou URL)</label>
        <input id="target" placeholder="https://example.com ou 192.168.1.0/24" value="" spellcheck="false">
      </div>
      <div class="field" style="max-width:140px">
        <label>Ports</label>
        <input id="ports" placeholder="1-1000" value="1-1000" spellcheck="false">
      </div>
      <div class="field" style="max-width:180px">
        <label>Mode</label>
        <select id="mode">
          <option value="fast">⚡ Fast</option>
          <option value="balanced" selected>⚖ Balanced</option>
          <option value="deep">🔬 Deep</option>
          <option value="smart">🧠 Smart</option>
          <option value="url">🌐 URL</option>
        </select>
      </div>
      <button id="scanBtn" class="btn-scan">
        <svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2" fill="currentColor"/>
        </svg>
        SCAN
      </button>
    </div>
    <div class="hint">💡 <code>https://example.com</code> → DNS + HTTP + SSL + crawl + screenshot · <code>192.168.1.0/24</code> → réseau · <code>1.2.3.4</code> → IP</div>

    <div class="progress" id="progress"><div class="progress-bar" id="progressBar"></div></div>
    <svg class="radar-spinner" id="radarSpinner" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <circle cx="16" cy="16" r="14" fill="none" stroke="#ff2d95" stroke-width="1" opacity=".3"/>
      <line x1="16" y1="16" x2="16" y2="4" stroke="#ff2d95" stroke-width="2" stroke-linecap="round">
        <animateTransform attributeName="transform" type="rotate" from="0 16 16" to="360 16 16" dur="1.2s" repeatCount="indefinite"/>
      </line>
      <circle cx="16" cy="16" r="2" fill="#ff2d95"/>
    </svg>
    <div class="status-line" id="statusLine">En attente d'une cible…</div>
  </section>

  <section class="results-panel" id="resultsPanel">
    <div class="results-head">
      <span>▸ RÉSULTATS DU SCAN</span>
      <span class="count" id="resultCount"></span>
    </div>
    <div id="resultsBody"><div class="empty"><div class="big">◇</div>Aucun résultat pour le moment</div></div>
  </section>

  <footer><span class="warn">⚠</span> Ne scannez que les réseaux dont vous avez l'autorisation explicite.</footer>
</div>

<!-- Modale -->
<div class="modal" id="modal">
  <div class="modal-content" style="position:relative">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <div id="modalBody"></div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const API = '';

function closeModal(){ $('modal').classList.remove('show'); }
$('modal').addEventListener('click', e => { if(e.target === $('modal')) closeModal(); });

async function lancerScan(){
  const target = $('target').value.trim();
  const ports  = $('ports').value.trim();
  const mode   = $('mode').value;
  if(!target) return;

  const btn = $('scanBtn');
  btn.disabled = true;
  $('resultsPanel').classList.remove('show');
  $('progress').classList.add('active');
  $('radarSpinner').style.display = 'block';
  $('progressBar').style.width = '10%';
  $('statusLine').innerHTML = '◇ Mode <b>' + mode + '</b> — connexion…';

  try{
    const r = await fetch(API + '/api/scan', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target, ports, mode})
    });
    if(!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const job_id = data.job_id;
    $('progressBar').style.width = '25%';
    $('statusLine').innerHTML = '◇ Scan <b>' + data.mode + '</b> (' + data.target_type + ') sur <b>' + target + '</b>…';

    let progress = 25;
    const interval = setInterval(async () => {
      try{
        const jr = await fetch(API + '/api/jobs/' + job_id);
        const job = await jr.json();
        progress = Math.min(progress + 5, 92);
        $('progressBar').style.width = progress + '%';
        if(job.status === 'done'){
          clearInterval(interval);
          $('progressBar').style.width = '100%';
          setTimeout(() => { $('progress').classList.remove('active'); $('radarSpinner').style.display = 'none'; }, 400);
          afficherResultats(job.results, job.target_type, job_id);
          $('statusLine').innerHTML = '<span class="ok">✓ Scan terminé</span> — ' + job.results.length + ' résultat(s)';
          btn.disabled = false;
        } else if(job.status === 'error'){
          clearInterval(interval);
          $('progress').classList.remove('active'); $('radarSpinner').style.display = 'none';
          $('statusLine').innerHTML = '<span class="err">✗ Erreur lors du scan.</span>';
          btn.disabled = false;
        }
      }catch(e){
        clearInterval(interval);
        $('progress').classList.remove('active'); $('radarSpinner').style.display = 'none';
        $('statusLine').innerHTML = '<span class="err">✗ Connexion perdue.</span>';
        btn.disabled = false;
      }
    }, 2000);
  }catch(e){
    $('progress').classList.remove('active'); $('radarSpinner').style.display = 'none';
    $('statusLine').innerHTML = '<span class="err">✗ ' + e.message + '</span>';
    btn.disabled = false;
  }
}

function httpClass(code){
  if(!code) return '';
  if(code >= 200 && code < 300) return 'http-2xx';
  if(code >= 300 && code < 400) return 'http-3xx';
  if(code >= 400 && code < 500) return 'http-4xx';
  if(code >= 500) return 'http-5xx';
  return '';
}
function certClass(days){
  if(days === null || days === undefined) return '';
  if(days < 0) return 'cert-err';
  if(days < 30) return 'cert-warn';
  return 'cert-ok';
}

function showLinks(json){
  let links = [];
  try { links = JSON.parse(json || '[]'); } catch(e){}
  const html = links.length ?
    '<ul>' + links.map(l => `<li><a href="${l.url}" target="_blank">${l.url}</a>${l.text ? ' — ' + l.text : ''}</li>`).join('') + '</ul>' :
    '<p style="color:var(--dim)">Aucun lien trouvé</p>';
  $('modalBody').innerHTML = '<h3>🕷️ Liens trouvés (' + links.length + ')</h3>' + html;
  $('modal').classList.add('show');
}
function showScreenshot(filename){
  $('modalBody').innerHTML = '<h3>📸 Capture d\'écran</h3><img src="/screenshots/' + filename + '" alt="screenshot">';
  $('modal').classList.add('show');
}
function showCert(row){
  $('modalBody').innerHTML = `
    <h3>🔒 Certificat SSL</h3>
    <table style="font-size:13px">
      <tr><td style="color:var(--dim)">Sujet</td><td>${row.cert_subject || '—'}</td></tr>
      <tr><td style="color:var(--dim)">Émetteur</td><td>${row.cert_issuer || '—'}</td></tr>
      <tr><td style="color:var(--dim)">Valide du</td><td>${row.cert_valid_from || '—'}</td></tr>
      <tr><td style="color:var(--dim)">Valide au</td><td>${row.cert_valid_until || '—'}</td></tr>
      <tr><td style="color:var(--dim)">Expire dans</td><td>${row.cert_days_left !== null ? row.cert_days_left + ' jours' : '—'}</td></tr>
      <tr><td style="color:var(--dim)">SAN</td><td>${(row.cert_san || '[]').replace(/[\[\]"]/g, '').replace(/,/g, ', ')}</td></tr>
    </table>`;
  $('modal').classList.add('show');
}

function afficherResultats(results, targetType, jobId){
  $('resultsPanel').classList.add('show');
  $('resultCount').textContent = results.length + ' ligne(s)';
  const body = $('resultsBody');
  if(!results.length){
    body.innerHTML = '<div class="empty"><div class="big">◇</div>Aucun résultat</div>';
    return;
  }

  if(targetType === 'url'){
    body.innerHTML = `
      <table>
        <thead><tr>
          <th>URL</th><th>IP</th><th>HTTP</th><th>Serveur</th>
          <th>Titre</th><th>TLS</th><th>Cert (j)</th>
          <th>Liens</th><th>📸</th>
        </tr></thead>
        <tbody>
          ${results.map((r,i) => `
            <tr>
              <td class="url-cell" title="${r.url || ''}">${r.url || '—'}</td>
              <td class="ip">${r.ip}</td>
              <td class="http-status ${httpClass(r.http_status)}">${r.http_status || '—'}</td>
              <td class="server-cell" title="${r.server_header || ''}">${r.server_header || '—'}</td>
              <td class="title-cell" title="${r.title || ''}">${r.title || '—'}</td>
              <td class="tls-cell">${r.tls_version || '—'}</td>
              <td class="cert-days ${certClass(r.cert_days_left)}" onclick='showCert(${JSON.stringify(r).replace(/'/g,"&#39;")})' style="cursor:pointer">
                ${r.cert_days_left !== null && r.cert_days_left !== undefined ? r.cert_days_left + 'j' : '—'}
              </td>
              <td>${r.links_count ? `<a class="links-badge" onclick='showLinks(${JSON.stringify(r.links_json || "").replace(/'/g,"&#39;")})'>${r.links_count} 🔗</a>` : '—'}</td>
              <td>${r.screenshot ? `<img src="/screenshots/${r.screenshot}" class="shot-thumb" onclick="showScreenshot('${r.screenshot}')">` : '—'}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  } else {
    body.innerHTML = `
      <table>
        <thead><tr>
          <th>Adresse IP</th><th>Port</th><th>Protocole</th>
          <th>Service</th><th>Version</th><th>État</th>
        </tr></thead>
        <tbody>
          ${results.map(r => `
            <tr>
              <td class="ip">${r.ip}</td>
              <td class="port">${r.port}</td>
              <td>${(r.protocol||'').toUpperCase()}</td>
              <td class="svc">${r.service || '—'}</td>
              <td class="ver">${r.version || '—'}</td>
              <td class="state"><span class="pill">${r.state || '—'}</span></td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }
}

$('scanBtn').addEventListener('click', lancerScan);
$('target').addEventListener('keydown', e => { if(e.key === 'Enter') lancerScan(); });
$('ports').addEventListener('keydown',  e => { if(e.key === 'Enter') lancerScan(); });
</script>
</body>
</html>
HTML

ok "Frontend généré."

log "Construction et démarrage..."
docker compose up -d --build

log "Attente de l'API..."
for i in {1..60}; do
  if curl -s "http://localhost:${APP_PORT}/api/jobs/0" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "200|404"; then
    break
  fi
  sleep 2
done

ok "=============================================="
ok " IP EXPERT SCANNER — édition complète"
ok " Interface : http://localhost:${APP_PORT}"
ok " API docs  : http://localhost:${APP_PORT}/docs"
ok "=============================================="
echo ""
echo -e "${CYAN}Fonctionnalités :${NC}"
echo "  🌐 Scan URL        → DNS + HTTP + SSL + crawl + screenshot"
echo "  🔒 Certificat SSL  → expiration, émetteur, SAN, TLS"
echo "  🕷️  Crawl           → liens internes (max 50)"
echo "  📸 Screenshot      → Playwright headless"
echo "  🌍 Scan IP/CIDR    → Masscan + Nmap"
echo ""
echo -e "${RED}⚠ Ne scannez que des réseaux autorisés.${NC}"