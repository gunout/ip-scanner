#!/usr/bin/env bash
# ============================================================
#  IP EXPERT SCANNER v4 — Rose Fluo + OSINT ULTRA complet
#  Port web : 9745 · Usage: sudo ./CREATE.SH
#  FIX: analyze_email_security + SQLAlchemy 2.0 + celery alias
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
fail() { echo -e "${RED}[!]${NC} $1"; exit 1; }

export APP_PORT=9745

log "Arrêt de l'ancien déploiement..."
docker compose down -v --remove-orphans 2>/dev/null || true
docker ps -q --filter "publish=${APP_PORT}" 2>/dev/null | xargs -r docker rm -f 2>/dev/null || true
for i in {1..15}; do
  if ss -tln 2>/dev/null | grep -qE ":${APP_PORT}\b"; then log "Port ${APP_PORT} occupé ($i/15)…"; sleep 1; else break; fi
done

log "Vérification des prérequis..."
[[ $EUID -eq 0 ]] || fail "Lancez avec sudo."
command -v docker &>/dev/null || fail "Docker requis."
docker compose version &>/dev/null || fail "Docker Compose v2 requis."
command -v nmap &>/dev/null || { log "Installation nmap..."; apt-get update -qq && apt-get install -y -qq nmap; }
ss -tlnp 2>/dev/null | grep -qE ":${APP_PORT}\b" && fail "Port ${APP_PORT} occupé."
ok "Prérequis OK."

mkdir -p backend frontend screenshots

# ============================================================
# requirements.txt
# ============================================================
cat > backend/requirements.txt <<'EOF'
fastapi==0.115.0
uvicorn[standard]==0.32.0
celery==5.4.0
kombu==5.4.2
packaging==24.1
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
python-whois==0.9.4
mmh3==5.0.1
EOF

# ============================================================
# Dockerfile
# ============================================================
cat > backend/Dockerfile <<'EOF'
FROM python:3.12-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan curl whois libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2 libpango-1.0-0 libpangocairo-1.0-0 \
    libx11-6 libx11-xcb1 libxcb1 libxext6 libxrender1 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium && playwright install-deps chromium
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# ============================================================
# database.py
# ============================================================
cat > backend/database.py <<'EOF'
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
DB_URL = os.getenv("DATABASE_URL", "postgresql://scanner:scanner@db:5432/scanner")
engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
EOF

# ============================================================
# models.py — v4 : +20 champs
# ============================================================
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
    results = relationship("HostResult", back_populates="job", cascade="all, delete-orphan")

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

    # HTTP
    url = Column(String, nullable=True)
    http_status = Column(Integer, nullable=True)
    server_header = Column(String, nullable=True)
    title = Column(String, nullable=True)
    redirect_to = Column(String, nullable=True)
    redirect_chain = Column(Text, nullable=True)
    content_type = Column(String, nullable=True)
    content_size = Column(Integer, nullable=True)
    charset = Column(String, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    http_methods = Column(String, nullable=True)
    powered_by = Column(String, nullable=True)
    cache_control = Column(String, nullable=True)
    http2 = Column(Integer, nullable=True)
    http3 = Column(Integer, nullable=True)                  # NEW
    compression = Column(String, nullable=True)
    server_timing = Column(Text, nullable=True)             # NEW
    cache_detail = Column(Text, nullable=True)              # NEW
    x_robots_tag = Column(String, nullable=True)            # NEW
    content_language = Column(String, nullable=True)        # NEW
    raw_headers = Column(Text, nullable=True)

    # Sécurité (v3 classique)
    security_headers = Column(Text, nullable=True)
    security_score = Column(Integer, nullable=True)
    security_missing = Column(Text, nullable=True)
    # Sécurité moderne (v4)
    modern_headers = Column(Text, nullable=True)            # NEW
    modern_missing = Column(Text, nullable=True)            # NEW
    modern_score = Column(Integer, nullable=True)           # NEW (/55)
    security_score_ext = Column(Integer, nullable=True)     # NEW (/130)
    hsts_max_age = Column(Integer, nullable=True)           # NEW
    hsts_preload = Column(Integer, nullable=True)           # NEW (flag présent)
    hsts_preloaded = Column(Integer, nullable=True)         # NEW (via hstspreload.org)
    cookies = Column(Text, nullable=True)
    cookies_detail = Column(Text, nullable=True)            # NEW
    sensitive_paths = Column(Text, nullable=True)
    robots_txt = Column(Text, nullable=True)
    security_txt = Column(Text, nullable=True)
    sitemap_found = Column(Integer, nullable=True)
    meta_refresh = Column(String, nullable=True)            # NEW

    # TLS
    tls_version = Column(String, nullable=True)
    tls_cipher = Column(String, nullable=True)
    tls_versions_supported = Column(Text, nullable=True)    # NEW (TLS 1.0/1.1/1.2/1.3)
    cert_chain_len = Column(Integer, nullable=True)
    cert_subject = Column(String, nullable=True)
    cert_issuer = Column(String, nullable=True)
    cert_valid_from = Column(String, nullable=True)
    cert_valid_until = Column(String, nullable=True)
    cert_days_left = Column(Integer, nullable=True)
    cert_expired = Column(Integer, nullable=True)
    cert_san = Column(Text, nullable=True)
    ssl_ciphers = Column(Text, nullable=True)

    # Contenu
    links_count = Column(Integer, nullable=True)
    links_json = Column(Text, nullable=True)
    technologies = Column(Text, nullable=True)
    screenshot = Column(String, nullable=True)
    meta_tags = Column(Text, nullable=True)
    emails = Column(Text, nullable=True)
    social_links = Column(Text, nullable=True)
    favicon_hash = Column(String, nullable=True)
    html_stats = Column(Text, nullable=True)
    structured_data = Column(Text, nullable=True)
    html_comments = Column(Text, nullable=True)             # NEW
    js_endpoints = Column(Text, nullable=True)              # NEW
    script_srcs = Column(Text, nullable=True)               # NEW
    asset_urls = Column(Text, nullable=True)                # NEW
    i18n = Column(Text, nullable=True)                      # NEW
    forms_detail = Column(Text, nullable=True)              # NEW

    # DNS / WHOIS / Géo
    dns_records = Column(Text, nullable=True)
    dns_extra = Column(Text, nullable=True)
    dns_modern = Column(Text, nullable=True)                # NEW (HTTPS/SVCB/TLSA)
    wildcard_dns = Column(Integer, nullable=True)           # NEW (1/0/-1)
    dnssec = Column(Integer, nullable=True)
    dns_zone_transfer = Column(Integer, nullable=True)
    email_security = Column(Text, nullable=True)
    subdomains = Column(Text, nullable=True)
    ct_logs_count = Column(Integer, nullable=True)          # NEW
    whois_data = Column(Text, nullable=True)
    geolocation = Column(Text, nullable=True)
    reverse_dns = Column(String, nullable=True)

    # OSINT externe
    shodan_internetdb = Column(Text, nullable=True)         # NEW
    wayback = Column(Text, nullable=True)                   # NEW

    # WAF / CDN / Système
    waf = Column(String, nullable=True)
    cdn = Column(String, nullable=True)
    os_guess = Column(String, nullable=True)

    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    job = relationship("ScanJob", back_populates="results")

Index("ix_host_port", HostResult.ip, HostResult.port)
EOF

# ============================================================
# intel.py — v4 : OSINT étendu + FIX analyze_email_security
# ============================================================
cat > backend/intel.py <<'PYEOF'
"""Collecte OSINT v4 : DNS, WHOIS, Géo, Sécurité (classique + moderne),
Tech, WAF, Meta, Subdomains, HTML comments, JS endpoints, Shodan, Wayback."""
import base64, json, random, re, socket, ssl, threading, time
from urllib.parse import urlparse

import requests
import dns.resolver
import dns.query
import dns.zone
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECURITY_HEADERS = {
    "strict-transport-security": {"w": 15, "label": "HSTS"},
    "content-security-policy":   {"w": 20, "label": "CSP"},
    "x-frame-options":           {"w": 10, "label": "X-Frame-Options"},
    "x-content-type-options":    {"w": 10, "label": "X-Content-Type-Options"},
    "referrer-policy":           {"w": 8,  "label": "Referrer-Policy"},
    "permissions-policy":        {"w": 7,  "label": "Permissions-Policy"},
    "x-xss-protection":          {"w": 5,  "label": "X-XSS-Protection"},
}

# v4 : en-têtes de sécurité MODERNES (score max 55)
MODERN_HEADERS = {
    "cross-origin-opener-policy":          {"w": 10, "label": "COOP"},
    "cross-origin-embedder-policy":        {"w": 10, "label": "COEP"},
    "cross-origin-resource-policy":        {"w": 5,  "label": "CORP"},
    "origin-agent-cluster":                {"w": 5,  "label": "Origin-Agent-Cluster"},
    "reporting-endpoints":                 {"w": 5,  "label": "Reporting-Endpoints"},
    "document-policy":                     {"w": 5,  "label": "Document-Policy"},
    "x-permitted-cross-domain-policies":   {"w": 3,  "label": "X-Permitted-Cross-Domain-Policies"},
    "content-security-policy-report-only": {"w": 2,  "label": "CSP-Report-Only"},
}

TECH_PATTERNS = {
    "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
    "cloudflare": "Cloudflare", "caddy": "Caddy", "litespeed": "LiteSpeed",
    "openresty": "OpenResty", "gunicorn": "Gunicorn",
    "php": "PHP", "asp.net": "ASP.NET", "express": "Express.js",
    "django": "Django", "flask": "Flask", "rails": "Ruby on Rails",
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
    "react": "React", "vue": "Vue.js", "angular": "Angular",
    "jquery": "jQuery", "bootstrap": "Bootstrap", "next.js": "Next.js",
    "nuxt": "Nuxt", "laravel": "Laravel", "symfony": "Symfony",
    "spring": "Spring", "tomcat": "Tomcat", "jetty": "Jetty",
}

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.htaccess", "/admin", "/phpmyadmin",
    "/wp-admin", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/config.php", "/server-status", "/actuator/health",
]

WAF_SIGNATURES = {
    "cf-ray": "Cloudflare WAF", "x-sucuri-id": "Sucuri",
    "x-iinfo": "Imperva Incapsula", "server: cloudflare": "Cloudflare",
    "x-akamai-transformed": "Akamai", "akamai-grn": "Akamai",
    "x-amzn-requestid": "AWS WAF", "x-amz-cf-id": "AWS CloudFront",
    "x-fastly-request-id": "Fastly", "x-fw-hash": "FortiWeb",
    "barra_counter_session": "Barracuda", "x-waf-event-info": "F5 BIG-IP",
    "x-cdn": "Generic CDN", "x-cache": "Generic CDN Cache",
    "x-varnish": "Varnish", "x-cache-hits": "Fastly/Varnish",
    "via": "Proxy / CDN",
}

SOCIAL_DOMAINS = {
    "twitter.com": "Twitter/X", "x.com": "Twitter/X",
    "facebook.com": "Facebook", "linkedin.com": "LinkedIn",
    "instagram.com": "Instagram", "github.com": "GitHub",
    "youtube.com": "YouTube", "tiktok.com": "TikTok",
    "discord.gg": "Discord", "t.me": "Telegram",
    "reddit.com": "Reddit", "pinterest.com": "Pinterest",
    "mastodon": "Mastodon", "bsky.app": "Bluesky",
}

COMMON_DKIM_SELECTORS = ["default", "mail", "google", "k1", "s1",
                          "selector1", "selector2", "dkim", "smtp"]


# =========================================================
# DNS classique + extra
# =========================================================
def enumerate_dns(hostname: str) -> dict:
    out = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [],
           "cname": [], "soa": None}
    handlers = {
        "A":     lambda r: out["a"].append(str(r)),
        "AAAA":  lambda r: out["aaaa"].append(str(r)),
        "MX":    lambda r: out["mx"].append({"priority": r.preference,
                                             "host": str(r.exchange).rstrip(".")}),
        "NS":    lambda r: out["ns"].append(str(r).rstrip(".")),
        "TXT":   lambda r: out["txt"].append(str(r)[:300]),
        "CNAME": lambda r: out["cname"].append(str(r).rstrip(".")),
        "SOA":   lambda r: out.update({"soa": {
            "mname": str(r.mname).rstrip("."),
            "rname": str(r.rname).rstrip("."),
            "serial": r.serial,
        }}),
    }
    for rtype, cb in handlers.items():
        try:
            for r in dns.resolver.resolve(hostname, rtype, lifetime=4):
                cb(r)
        except Exception:
            continue
    return out


def enumerate_dns_extra(hostname: str, dns_base: dict) -> dict:
    out = {"caa": [], "srv": [], "dmarc": None, "spf": None,
           "dkim_selectors": [], "dnssec": False}
    try:
        for r in dns.resolver.resolve(hostname, "CAA", lifetime=4):
            out["caa"].append({
                "flags": r.flags,
                "tag": r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag),
                "value": r.value.decode() if isinstance(r.value, bytes) else str(r.value),
            })
    except Exception: pass
    for svc in ["_sip._tcp", "_imap._tcp", "_xmpp-server._tcp", "_autodiscover._tcp"]:
        try:
            for r in dns.resolver.resolve(f"{svc}.{hostname}", "SRV", lifetime=3):
                out["srv"].append({"name": svc, "target": str(r.target).rstrip("."),
                                   "port": r.port, "priority": r.priority})
        except Exception: continue
    for txt in dns_base.get("txt", []):
        if txt.startswith("v=spf1"):
            out["spf"] = txt
            break
    try:
        for r in dns.resolver.resolve(f"_dmarc.{hostname}", "TXT", lifetime=4):
            txt = str(r).strip('"')
            if "v=DMARC1" in txt:
                out["dmarc"] = txt[:400]
                break
    except Exception: pass
    for sel in COMMON_DKIM_SELECTORS:
        try:
            for r in dns.resolver.resolve(f"{sel}._domainkey.{hostname}", "TXT", lifetime=3):
                txt = str(r)[:80]
                if "v=DKIM1" in txt or "p=" in txt:
                    out["dkim_selectors"].append(sel)
                    break
        except Exception: continue
    try:
        dns.resolver.resolve(hostname, "DNSKEY", lifetime=4)
        out["dnssec"] = True
    except Exception: pass
    return out


def analyze_email_security(hostname: str, dns_extra: dict) -> dict:
    """Analyse SPF / DMARC / DKIM depuis les données DNS déjà collectées.
    Score max : 3 (1 point par mécanisme présent)."""
    spf = dns_extra.get("spf")
    dmarc = dns_extra.get("dmarc")
    dkim_selectors = dns_extra.get("dkim_selectors", []) or []

    spf_policy = None
    if spf:
        m = re.search(r"([~\-+?]all)", spf)
        if m:
            spf_policy = m.group(1)

    dmarc_policy = None
    if dmarc:
        m = re.search(r"p\s*=\s*(\w+)", dmarc)
        if m:
            dmarc_policy = m.group(1).lower()

    return {
        "spf_present": bool(spf),
        "spf_policy": spf_policy,
        "dmarc_present": bool(dmarc),
        "dmarc_policy": dmarc_policy,
        "dkim_present": bool(dkim_selectors),
        "dkim_selectors": dkim_selectors,
        "score": int(bool(spf)) + int(bool(dmarc)) + int(bool(dkim_selectors)),
        "max": 3,
    }


def enumerate_dns_modern(hostname: str) -> dict:
    """v4 : HTTPS (type 65), SVCB, TLSA."""
    out = {"https": [], "tlsa": []}
    try:
        for r in dns.resolver.resolve(hostname, "HTTPS", lifetime=4):
            out["https"].append(str(r)[:300])
    except Exception: pass
    for prefix in ["_443._tcp", "_25._tcp", "_853._tcp"]:
        try:
            for r in dns.resolver.resolve(f"{prefix}.{hostname}", "TLSA", lifetime=3):
                out["tlsa"].append({"name": prefix, "record": str(r)[:300]})
                break
        except Exception: continue
    return out


def check_wildcard_dns(hostname: str) -> int:
    """1 = wildcard actif, 0 = non, -1 = erreur."""
    try:
        rnd = f"zzz{random.randint(10000,99999)}test.{hostname}"
        try:
            dns.resolver.resolve(rnd, "A", lifetime=4)
            return 1
        except dns.resolver.NXDOMAIN:
            return 0
        except dns.resolver.NoNameservers:
            return 0
        except Exception:
            return -1
    except Exception:
        return -1


def try_zone_transfer(hostname: str, ns_list: list) -> int:
    for ns in ns_list[:3]:
        try:
            ns_ip = socket.gethostbyname(ns)
            dns.zone.from_xfr(dns.query.xfr(ns_ip, hostname, timeout=5))
            return 1
        except Exception: continue
    return 0


# =========================================================
# Subdomains + CT logs
# =========================================================
def get_subdomains_crtsh(hostname: str, limit: int = 100) -> list:
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{hostname}&output=json",
                        timeout=12, headers={"User-Agent": "IPExpertScanner/4.0"})
        if r.status_code != 200: return []
        subs = set()
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.endswith(f".{hostname}") or name == hostname:
                    subs.add(name)
                    if len(subs) >= limit: break
            if len(subs) >= limit: break
        return sorted(subs)[:limit]
    except Exception:
        return []


def check_ct_logs(hostname: str) -> int:
    """Nombre de certificats dans les CT logs (via crt.sh)."""
    try:
        r = requests.get(f"https://crt.sh/?q={hostname}&output=json", timeout=10)
        if r.status_code == 200:
            return len(r.json())
    except Exception: pass
    return 0


# =========================================================
# WHOIS / Géo
# =========================================================
def get_whois(hostname: str) -> dict:
    result = {"error": "timeout"}
    def _worker():
        try:
            import whois as w
            data = w.whois(hostname)
            result.clear()
            result.update({
                "registrar": str(data.registrar) if getattr(data, "registrar", None) else None,
                "creation_date": str(data.creation_date) if getattr(data, "creation_date", None) else None,
                "expiration_date": str(data.expiration_date) if getattr(data, "expiration_date", None) else None,
                "name_servers": list(data.name_servers) if getattr(data, "name_servers", None) else [],
                "status": list(data.status) if getattr(data, "status", None) else [],
            })
        except Exception as e:
            result.clear()
            result["error"] = f"{type(e).__name__}: {str(e)[:100]}"
    t = threading.Thread(target=_worker, daemon=True); t.start(); t.join(timeout=8)
    return dict(result)


def get_geolocation(ip: str) -> dict:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,regionName,city,isp,org,as,query", timeout=5)
        if r.status_code == 200 and r.json().get("status") == "success":
            d = r.json()
            return {"country": d.get("country"), "country_code": d.get("countryCode"),
                    "region": d.get("regionName"), "city": d.get("city"),
                    "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as")}
    except Exception: pass
    return {}


# =========================================================
# Sécurité classique + moderne + HSTS preload
# =========================================================
def analyze_security_headers(headers: dict) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    present, missing, score = {}, [], 0
    for hdr, info in SECURITY_HEADERS.items():
        if hdr in h:
            present[info["label"]] = str(h[hdr])[:200]
            score += info["w"]
        else:
            missing.append(info["label"])
    return {"present": present, "missing": missing, "score": score, "max": 75}


def analyze_modern_headers(headers: dict) -> dict:
    """v4 : COOP, COEP, OAC, Reporting-Endpoints, etc."""
    h = {k.lower(): v for k, v in headers.items()}
    present, missing, score = {}, [], 0
    for hdr, info in MODERN_HEADERS.items():
        if hdr in h:
            present[info["label"]] = str(h[hdr])[:200]
            score += info["w"]
        else:
            missing.append(info["label"])
    return {"present": present, "missing": missing, "score": score, "max": 55}


def get_hsts_info(headers: dict) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    hsts = h.get("strict-transport-security", "")
    out = {"max_age": 0, "preload": 0}
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m: out["max_age"] = int(m.group(1))
        out["preload"] = 1 if "preload" in hsts.lower() else 0
    return out


def check_hsts_preload(hostname: str) -> int:
    """Interroge hstspreload.org pour savoir si le domaine est préchargé."""
    try:
        r = requests.get(f"https://hstspreload.org/api/v2/status?domain={hostname}", timeout=6)
        if r.status_code == 200:
            d = r.json()
            return 1 if d.get("status") == "preloaded" else 0
    except Exception: pass
    return 0


# =========================================================
# Tech / WAF / Cookies / Cache
# =========================================================
def detect_technologies(headers: dict, html: str) -> list:
    h = {k.lower(): v for k, v in headers.items()}
    blob = str(h.get("server", "")) + " " + str(h.get("x-powered-by", "")) + " " + (html[:6000].lower() if html else "")
    techs = {name for pat, name in TECH_PATTERNS.items() if pat in blob}
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta and meta.get("content"):
            techs.add(str(meta["content"])[:60])
    except Exception: pass
    return sorted(techs)


def detect_waf_cdn(headers: dict) -> tuple:
    h = {k.lower(): f"{k}: {v}" for k, v in headers.items()}
    flat = " ".join(h.values()).lower()
    waf = None; cdn = None
    for sig, name in WAF_SIGNATURES.items():
        if sig in flat:
            if "CDN" in name or "Cache" in name or "Proxy" in name or "Varnish" in name:
                cdn = cdn or name
            else:
                waf = waf or name
    return waf, cdn


def analyze_cookies(response) -> list:
    out = []
    try:
        raw = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
    except Exception: raw = []
    for c in raw:
        low = c.lower()
        out.append({"name": c.split("=")[0].strip(),
                    "secure": "secure" in low,
                    "httponly": "httponly" in low,
                    "samesite": "samesite=" in low})
    return out


def analyze_cookies_detailed(response) -> list:
    """v4 : SameSite value, Domain, Path."""
    out = []
    try:
        raw = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
    except Exception: raw = []
    for c in raw:
        low = c.lower()
        name = c.split("=")[0].strip()[:50]
        samesite_val = "default"
        m = re.search(r"samesite=(\w+)", low)
        if m: samesite_val = m.group(1)
        domain = None
        m2 = re.search(r"domain=([^;,\s]+)", low)
        if m2: domain = m2.group(1)
        path = None
        m3 = re.search(r"path=([^;,\s]+)", low)
        if m3: path = m3.group(1)
        out.append({"name": name, "secure": "secure" in low,
                    "httponly": "httponly" in low,
                    "samesite": samesite_val,
                    "domain": domain, "path": path})
    return out


def parse_server_timing(headers: dict) -> dict:
    """v4 : extrait les latences internes (Server-Timing)."""
    h = {k.lower(): v for k, v in headers.items()}
    st = h.get("server-timing", "")
    out = {}
    for part in st.split(","):
        m = re.match(r"\s*([\w-]+);dur=([\d.\-]+)", part.strip())
        if m:
            try: out[m.group(1)] = float(m.group(2))
            except: pass
    return out


def parse_cache_detail(headers: dict) -> dict:
    """v4 : Age, X-Cache, X-Cache-Hits, Vary."""
    h = {k.lower(): v for k, v in headers.items()}
    return {
        "age": h.get("age"),
        "x_cache": h.get("x-cache"),
        "x_cache_hits": h.get("x-cache-hits"),
        "vary": h.get("vary"),
        "cache_control": h.get("cache-control"),
        "expires": h.get("expires"),
    }


def check_http3(headers: dict) -> int:
    """v4 : HTTP/3 via Alt-Svc."""
    h = {k.lower(): v for k, v in headers.items()}
    alt = h.get("alt-svc", "")
    return 1 if ("h3=" in alt or "h3-" in alt) else 0


def detect_http_methods(url: str) -> list:
    try:
        r = requests.options(url, timeout=5, verify=False)
        allow = r.headers.get("Allow", "")
        if allow: return [m.strip() for m in allow.split(",")]
    except Exception: pass
    return []


def get_robots(url: str):
    try:
        p = urlparse(url); base = f"{p.scheme}://{p.netloc}"
        r = requests.get(f"{base}/robots.txt", timeout=5, verify=False)
        if r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
            return r.text[:3000]
    except Exception: pass
    return None


def get_security_txt(url: str):
    try:
        p = urlparse(url); base = f"{p.scheme}://{p.netloc}"
        for path in ("/.well-known/security.txt", "/security.txt"):
            r = requests.get(base + path, timeout=5, verify=False)
            if r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
                return r.text[:2000]
    except Exception: pass
    return None


def check_sitemap(url: str) -> int:
    try:
        p = urlparse(url); base = f"{p.scheme}://{p.netloc}"
        r = requests.get(f"{base}/sitemap.xml", timeout=5, verify=False)
        if r.status_code == 200 and ("<urlset" in r.text or "<sitemapindex" in r.text):
            return 1
    except Exception: pass
    return 0


def check_sensitive_paths(base_url: str) -> list:
    found = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.head(base_url + path, timeout=3, verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                found.append({"path": path, "status": r.status_code})
        except Exception: continue
    return found


# =========================================================
# HTML analysis
# =========================================================
def extract_meta_tags(html: str) -> dict:
    out = {"title": None, "description": None, "keywords": None,
           "author": None, "generator": None, "og": {}, "twitter": {}}
    if not html: return out
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            out["title"] = soup.title.string.strip()[:200]
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            prop = (meta.get("property") or "").lower()
            content = (meta.get("content") or "").strip()[:300]
            if name == "description": out["description"] = content
            elif name == "keywords":  out["keywords"] = content
            elif name == "author":    out["author"] = content
            elif name == "generator": out["generator"] = content
            elif prop.startswith("og:"):       out["og"][prop] = content
            elif name.startswith("twitter:"):  out["twitter"][name] = content
    except Exception: pass
    return out


def extract_emails(html: str) -> list:
    if not html: return []
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return sorted(list(set(re.findall(pattern, html[:500000]))))[:30]


def extract_social_links(links: list) -> list:
    out = []
    for l in links:
        url = (l.get("url") or "").lower()
        for dom, name in SOCIAL_DOMAINS.items():
            if dom in url:
                out.append({"network": name, "url": l["url"]})
                break
    return out[:30]


def extract_html_stats(html: str) -> dict:
    if not html: return {}
    try:
        soup = BeautifulSoup(html, "html.parser")
        scripts = soup.find_all("script")
        return {
            "forms": len(soup.find_all("form")),
            "inputs": len(soup.find_all("input")),
            "scripts": len(scripts),
            "inline_scripts": len([s for s in scripts if not s.get("src")]),
            "external_scripts": len([s for s in scripts if s.get("src")]),
            "iframes": len(soup.find_all("iframe")),
            "images": len(soup.find_all("img")),
            "stylesheets": len(soup.find_all("link", rel="stylesheet")),
            "links": len(soup.find_all("a")),
            "meta_tags": len(soup.find_all("meta")),
        }
    except Exception: return {}


def extract_structured_data(html: str) -> list:
    if not html: return []
    try:
        soup = BeautifulSoup(html, "html.parser")
        blocks = []
        for s in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(s.string or "")
                t = data.get("@type", "?") if isinstance(data, dict) else "?"
                blocks.append({"type": t})
            except Exception: continue
            if len(blocks) >= 10: break
        return blocks
    except Exception: return []


def extract_html_comments(html: str) -> list:
    """v4 : commentaires HTML/JS (leak potentiel)."""
    if not html: return []
    raw = re.findall(r"<!--(.*?)-->", html[:200000], re.DOTALL)
    out = []
    for c in raw[:30]:
        c = c.strip()
        if 0 < len(c) < 500:
            out.append(c[:300])
    return out


def extract_js_endpoints(html: str) -> list:
    """v4 : endpoints API visibles dans le JS inline."""
    if not html: return []
    patterns = [
        r'["\'](/api/[a-zA-Z0-9_\-/{}.:]+)["\']',
        r'["\'](/v\d+/[a-zA-Z0-9_\-/{}.:]+)["\']',
        r'fetch\(["\']([^"\']{3,200})["\']',
        r'axios\.[a-z]+\(["\']([^"\']{3,200})["\']',
        r'["\'](https?://[a-zA-Z0-9.-]+\.[a-z]+/[a-zA-Z0-9_\-/{}.:]+)["\']',
    ]
    endpoints = set()
    for p in patterns:
        for m in re.findall(p, html[:500000]):
            if isinstance(m, tuple): m = m[0]
            if 2 < len(m) < 200:
                endpoints.add(m)
    return sorted(list(endpoints))[:50]


def extract_script_srcs(html: str) -> list:
    """v4 : liste des <script src>."""
    if not html: return []
    try:
        soup = BeautifulSoup(html, "html.parser")
        return [s["src"][:200] for s in soup.find_all("script", src=True)][:30]
    except Exception: return []


def extract_asset_urls(html: str) -> list:
    """v4 : CSS + images."""
    if not html: return []
    try:
        soup = BeautifulSoup(html, "html.parser")
        assets = []
        for link in soup.find_all("link", href=True)[:20]:
            rel = " ".join(link.get("rel", []))
            assets.append({"rel": rel[:30], "href": link["href"][:200]})
        for img in soup.find_all("img", src=True)[:20]:
            assets.append({"type": "img", "src": img["src"][:200]})
        return assets[:40]
    except Exception: return []


def extract_i18n(html: str) -> dict:
    """v4 : lang + hreflang."""
    if not html: return {}
    try:
        soup = BeautifulSoup(html, "html.parser")
        out = {"lang": None, "hreflang": []}
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            out["lang"] = html_tag["lang"]
        for link in soup.find_all("link", rel="alternate", hreflang=True)[:20]:
            out["hreflang"].append({"lang": link["hreflang"], "href": link.get("href", "")[:200]})
        return out
    except Exception: return {}


def extract_forms_detail(html: str) -> list:
    """v4 : détail des formulaires."""
    if not html: return []
    try:
        soup = BeautifulSoup(html, "html.parser")
        out = []
        for f in soup.find_all("form")[:10]:
            out.append({
                "action": (f.get("action") or "")[:200],
                "method": (f.get("method") or "get").upper(),
                "inputs": len(f.find_all("input")),
                "hidden": len(f.find_all("input", {"type": "hidden"})),
                "csrf": len(f.find_all("input", {"name": re.compile(r"csrf|token", re.I)})),
            })
        return out
    except Exception: return []


def extract_meta_refresh(html: str):
    """v4 : <meta http-equiv='refresh'>."""
    if not html: return None
    try:
        soup = BeautifulSoup(html, "html.parser")
        m = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
        if m: return (m.get("content") or "")[:200]
    except Exception: pass
    return None


def get_favicon_hash(url: str):
    try:
        p = urlparse(url); base = f"{p.scheme}://{p.netloc}"
        r = requests.get(f"{base}/favicon.ico", timeout=5, verify=False)
        if r.status_code == 200 and len(r.content) > 0:
            import mmh3
            b64 = base64.encodebytes(r.content)
            return str(mmh3.hash(b64))
    except Exception: pass
    return None


def get_redirect_chain(url: str) -> list:
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
        chain = [{"url": h.url, "status": h.status_code} for h in r.history]
        chain.append({"url": r.url, "status": r.status_code})
        return chain
    except Exception: return []


def check_http2(hostname: str) -> int:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return 1 if ssock.selected_alpn_protocol() == "h2" else 0
    except Exception: return 0


def probe_tls_versions(hostname: str, port: int = 443) -> list:
    """v4 : teste TLS 1.0/1.1/1.2/1.3."""
    versions = {
        "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
        "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
    }
    supported = []
    for name, ver in versions.items():
        if ver is None: continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver; ctx.maximum_version = ver
            try: ctx.set_ciphers("ALL:@SECLEVEL=0")
            except Exception: pass
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    supported.append(name)
        except Exception: continue
    return supported


# =========================================================
# OSINT externe
# =========================================================
def shodan_internetdb(ip: str) -> dict:
    """API Shodan InternetDB — gratuit, sans clé."""
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {"ports": d.get("ports", [])[:100],
                    "hostnames": d.get("hostnames", [])[:30],
                    "cpes": d.get("cpes", [])[:20],
                    "tags": d.get("tags", [])[:20],
                    "vulns": d.get("vulns", [])[:30]}
        elif r.status_code == 404:
            return {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}
    except Exception: pass
    return {}


def wayback_check(url: str) -> dict:
    """Wayback Machine — dernier snapshot."""
    try:
        r = requests.get(f"http://archive.org/wayback/available?url={url}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            snap = d.get("archived_snapshots", {}).get("closest", {})
            if snap:
                return {"available": 1, "url": snap.get("url"),
                        "timestamp": snap.get("timestamp")}
    except Exception: pass
    return {"available": 0}
PYEOF

# ============================================================
# scanner.py — v4 (FIX reverse_dns sur IP)
# ============================================================
cat > backend/scanner.py <<'PYEOF'
import subprocess, json, socket, nmap, re, time
import requests
import dns.resolver
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from intel import (
    enumerate_dns, enumerate_dns_extra, enumerate_dns_modern,
    analyze_email_security, check_wildcard_dns, try_zone_transfer,
    get_subdomains_crtsh, check_ct_logs, get_whois, get_geolocation,
    analyze_security_headers, analyze_modern_headers,
    get_hsts_info, check_hsts_preload,
    detect_technologies, detect_waf_cdn,
    analyze_cookies, analyze_cookies_detailed,
    parse_server_timing, parse_cache_detail, check_http3,
    detect_http_methods, get_robots, check_sensitive_paths,
    get_security_txt, check_sitemap,
    extract_meta_tags, extract_emails, extract_social_links,
    extract_html_stats, extract_structured_data,
    extract_html_comments, extract_js_endpoints,
    extract_script_srcs, extract_asset_urls,
    extract_i18n, extract_forms_detail, extract_meta_refresh,
    get_favicon_hash, get_redirect_chain, check_http2,
    probe_tls_versions, shodan_internetdb, wayback_check,
)

BASE_KEYS = {
    "url": None, "http_status": None, "server_header": None,
    "title": None, "redirect_to": None, "redirect_chain": None,
    "content_type": None, "content_size": None, "charset": None,
    "response_time_ms": None, "http_methods": None,
    "powered_by": None, "cache_control": None,
    "http2": None, "http3": None, "compression": None,
    "server_timing": None, "cache_detail": None,
    "x_robots_tag": None, "content_language": None,
    "raw_headers": None,
    "security_headers": None, "security_score": None,
    "security_missing": None,
    "modern_headers": None, "modern_missing": None,
    "modern_score": None, "security_score_ext": None,
    "hsts_max_age": None, "hsts_preload": None, "hsts_preloaded": None,
    "cookies": None, "cookies_detail": None,
    "sensitive_paths": None, "robots_txt": None,
    "security_txt": None, "sitemap_found": None, "meta_refresh": None,
    "tls_version": None, "tls_cipher": None, "tls_versions_supported": None,
    "cert_chain_len": None, "cert_subject": None, "cert_issuer": None,
    "cert_valid_from": None, "cert_valid_until": None,
    "cert_days_left": None, "cert_expired": None, "cert_san": None,
    "ssl_ciphers": None,
    "links_count": None, "links_json": None,
    "technologies": None, "screenshot": None,
    "meta_tags": None, "emails": None, "social_links": None,
    "favicon_hash": None, "html_stats": None, "structured_data": None,
    "html_comments": None, "js_endpoints": None,
    "script_srcs": None, "asset_urls": None,
    "i18n": None, "forms_detail": None,
    "dns_records": None, "dns_extra": None, "dns_modern": None,
    "wildcard_dns": None, "dnssec": None, "dns_zone_transfer": None,
    "email_security": None, "subdomains": None, "ct_logs_count": None,
    "whois_data": None, "geolocation": None, "reverse_dns": None,
    "shodan_internetdb": None, "wayback": None,
    "waf": None, "cdn": None, "os_guess": None,
}


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
        hostname = parsed.hostname; scheme = parsed.scheme; url = target
    else:
        hostname = target; scheme = "https"; url = f"https://{target}"
    ips = []
    try: ips = [str(r) for r in dns.resolver.resolve(hostname, 'A')]
    except Exception:
        try: ips = [socket.gethostbyname(hostname)]
        except Exception: ips = []
    return {"hostname": hostname, "ips": ips, "url": url, "scheme": scheme}


def scan_certificate(hostname: str, port: int = 443) -> dict:
    result = {"subject": None, "issuer": None, "valid_from": None,
              "valid_until": None, "days_left": None, "expired": None,
              "san": [], "tls_version": None, "tls_cipher": None, "chain_len": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["tls_version"] = ssock.version()
                c = ssock.cipher()
                if c: result["tls_cipher"] = f"{c[0]} / {c[1]} bits"
                try:
                    chain = ssock.get_verified_chain() if hasattr(ssock, "get_verified_chain") else None
                    if chain: result["chain_len"] = len(chain)
                except Exception: pass
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
        except x509.ExtensionNotFound: result["san"] = []
    except Exception as e:
        result["error"] = str(e)
    return result


def crawl_links(url: str, max_links: int = 50, same_domain: bool = True) -> list:
    links = []
    try:
        r = requests.get(url, headers={"User-Agent": "IPExpertScanner/4.0"}, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        base = urlparse(url).netloc
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")): continue
            full = urljoin(url, href); parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"): continue
            if same_domain and parsed.netloc != base: continue
            links.append({"url": full, "text": a.get_text(strip=True)[:80], "domain": parsed.netloc})
            if len(links) >= max_links: break
    except Exception as e:
        return [{"error": str(e)}]
    return links


def capture_screenshot(url: str, filename: str):
    import os
    SCREENSHOT_DIR = "/app/screenshots"; os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    path = os.path.join(SCREENSHOT_DIR, filename)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            try: page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception: pass
            page.screenshot(path=path, full_page=True)
            browser.close()
        return filename
    except Exception as e:
        print(f"Screenshot error: {e}")
        return None


def scan_url_full(url, ip=None, job_id=None, do_crawl=True, do_screenshot=True):
    result = {**BASE_KEYS}; result["url"] = url
    headers_req = {"User-Agent": "IPExpertScanner/4.0"}
    html_body = ""; last_resp_headers = {}

    t0 = time.time()
    try:
        r = requests.get(url, headers=headers_req, timeout=10,
                         allow_redirects=False, verify=False)
        result["response_time_ms"] = int((time.time() - t0) * 1000)
        result["http_status"] = r.status_code
        result["server_header"] = r.headers.get("Server", "")[:120]
        result["powered_by"] = r.headers.get("X-Powered-By", "")[:120] or None
        result["cache_control"] = r.headers.get("Cache-Control", "")[:200] or None
        result["content_type"] = r.headers.get("Content-Type", "")[:120]
        result["charset"] = r.encoding or ""
        result["content_size"] = len(r.content)
        result["compression"] = r.headers.get("Content-Encoding", "none") or "none"
        result["x_robots_tag"] = (r.headers.get("X-Robots-Tag") or "")[:200] or None
        result["content_language"] = (r.headers.get("Content-Language") or "")[:60] or None
        result["raw_headers"] = json.dumps(dict(r.headers))[:4000]
        if r.is_redirect:
            result["redirect_to"] = r.headers.get("Location", "")[:200]
        html_body = r.text; last_resp_headers = dict(r.headers)

        # Titre
        m = re.search(r"<title[^>]*>(.*?)</title>", html_body[:6000], re.IGNORECASE | re.DOTALL)
        if m: result["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:150]

        # Sécurité classique
        sec = analyze_security_headers(last_resp_headers)
        result["security_headers"] = json.dumps(sec["present"])[:4000]
        result["security_missing"] = json.dumps(sec["missing"])
        result["security_score"] = sec["score"]

        # Sécurité moderne
        modern = analyze_modern_headers(last_resp_headers)
        result["modern_headers"] = json.dumps(modern["present"])[:4000]
        result["modern_missing"] = json.dumps(modern["missing"])
        result["modern_score"] = modern["score"]
        result["security_score_ext"] = sec["score"] + modern["score"]

        # HSTS
        hsts = get_hsts_info(last_resp_headers)
        result["hsts_max_age"] = hsts["max_age"]
        result["hsts_preload"] = hsts["preload"]

        # Cookies
        result["cookies"] = json.dumps(analyze_cookies(r))[:2000]
        result["cookies_detail"] = json.dumps(analyze_cookies_detailed(r))[:4000]

        # WAF / CDN
        waf, cdn = detect_waf_cdn(last_resp_headers)
        result["waf"] = waf; result["cdn"] = cdn

        # HTTP/3 + Server-Timing + Cache
        result["http3"] = check_http3(last_resp_headers)
        st = parse_server_timing(last_resp_headers)
        if st: result["server_timing"] = json.dumps(st)[:2000]
        result["cache_detail"] = json.dumps(parse_cache_detail(last_resp_headers))[:2000]

        # Redirect chain
        result["redirect_chain"] = json.dumps(get_redirect_chain(url))[:4000]

    except requests.exceptions.SSLError:
        result["server_header"] = "SSL_ERROR"
    except requests.exceptions.ConnectionError:
        result["server_header"] = "CONNECTION_ERROR"
    except requests.exceptions.Timeout:
        result["server_header"] = "TIMEOUT"
    except Exception as e:
        result["server_header"] = f"ERROR: {type(e).__name__}"

    # ---------- HTML analysis ----------
    if html_body:
        result["technologies"] = json.dumps(detect_technologies(last_resp_headers, html_body))[:2000]
        result["meta_tags"] = json.dumps(extract_meta_tags(html_body))[:4000]
        result["emails"] = json.dumps(extract_emails(html_body))[:2000]
        result["html_stats"] = json.dumps(extract_html_stats(html_body))[:2000]
        result["structured_data"] = json.dumps(extract_structured_data(html_body))[:2000]
        # v4
        comments = extract_html_comments(html_body)
        if comments: result["html_comments"] = json.dumps(comments)[:4000]
        endpoints = extract_js_endpoints(html_body)
        if endpoints: result["js_endpoints"] = json.dumps(endpoints)[:4000]
        srcs = extract_script_srcs(html_body)
        if srcs: result["script_srcs"] = json.dumps(srcs)[:2000]
        assets = extract_asset_urls(html_body)
        if assets: result["asset_urls"] = json.dumps(assets)[:3000]
        i18n = extract_i18n(html_body)
        if i18n: result["i18n"] = json.dumps(i18n)[:1000]
        forms = extract_forms_detail(html_body)
        if forms: result["forms_detail"] = json.dumps(forms)[:2000]
        mr = extract_meta_refresh(html_body)
        if mr: result["meta_refresh"] = mr

    # ---------- HTTP avancé ----------
    methods = detect_http_methods(url)
    if methods: result["http_methods"] = ", ".join(methods)[:200]
    hostname = urlparse(url).hostname
    if url.startswith("https://") and hostname:
        result["http2"] = check_http2(hostname)
        tls_versions = probe_tls_versions(hostname)
        if tls_versions: result["tls_versions_supported"] = json.dumps(tls_versions)

    # ---------- Fichiers ----------
    robots = get_robots(url)
    if robots: result["robots_txt"] = robots
    st_txt = get_security_txt(url)
    if st_txt: result["security_txt"] = st_txt
    result["sitemap_found"] = check_sitemap(url)

    # ---------- Chemins sensibles ----------
    paths = check_sensitive_paths(url.rstrip("/"))
    if paths: result["sensitive_paths"] = json.dumps(paths)[:2000]

    # ---------- TLS ----------
    if url.startswith("https://") and hostname:
        cert = scan_certificate(hostname, 443)
        result["tls_version"] = cert.get("tls_version")
        result["tls_cipher"] = cert.get("tls_cipher")
        result["cert_chain_len"] = cert.get("chain_len")
        result["cert_subject"] = cert.get("subject")
        result["cert_issuer"] = cert.get("issuer")
        result["cert_valid_from"] = cert.get("valid_from")
        result["cert_valid_until"] = cert.get("valid_until")
        result["cert_days_left"] = cert.get("days_left")
        result["cert_expired"] = cert.get("expired")
        result["cert_san"] = json.dumps(cert.get("san", []))[:2000]

    # ---------- DNS / WHOIS / Email / Subdomains ----------
    if hostname:
        dns_data = enumerate_dns(hostname)
        result["dns_records"] = json.dumps(dns_data)[:4000]
        dns_extra = enumerate_dns_extra(hostname, dns_data)
        result["dns_extra"] = json.dumps(dns_extra)[:4000]
        result["dnssec"] = 1 if dns_extra.get("dnssec") else 0
        # v4
        dns_modern = enumerate_dns_modern(hostname)
        if dns_modern: result["dns_modern"] = json.dumps(dns_modern)[:3000]
        result["wildcard_dns"] = check_wildcard_dns(hostname)
        result["email_security"] = json.dumps(analyze_email_security(hostname, dns_extra))[:2000]
        result["subdomains"] = json.dumps(get_subdomains_crtsh(hostname))[:5000]
        result["ct_logs_count"] = check_ct_logs(hostname)
        # HSTS preload
        result["hsts_preloaded"] = check_hsts_preload(hostname)
        # AXFR
        ns_list = dns_data.get("ns", [])[:3]
        if ns_list: result["dns_zone_transfer"] = try_zone_transfer(hostname, ns_list)
        whois_data = get_whois(hostname)
        if whois_data: result["whois_data"] = json.dumps(whois_data)[:4000]
        # FIX : reverse DNS sur l'IP résolue, pas sur le FQDN
        try:
            if ip:
                result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    # ---------- Géo ----------
    if ip:
        geo = get_geolocation(ip)
        if geo: result["geolocation"] = json.dumps(geo)[:2000]
        # v4 : Shodan InternetDB
        shodan = shodan_internetdb(ip)
        if shodan: result["shodan_internetdb"] = json.dumps(shodan)[:3000]

    # ---------- Favicon ----------
    result["favicon_hash"] = get_favicon_hash(url)

    # ---------- Wayback ----------
    wb = wayback_check(url)
    if wb: result["wayback"] = json.dumps(wb)[:1000]

    # ---------- Crawl + social ----------
    if do_crawl:
        links = crawl_links(url, max_links=50)
        result["links_count"] = len(links)
        result["links_json"] = json.dumps(links)[:8000]
        soc = extract_social_links(links)
        if soc: result["social_links"] = json.dumps(soc)[:2000]

    # ---------- Screenshot ----------
    if do_screenshot and job_id:
        fname = f"job{job_id}_{re.sub(r'[^a-zA-Z0-9]', '_', (ip or hostname or 'x'))[:20]}.png"
        result["screenshot"] = capture_screenshot(url, fname)

    return result


def masscan_discover(target, ports="1-65535", rate=1000):
    cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}", "--open-only", "-oJ", "-"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return []
    out = []
    for line in result.stdout.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"): continue
        try:
            entry = json.loads(line)
            ip = entry.get("ip")
            for p in entry.get("ports", []):
                if p.get("status") == "open": out.append((ip, p["port"]))
        except json.JSONDecodeError: continue
    return out


def nmap_fingerprint(open_ports, version_scan=False, os_scan=False, ssl_enum=False):
    if not open_ports: return []
    by_ip = {}
    for ip, port in open_ports:
        by_ip.setdefault(ip, []).append(port)
    results = []; nm = nmap.PortScanner()
    if ssl_enum: args = "-sV -T4 --script ssl-enum-ciphers"
    elif os_scan: args = "-sV -O -T4 --open"
    elif version_scan: args = "-sV -T4"
    else: args = "-T4"
    for ip, ports in by_ip.items():
        port_str = ",".join(str(p) for p in sorted(set(ports)))
        try: nm.scan(hosts=ip, ports=port_str, arguments=args)
        except Exception: continue
        osmatch = nm[ip].get("osmatch", []) if ip in nm.all_hosts() else []
        os_name = osmatch[0].get("name", "")[:100] if osmatch else None
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto].keys():
                info = nm[ip][proto][port]
                result = {"ip": ip, "port": port, "protocol": proto,
                    "service": info.get("name", "unknown"),
                    "version": f"{info.get('product','')} {info.get('version','')}".strip(),
                    "state": info.get("state", "open"), "os_guess": os_name}
                if ssl_enum and "script" in info:
                    for sname, sdata in info["script"].items():
                        if "ssl-enum" in sname:
                            result["ssl_ciphers"] = sdata[:4000]
                results.append(result)
    return results


def probe_unknown(ip, port):
    probes = {"http": b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
              "ssh": b"SSH-2.0-Probe\r\n", "smtp": b"EHLO probe\r\n",
              "ftp": b"USER anonymous\r\n"}
    for name, payload in probes.items():
        try:
            with socket.create_connection((ip, port), timeout=2) as s:
                s.sendall(payload); data = s.recv(256)
                if name == "http" and b"HTTP/" in data: return "http"
                if name == "ssh" and b"SSH-" in data: return "ssh"
                if name == "smtp" and b"220" in data: return "smtp"
                if name == "ftp" and b"220" in data: return "ftp"
        except (socket.timeout, ConnectionRefusedError, OSError): continue
    return "unknown"


def _enrich_ip_results(results):
    ip_meta = {}
    for r in results:
        ip = r.get("ip")
        if not ip: continue
        if ip in ip_meta:
            r["reverse_dns"] = ip_meta[ip]["reverse_dns"]
            r["geolocation"] = ip_meta[ip]["geolocation"]
            r["shodan_internetdb"] = ip_meta[ip]["shodan_internetdb"]
            continue
        meta = {"reverse_dns": None, "geolocation": None, "shodan_internetdb": None}
        try: meta["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception: pass
        geo = get_geolocation(ip)
        if geo: meta["geolocation"] = json.dumps(geo)[:2000]
        # v4 : Shodan InternetDB
        shodan = shodan_internetdb(ip)
        if shodan: meta["shodan_internetdb"] = json.dumps(shodan)[:3000]
        ip_meta[ip] = meta
        r["reverse_dns"] = meta["reverse_dns"]
        r["geolocation"] = meta["geolocation"]
        r["shodan_internetdb"] = meta["shodan_internetdb"]
    return results


def scan_target(target, ports="1-1000", mode="balanced", prior_ips=None, job_id=None):
    ttype = detect_target_type(target)

    if ttype == "url":
        info = resolve_target(target)
        if not info["ips"]:
            return [{**BASE_KEYS, "ip": "0.0.0.0", "port": 0, "protocol": "tcp",
                     "service": "dns_error", "version": "", "state": "error", "url": target}]
        results = []
        for ip in info["ips"][:1]:
            full = scan_url_full(info["url"], ip=ip, job_id=job_id,
                                 do_crawl=True, do_screenshot=True)
            full.update({"ip": ip,
                         "port": 443 if info["scheme"] == "https" else 80,
                         "protocol": "tcp", "service": info["scheme"],
                         "version": full.get("tls_version") or "", "state": "open"})
            results.append(full)
            web_ports = "80,443,8080,8443,3000,5000,8000"
            open_ports = masscan_discover(ip, web_ports, rate=500)
            if open_ports:
                for r in nmap_fingerprint(open_ports, version_scan=False):
                    results.append({**BASE_KEYS, **r, "url": info["url"]})
        return results

    if mode == "fast":
        return [{**BASE_KEYS, "ip": ip, "port": p, "protocol": "tcp",
                 "service": "unknown", "version": "", "state": "open", "os_guess": None}
                for ip, p in masscan_discover(target, ports, rate=2000)]

    if mode == "deep":
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments="-sV -O -T4 --open")
        results = []
        for host in nm.all_hosts():
            osmatch = nm[host].get("osmatch", [])
            os_name = osmatch[0].get("name", "")[:100] if osmatch else None
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info = nm[host][proto][port]
                    results.append({**BASE_KEYS, "ip": host, "port": port, "protocol": proto,
                        "service": info.get("name", "unknown"),
                        "version": f"{info.get('product','')} {info.get('version','')}".strip(),
                        "state": info.get("state", "open"), "os_guess": os_name})
        return _enrich_ip_results(results)

    rate = 1000 if mode in ("balanced", "smart") else 3000
    open_ports = masscan_discover(target, ports, rate=rate)
    results = nmap_fingerprint(open_ports, version_scan=True)
    for r in results:
        if r.get("service") in ("unknown", "tcpwrapped", ""):
            detected = probe_unknown(r["ip"], r["port"])
            if detected != "unknown": r["service"] = detected
        for k, v in BASE_KEYS.items(): r.setdefault(k, v)
    return _enrich_ip_results(results)
PYEOF

# ============================================================
# tasks.py — FIX db.get + alias celery
# ============================================================
cat > backend/tasks.py <<'EOF'
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from scanner import scan_target
from database import SessionLocal
from models import ScanJob, HostResult
from datetime import datetime, timedelta
import os

celery_app = Celery("scanner",
    broker=os.getenv("REDIS_URL", "redis://redis:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://redis:6379/0"))
celery_app.conf.broker_connection_retry_on_startup = True
celery_app.conf.task_time_limit = 300
celery_app.conf.task_soft_time_limit = 260

# FIX : alias requis par `celery -A tasks worker`
celery = celery_app
app = celery_app

def get_prior_ips(db):
    cutoff = datetime.utcnow() - timedelta(days=7)
    rows = (db.query(HostResult.ip).filter(HostResult.last_seen > cutoff)
              .filter(HostResult.state == "open").distinct().all())
    return [r[0] for r in rows]

@celery_app.task(time_limit=300, soft_time_limit=260)
def run_scan(job_id):
    db = SessionLocal()
    # FIX : SQLAlchemy 2.0 — Query.get() supprimé
    job = db.get(ScanJob, job_id)
    if job is None:
        db.close()
        return
    job.status = "running"; db.commit()
    try:
        prior = get_prior_ips(db) if job.mode == "smart" else None
        results = scan_target(job.target, job.ports, mode=job.mode,
                              prior_ips=prior, job_id=job.id)
        now = datetime.utcnow()
        for r in results:
            db.add(HostResult(job_id=job.id, last_seen=now, **r))
        job.status = "done"
    except SoftTimeLimitExceeded:
        job.status = "error"; print(f"Timeout: job {job_id} > 260s")
    except Exception as e:
        job.status = "error"; print("Erreur:", e)
    finally:
        db.commit(); db.close()
EOF

# ============================================================
# main.py — FIX db.get
# ============================================================
cat > backend/main.py <<'EOF'
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from database import SessionLocal, engine
from models import Base, ScanJob, HostResult
from tasks import run_scan
from scanner import detect_target_type
import os, traceback

Base.metadata.create_all(bind=engine)
app = FastAPI(title="IP Expert Scanner v4")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    mode: str = "balanced"

FIELDS = ["ip","port","service","version","state","protocol","url","http_status",
    "server_header","title","redirect_to","redirect_chain","content_type",
    "content_size","charset","response_time_ms","http_methods","powered_by",
    "cache_control","http2","http3","compression",
    "server_timing","cache_detail","x_robots_tag","content_language","raw_headers",
    "security_headers","security_score","security_missing",
    "modern_headers","modern_missing","modern_score","security_score_ext",
    "hsts_max_age","hsts_preload","hsts_preloaded",
    "cookies","cookies_detail","sensitive_paths","robots_txt",
    "security_txt","sitemap_found","meta_refresh",
    "tls_version","tls_cipher","tls_versions_supported","cert_chain_len",
    "cert_subject","cert_issuer","cert_valid_from","cert_valid_until",
    "cert_days_left","cert_expired","cert_san","ssl_ciphers",
    "links_count","links_json","technologies","screenshot",
    "meta_tags","emails","social_links","favicon_hash","html_stats","structured_data",
    "html_comments","js_endpoints","script_srcs","asset_urls","i18n","forms_detail",
    "dns_records","dns_extra","dns_modern","wildcard_dns","dnssec",
    "dns_zone_transfer","email_security","subdomains","ct_logs_count",
    "whois_data","geolocation","reverse_dns",
    "shodan_internetdb","wayback",
    "waf","cdn","os_guess"]

@app.post("/api/scan")
def create_scan(req: ScanRequest):
    ttype = detect_target_type(req.target)
    mode = "url" if ttype == "url" else req.mode
    if mode not in ("fast", "balanced", "deep", "smart", "url"):
        raise HTTPException(400, "Mode invalide")
    db = SessionLocal()
    try:
        job = ScanJob(target=req.target, target_type=ttype, ports=req.ports, mode=mode)
        db.add(job); db.commit(); db.refresh(job)
        try: run_scan.delay(job.id)
        except Exception as e:
            traceback.print_exc(); job.status = "error"; db.commit()
            raise HTTPException(503, detail=f"File d'attente indisponible: {e}")
        return {"job_id": job.id, "status": "pending", "mode": mode, "target_type": ttype}
    finally: db.close()

@app.get("/api/jobs/{job_id}")
def get_job(job_id: int):
    db = SessionLocal()
    # FIX : SQLAlchemy 2.0 — Query.get() supprimé
    job = db.get(ScanJob, job_id)
    if not job: raise HTTPException(404, "Job introuvable")
    results = [{f: getattr(r, f, None) for f in FIELDS} for r in job.results]
    db.close()
    return {"id": job.id, "status": job.status, "target": job.target,
            "target_type": job.target_type, "mode": job.mode, "results": results}

if os.path.isdir("/app/screenshots"):
    app.mount("/screenshots", StaticFiles(directory="/app/screenshots"), name="screenshots")
if os.path.isdir("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
EOF

# ============================================================
# docker-compose.yml
# ============================================================
cat > docker-compose.yml <<EOF
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: scanner
      POSTGRES_PASSWORD: scanner
      POSTGRES_DB: scanner
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck: {test: ["CMD-SHELL", "pg_isready -U scanner"], interval: 5s, retries: 5}
  redis:
    image: redis:7
    ports: ["127.0.0.1:6379:6379"]
    healthcheck: {test: ["CMD", "redis-cli", "ping"], interval: 3s, timeout: 2s, retries: 20}
  api:
    build: ./backend
    ports: ["${APP_PORT}:8000"]
    volumes: ["./frontend:/app/static:ro", "./screenshots:/app/screenshots"]
    depends_on:
      db: {condition: service_healthy}
      redis: {condition: service_healthy}
    environment:
      DATABASE_URL: postgresql://scanner:scanner@db:5432/scanner
      REDIS_URL: redis://redis:6379/0
    healthcheck:
      test: ["CMD-SHELL", "curl -sf --max-time 3 -o /dev/null http://localhost:8000/openapi.json || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 30
      start_period: 20s
  worker:
    build: ./backend
    command:
      - sh
      - -c
      - |
        python -c "from database import engine; from models import Base; Base.metadata.create_all(bind=engine)"
        exec celery -A tasks worker --loglevel=info --concurrency=2
    cap_add: [NET_RAW, NET_ADMIN]
    shm_size: "2gb"
    volumes: ["./screenshots:/app/screenshots"]
    depends_on:
      db: {condition: service_healthy}
      redis: {condition: service_healthy}
      api: {condition: service_healthy}
    environment:
      DATABASE_URL: postgresql://scanner:scanner@db:5432/scanner
      REDIS_URL: redis://redis:6379/0
volumes:
  pgdata:
EOF

# ============================================================
# FRONTEND v4
# ============================================================
cat > frontend/index.html <<'HTML'
<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP EXPERT // Scanner v4</title>
<style>
:root{--bg:#0d0221;--panel:#150a2e;--line:#3a1a5c;--pink:#ff2d95;--pink2:#ff006e;
--pink3:#ff66b3;--ok:#00ff9d;--warn:#ffb800;--cyan:#00f0ff;--txt:#f0e6ff;--dim:#8a6ba8;
--mono:'Roboto Mono',ui-monospace,monospace;--sans:'Inter',system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{background:var(--bg);color:var(--txt);font-family:var(--sans);overflow-x:hidden;min-height:100vh}
.bg-svg{position:fixed;inset:0;z-index:0;pointer-events:none;width:100%;height:100%}
body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
background:radial-gradient(circle at 50% 0%,rgba(255,45,149,.16),transparent 55%)}
.wrap{position:relative;z-index:1;max-width:1600px;margin:0 auto;padding:32px 24px 80px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:40px;flex-wrap:wrap;gap:16px}
.logo{display:flex;align-items:center;gap:14px}
.logo-mark svg{width:52px;height:52px;filter:drop-shadow(0 0 14px rgba(255,45,149,.7))}
.logo h1{font-family:var(--mono);font-size:20px;letter-spacing:3px;color:#fff;text-shadow:0 0 20px rgba(255,45,149,.7)}
.logo h1 span{color:var(--pink);text-shadow:0 0 30px var(--pink),0 0 60px var(--pink2)}
.status-badge{font-family:var(--mono);font-size:11px;letter-spacing:2px;padding:8px 14px 8px 10px;
border:1px solid var(--pink);border-radius:20px;display:flex;align-items:center;gap:8px;
color:var(--pink3);background:rgba(255,45,149,.06);box-shadow:0 0 20px rgba(255,45,149,.2)}
.status-badge svg{width:14px;height:14px}
.console{background:linear-gradient(180deg,rgba(21,10,46,.92),rgba(21,10,46,.6));
border:1px solid var(--line);border-radius:16px;padding:24px;backdrop-filter:blur(10px);
box-shadow:0 0 50px rgba(255,45,149,.12);margin-bottom:28px;position:relative;overflow:hidden}
.console-title{font-family:var(--mono);font-size:11px;letter-spacing:3px;color:var(--pink3);
margin-bottom:18px;display:flex;align-items:center;gap:10px;text-shadow:0 0 12px rgba(255,45,149,.5)}
.console-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(255,45,149,.5),transparent)}
.input-row{display:flex;gap:14px;flex-wrap:wrap}
.field{flex:1;min-width:180px;position:relative}
.field label{position:absolute;top:-9px;left:14px;padding:0 6px;background:var(--panel);
font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--pink);text-transform:uppercase}
.field input,.field select{width:100%;padding:16px 14px;background:rgba(13,2,33,.9);
border:1px solid var(--line);border-radius:10px;color:#fff;font-family:var(--mono);font-size:14px}
.field input:focus,.field select:focus{outline:none;border-color:var(--pink);
box-shadow:0 0 0 1px var(--pink),0 0 30px rgba(255,45,149,.45)}
.field input::placeholder{color:var(--dim)}
.btn-scan{padding:16px 34px;border:none;border-radius:10px;cursor:pointer;
font-family:var(--mono);font-size:13px;letter-spacing:3px;font-weight:700;color:#fff;
background:linear-gradient(135deg,var(--pink),var(--pink2));
box-shadow:0 0 30px rgba(255,45,149,.7);transition:all .2s;display:flex;align-items:center;gap:10px;justify-content:center}
.btn-scan:hover{transform:translateY(-2px);box-shadow:0 0 50px rgba(255,45,149,1)}
.btn-scan:disabled{opacity:.5;cursor:not-allowed;transform:none}
.progress{height:3px;background:var(--line);border-radius:2px;margin-top:20px;overflow:hidden;display:none}
.progress.active{display:block}
.progress-bar{height:100%;width:0;background:linear-gradient(90deg,var(--pink3),var(--pink),var(--pink2));
transition:width .3s;box-shadow:0 0 16px var(--pink)}
.status-line{font-family:var(--mono);font-size:12px;letter-spacing:1px;color:var(--dim);margin-top:14px;min-height:18px;word-break:break-word}
.status-line .ok{color:var(--ok)}.status-line .err{color:var(--pink2)}
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
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:12px 8px;font-family:var(--mono);font-size:10px;letter-spacing:1px;
color:var(--pink3);text-transform:uppercase;background:rgba(13,2,33,.7);
border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:12px 8px;border-bottom:1px solid rgba(58,26,92,.5);font-family:var(--mono);vertical-align:top}
tr:last-child td{border-bottom:none}tbody tr:hover td{background:rgba(255,45,149,.06)}
.ip{color:var(--pink);font-weight:600;cursor:pointer;text-shadow:0 0 10px rgba(255,45,149,.5)}
.port{color:var(--warn)}.svc{color:#fff}.ver{color:var(--dim);font-size:11px}
.state .pill{padding:3px 10px;border-radius:20px;background:rgba(0,255,157,.1);
border:1px solid rgba(0,255,157,.4);box-shadow:0 0 10px rgba(0,255,157,.2);color:var(--ok);font-size:11px}
.url-cell{max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--cyan);font-size:11px}
.http-status{font-weight:700}
.http-2xx{color:var(--ok)}.http-3xx{color:var(--warn)}.http-4xx,.http-5xx{color:var(--pink2)}
.title-cell{max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#fff;font-size:11px}
.tls-cell{color:var(--cyan);font-size:10px}
.cert-days{font-size:11px;font-weight:700;cursor:pointer}
.cert-ok{color:var(--ok)}.cert-warn{color:var(--warn)}.cert-err{color:var(--pink2)}
.tech-badge{display:inline-block;padding:2px 6px;border-radius:8px;margin:1px;
background:rgba(255,45,149,.15);border:1px solid rgba(255,45,149,.4);color:var(--pink3);font-size:10px}
.waf-badge{display:inline-block;padding:2px 6px;border-radius:8px;margin:1px;
background:rgba(255,184,0,.15);border:1px solid rgba(255,184,0,.4);color:var(--warn);font-size:10px}
.geo-cell{font-size:11px;color:var(--cyan);max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.links-badge{display:inline-block;padding:2px 8px;border-radius:10px;
background:rgba(0,240,255,.1);border:1px solid rgba(0,240,255,.3);color:var(--cyan);
font-size:10px;cursor:pointer;text-decoration:none;margin:1px}
.links-badge:hover{background:rgba(0,240,255,.2)}
.shot-thumb{width:56px;height:38px;object-fit:cover;border-radius:6px;
border:1px solid var(--pink);box-shadow:0 0 10px rgba(255,45,149,.4);cursor:pointer}
.empty{padding:60px 24px;text-align:center;font-family:var(--mono);color:var(--dim);font-size:13px}
.empty .big{font-size:40px;margin-bottom:16px;opacity:.5;text-shadow:0 0 30px var(--pink)}
.radar-spinner{width:32px;height:32px;display:none;margin:0 auto 12px}
footer{margin-top:60px;text-align:center;font-family:var(--mono);font-size:11px;letter-spacing:2px;color:var(--dim)}
footer .warn{color:var(--warn)}
.modal{display:none;position:fixed;inset:0;z-index:100;background:rgba(13,2,33,.92);
backdrop-filter:blur(8px);align-items:center;justify-content:center;padding:24px}
.modal.show{display:flex;animation:fadeIn .3s}
.modal-content{background:var(--panel);border:1px solid var(--pink);border-radius:16px;
max-width:90vw;max-height:90vh;overflow:auto;padding:24px;box-shadow:0 0 60px rgba(255,45,149,.5);position:relative}
.modal-content h3{font-family:var(--mono);color:var(--pink);margin-bottom:16px;letter-spacing:2px}
.modal-content h4{font-family:var(--mono);font-size:12px;margin-top:14px;letter-spacing:1px}
.modal-content img{max-width:100%;border-radius:8px}
.modal-content ul{font-family:var(--mono);font-size:12px;color:var(--txt);line-height:1.8;
max-height:60vh;overflow:auto;padding-left:20px;margin-top:6px}
.modal-content li a{color:var(--cyan);text-decoration:none;word-break:break-all}
.modal-content li a:hover{text-decoration:underline}
.modal-content pre{font-family:var(--mono);font-size:11px;color:var(--dim);
background:rgba(13,2,33,.6);padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto}
.modal-close{position:absolute;top:16px;right:20px;background:none;border:1px solid var(--pink);
color:var(--pink);font-size:18px;width:36px;height:36px;border-radius:50%;cursor:pointer;display:grid;place-items:center}
.modal-close:hover{background:var(--pink);color:#fff}
.kv{font-family:var(--mono);font-size:12px;width:100%}
.kv td{padding:4px 10px;border:none;vertical-align:top}
.kv td:first-child{color:var(--dim);width:35%}
</style></head><body>

<svg class="bg-svg" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice">
<defs><pattern id="grid-p" width="40" height="40" patternUnits="userSpaceOnUse">
<path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,45,149,.07)" stroke-width="1"/></pattern>
<radialGradient id="halo" cx="50%" cy="0%" r="70%">
<stop offset="0%" stop-color="#ff2d95" stop-opacity=".15"/>
<stop offset="100%" stop-color="#ff2d95" stop-opacity="0"/></radialGradient></defs>
<rect width="1440" height="900" fill="url(#halo)"/>
<rect width="1440" height="900" fill="url(#grid-p)"/>
</svg>

<div class="wrap">
<header>
<div class="logo">
<div class="logo-mark"><svg viewBox="0 0 56 56">
<rect x="2" y="2" width="52" height="52" rx="12" fill="none" stroke="#ff2d95" stroke-width="2">
<animate attributeName="stroke-opacity" values="1;.4;1" dur="2.5s" repeatCount="indefinite"/></rect>
<circle cx="28" cy="28" r="14" fill="none" stroke="#ff2d95" stroke-width="1" opacity=".4"/>
<line x1="28" y1="28" x2="28" y2="14" stroke="#ff2d95" stroke-width="2" stroke-linecap="round">
<animateTransform attributeName="transform" type="rotate" from="0 28 28" to="360 28 28" dur="2s" repeatCount="indefinite"/></line>
<circle cx="28" cy="28" r="3" fill="#ff2d95"/>
</svg></div>
<h1>IP <span>EXPERT</span> // SCANNER <span style="font-size:12px;color:var(--pink3);">v4</span></h1>
</div>
<div class="status-badge">
<svg viewBox="0 0 14 14"><circle cx="7" cy="7" r="3" fill="#00ff9d">
<animate attributeName="r" values="3;5;3" dur="1.6s" repeatCount="indefinite"/></circle></svg>
SYSTÈME EN LIGNE
</div>
</header>

<section class="console">
<div class="console-title">◆ TERMINAL DE RECONNAISSANCE — OSINT ULTRA</div>
<div class="input-row">
<div class="field"><label>Cible (IP, CIDR, URL)</label>
<input id="target" placeholder="https://example.com ou 192.168.1.0/24" spellcheck="false"></div>
<div class="field" style="max-width:140px"><label>Ports</label>
<input id="ports" value="1-1000" spellcheck="false"></div>
<div class="field" style="max-width:180px"><label>Mode</label>
<select id="mode">
<option value="fast">⚡ Fast</option>
<option value="balanced" selected>⚖ Balanced</option>
<option value="deep">🔬 Deep (OS)</option>
<option value="smart">🧠 Smart</option>
<option value="url">🌐 URL</option>
</select></div>
<button id="scanBtn" class="btn-scan">
<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="16">
<circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2" fill="currentColor"/></svg>SCAN</button>
</div>
<div class="hint">💡 URL → HTTP/3 · COOP · Shodan · Wayback · TLS probe · JS endpoints · comments · CT logs · forms</div>
<div class="progress" id="progress"><div class="progress-bar" id="progressBar"></div></div>
<svg class="radar-spinner" id="radarSpinner" viewBox="0 0 32 32">
<circle cx="16" cy="16" r="14" fill="none" stroke="#ff2d95" stroke-width="1" opacity=".3"/>
<line x1="16" y1="16" x2="16" y2="4" stroke="#ff2d95" stroke-width="2" stroke-linecap="round">
<animateTransform attributeName="transform" type="rotate" from="0 16 16" to="360 16 16" dur="1.2s" repeatCount="indefinite"/></line>
<circle cx="16" cy="16" r="2" fill="#ff2d95"/></svg>
<div class="status-line" id="statusLine">En attente d'une cible…</div>
</section>

<section class="results-panel" id="resultsPanel">
<div class="results-head"><span>▸ RÉSULTATS DU SCAN</span>
<span class="count" id="resultCount"></span></div>
<div class="tbl-wrap" id="resultsBody">
<div class="empty"><div class="big">◇</div>Aucun résultat pour le moment</div></div>
</section>

<footer><span class="warn">⚠</span> Ne scannez que les réseaux dont vous avez l'autorisation explicite.</footer>
</div>

<div class="modal" id="modal">
<div class="modal-content"><button class="modal-close" onclick="closeModal()">✕</button>
<div id="modalBody"></div></div></div>

<script>
const $ = id => document.getElementById(id);
window.__results = [];
function esc(s){return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
.replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function closeModal(){$('modal').classList.remove('show');}
$('modal').addEventListener('click', e => {if(e.target === $('modal')) closeModal();});
async function extractError(r){try{const t=await r.text();
try{const j=JSON.parse(t);if(j.detail)return `HTTP ${r.status} — ${typeof j.detail==='string'?j.detail:JSON.stringify(j.detail)}`;}catch(_){}
return `HTTP ${r.status} — ${t.slice(0,200)}`;}catch(e){return `HTTP ${r.status}`;}}

async function lancerScan(){
const target=$('target').value.trim(),ports=$('ports').value.trim(),mode=$('mode').value;
if(!target)return;
const btn=$('scanBtn');btn.disabled=true;
$('resultsPanel').classList.remove('show');
$('progress').classList.add('active');$('radarSpinner').style.display='block';
$('progressBar').style.width='10%';
$('statusLine').innerHTML='◇ Mode <b>'+esc(mode)+'</b> — connexion…';
try{
const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({target,ports,mode})});
if(!r.ok)throw new Error(await extractError(r));
const data=await r.json();const job_id=data.job_id;
$('progressBar').style.width='25%';
$('statusLine').innerHTML='◇ Scan <b>'+esc(data.mode)+'</b> ('+esc(data.target_type)+') sur <b>'+esc(target)+'</b>…';
let progress=25;
const interval=setInterval(async()=>{
try{
const jr=await fetch('/api/jobs/'+job_id);
if(!jr.ok){clearInterval(interval);$('progress').classList.remove('active');
$('radarSpinner').style.display='none';
$('statusLine').innerHTML='<span class="err">✗ '+esc(await extractError(jr))+'</span>';
btn.disabled=false;return;}
const job=await jr.json();
progress=Math.min(progress+3,92);$('progressBar').style.width=progress+'%';
if(job.status==='done'){clearInterval(interval);$('progressBar').style.width='100%';
setTimeout(()=>{$('progress').classList.remove('active');$('radarSpinner').style.display='none';},400);
afficherResultats(job.results,job.target_type);
$('statusLine').innerHTML='<span class="ok">✓ Scan terminé</span> — '+job.results.length+' résultat(s)';
btn.disabled=false;}
else if(job.status==='error'){clearInterval(interval);
$('progress').classList.remove('active');$('radarSpinner').style.display='none';
$('statusLine').innerHTML='<span class="err">✗ Erreur ou timeout du scan.</span>';
btn.disabled=false;}
}catch(e){clearInterval(interval);$('progress').classList.remove('active');
$('radarSpinner').style.display='none';
$('statusLine').innerHTML='<span class="err">✗ Connexion perdue: '+esc(e.message)+'</span>';
btn.disabled=false;}
},2000);
}catch(e){
$('progress').classList.remove('active');$('radarSpinner').style.display='none';
$('statusLine').innerHTML='<span class="err">✗ '+esc(e.message)+'</span>';btn.disabled=false;}
}

function httpClass(c){if(!c)return'';if(c>=200&&c<300)return'http-2xx';
if(c>=300&&c<400)return'http-3xx';if(c>=400&&c<500)return'http-4xx';return'http-5xx';}
function certClass(d){if(d===null||d===undefined)return'';if(d<0)return'cert-err';
if(d<30)return'cert-warn';return'cert-ok';}
function secClass(s,max){max=max||75;const r=(s||0)/max;if(r>=0.66)return'cert-ok';
if(r>=0.33)return'cert-warn';return'cert-err';}
function pJ(s,d){try{return s?JSON.parse(s):d;}catch(e){return d;}}

function showCert(row){
const tlsList = pJ(row.tls_versions_supported, []);
$('modalBody').innerHTML=`
<h3>🔒 Certificat SSL + TLS</h3>
<table class="kv">
<tr><td>Sujet</td><td>${esc(row.cert_subject)||'—'}</td></tr>
<tr><td>Émetteur</td><td>${esc(row.cert_issuer)||'—'}</td></tr>
<tr><td>TLS actif</td><td>${esc(row.tls_version)||'—'} ${row.tls_cipher?'· '+esc(row.tls_cipher):''}</td></tr>
<tr><td>Versions supportées</td><td>${tlsList.length?tlsList.map(v=>`<span class="tech-badge">${esc(v)}</span>`).join(' '):'—'}</td></tr>
<tr><td>Chaîne</td><td>${row.cert_chain_len??'—'} certificat(s)</td></tr>
<tr><td>Valide du</td><td>${esc(row.cert_valid_from)||'—'}</td></tr>
<tr><td>Valide au</td><td>${esc(row.cert_valid_until)||'—'}</td></tr>
<tr><td>Expire dans</td><td>${row.cert_days_left??'—'} jours</td></tr>
<tr><td>SAN</td><td style="word-break:break-all">${esc(pJ(row.cert_san,[]).join(', '))}</td></tr>
<tr><td>CT logs</td><td>${row.ct_logs_count??'—'} certs publics</td></tr>
</table>
${row.ssl_ciphers?`<h4>🔐 Ciphers (nmap)</h4><pre>${esc(row.ssl_ciphers)}</pre>`:''}`;
$('modal').classList.add('show');}

function showSecurity(row){
const p=pJ(row.security_headers,{}),m=pJ(row.security_missing,[]);
const pm=pJ(row.modern_headers,{}),mm=pJ(row.modern_missing,[]);
const ck=pJ(row.cookies_detail,[]),paths=pJ(row.sensitive_paths,[]);
$('modalBody').innerHTML=`
<h3>🛡️ Sécurité</h3>
<p class="kv" style="margin-bottom:8px">
<b>Classique : ${row.security_score??0}/75</b> ·
<b>Moderne : ${row.modern_score??0}/55</b> ·
<b style="color:var(--pink)">Total : ${row.security_score_ext??0}/130</b>
</p>
<h4 style="color:var(--ok)">✔ Headers classiques (${Object.keys(p).length}/7)</h4>
<ul style="color:var(--ok)">${Object.entries(p).map(([k,v])=>`<li><b>${esc(k)}</b> : <code>${esc(v)}</code></li>`).join('')||'<li>—</li>'}</ul>
<h4 style="color:var(--cyan)">✔ Headers modernes (${Object.keys(pm).length}/8)</h4>
<ul style="color:var(--cyan)">${Object.entries(pm).map(([k,v])=>`<li><b>${esc(k)}</b> : <code>${esc(v)}</code></li>`).join('')||'<li>—</li>'}</ul>
<h4 style="color:var(--pink2)">✘ Manquants (classique + moderne)</h4>
<ul style="color:var(--pink2)">${[...m,...mm].map(x=>`<li>${esc(x)}</li>`).join('')||'<li>—</li>'}</ul>
<h4>🔐 HSTS</h4>
<p class="kv">max-age : <b>${row.hsts_max_age??'—'}</b> s · preload flag : <b>${row.hsts_preload?'oui':'non'}</b> · preloaded (hstspreload.org) : <b style="color:${row.hsts_preloaded?'var(--ok)':'var(--dim)'}">${row.hsts_preloaded?'✅ oui':'non'}</b></p>
<h4>🍪 Cookies (${ck.length})</h4>
<table style="font-size:12px;width:100%">
<tr><th>Nom</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th></tr>
${ck.map(c=>`<tr><td>${esc(c.name)}</td>
<td>${c.secure?'✔':'✘'}</td>
<td>${c.httponly?'✔':'✘'}</td>
<td>${esc(c.samesite)||'—'}</td>
<td style="font-size:10px">${esc(c.domain)||'—'}</td></tr>`).join('')||'<tr><td colspan="5">—</td></tr>'}
</table>
${paths.length?`<h4 style="color:var(--warn)">⚠ Chemins sensibles détectés</h4>
<ul>${paths.map(x=>`<li><code>${esc(x.path)}</code> — HTTP ${x.status}</li>`).join('')}</ul>`:''}
${row.robots_txt?`<h4>🤖 robots.txt</h4><pre>${esc(row.robots_txt)}</pre>`:''}
${row.security_txt?`<h4>📜 security.txt</h4><pre>${esc(row.security_txt)}</pre>`:''}
${row.http_methods?`<h4>📡 Méthodes HTTP</h4><p>${esc(row.http_methods)}</p>`:''}
${row.meta_refresh?`<h4>🔄 Meta refresh</h4><p><code>${esc(row.meta_refresh)}</code></p>`:''}`;
$('modal').classList.add('show');}

function showDns(row){
const dns=pJ(row.dns_records,{}),extra=pJ(row.dns_extra,{}),
modern=pJ(row.dns_modern,{}),whois=pJ(row.whois_data,{}),geo=pJ(row.geolocation,{});
$('modalBody').innerHTML=`
<h3>🌐 DNS / WHOIS / Géo</h3>
<h4 style="color:var(--pink3)">DNS de base</h4><pre>${esc(JSON.stringify(dns,null,2))}</pre>
<h4 style="color:var(--pink3)">DNS extra (CAA, SRV, DMARC, DKIM, DNSSEC)</h4>
<pre>${esc(JSON.stringify(extra,null,2))}</pre>
<h4 style="color:var(--pink3)">DNS moderne (HTTPS/SVCB, TLSA)</h4>
<pre>${esc(JSON.stringify(modern,null,2))}</pre>
<p class="kv">🔐 DNSSEC : <b style="color:${row.dnssec?'var(--ok)':'var(--pink2)'}">${row.dnssec?'activé':'absent'}</b></p>
<p class="kv">🌐 Wildcard DNS : <b style="color:${row.wildcard_dns===1?'var(--warn)':'var(--ok)'}">${row.wildcard_dns===1?'détecté':(row.wildcard_dns===0?'non':'erreur')}</b></p>
<p class="kv">⚠ Zone transfer (AXFR) : <b style="color:${row.dns_zone_transfer?'var(--pink2)':'var(--ok)'}">${row.dns_zone_transfer?'POSSIBLE !':'non autorisé'}</b></p>
<p class="kv">📜 CT logs (crt.sh) : <b>${row.ct_logs_count??'—'}</b> certificats publics</p>
<h4 style="color:var(--pink3)">WHOIS</h4><pre>${esc(JSON.stringify(whois,null,2))}</pre>
<h4 style="color:var(--pink3)">Géolocalisation / ASN</h4>
<pre>${esc(JSON.stringify(geo,null,2))}</pre>
<p style="color:var(--dim);margin-top:12px">Reverse DNS : ${esc(row.reverse_dns)||'—'}</p>
${row.os_guess?`<p style="color:var(--dim)">OS nmap : ${esc(row.os_guess)}</p>`:''}`;
$('modal').classList.add('show');}

function showEmail(row){
const e=pJ(row.email_security,{});
$('modalBody').innerHTML=`
<h3>📧 Sécurité Email — Score ${e.score??0}/${e.max??3}</h3>
<table class="kv">
<tr><td>SPF présent</td><td>${e.spf_present?'✅':'❌'}</td></tr>
<tr><td>SPF policy</td><td>${esc(e.spf_policy)||'—'}</td></tr>
<tr><td>DMARC présent</td><td>${e.dmarc_present?'✅':'❌'}</td></tr>
<tr><td>DMARC policy</td><td>${esc(e.dmarc_policy)||'—'}</td></tr>
<tr><td>DKIM présent</td><td>${e.dkim_present?'✅':'❌'}</td></tr>
<tr><td>DKIM selectors</td><td>${esc((e.dkim_selectors||[]).join(', '))||'—'}</td></tr>
</table>`;
$('modal').classList.add('show');}

function showSubs(row){
const subs=pJ(row.subdomains,[]);
$('modalBody').innerHTML=`
<h3>🔎 Sous-domaines (crt.sh) — ${subs.length} trouvés</h3>
<ul>${subs.map(s=>`<li>${esc(s)}</li>`).join('')||'<li style="color:var(--dim)">Aucun</li>'}</ul>`;
$('modal').classList.add('show');}

function showMeta(row){
const m=pJ(row.meta_tags,{}),em=pJ(row.emails,[]),
soc=pJ(row.social_links,[]),stats=pJ(row.html_stats,{}),
sd=pJ(row.structured_data,[]),comments=pJ(row.html_comments,[]),
endpoints=pJ(row.js_endpoints,[]),srcs=pJ(row.script_srcs,[]),
assets=pJ(row.asset_urls,[]),i18n=pJ(row.i18n,{}),forms=pJ(row.forms_detail,[]);
$('modalBody').innerHTML=`
<h3>📄 Meta / OSINT page</h3>
<h4>Meta tags</h4>
<pre>${esc(JSON.stringify(m,null,2))}</pre>
<h4>🌍 i18n</h4>
<pre>${esc(JSON.stringify(i18n,null,2))}</pre>
<h4>💬 Commentaires HTML/JS (${comments.length})</h4>
<ul style="max-height:200px">${comments.map(c=>`<li style="color:var(--dim);font-size:11px">${esc(c)}</li>`).join('')||'<li style="color:var(--dim)">—</li>'}</ul>
<h4>🔌 Endpoints JS (${endpoints.length})</h4>
<ul style="max-height:200px">${endpoints.map(x=>`<li><code>${esc(x)}</code></li>`).join('')||'<li style="color:var(--dim)">—</li>'}</ul>
<h4>📜 Script src (${srcs.length})</h4>
<ul style="max-height:150px">${srcs.map(x=>`<li><code>${esc(x)}</code></li>`).join('')||'<li style="color:var(--dim)">—</li>'}</ul>
<h4>🎨 Assets CSS/IMG (${assets.length})</h4>
<pre style="max-height:150px">${esc(JSON.stringify(assets,null,2))}</pre>
<h4>📝 Formulaires (${forms.length})</h4>
<pre>${esc(JSON.stringify(forms,null,2))}</pre>
<h4>📧 Emails (${em.length})</h4>
<ul>${em.map(x=>`<li>${esc(x)}</li>`).join('')||'<li style="color:var(--dim)">—</li>'}</ul>
<h4>🌐 Réseaux sociaux (${soc.length})</h4>
<ul>${soc.map(s=>`<li><b>${esc(s.network)}</b> — <a href="${esc(s.url)}" target="_blank">${esc(s.url)}</a></li>`).join('')||'<li style="color:var(--dim)">—</li>'}</ul>
<h4>📊 Structure HTML</h4>
<pre>${esc(JSON.stringify(stats,null,2))}</pre>
<h4>🗂️ JSON-LD (${sd.length})</h4>
<pre>${esc(JSON.stringify(sd,null,2))}</pre>
${row.favicon_hash?`<p class="kv" style="margin-top:10px">🔖 Favicon hash (Shodan) : <code>${esc(row.favicon_hash)}</code></p>`:''}`;
$('modal').classList.add('show');}

function showHeaders(row){
const h=pJ(row.raw_headers,{}),st=pJ(row.server_timing,{}),cd=pJ(row.cache_detail,{});
$('modalBody').innerHTML=`<h3>📋 Headers HTTP bruts</h3>
<pre>${esc(JSON.stringify(h,null,2))}</pre>
<h4>⏱️ Server-Timing</h4>
<pre>${esc(JSON.stringify(st,null,2))}</pre>
<h4>💾 Cache</h4>
<pre>${esc(JSON.stringify(cd,null,2))}</pre>
<h4>🔁 Redirect chain</h4>
<pre>${esc(JSON.stringify(pJ(row.redirect_chain,[]),null,2))}</pre>
<p class="kv">HTTP/2 : <b>${row.http2?'✅':'❌'}</b> · HTTP/3 : <b>${row.http3?'✅':'❌'}</b></p>
<p class="kv">Compression : ${esc(row.compression)||'—'}</p>
<p class="kv">X-Robots-Tag : ${esc(row.x_robots_tag)||'—'}</p>
<p class="kv">Content-Language : ${esc(row.content_language)||'—'}</p>
<p class="kv">X-Powered-By : ${esc(row.powered_by)||'—'}</p>`;
$('modal').classList.add('show');}

function showShodan(row){
const s=pJ(row.shodan_internetdb,{}),wb=pJ(row.wayback,{});
$('modalBody').innerHTML=`
<h3>🛰️ Shodan InternetDB + Wayback</h3>
<h4>Shodan InternetDB (gratuit)</h4>
<pre>${esc(JSON.stringify(s,null,2))}</pre>
${(s.ports||[]).length?`<p class="kv">Ports indexés : ${(s.ports||[]).map(p=>`<span class="tech-badge">${p}</span>`).join(' ')}</p>`:''}
${(s.vulns||[]).length?`<p class="kv" style="color:var(--pink2)">⚠ Vulns : ${(s.vulns||[]).map(v=>`<span class="tech-badge" style="background:rgba(255,45,149,.3)">${esc(v)}</span>`).join(' ')}</p>`:''}
<h4>Wayback Machine</h4>
${wb.available?`<p class="kv">Dernier snapshot : <a href="${esc(wb.url)}" target="_blank" style="color:var(--cyan)">${esc(wb.timestamp)}</a></p>`:'<p style="color:var(--dim)">Pas de snapshot archivé</p>'}`;
$('modal').classList.add('show');}

function showLinks(row){
const l=pJ(row.links_json,[]);
const html=l.length?`<ul>${l.map(x=>`<li><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.url)}</a>${x.text?' — '+esc(x.text):''}</li>`).join('')}</ul>`:
'<p style="color:var(--dim)">Aucun lien trouvé</p>';
$('modalBody').innerHTML=`<h3>🕷️ Liens (${l.length})</h3>${html}`;
$('modal').classList.add('show');}

function showScreenshot(f){
$('modalBody').innerHTML=`<h3>📸 Screenshot</h3><img src="/screenshots/${esc(f)}" alt="screenshot">`;
$('modal').classList.add('show');}

function afficherResultats(results, targetType){
window.__results=results;
$('resultsPanel').classList.add('show');
$('resultCount').textContent=results.length+' ligne(s)';
const body=$('resultsBody');
if(!results.length){body.innerHTML='<div class="empty"><div class="big">◇</div>Aucun résultat</div>';return;}

if(targetType==='url'){
body.innerHTML=`
<table>
<thead><tr>
<th>URL</th><th>IP</th><th>HTTP</th><th>Titre</th>
<th>Tech</th><th>WAF/CDN</th><th>Sécu</th><th>Modern</th><th>Total</th><th>Cert</th>
<th>H3</th><th>Email</th><th>Subs</th><th>CT</th><th>Géo</th><th>Perf</th>
<th>Liens</th><th>📄</th><th>📋</th><th>🛰️</th><th>📸</th>
</tr></thead><tbody>
${results.map((r,i)=>{
const tech=pJ(r.technologies,[]),geo=pJ(r.geolocation,{}),
emailSec=pJ(r.email_security,{}),subs=pJ(r.subdomains,[]);
return `<tr>
<td class="url-cell" title="${esc(r.url)}">${esc(r.url)||'—'}</td>
<td class="ip" onclick="showDns(window.__results[${i}])">${esc(r.ip)}</td>
<td class="http-status ${httpClass(r.http_status)}">${r.http_status||'—'}</td>
<td class="title-cell" title="${esc(r.title)}">${esc(r.title)||'—'}</td>
<td title="${esc(tech.join(', '))}">${tech.slice(0,2).map(t=>`<span class="tech-badge">${esc(t)}</span>`).join(' ')}
${tech.length>2?`<span class="tech-badge">+${tech.length-2}</span>`:''}</td>
<td>${r.waf?`<span class="waf-badge">${esc(r.waf)}</span>`:''}
${r.cdn?`<span class="tech-badge">${esc(r.cdn)}</span>`:''}${!r.waf&&!r.cdn?'<span style="color:var(--dim)">—</span>':''}</td>
<td class="cert-days ${secClass(r.security_score,75)}"
onclick="showSecurity(window.__results[${i}])">${r.security_score??'—'}/75</td>
<td class="cert-days ${secClass(r.modern_score,55)}"
onclick="showSecurity(window.__results[${i}])">${r.modern_score??'—'}/55</td>
<td class="cert-days ${secClass(r.security_score_ext,130)}"
onclick="showSecurity(window.__results[${i}])" style="color:var(--pink)"><b>${r.security_score_ext??'—'}/130</b></td>
<td class="cert-days ${certClass(r.cert_days_left)}"
onclick="showCert(window.__results[${i}])">${r.cert_days_left!==null&&r.cert_days_left!==undefined?r.cert_days_left+'j':'—'}</td>
<td style="font-size:11px;text-align:center">${r.http3?'<span style="color:var(--ok)">✅</span>':'<span style="color:var(--dim)">—</span>'}</td>
<td class="cert-days ${secClass((emailSec.score||0)*25,75)}" style="font-size:10px"
onclick="showEmail(window.__results[${i}])">${emailSec.score??0}/${emailSec.max??3}</td>
<td>${subs.length?`<a class="links-badge" onclick="showSubs(window.__results[${i}])">${subs.length}🔎</a>`:'—'}</td>
<td style="font-size:10px">${r.ct_logs_count??'—'}</td>
<td class="geo-cell">${geo.country_code?`<b>${esc(geo.country_code)}</b>`:'—'}</td>
<td class="tls-cell">${r.response_time_ms??'—'}ms</td>
<td>${r.links_count?`<a class="links-badge" onclick="showLinks(window.__results[${i}])">${r.links_count}🔗</a>`:'—'}</td>
<td><a class="links-badge" onclick="showMeta(window.__results[${i}])">📄</a></td>
<td><a class="links-badge" onclick="showHeaders(window.__results[${i}])">📋</a></td>
<td><a class="links-badge" onclick="showShodan(window.__results[${i}])">🛰️</a></td>
<td>${r.screenshot?`<img src="/screenshots/${esc(r.screenshot)}" class="shot-thumb" onclick="showScreenshot('${esc(r.screenshot)}')">`:'—'}</td>
</tr>`;}).join('')}
</tbody></table>`;
} else {
body.innerHTML=`
<table><thead><tr>
<th>Adresse IP</th><th>Port</th><th>Proto</th><th>Service</th>
<th>Version</th><th>OS</th><th>Géo</th><th>Shodan</th><th>État</th>
</tr></thead><tbody>
${results.map((r,i)=>{
const geo=pJ(r.geolocation,{}),shodan=pJ(r.shodan_internetdb,{});
const shPorts=(shodan.ports||[]).length;
return `<tr>
<td class="ip" onclick="showDns(window.__results[${i}])">${esc(r.ip)}</td>
<td class="port">${r.port}</td>
<td>${esc((r.protocol||'').toUpperCase())}</td>
<td class="svc">${esc(r.service)||'—'}</td>
<td class="ver">${esc(r.version)||'—'}</td>
<td class="ver">${esc(r.os_guess)||'—'}</td>
<td class="geo-cell">${geo.country_code?`<b>${esc(geo.country_code)}</b>`:'—'}</td>
<td>${shPorts?`<a class="links-badge" onclick="showShodan(window.__results[${i}])">${shPorts}🛰️</a>`:'—'}</td>
<td class="state"><span class="pill">${esc(r.state)||'—'}</span></td>
</tr>`;}).join('')}
</tbody></table>`;
}}

$('scanBtn').addEventListener('click', lancerScan);
$('target').addEventListener('keydown', e => {if(e.key==='Enter') lancerScan();});
$('ports').addEventListener('keydown', e => {if(e.key==='Enter') lancerScan();});
</script>
</body></html>
HTML

ok "Frontend généré."

# ============================================================
# Build + démarrage
# ============================================================
log "Construction des images..."
docker compose build api worker
log "Démarrage des services..."
docker compose up -d

log "Attente de l'API..."
for i in {1..90}; do
  if curl -s "http://localhost:${APP_PORT}/api/jobs/0" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "200|404"; then break; fi
  sleep 2
done

log "Vérification des dépendances..."
if docker compose exec -T api python -c "import packaging, kombu, whois, dns, nmap, mmh3; print('OK')" 2>/dev/null; then
  ok "Dépendances Python OK"
else
  fail "Dépendances manquantes → rebuild."
fi

log "Vérification import analyze_email_security..."
if docker compose exec -T api python -c "from intel import analyze_email_security; print('OK')" 2>/dev/null; then
  ok "analyze_email_security importable"
else
  fail "intel.py cassé — analyze_email_security manquant."
fi

log "Ping Celery..."
CELERY_OK=0
for i in {1..10}; do
  if docker compose exec -T worker celery -A tasks inspect ping 2>/dev/null | grep -q "pong"; then
    ok "Worker Celery répond"; CELERY_OK=1; break
  fi
  sleep 1
done
[[ $CELERY_OK -eq 0 ]] && echo -e "${YEL}[!]${NC} Worker ne répond pas — voir docker compose logs worker"

ok "=============================================="
ok " IP EXPERT SCANNER v4 — OSINT ULTRA"
ok " Interface : http://localhost:${APP_PORT}"
ok " API docs  : http://localhost:${APP_PORT}/docs"
ok "=============================================="
echo ""
echo -e "${CYAN}Nouveautés v4 :${NC}"
echo "  🌐 HTTP/3          → détection via Alt-Svc"
echo "  ⏱️  Server-Timing   → latences edge (slb_crtt, slb_ssl…)"
echo "  🛡️  Headers modernes → COOP, COEP, CORP, OAC, Reporting-Endpoints, Document-Policy"
echo "  📊 Score étendu    → classique /75 + moderne /55 = /130"
echo "  🔐 HSTS preload    → status hstspreload.org"
echo "  🔒 TLS probe       → teste TLS 1.0/1.1/1.2/1.3"
echo "  🌍 DNS moderne     → HTTPS/SVCB (type 65), TLSA (type 52)"
echo "  🔀 Wildcard DNS    → détection wildcard A"
echo "  📜 CT logs count   → nombre de certs dans les logs publics"
echo "  🛰️  Shodan InternetDB → ports/hostnames/CPEs/vulns (gratuit, sans clé)"
echo "  🕰️  Wayback Machine → dernier snapshot archivé"
echo "  💬 HTML comments   → leak potentiel dans les commentaires"
echo "  🔌 JS endpoints    → /api/*, fetch, axios détectés"
echo "  📜 Script srcs     → liste <script src>"
echo "  🎨 Asset URLs      → CSS + images"
echo "  🌍 i18n            → lang + hreflang"
echo "  📝 Forms detail    → action, method, inputs, CSRF tokens"
echo "  🍪 Cookies detail  → SameSite value, Domain, Path"
echo "  🔄 Meta refresh    → détection"
echo "  💾 Cache detail    → Age, X-Cache, X-Cache-Hits, Vary"
echo "  📡 X-Robots-Tag / Content-Language"
echo ""
echo -e "${RED}⚠ Ne scannez que des réseaux autorisés.${NC}"
