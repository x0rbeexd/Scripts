#!/usr/bin/env python3
"""
jsrecon.py  —  JavaScript Recon Tool for Authorized Pentests
=============================================================
What it does:
  1. Crawls target host for ALL .js files (inline + external + dynamic imports)
  2. Follows source maps if present (.js.map) for original source
  3. Beautifies / de-minifies every file with jsbeautifier
  4. Scans for secrets: API keys, tokens, passwords, IPs, cloud creds, JWTs...
  5. Extracts all endpoints: REST paths, GraphQL, WebSocket, fetch/axios/XHR calls
  6. Detects framework (React/Vue/Angular/Next/Nuxt/etc.)
  7. Saves everything to an output dir, produces endpoints.json + secrets.json

Usage:
  python3 jsrecon.py -u https://target.com
  python3 jsrecon.py -u https://target.com/gis/ -c "albert_sso=abc" --proxy 127.0.0.1:8080
  python3 jsrecon.py -u https://target.com --depth 3 --no-beautify
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from bs4 import BeautifulSoup

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════
#  COLOURS
# ═══════════════════════════════════════════════
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"

BANNER = f"""{B}
     _  ____    ____
    | |/ ___|  |  _ \\ ___  ___ ___  _ __
 _  | |\\___ \\  | |_) / _ \\/ __/ _ \\| '_ \\
| |_| | ___) | |  _ <  __/ (_| (_) | | | |
 \\___/ |____/  |_| \\_\\___|\\___\\___/|_| |_|
{C}  JS Recon  |  Download · Deobfuscate · Secrets · Endpoints{RST}
"""

# ═══════════════════════════════════════════════
#  SECRET PATTERNS  (critical thinking section)
# ═══════════════════════════════════════════════
# Each entry: (name, regex, severity, context_note)
SECRET_PATTERNS = [

    # ── API Keys / Tokens ──────────────────────────────────────────
    ("AWS Access Key",
     r'AKIA[0-9A-Z]{16}', "CRITICAL",
     "AWS access key — pair with secret to auth"),

    ("AWS Secret Key",
     r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key["\s:=]+["\']?([A-Za-z0-9/+=]{40})',
     "CRITICAL", "AWS secret — full account access if paired with access key"),

    ("GCP Service Account Key",
     r'"type"\s*:\s*"service_account"', "CRITICAL",
     "GCP SA key JSON embedded"),

    ("GCP API Key",
     r'AIza[0-9A-Za-z\-_]{35}', "HIGH",
     "GCP/Firebase API key"),

    ("Firebase URL",
     r'https://[a-zA-Z0-9\-]+\.firebaseio\.com', "MEDIUM",
     "Firebase DB — check for unauthenticated read/write"),

    ("Firebase Config",
     r'apiKey\s*:\s*["\']AIza[0-9A-Za-z\-_]{35}["\']', "HIGH",
     "Firebase client config — check rules"),

    ("Azure Storage Key",
     r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
     "CRITICAL", "Azure Storage connection string"),

    ("Azure SAS Token",
     r'(?i)sig=[A-Za-z0-9%+/=]{43,}', "HIGH",
     "Azure SAS — may allow storage access"),

    ("Azure Client Secret",
     r'(?i)client[_\-]?secret["\s:=]+["\']([A-Za-z0-9_\-\.~]{34,})["\']',
     "CRITICAL", "Azure app client secret"),

    ("GitHub Token",
     r'gh[pousr]_[A-Za-z0-9_]{36,}', "CRITICAL",
     "GitHub personal/OAuth/actions token"),

    ("Slack Token",
     r'xox[baprs]-[0-9A-Za-z\-]{10,}', "HIGH",
     "Slack bot/app token"),

    ("Slack Webhook",
     r'https://hooks\.slack\.com/services/[A-Za-z0-9/+]{44,}',
     "HIGH", "Slack incoming webhook"),

    ("Stripe Secret Key",
     r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL",
     "Stripe live secret key — full payment access"),

    ("Stripe Publishable",
     r'pk_live_[0-9a-zA-Z]{24,}', "LOW",
     "Stripe publishable key — low risk but confirms Stripe use"),

    ("Twilio Auth Token",
     r'(?i)twilio[^"\']{0,20}["\']([a-f0-9]{32})["\']', "HIGH",
     "Twilio auth token"),

    ("SendGrid Key",
     r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "HIGH",
     "SendGrid API key"),

    ("Mailgun Key",
     r'key-[0-9a-zA-Z]{32}', "HIGH",
     "Mailgun private API key"),

    ("NPM Token",
     r'npm_[A-Za-z0-9]{36}', "HIGH",
     "NPM publish token"),

    ("PyPI Token",
     r'pypi-[A-Za-z0-9\-_]{40,}', "HIGH",
     "PyPI upload token"),

    ("Generic API Key",
     r'(?i)(?:api[_\-]?key|apikey|api[_\-]?token)["\s:=]+["\']([A-Za-z0-9_\-]{16,})["\']',
     "HIGH", "Generic API key pattern"),

    ("Bearer Token",
     r'(?i)bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)',
     "HIGH", "Bearer token — likely JWT, decode it"),

    # ── JWT ─────────────────────────────────────────────────────────
    ("JWT Token",
     r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+',
     "HIGH", "JWT — decode header/payload, check alg:none, check expiry"),

    # ── Passwords / Secrets ─────────────────────────────────────────
    ("Hardcoded Password",
     r'(?i)(?:password|passwd|pwd)["\s:=]+["\']([^\s"\']{8,})["\']',
     "CRITICAL", "Hardcoded password in JS"),

    ("Hardcoded Secret",
     r'(?i)(?:secret|client_secret|app_secret)["\s:=]+["\']([^\s"\']{8,})["\']',
     "CRITICAL", "Hardcoded secret/client_secret"),

    ("Private Key (PEM)",
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "CRITICAL", "Private key embedded in JS — severe"),

    ("Basic Auth in URL",
     r'https?://[^:@\s]+:[^@\s]+@[^\s"\']+',
     "HIGH", "Credentials embedded in URL"),

    # ── Internal IPs / Hosts ────────────────────────────────────────
    ("Internal IP (10.x)",
     r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
     "MEDIUM", "RFC1918 internal IP — confirms internal topology"),

    ("Internal IP (172.16-31)",
     r'\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b',
     "MEDIUM", "RFC1918 internal IP"),

    ("Internal IP (192.168)",
     r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
     "MEDIUM", "RFC1918 internal IP"),

    ("Localhost reference",
     r'(?i)(?:localhost|127\.0\.0\.1)(?::\d+)?',
     "LOW", "Localhost — dev leftover or SSRF pivot"),

    ("Internal hostname",
     r'(?i)(?:https?://)?(?:internal|intranet|corp|dev|staging|uat|test|admin|mgmt)\.[a-z0-9\-]+\.[a-z]{2,}',
     "MEDIUM", "Internal/dev hostname — may be accessible"),

    # ── Cloud Metadata / SSRF hints ─────────────────────────────────
    ("GCP Metadata URL",
     r'169\.254\.169\.254|metadata\.google\.internal',
     "HIGH", "GCP/AWS IMDS endpoint hardcoded — SSRF target"),

    ("AWS Metadata URL",
     r'169\.254\.169\.254/latest/meta-data',
     "CRITICAL", "AWS metadata endpoint — if SSRF exists this leaks creds"),

    # ── Database connection strings ──────────────────────────────────
    ("MongoDB URI",
     r'mongodb(?:\+srv)?://[^\s"\'<>]+',
     "CRITICAL", "MongoDB connection string — may include credentials"),

    ("PostgreSQL URI",
     r'postgres(?:ql)?://[^\s"\'<>]+',
     "CRITICAL", "PostgreSQL connection string"),

    ("MySQL URI",
     r'mysql://[^\s"\'<>]+',
     "CRITICAL", "MySQL connection string"),

    ("MSSQL connection",
     r'(?i)Server=[^;]+;Database=[^;]+;(?:User Id|Uid)=[^;]+;(?:Password|Pwd)=[^;]+',
     "CRITICAL", "MSSQL connection string with credentials"),

    ("Redis URI",
     r'redis://[^\s"\'<>]+',
     "HIGH", "Redis connection string"),

    # ── OAuth / SSO ─────────────────────────────────────────────────
    ("OAuth Client ID",
     r'(?i)client[_\-]?id["\s:=]+["\']([A-Za-z0-9\-_]{16,})["\']',
     "MEDIUM", "OAuth client ID — pair with secret for full OAuth abuse"),

    ("AAD Tenant ID",
     r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
     "LOW", "UUID — could be AAD tenant/client/object ID, note context"),

    # ── Interesting URLs ─────────────────────────────────────────────
    ("S3 Bucket URL",
     r'https?://[a-zA-Z0-9\-\.]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com[^\s"\']*',
     "HIGH", "S3 bucket URL — check public access"),

    ("GCS Bucket URL",
     r'https?://storage\.googleapis\.com/[a-zA-Z0-9\-_\.]+',
     "HIGH", "GCS bucket URL — check public access"),

    # ── Debug / Dev leftovers ────────────────────────────────────────
    ("Debug/console statement",
     r'console\.\s*(?:log|warn|error|debug)\s*\([^)]{20,}\)',
     "LOW", "Console statement — may leak data in production"),

    ("TODO / FIXME with sensitive context",
     r'(?i)(?:todo|fixme|hack|xxx|bug)\s*:?\s*(?:password|secret|key|token|auth|cred)[^\n]{0,80}',
     "MEDIUM", "Dev comment referencing sensitive item"),

    ("sourceMappingURL",
     r'//# sourceMappingURL=(.+\.map)',
     "MEDIUM", "Source map present — original source recoverable"),
]

# ═══════════════════════════════════════════════
#  ENDPOINT PATTERNS  (critical thinking)
# ═══════════════════════════════════════════════
ENDPOINT_PATTERNS = [

    # fetch / axios / XHR / superagent calls
    (r"""fetch\s*\(\s*[`"']([^`"']+)[`"']""",           "fetch"),
    (r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[`"']([^`"']+)[`"']""", "axios"),
    (r"""axios\s*\(\s*\{[^}]*url\s*:\s*[`"']([^`"']+)[`"']""", "axios-cfg"),
    (r"""\$http\s*\.\s*(?:get|post|put|delete)\s*\(\s*[`"']([^`"']+)[`"']""", "angular-http"),
    (r"""XMLHttpRequest[^;]{0,200}\.open\s*\(\s*[`"'][A-Z]+[`"']\s*,\s*[`"']([^`"']+)[`"']""", "xhr"),
    (r"""superagent\s*\.\s*(?:get|post|put|del)\s*\(\s*[`"']([^`"']+)[`"']""", "superagent"),
    (r"""(?:got|request|needle)\s*\.\s*(?:get|post)\s*\(\s*[`"']([^`"']+)[`"']""", "node-http"),

    # String patterns that look like API paths
    (r"""[`"'](/api/[v\d][^`"'\s]{0,80})[`"']""",      "api-path"),
    (r"""[`"'](/v\d+/[^`"'\s]{3,80})[`"']""",           "versioned-api"),
    (r"""[`"'](/graphql[^`"'\s]{0,30})[`"']""",          "graphql"),
    (r"""[`"'](/gql[^`"'\s]{0,30})[`"']""",              "graphql"),

    # Template literals with variable paths (partial — capture the static prefix)
    (r"""`(/[a-zA-Z0-9_\-/]+)\$\{""",                    "template-literal"),

    # Route definitions (React Router / Next / Vue Router)
    (r"""path\s*:\s*[`"']([/][^`"']+)[`"']""",           "route"),
    (r"""to\s*:\s*[`"']([/][^`"']+)[`"']""",             "router-link"),
    (r"""<Route[^>]+path=[`"']([^`"']+)[`"']""",         "jsx-route"),

    # WebSocket
    (r"""new\s+WebSocket\s*\(\s*[`"'](wss?://[^`"']+)[`"']""", "websocket"),

    # Environment variable names (often proxy to real endpoints)
    (r"""process\.env\.([A-Z_]{4,}(?:URL|HOST|ENDPOINT|BASE|API)[A-Z_]*)""", "env-var"),

    # NEXT_PUBLIC_ / REACT_APP_ env vars
    (r"""(?:NEXT_PUBLIC_|REACT_APP_)([A-Z_]+)\s*[=:]\s*[`"']([^`"']+)[`"']""", "react-env"),

    # Full URLs embedded
    (r"""[`"'](https?://[^\s`"']{10,})[`"']""",          "full-url"),

    # GraphQL operation names
    (r"""(?:query|mutation|subscription)\s+([A-Za-z]+)\s*(?:\([^)]*\))?\s*\{""", "gql-operation"),
]

# ═══════════════════════════════════════════════
#  FRAMEWORK FINGERPRINTS
# ═══════════════════════════════════════════════
FRAMEWORKS = {
    "React":      [r'React\.createElement', r'__reactFiber', r'react-dom'],
    "Next.js":    [r'__NEXT_DATA__', r'_next/static', r'next/router'],
    "Vue":        [r'Vue\.component', r'__vue__', r'\$mount'],
    "Nuxt":       [r'__NUXT__', r'nuxt-link'],
    "Angular":    [r'ng\.module', r'angular\.bootstrap', r'NgModule'],
    "Svelte":     [r'svelte/internal', r'SvelteComponent'],
    "Remix":      [r'__remixContext', r'remix-run'],
    "Vite":       [r'import\.meta\.hot', r'vite/modulepreload'],
    "Webpack":    [r'__webpack_require__', r'webpackJsonp'],
    "GraphQL":    [r'ApolloClient', r'gql`', r'useQuery', r'useMutation'],
}

# ═══════════════════════════════════════════════
#  LOGGER
# ═══════════════════════════════════════════════
class Logger:
    def __init__(self, outdir: Path):
        self.outdir = outdir
        self.outdir.mkdir(parents=True, exist_ok=True)
        self._fh = open(outdir / "jsrecon.log", "w")
    def _p(self, col, tag, msg):
        line = f"[{datetime.now().strftime('%H:%M:%S')}][{tag:8s}] {msg}"
        print(f"{col}{line}{RST}"); self._fh.write(line+"\n"); self._fh.flush()
    def info(self, m):  self._p(B,  "INFO",  m)
    def good(self, m):  self._p(G,  "FOUND", m)
    def warn(self, m):  self._p(Y,  "WARN",  m)
    def vuln(self, m):  self._p(R,  "SECRET",m)
    def dim(self,  m):  self._p(DIM,"CHECK", m)
    def close(self):    self._fh.close()

# ═══════════════════════════════════════════════
#  HTTP
# ═══════════════════════════════════════════════
SESSION = requests.Session()
SESSION.verify = False

def get(url: str, cookies: str = "", proxy: str = None,
        timeout: int = 15) -> Optional[requests.Response]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    if cookies:
        hdrs["Cookie"] = cookies
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    try:
        r = SESSION.get(url, headers=hdrs, proxies=proxies,
                        timeout=timeout, allow_redirects=True)
        return r
    except Exception as e:
        return None

# ═══════════════════════════════════════════════
#  JS FILE DISCOVERY
# ═══════════════════════════════════════════════

def discover_js_files(base_url: str, cookies: str, proxy: str,
                       depth: int, log: Logger) -> Set[str]:
    """
    Crawl pages to find all .js file URLs.
    Handles: <script src>, dynamic imports, webpack chunks,
    source maps, /static/ paths, /_next/, /gis/, /gfo/, /archive/ etc.
    """
    found_js: Set[str] = set()
    visited:  Set[str] = set()
    to_visit: List[str] = [base_url]

    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Common React/Next/Webpack chunk paths to probe
    common_chunk_paths = [
        "/static/js/", "/static/chunks/", "/static/media/",
        "/_next/static/chunks/", "/_next/static/js/",
        "/assets/js/", "/js/", "/bundle.js", "/app.js", "/main.js",
        "/vendor.js", "/runtime.js", "/polyfills.js",
        "/gis/static/js/", "/gfo/static/js/", "/archive/static/js/",
        "/manifest.json", "/asset-manifest.json",
    ]

    def extract_js_from_html(html: str, page_url: str) -> Set[str]:
        urls = set()
        soup = BeautifulSoup(html, "html.parser")

        # <script src="...">
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            full = urllib.parse.urljoin(page_url, src)
            if full.endswith(".js") or ".js?" in full:
                urls.add(full)

        # Inline scripts — look for import() / require() / dynamic chunks
        for tag in soup.find_all("script"):
            if not tag.string:
                continue
            text = tag.string
            # webpack chunk references
            for m in re.finditer(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', text):
                candidate = urllib.parse.urljoin(page_url, m.group(1))
                if origin in candidate:
                    urls.add(candidate)
            # __webpack_require__ chunk map
            for m in re.finditer(r'"(\d+)"\s*:\s*"([a-f0-9]+)"', text):
                pass  # chunk hash maps — handled via manifest

        # next/react asset-manifest
        for path in ["/asset-manifest.json", "/manifest.json",
                     "/_next/static/chunks/",
                     "/static/js/"]:
            pass  # these get probed separately

        return urls

    def extract_js_from_js(content: str, page_url: str) -> Set[str]:
        """Find JS imports/requires inside JS files."""
        urls = set()
        patterns = [
            r'import\s*\([`"\'](\.?/[^`"\']+\.js(?:\?[^`"\']*)?)[`"\']',
            r'require\([`"\'](\.?/[^`"\']+\.js)[`"\']\)',
            r'["\']([^"\']*static/(?:js|chunks)/[^"\']+\.js)["\']',
            r'["\']([^"\']*/_next/[^"\']+\.js)["\']',
            r'src\s*:\s*["\']([^"\']+\.js)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, content):
                candidate = urllib.parse.urljoin(page_url, m.group(1))
                if origin in candidate or candidate.startswith("/"):
                    full = urllib.parse.urljoin(origin, candidate) if candidate.startswith("/") else candidate
                    urls.add(full)
        return urls

    def probe_manifest(url: str) -> Set[str]:
        """Try to get webpack/react manifest for chunk list."""
        urls = set()
        for mpath in ["/asset-manifest.json", "/static/js/asset-manifest.json",
                      "/manifest.json", "/_next/static/chunks/pages/_app.js"]:
            r = get(urllib.parse.urljoin(url, mpath), cookies, proxy)
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
                # React CRA asset-manifest
                for k, v in data.get("files", {}).items():
                    if v.endswith(".js"):
                        urls.add(urllib.parse.urljoin(origin, v))
                # Flat manifest
                if isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, str) and v.endswith(".js"):
                            urls.add(urllib.parse.urljoin(origin, v))
            except Exception:
                # Try regex fallback
                for m in re.finditer(r'["\']([^"\']+\.js)["\']', r.text):
                    candidate = urllib.parse.urljoin(origin, m.group(1))
                    if origin in candidate:
                        urls.add(candidate)
        return urls

    # ── crawl ──────────────────────────────────
    current_depth = 0
    while to_visit and current_depth <= depth:
        next_round = []
        for url in to_visit:
            if url in visited:
                continue
            visited.add(url)
            log.dim(f"Crawling: {url}")
            r = get(url, cookies, proxy)
            if not r:
                continue

            ct = r.headers.get("Content-Type", "")
            if "javascript" in ct or url.endswith(".js") or ".js?" in url:
                found_js.add(url)
                more = extract_js_from_js(r.text, url)
                for u in more:
                    if u not in visited:
                        next_round.append(u)
            elif "html" in ct or not ct:
                js_in_page = extract_js_from_html(r.text, url)
                found_js.update(js_in_page)
                for u in js_in_page:
                    if u not in visited:
                        next_round.append(u)
                # also find linked HTML pages (same origin, shallow)
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = urllib.parse.urljoin(url, a["href"])
                    if origin in href and href not in visited:
                        next_round.append(href)

            time.sleep(0.1)

        # Probe manifests from base
        manifest_js = probe_manifest(base_url)
        found_js.update(manifest_js)

        to_visit = next_round
        current_depth += 1

    # ── probe common chunk paths ────────────────
    log.info(f"Probing {len(common_chunk_paths)} common chunk paths...")
    for path in common_chunk_paths:
        url = urllib.parse.urljoin(origin, path)
        r = get(url, cookies, proxy, timeout=5)
        if r and r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            if "javascript" in ct or url.endswith(".js"):
                found_js.add(url)
            elif "html" in ct or "json" in ct:
                for m in re.finditer(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text):
                    candidate = urllib.parse.urljoin(origin, m.group(1))
                    if origin in candidate:
                        found_js.add(candidate)

    log.info(f"Total JS files discovered: {len(found_js)}")
    return found_js


# ═══════════════════════════════════════════════
#  DOWNLOAD + BEAUTIFY
# ═══════════════════════════════════════════════

def sanitize_filename(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path.lstrip("/").replace("/", "__")
    if parsed.query:
        q = hashlib.md5(parsed.query.encode()).hexdigest()[:6]
        path = f"{path}___{q}"
    if not path.endswith(".js"):
        path += ".js"
    return re.sub(r'[^\w\-_\.]', '_', path)


def download_and_beautify(url: str, cookies: str, proxy: str,
                           js_dir: Path, beautify: bool,
                           log: Logger) -> Optional[Tuple[str, str]]:
    """Download a JS file, optionally beautify it. Returns (filename, content)."""
    r = get(url, cookies, proxy)
    if not r or r.status_code != 200:
        log.warn(f"  Failed {r.status_code if r else 'no response'}: {url}")
        return None

    raw = r.text
    fname = sanitize_filename(url)

    # Save raw
    raw_path = js_dir / "raw" / fname
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(raw, encoding="utf-8", errors="replace")

    # Beautify
    if beautify and HAS_BEAUTIFIER:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.max_preserve_newlines = 2
            opts.wrap_line_length = 0
            beautiful = jsbeautifier.beautify(raw, opts)
        except Exception:
            beautiful = raw
    else:
        beautiful = raw

    beauty_path = js_dir / "beautified" / fname
    beauty_path.parent.mkdir(parents=True, exist_ok=True)
    beauty_path.write_text(beautiful, encoding="utf-8", errors="replace")

    # Try source map
    map_url = url + ".map"
    r_map = get(map_url, cookies, proxy, timeout=5)
    if r_map and r_map.status_code == 200:
        try:
            smap = r_map.json()
            sources = smap.get("sourcesContent", [])
            names   = smap.get("sources", [])
            if sources:
                map_dir = js_dir / "sourcemaps" / fname
                map_dir.mkdir(parents=True, exist_ok=True)
                for i, (src_name, src_content) in enumerate(zip(names, sources)):
                    if src_content:
                        safe = re.sub(r'[^\w\-_\.]', '_', src_name)[-60:]
                        (map_dir / f"{i:03d}_{safe}").write_text(
                            src_content, encoding="utf-8", errors="replace")
                log.good(f"  Source map recovered: {len(sources)} source files from {url}")
        except Exception:
            pass

    size = len(raw)
    log.dim(f"  Downloaded ({size//1024}KB): {fname}")
    return fname, beautiful


# ═══════════════════════════════════════════════
#  SECRET SCANNER
# ═══════════════════════════════════════════════

def scan_secrets(content: str, filename: str) -> List[dict]:
    findings = []
    lines    = content.split("\n")

    for name, pattern, severity, note in SECRET_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            # Get line number and surrounding context
            start = m.start()
            line_no = content[:start].count("\n") + 1
            line_start = max(0, line_no - 2)
            line_end   = min(len(lines), line_no + 2)
            context = "\n".join(lines[line_start:line_end]).strip()

            # Deduplicate by match value
            match_val = m.group(0)[:200]

            findings.append({
                "type":     name,
                "severity": severity,
                "note":     note,
                "file":     filename,
                "line":     line_no,
                "match":    match_val,
                "context":  context[:300],
            })

    return findings


# ═══════════════════════════════════════════════
#  ENDPOINT EXTRACTOR
# ═══════════════════════════════════════════════

def extract_endpoints(content: str, filename: str,
                       base_url: str) -> List[dict]:
    endpoints = []
    seen      = set()
    origin    = urllib.parse.urlparse(base_url).netloc

    for pattern, source_type in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            try:
                ep = m.group(1)
            except IndexError:
                ep = m.group(0)

            ep = ep.strip().strip("'\"` ")
            if not ep or len(ep) < 2:
                continue

            # Filter noise
            if any(ext in ep for ext in [".png",".jpg",".css",".svg",".ico",".woff",".ttf"]):
                continue
            if ep.startswith("//") and "." not in ep:
                continue

            # Classify
            if ep.startswith("ws://") or ep.startswith("wss://"):
                kind = "WebSocket"
            elif ep.startswith("http"):
                kind = "Full URL" if origin not in ep else "Internal URL"
            elif ep.startswith("/"):
                kind = "API Path"
            elif ep.startswith("process.env"):
                kind = "Env Var"
            else:
                kind = "Relative"

            key = f"{kind}:{ep}"
            if key in seen:
                continue
            seen.add(key)

            # Get line number
            start   = content.find(m.group(0))
            line_no = content[:start].count("\n") + 1 if start != -1 else 0

            endpoints.append({
                "endpoint":    ep,
                "kind":        kind,
                "source_type": source_type,
                "file":        filename,
                "line":        line_no,
            })

    return endpoints


# ═══════════════════════════════════════════════
#  FRAMEWORK DETECTOR
# ═══════════════════════════════════════════════

def detect_frameworks(all_content: str) -> List[str]:
    detected = []
    for fw, patterns in FRAMEWORKS.items():
        if any(re.search(p, all_content) for p in patterns):
            detected.append(fw)
    return detected


# ═══════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════

def save_reports(outdir: Path, all_secrets: List[dict],
                 all_endpoints: List[dict], frameworks: List[str],
                 js_urls: Set[str], log: Logger):

    # Group endpoints by kind
    ep_grouped = defaultdict(list)
    for e in all_endpoints:
        ep_grouped[e["kind"]].append(e)

    # Deduplicate endpoints by value
    unique_eps = {}
    for e in all_endpoints:
        k = e["endpoint"]
        if k not in unique_eps:
            unique_eps[k] = e

    # Group secrets by severity
    sec_grouped = defaultdict(list)
    for s in all_secrets:
        sec_grouped[s["severity"]].append(s)

    # Deduplicate secrets by match value
    seen_matches = set()
    unique_secrets = []
    for s in all_secrets:
        if s["match"] not in seen_matches:
            seen_matches.add(s["match"])
            unique_secrets.append(s)

    # Save endpoints.json
    endpoints_out = {
        "generated":     datetime.now().isoformat(),
        "target":        str(outdir.name),
        "frameworks":    frameworks,
        "total_js_files": len(js_urls),
        "total_unique_endpoints": len(unique_eps),
        "by_kind": {k: [e["endpoint"] for e in v] for k, v in ep_grouped.items()},
        "all": list(unique_eps.values()),
    }
    (outdir / "endpoints.json").write_text(
        json.dumps(endpoints_out, indent=2), encoding="utf-8")

    # Save secrets.json
    secrets_out = {
        "generated": datetime.now().isoformat(),
        "total_findings": len(unique_secrets),
        "by_severity": {k: len(v) for k, v in sec_grouped.items()},
        "findings": unique_secrets,
    }
    (outdir / "secrets.json").write_text(
        json.dumps(secrets_out, indent=2), encoding="utf-8")

    # Save js_files.txt
    (outdir / "js_files.txt").write_text(
        "\n".join(sorted(js_urls)), encoding="utf-8")

    # Save flat endpoint list (easy grep)
    flat_eps = sorted(set(e["endpoint"] for e in all_endpoints
                          if e["kind"] in ("API Path", "Full URL",
                                           "Internal URL", "WebSocket")))
    (outdir / "endpoints_flat.txt").write_text(
        "\n".join(flat_eps), encoding="utf-8")

    # Terminal summary
    sev_col = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": DIM}
    print(f"\n{W}{'═'*65}{RST}")
    print(f"{W}  SUMMARY{RST}")
    print(f"{W}{'═'*65}{RST}")
    print(f"{B}  Frameworks   : {', '.join(frameworks) or 'unknown'}{RST}")
    print(f"{B}  JS Files     : {len(js_urls)}{RST}")
    print(f"{G}  Endpoints    : {len(unique_eps)} unique{RST}")
    for kind, eps in ep_grouped.items():
        print(f"{DIM}    {kind:20s}: {len(eps)}{RST}")
    print(f"\n{R}  Secrets      : {len(unique_secrets)} unique findings{RST}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        items = sec_grouped.get(sev, [])
        if items:
            col = sev_col.get(sev, W)
            print(f"{col}    {sev:10s}: {len(items)}{RST}")
            for s in items[:3]:
                print(f"{col}      [{s['file'][:30]}:{s['line']}] {s['type']}{RST}")
                print(f"{DIM}      {s['match'][:80]}{RST}")

    print(f"\n{B}  Output dir   : {outdir}/{RST}")
    print(f"{B}  endpoints.json, secrets.json, endpoints_flat.txt{RST}")


# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════

def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="JS Recon Tool")
    ap.add_argument("-u", "--url",          required=True,
                    help="Target URL (e.g. https://target.com/gis/)")
    ap.add_argument("-c", "--cookies",      default="",
                    help='Cookie string from Burp e.g. "albert_sso=abc; session=xyz"')
    ap.add_argument("--proxy",              default=None,
                    help="Proxy host:port (e.g. 127.0.0.1:8080)")
    ap.add_argument("--depth",              default=2, type=int,
                    help="Crawl depth for JS discovery (default: 2)")
    ap.add_argument("--threads",            default=5, type=int,
                    help="Download threads (default: 5)")
    ap.add_argument("--no-beautify",        action="store_true",
                    help="Skip jsbeautifier (faster, harder to read)")
    ap.add_argument("-o", "--outdir",       default=None,
                    help="Output directory (default: jsrecon_<host>_<ts>)")
    args = ap.parse_args()

    parsed  = urllib.parse.urlparse(args.url)
    host    = parsed.netloc.replace(":", "_")
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir  = Path(args.outdir or f"jsrecon_{host}_{ts}")
    js_dir  = outdir / "js_files"
    log     = Logger(outdir)

    if not HAS_BEAUTIFIER and not args.no_beautify:
        log.warn("jsbeautifier not installed — run: pip install jsbeautifier")

    print(f"{B}[*] Target    : {args.url}{RST}")
    print(f"{B}[*] Cookies   : {'SET' if args.cookies else 'not set'}{RST}")
    print(f"{B}[*] Depth     : {args.depth}{RST}")
    print(f"{B}[*] Threads   : {args.threads}{RST}")
    print(f"{B}[*] Beautify  : {not args.no_beautify}{RST}")
    print(f"{B}[*] Output    : {outdir}/{RST}\n")

    # Step 1 — Discover
    log.info("Step 1/4: Discovering JS files...")
    js_urls = discover_js_files(args.url, args.cookies, args.proxy,
                                 args.depth, log)

    if not js_urls:
        log.warn("No JS files found. Try increasing --depth or check cookies.")
        sys.exit(1)

    # Step 2 — Download + Beautify
    log.info(f"Step 2/4: Downloading & beautifying {len(js_urls)} files...")
    all_content = {}
    beautify    = not args.no_beautify

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(download_and_beautify, url, args.cookies,
                      args.proxy, js_dir, beautify, log): url
            for url in js_urls
        }
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                fname, content = result
                all_content[fname] = content

    # Step 3 — Analyze
    log.info(f"Step 3/4: Scanning {len(all_content)} files for secrets & endpoints...")
    all_secrets   = []
    all_endpoints = []
    combined      = ""

    for fname, content in all_content.items():
        combined += content + "\n"
        secrets   = scan_secrets(content, fname)
        endpoints = extract_endpoints(content, fname, args.url)
        all_secrets.extend(secrets)
        all_endpoints.extend(endpoints)
        if secrets:
            log.vuln(f"  {fname}: {len(secrets)} secret(s) found")
        if endpoints:
            log.good(f"  {fname}: {len(endpoints)} endpoint(s) found")

    # Step 4 — Framework detection + reports
    log.info("Step 4/4: Detecting frameworks and saving reports...")
    frameworks = detect_frameworks(combined)
    if frameworks:
        log.good(f"Frameworks detected: {', '.join(frameworks)}")

    save_reports(outdir, all_secrets, all_endpoints,
                 frameworks, js_urls, log)
    log.close()


if __name__ == "__main__":
    main()
