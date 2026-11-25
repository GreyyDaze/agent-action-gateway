"""Plays the person for test runs: approves waiting requests in the dashboard
the way a browser does (token once, then cookie + CSRF). Prints each one.
Usage: python3 approve.py [--all | APPROVAL_ID ...]"""
import http.cookiejar
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

env_lines = Path(".env").read_text().splitlines()
token = dict(line.strip().split("=", 1) for line in env_lines if "=" in line)["AGENT_GATEWAY_DASHBOARD_TOKEN"]
base = "http://127.0.0.1:8765"
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
page = op.open(f"{base}/?token={token}").read().decode()
ids = sys.argv[1:] if sys.argv[1:] != ["--all"] else re.findall(r"name='approval_id' value='([^']+)'", page)
for aid in ids:
    page = op.open(base + "/").read().decode()
    csrf = re.search(r"name='csrf_token' value='([^']+)'", page).group(1)
    data = urllib.parse.urlencode({"approval_id": aid, "approver": "Reviewer", "csrf_token": csrf}).encode()
    req = urllib.request.Request(base + "/approvals/approve", data, {"Origin": base})
    print("approved", aid, op.open(req).status)
