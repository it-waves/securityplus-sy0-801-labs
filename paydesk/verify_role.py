#!/usr/bin/env python3
"""verify_role.py — prove a PayDesk role does what it should, and nothing more.

Usage: python3 verify_role.py <checks.json> [--url http://127.0.0.1:8443]
checks.json: {"user": "andre.okafor", "checks": [{"id": "T1", "method": "GET", "path": "/timesheets/E-1042",
              "expect": 200, "why": "task: read Maya's timesheet"}, ...]}
Signs the user in (password + TOTP from data/lab_credentials.txt, lab only), runs every check,
prints one line per check and exits 0 only if every check got exactly the expected status."""
import argparse, http.client, json, os, sys, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paydesk import totp  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("checks"); ap.add_argument("--url", default="http://127.0.0.1:8443")
args = ap.parse_args()
spec = json.load(open(args.checks))
u = urllib.parse.urlparse(args.url)
creds = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "lab_credentials.txt")) if not l.startswith("user\t")}


def call(method, path, body=None, cookie=None):
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    h = {"Content-Type": "application/json"}
    if cookie: h["Cookie"] = cookie
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse(); data = r.read()
    return r.status, r.getheader("Set-Cookie"), data


user = spec["user"]
_, pw, secret = creds[user]
st, _, data = call("POST", "/login", {"username": user, "password": pw})
ch = json.loads(data)["challenge"]
st, setc, _ = call("POST", "/mfa", {"challenge": ch, "code": totp(secret)})
cookie = setc.split(";")[0]
print(f"signed in as {user}  (password + TOTP)")
print(f"{'ID':4} {'REQUEST':42} {'EXPECT':>6} {'GOT':>4}  RESULT  WHY")
fails = 0
for ck in spec["checks"]:
    st, _, _ = call(ck["method"], ck["path"], ck.get("body"), cookie)
    ok = st == ck["expect"]; fails += not ok
    print(f"{ck['id']:4} {ck['method'] + ' ' + ck['path']:42} {ck['expect']:>6} {st:>4}  {'PASS' if ok else 'FAIL':6}  {ck['why']}")
n = len(spec["checks"])
print(f"{n - fails}/{n} checks passed" + ("" if not fails else f"  ·  {fails} FAILED"))
sys.exit(1 if fails else 0)
