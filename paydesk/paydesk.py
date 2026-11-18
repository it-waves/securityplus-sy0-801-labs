#!/usr/bin/env python3
"""PayDesk — Quillmere Outfitters' payroll app (LAB BUILD, fictional company, test data only).

Teaching build for the Security+ SY0-801 Masterclass. Python standard library only.
  * passwords: scrypt (N=2**14, r=8, p=1), 16-byte random salt per user
  * second factor: TOTP per RFC 6238 (HMAC-SHA1, 6 digits, 30 s step, +/-1 step tolerance)
  * session: 256-bit random token in an HttpOnly; Secure; SameSite=Strict cookie
  * every decision is written to logs/auth.jsonl as one JSON object per line

  * authorization (0.2): role-based policy in data/policy.json, default deny, one authz.decision record per request
  * 0.3: timesheets, overtime corrections, pay rates; permission scopes self | any | dept:<department>
         policy file can be chosen with PAYDESK_POLICY (used to compare candidate roles)

Not for production use: no TLS termination, in-memory sessions, no rate limiting (added in later lessons).
"""
import base64, hashlib, hmac, json, os, secrets, struct, sys, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
USERS = json.load(open(os.path.join(HERE, "data", "users.json")))
LOG = os.path.join(HERE, "logs", "auth.jsonl")
CHALLENGES, SESSIONS = {}, {}          # challenge -> (user, expires) ; token -> session dict
CHALLENGE_TTL, SESSION_TTL = 120, 8 * 3600
POLICY_FILE = os.environ.get("PAYDESK_POLICY", os.path.join(HERE, "data", "policy.json"))
POLICY = json.load(open(POLICY_FILE))
PAYSLIPS = json.load(open(os.path.join(HERE, "data", "payslips.json")))
EMPLOYEES = {k: v for k, v in json.load(open(os.path.join(HERE, "data", "employees.json"))).items() if not k.startswith("_")}
TIMESHEETS = json.load(open(os.path.join(HERE, "data", "timesheets.json")))
PAYRATES = json.load(open(os.path.join(HERE, "data", "payrates.json")))
LOG_KEY = secrets.token_bytes(32)      # per-process key: log references cannot be reversed or matched to a token outside the server


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log(event, **fields):
    rec = {"ts": now_iso(), "app": "paydesk", "event": event, **fields}
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def scrypt_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def check_password(user, password):
    rec = USERS.get(user)
    if rec is None:                       # same cost for unknown users: no timing hint
        scrypt_hash(password, b"\x00" * 16)
        return False
    calc = scrypt_hash(password, bytes.fromhex(rec["salt"]))
    return hmac.compare_digest(calc.hex(), rec["pw_hash"])


def totp(secret_b32, for_time=None, step=30, digits=6, digest=hashlib.sha1):
    """RFC 6238 TOTP (HOTP over T = floor(unix_time / step)), RFC 4226 dynamic truncation."""
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int((time.time() if for_time is None else for_time) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def permissions(user):
    """Union of the permissions of every role assigned to the user."""
    roles = POLICY["assignments"].get(user, [])
    return roles, sorted({p for r in roles for p in POLICY["roles"][r]})


def authorize(user, action, resource_type, resource_id, owner_id):
    """Default deny. Allow only if a granted permission covers this action on this resource.
    Scopes: any | self (resource belongs to the caller) | dept:<d> (resource owner works in department d).
    Returns (decision, rule) where rule names exactly what allowed it, or 'default_deny'."""
    roles, perms = permissions(user)
    if f"{resource_type}.{action}.any" in perms:
        return "allow", f"{resource_type}.{action}.any"
    if f"{resource_type}.{action}.self" in perms and owner_id == USERS[user]["employee_id"]:
        return "allow", f"{resource_type}.{action}.self (owner match)"
    dept = EMPLOYEES.get(owner_id, {}).get("department")
    if dept and f"{resource_type}.{action}.dept:{dept}" in perms:
        return "allow", f"{resource_type}.{action}.dept:{dept} (department match)"
    return "deny", "default_deny"


def decide(handler, action, rtype, rid):
    """Authenticate, authorize, log one authz.decision record. Returns (session, status) — status is None when allowed."""
    tok, s = handler._session()
    if not s:
        log("authz.decision", user=None, action=action, resource=f"{rtype}:{rid}", decision="deny",
            rule="no_session", status=401, **handler._ctx())
        return None, 401
    user = s["user"]
    roles, _ = permissions(user)
    decision, rule = authorize(user, action, rtype, rid, rid)
    status = None if decision == "allow" else 403
    log("authz.decision", user=user, employee_id=USERS[user]["employee_id"], roles=roles, action=action,
        resource=f"{rtype}:{rid}", decision=decision, rule=rule, status=status or 200,
        session_ref=s["sid"], **handler._ctx())
    return s, status


def check_totp(user, code):
    secret = USERS[user]["totp_secret"]
    t = time.time()
    return any(hmac.compare_digest(totp(secret, t + d * 30), code) for d in (-1, 0, 1))


class Handler(BaseHTTPRequestHandler):
    server_version = "PayDesk/0.3-lab"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def log_message(self, *a):            # keep stdout quiet; decisions go to auth.jsonl
        pass

    def _send(self, status, body, cookie=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _session(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pd_session" and v in SESSIONS and SESSIONS[v]["expires"] > time.time():
                return v, SESSIONS[v]
        return None, None

    def _ctx(self):
        return {"src_ip": self.client_address[0], "user_agent": self.headers.get("User-Agent", "")}

    def do_POST(self):
        body = self._json()
        if self.path == "/login":
            user, pw = str(body.get("username", "")), str(body.get("password", ""))
            pw_ok = check_password(user, pw)
            if user not in USERS:
                reason = "unknown_user"
            elif not pw_ok:
                reason = "bad_password"
            elif USERS[user]["status"] != "active":
                reason = "account_disabled"
            else:
                reason = None
            ok = reason is None
            # the client always gets the same generic answer; the log keeps the real reason for defenders
            log("auth.password", user=user, result="success" if ok else "failure",
                **({"reason": reason} if reason else {}), **self._ctx())
            if not ok:
                return self._send(401, {"error": "invalid username or password"})
            ch = secrets.token_urlsafe(16)
            CHALLENGES[ch] = (user, time.time() + CHALLENGE_TTL)
            return self._send(200, {"status": "mfa_required", "method": "totp", "challenge": ch})
        if self.path == "/mfa":
            ch, code = str(body.get("challenge", "")), str(body.get("code", ""))
            user, exp = CHALLENGES.pop(ch, (None, 0))
            if user is None or exp < time.time():
                log("auth.mfa", user=user, method="totp", result="failure", reason="unknown_or_expired_challenge", **self._ctx())
                return self._send(401, {"error": "sign-in expired, start again"})
            if not check_totp(user, code):
                log("auth.mfa", user=user, method="totp", result="failure", reason="code_mismatch", **self._ctx())
                return self._send(401, {"error": "invalid code, start again"})
            token = secrets.token_urlsafe(32)
            sid = hmac.new(LOG_KEY, token.encode(), hashlib.sha256).hexdigest()[:12]   # keyed reference, never the raw token (OWASP)
            SESSIONS[token] = {"user": user, "sid": sid, "auth_time": now_iso(),
                               "factors": ["password", "totp"], "expires": time.time() + SESSION_TTL}
            log("auth.mfa", user=user, method="totp", result="success", **self._ctx())
            log("session.issued", user=user, session_ref=sid, factors=["password", "totp"],
                ttl_seconds=SESSION_TTL, **self._ctx())
            cookie = f"pd_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
            return self._send(200, {"status": "authenticated", "user": user}, cookie)
        parts = self.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "timesheets" and parts[2] == "overtime":
            rid = parts[1]
            s, status = decide(self, "correct", "timesheet", rid)
            if status: return self._send(status, {"error": "not signed in" if status == 401 else "forbidden"})
            if rid not in TIMESHEETS: return self._send(404, {"error": "not found"})
            hours = body.get("overtime_hours")
            if not isinstance(hours, (int, float)) or not 0 <= hours <= 30:
                return self._send(400, {"error": "overtime_hours must be a number from 0 to 30"})
            old = TIMESHEETS[rid]["overtime_hours"]; TIMESHEETS[rid]["overtime_hours"] = hours
            log("timesheet.overtime_corrected", user=s["user"], employee_id=rid, old=old, new=hours, session_ref=s["sid"])
            return self._send(200, TIMESHEETS[rid])
        if len(parts) == 2 and parts[0] == "payrates":
            rid = parts[1]
            s, status = decide(self, "update", "payrate", rid)
            if status: return self._send(status, {"error": "not signed in" if status == 401 else "forbidden"})
            if rid not in PAYRATES: return self._send(404, {"error": "not found"})
            PAYRATES[rid]["hourly"] = str(body.get("hourly", PAYRATES[rid]["hourly"]))
            log("payrate.updated", user=s["user"], employee_id=rid, session_ref=s["sid"])
            return self._send(200, PAYRATES[rid])
        return self._send(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/me":
            tok, s = self._session()
            if not s:
                return self._send(401, {"error": "not signed in"})
            u = USERS[s["user"]]
            return self._send(200, {"user": s["user"], "employee_id": u["employee_id"], "display_name": u["display_name"],
                                    "authenticated_at": s["auth_time"], "factors": s["factors"], "session_ref": s["sid"]})
        for prefix, rtype, store in (("/payslips/", "payslip", PAYSLIPS), ("/employees/", "employee", EMPLOYEES),
                                     ("/timesheets/", "timesheet", TIMESHEETS)):
            if self.path.startswith(prefix):
                rid = self.path[len(prefix):]
                tok, s = self._session()
                if not s:   # no session: authentication failed, so authorization never runs
                    log("authz.decision", user=None, action="read", resource=f"{rtype}:{rid}", decision="deny",
                        rule="no_session", status=401, **self._ctx())
                    return self._send(401, {"error": "not signed in"})
                user = s["user"]
                roles, _ = permissions(user)
                decision, rule = authorize(user, "read", rtype, rid, rid)
                status = (200 if rid in store else 404) if decision == "allow" else 403
                log("authz.decision", user=user, employee_id=USERS[user]["employee_id"], roles=roles,
                    action="read", resource=f"{rtype}:{rid}", decision=decision, rule=rule, status=status,
                    session_ref=s["sid"], **self._ctx())
                if decision == "deny":
                    return self._send(403, {"error": "forbidden"})
                if rid not in store:
                    return self._send(404, {"error": "not found"})
                return self._send(200, store[rid])
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    print(f"PayDesk lab listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
