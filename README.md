# Security+ SY0-801 Masterclass — Labs

Free, hands-on labs for the **CompTIA Security+ SY0-801 (V8) Masterclass** on the DevOps Simplified YouTube channel
(playlist: *CompTIA Security+ SY0-801 (Full Course)*).

Every demonstration in the course is captured from these labs. Run them yourself and you will get the same results.

> **Lab only.** PayDesk is the payroll app of **Quillmere Outfitters, a fictional company**. All people, pay figures and
> credentials are test data. PayDesk is a teaching build: it listens on `127.0.0.1` only, has no TLS and keeps sessions in
> memory. Never expose it to a network and never reuse its code in production.

## What you need
- **Python 3.8 or newer** (standard library only: nothing to `pip install`)
- Optional, for the `capture_*.sh` scripts: **bash** and **curl** (Linux, macOS, WSL or Git Bash on Windows)

## Set up (once)
```bash
git clone https://github.com/it-waves/securityplus-sy0-801-labs.git
cd securityplus-sy0-801-labs/paydesk
python3 seed_users.py        # creates YOUR lab users: data/users.json + data/lab_credentials.txt
python3 test_totp_rfc6238.py # optional: checks the one-time-code code against the RFC 6238 test vectors (6/6)
```
On Windows, use `python` instead of `python3`.

`seed_users.py` generates fresh random passwords and authenticator secrets for four fictional people.
They are written to `data/lab_credentials.txt` so the lab scripts can sign in. Treat them as lab-only test values.

## Run PayDesk
```bash
python3 paydesk.py           # PayDesk lab listening on 127.0.0.1:8443 — leave this running, use a second terminal
```
Every decision is written to `logs/auth.jsonl`, one JSON record per line.

## Lessons and their labs
| Lesson | Video | What you run |
|---|---|---|
| SP8-A01 Authentication: what a sign-in really proves | https://youtu.be/VUibvYc8Mi8 | `bash capture_a01.sh evidence/A01` and `bash capture_a01_practice.sh evidence/A01p` |
| SP8-A02 Authorization: same sign-in, different answer | https://youtu.be/ANrQRnpzev0 | `bash capture_a02.sh evidence/A02` |
| SP8-A03 Least privilege: four candidate roles, one job | https://youtu.be/tcXZ1uyf96w | `bash capture_a03.sh evidence/A03` (results in `results.csv`) |
| SP8-A04 Defender Workshop: build and verify a least-privilege role | https://youtu.be/jWPFev6ek-o | follow the workshop below, or replay it with `bash workshop_a04.sh evidence/A04` |

The capture scripts start PayDesk themselves on port 8443, so stop your own `paydesk.py` first.

## SP8-A04 Defender Workshop (do it by hand)
1. Start PayDesk, then run the checks against Andre's **current** role:
   `python3 verify_role.py data/checks_overtime_editor.json` → expect **3/8 checks passed** (he can't do his job, and he can see the HR director's payslip).
2. Stop PayDesk. Back up the policy: `cp data/policy.json data/policy.json.bak`
3. Edit `data/policy.json` (two lines):
   - add the role: `"warehouse-overtime-editor": ["timesheet.read.dept:warehouse", "timesheet.correct.dept:warehouse"]`
     (and a comma after the `"hr"` line)
   - change Andre's assignment to `["employee", "warehouse-overtime-editor"]` (payroll removed)
4. Check it is still valid JSON: `python3 -m json.tool data/policy.json > /dev/null && echo valid`
5. Start PayDesk again and rerun the checks → **8/8 checks passed**. Restart PayDesk and run them once more: two clean runs.
6. Try the classic mistake: change `dept:warehouse` to `dept:Warehouse` in one permission, restart, rerun → **6/8**. Then fix it.

Your turn: give Priya a read-only `warehouse-overtime-auditor` role (`timesheet.read.dept:warehouse`) and prove it with
`python3 verify_role.py data/checks_overtime_auditor.json` → **4/4**. Worked answer: `bash workshop_a04_practice.sh evidence/A04p`.

To reset everything: `cp data/policy.json.bak data/policy.json` (or re-clone).

## Sources used in the lessons
NIST SP 800-63B-4; IETF RFC 6238 and RFC 4226; OWASP Authentication, Session Management and Authorization Cheat Sheets;
OWASP Top 10:2025; CNSSI 4009 / NIST SP 800-12 Rev. 1; CompTIA Security+ SY0-801 V8 Exam Objectives v2.0.

Independent course: not affiliated with or endorsed by CompTIA. CompTIA and Security+ are trademarks of CompTIA, Inc.

## License
MIT. See `LICENSE`.
