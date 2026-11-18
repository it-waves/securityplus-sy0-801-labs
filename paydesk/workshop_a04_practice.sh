#!/usr/bin/env bash
# SP8-A04 "your turn" worked answer: a read-only warehouse-overtime-auditor role for Priya, proven in two clean runs.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"; OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
WORK=$(mktemp -d); cp -r "$SRC"/paydesk.py "$SRC"/verify_role.py "$SRC"/data "$WORK"/; mkdir -p "$WORK/logs"; cd "$WORK"
python3 - <<'PY'
s = open("data/policy.json").read()
s = s.replace('  "hr":       ["employee.read.any"]\n', '  "hr":       ["employee.read.any"],\n  "warehouse-overtime-auditor": ["timesheet.read.dept:warehouse"]\n')
s = s.replace('"priya.raman":  ["employee", "hr"]', '"priya.raman":  ["employee", "hr", "warehouse-overtime-auditor"]')
open("data/policy.json", "w").write(s)
PY
for r in 1 2; do
  python3 paydesk.py 8443 > /dev/null 2>&1 & PID=$!; for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8443/me && break; sleep 0.2; done
  { echo "\$ python3 verify_role.py data/checks_overtime_auditor.json"; python3 verify_role.py data/checks_overtime_auditor.json || true; } > "$OUT/practice_run$r.txt"
  kill $PID; wait $PID 2>/dev/null || true
done
cp data/policy.json "$OUT/policy_practice.json"; cd /; rm -rf "$WORK"; echo "evidence written to $OUT"
