#!/usr/bin/env bash
# SP8-A04 Defender Workshop capture: build the warehouse-overtime-editor role, assign it, prove it in two clean runs.
# Runs in a throw-away copy of the lab so the canonical lab files stay unchanged. Usage: ./workshop_a04.sh <outdir>
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"; OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
WORK=$(mktemp -d); cp -r "$SRC"/paydesk.py "$SRC"/verify_role.py "$SRC"/data "$WORK"/; mkdir -p "$WORK/logs"; cd "$WORK"
start() { python3 paydesk.py 8443 > /dev/null 2>&1 & PID=$!; for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8443/me && break; sleep 0.2; done; }
stop() { kill $PID; wait $PID 2>/dev/null || true; }
show() { echo "\$ $*"; eval "$@" 2>&1 || true; echo; }
# 1 before: what does Andre's current role do?
{ show "grep -A4 '\"assignments\"' data/policy.json"
  start; show "python3 verify_role.py data/checks_overtime_editor.json"; stop; } > "$OUT/1_before.txt"
# 2 back up, then edit: add the role, assign it, remove payroll from Andre
cp data/policy.json data/policy.json.bak
python3 - <<'PY'
# the same two-line edit an admin makes in an editor (style kept, nothing else touched)
s = open("data/policy.json").read()
s = s.replace('  "hr":       ["employee.read.any"]\n',
              '  "hr":       ["employee.read.any"],\n'
              '  "warehouse-overtime-editor": ["timesheet.read.dept:warehouse", "timesheet.correct.dept:warehouse"]\n')
s = s.replace('"andre.okafor": ["employee", "payroll"]', '"andre.okafor": ["employee", "warehouse-overtime-editor"]')
open("data/policy.json", "w").write(s)
PY
{ show "diff -u --label policy.json.bak --label policy.json data/policy.json.bak data/policy.json"
  show "python3 -m json.tool data/policy.json > /dev/null && echo 'policy.json: valid JSON'"; } > "$OUT/2_edit.txt"
# 3 two clean runs (fresh server each time)
for r in 1 2; do { start; show "python3 verify_role.py data/checks_overtime_editor.json"; stop; } > "$OUT/3_run$r.txt"; done
# 4 a common mistake: one capital letter
sed -i 's/timesheet.correct.dept:warehouse/timesheet.correct.dept:Warehouse/' data/policy.json
{ show "grep -n 'dept:' data/policy.json"; start; show "python3 verify_role.py data/checks_overtime_editor.json"; stop; } > "$OUT/4_mistake.txt"
sed -i 's/timesheet.correct.dept:Warehouse/timesheet.correct.dept:warehouse/' data/policy.json
{ start; show "python3 verify_role.py data/checks_overtime_editor.json"; stop; } > "$OUT/5_fixed.txt"
cp data/policy.json "$OUT/policy_after.json"; cp logs/auth.jsonl "$OUT/auth.jsonl"
{ date -u +"captured_utc=%Y-%m-%dT%H:%M:%SZ"; python3 --version; uname -srm; sha256sum paydesk.py verify_role.py data/checks_overtime_editor.json; } > "$OUT/environment.txt"
sha256sum "$OUT"/*.txt "$OUT"/*.json > "$OUT/SHA256SUMS"
rm -rf "$WORK"; echo "evidence written to $OUT"
