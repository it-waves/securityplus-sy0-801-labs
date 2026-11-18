#!/usr/bin/env bash
# SP8-A03 evidence: the same duty (correct overtime for the warehouse team) run against four candidate roles for Andre.
# For each candidate: start PayDesk 0.3 with that policy, sign Andre in, run 4 task requests + 4 "not needed" probes.
# Usage: ./capture_a03.sh <outdir>
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-evidence}; mkdir -p "$OUT"
U=http://127.0.0.1:8443
cred() { awk -v u="$1" -F'\t' '$1==u{print $'"$2"'}' data/lab_credentials.txt; }
code_for() { python3 -c "import sys;sys.path.insert(0,'.');from paydesk import totp;print(totp('$(cred "$1" 3)'))"; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 (Quillmere managed laptop)"
REQS=(
 "T1|GET|/timesheets/E-1042||task: read Maya's timesheet (warehouse)"
 "T2|POST|/timesheets/E-1042/overtime|{\"overtime_hours\": 5}|task: correct Maya's overtime (warehouse)"
 "T3|GET|/timesheets/E-1063||task: read Sam's timesheet (warehouse)"
 "T4|POST|/timesheets/E-1063/overtime|{\"overtime_hours\": 2}|task: correct Sam's overtime (warehouse)"
 "X1|GET|/payslips/E-1001||not needed: read the HR director's payslip"
 "X2|POST|/payrates/E-1042|{\"hourly\": \"99.00\"}|not needed: change Maya's pay rate"
 "X3|GET|/timesheets/E-1001||not needed: read the HR director's timesheet"
 "X4|POST|/timesheets/E-1001/overtime|{\"overtime_hours\": 9}|not needed: correct the HR director's overtime"
)
echo "candidate,id,method,path,status,purpose" > "$OUT/results.csv"
for pol in data/candidates/*.json; do
  name=$(basename "$pol" .json); : > logs/auth.jsonl
  PAYDESK_POLICY="$pol" python3 paydesk.py 8443 > "$OUT/server_$name.out" 2>&1 & PID=$!
  for i in $(seq 1 30); do curl -s -o /dev/null $U/me && break; sleep 0.2; done
  ch=$(curl -s -A "$UA" -H 'Content-Type: application/json' -d "{\"username\":\"andre.okafor\",\"password\":\"$(cred andre.okafor 2)\"}" $U/login | sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p')
  curl -s -o /dev/null -c "$OUT/c.txt" -A "$UA" -H 'Content-Type: application/json' -d "{\"challenge\":\"$ch\",\"code\":\"$(code_for andre.okafor)\"}" $U/mfa
  { echo "### candidate $name"; python3 -c "import json;print('candidate role permissions:', json.load(open('$pol'))['roles']['candidate'])"; echo
    for r in "${REQS[@]}"; do
      IFS='|' read -r id m p body purpose <<< "$r"
      echo "## $id  $purpose"
      if [ "$m" = GET ]; then echo "\$ curl -s -i -b andre.cookies $U$p"; resp=$(curl -s -i -b "$OUT/c.txt" -A "$UA" $U$p)
      else echo "\$ curl -s -i -b andre.cookies -X POST -d '$body' $U$p"; resp=$(curl -s -i -b "$OUT/c.txt" -A "$UA" -H 'Content-Type: application/json' -d "$body" $U$p); fi
      echo "$resp"; echo; echo
      st=$(echo "$resp" | head -1 | awk '{print $2}')
      echo "$name,$id,$m,$p,$st,$purpose" >> "$OUT/results.csv"
    done; } > "$OUT/$name.txt"
  grep '"authz.decision"' logs/auth.jsonl > "$OUT/decisions_$name.jsonl"
  kill $PID; wait $PID 2>/dev/null || true
done
rm -f "$OUT/c.txt"
{ date -u +"captured_utc=%Y-%m-%dT%H:%M:%SZ"; python3 --version; curl --version | head -1; uname -srm
  sha256sum paydesk.py data/candidates/*.json data/employees.json data/timesheets.json data/payrates.json; } > "$OUT/environment.txt"
sha256sum "$OUT"/*.txt "$OUT"/*.csv "$OUT"/*.jsonl > "$OUT/SHA256SUMS"
echo "evidence written to $OUT"
