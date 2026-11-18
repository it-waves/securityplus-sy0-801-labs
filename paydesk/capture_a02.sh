#!/usr/bin/env bash
# SP8-A02 evidence capture: real authorization decisions from the PayDesk 0.2 lab build.
# Usage: ./capture_a02.sh <outdir>   (starts PayDesk on 127.0.0.1:8443, signs in three users, runs 8 requests, stops it)
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-evidence}; mkdir -p "$OUT"; : > logs/auth.jsonl
python3 paydesk.py 8443 > "$OUT/server.out" 2>&1 & PID=$!; trap 'kill $PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8443/me && break; sleep 0.2; done
U=http://127.0.0.1:8443
cred() { awk -v u="$1" -F'\t' '$1==u{print $'"$2"'}' data/lab_credentials.txt; }
code_for() { python3 -c "import sys;sys.path.insert(0,'.');from paydesk import totp;print(totp('$(cred "$1" 3)'))"; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 (Quillmere managed laptop)"
signin() {  # $1 user -> cookie jar $OUT/$1.cookies
  local ch; ch=$(curl -s -A "$UA" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$(cred "$1" 2)\"}" $U/login | sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p')
  curl -s -o /dev/null -c "$OUT/$1.cookies" -A "$UA" -H 'Content-Type: application/json' -d "{\"challenge\":\"$ch\",\"code\":\"$(code_for "$1")\"}" $U/mfa
}
get() {  # $1 label, $2 user or "-", $3 path
  echo "### $1"
  if [ "$2" = "-" ]; then echo "\$ curl -s -i $U$3"; curl -s -i -A "$UA" $U$3
  else echo "\$ curl -s -i -b $2.cookies $U$3"; curl -s -i -b "$OUT/$2.cookies" -A "$UA" $U$3; fi
  echo; echo
}
signin maya.chen; signin andre.okafor; signin priya.raman
{ get "W1 Maya reads her own payslip" maya.chen /payslips/E-1042
  get "W2 Maya changes one thing: the employee ID" maya.chen /payslips/E-1007; } > "$OUT/worked.txt"
{ get "P1 Andre (payroll) reads Maya's payslip" andre.okafor /payslips/E-1042
  get "P2 Priya (HR director) reads Andre's payslip" priya.raman /payslips/E-1007
  get "P3 Priya (HR director) reads Maya's employee record" priya.raman /employees/E-1042
  get "P4 Maya reads her own employee record" maya.chen /employees/E-1042
  get "P5 No session cookie: read Maya's payslip" - /payslips/E-1042
  get "P6 Andre (payroll) reads Priya's payslip" andre.okafor /payslips/E-1001; } > "$OUT/practice.txt"
cp logs/auth.jsonl "$OUT/auth.jsonl"
grep '"authz.decision"' "$OUT/auth.jsonl" > "$OUT/decisions.jsonl"
{ date -u +"captured_utc=%Y-%m-%dT%H:%M:%SZ"; python3 --version; curl --version | head -1; uname -srm
  sha256sum paydesk.py data/policy.json data/payslips.json; } > "$OUT/environment.txt"
rm -f "$OUT"/*.cookies
sha256sum "$OUT"/*.txt "$OUT"/*.jsonl > "$OUT/SHA256SUMS"
echo "evidence written to $OUT"
