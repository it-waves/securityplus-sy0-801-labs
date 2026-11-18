#!/usr/bin/env bash
# SP8-A01 evidence capture: real requests against the PayDesk lab build.
# Usage: ./capture_a01.sh <outdir>      (starts PayDesk on 127.0.0.1:8443, runs 4 scenarios, stops it)
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-evidence}; mkdir -p "$OUT"; : > logs/auth.jsonl
python3 paydesk.py 8443 > "$OUT/server.out" 2>&1 & PID=$!; trap 'kill $PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8443/me && break; sleep 0.2; done
U=http://127.0.0.1:8443
cred() { awk -v u="$1" -F'\t' '$1==u{print $'"$2"'}' data/lab_credentials.txt; }
code_for() { python3 -c "import sys;sys.path.insert(0,'.');from paydesk import totp;print(totp('$(cred "$1" 3)'))"; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 (Quillmere managed laptop QM-LT-0417)"
run() { printf "$ "; printf "%q " "$@"; echo; "$@"; echo; echo; }

{
echo "### Scenario 1 - Maya signs in: password, then TOTP code"
run curl -s -i -A "$UA" -H 'Content-Type: application/json' -d "{\"username\":\"maya.chen\",\"password\":\"$(cred maya.chen 2)\"}" $U/login
} > "$OUT/s1_login.txt"
CH=$(sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p' "$OUT/s1_login.txt")
CODE=$(code_for maya.chen)
{
run curl -s -i -c "$OUT/cookies.txt" -A "$UA" -H 'Content-Type: application/json' -d "{\"challenge\":\"$CH\",\"code\":\"$CODE\"}" $U/mfa
run curl -s -i -b "$OUT/cookies.txt" -A "$UA" $U/me
} > "$OUT/s1_mfa_me.txt"

# Scenario 2: correct password, wrong code
CH2=$(curl -s -A "$UA" -H 'Content-Type: application/json' -d "{\"username\":\"maya.chen\",\"password\":\"$(cred maya.chen 2)\"}" $U/login | sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p')
GOOD=$(code_for maya.chen); BAD=$(printf '%06d' $(( (10#$GOOD + 271828) % 1000000 )))
{ echo "### Scenario 2 - right password, wrong code"; run curl -s -i -A "$UA" -H 'Content-Type: application/json' -d "{\"challenge\":\"$CH2\",\"code\":\"$BAD\"}" $U/mfa; } > "$OUT/s2_wrong_code.txt"

# Scenario 3: wrong password (and an account that does not exist): same answer
{ echo "### Scenario 3 - wrong password vs unknown user"
  run curl -s -i -A "$UA" -H 'Content-Type: application/json' -d '{"username":"maya.chen","password":"summer2026!"}' $U/login
  run curl -s -i -A "$UA" -H 'Content-Type: application/json' -d '{"username":"maya.chenn","password":"summer2026!"}' $U/login
} > "$OUT/s3_wrong_password.txt"

# Scenario 4: disabled contractor account, correct password
{ echo "### Scenario 4 - disabled account, correct password"
  run curl -s -i -A "curl/8.5.0" -H 'Content-Type: application/json' -d "{\"username\":\"leo.brandt\",\"password\":\"$(cred leo.brandt 2)\"}" $U/login
} > "$OUT/s4_disabled.txt"

cp logs/auth.jsonl "$OUT/auth.jsonl"
{ date -u +"captured_utc=%Y-%m-%dT%H:%M:%SZ"; python3 --version; curl --version | head -1; uname -srm
  sha256sum paydesk.py seed_users.py; } > "$OUT/environment.txt"
sha256sum "$OUT"/*.txt "$OUT"/auth.jsonl > "$OUT/SHA256SUMS"
echo "evidence written to $OUT"
