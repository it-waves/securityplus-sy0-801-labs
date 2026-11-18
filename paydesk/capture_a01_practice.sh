#!/usr/bin/env bash
# SP8-A01 practice evidence: three NEW records not shown in the lesson body.
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-evidence/A01_practice}; mkdir -p "$OUT"; : > logs/auth.jsonl
python3 paydesk.py 8443 > "$OUT/server.out" 2>&1 & PID=$!; trap 'kill $PID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8443/me && break; sleep 0.2; done
U=http://127.0.0.1:8443
cred() { awk -v u="$1" -F'\t' '$1==u{print $'"$2"'}' data/lab_credentials.txt; }
code_for() { python3 -c "import sys;sys.path.insert(0,'.');from paydesk import totp;print(totp('$(cred "$1" 3)'))"; }
J='Content-Type: application/json'
# P1: Andre signs in successfully, but the client calls itself "curl"
CH=$(curl -s -A "curl/8.5.0" -H "$J" -d "{\"username\":\"andre.okafor\",\"password\":\"$(cred andre.okafor 2)\"}" $U/login | sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p')
curl -s -A "curl/8.5.0" -H "$J" -d "{\"challenge\":\"$CH\",\"code\":\"$(code_for andre.okafor)\"}" $U/mfa > "$OUT/p1.txt"
# P2: Maya completes MFA, then the same challenge is sent again (replay of an old step)
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 (Quillmere managed laptop QM-LT-0417)"
CH2=$(curl -s -A "$UA" -H "$J" -d "{\"username\":\"maya.chen\",\"password\":\"$(cred maya.chen 2)\"}" $U/login | sed -n 's/.*"challenge": "\([^"]*\)".*/\1/p')
C2=$(code_for maya.chen)
curl -s -A "$UA" -H "$J" -d "{\"challenge\":\"$CH2\",\"code\":\"$C2\"}" $U/mfa > /dev/null
curl -s -i -A "python-requests/2.32" -H "$J" -d "{\"challenge\":\"$CH2\",\"code\":\"$C2\"}" $U/mfa > "$OUT/p2.txt"
# P3: correct password for Maya, then no second step at all
curl -s -A "python-requests/2.32" -H "$J" -d "{\"username\":\"maya.chen\",\"password\":\"$(cred maya.chen 2)\"}" $U/login > "$OUT/p3.txt"
sleep 1
cp logs/auth.jsonl "$OUT/auth.jsonl"; sha256sum "$OUT"/* > "$OUT/SHA256SUMS" 2>/dev/null || true
echo done
