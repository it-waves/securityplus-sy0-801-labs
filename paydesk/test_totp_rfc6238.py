"""Verify paydesk.totp() against the SHA-1 test vectors in RFC 6238, Appendix B."""
import base64, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paydesk import totp

SECRET = base64.b32encode(b"12345678901234567890").decode()   # RFC 6238 SHA-1 seed
VECTORS = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
           (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
fails = 0
for t, expected in VECTORS:
    got = totp(SECRET, for_time=t, digits=8)
    ok = got == expected
    fails += not ok
    print(f"T={t:<12} expected {expected}  got {got}  {'PASS' if ok else 'FAIL'}")
print(f"{len(VECTORS) - fails}/{len(VECTORS)} RFC 6238 SHA-1 vectors pass")
sys.exit(1 if fails else 0)
