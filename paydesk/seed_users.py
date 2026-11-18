#!/usr/bin/env python3
"""Create PayDesk lab users (fictional people, test credentials only).
Writes data/users.json (salted scrypt hashes) and data/lab_credentials.txt (for the lab learner)."""
import base64, hashlib, json, os, secrets


def scrypt_hash(password, salt):
    """identical to paydesk.scrypt_hash (scrypt N=2**14, r=8, p=1, 32 bytes); defined here so a fresh lab can be seeded
    before data/users.json exists"""
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

PEOPLE = [
    # user, employee_id, display name, role, status
    ("maya.chen",   "E-1042", "Maya Chen",   "Warehouse associate", "active"),
    ("andre.okafor","E-1007", "Andre Okafor","Payroll specialist",  "active"),
    ("priya.raman", "E-1001", "Priya Raman", "HR director",         "active"),
    ("leo.brandt",  "C-2203", "Leo Brandt",  "Contractor (Northgate Data Services)", "disabled"),
]

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    users, creds = {}, []
    for user, eid, name, role, status in PEOPLE:
        pw = "-".join(secrets.choice(["cedar", "lantern", "harbor", "maple", "summit", "willow", "copper", "meadow",
                                      "ember", "falcon", "pine", "river"]) for _ in range(4))
        salt = secrets.token_bytes(16)
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        users[user] = {"employee_id": eid, "display_name": name, "role": role, "status": status,
                       "salt": salt.hex(), "pw_hash": scrypt_hash(pw, salt).hex(), "totp_secret": secret}
        creds.append(f"{user}\t{pw}\t{secret}")
    os.makedirs(os.path.join(here, "data"), exist_ok=True); os.makedirs(os.path.join(here, "logs"), exist_ok=True)
    json.dump(users, open(os.path.join(here, "data", "users.json"), "w"), indent=1)
    open(os.path.join(here, "data", "lab_credentials.txt"), "w").write("user\tpassword\ttotp_secret\n" + "\n".join(creds) + "\n")
    print("seeded", len(users), "users")

if __name__ == "__main__":
    main()
