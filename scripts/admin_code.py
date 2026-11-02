"""Generate a one-use administrator activation code and its server-side hash."""

import hashlib
import secrets

if __name__ == "__main__":
    code = secrets.token_urlsafe(32)
    print("Activation code (keep private):", code)
    print("SV_ADMIN_CLAIM_HASH=" + hashlib.sha256(code.encode()).hexdigest())
