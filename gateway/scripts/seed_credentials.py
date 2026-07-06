"""Seed or rotate operator passwords — the first-boot bootstrap for a fresh install.

A fresh container/volume has no data/credentials.json, so no operator can log in
(dev cert login is disabled in production config). Run this ONCE per operator to
set their password, then hand it over out-of-band and have them rotate it.

Usage (from the gateway root, or via `docker exec` into the container):

  python scripts/seed_credentials.py --list
  python scripts/seed_credentials.py admin --generate         # random strong pw, printed once
  python scripts/seed_credentials.py noura --password 'S3cure!Pass99'
  echo 'S3cure!Pass99' | python scripts/seed_credentials.py noura --stdin
  python scripts/seed_credentials.py khalid --mfa             # (re)enroll authenticator only

Passwords are stored ONLY as salted PBKDF2-HMAC-SHA256 hashes (OWASP-floor
iterations from config.yaml). The script refuses weak passwords using the same
strength rule as the gateway itself.

MFA: when auth.require_mfa is on (production default), setting a password also
enrolls a TOTP secret automatically (unless one exists) and prints the
otpauth:// URI ONCE for the operator's authenticator app. Secrets are stored
AES-256-GCM-encrypted under MCP_GATEWAY_KEK in data/mfa_secrets.json.
"""
import argparse
import json
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth                                   # noqa: E402  (loads config)

CREDS_FILE = auth._CREDS_FILE


def _load() -> dict:
    try:
        return json.loads(CREDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(16))
        ok, _ = auth.password_strength(pw)
        if ok:
            return pw


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed/rotate operator passwords")
    ap.add_argument("username", nargs="?", help="operator username (must exist in the user directory)")
    ap.add_argument("--password", help="set this password (prefer --generate or --stdin)")
    ap.add_argument("--generate", action="store_true", help="generate a strong random password and print it once")
    ap.add_argument("--stdin", action="store_true", help="read the password from stdin (no shell history)")
    ap.add_argument("--list", action="store_true", help="show users and whether they have a credential set")
    ap.add_argument("--mfa", action="store_true", help="(re)enroll the TOTP authenticator (invalidates the old one)")
    ap.add_argument("--no-force", action="store_true", help="do not force a first-login password change (service accounts)")
    args = ap.parse_args()

    creds = _load()

    if args.list or not args.username:
        print(f"{'user':<12} {'role':<10} {'clearance':<12} {'credential':<12} authenticator")
        for user, meta in auth.USERS.items():
            print(f"{user:<12} {meta['role']:<10} {meta['clearance']:<12} "
                  f"{'set' if user in creds else 'MISSING':<12} "
                  f"{'enrolled' if auth.mfa_enrolled(user) else 'MISSING'}")
        return 0

    if args.username not in auth.USERS:
        print(f"error: unknown user {args.username!r} — the user directory is defined in "
              f"app/auth.py (USERS) for builtin mode; OIDC mode uses the IdP instead.")
        return 1

    if args.mfa and not (args.generate or args.password or args.stdin):
        secret, uri = auth.enroll_totp(args.username)
        print(f"TOTP authenticator (re)enrolled for {args.username!r} — one-time display:\n\n"
              f"  secret: {secret}\n  {uri}\n\n"
              "add it to the operator's authenticator app now; it is never shown again.")
        return 0

    if args.generate:
        password = _generate_password()
    elif args.stdin:
        password = sys.stdin.readline().strip()
    elif args.password:
        password = args.password
    else:
        print("error: give one of --generate, --password, --stdin (or --mfa alone)")
        return 1

    # must_change forces the operator to rotate at first login (default). Pass
    # --no-force to seed a final password (e.g. automated/service accounts).
    ok, msg = auth.set_password(args.username, password, must_change=not args.no_force)
    if not ok:
        print(f"error: {msg}")
        return 1
    print(f"credential set for {args.username!r} in {CREDS_FILE}"
          + ("" if args.no_force else " (must change at first login)"))
    if args.generate:
        print(f"one-time display of the generated password:\n\n  {password}\n\n"
              "hand it over out-of-band; the operator MUST rotate it at first login.")

    # MFA is enforced at login — make sure the operator can actually get in.
    if args.mfa or (auth._REQUIRE_MFA and not auth.mfa_enrolled(args.username)):
        secret, uri = auth.enroll_totp(args.username)
        print(f"\nTOTP authenticator enrolled — one-time display:\n\n"
              f"  secret: {secret}\n  {uri}\n\n"
              "add it to the operator's authenticator app now; it is never shown again.")

    print("restart the gateway (or wait for next boot) to load the new hash.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
