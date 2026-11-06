#!/usr/bin/env python3
"""Generate AUDIT_ADMIN_PASSWORD_HASH for the audit administrator account.

    python scripts/hash_admin_password.py --password 'admin@123456'

Writes nothing; prints the hash so it can be pasted into .env. Storing the hash
instead of the plaintext means a leaked environment file does not by itself
grant the ability to decrypt conversations.
"""

from __future__ import annotations

import argparse
import getpass
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from openagent_audit.services.auth import hash_admin_password  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password", help="administrator password (prompted when omitted)")
    parser.add_argument("--iterations", type=int, default=210_000)
    args = parser.parse_args()

    password = args.password or getpass.getpass("Administrator password: ")
    if not password:
        print("error: empty password is not allowed", file=sys.stderr)
        return 1

    print(hash_admin_password(password, iterations=args.iterations))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())