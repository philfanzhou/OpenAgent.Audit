#!/usr/bin/env python
"""Provision the audit keypair: writes audit_public_key.pem and
audit_private_key.pem (passphrase-encrypted) into ./keys (or --out).

    python scripts/provision_keys.py --out keys --passphrase "correct horse"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openagent_audit.crypto.keys import write_keypair


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="keys", help="output directory (default: ./keys)")
    parser.add_argument("--passphrase", default=None, help="private key passphrase (recommended)")
    args = parser.parse_args()

    pub, priv = write_keypair(args.out, args.passphrase)
    print(f"public  key: {pub}   <- distribute to Agents / audit-api (AUDIT_PUBLIC_KEY_PATH)")
    print(f"private key: {priv}  <- decrypt-svc only (AUDIT_PRIVATE_KEY_PATH)")
    print("Keep the private key out of the Agent deployment entirely.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
