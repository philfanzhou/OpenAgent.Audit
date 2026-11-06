#!/usr/bin/env python3
"""Start the audit console locally for manual testing.

Boots audit-api (with the server-rendered console) against a throwaway SQLite
database seeded with demo conversations, so the whole two-role flow can be
exercised in a browser without any external service:

    python scripts/run_local.py            # http://127.0.0.1:8100
    python scripts/run_local.py --port 9000

Demo data: every session id starts with ``sess-demo-``. They disappear as soon
as a real conversation exists, which is what the suppression rule is for.

Sign-in tokens are printed at startup.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEMO_USERS = "demo-alice:alice:user,demo-bob:bob:user"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin@123456"
TEST_USERNAME = "test"
TEST_PASSWORD = "test@1233456"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--data-dir", default=None, help="reuse an existing state directory")
    args = parser.parse_args()

    # Windows consoles default to a legacy code page that cannot render the
    # Chinese banner; force UTF-8 so the startup instructions are readable.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-text streams
        pass

    data_dir = pathlib.Path(args.data_dir) if args.data_dir else pathlib.Path(
        tempfile.mkdtemp(prefix="openagent-audit-local-")
    )
    data_dir.mkdir(parents=True, exist_ok=True)

    # A local key pair, generated once per data directory.
    from openagent_audit.crypto.keys import generate_keypair

    public_key = data_dir / "audit_public_key.pem"
    private_key = data_dir / "audit_private_key.pem"
    passphrase = "local-dev-passphrase"
    if not (public_key.exists() and private_key.exists()):
        public, private = generate_keypair(passphrase.encode())
        public_key.write_bytes(public)
        private_key.write_bytes(private)

    # Store the administrator password as a hash, exactly as production should.
    from openagent_audit.services.auth import hash_admin_password

    os.environ.update(
        {
            "AUDIT_DB_URL": f"sqlite:///{data_dir / 'audit.db'}",
            "AUDIT_ENV": "local",
            "AUDIT_USERS": DEMO_USERS,
            "AUDIT_ADMIN_USERNAME": ADMIN_USERNAME,
            "AUDIT_ADMIN_PASSWORD_HASH": hash_admin_password(ADMIN_PASSWORD),
            "AUDIT_ADMIN_SESSION_MINUTES": "5",
            "AUDIT_ADMIN_COOLDOWN_MINUTES": "10",
            "AUDIT_TEST_USERNAME": TEST_USERNAME,
            "AUDIT_TEST_PASSWORD": TEST_PASSWORD,
            "AUDIT_TEST_SESSION_MINUTES": "60",
            "AUDIT_PRIVATE_KEY_PATH": str(private_key),
            "AUDIT_PRIVATE_KEY_PASSPHRASE": passphrase,
            "AUDIT_PUBLIC_KEY_PATH": str(public_key),
            "AUDIT_OBJECT_STORE": "local",
            "AUDIT_OBJECT_STORE_ROOT": str(data_dir / "objects"),
            "AUDIT_TRACE_STORE": "local",
            "AUDIT_DEMO_SEED": "1",
            # In-process decryption keeps this a single process; production runs
            # decrypt-svc separately.
            "AUDIT_DECRYPT_SVC_URL": "",
        }
    )

    print("=" * 68)
    print("OpenAgent 审计台 — 本地演示")
    print("=" * 68)
    print(f"  地址       : http://{args.host}:{args.port}/ui/login")
    print(f"  数据目录   : {data_dir}")
    print()
    print("  1) 平台用户登录（令牌）：")
    print("    alice : demo-alice")
    print("    bob   : demo-bob")
    print()
    print(f"  2) 测试账号（普通用户，不能登录管理员，1 小时过期）：")
    print(f"    {TEST_USERNAME} / {TEST_PASSWORD}")
    print()
    print(f"  3) 管理员（5 分钟有效，退出后 10 分钟内不可再登录）：")
    print(f"    {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("  使用方式   : 先用 1) 或 2) 登录，再点右上角「登录管理员」")
    print("=" * 68)

    import uvicorn

    uvicorn.run(
        "openagent_audit.services.audit_api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())