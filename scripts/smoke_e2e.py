"""Boot both services under real uvicorn processes and exercise them over
real HTTP — audit-api -> decrypt-svc network path included.

    python scripts/smoke_e2e.py
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.conftest import PASSPHRASE, generate_keypair  # noqa: E402


def wait_ready(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"service not ready: {url}")


def http(method: str, url: str, *, token: str | None = None, payload: dict | None = None):
    """Returns (status_code, parsed_body); never raises on HTTP errors."""
    import urllib.error

    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
        return resp.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, (json.loads(body) if body else {})


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="openagent-audit-smoke-"))
    pub, priv = generate_keypair(PASSPHRASE)
    (tmp / "priv.pem").write_bytes(priv)
    (tmp / "pub.pem").write_bytes(pub)

    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT / "src"),
        "AUDIT_DB_URL": (tmp / "audit.db").as_uri().replace("file:///", "sqlite:///"),
        "AUDIT_SERVICE_TOKEN": "smoke-svc-token",
        "AUDIT_KEY_PROVIDER": "local",
        "AUDIT_PRIVATE_KEY_PATH": str(tmp / "priv.pem"),
        "AUDIT_PRIVATE_KEY_PASSPHRASE": PASSPHRASE.decode(),
        "AUDIT_PUBLIC_KEY_PATH": str(tmp / "pub.pem"),
        "AUDIT_OBJECT_STORE": "local",
        "AUDIT_OBJECT_STORE_ROOT": str(tmp / "objects"),
        "AUDIT_USERS": ("smoke-auditor:alice:auditor,smoke-lead:bob:compliance_lead,"
                        "smoke-lead2:carol:compliance_lead"),
    })

    decrypt_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "openagent_audit.services.decrypt_app:app",
         "--port", "8191", "--log-level", "critical"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    api_env = {**env, "AUDIT_DECRYPT_SVC_URL": "http://127.0.0.1:8191"}
    api_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn",
         "openagent_audit.services.audit_api:create_app", "--factory",
         "--port", "8190", "--log-level", "critical"],
        env=api_env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        wait_ready("http://127.0.0.1:8191/healthz")
        wait_ready("http://127.0.0.1:8190/healthz")
        print("[ok] both services booted")

        # write-side: seal an entity into the shared vault via the pipeline
        from openagent_audit.bootstrap import build_cipher, build_db, build_key_provider
        from openagent_audit.config import Settings
        from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

        settings = Settings.from_env(env)
        cipher = build_cipher(settings, build_key_provider(settings))
        db = build_db(settings)
        pipeline = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(db))
        result = pipeline.protect("电话13812345678需要核查", trace_id="smoke-t1", session_id="smoke-s1")
        entity_id = result.entities[0].entity_id
        assert "13812345678" not in result.masked_text
        print("[ok] entity sealed into vault:", entity_id)

        audit = "http://127.0.0.1:8190"
        # health + authn
        status, body = http("GET", f"{audit}/healthz")
        assert status == 200 and body["ok"]
        status, _ = http("GET", f"{audit}/v1/restore-requests")
        assert status == 401
        print("[ok] auth enforced over real HTTP")

        # restore flow across two real processes
        status, r = http("POST", f"{audit}/v1/restore-requests", token="smoke-lead", payload={
            "object_type": "entity", "object_id": entity_id, "reason": "smoke test"})
        assert status == 201, (status, r)
        request_id = r["id"]
        status, body = http("POST", f"{audit}/v1/restore-requests/{request_id}/approve",
                            token="smoke-lead", payload={})
        assert status == 403 and body["detail"] == "four_eyes", (status, body)
        status, body = http("POST", f"{audit}/v1/restore-requests/{request_id}/approve",
                            token="smoke-lead2", payload={})
        assert status == 200 and body["status"] == "approved", (status, body)
        status, revealed = http("POST", f"{audit}/v1/restore-requests/{request_id}/reveal",
                                token="smoke-lead2")
        assert status == 200 and revealed["plaintext"] == "13812345678", (status, revealed)
        print("[ok] audit-api -> decrypt-svc network decrypt path works")

        status, log = http("GET", f"{audit}/v1/audit-log?verify=true", token="smoke-auditor")
        assert status == 200 and log["verification"]["ok"] is True
        actions = [e["action"] for e in log["entries"]]
        assert "DECRYPT_PERFORMED" in actions  # logged by the separate process
        print("[ok] hash chain intact; decrypt logged by decrypt-svc process")
        print("SMOKE PASS")
        return 0
    finally:
        api_proc.terminate()
        decrypt_proc.terminate()
        api_proc.wait(timeout=10)
        decrypt_proc.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
