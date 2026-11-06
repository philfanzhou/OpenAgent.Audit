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
import urllib.error
import urllib.parse
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
        "AUDIT_USERS": "smoke-alice:alice:user,smoke-bob:bob:user",
        "AUDIT_ADMIN_USERNAME": "admin",
        "AUDIT_ADMIN_PASSWORD": "admin@123456",
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
        status, _ = http("GET", f"{audit}/v1/sessions")
        assert status == 401
        print("[ok] auth enforced over real HTTP")

        # A browser session is a cookie; use cookies explicitly here because
        # the two-step admin login depends on it.
        from http.cookiejar import CookieJar
        import urllib.request

        jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        def post_form(url: str, form: dict):
            data = urllib.parse.urlencode(form).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            try:
                with opener.open(req, timeout=10) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read()

        def get_cookie(url: str):
            try:
                with opener.open(urllib.request.Request(url), timeout=10) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read()

        # sign in as an ordinary platform user
        status, _ = post_form(f"{audit}/ui/login", {"token": "smoke-alice"})
        assert status == 200, status  # follows the redirect to /ui/sessions
        status, body = get_cookie(f"{audit}/v1/me")
        assert status == 200, (status, body[:200])
        principal = json.loads(body)
        assert principal["role"] == "user" and principal["is_admin"] is False, principal
        print("[ok] platform user signed in as 'user' over real HTTP")

        # a plain user cannot reveal
        status, body = post_form(f"{audit}/v1/reveal/{entity_id}", {})
        assert status == 403, (status, body[:200])
        print("[ok] plain user refused plaintext (403)")

        # step up to administrator
        status, _ = post_form(
            f"{audit}/ui/admin/login", {"username": "admin", "password": "admin@123456"}
        )
        assert status == 200, status
        status, body = get_cookie(f"{audit}/v1/me")
        assert json.loads(body)["is_admin"] is True, body[:200]
        print("[ok] administrator step-up over real HTTP")

        # reveal one entity through audit-api -> decrypt-svc
        status, body = post_form(f"{audit}/v1/reveal/{entity_id}", {})
        assert status == 200, (status, body[:300])
        revealed = json.loads(body)
        assert revealed["plaintext"] == "13812345678", revealed
        print("[ok] audit-api -> decrypt-svc network decrypt path works")

        status, body = get_cookie(f"{audit}/v1/audit-log?verify=true")
        assert status == 200, (status, body[:200])
        log = json.loads(body)
        assert log["verification"]["ok"] is True
        actions = [e["action"] for e in log["entries"]]
        for expected in ("LOGIN", "ADMIN_LOGIN", "ENTITY_REVEALED", "DECRYPT_PERFORMED"):
            assert expected in actions, actions
        reveal_entry = next(e for e in log["entries"] if e["action"] == "ENTITY_REVEALED")
        assert reveal_entry["detail"]["session_user"] == "alice", reveal_entry
        print("[ok] hash chain intact; step-up and reveal both recorded")

        print("SMOKE PASS")
        return 0
    finally:
        api_proc.terminate()
        decrypt_proc.terminate()
        api_proc.wait(timeout=10)
        decrypt_proc.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
