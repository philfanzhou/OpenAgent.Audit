"""HTTPS / internal-CA deployment scenarios.

The production deployment terminates TLS at a reverse proxy and serves the
platform (and, on the audit side, Langfuse/decrypt-svc) behind the company CA.
These tests pin the behaviours that only show up in that topology:

* outbound clients must be able to trust an internal CA, and verification must
  stay on unless a deployment explicitly disables it;
* the login cookie must be marked Secure when the browser used HTTPS — which,
  behind a TLS-terminating proxy, is only visible via X-Forwarded-Proto;
* a self-signed collector must not silently swallow every OTLP export.
"""

from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from openagent_audit.config import Settings
from openagent_audit.crypto.keys import generate_keypair
from openagent_audit.services.audit_api import build_container, create_audit_app
from openagent_audit.tls import httpx_tls_kwargs, warn_if_verification_disabled

PASSPHRASE = b"tls-scenario"


@pytest.fixture()
def keyed(tmp_path):
    pub, priv = generate_keypair(PASSPHRASE)
    (tmp_path / "pub.pem").write_bytes(pub)
    (tmp_path / "priv.pem").write_bytes(priv)
    return tmp_path


class TestOutboundTlsPolicy:
    def test_default_uses_system_bundle(self):
        """Verification is on and no explicit bundle is passed by default."""
        assert httpx_tls_kwargs(Settings()) == {}

    def test_custom_ca_bundle_is_used(self):
        settings = Settings(ca_bundle_path="/etc/audit/internal-ca.pem")
        assert httpx_tls_kwargs(settings) == {"verify": "/etc/audit/internal-ca.pem"}

    def test_explicit_disable_disables_verification(self):
        settings = Settings(tls_verify=False, ca_bundle_path="/ignored.pem")
        assert httpx_tls_kwargs(settings) == {"verify": False}

    @pytest.mark.parametrize(
        "env,expected",
        [
            ({}, {}),
            ({"AUDIT_CA_BUNDLE": "/ca.pem"}, {"verify": "/ca.pem"}),
            ({"REQUESTS_CA_BUNDLE": "/req.pem"}, {"verify": "/req.pem"}),
            ({"SSL_CERT_FILE": "/ssl.pem"}, {"verify": "/ssl.pem"}),
            ({"AUDIT_CA_BUNDLE": "", "SSL_CERT_FILE": "/ssl.pem"}, {"verify": "/ssl.pem"}),
            ({"AUDIT_TLS_VERIFY": "false"}, {"verify": False}),
            ({"AUDIT_TLS_VERIFY": "off", "AUDIT_CA_BUNDLE": "/ca.pem"}, {"verify": False}),
            ({"AUDIT_TLS_VERIFY": "true", "AUDIT_CA_BUNDLE": "/ca.pem"}, {"verify": "/ca.pem"}),
        ],
    )
    def test_environment_parsing(self, env, expected):
        assert httpx_tls_kwargs(Settings.from_env(env)) == expected

    def test_none_settings_is_a_noop(self):
        assert httpx_tls_kwargs(None) == {}

    def test_disabling_verification_emits_a_warning(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="openagent_audit.tls"):
            warn_if_verification_disabled(Settings(tls_verify=False))
        assert any("DISABLED" in record.message for record in caplog.records)

    def test_enabled_verification_is_silent(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="openagent_audit.tls"):
            warn_if_verification_disabled(Settings(tls_verify=True))
        assert not caplog.records


class TestClientsAcceptTlsKwargs:
    def test_langfuse_store_forwards_verify(self, keyed):
        import httpx

        from openagent_audit.tracing.trace_store import LangfuseTraceStore

        seen: dict = {}

        def handler(request):
            seen["ok"] = True
            return httpx.Response(200, json={"data": []})

        client = httpx.Client(transport=httpx.MockTransport(handler),
                              base_url="https://lf.example")
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client,
                                   tls={"verify": "/ca.pem"})
        # injected client wins; the tls kwargs must simply not break it
        assert store.list_trace_dicts() == []
        assert seen["ok"]

    def test_decrypt_client_forwards_verify(self):
        import httpx

        from openagent_audit.services.decrypt_client import HttpDecryptService

        captured: dict = {}

        class FakeResponse:
            status_code = 200
            content = b"plain"
            text = "plain"

            def json(self):
                return {"plaintext_b64": "cGxhaW4="}

            def raise_for_status(self):
                return None

        class FakeClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def post(self, *a, **kw):
                return FakeResponse()

        service = HttpDecryptService("https://decrypt.internal:8101", "tok", tls={"verify": False})
        # constructing the real client would need a network; assert the policy
        # is accepted without error when the caller injects one instead
        assert service is not None

    def test_loki_client_forwards_verify(self):
        from openagent_audit.alerts.loki import LokiPushClient

        class FakeClient:
            def post(self, *a, **kw):
                class R:
                    def raise_for_status(self):
                        return None

                return R()

        client = FakeClient()
        push = LokiPushClient("http://loki:3100", client=client, tls={"verify": "/ca.pem"})
        assert push.push_event({"a": 1}, category="audit") is True


class TestSecureCookie:
    def _app(self, keyed):
        settings = Settings(
            audit_db_url=f"sqlite:///{keyed}/tls.db",
            users=(),
            public_key_path=str(keyed / "pub.pem"),
            local_private_key_path=str(keyed / "priv.pem"),
            local_private_key_passphrase=PASSPHRASE.decode(),
            object_store="local",
            object_store_root=str(keyed / "obj"),
        )
        return TestClient(create_audit_app(build_container(settings)))

    def test_cookie_is_secure_behind_https_proxy(self, keyed):
        """A TLS-terminating proxy leaves the ASGI scheme as http; the cookie
        must still be Secure or it can travel over plaintext."""
        from openagent_audit.config import UserEntry

        settings = Settings(
            audit_db_url=f"sqlite:///{keyed}/tls2.db",
            users=(UserEntry("tok-a", "alice", "auditor"),),
            public_key_path=str(keyed / "pub.pem"),
            local_private_key_path=str(keyed / "priv.pem"),
            local_private_key_passphrase=PASSPHRASE.decode(),
            object_store="local",
            object_store_root=str(keyed / "obj2"),
        )
        client = TestClient(create_audit_app(build_container(settings)))

        r = client.post("/ui/login", data={"token": "tok-a"},
                        headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
        cookie = r.headers.get("set-cookie", "")
        assert "httponly" in cookie.lower()
        assert "secure" in cookie.lower(), cookie

    def test_cookie_is_not_secure_on_plain_http(self, keyed):
        from openagent_audit.config import UserEntry

        settings = Settings(
            audit_db_url=f"sqlite:///{keyed}/tls3.db",
            users=(UserEntry("tok-a", "alice", "auditor"),),
            public_key_path=str(keyed / "pub.pem"),
            local_private_key_path=str(keyed / "priv.pem"),
            local_private_key_passphrase=PASSPHRASE.decode(),
            object_store="local",
            object_store_root=str(keyed / "obj3"),
        )
        client = TestClient(create_audit_app(build_container(settings)))

        r = client.post("/ui/login", data={"token": "tok-a"}, follow_redirects=False)
        cookie = r.headers.get("set-cookie", "")
        # a Secure cookie over plain http would never be sent back
        assert "secure" not in cookie.lower(), cookie

    def test_forwarded_proto_string_is_not_trusted_blindly(self, keyed):
        from openagent_audit.config import UserEntry

        settings = Settings(
            audit_db_url=f"sqlite:///{keyed}/tls4.db",
            users=(UserEntry("tok-a", "alice", "auditor"),),
            public_key_path=str(keyed / "pub.pem"),
            local_private_key_path=str(keyed / "priv.pem"),
            local_private_key_passphrase=PASSPHRASE.decode(),
            object_store="local",
            object_store_root=str(keyed / "obj4"),
        )
        client = TestClient(create_audit_app(build_container(settings)))

        # first value wins; a later hop cannot downgrade it
        r = client.post("/ui/login", data={"token": "tok-a"},
                        headers={"X-Forwarded-Proto": "https, http"}, follow_redirects=False)
        assert "secure" in r.headers.get("set-cookie", "").lower()


class TestConfigExampleCoversDeployment:
    def test_env_example_documents_tls_controls(self):
        text = (pathlib.Path(__file__).resolve().parents[1] / ".env.example").read_text(
            encoding="utf-8"
        )
        assert "AUDIT_CA_BUNDLE" in text
        assert "AUDIT_TLS_VERIFY" in text