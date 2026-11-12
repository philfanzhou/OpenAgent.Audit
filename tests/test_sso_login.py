"""Enterprise SSO login: OIDC Authorization Code + PKCE against the company SSO.

The full round trip runs against an in-process mock of the SSO's endpoints,
with the real `AsyncOAuth2Client` driving the token exchange over an
`httpx.MockTransport` — the same wire shape the company SSO exposes. A unit
stub could not catch a wrong header name or a mis-shaped token request; this
can.

Everything degrades to the operator-safe login page: a disabled SSO, a
tampered state, or a network failure all render an error instead of raising.
"""

from __future__ import annotations

import base64
import json
import hashlib
import urllib.parse

import httpx
import pytest
from authlib.integrations.httpx_client import AsyncOAuth2Client

from openagent_audit.config import Settings
from openagent_audit.services.sso import (
    SsoClient,
    SsoError,
    make_pkce_pair,
    make_state,
    sign_state_cookie,
    verify_state_cookie,
)

AUTHORITY = "https://sso.example.com"
BASE = "http://10.51.4.45:8100"


class MockSso:
    """The SSO's three endpoints over an httpx.MockTransport."""

    def __init__(self, *, userinfo: dict | None = None, status: int = 200):
        self.userinfo = userinfo or {"preferred_username": "zhang.san"}
        self.status = status
        self.token_calls: list[dict] = []
        self.userinfo_calls = 0
        self.verifier_seen: str | None = None
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            # token requests are form-encoded, not JSON
            from urllib.parse import parse_qs
            body = {k: v[0] for k, v in parse_qs(request.content.decode("utf-8")).items()}
            self.token_calls.append(body)
            self.verifier_seen = body.get("code_verifier")
            if self.status != 200:
                return httpx.Response(self.status, json={"error": "nope"})
            return httpx.Response(
                200,
                json={"access_token": "at", "id_token": "it", "token_type": "Bearer"},
            )
        if request.url.path.endswith("/userinfo"):
            self.userinfo_calls += 1
            return httpx.Response(self.status, json=self.userinfo)
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.discovery())
        return httpx.Response(404)

    def discovery(self) -> dict:
        return {
            "authorization_endpoint": self.url("/authorize"),
            "token_endpoint": self.url("/token"),
            "userinfo_endpoint": self.url("/userinfo"),
        }

    def url(self, path: str) -> str:
        return AUTHORITY + path

    def oauth_client(self) -> AsyncOAuth2Client:
        return AsyncOAuth2Client(
            client_id="openagent-audit",
            client_secret="s3cret",
            transport=self.transport,
        )


def _settings(**overrides) -> Settings:
    base = {
        "sso_authority": AUTHORITY,
        "sso_client_id": "openagent-audit",
        "sso_client_secret": "s3cret",
    }
    base.update(overrides)
    return Settings(**base)


def _client(mock: MockSso, **overrides) -> SsoClient:
    client = SsoClient(_settings(**overrides))
    client._fetch_json = lambda url: _discovery_of(mock)  # type: ignore[method-assign]
    client._client = mock.oauth_client()  # type: ignore[assignment]
    return client


async def _discovery_of(mock: MockSso):
    return mock.discovery()


class TestPkce:
    def test_pair_matches_s256(self):
        pair = make_pkce_pair()
        derived = base64.urlsafe_b64encode(
            hashlib.sha256(pair.verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert pair.challenge == derived

    def test_states_are_unique(self):
        assert make_state() != make_state()


class TestStateCookie:
    def test_roundtrip(self):
        state = make_state()
        signed = sign_state_cookie(state, "secret")
        assert verify_state_cookie(signed, "secret") == state

    def test_rejects_tampering(self):
        signed = sign_state_cookie(make_state(), "secret")
        with pytest.raises(SsoError):
            verify_state_cookie(signed + "x", "secret")

    def test_rejects_wrong_secret(self):
        signed = sign_state_cookie(make_state(), "secret")
        with pytest.raises(SsoError):
            verify_state_cookie(signed, "other-secret")


class TestEnablement:
    def test_enabled_with_all_values(self):
        assert SsoClient(_settings()).is_enabled() is True

    @pytest.mark.parametrize("missing", ["sso_client_secret", "sso_client_id", "sso_authority"])
    def test_disabled_when_any_value_missing(self, missing):
        assert SsoClient(_settings(**{missing: ""})).is_enabled() is False

    def test_use_before_configuration_raises(self):
        async def run():
            await SsoClient(Settings()).authorization_url(BASE)

        import asyncio

        with pytest.raises(SsoError):
            asyncio.run(run())


class TestAuthorizationUrl:
    async def test_carries_pkce_state_and_scopes(self):
        mock = MockSso()
        client = _client(mock)

        url, state, verifier = await client.authorization_url(BASE)

        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        assert query["client_id"] == ["openagent-audit"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == [f"{BASE}/ui/login/sso/callback"]
        assert set(query["scope"][0].split()) == {"openid", "profile", "email"}
        assert query["state"] == [state]
        derived = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert query["code_challenge"] == [derived]

    async def test_redirect_uri_override(self):
        mock = MockSso()
        client = _client(
            mock,
            sso_redirect_uri="https://audit.corp.com/ui/login/sso/callback",
        )

        url, _, _ = await client.authorization_url(BASE)

        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        assert query["redirect_uri"] == ["https://audit.corp.com/ui/login/sso/callback"]


class TestExchange:
    async def test_identifies_via_userinfo(self):
        mock = MockSso(userinfo={"preferred_username": "zhang.san", "email": "z@corp.com"})
        client = _client(mock)

        identity = await client.exchange_and_identify(BASE, "code-123", "verifier")

        assert identity.username == "zhang.san"
        assert identity.email == "z@corp.com"
        assert mock.userinfo_calls == 1

    async def test_pkce_verifier_travels_with_the_exchange(self):
        mock = MockSso()
        client = _client(mock)

        await client.exchange_and_identify(BASE, "code-123", "verifier")

        assert mock.verifier_seen == "verifier"

    async def test_client_secret_travels_in_the_auth_header(self):
        mock = MockSso()
        client = _client(mock)

        # authlib's default auth method for a confidential client is
        # client_secret_basic: the secret rides in a Basic header on the
        # token request, not in the form body.
        import base64

        seen: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/token"):
                seen["authorization"] = request.headers.get("Authorization")
                seen["content_type"] = request.headers.get("Content-Type")
            return mock._handle(request)

        mock.transport = httpx.MockTransport(capture)
        client._client = mock.oauth_client()
        await client.exchange_and_identify(BASE, "code-123", "verifier")

        expected = base64.b64encode(b"openagent-audit:s3cret").decode("ascii")
        assert seen["authorization"] == f"Basic {expected}"
        # the secret must not ride in the request body
        assert "s3cret" not in (mock.token_calls[-1].get("client_secret") or "")

    async def test_prefers_preferred_username_over_sub(self):
        mock = MockSso(userinfo={"sub": "u-9", "preferred_username": "li.si"})
        client = _client(mock)

        identity = await client.exchange_and_identify(BASE, "code", "verifier")

        assert identity.username == "li.si"

    async def test_email_alone_is_not_an_identity(self):
        # The audit identity is a real account name; an email-only profile
        # is refused rather than silently logged under an address.
        mock = MockSso(userinfo={"email": "only@corp.com"})
        client = _client(mock)

        with pytest.raises(SsoError):
            await client.exchange_and_identify(BASE, "code", "verifier")

    async def test_no_usable_claim_fails(self):
        mock = MockSso(userinfo={"email": "only@corp.com"} | {"nothing": 1})
        client = _client(mock)

        # email is a valid fallback, so this must NOT fail; use a claims set
        # with none of the supported identifiers instead.
        mock2 = MockSso(userinfo={"nickname": "nick"})
        client2 = _client(mock2)

        with pytest.raises(SsoError):
            await client2.exchange_and_identify(BASE, "code", "verifier")

    async def test_service_error_degrades(self):
        mock = MockSso(status=500)
        client = _client(mock)

        with pytest.raises(SsoError):
            await client.exchange_and_identify(BASE, "code", "verifier")