"""Enterprise SSO login (OIDC Authorization Code + PKCE).

The audit console signs users in through the company SSO, the same way the
OpenAgent workbench does. The design follows from three facts:

* **The SSO owns identity.** After the code exchange the audit plane asks the
  SSO's userinfo endpoint who the user is; it never parses unverified tokens
  and never keeps its own user list. `preferred_username` (falling back to
  `upn`, `email`) becomes the audit identity, mapped to the ordinary `user`
  role. The administrator capability stays behind the separate step-up login.

* **The state parameter is the CSRF defence.** A random value travels to the
  SSO inside the authorization URL and comes back on the callback; it is bound
  to the browser with a short-lived, signed cookie. A callback whose state does
  not match the cookie is rejected — that is what stops someone fabricating a
  callback out of thin air.

* **Configuration is the switch.** With `AUDIT_SSO_CLIENT_ID` unset the whole
  flow is inert: the console shows no SSO button and the test account remains
  the only way in. Deployment turns it on by supplying the three values the
  SSO administrator issues (authority, client id, client secret).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
import json
from urllib.parse import urlencode

from authlib.integrations.httpx_client import AsyncOAuth2Client
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from openagent_audit.config import Settings


class SsoError(Exception):
    """Operator-safe message for a failed SSO round trip."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class SsoIdentity:
    """The verified answer to "who signed in"."""

    username: str
    email: str | None
    display_name: str | None
    #: Every claim the SSO's userinfo endpoint returned. Kept so the login
    #: audit record can show which identity fields the deployment's SSO
    #: actually provides - the first live login answered with a bare `sub`,
    #: and this is how that becomes visible instead of a mystery.
    raw_claims: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PkcePair:
    verifier: str
    challenge: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_pkce_pair() -> PkcePair:
    """RFC 7636 verifier + S256 challenge."""
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return PkcePair(verifier=verifier, challenge=challenge)


def make_state() -> str:
    return secrets.token_urlsafe(32)


def sign_state_cookie(state: str, secret: str) -> str:
    """Bind the state to this browser with a short-lived signed cookie value."""
    return URLSafeTimedSerializer(secret).dumps(state)


def verify_state_cookie(cookie_value: str, secret: str, max_age_seconds: int = 600) -> str:
    """Recover the state from the cookie, or raise if tampered/expired."""
    try:
        state = URLSafeTimedSerializer(secret).loads(
            cookie_value, max_age=max_age_seconds
        )
    except (BadSignature, SignatureExpired) as exc:
        raise SsoError("登录会话已过期或无效，请重新发起登录。") from exc
    if not isinstance(state, str) or not state:
        raise SsoError("登录会话已过期或无效，请重新发起登录。")
    return state


class SsoClient:
    """OIDC client for the company SSO.

    Uses discovery (`/.well-known/openid-configuration`) so that only the
    authority is configured; endpoints are read from the document. HTTP access
    goes through the provided httpx client, which carries the deployment's TLS
    settings (company CA bundle).
    """

    def __init__(self, settings: Settings, http_client=None) -> None:
        self._settings = settings
        self._client = http_client

    def is_enabled(self) -> bool:
        s = self._settings
        return bool(
            s.sso_authority
            and s.sso_client_id
            and s.sso_client_secret
        )

    def _require_enabled(self) -> None:
        if not self.is_enabled():
            raise SsoError("SSO 登录未配置。请使用测试账号，或联系管理员。")

    async def _discovery(self) -> dict:
        authority = self._settings.sso_authority.rstrip("/")
        url = f"{authority}/.well-known/openid-configuration"
        data = await self._fetch_json(url)
        for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint"):
            if not data.get(key):
                raise SsoError("SSO discovery 文档不完整，请联系管理员。")
        return data

    async def _fetch_json(self, url: str) -> dict:
        import httpx

        from openagent_audit.tls import httpx_tls_kwargs

        client = self._client
        own = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, **httpx_tls_kwargs(self._settings))
            own = True
        try:
            response = await client.get(url)
            if response.status_code != 200:
                raise SsoError(f"SSO 服务返回 {response.status_code}，暂时不可用。")
            return response.json()
        except SsoError:
            raise
        except Exception as exc:  # noqa: BLE001 - network failure degrades to login page
            raise SsoError("SSO 服务暂时不可达，请稍后重试或使用测试账号。") from exc
        finally:
            if own:
                await client.aclose()

    def _redirect_uri(self, base_url: str) -> str:
        configured = self._settings.sso_redirect_uri
        if configured:
            return configured
        return base_url.rstrip("/") + "/ui/login/sso/callback"

    async def authorization_url(
        self, base_url: str
    ) -> tuple[str, str, str]:
        """Build the SSO authorize URL.

        Returns ``(url, state, pkce_verifier)``. The caller stores the state in
        a browser cookie and the verifier in the same cookie set, then passes
        both back on the callback.
        """
        self._require_enabled()
        discovery = await self._discovery()
        redirect_uri = self._redirect_uri(base_url)
        state = make_state()
        pkce = make_pkce_pair()

        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._settings.sso_client_id,
                "redirect_uri": redirect_uri,
                "scope": self._settings.sso_scopes,
                "state": state,
                "code_challenge": pkce.challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{discovery['authorization_endpoint']}?{query}", state, pkce.verifier

    async def exchange_and_identify(
        self,
        base_url: str,
        code: str,
        pkce_verifier: str,
    ) -> SsoIdentity:
        """Exchange the authorization code and resolve the signed-in identity.

        The userinfo endpoint is the source of truth: the token response is
        accepted only as a bearer credential, and the identity comes back
        verified by the SSO itself.
        """
        self._require_enabled()
        discovery = await self._discovery()
        redirect_uri = self._redirect_uri(base_url)

        import httpx

        from openagent_audit.tls import httpx_tls_kwargs

        try:
            # An injected client (tests) is reused as-is; production builds a
            # fresh one with the deployment TLS settings.
            if self._client is not None:
                oauth = self._client
            else:
                oauth = AsyncOAuth2Client(
                    client_id=self._settings.sso_client_id,
                    client_secret=self._settings.sso_client_secret,
                    timeout=10.0,
                    **httpx_tls_kwargs(self._settings),
                )
            # authlib's httpx client manages its own lifecycle; there is no
            # async context manager. The token exchange follows the RFC 6749
            # §4.1.3 shape directly, and the identity comes from userinfo so
            # the SSO itself vouches for the claims.
            token = await oauth.fetch_token(
                discovery["token_endpoint"],
                authorization_response=f"{base_url.rstrip('/')}/ui/login/sso/callback?code={code}",
                redirect_uri=redirect_uri,
                code_verifier=pkce_verifier,
            )
            response = await oauth.get(
                discovery["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {token['access_token']}"},
            )
            if self._client is None:
                await oauth.aclose()
        except SsoError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure degrades to the login page
            raise SsoError("SSO 登录失败，请稍后重试或使用测试账号。") from exc

        if response.status_code != 200:
            raise SsoError("SSO 登录失败：无法获取用户身份。")
        claims = response.json()

        # Some SSO deployments keep human-readable identity in the id_token
        # rather than userinfo. Merge both, userinfo winning: everything here
        # arrived over the TLS-protected token exchange, so the claims are
        # as trustworthy as the channel.
        raw_id_token = token.get("id_token") if isinstance(token, dict) else None
        if isinstance(raw_id_token, str) and raw_id_token.count(".") == 2:
            try:
                payload = raw_id_token.split(".")[1]
                payload += "=" * (-len(payload) % 4)
                id_claims = json.loads(base64.urlsafe_b64decode(payload))
                if isinstance(id_claims, dict):
                    claims = {**id_claims, **claims}
            except (ValueError, TypeError):
                pass

        username = _first_claim(claims, ("preferred_username", "upn", "username", "name", "loginname", "login_name", "account", "employeeid", "employee_id", "sub"))
        if not username:
            raise SsoError("SSO 未返回可用的用户标识，请联系管理员。")

        if not isinstance(claims, dict):
            raise SsoError("SSO 用户信息格式异常，请联系管理员。")

        return SsoIdentity(
            username=username,
            email=_first_claim(claims, ("email",)),
            display_name=_first_claim(claims, ("name", "displayName", "nickname")),
            raw_claims=dict(claims),
        )


def _first_claim(claims: dict, keys: tuple[str, ...]) -> str | None:
    """First non-blank string among *keys*.

    The MPS SSO's userinfo shape is not publicly documented, so the lookup is
    case-insensitive and covers camelCase variants of the snake_case keys
    before giving up. Non-string values are skipped.
    """
    lowered = {
        key.strip().lower(): value
        for key, value in claims.items()
        if isinstance(key, str)
    }
    for key in keys:
        for candidate in (key, key.replace("_", "")):
            value = lowered.get(candidate.lower())
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None