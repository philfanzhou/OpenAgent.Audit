"""Decryption clients used by audit-api.

``HttpDecryptService`` calls the separately deployed decrypt-svc (the only
component holding the private key). ``InProcessDecryptService`` is the
dev/test variant running the same logic in one process.

Both take the administrator's identity with every call: the decrypt service
records who caused the decryption, so the audit trail is complete even when
the two components' logs are reviewed separately.
"""

from __future__ import annotations

import base64
from typing import Protocol


class DecryptGateway(Protocol):
    """One-entity decryption, scoped to a single object per call."""

    def decrypt_entity(self, entity_id: str, *, actor: str, session_user: str) -> bytes: ...

    def decrypt_media(self, object_key: str, *, actor: str, session_user: str) -> bytes: ...


class HttpDecryptService:
    def __init__(
        self,
        base_url: str,
        service_token: str,
        client=None,
        timeout: float = 10.0,
        tls: dict | None = None,
    ) -> None:
        self._auth_headers = {"Authorization": f"Bearer {service_token}"}
        if client is not None:
            self._client = client
        else:
            import httpx

            self._client = httpx.Client(
                base_url=base_url.rstrip("/"),
                headers=self._auth_headers,
                timeout=timeout,
                **(tls or {}),
            )

    def decrypt_entity(self, entity_id: str, *, actor: str, session_user: str) -> bytes:
        resp = self._client.post(
            "/v1/decrypt",
            json={"entity_id": entity_id, "actor": actor, "session_user": session_user},
            headers=self._auth_headers,
        )
        resp.raise_for_status()
        return base64.b64decode(resp.json()["plaintext_b64"])

    def decrypt_media(self, object_key: str, *, actor: str, session_user: str) -> bytes:
        resp = self._client.post(
            "/v1/decrypt-media",
            json={"object_key": object_key, "actor": actor, "session_user": session_user},
            headers=self._auth_headers,
        )
        resp.raise_for_status()
        return resp.content


class InProcessDecryptService:
    """Dev/test variant: decrypts directly from the vault in this process."""

    def __init__(self, *, cipher, key_provider, vault, object_store=None, audit=None) -> None:
        self._cipher = cipher
        self._provider = key_provider
        self._vault = vault
        self._store = object_store
        self._audit = audit

    def decrypt_entity(self, entity_id: str, *, actor: str, session_user: str) -> bytes:
        row = self._vault.get_entity(entity_id)
        if row is None:
            raise KeyError(entity_id)
        plaintext = self._cipher.open(row.ciphertext, aad=entity_id.encode("ascii"))
        if self._audit is not None:
            self._audit.append(
                actor=actor,
                role="admin",
                action="DECRYPT_PERFORMED",
                object_type="entity",
                object_id=entity_id,
                detail={"session_user": session_user or actor, "entity_type": row.entity_type},
            )
        return plaintext

    def decrypt_media(self, object_key: str, *, actor: str, session_user: str) -> bytes:
        if self._store is None:
            raise RuntimeError("object store is not configured")
        sealed = self._store.get(object_key)
        # Media is stored encrypted with AAD = object key (same as decrypt-svc).
        plaintext = self._cipher.open(
            sealed.decode("ascii") if isinstance(sealed, bytes) else sealed,
            aad=object_key.encode("utf-8"),
        )
        if self._audit is not None:
            self._audit.append(
                actor=actor,
                role="admin",
                action="MEDIA_DECRYPT_PERFORMED",
                object_type="media",
                object_id=object_key,
                detail={"session_user": session_user or actor},
            )
        return plaintext