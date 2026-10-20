"""decrypt-svc client used by audit-api.

``HttpDecryptService`` calls the separately deployed decrypt-svc (the only
component holding the private key / ``kms:Decrypt``).
``InProcessDecryptService`` is the dev/test variant running the same logic in
one process; both log through decrypt-svc's own audit path.
"""

from __future__ import annotations

import base64
from typing import Protocol

from openagent_audit.services.restore_service import DecryptGateway


class HttpDecryptService(DecryptGateway):
    def __init__(self, base_url: str, service_token: str, client=None, timeout: float = 10.0) -> None:
        self._auth_headers = {"Authorization": f"Bearer {service_token}"}
        if client is not None:
            self._client = client
        else:
            import httpx

            self._client = httpx.Client(
                base_url=base_url.rstrip("/"),
                headers=self._auth_headers,
                timeout=timeout,
            )

    def decrypt_entity(self, entity_id: str, *, request_id: str, requested_by: str) -> bytes:
        resp = self._client.post(
            "/v1/decrypt",
            json={"entity_id": entity_id, "request_id": request_id, "requested_by": requested_by},
            headers=self._auth_headers,
        )
        resp.raise_for_status()
        return base64.b64decode(resp.json()["plaintext_b64"])

    def decrypt_media(self, key: str, *, request_id: str, requested_by: str) -> bytes:
        resp = self._client.post(
            "/v1/decrypt-media",
            json={"key": key, "request_id": request_id, "requested_by": requested_by},
            headers=self._auth_headers,
        )
        resp.raise_for_status()
        return resp.content


class InProcessDecryptService(DecryptGateway):
    """Same behavior as the HTTP service, linked directly to the vault.

    Dev/tests only — in deployment decrypt-svc runs separately with exclusive
    access to the private key.
    """

    def __init__(self, *, cipher, key_provider, vault, object_store=None, audit=None) -> None:
        self._cipher = cipher
        self._provider = key_provider
        self._vault = vault
        self._store = object_store
        self._audit = audit

    def decrypt_entity(self, entity_id: str, *, request_id: str, requested_by: str) -> bytes:
        row = self._vault.get_entity(entity_id)
        if row is None:
            raise KeyError(f"entity {entity_id!r} not found")
        plaintext = self._cipher.open(row.ciphertext, aad=entity_id.encode("ascii"))
        if self._audit is not None:
            self._audit.append(
                actor="decrypt-svc", role="service", action="DECRYPT_PERFORMED",
                object_type="entity", object_id=entity_id,
                detail={"request_id": request_id, "requested_by": requested_by},
            )
        return plaintext

    def decrypt_media(self, key: str, *, request_id: str, requested_by: str) -> bytes:
        if self._store is None:
            raise RuntimeError("no object store configured for media decryption")
        plaintext = self._cipher.open(self._store.get(key).decode("ascii"), aad=key.encode("ascii"))
        if self._audit is not None:
            self._audit.append(
                actor="decrypt-svc", role="service", action="DECRYPT_PERFORMED",
                object_type="media", object_id=key,
                detail={"request_id": request_id, "requested_by": requested_by},
            )
        return plaintext
