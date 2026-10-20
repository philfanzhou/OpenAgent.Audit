"""Object storage backends for encrypted media (proposal §01 lane S3).

``LocalObjectStore`` is the dev/test backend; ``S3ObjectStore`` targets any
S3-compatible store (SeaweedFS / MinIO) with SSE-KMS as the second
static-encryption layer. Keys are always the *ciphertext* — the client
encrypts before this layer is involved.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


_KEY_RE = re.compile(r"^[A-Za-z0-9._\-/]+$")


def validate_key(key: str) -> str:
    if not key or not _KEY_RE.match(key) or ".." in key:
        raise ValueError(f"illegal object key {key!r}")
    return key


class LocalObjectStore:
    """Filesystem-backed store; keys map to paths under ``root``."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        validate_key(key)
        return self._root / key

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()


class S3ObjectStore:
    """S3-compatible backend (boto3). Encryption happened client-side; the
    bucket should still enable SSE-KMS and (for the audit archive) Object
    Lock."""

    def __init__(
        self,
        bucket: str,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str | None = None,
        client=None,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - depends on extras
                raise RuntimeError("boto3 is not installed; pip install 'openagent-audit[s3]'") from exc
            self._client = boto3.client(
                "s3",
                endpoint_url=endpoint_url or None,
                aws_access_key_id=access_key or None,
                aws_secret_access_key=secret_key or None,
                region_name=region or "us-east-1",
            )
        self._bucket = bucket

    def put(self, key: str, data: bytes) -> None:
        validate_key(key)
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        validate_key(key)
        resp = self._client.get_object(Bucket=self._bucket, Key=key)
        body = resp["Body"]
        return body.read() if hasattr(body, "read") else bytes(body)

    def delete(self, key: str) -> None:
        validate_key(key)
        self._client.delete_object(Bucket=self._bucket, Key=key)
