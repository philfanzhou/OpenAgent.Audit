"""Client-side encrypted media handling (proposal §02 通路② / §09).

Ingest order matters and is enforced here: sha256 -> envelope-encrypt with the
same audit public key -> upload ciphertext to object storage -> *only then*
replace base64 payloads in messages with ``s3://`` references that travel with
the trace. Media bytes never enter the Langfuse pipeline.
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from openagent_audit.crypto.envelope import EnvelopeCipher
from openagent_audit.media.objectstore import ObjectStore

_DATA_URI_RE = re.compile(r"^data:(?P<mime>[^;,]+)(?P<params>(?:;[^,]*)*),", re.IGNORECASE)


@dataclass(frozen=True)
class MediaReference:
    key: str
    url: str
    sha256: str
    bytes: int
    mime: str
    enc: str = "envelope/aes-256-gcm"

    def as_meta(self) -> dict:
        return {
            "sha256": self.sha256,
            "bytes": self.bytes,
            "mime": self.mime,
            "enc": self.enc,
        }


class MediaService:
    def __init__(
        self,
        cipher: EnvelopeCipher,
        object_store: ObjectStore,
        bucket: str = "agent-media",
        key_prefix: str = "agent-media",
    ) -> None:
        self._cipher = cipher
        self._store = object_store
        self._bucket = bucket
        self._prefix = key_prefix.strip("/")

    # -- ingest --------------------------------------------------------------
    def encrypt_and_upload(self, data: bytes, mime: str) -> MediaReference:
        digest = hashlib.sha256(data).hexdigest()
        now = datetime.now(timezone.utc)
        key = f"{self._prefix}/{now:%Y/%m}/{uuid.uuid4().hex}.enc"
        sealed = self._cipher.seal(data, aad=key.encode("utf-8"))
        self._store.put(key, sealed.encode("ascii"))
        return MediaReference(
            key=key,
            url=f"s3://{self._bucket}/{key}",
            sha256=digest,
            bytes=len(data),
            mime=mime,
        )

    def decrypt(self, key: str) -> bytes:
        sealed = self._store.get(key)
        return self._cipher.open(sealed.decode("ascii"), aad=key.encode("utf-8"))

    # -- message rewriting ------------------------------------------------------
    def replace_references(self, messages: Sequence[dict]) -> tuple[list[dict], list[MediaReference]]:
        """Return a copy of OpenAI-style ``messages`` with every base64 data
        URI replaced by an ``s3://`` reference (+ ``meta``)."""
        refs: list[MediaReference] = []
        out: list[dict] = []
        for message in messages:
            out.append(self._rewrite_message(message, refs))
        return out, refs

    def _rewrite_message(self, message: dict, refs: list[MediaReference]) -> dict:
        content = message.get("content")
        if isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "image_url":
                    rewritten, ref = self._rewrite_image_url(part)
                    if ref is not None:
                        refs.append(ref)
                    new_parts.append(rewritten)
                else:
                    new_parts.append(part)
            return {**message, "content": new_parts}
        if isinstance(content, str):
            match = _DATA_URI_RE.match(content)
            if match:
                payload = base64.b64decode(content[match.end():])
                ref = self.encrypt_and_upload(payload, match.group("mime"))
                refs.append(ref)
                return {
                    **message,
                    "content": ref.url,
                    "meta": ref.as_meta(),
                }
        return message

    def _rewrite_image_url(self, part: dict) -> tuple[dict, "MediaReference | None"]:
        url = (part.get("image_url") or {}).get("url", "")
        match = _DATA_URI_RE.match(url)
        if not match:
            return part, None
        payload = base64.b64decode(url[match.end():])
        ref = self.encrypt_and_upload(payload, match.group("mime"))
        rewritten = {
            **part,
            "image_url": {"url": ref.url},
            "meta": ref.as_meta(),
        }
        return rewritten, ref
