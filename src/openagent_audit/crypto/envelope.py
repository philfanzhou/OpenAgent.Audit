"""AES-256-GCM envelope encryption (proposal §08, mode B).

Layout of a sealed payload (before base64)::

    version(1B) | wrapped_len(2B BE) | wrapped_dek | nonce(12B) | ciphertext+tag

- The raw value is encrypted with a fresh random 32-byte data-encryption key
  (DEK) using AES-256-GCM; the DEK is wrapped with RSA-OAEP-SHA256 under the
  audit public key, or with a KMS symmetric key.
- Same plaintext seals to different ciphertexts every time (random DEK +
  nonce); entity ids are random too — nothing is derived from the plaintext.
- ``aad`` binds the ciphertext to its entity id, so rows cannot be swapped in
  the vault.
"""

from __future__ import annotations

import base64
import os
import struct
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = 1
_NONCE_BYTES = 12
_DEK_BYTES = 32


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    """Raised for tampered payloads, wrong keys, or malformed envelopes."""


class EnvelopeCipher(Protocol):
    """Write side only needs ``seal``; only decrypt-svc ever calls ``open``."""

    def seal(self, raw: bytes, *, aad: bytes = b"") -> str: ...

    def open(self, payload: str, *, aad: bytes = b"") -> bytes: ...


class RsaEnvelopeCipher:
    """Asymmetric envelope: holders of the public key can only encrypt."""

    def __init__(self, public_key: rsa.RSAPublicKey) -> None:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("RsaEnvelopeCipher needs an RSAPublicKey")
        self._public_key = public_key

    @classmethod
    def from_public_key_pem(cls, pem: bytes) -> "RsaEnvelopeCipher":
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError(f"expected RSA public key, got {type(key).__name__}")
        return cls(key)

    @staticmethod
    def _oaep() -> padding.AsymmetricPadding:
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def _wrap_dek(self, dek: bytes) -> bytes:
        return self._public_key.encrypt(dek, self._oaep())

    def _unwrap_dek(self, wrapped: bytes, key_provider) -> bytes:
        return key_provider.unwrap(wrapped)

    def seal(self, raw: bytes | str, *, aad: bytes = b"") -> str:
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        dek = os.urandom(_DEK_BYTES)
        nonce = os.urandom(_NONCE_BYTES)
        wrapped = self._wrap_dek(dek)
        if len(wrapped) > 0xFFFF:
            raise EncryptionError("wrapped DEK too large")
        ciphertext = AESGCM(dek).encrypt(nonce, raw, aad or None)
        payload = (
            bytes([_VERSION])
            + struct.pack(">H", len(wrapped))
            + wrapped
            + nonce
            + ciphertext
        )
        return base64.b64encode(payload).decode("ascii")

    def open(self, payload: str, *, aad: bytes = b"") -> bytes:
        if getattr(self, "_key_provider", None) is None:
            raise DecryptionError(
                "no private key bound: write-side holders of the public key "
                "cannot decrypt; only decrypt-svc opens payloads"
            )
        try:
            blob = base64.b64decode(payload.encode("ascii"), validate=True)
        except Exception as exc:
            raise DecryptionError("payload is not valid base64") from exc
        if len(blob) < 1 + 2 + _NONCE_BYTES + 16:
            raise DecryptionError("payload too short")
        if blob[0] != _VERSION:
            raise DecryptionError(f"unsupported envelope version {blob[0]}")
        (wrapped_len,) = struct.unpack(">H", blob[1:3])
        wrapped = blob[3 : 3 + wrapped_len]
        nonce = blob[3 + wrapped_len : 3 + wrapped_len + _NONCE_BYTES]
        ciphertext = blob[3 + wrapped_len + _NONCE_BYTES :]
        try:
            dek = self._unwrap_dek(wrapped, self._key_provider)
        except DecryptionError:
            raise
        except Exception as exc:
            raise DecryptionError("DEK unwrap failed (wrong key)") from exc
        try:
            return AESGCM(dek).decrypt(nonce, ciphertext, aad or None)
        except Exception as exc:
            raise DecryptionError("authentication failed") from exc

    # decrypt-svc wires the private key in after construction; the write side
    # (Agents) never configures one.
    _key_provider: "KeyProviderLike" = None  # type: ignore[assignment]

    def bind_key_provider(self, key_provider: "KeyProviderLike") -> None:
        self._key_provider = key_provider


class KmsEnvelopeCipher:
    """Envelope variant where the DEK is wrapped by an AWS-KMS symmetric key.

    ``kms_client`` is any object with ``encrypt``/``decrypt`` methods matching
    boto3's KMS client, so tests can inject a fake. Agents need only
    ``kms:Encrypt``; only decrypt-svc holds ``kms:Decrypt``.
    """

    def __init__(self, kms_client, key_id: str) -> None:
        self._kms = kms_client
        self._key_id = key_id

    def seal(self, raw: bytes | str, *, aad: bytes = b"") -> str:
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        dek = os.urandom(_DEK_BYTES)
        nonce = os.urandom(_NONCE_BYTES)
        wrapped = self._kms.encrypt(KeyId=self._key_id, Plaintext=dek)["CiphertextBlob"]
        if len(wrapped) > 0xFFFF:
            raise EncryptionError("wrapped DEK too large")
        ciphertext = AESGCM(dek).encrypt(nonce, raw, aad or None)
        payload = bytes([_VERSION]) + struct.pack(">H", len(wrapped)) + wrapped + nonce + ciphertext
        return base64.b64encode(payload).decode("ascii")

    def open(self, payload: str, *, aad: bytes = b"") -> bytes:
        try:
            blob = base64.b64decode(payload.encode("ascii"), validate=True)
        except Exception as exc:
            raise DecryptionError("payload is not valid base64") from exc
        if len(blob) < 1 + 2 + _NONCE_BYTES + 16:
            raise DecryptionError("payload too short")
        if blob[0] != _VERSION:
            raise DecryptionError(f"unsupported envelope version {blob[0]}")
        (wrapped_len,) = struct.unpack(">H", blob[1:3])
        wrapped = blob[3 : 3 + wrapped_len]
        nonce = blob[3 + wrapped_len : 3 + wrapped_len + _NONCE_BYTES]
        ciphertext = blob[3 + wrapped_len + _NONCE_BYTES :]
        dek = self._kms.decrypt(CiphertextBlob=wrapped, KeyId=self._key_id)["Plaintext"]
        try:
            return AESGCM(dek).decrypt(nonce, ciphertext, aad or None)
        except Exception as exc:
            raise DecryptionError("authentication failed") from exc


KeyProviderLike = object  # structural: something with unwrap(bytes) -> bytes
