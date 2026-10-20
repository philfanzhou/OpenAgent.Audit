"""Key custody (proposal §10 step 4): the private key lives only where
decryption happens — a PEM file owned by decrypt-svc, or AWS KMS.

Agents receive **only the public key** (``public_key_path``); they are
structurally unable to decrypt history.
"""

from __future__ import annotations

import os
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class KeyProvider(Protocol):
    def unwrap(self, wrapped: bytes) -> bytes: ...


def generate_keypair(passphrase: bytes | None = None) -> tuple[bytes, bytes]:
    """Generate an RSA-4096 keypair; returns ``(public_pem, private_pem)``.

    The private PEM is passphrase-encrypted when a passphrase is given.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if passphrase is not None:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    return public_pem, private_pem


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError(f"expected RSA public key, got {type(key).__name__}")
    return key


class LocalKeyProvider:
    """RSA-OAEP unwrap with a (passphrase-protected) local private PEM."""

    def __init__(self, private_key_pem: bytes, passphrase: bytes | None = None) -> None:
        key = serialization.load_pem_private_key(private_key_pem, password=passphrase)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError(f"expected RSA private key, got {type(key).__name__}")
        self._key = key

    @classmethod
    def from_file(cls, path: str, passphrase: str | None = None) -> "LocalKeyProvider":
        with open(path, "rb") as fh:
            pem = fh.read()
        return cls(pem, passphrase.encode("utf-8") if passphrase else None)

    def unwrap(self, wrapped: bytes) -> bytes:
        return self._key.decrypt(
            wrapped,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    def public_key(self) -> rsa.RSAPublicKey:
        return self._key.public_key()


class KmsKeyProvider:
    """Unwrap DEKs via AWS KMS ``Decrypt`` (``kms_client`` is boto3-shaped)."""

    def __init__(self, kms_client, key_id: str) -> None:
        self._kms = kms_client
        self._key_id = key_id

    def unwrap(self, wrapped: bytes) -> bytes:
        return self._kms.decrypt(CiphertextBlob=wrapped, KeyId=self._key_id)["Plaintext"]


def write_keypair(directory: str, passphrase: str | None = None) -> tuple[str, str]:
    """Provisioning helper: writes ``audit_public_key.pem`` and
    ``audit_private_key.pem`` into ``directory`` and returns their paths."""
    public_pem, private_pem = generate_keypair(passphrase.encode() if passphrase else None)
    pub_path = os.path.join(directory, "audit_public_key.pem")
    priv_path = os.path.join(directory, "audit_private_key.pem")
    os.makedirs(directory, exist_ok=True)
    with open(pub_path, "wb") as fh:
        fh.write(public_pem)
    with open(priv_path, "wb") as fh:
        fh.write(private_pem)
    os.chmod(priv_path, 0o600)
    return pub_path, priv_path
