"""Envelope encryption: roundtrip, tamper detection, AAD binding, uniqueness,
KMS variant, key custody."""

from __future__ import annotations

import base64

import pytest

from openagent_audit.crypto.envelope import (
    DecryptionError,
    KmsEnvelopeCipher,
    RsaEnvelopeCipher,
)
from openagent_audit.crypto.keys import LocalKeyProvider, generate_keypair, write_keypair
from tests.conftest import PASSPHRASE


def test_seal_open_roundtrip(cipher, key_provider):
    raw = "身份证 110101199003078515".encode("utf-8")
    sealed = cipher.seal(raw)
    unbound = RsaEnvelopeCipher(cipher._public_key)
    unbound.bind_key_provider(key_provider)
    assert unbound.open(sealed).decode("utf-8") == "身份证 110101199003078515"


def test_ciphertext_is_base64_and_long_enough(cipher):
    sealed = cipher.seal(b"13812345678")
    base64.b64decode(sealed, validate=True)
    # proposal §08: nonce + ciphertext + tag + wrapped DEK ≈ 100+ chars
    assert len(sealed) >= 100


def test_same_plaintext_seals_differently(cipher):
    a = cipher.seal(b"13812345678")
    b = cipher.seal(b"13812345678")
    assert a != b, "random DEK+nonce required"


def test_tampered_payload_fails(cipher, key_provider):
    sealed = cipher.seal(b"sensitive")
    blob = bytearray(base64.b64decode(sealed))
    blob[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(DecryptionError):
        cipher.open(tampered)


def test_wrong_key_fails(keypair):
    pub1, _ = keypair
    pub2, priv2 = generate_keypair(b"other-pass")
    c1 = RsaEnvelopeCipher(load(pub1))
    c1.bind_key_provider(LocalKeyProvider(priv2, b"other-pass"))
    with pytest.raises(DecryptionError):
        c1.open(c1.seal(b"data"))


def load(pem: bytes):
    from openagent_audit.crypto.keys import load_public_key

    return load_public_key(pem)


def test_aad_binding_prevents_row_swaps(cipher):
    sealed_for_id1 = cipher.seal(b"13812345678", aad=b"entity-1")
    with pytest.raises(DecryptionError):
        cipher.open(sealed_for_id1, aad=b"entity-2")


def test_public_key_holder_cannot_decrypt(keypair):
    """Write-side property: a cipher without a bound private key refuses."""
    c = RsaEnvelopeCipher(load(keypair[0]))
    sealed = c.seal(b"data")
    with pytest.raises(DecryptionError, match="no private key bound"):
        c.open(sealed)


def test_local_key_provider_passphrase_required(keypair):
    public_pem, private_pem = keypair
    with pytest.raises(Exception):
        LocalKeyProvider(private_pem, b"wrong-passphrase")
    provider = LocalKeyProvider(private_pem, PASSPHRASE)
    c = RsaEnvelopeCipher(load(public_pem))
    c.bind_key_provider(provider)
    assert c.open(c.seal(b"roundtrip")) == b"roundtrip"


class FakeKms:
    def __init__(self) -> None:
        self.store: dict[bytes, bytes] = {}
        self.counter = 0

    def encrypt(self, *, KeyId, Plaintext):
        self.counter += 1
        blob = f"wrapped-{self.counter}".encode()
        self.store[blob] = Plaintext
        return {"CiphertextBlob": blob, "KeyId": KeyId}

    def decrypt(self, *, CiphertextBlob, KeyId=None):
        if CiphertextBlob not in self.store:
            raise ValueError("unknown ciphertext")
        return {"Plaintext": self.store[CiphertextBlob], "KeyId": KeyId or "kms-key"}


def test_kms_envelope_cipher_roundtrip():
    kms = FakeKms()
    cipher = KmsEnvelopeCipher(kms, "kms-key-1")
    sealed = cipher.seal("张三的银行卡".encode("utf-8"))
    assert cipher.open(sealed).decode("utf-8") == "张三的银行卡"
    assert len(kms.store) >= 1


def test_kms_envelope_tamper_fails():
    kms = FakeKms()
    cipher = KmsEnvelopeCipher(kms, "kms-key-1")
    sealed = cipher.seal(b"data")
    blob = bytearray(base64.b64decode(sealed))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        cipher.open(base64.b64encode(bytes(blob)).decode())


def test_write_keypair_provisioning(tmp_path):
    pub, priv = write_keypair(str(tmp_path), "secret")
    from pathlib import Path

    assert Path(pub).exists() and Path(priv).exists()
    provider = LocalKeyProvider.from_file(priv, "secret")
    cipher = RsaEnvelopeCipher.from_public_key_pem(Path(pub).read_bytes())
    cipher.bind_key_provider(provider)
    assert cipher.open(cipher.seal(b"x")) == b"x"


def test_payload_version_guard(cipher):
    sealed = cipher.seal(b"data")
    blob = bytearray(base64.b64decode(sealed))
    blob[0] = 99
    with pytest.raises(DecryptionError):
        cipher.open(base64.b64encode(bytes(blob)).decode())
