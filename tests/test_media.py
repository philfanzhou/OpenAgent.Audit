"""Media: encrypt-upload, base64 reference replacement, decryption, path
safety, S3 backend."""

from __future__ import annotations

import base64
from pathlib import Path

import httpx
import pytest

from openagent_audit.media.objectstore import LocalObjectStore, S3ObjectStore
from openagent_audit.media.service import MediaService


@pytest.fixture()
def media(cipher, tmp_path) -> MediaService:
    return MediaService(cipher, LocalObjectStore(tmp_path / "objects"), bucket="agent-media")


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def test_encrypt_and_upload_stores_ciphertext_only(media, tmp_path):
    ref = media.encrypt_and_upload(PNG, "image/png")
    assert ref.url == f"s3://agent-media/{ref.key}"
    assert ref.sha256 and len(ref.sha256) == 64
    stored = (tmp_path / "objects" / ref.key).read_bytes()
    assert PNG[:8] not in stored  # object holds ciphertext, not the original


def test_decrypt_roundtrip(media):
    ref = media.encrypt_and_upload(PNG, "image/png")
    assert media.decrypt(ref.key) == PNG


def test_reference_replacement_for_content_parts(media):
    messages = [
        {"role": "user", "content": [
            {"type": "text", "text": "这张截图里的银行卡号是多少"},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64.b64encode(PNG).decode()}"}},
        ]}
    ]
    out, refs = media.replace_references(messages)
    (part,) = [p for p in out[0]["content"] if p.get("type") == "image_url"]
    assert part["image_url"]["url"].startswith("s3://agent-media/")
    assert part["meta"]["mime"] == "image/png"
    assert part["meta"]["enc"] == "envelope/aes-256-gcm"
    assert len(refs) == 1
    # original message untouched (copy semantics)
    assert messages[0]["content"][1]["image_url"]["url"].startswith("data:")


def test_reference_replacement_for_string_content(media):
    messages = [{"role": "user", "content": f"data:image/jpeg;base64,{base64.b64encode(PNG).decode()}"}]
    out, refs = media.replace_references(messages)
    assert out[0]["content"].startswith("s3://agent-media/")
    assert out[0]["meta"]["bytes"] == len(PNG)
    assert len(refs) == 1


def test_plain_messages_untouched(media):
    messages = [{"role": "user", "content": "普通文本"}, {"role": "assistant", "content": "回复"}]
    out, refs = media.replace_references(messages)
    assert out == messages and refs == []


def test_decrypt_via_reference(media):
    _, refs = media.replace_references(
        [{"role": "user", "content": f"data:image/png;base64,{base64.b64encode(PNG).decode()}"}]
    )
    assert media.decrypt(refs[0].key) == PNG


def test_local_object_store_rejects_traversal(tmp_path):
    store = LocalObjectStore(tmp_path / "objects")
    with pytest.raises(ValueError):
        store.put("../escape.txt", b"x")
    with pytest.raises(ValueError):
        store.get("a/../../b")
    with pytest.raises(ValueError):
        S3ObjectStore("bucket", client=object()).put("bad key!", b"x")


def test_s3_object_store_via_fake():
    class FakeS3:
        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}

        def put_object(self, Bucket, Key, Body):
            self.objects[f"{Bucket}/{Key}"] = Body

        def get_object(self, Bucket, Key):
            return {"Body": self.objects[f"{Bucket}/{Key}"]}

        def delete_object(self, Bucket, Key):
            self.objects.pop(f"{Bucket}/{Key}", None)

    fake = FakeS3()
    store = S3ObjectStore("bucket", client=fake)
    store.put("a/b.enc", b"sealed")
    assert store.get("a/b.enc") == b"sealed"
    store.delete("a/b.enc")
    with pytest.raises(Exception):
        store.get("a/b.enc")
