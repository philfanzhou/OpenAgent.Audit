"""Loki fan-out: payload shape (low-cardinality labels, no PII), failure
handling."""

from __future__ import annotations

import json

import httpx

from openagent_audit.alerts.loki import LokiPushClient, NullLokiClient


def test_push_payload_shape():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["payload"] = json.loads(request.content)
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    loki = LokiPushClient("http://loki.test", labels={"env": "prod"}, client=client)
    ok = loki.push_event(
        {"ts": "2026-10-20T00:00:00+00:00", "actor": "bob", "role": "compliance_lead",
         "action": "DECRYPT_PERFORMED", "object_type": "entity", "object_id": "abcd1234"},
        category="decrypt",
    )
    assert ok is True
    assert captured["path"] == "/loki/api/v1/push"
    stream = captured["payload"]["streams"][0]
    # low-cardinality labels only
    assert stream["stream"] == {"job": "openagent-audit", "category": "decrypt", "env": "prod"}
    (value,) = stream["values"]
    assert value[0].isdigit()
    event = json.loads(value[1])
    assert event["action"] == "DECRYPT_PERFORMED"


def test_push_failure_counted_not_raised():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("loki down")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    loki = LokiPushClient("http://loki.test", client=client)
    assert loki.push_event({"action": "X"}, category="audit") is False
    assert loki.push_failures == 1


def test_null_client_when_disabled():
    loki = NullLokiClient()
    assert loki.push_event({"action": "X"}, category="audit") is False
