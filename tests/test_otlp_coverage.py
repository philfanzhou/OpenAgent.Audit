"""OTLP coverage: every content-bearing location is scanned, not just
``span.attributes`` scalars.

The reported defect: a synthetic phone number placed in span ``name``,
``status.message``, ``events``, ``resource.attributes`` or ``scope`` was
forwarded to Langfuse in the clear while the same number inside a prefixed
attribute was masked correctly.
"""

from __future__ import annotations

import json

import pytest

from openagent_audit.gateway.otlp import process_otlp_payload
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

PHONE = "13812345678"
PHONE2 = "13900001111"


def _span(**overrides) -> dict:
    span = {
        "traceId": "a" * 32,
        "spanId": "1" * 16,
        "name": "POST /api/v1/agent/chat",
        "attributes": [],
    }
    span.update(overrides)
    return span


def _payload(span: dict, *, resource_attrs=None, scope=None) -> dict:
    return {
        "resourceSpans": [{
            "resource": {"attributes": resource_attrs or []},
            "scopeSpans": [{
                "scope": scope or {"name": "OpenAgent.Engine"},
                "spans": [span],
            }],
        }]
    }


def _run(payload, pipeline, prefixes=("gen_ai.", "openagent.content", "service.")):
    process_otlp_payload(
        payload,
        pipeline=pipeline,
        content_prefixes=prefixes,
        session_attrs=("openagent.conversation_id",),
        user_attrs=("openagent.user_id",),
        agent_attrs=("agent.id",),
    )
    return payload


def _text(payload) -> str:
    return json.dumps(payload, ensure_ascii=False)


class TestAttributeMasking:
    def test_prefixed_attribute_is_masked(self, pipeline):
        payload = _payload(_span(attributes=[
            {"key": "gen_ai.prompt.0.content", "value": {"stringValue": f"call {PHONE}"}},
        ]))
        _run(payload, pipeline)

        text = _text(payload)
        assert PHONE not in text
        assert "⟦PHONE_NUMBER#" in text

    def test_unprefixed_attribute_is_left_alone(self, pipeline):
        payload = _payload(_span(attributes=[
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
        ]))
        _run(payload, pipeline)
        assert "POST" in _text(payload)


class TestSpanNameMasking:
    def test_span_name_with_pii_is_masked(self, pipeline):
        # Span names are forwarded to Langfuse as the observation name.
        payload = _payload(_span(name=f"chat with {PHONE}"))
        _run(payload, pipeline)

        span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        assert PHONE not in span["name"]
        assert "⟦PHONE_NUMBER#" in span["name"]

    def test_span_name_without_pii_is_unchanged(self, pipeline):
        payload = _payload(_span(name="POST /api/v1/agent/chat"))
        _run(payload, pipeline)
        assert payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"] == (
            "POST /api/v1/agent/chat"
        )


class TestStatusMasking:
    def test_status_message_with_pii_is_masked(self, pipeline):
        payload = _payload(_span(status={"code": "ERROR", "message": f"rejected {PHONE}"}))
        _run(payload, pipeline)

        status = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"]
        assert PHONE not in status["message"]
        assert "⟦PHONE_NUMBER#" in status["message"]


class TestEventMasking:
    def test_event_name_with_pii_is_masked(self, pipeline):
        payload = _payload(_span(events=[
            {"name": f"event {PHONE}", "timeUnixNano": "1", "attributes": []},
        ]))
        _run(payload, pipeline)

        event = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["events"][0]
        assert PHONE not in event["name"]

    def test_event_attribute_with_pii_is_masked(self, pipeline):
        payload = _payload(_span(events=[
            {"name": "tool", "timeUnixNano": "1", "attributes": [
                {"key": "gen_ai.event.detail", "value": {"stringValue": f"called {PHONE2}"}},
            ]},
        ]))
        _run(payload, pipeline)

        text = _text(payload)
        assert PHONE2 not in text
        assert "⟦PHONE_NUMBER#" in text


class TestResourceAndScopeMasking:
    def test_resource_attribute_with_pii_is_masked(self, pipeline):
        payload = _payload(
            _span(),
            resource_attrs=[
                {"key": "service.description", "value": {"stringValue": f"tenant {PHONE}"}},
            ],
        )
        _run(payload, pipeline)

        text = _text(payload)
        assert PHONE not in text

    def test_resource_service_name_is_preserved(self, pipeline):
        # service.name is identity, not content: it must survive untouched or
        # Langfuse loses the service dimension.
        payload = _payload(
            _span(),
            resource_attrs=[
                {"key": "service.name", "value": {"stringValue": "openagent-engine"}},
            ],
        )
        _run(payload, pipeline)
        assert "openagent-engine" in _text(payload)


class TestIdentifierPreservation:
    """Audit correlation ids must never be masked, or the audit plane loses the
    ability to group traces by session/user."""

    @pytest.mark.parametrize(
        "key",
        [
            "openagent.conversation_id",
            "openagent.user_id",
            "openagent.agent_id",
            "openagent.tenant_id",
        ],
    )
    def test_correlation_ids_are_stamped_and_not_masked(self, pipeline, key):
        payload = _payload(_span(attributes=[
            {"key": key, "value": {"stringValue": "internal-id-1234"}},
        ]))
        # deliberately include these keys in the content prefixes
        _run(payload, pipeline, prefixes=("gen_ai.", "openagent."))

        attrs = {
            a["key"]: a.get("value", {}).get("stringValue")
            for a in payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
        }
        assert attrs[key] == "internal-id-1234"

    def test_stdio_identifiers_are_stamped(self, pipeline):
        payload = _payload(_span(attributes=[
            {"key": "openagent.conversation_id", "value": {"stringValue": "conv-9"}},
            {"key": "openagent.user_id", "value": {"stringValue": "usr_9"}},
            {"key": "agent.id", "value": {"stringValue": "cs-bot"}},
        ]))
        _run(payload, pipeline)

        attrs = {
            a["key"]: a.get("value", {}).get("stringValue")
            for a in payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
        }
        assert attrs["langfuse.session.id"] == "conv-9"
        assert attrs["langfuse.user.id"] == "usr_9"
        assert attrs["langfuse.tag.agent"] == "cs-bot"


class TestNestedStructures:
    def test_no_plaintext_survives_anywhere_in_the_tree(self, pipeline):
        """Belt-and-braces: plant the same number in every supported location
        and assert the serialised payload contains none of it."""
        payload = _payload(
            _span(
                name=f"span {PHONE}",
                status={"code": "ERROR", "message": f"err {PHONE}"},
                attributes=[
                    {"key": "gen_ai.prompt.0.content", "value": {"stringValue": f"a {PHONE}"}},
                ],
                events=[{
                    "name": f"ev {PHONE}",
                    "attributes": [
                        {"key": "gen_ai.event.x", "value": {"stringValue": f"b {PHONE}"}},
                    ],
                }],
            ),
            resource_attrs=[
                {"key": "service.description", "value": {"stringValue": f"c {PHONE}"}},
            ],
        )
        _run(payload, pipeline)
        assert PHONE not in _text(payload)