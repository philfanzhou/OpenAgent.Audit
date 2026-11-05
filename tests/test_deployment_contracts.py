"""Deployment configuration that only works if it matches the other repo.

The audit stack is deployed alongside the OpenAgent .NET services, so a few
of its files encode contracts with that codebase. These tests pin those
contracts against evidence captured from a real OpenAgent run, so a future
edit cannot quietly break log correlation or trace ingestion again.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A log event captured from the real OpenAgent composition
# (UseAgentSerilog + Serilog:ConsoleFormat=Json, see
# src/OpenAgent.Hosting/SerilogHostBuilderExtensions.cs upstream).
SERILOG_JSON_SAMPLE = {
    "Timestamp": "2026-11-05T10:48:20.5023430+08:00",
    "Level": "Information",
    "MessageTemplate": (
        "LLM interaction recorded. ConversationId={ConversationId} "
        "TraceId={TraceId} AgentId={AgentId}"
    ),
    "TraceId": "ea83bb32abbadee21343a1ac9175f622",  # W3C Activity id
    "SpanId": "09842bdaea3caa5e",
    "Properties": {
        "ConversationId": "conv-e2e-1",
        "TraceId": "trace-e2e-1",  # business trace id (X-Trace-Id)
        "AgentId": "cs-bot",
        "SourceContext": "OpenAgent.E2E",
        "ServiceName": "agent-engine",
        "ServiceVersion": "1.0.0",
        "InstanceId": "host-1",
    },
}

# The plain-text template Serilog uses by default. Parsing it as JSON yields
# nothing, which is why ConsoleFormat=Json exists upstream.
SERILOG_PLAIN_SAMPLE = (
    "[10:33:57 INF] LLM interaction recorded. ConversationId=conv-abc-123 "
    "TraceId=4bf92f3577b34da6a3ce929d0e0e4736 AgentId=cs-bot"
)


def _promtail() -> dict:
    return yaml.safe_load(
        (ROOT / "deploy/promtail/promtail-config.yml").read_text(encoding="utf-8")
    )


def _json_expression_stage(config: dict) -> dict[str, str]:
    for job in config["scrape_configs"]:
        for stage in job.get("pipeline_stages", []):
            if "json" in stage:
                return stage["json"]["expressions"]
    raise AssertionError("no json pipeline stage configured")


def _resolve(data: dict, path: str):
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def test_promtail_reads_the_serilog_json_fields():
    """Every extraction path must resolve against a real OpenAgent JSON event.

    The previous config parsed top-level ``ConversationId``/``ServiceName``,
    but Serilog puts them under ``Properties`` — so the fields all came back
    empty and Loki had no way to correlate a log line with a session.
    """
    expressions = _json_expression_stage(_promtail())

    missing = {
        name: path
        for name, path in expressions.items()
        if _resolve(SERILOG_JSON_SAMPLE, path) is None
    }
    assert not missing, f"fields that do not resolve against real Serilog JSON: {missing}"

    assert _resolve(SERILOG_JSON_SAMPLE, expressions["conversation_id"]) == "conv-e2e-1"
    assert _resolve(SERILOG_JSON_SAMPLE, expressions["service_name"]) == "agent-engine"


def test_promtail_distinguishes_activity_and_business_trace_ids():
    """Serilog emits two different TraceId values; conflating them would make
    Loki correlation disagree with the audit plane's trace ids."""
    expressions = _json_expression_stage(_promtail())

    assert _resolve(SERILOG_JSON_SAMPLE, expressions["activity_trace_id"]) == (
        "ea83bb32abbadee21343a1ac9175f622"
    )
    assert _resolve(SERILOG_JSON_SAMPLE, expressions["source_trace_id"]) == "trace-e2e-1"
    assert expressions["activity_trace_id"] != expressions["source_trace_id"]


def test_plain_text_output_is_why_json_format_is_required():
    """Documents the failure mode this configuration guards against."""
    with pytest.raises(json.JSONDecodeError):
        json.loads(SERILOG_PLAIN_SAMPLE)

    # ...and the plain-text line carries no ServiceName at all.
    assert "ServiceName" not in SERILOG_PLAIN_SAMPLE


def test_promtail_timestamps_use_the_extracted_field():
    config = _promtail()
    expressions = _json_expression_stage(config)

    for job in config["scrape_configs"]:
        for stage in job.get("pipeline_stages", []):
            if "timestamp" in stage:
                assert stage["timestamp"]["source"] in expressions, stage


def test_promtail_labels_stay_low_cardinality():
    """Only service identity may become a Loki label; ids belong in
    structured metadata, or the index explodes."""
    config = _promtail()

    labelled: set[str] = set()
    for job in config["scrape_configs"]:
        for stage in job.get("pipeline_stages", []):
            if "labels" in stage and isinstance(stage["labels"], dict):
                labelled.update(stage["labels"])

    assert labelled == {"service_name"}, labelled


def test_promtail_selects_the_openagent_app_services():
    """The Docker discovery must target the platform's compose services, not
    pick up the audit stack's own containers."""
    config = _promtail()
    job = config["scrape_configs"][0]

    assert "docker_sd_configs" in job
    keep_rules = [
        rule for rule in job["relabel_configs"] if rule.get("action") == "keep"
    ]
    assert keep_rules, "no keep rule: promtail would scrape every container"
    pattern = keep_rules[0]["regex"]
    for service in ("engine", "router", "runner"):
        assert re.search(pattern, service), f"{service} not matched by {pattern}"
    # The audit stack itself must not be scraped into the alerting copy.
    assert not re.search(pattern, "audit-api")
    assert not re.search(pattern, "loki")


def test_compose_gateway_requires_auth_and_joins_the_app_network():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    gateway = compose["services"]["masking-gateway"]

    assert gateway["environment"]["AUDIT_GATEWAY_REQUIRE_AUTH"] == "true"
    assert "openagent" in gateway["networks"], gateway["networks"]


def test_compose_owns_both_networks_and_declares_neither_external():
    """Guards a deadlock that made a fresh two-stack deployment impossible.

    The audit stack and the OpenAgent stack share two networks. If either side
    declares one of them ``external``, ``docker compose up`` aborts with
    "network ... declared as external, but could not be found" — each stack
    waits for the other to create it. This stack therefore owns both networks
    (no ``external`` flag) and must be started first.
    """
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    for network in ("default", "openagent"):
        assert network in compose["networks"], network
        assert "external" not in compose["networks"][network], (
            f"network '{network}' must be created by this stack; declaring it external "
            "deadlocks against the OpenAgent stack's external reference"
        )


def test_compose_does_not_expose_audit_internals_to_the_platform():
    """Only the gateway joins the OpenAgent network; the vault, Langfuse and
    decrypt service must stay on the audit network."""
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    for name in ("audit-db", "langfuse-web", "langfuse-worker", "decrypt-svc"):
        networks = compose["services"][name].get("networks")
        assert networks in (None, ["default"], ["openagent-audit"]), (name, networks)