"""Masking Gateway — OTLP ingest for non-Python agents (e.g. OpenAgent .NET).

Why this exists: the proposal's primary ingest path is the Langfuse *Python*
SDK with the ``mask_otel_spans`` export-thread hook. OpenAgent's backend is
.NET, which cannot embed that SDK. Instead of duplicating the PII rules and
envelope-encryption in a second language, non-Python agents point their
standard OpenTelemetry OTLP exporter at this gateway; it applies the *same*
masking pipeline (single source of truth), seals entities into the audit-domain
vault, and only then forwards the fully-masked spans to Langfuse's native
OTLP endpoint.

Invariants (mirrors proposal §02 通路①):
- nothing unmasked is ever forwarded (fail-closed: masking/vault failure drops
  the batch and the upstream exporter retries);
- ciphertext only ever lands in the audit-domain vault;
- drop counters are exposed for alerting (drops > 0 must page someone).

Trust boundary note: plaintext transits OpenAgent -> gateway over the network,
so the gateway must run inside the same trust domain (same cluster), with
bearer auth on ingest; this is documented as a deviation in
docs/openagent-integration.md.
"""
