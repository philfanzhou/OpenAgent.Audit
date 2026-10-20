"""OpenAgent.Audit — audit and observability data plane.

Layout mirrors the technical proposal (docs/design/agent-logging-audit-solution.html):

- ``openagent_audit.crypto``   — AES-256-GCM envelope encryption (public-key wrap / KMS)
- ``openagent_audit.pii``      — Chinese PII detection + display-time masking pipeline
- ``openagent_audit.vault``    — ciphertext vault, hash-chained append-only audit log
- ``openagent_audit.tracing``  — Langfuse export-thread masking hook, trace stores
- ``openagent_audit.media``    — client-side encrypted media upload / references
- ``openagent_audit.alerts``   — Loki audit-event copies (alerting only)
- ``openagent_audit.services`` — audit-api (+ audit-web), decrypt-svc, retention jobs
- ``openagent_audit.agent``    — agent-side instrumentation helpers
"""

__version__ = "0.1.0"
