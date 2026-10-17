# OpenAgent.Audit

The audit and observability data plane for OpenAgent: records user request details, prompts, and every model response, and powers conversation auditing with display-time masking of sensitive information.

- **Trace data**: self-hosted Langfuse (Postgres + ClickHouse + Redis); SDK / OTLP asynchronous batched ingestion that never blocks business requests
- **Multimodal media**: images and files are uploaded directly to S3-compatible object storage (SeaweedFS / MinIO, SSE-KMS); traces store only `s3://` key + sha256 references
- **Display-time masking (Mode B)**: Presidio encrypt (AES-256-GCM) turns sensitive entities into reversible ciphertext tokens at ingestion; audit views render masked values by default, and compliance leads can decrypt single records via KMS authorization with every decryption fully logged
- **Storage boundary**: conversation business storage (session restore / continuation, backed by the business's own online store such as Postgres) is separate from this audit store; the two correlate by conversation id. This repo is not a business data source.

Loki carries only regular service logs (errors, audit events, metadata) — never prompt storage.

## Documentation

- [Technical solution report (single-page HTML, opens directly in browsers)](docs/design/agent-logging-audit-solution.html)
  - Recommended architecture and data transports (Agent → Langfuse / S3 / Loki)
  - Trace tree example and identifier mapping (conversation / user / agent id)
  - Loki limitations and candidate comparison
  - Display-time masking: three-view demo, role-based permissions, bypass prevention, and Chinese entity recognition notes
  - Rollout checklist and phased implementation path (config / light coding / custom development)

## License

[MIT](LICENSE)
