# OpenAgent.Audit

The audit and observability data plane for OpenAgent: records user request details, prompts, and every model response, and powers conversation auditing with display-time masking of sensitive information.

- **Trace data**: self-hosted Langfuse open-source edition (Postgres + ClickHouse + Redis + S3 event bucket); every Agent reports through the Langfuse Python SDK, and masking plus export run on the background export thread, not the request thread
- **Display-time masking (Mode B)**: at ingestion, each sensitive entity detected by Presidio becomes an `entity ID + mask` in the trace; its AES-256-GCM ciphertext (data key wrapped with a public key) goes to a separate vault table. Audit views render the stored masks without decrypting; compliance leads can restore single records after approval, and only the decrypt service can use the private key in KMS
- **Multimodal media**: images and files are encrypted on the Agent with the same public key and uploaded directly to S3-compatible object storage (SeaweedFS / MinIO, SSE-KMS); traces store only `s3://` key + sha256 references, and viewing an original follows the same approval flow
- **Audit log**: browsing, restore requests, approvals, and decryptions go to an append-only, hash-chained audit log table, archived to an Object Lock bucket; Loki receives only a copy for real-time alerting
- **Storage boundary**: conversation business storage (session restore / continuation, backed by the business's own online store such as Postgres) is separate from this audit store; the two correlate by conversation id. This repo is not a business data source.

Loki carries only regular service logs (errors, metadata) and the alerting copy of audit events — never prompt storage.

## Documentation

- [Technical solution report (single-page HTML, opens directly in browsers)](docs/design/agent-logging-audit-solution.html)
  - Recommended architecture and data transports (Agent → Langfuse / audit vault / S3 / Loki)
  - Trace tree example and identifier mapping (conversation / user / agent id)
  - Loki limitations and candidate comparison
  - Threat model: what the design protects against and what is out of scope
  - Display-time masking: three-view demo, role-based permissions, audit log, and Chinese entity recognition notes
  - Rollout checklist and phased implementation path (test environment → write side before real traffic → read side)

## License

[MIT](LICENSE)
