# OpenAgent.Audit

The audit and observability data plane for OpenAgent: records user request details, prompts, and every model response, and powers conversation auditing with display-time masking of sensitive information.

> **Status: implemented.** This repository now contains the full reference
> implementation of the proposal below — masking pipeline, envelope-encrypted
> entity vault, hash-chained audit log, decrypt-svc, audit-api/audit-web,
> retention jobs, and the Langfuse export hook. See [Implementation](#implementation).

- **Trace data**: self-hosted Langfuse open-source edition (Postgres + ClickHouse + Redis + S3 event bucket); every Agent reports through the Langfuse Python SDK, and masking plus export run on the background export thread, not the request thread
- **Display-time masking (Mode B)**: at ingestion, each sensitive entity detected by Presidio becomes an `entity ID + mask` in the trace; its AES-256-GCM ciphertext (data key wrapped with a public key) goes to a separate vault table. Audit views render the stored masks without decrypting; compliance leads can restore single records after approval, and only the decrypt service can use the private key in KMS
- **Multimodal media**: images and files are encrypted on the Agent with the same public key and uploaded directly to S3-compatible object storage (SeaweedFS / MinIO, SSE-KMS); traces store only `s3://` key + sha256 references, and viewing an original follows the same approval flow
- **Audit log**: browsing, restore requests, approvals, and decryptions go to an append-only, hash-chained audit log table, archived to an Object Lock bucket; Loki receives only a copy for real-time alerting
- **Storage boundary**: conversation business storage (session restore / continuation, backed by the business's own online store such as Postgres) is separate from this audit store; the two correlate by conversation id. This repo is not a business data source.

Loki carries only regular service logs (errors, metadata) and the alerting copy of audit events — never prompt storage.

## Implementation

```
src/openagent_audit/
├── config.py                  # env-driven settings (retention, roles, backends)
├── crypto/                    # AES-256-GCM envelope encryption
│   ├── envelope.py            #   RSA-OAEP public-key wrap + AWS KMS variant
│   └── keys.py                #   key custody: local PEM (decrypt-svc only) / KMS
├── pii/                       # write side: detection + display-time masking
│   ├── recognizers.py         #   CN phone / ID (GB 11643 checksum) / bank card
│   │                          #   (Luhn) / email / context-triggered names
│   ├── engine.py              #   rule engine + optional Presidio (zh spaCy)
│   └── masking.py             #   ⟦TYPE#id|mask⟧ rewriting, vault writes, cache
├── vault/                     # audit domain storage
│   ├── store.py               #   SQLite (dev/tests) implementation
│   ├── postgres_store.py      #   Postgres (deployment) twin
│   ├── hashchain.py           #   append-only audit log hash chain
│   └── models.py
├── tracing/                   # Langfuse integration
│   ├── hook.py                #   mask_otel_spans export-thread hook (fail-closed)
│   ├── drop_monitor.py        #   dropped-batch counters (alert when > 0)
│   ├── trace_store.py         #   Langfuse API adapter + local dev store
│   └── langfuse_setup.py
├── media/                     # client-side encrypted media (s3:// references)
├── alerts/loki.py             # audit-event copies for alerting only
├── services/                  # read side
│   ├── audit_api.py           #   audit-api REST + audit-web UI (3 roles)
│   ├── decrypt_svc.py         #   decrypt-svc: sole ciphertext reader
│   ├── restore_service.py     #   request -> four-eyes approve -> reveal (TTL)
│   ├── retention.py           #   purge + Object-Lock archive + watermark
│   └── templates/             #   server-rendered audit-web pages
└── agent/instrument.py        # agent-side reporting (media swap, identifiers)
```

### Quick start (dev, no external services)

```bash
pip install -e ".[dev,langfuse,postgres,s3]"
python scripts/provision_keys.py --out keys --passphrase "..."
set AUDIT_USERS=token-a:alice:auditor,token-b:bob:compliance_lead,token-c:carol:compliance_lead
set AUDIT_PRIVATE_KEY_PATH=keys/audit_private_key.pem
set AUDIT_PRIVATE_KEY_PASSPHRASE=...
set AUDIT_PUBLIC_KEY_PATH=keys/audit_public_key.pem
uvicorn openagent_audit.services.audit_api:create_app --factory --port 8100   # audit-api + audit-web
uvicorn openagent_audit.services.decrypt_app:app --port 8101                  # decrypt-svc
```

Open `http://localhost:8100/ui/login` and sign in with a token from `AUDIT_USERS`.

### Tests

```bash
python -m pytest tests -q          # 146 tests pass (3 Postgres integration tests skip without a container)
python scripts/smoke_e2e.py        # boots both services under real uvicorn, exercises audit-api -> decrypt-svc over HTTP
```

The Postgres integration tests (`tests/test_postgres_integration.py`) auto-skip
unless a disposable container is reachable:

```bash
docker run -d --name openagent-audit-pg-test \
  -e POSTGRES_USER=audit_owner -e POSTGRES_PASSWORD=testpw \
  -e POSTGRES_DB=openagent_audit -p 15432:5432 \
  -v "$(pwd)/deploy/audit_db_init.sql:/docker-entrypoint-initdb.d/10_init.sql:ro" \
  postgres:17
```

They verify the deployment privilege split live: the Agent role is
INSERT-only on the ciphertext table, audit-api has no ciphertext grants at
all (the structural no-bypass property), and decrypt-svc is the sole reader.

### Deployment

`docker-compose.yml` brings up the full stack (Langfuse v4 + audit-db +
audit-api + decrypt-svc + Loki/Promtail); copy `.env.example` to `.env` and
fill in the secrets. `deploy/audit_db_init.sql` creates the audit schema and
the application roles with the grant matrix above.

Operations:

- **Retention** runs one pass via `python -m openagent_audit.services.retention`
  (schedule with cron / k8s CronJob; in deployment use the `audit_retention`
  DB role from `deploy/audit_db_init.sql`).
- **Alerting** — `deploy/alerting/` contains the Prometheus scrape config and
  alert rules for the export drop counters (`dropped_batches > 0` must page
  someone; fail-closed drops are a loss of restorability).

What remains a compliance decision (configured, not hard-coded): mask depth
per entity type, retention windows, reveal TTL, and the recall/precision
bar for the PII test set — see the 待合规确认 items in the proposal.

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
