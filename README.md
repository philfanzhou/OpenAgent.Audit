# OpenAgent.Audit

The audit and observability data plane for OpenAgent: records user request details, prompts, and every model response, and powers conversation auditing with display-time masking of sensitive information.

> **Status: implemented.** This repository now contains the full reference
> implementation of the proposal below — masking pipeline, envelope-encrypted
> entity vault, hash-chained audit log, decrypt-svc, audit-api/audit-web,
> retention jobs, and the Langfuse export hook. See [Implementation](#implementation).

- **Trace data**: self-hosted Langfuse open-source edition (Postgres + ClickHouse + Redis + S3 event bucket); every Agent reports through the Langfuse Python SDK, and masking plus export run on the background export thread, not the request thread
- **Two roles, one console**: every identity the OpenAgent platform vouches for signs in as an ordinary `user` and sees masked conversations. Inside that session an administrator can step up with the admin credentials; masked values then become clickable, and clicking one decrypts that single value. Only the decrypt service ever holds the private key
- **Display-time masking (Mode B)**: at ingestion, each sensitive entity detected by Presidio becomes an `entity ID + mask` in the trace; its AES-256-GCM ciphertext (data key wrapped with a public key) goes to a separate vault table. Audit views render the stored masks without decrypting
- **Every reveal is recorded first**: the audit entry is written before the plaintext is returned, so an unlogged reveal is impossible; the append-only hash chain makes later edits and deletions detectable
- **Multimodal media**: images and files are encrypted on the Agent with the same public key and uploaded directly to S3-compatible object storage (SeaweedFS / MinIO, SSE-KMS); traces store only `s3://` key + sha256 references, and viewing an original follows the same approval flow
- **Audit log**: sign-ins, administrative step-ups, browsing and every decryption go to an append-only, hash-chained audit log table, archived to an Object Lock bucket; Loki receives only a copy for real-time alerting
- **Storage boundary**: conversation business storage (session restore / continuation, backed by the business's own online store such as Postgres) is separate from this audit store; the two correlate by conversation id. This repo is not a business data source.

Loki carries only regular service logs (errors, metadata) and the alerting copy of audit events — never prompt storage.

## Roles and the administrator policy

The audit console is an internal IT tool, so it has exactly two roles.

| Role | How you get it | What you can do |
|---|---|---|
| `user` | Your OpenAgent identity (or the local test account) | Browse sessions and read **masked** conversations |
| `admin` | Click **登录管理员** inside a signed-in session and enter the admin credentials | Everything above, plus click a mask to reveal that one value |

### Who am I? (identity sources)

The console learns your identity from OpenAgent — it does not keep its own
user list.

| Source | When it is used | Identity |
|---|---|---|
| OpenAgent `/api/v1/agent/me` (`AUDIT_AUTH_PROVIDER=http`) | Normal path: the browser carries a platform token | The platform's `username`/`userId`. Always `user` |
| `AUDIT_USERS` (`AUDIT_AUTH_PROVIDER=static`) | Local runs with no platform | The configured name. Always `user` |
| Local test account (`AUDIT_TEST_USERNAME`) | Fallback when the platform forwards no identity | `test`, marked `ephemeral` |

Every platform identity becomes `user`, whatever roles the platform reports:
a role claim in the token never grants the administrator capability here.

### The local test account

`test` / `test@1233456` exists so somebody can confirm the console renders when
OpenAgent is not forwarding an identity. It is deliberately limited:

- **always an ordinary user** — it cannot unlock the administrator role, the
  button is not rendered, and a direct attempt is refused (403) and logged as
  `ADMIN_LOGIN_REFUSED`;
- **expires after one hour** (`AUDIT_TEST_SESSION_MINUTES`);
- **disabled** by leaving `AUDIT_TEST_USERNAME`/`AUDIT_TEST_PASSWORD` empty.

Its credentials are documented here, which is exactly why it must never be
able to decrypt.

### Administrator password storage

Store a **hash**, not the plaintext:

```bash
python scripts/hash_admin_password.py --password 'your-admin-password'
# -> pbkdf2_sha256$210000$<salt>$<hash>   → AUDIT_ADMIN_PASSWORD_HASH
```

The console then verifies the password against the hash (PBKDF2-HMAC-SHA256,
210 000 iterations, constant-time compare). A leaked `.env` no longer hands out
decryption capability, and `AUDIT_ADMIN_PASSWORD` (plaintext) is ignored when a
hash is configured.

### Unlock policy (configurable via `.env`)

| Setting | Default | Effect |
|---|---|---|
| `AUDIT_ADMIN_SESSION_MINUTES` | `5` | The unlock expires five minutes after login; the session drops back to `user` automatically, even if the browser sends no further requests |
| `AUDIT_ADMIN_COOLDOWN_MINUTES` | `10` | After the unlock ends (by timeout **or** by 退出管理员) the same account cannot unlock again for ten minutes. A blocked attempt is logged as `ADMIN_LOGIN_BLOCKED` |

**Search and paging**: the session list and the audit log both page at ten
rows per page, twenty pages maximum (200 rows). Anything older is reached with
a filter — date range, role, action, account or keyword — rather than by
paging forever. Filters accept local time (`YYYY-MM-DDTHH:MM`).

**Timezone**: every entry is **stored in UTC** and **rendered** in
`AUDIT_DISPLAY_TIMEZONE` (default `Asia/Shanghai`). Pages show the zone label
in the footer; the JSON API returns both `ts` (UTC) and `ts_display`.

| Setting | Default | Effect |
|---|---|---|
| `AUDIT_ADMIN_USERNAME` | `admin` | Administrator account name |
| `AUDIT_ADMIN_PASSWORD_HASH` | *(empty)* | Preferred: `python scripts/hash_admin_password.py` — a leaked `.env` then cannot decrypt |
| `AUDIT_ADMIN_PASSWORD` | *(empty)* | Plaintext, for local runs only; the hash wins when both are set. Leave both empty to close the admin login entirely |
| `AUDIT_DISPLAY_TIMEZONE` | `Asia/Shanghai` | Zone used to render and to interpret date filters |

## Implementation

```
src/openagent_audit/
├── config.py                  # env-driven settings (retention, admin policy, backends)
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
├── gateway/                   # Masking Gateway: OTLP ingest for non-Python agents
│   ├── app.py                 #   bearer/x-api-key auth, fail-closed counters
│   └── otlp.py                #   protobuf/gRPC decoding, mask+seal, JSON re-encode
├── alerts/loki.py             # audit-event copies for alerting only
├── services/                  # read side
│   ├── audit_api.py           #   audit-api REST + audit-web UI (user/admin)
│   ├── decrypt_svc.py         #   decrypt-svc: sole ciphertext reader
│   ├── reveal_service.py      #   admin click -> record -> decrypt one entity
│   ├── retention.py           #   purge + Object-Lock archive + watermark
│   └── templates/             #   server-rendered audit-web pages
└── agent/instrument.py        # agent-side reporting (media swap, identifiers)
```

### Quick start (dev, no external services)

```bash
pip install -e ".[dev,langfuse,postgres,s3,otlp]"
python scripts/provision_keys.py --out keys --passphrase "..."
set AUDIT_USERS=token-a:alice:user,token-b:bob:user
set AUDIT_ADMIN_PASSWORD=admin@123456   # local only; use AUDIT_ADMIN_PASSWORD_HASH in production
set AUDIT_PRIVATE_KEY_PATH=keys/audit_private_key.pem
set AUDIT_PRIVATE_KEY_PASSPHRASE=...
set AUDIT_PUBLIC_KEY_PATH=keys/audit_public_key.pem
uvicorn openagent_audit.services.audit_api:create_app --factory --port 8100   # audit-api + audit-web
uvicorn openagent_audit.services.decrypt_app:app --port 8101                  # decrypt-svc
uvicorn openagent_audit.gateway.app:create_app --factory --port 8102          # masking gateway (OpenAgent .NET ingest)
```

Open `http://localhost:8100/ui/login` and sign in with a token from `AUDIT_USERS`.

The masking gateway accepts OTLP over `http/protobuf` (ASP.NET Core's default),
`http/json` and gRPC framing, and forwards masked OTLP/JSON to Langfuse. The
`otlp` extra is only needed for the protobuf/gRPC transports; the Docker image
installs it.

### Tests

```bash
python -m pytest tests -q          # 198 tests pass (3 Postgres integration tests skip without a container)
python scripts/smoke_e2e.py        # boots both services under real uvicorn, exercises audit-api -> decrypt-svc over HTTP
python scripts/smoke_gateway_otlp.py  # boots the gateway + a fake Langfuse, drives real protobuf/gRPC/JSON exports
```

The Postgres integration tests (`tests/test_postgres_integration.py`) auto-skip
unless a disposable container is reachable:

```bash
docker run -d --name openagent-audit-pg-test \
  -e POSTGRES_USER=audit_owner -e POSTGRES_PASSWORD=testpw \
  -e POSTGRES_DB=openagent_audit -p 15432:5432 \
  -v "$(pwd)/deploy/10_audit_schema.sql:/docker-entrypoint-initdb.d/10_audit_schema.sql:ro" \
  postgres:17
```

They verify the deployment privilege split live: the Agent role is
INSERT-only on the ciphertext table, audit-api has no ciphertext grants at
all (the structural no-bypass property), and decrypt-svc is the sole reader.

### Deployment

`docker-compose.yml` brings up the full stack (Langfuse v4 + audit-db +
audit-api + decrypt-svc + masking-gateway + Loki/Promtail); copy `.env.example`
to `.env` and fill in the secrets. `deploy/10_audit_schema.sql` (applied by `deploy/init_db.sh`) creates the audit
schema and the application roles with the grant matrix above.

The `masking-gateway` service joins the OpenAgent application network
(`OPENAGENT_APP_NETWORK`, default `openagent`) so the .NET platform can reach
it by service name; nothing else in this stack is published to that network.

Promtail discovers containers through the Docker socket because the OpenAgent
services log to **container stdout** (Serilog console sink), not to files —
see `deploy/promtail/promtail-config.yml`.

Operations:

- **Retention** runs one pass via `python -m openagent_audit.services.retention`
  (schedule with cron / k8s CronJob; in deployment use the `audit_retention`
  DB role per `deploy/10_audit_schema.sql`).
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
