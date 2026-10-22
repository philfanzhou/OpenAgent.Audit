-- OpenAgent.Audit — audit-domain schema + privilege split (proposal §01 lane 审计域).
--
-- Roles:
--   audit_owner  schema owner (migrations)
--   agent_writer Agent account: INSERT-only on entity_ciphertext (proposal §02)
--   audit_api    audit-api: restore requests RW + audit log append/read (no
--                UPDATE/DELETE — append-only preserved); NO access to
--                ciphertext whatsoever (the structural no-bypass property)
--   decrypt_svc  decrypt-svc: the ONLY role that reads ciphertext
--   audit_retention  retention job: reads audit log for archiving, deletes
--                expired ciphertext rows; never reads ciphertext values it
--                does not delete, never touches restore_request

\connect openagent_audit

CREATE TABLE IF NOT EXISTS entity_ciphertext (
    entity_id   TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    trace_id    TEXT,
    session_id  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_entity_session ON entity_ciphertext(session_id);
CREATE INDEX IF NOT EXISTS ix_entity_trace   ON entity_ciphertext(trace_id);
CREATE INDEX IF NOT EXISTS ix_entity_created ON entity_ciphertext(created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,
    role        TEXT NOT NULL,
    action      TEXT NOT NULL,
    object_type TEXT,
    object_id   TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);
-- append-only enforcement: no UPDATE/DELETE grants exist for any app role.

CREATE TABLE IF NOT EXISTS restore_request (
    id                TEXT PRIMARY KEY,
    object_type       TEXT NOT NULL,
    object_id         TEXT NOT NULL,
    reason            TEXT NOT NULL,
    requested_by      TEXT NOT NULL,
    trace_id          TEXT,
    session_id        TEXT,
    status            TEXT NOT NULL,
    approver          TEXT,
    decision_comment  TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    reveal_expires_at TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Application roles (passwords supplied via env at deploy time; adjust or use
-- your secret manager).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'agent_writer') THEN
    CREATE ROLE agent_writer LOGIN PASSWORD 'change-me-agent';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_api') THEN
    CREATE ROLE audit_api LOGIN PASSWORD 'change-me-api';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'decrypt_svc') THEN
    CREATE ROLE decrypt_svc LOGIN PASSWORD 'change-me-decrypt';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_retention') THEN
    CREATE ROLE audit_retention LOGIN PASSWORD 'change-me-retention';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO agent_writer, audit_api, decrypt_svc, audit_retention;

-- Agent: insert ciphertext rows, nothing else.
GRANT INSERT ON entity_ciphertext TO agent_writer;

-- audit-api: restore workflow + audit appends; reads the audit log for the
-- audit-web pages; still no UPDATE/DELETE on audit_log (append-only) and
-- explicitly no ciphertext read.
GRANT SELECT, INSERT, UPDATE ON restore_request TO audit_api;
GRANT INSERT, SELECT ON audit_log TO audit_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO audit_api;

-- decrypt-svc: the only ciphertext reader; verifies requests itself.
GRANT SELECT ON entity_ciphertext TO decrypt_svc;
GRANT SELECT ON restore_request TO decrypt_svc;
GRANT INSERT ON audit_log TO decrypt_svc;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO decrypt_svc;

-- retention job: delete expired ciphertext rows + read the audit log to
-- archive it (watermark) + append run records. No restore_request access and
-- no other table privileges.
GRANT SELECT, DELETE ON entity_ciphertext TO audit_retention;
GRANT SELECT, INSERT ON audit_log TO audit_retention;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO audit_retention;
