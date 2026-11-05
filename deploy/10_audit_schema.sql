-- OpenAgent.Audit — audit-domain schema + privilege split (proposal §01 lane 审计域).
--
-- Schema ownership and DDL live HERE, never in application startup: the
-- application roles deliberately have no CREATE right, so a service cannot
-- grant itself capabilities at runtime (see postgres_store.py).
--
-- Roles and their secret variable (each must be independent — do NOT reuse
-- one password across roles, that breaks the whole isolation argument):
--
--   audit_owner      schema owner, runs this file + migrations   AUDIT_OWNER_PASSWORD
--   agent_writer     INSERT-only on entity_ciphertext            AUDIT_AGENT_WRITER_PASSWORD
--   audit_api        restore requests RW + audit log append/read  AUDIT_API_PASSWORD
--                    NO access to ciphertext whatsoever (the structural
--                    no-bypass property)
--   decrypt_svc      the ONLY role that reads ciphertext          AUDIT_DECRYPT_PASSWORD
--   audit_retention  deletes expired ciphertext, reads audit log   AUDIT_RETENTION_PASSWORD
--                    for archiving; never reads restore_request
--
-- Passwords are injected by deploy/init_db.sh from the environment; this
-- file contains no literal credentials.

\connect openagent_audit

-- ---------------------------------------------------------------------------
-- Schema (owned by audit_owner, created here only)
-- ---------------------------------------------------------------------------

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

-- Schema version marker: application startup reads this and refuses to run
-- against an un-migrated schema instead of trying to create tables itself.
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO schema_version (version) VALUES (1)
ON CONFLICT (version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  v_role TEXT;
BEGIN
  FOREACH v_role IN ARRAY ARRAY['agent_writer', 'audit_api', 'decrypt_svc', 'audit_retention']
  LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = v_role) THEN
      EXECUTE format('CREATE ROLE %I LOGIN', v_role);
    END IF;
  END LOOP;
END
$$;

-- Passwords come from psql variables so no credential is committed here.
-- deploy/init_db.sh passes them via `psql -v api_password=... -v ...`.
\set ON_ERROR_STOP on
ALTER ROLE agent_writer    PASSWORD :'agent_writer_password';
ALTER ROLE audit_api       PASSWORD :'audit_api_password';
ALTER ROLE decrypt_svc     PASSWORD :'decrypt_svc_password';
ALTER ROLE audit_retention PASSWORD :'audit_retention_password';

GRANT USAGE ON SCHEMA public TO agent_writer, audit_api, decrypt_svc, audit_retention;

-- ---------------------------------------------------------------------------
-- Grants (least privilege per service)
-- ---------------------------------------------------------------------------

-- Agent: insert ciphertext rows, nothing else. No SELECT — the writer can
-- never read back what it wrote (or anything else) to exfiltrate.
GRANT INSERT ON entity_ciphertext TO agent_writer;

-- audit-api: restore workflow + audit appends; reads the audit log for the
-- audit-web pages; still no UPDATE/DELETE on audit_log (append-only) and
-- explicitly no ciphertext access at all.
GRANT SELECT, INSERT, UPDATE ON restore_request TO audit_api;
GRANT INSERT, SELECT ON audit_log TO audit_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO audit_api;

-- decrypt-svc: the only ciphertext reader; verifies restore requests itself.
GRANT SELECT ON entity_ciphertext TO decrypt_svc;
GRANT SELECT ON restore_request TO decrypt_svc;
-- Audit-log hash chain: appending requires reading the previous link
-- (seq + entry_hash) and RETURNING seq. Column-level grants give exactly
-- that and nothing more: `detail` (which may quote object identifiers) and
-- DELETEs stay denied.
GRANT SELECT (seq, entry_hash) ON audit_log TO decrypt_svc;
GRANT INSERT ON audit_log TO decrypt_svc;
GRANT USAGE, SELECT ON SEQUENCE audit_log_seq_seq TO decrypt_svc;

-- retention job: delete expired ciphertext rows + read the audit log to
-- archive it (watermark) + append run records. No restore_request access.
GRANT SELECT, DELETE ON entity_ciphertext TO audit_retention;
GRANT SELECT, INSERT ON audit_log TO audit_retention;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO audit_retention;
GRANT SELECT ON schema_version TO agent_writer, audit_api, decrypt_svc, audit_retention;