#!/bin/sh
# Initialise the audit database: apply the schema/role split, with each
# service role receiving its OWN password.
#
# Why a script instead of mounting init.sql straight into Postgres: the SQL
# needs psql variables for the passwords, and it must be re-runnable on an
# existing volume (role passwords can be rotated without dropping data).

set -eu

DB_NAME="${AUDIT_DB_NAME:-openagent_audit}"

: "${AUDIT_AGENT_WRITER_PASSWORD:?AUDIT_AGENT_WRITER_PASSWORD is required}"
: "${AUDIT_API_PASSWORD:?AUDIT_API_PASSWORD is required}"
: "${AUDIT_DECRYPT_PASSWORD:?AUDIT_DECRYPT_PASSWORD is required}"
: "${AUDIT_RETENTION_PASSWORD:?AUDIT_RETENTION_PASSWORD is required}"

# Guard against the classic misconfiguration: one password shared by every
# role reintroduces the privilege-escalation path this split exists to close.
if [ "${AUDIT_AGENT_WRITER_PASSWORD}" = "${AUDIT_API_PASSWORD}" ] || \
   [ "${AUDIT_API_PASSWORD}" = "${AUDIT_DECRYPT_PASSWORD}" ] || \
   [ "${AUDIT_DECRYPT_PASSWORD}" = "${AUDIT_RETENTION_PASSWORD}" ] || \
   [ "${AUDIT_AGENT_WRITER_PASSWORD}" = "${AUDIT_DECRYPT_PASSWORD}" ] || \
   [ "${AUDIT_AGENT_WRITER_PASSWORD}" = "${AUDIT_RETENTION_PASSWORD}" ] || \
   [ "${AUDIT_API_PASSWORD}" = "${AUDIT_RETENTION_PASSWORD}" ]; then
  echo "error: every audit role needs a DISTINCT password" >&2
  echo "       rotate them: openssl rand -hex 32 (one per role)" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 \
     --username "${POSTGRES_USER:-audit_owner}" \
     --dbname "${DB_NAME}" \
     -v agent_writer_password="${AUDIT_AGENT_WRITER_PASSWORD}" \
     -v audit_api_password="${AUDIT_API_PASSWORD}" \
     -v decrypt_svc_password="${AUDIT_DECRYPT_PASSWORD}" \
     -v audit_retention_password="${AUDIT_RETENTION_PASSWORD}" \
     -f /docker-entrypoint-initdb.d/10_audit_schema.sql

echo "audit schema + roles initialised"