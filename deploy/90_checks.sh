#!/bin/sh
# Post-initialisation assertions for the audit database.
#
# These run only on the first boot (docker-entrypoint-initdb.d), and catch the
# privilege mistakes that would otherwise surface as confusing runtime errors
# in production:
#
#   * a role that can read ciphertext but is not decrypt_svc (isolation breach)
#   * decrypt_svc unable to append to the audit-log hash chain
#   * the schema missing for an application role

set -eu
DB="${AUDIT_DB_NAME:-openagent_audit}"
FAIL=0

check() {
  local desc="$1" sql="$2" user="$3" pwd="$4" expect="$5"
  if PGPASSWORD="$pwd" psql -h 127.0.0.1 -U "$user" -d "$DB" -tAc "$sql" >/dev/null 2>&1; then
    actual="allowed"
  else
    actual="denied"
  fi
  if [ "$actual" != "$expect" ]; then
    echo "  [FAIL] $desc: expected $expect, got $actual" >&2
    FAIL=1
  else
    echo "  [ok]   $desc"
  fi
}

echo "verifying audit privilege split"

# The writer must not be able to read back ciphertext.
check "agent_writer cannot SELECT ciphertext" \
  "SELECT 1 FROM entity_ciphertext LIMIT 1" \
  agent_writer "${AUDIT_AGENT_WRITER_PASSWORD}" denied

# audit-api must have no ciphertext access at all.
check "audit_api cannot SELECT ciphertext" \
  "SELECT 1 FROM entity_ciphertext LIMIT 1" \
  audit_api "${AUDIT_API_PASSWORD}" denied

# decrypt-svc is the sole reader.
check "decrypt_svc can SELECT ciphertext" \
  "SELECT 1 FROM entity_ciphertext LIMIT 1" \
  decrypt_svc "${AUDIT_DECRYPT_PASSWORD}" allowed

# Hash-chain append needs seq + entry_hash, and RETURNING seq.
check "decrypt_svc can read audit_log hash chain" \
  "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1" \
  decrypt_svc "${AUDIT_DECRYPT_PASSWORD}" allowed

# ...but must not see the free-form detail column.
check "decrypt_svc cannot read audit_log.detail" \
  "SELECT detail FROM audit_log LIMIT 1" \
  decrypt_svc "${AUDIT_DECRYPT_PASSWORD}" denied

# Append-only: no role may delete audit entries.
check "audit_api cannot DELETE audit_log" \
  "DELETE FROM audit_log WHERE false" \
  audit_api "${AUDIT_API_PASSWORD}" denied

if [ "$FAIL" -ne 0 ]; then
  echo "error: privilege verification failed" >&2
  exit 1
fi

echo "privilege split verified"