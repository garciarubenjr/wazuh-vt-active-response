#!/usr/bin/env bash
set -euo pipefail

# Wazuh Active Response:
# Quarantines a file after a manager-side security rule triggers.
#
# Designed for controlled Wazuh FIM + VirusTotal validation workflows.
# The file is preserved for analyst review instead of being deleted.

AR_LOG="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/quarantine"

# Rule used by this lab for the VirusTotal malicious-file alert.
# Make configurable because rule IDs may differ across environments/versions.
EXPECTED_RULE_ID="${EXPECTED_RULE_ID:-87105}"

# Conservative default roots.
ALLOWED_ROOTS=(
  "/tmp"
  "/var/tmp"
  "/home"
  "/var/www"
)

log() {
  printf '%s [quarantine-threat] %s\n' "$(date -Is)" "$*" >> "${AR_LOG}"
}

die() {
  log "ERROR: $*"
  exit 1
}

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v readlink >/dev/null 2>&1 || die "readlink is required"

PAYLOAD="$(cat || true)"
[[ -n "${PAYLOAD}" ]] || die "empty Active Response payload"

if ! echo "${PAYLOAD}" | jq -e . >/dev/null 2>&1; then
  die "invalid JSON payload"
fi

# Ignore timeout/delete-style actions if ever received.
ACTION="$(echo "${PAYLOAD}" | jq -r '.command // "add"')"

if [[ "${ACTION}" != "add" ]]; then
  log "INFO: ignoring Active Response action: ${ACTION}"
  exit 0
fi

RULE_ID="$(echo "${PAYLOAD}" | jq -r '
  .parameters.alert.rule.id? //
  empty
')"

if [[ -n "${RULE_ID}" && "${RULE_ID}" != "${EXPECTED_RULE_ID}" ]]; then
  log "WARN: refused event from unexpected rule ID: ${RULE_ID}"
  exit 0
fi

# Prefer explicit structured fields.
# Do not attempt to scrape arbitrary paths from full_log.
FILE_PATH="$(echo "${PAYLOAD}" | jq -r '
  .parameters.alert.data.virustotal.source.file? //
  .parameters.alert.syscheck.path? //
  .parameters.alert.data.path? //
  .parameters.alert.file? //
  empty
')"

[[ -n "${FILE_PATH}" && "${FILE_PATH}" != "null" ]] \
  || die "could not determine file path from structured alert fields"

[[ "${FILE_PATH}" == /* ]] \
  || die "refused non-absolute path: ${FILE_PATH}"

# Refuse symlink input rather than following it to another target.
if [[ -L "${FILE_PATH}" ]]; then
  die "refused symbolic link: ${FILE_PATH}"
fi

[[ -f "${FILE_PATH}" ]] \
  || die "file missing or not a regular file: ${FILE_PATH}"

REAL_PATH="$(readlink -f -- "${FILE_PATH}")"
[[ -n "${REAL_PATH}" ]] || die "could not resolve path: ${FILE_PATH}"

allowed=false

for root in "${ALLOWED_ROOTS[@]}"; do
  if [[ "${REAL_PATH}" == "${root}" || "${REAL_PATH}" == "${root}/"* ]]; then
    allowed=true
    break
  fi
done

if [[ "${allowed}" != true ]]; then
  log "WARN: refused quarantine outside allowed roots: ${REAL_PATH}"
  exit 0
fi

install -d -m 0750 -o root -g wazuh "${QUARANTINE_DIR}"

SHA256="$(sha256sum -- "${REAL_PATH}" | awk '{print $1}')"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

BASENAME="$(basename -- "${REAL_PATH}")"

# Keep the resulting filename simple and filesystem-safe.
SAFE_BASENAME="$(printf '%s' "${BASENAME}" | tr -cd 'A-Za-z0-9._-')"
[[ -n "${SAFE_BASENAME}" ]] || SAFE_BASENAME="unknown-file"

DEST="${QUARANTINE_DIR}/${TIMESTAMP}_${SHA256}_${SAFE_BASENAME}"
META="${DEST}.json"

FILE_SIZE="$(stat -c '%s' "${REAL_PATH}" 2>/dev/null || echo "unknown")"
FILE_OWNER="$(stat -c '%U:%G' "${REAL_PATH}" 2>/dev/null || echo "unknown")"

# Capture useful evidence before moving the file.
jq -n \
  --arg timestamp "$(date -Is)" \
  --arg original_path "${REAL_PATH}" \
  --arg quarantine_path "${DEST}" \
  --arg sha256 "${SHA256}" \
  --arg rule_id "${RULE_ID:-unknown}" \
  --arg size "${FILE_SIZE}" \
  --arg owner "${FILE_OWNER}" \
  '{
    timestamp: $timestamp,
    original_path: $original_path,
    quarantine_path: $quarantine_path,
    sha256: $sha256,
    wazuh_rule_id: $rule_id,
    size_bytes: $size,
    original_owner: $owner
  }' > "${META}"

chmod 0600 "${META}"

mv -- "${REAL_PATH}" "${DEST}"
chmod 0600 "${DEST}"

log "SUCCESS: quarantined ${REAL_PATH} -> ${DEST} sha256=${SHA256}"

exit 0
