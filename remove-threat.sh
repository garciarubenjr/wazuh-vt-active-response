#!/usr/bin/env bash
set -euo pipefail

# Wazuh Active Response script: deletes a malicious file.
# Triggered by manager (commonly rule_id 87105 from VirusTotal integration).
# Reads JSON payload from stdin.

AR_LOG="/var/ossec/logs/active-responses.log"

log() { echo "$(date -Is) [remove-threat] $*" >> "${AR_LOG}"; }

PAYLOAD="$(cat || true)"
if [[ -z "${PAYLOAD}" ]]; then
  log "ERROR: empty payload"
  exit 0
fi

# Extract likely file path from AR JSON
FILE_PATH="$(echo "${PAYLOAD}" | jq -r '
  .parameters.alert.syscheck.path? //
  .parameters.alert.data.path? //
  .parameters.alert.file? //
  .parameters.alert.full_log? //
  empty
' 2>/dev/null || true)"

# If it's a log line, extract a /path token
if [[ -n "${FILE_PATH}" && "${FILE_PATH}" == *" "* ]]; then
  CANDIDATE="$(echo "${FILE_PATH}" | grep -oE '(/[^ ]+)' | head -n1 || true)"
  [[ -n "${CANDIDATE}" ]] && FILE_PATH="${CANDIDATE}"
fi

if [[ -z "${FILE_PATH}" || "${FILE_PATH}" == "null" ]]; then
  log "ERROR: could not determine file path from payload"
  exit 0
fi

# Safety: only delete regular files
if [[ ! -f "${FILE_PATH}" ]]; then
  log "INFO: not a regular file or missing: ${FILE_PATH}"
  exit 0
fi

# Safety allowlist (adjust as needed)
case "${FILE_PATH}" in
  /tmp/*|/home/*|/var/www/*|/opt/*|/root/*) ;;
  *)
    log "WARN: refused to delete outside allowed roots: ${FILE_PATH}"
    exit 0
    ;;
esac

rm -f -- "${FILE_PATH}"
log "SUCCESS: deleted ${FILE_PATH}"
exit 0
