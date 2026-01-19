#!/usr/bin/env bash
set -euo pipefail

# Wazuh Agent bootstrap: enable FIM on chosen paths + install Active Response delete script
# Usage:
#   sudo bash install_agent_fim_ar.sh --monitor "/tmp" --monitor "/home" --monitor "/var/www"
# Defaults if no --monitor is given: /tmp and /home

OSSEC_CONF="/var/ossec/etc/ossec.conf"
AR_BIN_DIR="/var/ossec/active-response/bin"
AR_SCRIPT_NAME="remove-threat.sh"
AR_SCRIPT_PATH="${AR_BIN_DIR}/${AR_SCRIPT_NAME}"

declare -a MONITOR_DIRS=()

die() { echo "[-] $*" >&2; exit 1; }
info() { echo "[+] $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }

require_wazuh_agent() {
  [[ -d /var/ossec && -f "${OSSEC_CONF}" ]] || die "Wazuh agent not found at /var/ossec. Install wazuh-agent first."
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --monitor)
        [[ -n "${2:-}" ]] || die "--monitor requires a path"
        MONITOR_DIRS+=("$2")
        shift 2
        ;;
      -h|--help)
        cat <<EOF
Usage:
  sudo bash install_agent_fim_ar.sh --monitor "/tmp" --monitor "/home" --monitor "/var/www"

If no --monitor is given, defaults to:
  /tmp and /home
EOF
        exit 0
        ;;
      *)
        die "Unknown arg: $1"
        ;;
    esac
  done

  if [[ "${#MONITOR_DIRS[@]}" -eq 0 ]]; then
    MONITOR_DIRS=("/tmp" "/home")
  fi
}

backup_conf() {
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  cp -a "${OSSEC_CONF}" "${OSSEC_CONF}.bak.${ts}"
  info "Backed up ${OSSEC_CONF} -> ${OSSEC_CONF}.bak.${ts}"
}

install_deps() {
  info "Installing dependencies (jq, curl)..."
  apt-get update -y
  apt-get install -y jq curl
}

ensure_syscheck_enabled_and_dirs() {
  info "Enabling FIM (syscheck) + adding monitored directories..."

  grep -q "<syscheck>" "${OSSEC_CONF}" || die "No <syscheck> section found in ${OSSEC_CONF}"

  # Ensure syscheck not disabled
  sed -i 's|<disabled>yes</disabled>|<disabled>no</disabled>|g' "${OSSEC_CONF}"

  # Ensure scan_on_start + reasonable frequency exist
  if ! grep -q "<scan_on_start>" "${OSSEC_CONF}"; then
    sed -i '/<syscheck>/a\  <scan_on_start>yes</scan_on_start>' "${OSSEC_CONF}"
  fi
  if ! grep -q "<frequency>" "${OSSEC_CONF}"; then
    sed -i '/<syscheck>/a\  <frequency>60</frequency>' "${OSSEC_CONF}"
  fi

  # Add dirs (realtime + report_changes)
  for d in "${MONITOR_DIRS[@]}"; do
    if grep -q "<directories[^>]*>${d}</directories>" "${OSSEC_CONF}"; then
      info "Already monitoring: ${d}"
    else
      sed -i "/<\/syscheck>/ i\\
  <directories realtime=\"yes\" report_changes=\"yes\">${d}</directories>" "${OSSEC_CONF}"
      info "Added realtime FIM monitor: ${d}"
    fi
  done
}

install_remove_script() {
  info "Installing Active Response script (${AR_SCRIPT_NAME})..."

  install -d -m 0750 -o root -g wazuh "${AR_BIN_DIR}"

  local src
  src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/active-response/${AR_SCRIPT_NAME}"
  [[ -f "${src}" ]] || die "Missing ${src}. Keep the repo structure."

  cp -f "${src}" "${AR_SCRIPT_PATH}"
  chown root:wazuh "${AR_SCRIPT_PATH}"
  chmod 0750 "${AR_SCRIPT_PATH}"

  info "Installed ${AR_SCRIPT_PATH}"
}

restart_agent() {
  info "Restarting wazuh-agent..."
  systemctl restart wazuh-agent
  systemctl --no-pager --full status wazuh-agent | sed -n '1,12p' || true
}

print_test() {
  cat <<EOF

============================================================
Agent setup complete.

Test (on agent):
  sudo mkdir -p /tmp/malware
  sudo curl https://secure.eicar.org/eicar.com -o /tmp/malware/eicar

Then check logs:
  sudo tail -n 100 /var/ossec/logs/ossec.log | egrep -i "syscheck|integrity"
  sudo tail -n 100 /var/ossec/logs/active-responses.log

Note:
- The file will only be deleted when the MANAGER triggers Active Response (VT rule 87105).
============================================================

EOF
}

main() {
  need_root
  parse_args "$@"
  require_wazuh_agent
  backup_conf
  install_deps
  ensure_syscheck_enabled_and_dirs
  install_remove_script
  restart_agent
  print_test
}

main "$@"
