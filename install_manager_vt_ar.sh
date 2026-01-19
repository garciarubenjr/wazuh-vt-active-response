#!/usr/bin/env bash
set -euo pipefail

# Wazuh Manager bootstrap: add VirusTotal integration + Active Response trigger on rule 87105
# Usage:
#   sudo bash install_manager_vt_ar.sh --vt-key "YOUR_VT_API_KEY"
#
# Notes:
# - VirusTotal integration runs on the manager
# - Active Response executes on the agent (location=local)
# - Requires agent has /var/ossec/active-response/bin/remove-threat.sh installed

OSSEC_CONF="/var/ossec/etc/ossec.conf"
VT_KEY=""

die() { echo "[-] $*" >&2; exit 1; }
info() { echo "[+] $*"; }
need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vt-key)
        VT_KEY="${2:-}"
        [[ -n "${VT_KEY}" ]] || die "--vt-key requires a value"
        shift 2
        ;;
      -h|--help)
        echo 'Usage: sudo bash install_manager_vt_ar.sh --vt-key "YOUR_VT_API_KEY"'
        exit 0
        ;;
      *)
        die "Unknown arg: $1"
        ;;
    esac
  done
  [[ -n "${VT_KEY}" ]] || die "VirusTotal key required: --vt-key"
}

backup_conf() {
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  cp -a "${OSSEC_CONF}" "${OSSEC_CONF}.bak.${ts}"
  info "Backed up ossec.conf -> ${OSSEC_CONF}.bak.${ts}"
}

ensure_vt_integration() {
  info "Ensuring VirusTotal integration is present..."

  if grep -q "<name>virustotal</name>" "${OSSEC_CONF}"; then
    info "VirusTotal integration already present (not duplicating)."
    return 0
  fi

  sed -i "/<\/ossec_config>/ i\\
  <integration>\\
    <name>virustotal</name>\\
    <api_key>${VT_KEY}</api_key>\\
    <group>syscheck</group>\\
    <alert_format>json</alert_format>\\
  </integration>\\
" "${OSSEC_CONF}"

  info "Added VirusTotal integration."
}

ensure_active_response() {
  info "Ensuring Active Response command + trigger for VT rule 87105..."

  if grep -q "<name>remove-threat</name>" "${OSSEC_CONF}"; then
    info "Active Response command already present (not duplicating)."
    return 0
  fi

  sed -i "/<\/ossec_config>/ i\\
  <command>\\
    <name>remove-threat</name>\\
    <executable>remove-threat.sh</executable>\\
    <timeout_allowed>no</timeout_allowed>\\
  </command>\\
\\
  <active-response>\\
    <disabled>no</disabled>\\
    <command>remove-threat</command>\\
    <location>local</location>\\
    <rules_id>87105</rules_id>\\
  </active-response>\\
" "${OSSEC_CONF}"

  info "Added Active Response trigger for rule 87105."
}

restart_manager() {
  info "Restarting wazuh-manager..."
  systemctl restart wazuh-manager
  systemctl --no-pager --full status wazuh-manager | sed -n '1,15p' || true
}

print_verify() {
  cat <<'EOF'

============================================================
Manager setup complete.

Verify VirusTotal integration:
  sudo tail -n 100 /var/ossec/logs/integrations.log

Verify VT alert firing (rule 87105):
  sudo tail -n 200 /var/ossec/logs/alerts/alerts.json | egrep -i "virustotal|87105"

If VT alerts appear but the file is not deleted:
- Confirm agent has /var/ossec/active-response/bin/remove-threat.sh
- Confirm agent log: /var/ossec/logs/active-responses.log
============================================================

EOF
}

main() {
  need_root
  parse_args "$@"
  backup_conf
  ensure_vt_integration
  ensure_active_response
  restart_manager
  print_verify
}

main "$@"
