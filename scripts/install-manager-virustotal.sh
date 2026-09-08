#!/usr/bin/env bash
set -euo pipefail

# Wazuh Manager bootstrap
#
# - Configures VirusTotal enrichment for FIM alerts
# - Configures Active Response using quarantine-threat.sh
# - Backs up and validates ossec.conf
# - Rolls back if the manager fails to restart
#
# VirusTotal API key:
#
# Option 1:
#   Run the script and enter the key at the hidden prompt.
#
# Option 2:
#   Supply VT_API_KEY through the environment.
#
# Example:
#   sudo env VT_API_KEY="YOUR_KEY" \
#       bash scripts/install-manager-virustotal.sh

OSSEC_CONF="/var/ossec/etc/ossec.conf"

COMMAND_NAME="quarantine-threat"
COMMAND_EXECUTABLE="quarantine-threat.sh"

VT_RULE_ID="${VT_RULE_ID:-87105}"
VT_KEY="${VT_API_KEY:-}"

BACKUP_FILE=""

die() {
    echo "[-] $*" >&2
    exit 1
}

info() {
    echo "[+] $*"
}

need_root() {
    [[ "${EUID}" -eq 0 ]] \
        || die "Run as root with sudo."
}

require_wazuh_manager() {
    [[ -d /var/ossec ]] \
        || die "Wazuh installation directory not found."

    [[ -f "${OSSEC_CONF}" ]] \
        || die "Wazuh configuration not found: ${OSSEC_CONF}"

    systemctl list-unit-files wazuh-manager.service \
        >/dev/null 2>&1 \
        || die "wazuh-manager service not found."
}

install_dependencies() {
    local missing=false

    command -v python3 >/dev/null 2>&1 || missing=true
    command -v xmllint >/dev/null 2>&1 || missing=true

    if [[ "${missing}" == false ]]; then
        return
    fi

    command -v apt-get >/dev/null 2>&1 \
        || die "Automatic dependency installation currently supports Debian/Ubuntu."

    info "Installing dependencies..."

    apt-get update

    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y python3 libxml2-utils
}

get_vt_key() {
    if [[ -z "${VT_KEY}" ]]; then
        [[ -r /dev/tty ]] \
            || die "No VirusTotal API key supplied."

        read \
            -r \
            -s \
            -p "VirusTotal API key: " \
            VT_KEY \
            </dev/tty

        printf '\n' >/dev/tty
    fi

    [[ -n "${VT_KEY}" ]] \
        || die "VirusTotal API key cannot be empty."

    # Prevent unsafe XML injection.
    if [[ "${VT_KEY}" =~ [\<\>\&] ]]; then
        die "VirusTotal API key contains unsupported XML characters."
    fi

    [[ "${VT_RULE_ID}" =~ ^[0-9]+$ ]] \
        || die "VT_RULE_ID must be numeric."
}

backup_conf() {
    local timestamp

    timestamp="$(date +%Y%m%d-%H%M%S)"
    BACKUP_FILE="${OSSEC_CONF}.bak.${timestamp}"

    cp -a "${OSSEC_CONF}" "${BACKUP_FILE}"

    info "Configuration backup created:"
    info "${BACKUP_FILE}"
}

configure_manager() {
    info "Configuring VirusTotal integration and Active Response..."

    VT_KEY_ENV="${VT_KEY}" \
    VT_RULE_ID_ENV="${VT_RULE_ID}" \
    COMMAND_NAME_ENV="${COMMAND_NAME}" \
    COMMAND_EXECUTABLE_ENV="${COMMAND_EXECUTABLE}" \
    python3 - "${OSSEC_CONF}" <<'PY'
import os
import re
import sys
from pathlib import Path

conf_path = Path(sys.argv[1])

vt_key = os.environ["VT_KEY_ENV"]
rule_id = os.environ["VT_RULE_ID_ENV"]
command_name = os.environ["COMMAND_NAME_ENV"]
command_executable = os.environ[
    "COMMAND_EXECUTABLE_ENV"
]

text = conf_path.read_text()

integration = f"""  <integration>
    <name>virustotal</name>
    <api_key>{vt_key}</api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
"""

command = f"""  <command>
    <name>{command_name}</name>
    <executable>{command_executable}</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
"""

active_response = f"""  <active-response>
    <disabled>no</disabled>
    <command>{command_name}</command>
    <location>local</location>
    <rules_id>{rule_id}</rules_id>
  </active-response>
"""

def replace_or_insert(pattern, replacement, content):
    if re.search(pattern, content, flags=re.DOTALL):
        return re.sub(
            pattern,
            replacement.rstrip(),
            content,
            count=1,
            flags=re.DOTALL
        )

    close = "</ossec_config>"

    idx = content.rfind(close)

    if idx < 0:
        raise SystemExit(
            "Could not locate </ossec_config>"
        )

    return (
        content[:idx]
        + replacement
        + "\n"
        + content[idx:]
    )

# Remove legacy remove-threat Active Response blocks to prevent
# both deletion and quarantine from firing.

text = re.sub(
    r"<command>\s*"
    r"<name>\s*remove-threat\s*</name>"
    r".*?</command>\s*",
    "",
    text,
    flags=re.DOTALL
)

text = re.sub(
    r"<active-response>\s*"
    r".*?<command>\s*remove-threat\s*</command>"
    r".*?</active-response>\s*",
    "",
    text,
    flags=re.DOTALL
)

# Replace an existing VirusTotal integration or add one.

vt_pattern = (
    r"<integration>\s*"
    r".*?<name>\s*virustotal\s*</name>"
    r".*?</integration>"
)

text = replace_or_insert(
    vt_pattern,
    integration,
    text
)

# Replace the quarantine command or add it.

command_pattern = (
    rf"<command>\s*"
    rf".*?<name>\s*{re.escape(command_name)}\s*</name>"
    rf".*?</command>"
)

text = replace_or_insert(
    command_pattern,
    command,
    text
)

# Replace the quarantine Active Response or add it.

response_pattern = (
    rf"<active-response>\s*"
    rf".*?<command>\s*{re.escape(command_name)}\s*</command>"
    rf".*?</active-response>"
)

text = replace_or_insert(
    response_pattern,
    active_response,
    text
)

conf_path.write_text(text)
PY
}

validate_xml() {
    info "Validating Wazuh manager XML..."

    if ! xmllint --noout "${OSSEC_CONF}"; then
        info "Invalid configuration detected."
        info "Restoring backup."

        cp -a "${BACKUP_FILE}" "${OSSEC_CONF}"

        die "XML validation failed."
    fi

    info "XML validation passed."
}

restart_manager() {
    info "Restarting wazuh-manager..."

    if ! systemctl restart wazuh-manager; then
        info "Manager restart failed."
        info "Restoring previous configuration."

        cp -a "${BACKUP_FILE}" "${OSSEC_CONF}"

        systemctl restart wazuh-manager || true

        die "Manager restart failed; configuration rolled back."
    fi

    systemctl \
        --no-pager \
        --full \
        status wazuh-manager \
        | sed -n '1,15p' \
        || true
}

print_summary() {
    cat <<EOF

============================================================
Wazuh Manager VirusTotal setup complete
============================================================

VirusTotal integration:

  group: syscheck

Active Response:

  command: ${COMMAND_NAME}
  executable: ${COMMAND_EXECUTABLE}
  location: local
  triggering rule: ${VT_RULE_ID}

Verify VirusTotal integration:

  sudo tail -n 100 /var/ossec/logs/integrations.log

Verify VirusTotal alert:

  sudo grep -Ei \\
      'virustotal|${VT_RULE_ID}' \\
      /var/ossec/logs/alerts/alerts.json

Important:

The VirusTotal API key is stored in:

  /var/ossec/etc/ossec.conf

Do not commit this configuration file to GitHub.

The manager does not delete files.

When the configured rule fires, the affected Wazuh agent
runs quarantine-threat.sh locally.

============================================================

EOF
}

main() {
    need_root
    require_wazuh_manager
    install_dependencies
    get_vt_key
    backup_conf
    configure_manager
    validate_xml
    restart_manager
    print_summary
}

main "$@"
