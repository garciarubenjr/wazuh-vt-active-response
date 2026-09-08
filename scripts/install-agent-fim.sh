#!/usr/bin/env bash
set -euo pipefail

# Wazuh Agent bootstrap
#
# - Enables/configures File Integrity Monitoring (FIM)
# - Installs quarantine-threat.sh as a Wazuh Active Response script
# - Backs up and validates ossec.conf before restarting the agent
#
# Usage:
#   sudo bash scripts/install-agent-fim.sh --monitor /tmp
#   sudo bash scripts/install-agent-fim.sh \
#       --monitor /tmp \
#       --monitor /var/www
#
# If no --monitor option is supplied, /tmp is monitored.

OSSEC_CONF="/var/ossec/etc/ossec.conf"
AR_BIN_DIR="/var/ossec/active-response/bin"
AR_SCRIPT_NAME="quarantine-threat.sh"
AR_SCRIPT_PATH="${AR_BIN_DIR}/${AR_SCRIPT_NAME}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

BACKUP_FILE=""
declare -a MONITOR_DIRS=()

die() {
    echo "[-] $*" >&2
    exit 1
}

info() {
    echo "[+] $*"
}

need_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run as root with sudo."
}

require_wazuh_agent() {
    [[ -d /var/ossec ]] \
        || die "Wazuh installation directory not found."

    [[ -f "${OSSEC_CONF}" ]] \
        || die "Wazuh configuration not found: ${OSSEC_CONF}"

    systemctl list-unit-files wazuh-agent.service \
        >/dev/null 2>&1 \
        || die "wazuh-agent service not found."
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --monitor)
                [[ -n "${2:-}" ]] \
                    || die "--monitor requires a path."

                MONITOR_DIRS+=("$2")
                shift 2
                ;;

            -h|--help)
                cat <<'EOF'
Usage:

  sudo bash scripts/install-agent-fim.sh \
      --monitor /tmp \
      --monitor /var/www

Options:

  --monitor PATH    Add a directory to Wazuh realtime FIM.
                    May be supplied multiple times.

If no --monitor option is supplied, /tmp is used.
EOF
                exit 0
                ;;

            *)
                die "Unknown argument: $1"
                ;;
        esac
    done

    if [[ "${#MONITOR_DIRS[@]}" -eq 0 ]]; then
        MONITOR_DIRS=("/tmp")
    fi
}

validate_monitor_dirs() {
    local d

    for d in "${MONITOR_DIRS[@]}"; do
        [[ "${d}" == /* ]] \
            || die "Monitor path must be absolute: ${d}"

        [[ -d "${d}" ]] \
            || die "Monitor directory does not exist: ${d}"

        # Avoid writing problematic characters directly into XML.
        if [[ "${d}" =~ [\<\>\&] ]]; then
            die "Unsupported character in monitor path: ${d}"
        fi

        info "Validated monitor directory: ${d}"
    done
}

install_dependencies() {
    local missing=false

    command -v jq >/dev/null 2>&1 || missing=true
    command -v xmllint >/dev/null 2>&1 || missing=true
    command -v python3 >/dev/null 2>&1 || missing=true

    if [[ "${missing}" == false ]]; then
        return
    fi

    command -v apt-get >/dev/null 2>&1 \
        || die "Automatic dependency installation currently supports Debian/Ubuntu."

    info "Installing dependencies..."

    apt-get update
    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y jq libxml2-utils python3
}

backup_conf() {
    local timestamp

    timestamp="$(date +%Y%m%d-%H%M%S)"
    BACKUP_FILE="${OSSEC_CONF}.bak.${timestamp}"

    cp -a "${OSSEC_CONF}" "${BACKUP_FILE}"

    info "Configuration backup created:"
    info "${BACKUP_FILE}"
}

configure_fim() {
    info "Configuring Wazuh File Integrity Monitoring..."

    python3 - "${OSSEC_CONF}" "${MONITOR_DIRS[@]}" <<'PY'
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

conf_path = Path(sys.argv[1])
monitor_dirs = sys.argv[2:]

text = conf_path.read_text()

match = re.search(
    r"<syscheck\b[^>]*>.*?</syscheck>",
    text,
    flags=re.DOTALL
)

if not match:
    raise SystemExit(
        "No <syscheck> section found in ossec.conf"
    )

block = match.group(0)

# Enable syscheck without changing unrelated <disabled> elements.
if re.search(
    r"<disabled>\s*yes\s*</disabled>",
    block,
    flags=re.IGNORECASE
):
    block = re.sub(
        r"<disabled>\s*yes\s*</disabled>",
        "<disabled>no</disabled>",
        block,
        count=1,
        flags=re.IGNORECASE
    )
elif not re.search(
    r"<disabled>\s*(yes|no)\s*</disabled>",
    block,
    flags=re.IGNORECASE
):
    block = re.sub(
        r"(<syscheck\b[^>]*>)",
        r"\1\n    <disabled>no</disabled>",
        block,
        count=1
    )

if "<scan_on_start>" not in block:
    block = re.sub(
        r"(<syscheck\b[^>]*>)",
        r"\1\n    <scan_on_start>yes</scan_on_start>",
        block,
        count=1
    )

if "<frequency>" not in block:
    block = re.sub(
        r"(<syscheck\b[^>]*>)",
        r"\1\n    <frequency>60</frequency>",
        block,
        count=1
    )

existing = [
    re.sub(r"\s+", "", x)
    for x in re.findall(
        r"<directories\b[^>]*>(.*?)</directories>",
        block,
        flags=re.DOTALL
    )
]

for directory in monitor_dirs:
    normalized = re.sub(r"\s+", "", directory)

    if normalized in existing:
        continue

    entry = (
        '    <directories realtime="yes" '
        'report_changes="yes">'
        f'{escape(directory)}'
        '</directories>\n'
    )

    block = block.replace(
        "</syscheck>",
        entry + "  </syscheck>",
        1
    )

new_text = (
    text[:match.start()]
    + block
    + text[match.end():]
)

conf_path.write_text(new_text)
PY
}

validate_xml() {
    info "Validating Wazuh XML configuration..."

    if ! xmllint --noout "${OSSEC_CONF}"; then
        info "Invalid XML detected."
        info "Restoring backup."

        cp -a "${BACKUP_FILE}" "${OSSEC_CONF}"

        die "Configuration validation failed."
    fi

    info "XML validation passed."
}

install_quarantine_script() {
    local source_script

    source_script="${SCRIPT_DIR}/${AR_SCRIPT_NAME}"

    [[ -f "${source_script}" ]] \
        || die "Missing ${source_script}"

    [[ -s "${source_script}" ]] \
        || die "${source_script} is empty."

    head -n1 "${source_script}" \
        | grep -q '^#!' \
        || die "${source_script} does not appear to be an executable script."

    info "Installing Active Response quarantine script..."

    install \
        -d \
        -m 0750 \
        -o root \
        -g wazuh \
        "${AR_BIN_DIR}"

    install \
        -m 0750 \
        -o root \
        -g wazuh \
        "${source_script}" \
        "${AR_SCRIPT_PATH}"

    info "Installed:"
    info "${AR_SCRIPT_PATH}"
}

restart_agent() {
    info "Restarting wazuh-agent..."

    if ! systemctl restart wazuh-agent; then
        info "Agent restart failed."
        info "Restoring previous configuration."

        cp -a "${BACKUP_FILE}" "${OSSEC_CONF}"

        systemctl restart wazuh-agent || true

        die "Agent restart failed; configuration rolled back."
    fi

    systemctl \
        --no-pager \
        --full \
        status wazuh-agent \
        | sed -n '1,12p' \
        || true
}

print_summary() {
    cat <<EOF

============================================================
Wazuh Agent FIM setup complete
============================================================

Monitored directories:
$(printf '  - %s\n' "${MONITOR_DIRS[@]}")

Active Response script:

  ${AR_SCRIPT_PATH}

Quarantine directory used by the response:

  /var/ossec/quarantine

Lab validation example:

  sudo mkdir -p /tmp/malware
  sudo curl https://secure.eicar.org/eicar.com \\
       -o /tmp/malware/eicar

FIM logs:

  sudo tail -n 100 /var/ossec/logs/ossec.log

Active Response logs:

  sudo tail -n 100 /var/ossec/logs/active-responses.log

Quarantine:

  sudo ls -lah /var/ossec/quarantine

Important:

The agent does NOT query VirusTotal directly.

VirusTotal enrichment and the rule decision occur on the
Wazuh manager. The manager then instructs the affected
agent to execute quarantine-threat.sh.

============================================================

EOF
}

main() {
    need_root
    parse_args "$@"
    require_wazuh_agent
    validate_monitor_dirs
    install_dependencies
    backup_conf
    configure_fim
    validate_xml
    install_quarantine_script
    restart_agent
    print_summary
}

main "$@"
