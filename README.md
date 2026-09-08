# Wazuh + VirusTotal Active Response & Threat Quarantine

A defensive security automation project that combines **Wazuh File Integrity Monitoring (FIM)**, **VirusTotal enrichment**, and **Wazuh Active Response** to detect suspicious files, evaluate them using threat intelligence, and automatically move confirmed threats into a protected quarantine location for analyst review.

> The project prioritizes **containment and evidence preservation over automatic deletion**.

---

## Project Objectives

The goal of this project is to demonstrate an automated endpoint detection and response workflow using Wazuh.

The workflow focuses on:

- Monitoring selected Linux directories with Wazuh FIM
- Detecting newly created or modified files
- Enriching file alerts through VirusTotal
- Triggering Wazuh Active Response after a configured malicious-file rule fires
- Validating the target path before taking action
- Quarantining the suspicious file rather than deleting it
- Calculating and preserving a SHA-256 hash
- Recording file metadata for analyst review
- Maintaining an auditable Active Response log
- Protecting the VirusTotal API key from source-code exposure

---

## Skills Demonstrated

- Wazuh File Integrity Monitoring
- Wazuh Active Response
- VirusTotal API integration
- Linux security automation
- Bash scripting
- Threat-intelligence enrichment
- Endpoint detection and response concepts
- Evidence preservation
- Secure configuration management
- Automated containment
- Defensive scripting
- SOC workflow design

---

## Architecture

The project uses a manager-side enrichment workflow and an agent-side containment workflow.

```text
Monitored Linux Endpoint
        |
        | File Created / Modified
        v
Wazuh File Integrity Monitoring
        |
        | FIM Alert
        v
Wazuh Manager
        |
        | VirusTotal Enrichment
        v
Configured Malicious-File Rule
        |
        | Active Response
        v
Affected Wazuh Agent
        |
        | Validate Path / Rule / File
        | Calculate SHA-256
        | Preserve Metadata
        v
Protected Quarantine
        |
        v
Analyst Review
```

The endpoint does **not** communicate directly with VirusTotal.

VirusTotal enrichment occurs on the Wazuh manager, which then instructs the affected endpoint to execute the Active Response locally.

---

## Response Philosophy

The original version of this project automatically deleted files after a malicious VirusTotal verdict.

The current design instead uses:

**Detect → Enrich → Validate → Quarantine → Preserve → Review**

This provides several advantages:

- Suspicious files remain available for forensic analysis
- SHA-256 hashes are preserved
- Original file paths are recorded
- Response actions remain auditable
- False-positive recovery is possible
- Destructive remediation is not performed automatically

---

## Repository Structure

```text
wazuh-vt-active-response/
├── README.md
└── scripts/
    ├── install-agent-fim.sh
    ├── install-manager-virustotal.sh
    └── quarantine-threat.sh
```

### Script Roles

| Script | Purpose |
|---|---|
| `install-manager-virustotal.sh` | Configures VirusTotal integration and manager-side Active Response |
| `install-agent-fim.sh` | Configures FIM directories and installs the response script on an endpoint |
| `quarantine-threat.sh` | Validates and quarantines a suspicious file while preserving evidence |

---

# Security Workflow

## 1. File Integrity Monitoring

The Wazuh agent monitors explicitly selected directories.

Example monitored locations may include:

- `/tmp`
- `/var/tmp`
- `/var/www`
- Selected application directories

The installer intentionally avoids enabling broad monitoring of the entire filesystem by default.

---

## 2. VirusTotal Enrichment

When Wazuh FIM detects a relevant file event, the manager can submit the file hash to the configured VirusTotal integration.

VirusTotal enrichment occurs centrally on the manager.

The API key is **not stored in this GitHub repository**.

---

## 3. Active Response

When the configured Wazuh malicious-file rule fires, the manager triggers:

```text
quarantine-threat
```

The response is executed locally on the affected endpoint.

The default lab rule is:

```text
87105
```

The rule ID is configurable because Wazuh rules and environments may differ.

---

## 4. Threat Validation

Before moving a file, `quarantine-threat.sh` performs several safety checks.

The response verifies:

- The Active Response payload is valid JSON
- The action is an expected response action
- The configured rule triggered the response
- A structured file path exists in the alert
- The path is absolute
- The target is not a symbolic link
- The target is a regular file
- The resolved path falls within an approved monitoring root

The script does not attempt to extract arbitrary file paths from unstructured log messages.

---

## 5. Evidence Preservation

Before quarantine, the response collects information about the target file.

Preserved evidence includes:

- Original file path
- Quarantine path
- SHA-256 hash
- File size
- Original owner/group
- Wazuh rule ID
- Response timestamp

Metadata is written alongside the quarantined file.

Example:

```text
/var/ossec/quarantine/
├── 20260908T120000Z_<SHA256>_suspicious-file
└── 20260908T120000Z_<SHA256>_suspicious-file.json
```

---

## 6. Quarantine

Confirmed files are moved into:

```text
/var/ossec/quarantine
```

The quarantine directory and its contents are restricted to protect the preserved evidence.

The file is **not automatically destroyed**.

An analyst can inspect the evidence and determine the appropriate remediation action.

---

# Installation

## Requirements

This lab assumes:

- Wazuh Manager installed
- Wazuh Agent installed on monitored endpoints
- Debian/Ubuntu-based systems for automatic dependency installation
- Root or `sudo` privileges
- VirusTotal API key
- Network access required for VirusTotal integration

Clone the repository:

```bash
git clone https://github.com/garciarubenjr/wazuh-vt-active-response.git
cd wazuh-vt-active-response
```

> Review security scripts before executing them in your environment.

---

# Manager Configuration

Run the manager installer on the **Wazuh Manager**:

```bash
sudo bash scripts/install-manager-virustotal.sh
```

The script securely prompts for the VirusTotal API key without placing the key directly in the command line.

Alternatively, the key can be supplied through the environment:

```bash
sudo env VT_API_KEY="YOUR_API_KEY" \
  bash scripts/install-manager-virustotal.sh
```

The manager installer:

- Validates the Wazuh manager installation
- Creates a timestamped backup of `ossec.conf`
- Configures VirusTotal integration
- Configures the `quarantine-threat` Active Response
- Validates the XML configuration
- Restores the backup if validation fails
- Restarts the Wazuh manager
- Rolls back if the manager cannot restart successfully

---

## VirusTotal API Key Security

The VirusTotal API key is written to the local Wazuh manager configuration as required by the integration.

Do **not** commit:

```text
/var/ossec/etc/ossec.conf
```

or any file containing the API key to GitHub.

The project does not hardcode the API key into its scripts.

---

# Agent Configuration

Run the agent installer on each Linux endpoint that should participate in the workflow.

Example:

```bash
sudo bash scripts/install-agent-fim.sh \
  --monitor /tmp \
  --monitor /var/www
```

If no `--monitor` option is specified, the script defaults to:

```text
/tmp
```

The installer:

- Validates the Wazuh agent installation
- Validates monitored directories
- Creates a timestamped configuration backup
- Configures File Integrity Monitoring
- Enables realtime monitoring
- Validates `ossec.conf`
- Installs `quarantine-threat.sh`
- Applies restrictive permissions
- Restarts the Wazuh agent
- Rolls back the configuration if restart fails

---

# Validation with EICAR

The harmless **EICAR anti-malware test file** can be used to validate the detection pipeline in a controlled lab.

Create a test directory:

```bash
sudo mkdir -p /tmp/malware
```

Download the EICAR test file:

```bash
sudo curl https://secure.eicar.org/eicar.com \
  -o /tmp/malware/eicar
```

Expected workflow:

```text
EICAR File Created
        ↓
Wazuh FIM Detects Change
        ↓
VirusTotal Enrichment
        ↓
Malicious-File Rule Fires
        ↓
Active Response
        ↓
File Quarantined
        ↓
Metadata + SHA-256 Preserved
```

---

## Verify FIM Activity

On the monitored endpoint:

```bash
sudo tail -n 100 /var/ossec/logs/ossec.log
```

---

## Verify Active Response

```bash
sudo tail -n 100 /var/ossec/logs/active-responses.log
```

A successful response should indicate that the target was moved into quarantine.

---

## Inspect Quarantine

```bash
sudo ls -lah /var/ossec/quarantine
```

The directory should contain both:

- The quarantined file
- A corresponding JSON metadata file

---

## Verify VirusTotal Integration

On the Wazuh manager:

```bash
sudo tail -n 100 /var/ossec/logs/integrations.log
```

Relevant Wazuh alerts can also be reviewed in:

```text
/var/ossec/logs/alerts/alerts.json
```

---

# Security Safeguards

This project includes several controls designed to reduce the risk of unsafe automated remediation.

### Quarantine Instead of Delete

Files are preserved rather than permanently removed.

### Path Allowlisting

The response only acts on files located under explicitly approved root directories.

### Symlink Protection

Symbolic links are rejected to reduce the risk of redirecting the response toward unintended files.

### Structured Alert Parsing

The script relies on structured Wazuh alert fields rather than scraping arbitrary paths from log text.

### Rule Validation

The response can verify that the expected malicious-file rule triggered the action.

### File Hashing

SHA-256 is calculated before quarantine for evidence tracking and future analysis.

### Metadata Preservation

File origin and response information are recorded before containment.

### Configuration Backups

Both installers create timestamped Wazuh configuration backups before making changes.

### XML Validation

Configuration files are checked before services are restarted.

### Automatic Rollback

If configuration validation or service restart fails, the previous configuration can be restored.

---

# Monitoring Guidance

Monitoring directories should be selected intentionally.

Large or frequently changing paths can generate excessive FIM events.

For example, monitoring all of:

```text
/home
```

with realtime change reporting may produce unnecessary telemetry in a busy environment.

A better approach is to monitor security-relevant locations based on the role of the endpoint.

Examples:

```text
/tmp
/var/tmp
/var/www
/opt/application/uploads
```

---

# Detection Engineering Considerations

A VirusTotal result alone should not automatically be interpreted as proof of compromise.

A mature workflow may consider:

- Number of malicious detections
- File reputation
- File prevalence
- Digital signature information
- File origin
- User context
- Process ancestry
- Endpoint role
- Related alerts
- Threat-intelligence confidence

Future versions of this project may introduce configurable response thresholds before quarantine occurs.

---

# Operational Limitations

This project is designed primarily for controlled security labs and defensive research.

Current limitations include:

- Automatic dependency installation is designed for Debian/Ubuntu systems
- VirusTotal API limits depend on the user's account
- Wazuh rule IDs may differ between versions and environments
- Production environments may require custom FIM exclusions
- Production response logic should be tested carefully before automated containment is enabled
- Quarantine restoration is currently a manual analyst process

---

# Future Enhancements

Planned improvements include:

- Dedicated quarantine restore utility
- Configurable VirusTotal detection thresholds
- Custom Wazuh rules
- Analyst approval mode
- Slack/email/SIEM notification after quarantine
- Additional evidence collection
- Process-context enrichment
- YARA scanning
- Automated case creation
- MITRE ATT&CK mapping
- Hash reputation caching
- RPM-based Linux support
- Formal detection-validation test cases

---

# SOC Workflow Demonstrated

This project demonstrates an end-to-end defensive workflow:

```text
Monitor
   ↓
Detect
   ↓
Enrich
   ↓
Validate
   ↓
Contain
   ↓
Preserve Evidence
   ↓
Investigate
   ↓
Remediate
```

A key design principle of the project is:

> **Automation should reduce response time without unnecessarily destroying evidence.**

---

## Disclaimer

This project was developed for authorized defensive security testing, SOC training, detection engineering, and professional development.

The EICAR file referenced in this repository is a harmless industry-standard anti-malware test file.

Before deploying Active Response in a production environment, validate all detection and containment logic in a controlled environment and ensure that monitoring paths, rule IDs, permissions, and response thresholds are appropriate for the organization.
