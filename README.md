# wazuh-vt-active-response

🔑 Getting a VirusTotal API Key

Before installing the manager integration, you need a VirusTotal API key.

Steps

Go to https://www.virustotal.com

Create an account or log in

Click your profile icon (top right)

Select API key

Copy your API key

A free VirusTotal account is sufficient for lab and testing purposes.

Using the API Key

The API key is provided at install time when running the manager script:

sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/garciarubenjr/wazuh-vt-active-response/main/install_manager_vt_ar.sh)" -- \
  --vt-key "YOUR_VIRUSTOTAL_API_KEY"

Important Notes

The API key is configured on the Wazuh manager only

The key is written to /var/ossec/etc/ossec.conf

The key is not stored in this repository

Agents do not have access to the VirusTotal API

This follows best practices for centralized threat-intelligence integrations.

🔐 API Key Security Recommendation

Do not hardcode your API key into scripts or commit it to GitHub.

If needed, you can also pass it temporarily via shell history-safe methods (e.g., copy/paste at runtime).
