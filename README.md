# wazuh-vt-active-response

Add this to your README.md (copy/paste)
One-command install
Manager
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/garciarubenjr/wazuh-vt-active-response/main/install_manager_vt_ar.sh)" -- \
  --vt-key "YOUR_VIRUSTOTAL_API_KEY"

Agent
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/garciarubenjr/wazuh-vt-active-response/main/install_agent_fim_ar.sh)" -- \
  --monitor "/tmp" --monitor "/home"


The VirusTotal API key is configured on the manager only and is not stored in this repo.

Quick check: are your agent scripts already “self-contained”?

Open your install_agent_fim_ar.sh and confirm it downloads/copies remove-threat.sh into:

/var/ossec/active-response/bin/remove-threat.sh


If it doesn’t, add the curl snippet I gave above and commit it — that’s the #1 thing that makes onboarding new servers painless.

If you paste your current install_agent_fim_ar.sh contents here, I’ll point out the exact spot to add the download block (and any tiny fixes so it’s idempotent).
