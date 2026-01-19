# wazuh-vt-active-response

🛡️ wazuh-vt-active-response

Automated Wazuh File Integrity Monitoring (FIM) with VirusTotal validation and Active Response (auto-delete).

This project allows you to onboard new Linux servers with one command and automatically:

Detect file changes with Wazuh FIM

Validate suspicious files using VirusTotal

Automatically remove confirmed malicious files

Log every action for audit and incident review

📐 Architecture Overview

[ Wazuh Agent ]

  └─ File Integrity Monitoring (syscheck)
  
        ↓
        
[ Wazuh Manager ]

  ├─ VirusTotal API integration
  
  ├─ Rule 87105 (malicious verdict)
  
  └─ Active Response trigger
  
        ↓
        
[ Wazuh Agent ]

  └─ remove-threat.sh deletes the malicious file

📦 Repository Contents


├── README.md

├── install_manager_vt_ar.sh    # Manager setup (VirusTotal + Active Response)

├── install_agent_fim_ar.sh     # Agent setup (FIM + AR install)

└── remove-threat.sh            # Active Response script (auto-delete)

⚠️ Important Security Notes

VirusTotal API key is configured on the manager only

The API key is never stored in this repository

Agents do not communicate with VirusTotal

Active Response deletes files — use carefully in production

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

2️⃣ Wazuh Agent (run on each server)

Run this on every Wazuh agent you want protected:

sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/garciarubenjr/wazuh-vt-active-response/main/install_agent_fim_ar.sh)" -- \
  --monitor "/tmp" \
  --monitor "/home"


What this does:

-Enables File Integrity Monitoring (FIM)

-Adds realtime monitored directories

-Installs the Active Response delete script

-Restarts the Wazuh agent

If no --monitor flags are provided, the script defaults to /tmp and /home.

🧪 Test the Setup (EICAR)

On the agent, run:

-sudo mkdir -p /tmp/malware
-sudo curl https://secure.eicar.org/eicar.com -o /tmp/malware/eicar

Expected behavior

-File is detected by FIM

-VirusTotal flags it as malicious

-Active Response deletes the file automatically

Verify deletion:

-sudo tail -n 50 /var/ossec/logs/active-responses.log


You should see:

SUCCESS: deleted /tmp/malware/eicar

🔍 Verification & Troubleshooting
Agent logs
-sudo tail -n 100 /var/ossec/logs/ossec.log
-sudo tail -n 100 /var/ossec/logs/active-responses.log

Manager logs
-sudo tail -n 100 /var/ossec/logs/integrations.log
-sudo tail -n 200 /var/ossec/logs/alerts/alerts.json | grep 87105

🧠 How This Scales

This setup is designed for reuse:

-New VM → run one command

-Ideal for:

---Honeypots

---DMZ web servers

---SOC labs

---Malware collection environments

No additional manager configuration is needed once VirusTotal is enabled
