# Attack scenarios and detection

## Overview

This document proposes realistic scenarios and their associated detections.
MITRE ATT&CK mapping is listed for each scenario.

## Scenario 1 - AD brute force

- Tactic: Credential Access
- Techniques: T1110 (Brute Force)

Attack:
- Repeated login attempts on the DC or workstation.

Expected events:
- Security 4625 (failures), 4740 (lockout).
- Wazuh alerts on abnormal thresholds.

Detection:
- Wazuh rule: alert if > 10 failures / 5 min / same account or IP.
- Correlate with pfSense for external IP via NAT.

## Scenario 2 - Kerberoasting

- Tactic: Credential Access
- Techniques: T1558.003 (Kerberoasting)

Attack:
- Kerberos ticket requests for service accounts.

Expected events:
- Security 4769 (TGS requests) with RC4.
- Abnormal activity on a service account.

Detection:
- Sigma: abnormal volume of 4769 + RC4 encryption.
- Correlation: same host + high volume in a short time window.

## Scenario 3 - Pass-the-Hash

- Tactic: Lateral Movement
- Techniques: T1550.002 (Pass the Hash)

Attack:
- Use of NTLM hashes to authenticate over SMB/WMI.

Expected events:
- Security 4624 Type 3, LogonProcess=NtLmSsp.
- Sysmon 3 (network) to SMB.

Detection:
- Wazuh: alert on remote NTLM logons + privileged accounts.
- Sigma: correlation 4624 + 4672 (privileged logon).

## Scenario 4 - PowerShell abuse

- Tactic: Execution
- Techniques: T1059.001 (PowerShell)

Attack:
- Encoded scripts, download cradle.

Expected events:
- PowerShell Script Block Logging.
- Sysmon 1 (process), 7 (image loaded).

Detection:
- Wazuh: detect suspicious commands (IEX, DownloadString).
- Sigma: base64 encoding, execution policy bypass.

## Scenario 5 - SMB/WMI lateral movement

- Tactic: Lateral Movement
- Techniques: T1021 (Remote Services)

Attack:
- PsExec, WMIExec, SMB admin shares.

Expected events:
- Security 4688 (process creation) on target.
- Sysmon 1 + 3, Event 7045 (service install).

Detection:
- Wazuh: remote service creation.
- Sigma: psexec service name patterns.

## Scenario 6 - Web server exploitation

- Tactic: Initial Access
- Techniques: T1190 (Exploit Public-Facing Application)

Attack:
- Webshell, file upload, RCE.

Expected events:
- HTTP logs with suspicious payloads.
- auth.log SSH attempts post-exploitation.

Detection:
- Wazuh: regex on webshell, abnormal uploads.
- Suricata: ET WEB_SERVER alerts.

## Coverage and visibility

- Enable DNS logging on the DC for C2 and exfil.
- Enable advanced auditing (object access, directory service).
- Add custom Wazuh rules for Sysmon.
- Establish baseline counters for logons.

## Example rules (pseudo)

Wazuh (bruteforce example):
- If event_id=4625 and count > 10 in 5 minutes

Sigma (kerberoasting example):
- EventID=4769 AND TicketEncryption=0x17
