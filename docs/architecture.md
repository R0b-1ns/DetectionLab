# Lab architecture

## Objectives

- Provide a SOC environment for detection, investigation, and correlation.
- Cover realistic attack scenarios (AD, endpoints, web, network).
- Use Wazuh, Sysmon, Suricata, pfSense, application logs.
- Map detections to the MITRE ATT&CK framework.

## Scope and network

- Hypervisor: Proxmox.
- Internal network: 10.10.0.0/24.
- Segmentation: internal traffic only, NAT via pfSense.

## Components

- pfSense (10.10.0.1)
  - Role: firewall/NAT.
  - Logs: pfSense, Suricata, pfBlockerNG to Wazuh.
- SIEM Ubuntu 22.04 (10.10.0.10)
  - Wazuh manager/indexer/dashboard.
  - Correlation, dashboards, MITRE mapping.
- AD Windows Server 2019/2022 (10.10.0.11)
  - AD DS + DNS (optional DHCP).
  - Sysmon, Wazuh agent, advanced audit policy.
- Windows 10 workstation (10.10.0.12)
  - Sysmon, Wazuh agent, PowerShell logging.
- Linux web server (10.10.0.13)
  - Nginx/Apache (+ PHP).
  - HTTP/SSH/auditd logs, Wazuh agent.

## Log flows

- Windows (DC, workstation): Security, Sysmon, PowerShell, WMI, GPO.
- Linux (web): auth.log, nginx/apache access/error, auditd.
- pfSense: firewall, NAT, DHCP (if enabled).
- Suricata: network alerts (ET or custom rules).
- pfBlockerNG: reputation, geoip, blocks.

## Security assumptions

- Isolated lab, no direct Internet exposure (beyond NAT).
- Test AD accounts with elevated privileges for scenarios.
- Password policy defined by GPO.

## Improvement ideas

- Add a second Windows endpoint to simulate lateral movement.
- Enable DNS logging on the DC.
- Add Sysmon on the Linux web server (via Sysmon for Linux).
- Enable auditing of access to critical AD objects.
