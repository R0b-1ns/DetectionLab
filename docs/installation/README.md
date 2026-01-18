# Installation Guide

This lab expects 4 VMs on the internal network.

## Tested OS versions

- Windows 10 Pro 2009 (Build 19045)
- Windows Server 2025 2009 (Build 26100)
- Debian 13.3 (Linux server)
- Ubuntu 22.04.5 LTS (SIEM)

## Prerequisites

- Configuration lives in `config/config.json`.
- Wazuh agent templates live in `config/wazuh/*.conf`.
- Windows Sysprep uses `config/unattend.xml`.

## Installation order

1) SIEM server (Ubuntu 22.04)
   - Deploy and configure first.
   - Run `scripts/bash/installation-SIEM.bash`.

2) Active Directory (Windows Server)
   - Boot the VM.
   - Run `scripts/powershell/ad/install-dc.ps1`.
   - After reboot and domain creation, run `scripts/powershell/ad/AD-config.ps1`.

3) Windows workstations
   - For a fresh install, run `scripts/powershell/workstations/install-w10.ps1`.
   - For Sysprep, use the preconfigured `config/unattend.xml`.

4) Linux web server (Debian 13)
   - Run `scripts/bash/installation-Server.bash`.
   - Add `--start-agent` if you want the Wazuh agent enabled immediately.

## Offline assets

- Wazuh server installer: `scripts/bash/assets/wazuh/wazuh-install.sh`
- Wazuh agent package: `scripts/bash/assets/wazuh/wazuh-agent_4.14.2-1_amd64.deb`
- Wazuh agent template (Linux server): `config/wazuh/linux-server-ossec.conf`

## Additional documentation

- SIEM: `docs/siem/README.md`
- Server: `docs/server/README.md`
