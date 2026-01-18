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
   - Install Wazuh manager/indexer/dashboard.

2) Active Directory (Windows Server)
   - Boot the VM.
   - Run `scripts/powershell/ad/install-dc.ps1`.
   - After reboot and domain creation, run `scripts/powershell/ad/AD-config.ps1`.

3) Windows workstations
   - For a fresh install, run `scripts/powershell/workstations/install-w10.ps1`.
   - For Sysprep, use the preconfigured `config/unattend.xml`.
