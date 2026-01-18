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

## Configuration

1) Edit `config/config.json`
   - Set IP addresses, gateway, DNS, and hostnames for each VM.
   - Keep the SIEM and Server blocks aligned with your lab network.

2) Update Wazuh templates in `config/wazuh/`
   - `workstation-ossec.conf` and `ad-ossec.conf` are applied by the Windows agent scripts.
   - `linux-server-ossec.conf` is applied by the Linux server agent script.
   - Replace placeholders (for example `WAZUH_MANAGER_IP`) where applicable.

3) Adjust `config/unattend.xml` (optional)
   - Used by Windows Sysprep to automate first boot.
   - Ensures the workstation bootstrap script runs after OOBE.

## Terraform (optional)

If you want Terraform to create the VMs on Proxmox, use the files in `terraform/`:

1) Copy and edit the variables file:

```
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

2) Update `terraform/terraform.tfvars` with your Proxmox API endpoint, token, node, and datastore.

3) Create the VMs:

```
terraform -chdir=terraform init
terraform -chdir=terraform apply
```

Notes:
- Windows Server (AD) needs the VirtIO driver ISO attached manually or disk/network models adjusted.
- EFI/TPM settings may need to be set in Proxmox after creation, depending on your provider version.

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

- For compatibility with newer Wazuh versions, the server installer script and agent package are stored locally.
- Wazuh server installer: `scripts/bash/assets/wazuh/wazuh-install.sh`
- Wazuh agent package: `scripts/bash/assets/wazuh/wazuh-agent_4.14.2-1_amd64.deb`
- Wazuh agent template (Linux server): `config/wazuh/linux-server-ossec.conf`

## Install tips

- `utils/create-repo-iso.sh` builds a repo ISO you can mount on each VM
  to avoid cloning from Git.
- Make sure your router or gateway is configured with the expected static IP
  before running the scripts. The scripts change network settings and then
  download packages, so a wrong gateway can leave the VM without internet.

## Additional documentation

- SIEM: `docs/siem/README.md`
- Server: `docs/server/README.md`
- Wazuh official docs: https://documentation.wazuh.com/current/
