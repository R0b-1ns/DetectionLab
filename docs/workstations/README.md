# Workstations Documentation

This section explains the workstation scripts and their roles.

## Script roles

- `scripts/powershell/workstations/install-w10.ps1`
  - First-run installer for a fresh workstation.
  - Installs Sysmon, applies the baseline, installs Wazuh agent, then calls the bootstrap script.
  - Copies the bootstrap script and `config.json` to `C:\Scripts` for Sysprep reuse.

- `scripts/powershell/workstations/w10-workstation-bootstrap.ps1`
  - Configures networking, renames the host, and joins the AD domain.
  - Accepts `-IpAddress` or prompts for a valid IPv4 address.
  - Uses `C:\Scripts\config.json` if present, otherwise falls back to the repo config.
  - Generates a unique hostname in the form `PC-<UUID8>`.

- `scripts/powershell/workstations/workstations-bootstrap.ps1`
  - Applies baseline Windows audit policy and PowerShell logging.
  - Writes a registry marker to prevent reapplying the baseline.

- `scripts/powershell/workstations/sysmon-install.ps1`
  - Offline Sysmon install with SwiftOnSecurity config.
  - Uses local assets in `scripts/powershell/workstations/assets`.

- `scripts/powershell/wazuh-agents/install-wazuh-agent.ps1`
  - Offline Wazuh agent install using local MSI.
  - Applies the correct `ossec.conf` template and replaces the manager IP from `config.json`.

## Sysprep with unattended.xml

Place `config/unattend.xml` on the VM (or in your image), then run:

```
%WINDIR%\System32\Sysprep\Sysprep.exe /generalize /oobe /shutdown /unattend:C:\Path\To\unattend.xml
```

On next boot, Windows skips OOBE, creates the `admin` account, and runs
`C:\Scripts\w10-workstation-bootstrap.ps1` automatically.
