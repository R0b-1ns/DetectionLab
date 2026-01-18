# AD Documentation

This section documents how the DC install and AD configuration scripts work.

## Scripts

- `scripts/powershell/ad/install-dc.ps1`
  - Configures IP/DNS and hostname on the future DC.
  - Installs AD DS + DNS and promotes the server to a new forest.
  - Reboots as needed.

- `scripts/powershell/ad/AD-config.ps1`
  - Creates OUs and GPOs and applies baseline policies.
  - Installs and starts the Wazuh agent after policies are in place.

## Organizational Units

Created in the domain root:
- OU "Workstations"
- OU "AdUsers"

## Group Policy Objects

Created and linked to the corresponding OUs:
- GPO "GPO-Users" linked to "AdUsers"
- GPO "GPO-Workstations" linked to "Workstations"

## GPO-Users defaults

User hardening policies applied via registry:
- Screen saver enabled, timeout 600s, password required
- Control Panel disabled
- Registry tools disabled
- CMD disabled
- File extensions shown
- Wallpaper and style configured

## GPO-Workstations defaults

Workstation hardening policies applied via registry:
- Process creation audit includes command line
- PowerShell Script Block and Module logging enabled
- PowerShell execution policy set to RemoteSigned
- WDigest UseLogonCredential disabled
- Legacy audit policy disabled (SCENoApplyLegacyAuditPolicy)
- Windows Firewall enabled for Domain profile
- Firewall dropped packets logging enabled
- Windows Defender enabled (no disable flags)
