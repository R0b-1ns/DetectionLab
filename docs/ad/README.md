# AD Documentation

This section documents what the AD bootstrap script creates by default.

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
