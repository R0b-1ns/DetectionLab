# Detectionlab

SOC/SIEM detection lab based on Active Directory, Wazuh, and multi-source logs.

## Layout

```
config/
  config.json
scripts/
  powershell/
    ad/
      AD-config.ps1
    workstations/
      w10-workstation-bootstrap.ps1
      workstations-bootstrap.ps1
  bash/
    installation-SIEM.bash
    installation-Server.bash
    common/
    siem/
    server/
docs/
```

## Documentation

- Architecture: `docs/architecture.md`
- Attack and detection notes: `docs/attaque-detection.md`
- Installation: `docs/installation/README.md`
- Active Directory: `docs/ad/README.md`
- Workstations: `docs/workstations/README.md`
- SIEM: `docs/siem/README.md`
- Server: `docs/server/README.md`

## Quick usage (AD/DC)

1) Edit `config/config.json` to match your domain and network.
2) Run `scripts/powershell/ad/install-dc.ps1` as administrator.
3) After reboot and domain creation, run `scripts/powershell/ad/AD-config.ps1`.

## Quick usage (Windows 10 workstation)

1) Run `scripts/powershell/workstations/w10-workstation-bootstrap.ps1` as administrator.
2) The script applies networking, joins the domain, installs Sysmon, and then runs
   `scripts/powershell/workstations/workstations-bootstrap.ps1` locally.

## Notes

- The AD script prompts for the DSRM password (no env var).
- The workstation script handles the local bootstrap and reboots at the end if required.

## Scenario examples (MITRE ATT&CK)

- Brute force and account lockout (T1110)
- Kerberoasting (T1558.003)
- Pass-the-Hash (T1550.002)
- PowerShell abuse and script block logging (T1059.001)
- Lateral movement via SMB/WMI (T1021)

## Detection and visibility

- Wazuh + Sysmon + AD audit policy for critical events
- Centralize logs from pfSense/Suricata and Windows (DC, workstations, servers)
- Enrich rules with MITRE mapping and multi-source correlations
