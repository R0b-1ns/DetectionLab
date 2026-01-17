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
      workstations-bootstrap.ps1
  bash/
docs/
```

## Quick usage (AD/DC)

1) Edit `config/config.json` to match your domain and network.
2) Update the path `GPO.Workstations.BootstrapScript` so it matches the local
   location of `workstations-bootstrap.ps1` on the DC.
3) Run `scripts/powershell/ad/AD-config.ps1` as administrator.

## Notes

- The AD script prompts for the DSRM password (no env var).
- The script then copies the bootstrap to SYSVOL and attaches it to the GPO.

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
