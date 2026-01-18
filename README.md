# Detectionlab

This project builds a SOC/SIEM lab based on Active Directory and Wazuh.
The repository contains the full lab structure and installation scripts.

![Lab architecture](https://github.com/R0b-1ns/DetectionLab/blob/main/docs/assets/lab-architecture.png)

## Prerequisites

- Designed on Proxmox 9.0.3, but works on any hypervisor.
- Lab size: 4 VMs (plus an optional pfSense router).
- Operating systems used:
  - Ubuntu 22.4 LTS (SIEM)
  - Windows Server 2025 (AD)
  - Windows 10 Pro (workstation)
  - Debian 13.1 (web server)

## Project architecture

```
config/
  config.json
  wazuh/
docs/
  installation/
  ad/
  workstations/
  siem/
  server/
  assets/
scripts/
  powershell/
  bash/
```

- `config/` holds lab-wide settings and Wazuh templates.
- `docs/` contains installation and role-specific documentation.
- `scripts/` contains PowerShell and Bash install/automation scripts.

## Documentation

- Installation: [docs/installation/README.md](https://github.com/R0b-1ns/DetectionLab/blob/main/docs/installation/README.md)
- Active Directory: [docs/ad/README.md](https://github.com/R0b-1ns/DetectionLab/blob/main/docs/ad/README.md)
- Workstations: [docs/workstations/README.md](https://github.com/R0b-1ns/DetectionLab/blob/main/docs/workstations/README.md)
- SIEM: [docs/siem/README.md](https://github.com/R0b-1ns/DetectionLab/blob/main/docs/siem/README.md)
- Server: [docs/server/README.md](https://github.com/R0b-1ns/DetectionLab/blob/main/docs/server/README.md)
