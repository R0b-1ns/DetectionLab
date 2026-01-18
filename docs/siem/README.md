# SIEM Documentation

This section describes the SIEM installation scripts and their roles.

## Scripts

- `scripts/bash/installation-SIEM.bash`
  - Applies hostname and static networking using `config/config.json`.
  - Calls the Wazuh server installer script.

- `scripts/bash/siem/wazuh_server_ubuntu.bash`
  - Installs Wazuh All-in-One (manager/indexer/dashboard).
  - Uses the offline installer script stored in the repo.

- `scripts/bash/common/linux-network-bootstrap.bash`
  - Shared network and hostname setup for Debian/Ubuntu.
  - Reads all values from `config/config.json`.

## Versions

- Wazuh server (All-in-One): 4.14.x
- Installer script: `scripts/bash/assets/wazuh/wazuh-install.sh`
