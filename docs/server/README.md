# Server Documentation

This section documents the Debian-based web server install and agent setup.

## Scripts

- `scripts/bash/installation-Server.bash`
  - Applies hostname and static networking using `config/config.json`.
  - Calls the web server installer script.

- `scripts/bash/server/web_server_debian.bash`
  - Installs the web server packages (nginx by default).
  - Installs the Wazuh agent from the local package.
  - Accepts `--start-agent` to enable and start the agent.

- `scripts/bash/server/wazuh_agent_debian.bash`
  - Installs the Wazuh agent from a local `.deb` package.
  - Uses `config/config.json` to set manager IP and agent name.
  - Applies the Linux agent template to collect web/auth/audit logs.

- `scripts/bash/server/security_tools_debian.bash`
  - Orchestrates the YARA and auditd installers.
  - Deploys auditd rules from `config/auditd/` to `/etc/audit/rules.d/` and reloads them.
  - Enables and starts auditd.

- `scripts/bash/server/yara_debian.bash`
  - Installs YARA if not already present.
  - Deploys YARA rules from `config/yara/` to `/etc/yara/rules/`.
  - Configures a daily systemd timer to scan `/var/www` and log to `/var/log/yara/yara.log`.

## Rules locations

- YARA rules (repo): `config/yara/`
- auditd rules (repo): `config/auditd/`
- YARA rules (system): `/etc/yara/rules/`
- YARA log (system): `/var/log/yara/yara.log`
- auditd rules (system): `/etc/audit/rules.d/`

## Versions

- Wazuh agent package: 4.14.2-1
- Package path: `scripts/bash/assets/wazuh/wazuh-agent_4.14.2-1_amd64.deb`
- Template path: `config/wazuh/linux-server-ossec.conf`
