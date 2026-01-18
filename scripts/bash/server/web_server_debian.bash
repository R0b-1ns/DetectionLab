#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common/lib/common.sh
source "$SCRIPT_DIR/../common/lib/common.sh"

require_root

CONFIG_PATH=""
START_AGENT="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --start-agent)
      START_AGENT="true"
      shift 1
      ;;
    *)
      log_error "Unknown argument: $1"
      exit 1
      ;;
  esac
done

REPO_ROOT="$(get_repo_root)"
CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/config/config.json}"

log_info "Installing web server packages..."
apt-get update
apt-get install -y nginx
systemctl enable nginx
systemctl start nginx

log_info "Installing Wazuh agent..."
START_AGENT="$START_AGENT" \
"$SCRIPT_DIR/wazuh_agent_debian.bash" --role Server --config "$CONFIG_PATH"

log_info "Web server installation completed."
