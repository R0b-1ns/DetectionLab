#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common/lib/common.sh
source "$SCRIPT_DIR/common/lib/common.sh"

require_root

CONFIG_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    *)
      log_error "Unknown argument: $1"
      exit 1
      ;;
  esac
done

REPO_ROOT="$(get_repo_root)"
CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/config/config.json}"

log_info "Bootstrapping SIEM network and hostname from config..."
"$SCRIPT_DIR/common/linux-network-bootstrap.bash" --role SIEM --config "$CONFIG_PATH"

log_info "Launching Wazuh server installer..."
"$SCRIPT_DIR/siem/wazuh_server_ubuntu.bash"
