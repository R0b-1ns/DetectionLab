#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

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

log_info "Bootstrapping web server network and hostname from config..."
"$SCRIPT_DIR/linux-network-bootstrap.bash" --role Server --config "$CONFIG_PATH"

log_info "Launching web server installer..."
"$SCRIPT_DIR/web_server_debian.bash" --config "$CONFIG_PATH" $([[ "$START_AGENT" == "true" ]] && echo "--start-agent")
