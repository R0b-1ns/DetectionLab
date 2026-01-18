#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root

ROLE="SIEM"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="$2"
      shift 2
      ;;
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

if [[ ! -f "$CONFIG_PATH" ]]; then
  log_error "Config file not found: $CONFIG_PATH"
  exit 1
fi

case "$ROLE" in
  SIEM|Server)
    ;;
  *)
    log_error "Unsupported role: $ROLE (use SIEM or Server)"
    exit 1
    ;;
esac

IP_ADDRESS="$(json_get "$CONFIG_PATH" "${ROLE}.Networking.IpAddress")"
PREFIX_LENGTH="$(json_get "$CONFIG_PATH" "${ROLE}.Networking.PrefixLength")"
GATEWAY="$(json_get "$CONFIG_PATH" "${ROLE}.Networking.Gateway")"
DNS_SERVER="$(json_get "$CONFIG_PATH" "${ROLE}.Networking.DnsServer")"
HOSTNAME_VALUE="$(json_get "$CONFIG_PATH" "${ROLE}.Networking.Hostname")"

log_info "Configuring hostname: $HOSTNAME_VALUE"
set_hostname "$HOSTNAME_VALUE"

log_info "Configuring network: ${IP_ADDRESS}/${PREFIX_LENGTH} via ${GATEWAY}"
configure_network "$IP_ADDRESS" "$PREFIX_LENGTH" "$GATEWAY" "$DNS_SERVER"

log_info "Network and hostname configuration completed."
