#!/bin/bash
set -euo pipefail

log_info() {
  echo "[INFO] $*"
}

log_error() {
  echo "[ERROR] $*" >&2
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
  fi
}

get_repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  echo "$(cd "$script_dir/../../../../" && pwd)"
}

json_get() {
  local config_path="$1"
  local dotted_path="$2"
  python3 - "$config_path" "$dotted_path" <<'PY'
import json
import sys

config_path = sys.argv[1]
dotted_path = sys.argv[2]

with open(config_path, "r", encoding="utf-8") as f:
    data = json.load(f)

for key in dotted_path.split("."):
    if key not in data:
        sys.exit(f"Missing key '{dotted_path}' in {config_path}")
    data = data[key]

print(data)
PY
}

prefix_to_netmask() {
  local prefix="$1"
  python3 - "$prefix" <<'PY'
import sys

prefix = int(sys.argv[1])
mask = (0xffffffff << (32 - prefix)) & 0xffffffff
print("{}.{}.{}.{}".format(
    (mask >> 24) & 0xff,
    (mask >> 16) & 0xff,
    (mask >> 8) & 0xff,
    mask & 0xff,
))
PY
}

get_default_iface() {
  ip -o -4 route show default | awk '{print $5}' | head -n 1
}

set_hostname() {
  local hostname_value="$1"

  hostnamectl set-hostname "$hostname_value"

  if grep -q "^127.0.1.1" /etc/hosts; then
    sed -i "s/^127.0.1.1.*/127.0.1.1 ${hostname_value}/" /etc/hosts
  else
    echo "127.0.1.1 ${hostname_value}" >> /etc/hosts
  fi
}

write_netplan_config() {
  local iface="$1"
  local ip="$2"
  local prefix="$3"
  local gateway="$4"
  local dns="$5"

  cat > /etc/netplan/01-detectionlab.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${iface}:
      dhcp4: no
      addresses: [${ip}/${prefix}]
      gateway4: ${gateway}
      nameservers:
        addresses: [${dns}]
EOF

  netplan apply
}

write_interfaces_config() {
  local iface="$1"
  local ip="$2"
  local prefix="$3"
  local gateway="$4"
  local dns="$5"
  local netmask

  netmask="$(prefix_to_netmask "$prefix")"

  cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto ${iface}
iface ${iface} inet static
  address ${ip}
  netmask ${netmask}
  gateway ${gateway}
  dns-nameservers ${dns}
EOF

  systemctl restart networking
}

configure_network() {
  local ip="$1"
  local prefix="$2"
  local gateway="$3"
  local dns="$4"

  local iface
  iface="$(get_default_iface)"

  if [[ -z "$iface" ]]; then
    log_error "Could not detect the default network interface."
    exit 1
  fi

  local os_id
  os_id="$(. /etc/os-release && echo "$ID")"

  case "$os_id" in
    ubuntu)
      write_netplan_config "$iface" "$ip" "$prefix" "$gateway" "$dns"
      ;;
    debian)
      write_interfaces_config "$iface" "$ip" "$prefix" "$gateway" "$dns"
      ;;
    *)
      log_error "Unsupported distribution ID: $os_id"
      exit 1
      ;;
  esac
}
