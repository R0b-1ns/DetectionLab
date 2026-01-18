variable "proxmox_endpoint" {
  type        = string
  description = "Proxmox API endpoint, e.g. https://pve:8006"
  default     = "https://pve.example:8006"
}

variable "proxmox_api_token" {
  type        = string
  description = "Proxmox API token in the form user@realm!token=secret"
  default     = "root@pam!terraform=CHANGEME"
  sensitive   = true
}

variable "proxmox_insecure" {
  type        = bool
  description = "Skip TLS verification for the Proxmox API"
  default     = true
}

variable "proxmox_node" {
  type        = string
  description = "Target Proxmox node name"
  default     = "pve"
}

variable "iso_datastore" {
  type        = string
  description = "Proxmox datastore that holds ISO files"
  default     = "local"
}

variable "disk_datastore" {
  type        = string
  description = "Proxmox datastore for VM disks"
  default     = "SSD-2to"
}

variable "lan_bridge" {
  type        = string
  description = "LAN bridge name"
  default     = "vmbr0"
}

variable "wan_bridge" {
  type        = string
  description = "WAN bridge name (pfSense only)"
  default     = "vmbr1"
}
