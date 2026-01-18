locals {
  vms = {
    siem = {
      name           = "SIEM"
      vm_id          = 113
      memory_mb      = 8192
      cores          = 4
      sockets        = 1
      cpu_type       = "x86-64-v2-AES"
      bios           = "seabios"
      machine        = null
      disk_gb        = 60
      disk_interface = "scsi0"
      iothread       = true
      iso            = "ubuntu-22.04.5-desktop-amd64.iso"
      networks = [
        { bridge = var.lan_bridge, model = "virtio" }
      ]
    }

    ad = {
      name           = "AD"
      vm_id          = 114
      memory_mb      = 8192
      cores          = 2
      sockets        = 1
      cpu_type       = "x86-64-v2-AES"
      bios           = "ovmf"
      machine        = "pc-q35-10.0"
      disk_gb        = 60
      disk_interface = "scsi0"
      iothread       = true
      iso            = "26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_fr_fr.iso"
      networks = [
        { bridge = var.lan_bridge, model = "virtio" }
      ]
    }

    workstation1 = {
      name           = "WorkStation1"
      vm_id          = 117
      memory_mb      = 4096
      cores          = 2
      sockets        = 1
      cpu_type       = "x86-64-v2-AES"
      bios           = "ovmf"
      machine        = "pc-q35-10.0"
      disk_gb        = 60
      disk_interface = "ide0"
      iothread       = true
      iso            = "Win10_22H2_EnglishInternational_x64v1.iso"
      networks = [
        { bridge = var.lan_bridge, model = "e1000" }
      ]
    }

    serverweb = {
      name           = "ServeurWeb"
      vm_id          = 115
      memory_mb      = 2048
      cores          = 1
      sockets        = 1
      cpu_type       = "x86-64-v2-AES"
      bios           = "seabios"
      machine        = null
      disk_gb        = 32
      disk_interface = "scsi0"
      iothread       = true
      iso            = "debian-13.1.0-amd64-netinst.iso"
      networks = [
        { bridge = var.lan_bridge, model = "virtio" }
      ]
    }

    routeur = {
      name           = "Routeur"
      vm_id          = 116
      memory_mb      = 2048
      cores          = 1
      sockets        = 1
      cpu_type       = "x86-64-v2-AES"
      bios           = "seabios"
      machine        = null
      disk_gb        = 20
      disk_interface = "scsi0"
      iothread       = true
      iso            = "netgate-installer-amd64.iso"
      networks = [
        { bridge = var.lan_bridge, model = "virtio" },
        { bridge = var.wan_bridge, model = "virtio" }
      ]
    }
  }
}

resource "proxmox_virtual_environment_vm" "vms" {
  for_each  = local.vms
  name      = each.value.name
  node_name = var.proxmox_node
  vm_id     = each.value.vm_id

  bios    = each.value.bios
  machine = each.value.machine

  cpu {
    cores   = each.value.cores
    sockets = each.value.sockets
    type    = each.value.cpu_type
  }

  memory {
    dedicated = each.value.memory_mb
  }

  disk {
    datastore_id = var.disk_datastore
    interface    = each.value.disk_interface
    size         = each.value.disk_gb
    iothread     = each.value.iothread
  }

  cdrom {
    enabled = true
    file_id = "${var.iso_datastore}:iso/${each.value.iso}"
  }

  dynamic "network_device" {
    for_each = each.value.networks
    content {
      bridge   = network_device.value.bridge
      model    = network_device.value.model
      firewall = true
    }
  }
}
