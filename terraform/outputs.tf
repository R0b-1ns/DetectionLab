output "vm_ids" {
  value = { for key, vm in proxmox_virtual_environment_vm.vms : key => vm.vm_id }
}

output "vm_names" {
  value = { for key, vm in proxmox_virtual_environment_vm.vms : key => vm.name }
}
