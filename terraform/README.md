# Terraform (Proxmox)

This folder creates the lab VMs on Proxmox with the same base sizing as the current manual setup.
It only creates the VMs and attaches the OS ISOs (no provisioning).

## Prerequisites

- Terraform 1.5+
- A Proxmox API token with VM creation rights
- ISOs uploaded to the ISO datastore (see `terraform/vms.tf` for filenames)

## Quick start

1) Copy the example vars file:

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

2) Edit `terraform/terraform.tfvars`:
   - Set `proxmox_endpoint`, `proxmox_api_token`, `proxmox_node`.
   - Adjust datastore and bridge names if they differ.

3) Create the VMs:

```bash
terraform -chdir=terraform init
terraform -chdir=terraform apply
```

## Notes

- Windows Server (AD) usually needs the VirtIO driver ISO. Add it manually as a second CD/DVD
  after the VM is created, or change the disk/network model in `terraform/vms.tf`.
- UEFI + TPM settings depend on your Proxmox version/provider support. If you want strict parity
  with the screenshots (EFI disk + TPM state), add those blocks manually after the first apply.
