<!-- BEGIN_TF_DOCS -->
# Fortigate Interface configuration module

This terraform module configures interfaces, zones & hardware
switches on a firewall

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.13.0 |
| <a name="requirement_fortios"></a> [fortios](#requirement\_fortios) | >= 1.22.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_fortios"></a> [fortios](#provider\_fortios) | >= 1.22.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_hardware_switch"></a> [hardware\_switch](#module\_hardware\_switch) | github.com/sncs-uk/terraform-fortigate-hardware-switch | n/a |

## Resources

| Name | Type |
|------|------|
| [fortios_system_interface.interfaces](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/system_interface) | resource |
| [fortios_system_zone.zones](https://registry.terraform.io/providers/fortinetdev/fortios/latest/docs/resources/system_zone) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_config_path"></a> [config\_path](#input\_config\_path) | Path to base configuration directory | `string` | n/a | yes |
| <a name="input_interface_key"></a> [interface\_key](#input\_interface\_key) | Key within the configuration path to use for the interface configuration | `string` | `"interfaces"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->