/**
 * # Fortigate Interface configuration module
 *
 * This terraform module configures interfaces, zones & hardware
 * switches on a firewall
 */
terraform {
  required_providers {
    fortios = {
      source  = "fortinetdev/fortios"
    }
  }
}

locals {
  interface_yaml = yamldecode(file("${var.config_path}/config/interfaces.yaml"))
}

resource fortios_system_interface interfaces {
  for_each          = { for name, interface in try(local.interface_yaml.interfaces, []) : name => interface}
  depends_on        = [
                        fortios_system_vdom.vdom,
                        fortios_system_interface.link_rt,
                        fortios_system_interface.link_vdom,
                        module.hardware_switch
                      ]
  lifecycle {
    ignore_changes = [ cli_conn_status, ipv6[0].cli_conn6_status ]
  }

  name              = each.key
  vdom              = each.value.vdom
  type              = each.value.type
  mode              = try(each.value.mode, null)
  vlanid            = try(each.value.vlanid, null)
  mtu               = try(each.value.mtu, null)
  interface         = try(each.value.interface, null)
  description       = try(each.value.description, null)
  alias             = try(each.value.alias, null)
  ip                = try(each.value.ip, null)
  role              = try(each.value.role, null)
  allowaccess       = join(" ", try(each.value.allowaccess, try(each.value.role, null) == "wan" ? [] : ["ping"]))

  ipv6 {
    ip6_mode                  = try(each.value.ip6_mode, null)
    dhcp6_prefix_delegation   = try(each.value.dhcp6_prefix_delegation, false) ? "enable" : "disable"
    ip6_delegated_prefix_iaid = try(each.value.ip6_delegated_prefix_iaid, null)
    ip6_upstream_interface    = try(each.value.ip6_upstream_interface, null)
    ip6_send_adv              = try(each.value.ip6_send_adv, null)
    ip6_address               = try(each.value.ip6_address, null)
    ip6_subnet                = try(each.value.ip6_subnet, null)
    ip6_allowaccess           = join(" ", try(each.value.allowaccess, []))
    dhcp6_client_options      = try(each.value.dhcp6_prefix_delegation, false) ? "iapd" : null
    dynamic dhcp6_iapd_list {
      for_each = try(each.value.dhcp6_prefix_delegation, false) ? [{iaid = 1, prefix_hint = "::/56"}] : []
      content {
        iaid                = 1
        prefix_hint         = "::/56"
      }
    }

    dynamic ip6_delegated_prefix_list {
      for_each = { for prefix in try(each.value.ip6_delegated_prefix_list, []) : prefix.id => prefix }
      content {
        upstream_interface    = ip6_delegated_prefix_list.value.upstream_interface
        delegated_prefix_iaid = ip6_delegated_prefix_list.value.delegated_prefix_iaid
        subnet                = ip6_delegated_prefix_list.value.subnet
        rdnss                 = ip6_delegated_prefix_list.value.rdnss
      }
    }
  }

  dynamic member {
    for_each = { for member in try(each.value.members, []) : member => member}
    content {
      interface_name = member.value
    }
  }
}

resource fortios_system_zone zones {
  for_each          = { for name, zone in try(local.interface_yaml.zones, []) : name => zone }
  depends_on        = [ fortios_system_interface.interfaces, module.hardware_switch ]
  name              = each.key
  intrazone         = try(each.value.intrazone, null)
  vdomparam         = each.value.vdom
  dynamic interface {
    for_each = { for interface in each.value.interfaces : interface => interface }
    content {
      interface_name = interface.value
    }
  }
}

module "hardware_switch" {
  for_each      = { for name, switch in try(local.interface_yaml.switches, []) : name => switch}
  source        = "github.com/sncs-uk/terraform-fortigate-hardware-switch"
  name          = each.key
  ports         = try(each.value.ports, null)
  vdom          = try(each.value.vdom, null)
  role          = try(each.value.role, null)
  ipv4          = try(each.value.ipv4, null)
  ipv6          = try(each.value.ipv6, null)
  allowaccess   = join(" ", try(each.value.allowaccess, []))
  allowaccess6  = join(" ", try(each.value.allowaccess, []))
}
