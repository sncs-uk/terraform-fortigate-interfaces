/**
 * # Fortigate Interface configuration module
 *
 * This terraform module configures interfaces, zones & hardware
 * switches on a firewall
 */
terraform {
  required_version = ">= 1.11.0"
  required_providers {
    fortios = {
      source  = "fortinetdev/fortios"
      version = ">= 1.22.0"
    }
  }
}

resource "fortios_system_interface" "interfaces" {
  for_each = { for interface in var.interfaces : interface.name => interface }
  lifecycle {
    ignore_changes = [cli_conn_status, ipv6[0].cli_conn6_status]
  }

  name                                       = each.value.name
  vdom                                       = each.value.vdom
  vrf                                        = each.value.vrf
  cli_conn_status                            = each.value.cli_conn_status
  fortilink                                  = each.value.fortilink
  switch_controller_source_ip                = each.value.switch_controller_source_ip
  mode                                       = each.value.mode
  distance                                   = each.value.distance
  priority                                   = each.value.priority
  dhcp_relay_interface_select_method         = each.value.dhcp_relay_interface_select_method
  dhcp_relay_interface                       = each.value.dhcp_relay_interface
  dhcp_relay_vrf_select                      = each.value.dhcp_relay_vrf_select
  dhcp_broadcast_flag                        = each.value.dhcp_broadcast_flag
  dhcp_relay_service                         = each.value.dhcp_relay_service
  dhcp_relay_ip                              = each.value.dhcp_relay_ip
  dhcp_relay_source_ip                       = each.value.dhcp_relay_source_ip
  dhcp_relay_circuit_id                      = each.value.dhcp_relay_circuit_id
  dhcp_relay_link_selection                  = each.value.dhcp_relay_link_selection
  dhcp_relay_request_all_server              = each.value.dhcp_relay_request_all_server
  dhcp_relay_allow_no_end_option             = each.value.dhcp_relay_allow_no_end_option
  dhcp_relay_type                            = each.value.dhcp_relay_type
  dhcp_smart_relay                           = each.value.dhcp_smart_relay
  dhcp_relay_agent_option                    = each.value.dhcp_relay_agent_option
  dhcp_classless_route_addition              = each.value.dhcp_classless_route_addition
  management_ip                              = each.value.management_ip
  ip                                         = each.value.ip
  allowaccess                                = each.value.allowaccess
  gwdetect                                   = each.value.gwdetect
  ping_serv_status                           = each.value.ping_serv_status
  detectserver                               = each.value.detectserver
  detectprotocol                             = each.value.detectprotocol
  ha_priority                                = each.value.ha_priority
  fail_detect                                = each.value.fail_detect
  fail_detect_option                         = each.value.fail_detect_option
  fail_alert_method                          = each.value.fail_alert_method
  fail_action_on_extender                    = each.value.fail_action_on_extender
  dhcp_client_identifier                     = each.value.dhcp_client_identifier
  dhcp_renew_time                            = each.value.dhcp_renew_time
  ipunnumbered                               = each.value.ipunnumbered
  username                                   = each.value.username
  pppoe_egress_cos                           = each.value.pppoe_egress_cos
  pppoe_unnumbered_negotiate                 = each.value.pppoe_unnumbered_negotiate
  password                                   = each.value.password
  idle_timeout                               = each.value.idle_timeout
  detected_peer_mtu                          = each.value.detected_peer_mtu
  disc_retry_timeout                         = each.value.disc_retry_timeout
  padt_retry_timeout                         = each.value.padt_retry_timeout
  service_name                               = each.value.service_name
  ac_name                                    = each.value.ac_name
  lcp_echo_interval                          = each.value.lcp_echo_interval
  lcp_max_echo_fails                         = each.value.lcp_max_echo_fails
  defaultgw                                  = each.value.defaultgw
  dns_server_override                        = each.value.dns_server_override
  dns_server_protocol                        = each.value.dns_server_protocol
  auth_type                                  = each.value.auth_type
  pptp_client                                = each.value.pptp_client
  pptp_user                                  = each.value.pptp_user
  pptp_password                              = each.value.pptp_password
  pptp_server_ip                             = each.value.pptp_server_ip
  pptp_auth_type                             = each.value.pptp_auth_type
  pptp_timeout                               = each.value.pptp_timeout
  arpforward                                 = each.value.arpforward
  ndiscforward                               = each.value.ndiscforward
  broadcast_forward                          = each.value.broadcast_forward
  bfd                                        = each.value.bfd
  bfd_desired_min_tx                         = each.value.bfd_desired_min_tx
  bfd_detect_mult                            = each.value.bfd_detect_mult
  bfd_required_min_rx                        = each.value.bfd_required_min_rx
  l2forward                                  = each.value.l2forward
  icmp_send_redirect                         = each.value.icmp_send_redirect
  icmp_accept_redirect                       = each.value.icmp_accept_redirect
  reachable_time                             = each.value.reachable_time
  vlanforward                                = each.value.vlanforward
  stpforward                                 = each.value.stpforward
  stpforward_mode                            = each.value.stpforward_mode
  ips_sniffer_mode                           = each.value.ips_sniffer_mode
  ident_accept                               = each.value.ident_accept
  ipmac                                      = each.value.ipmac
  subst                                      = each.value.subst
  macaddr                                    = each.value.macaddr
  virtual_mac                                = each.value.virtual_mac
  substitute_dst_mac                         = each.value.substitute_dst_mac
  speed                                      = each.value.speed
  status                                     = each.value.status
  netbios_forward                            = each.value.netbios_forward
  wins_ip                                    = each.value.wins_ip
  type                                       = each.value.type
  dedicated_to                               = each.value.dedicated_to
  trust_ip_1                                 = each.value.trust_ip_1
  trust_ip_2                                 = each.value.trust_ip_2
  trust_ip_3                                 = each.value.trust_ip_3
  trust_ip6_1                                = each.value.trust_ip6_1
  trust_ip6_2                                = each.value.trust_ip6_2
  trust_ip6_3                                = each.value.trust_ip6_3
  mtu_override                               = each.value.mtu_override
  mtu                                        = each.value.mtu
  ring_rx                                    = each.value.ring_rx
  ring_tx                                    = each.value.ring_tx
  wccp                                       = each.value.wccp
  netflow_sampler                            = each.value.netflow_sampler
  netflow_sample_rate                        = each.value.netflow_sample_rate
  netflow_sampler_id                         = each.value.netflow_sampler_id
  sflow_sampler                              = each.value.sflow_sampler
  drop_overlapped_fragment                   = each.value.drop_overlapped_fragment
  drop_fragment                              = each.value.drop_fragment
  scan_botnet_connections                    = each.value.scan_botnet_connections
  src_check                                  = each.value.src_check
  sample_rate                                = each.value.sample_rate
  polling_interval                           = each.value.polling_interval
  sample_direction                           = each.value.sample_direction
  explicit_web_proxy                         = each.value.explicit_web_proxy
  explicit_ftp_proxy                         = each.value.explicit_ftp_proxy
  proxy_captive_portal                       = each.value.proxy_captive_portal
  tcp_mss                                    = each.value.tcp_mss
  mediatype                                  = each.value.mediatype
  inbandwidth                                = each.value.inbandwidth
  outbandwidth                               = each.value.outbandwidth
  egress_shaping_profile                     = each.value.egress_shaping_profile
  ingress_shaping_profile                    = each.value.ingress_shaping_profile
  disconnect_threshold                       = each.value.disconnect_threshold
  spillover_threshold                        = each.value.spillover_threshold
  ingress_spillover_threshold                = each.value.ingress_spillover_threshold
  weight                                     = each.value.weight
  interface                                  = each.value.interface
  external                                   = each.value.external
  vlan_protocol                              = each.value.vlan_protocol
  vlanid                                     = each.value.vlanid
  trunk                                      = each.value.trunk
  forward_domain                             = each.value.forward_domain
  remote_ip                                  = each.value.remote_ip
  lacp_mode                                  = each.value.lacp_mode
  lacp_ha_secondary                          = each.value.lacp_ha_secondary
  lacp_ha_slave                              = each.value.lacp_ha_slave
  system_id_type                             = each.value.system_id_type
  system_id                                  = each.value.system_id
  lacp_speed                                 = each.value.lacp_speed
  min_links                                  = each.value.min_links
  min_links_down                             = each.value.min_links_down
  algorithm                                  = each.value.algorithm
  link_up_delay                              = each.value.link_up_delay
  aggregate_type                             = each.value.aggregate_type
  priority_override                          = each.value.priority_override
  aggregate                                  = each.value.aggregate
  redundant_interface                        = each.value.redundant_interface
  devindex                                   = each.value.devindex
  vindex                                     = each.value.vindex
  switch                                     = each.value.switch
  description                                = each.value.description
  alias                                      = each.value.alias
  security_mode                              = each.value.security_mode
  captive_portal                             = each.value.captive_portal
  security_mac_auth_bypass                   = each.value.security_mac_auth_bypass
  security_ip_auth_bypass                    = each.value.security_ip_auth_bypass
  security_external_web                      = each.value.security_external_web
  security_external_logout                   = each.value.security_external_logout
  replacemsg_override_group                  = each.value.replacemsg_override_group
  security_redirect_url                      = each.value.security_redirect_url
  auth_cert                                  = each.value.auth_cert
  auth_portal_addr                           = each.value.auth_portal_addr
  security_exempt_list                       = each.value.security_exempt_list
  ike_saml_server                            = each.value.ike_saml_server
  stp                                        = each.value.stp
  stp_ha_secondary                           = each.value.stp_ha_secondary
  device_identification                      = each.value.device_identification
  exclude_signatures                         = each.value.exclude_signatures
  device_user_identification                 = each.value.device_user_identification
  device_identification_active_scan          = each.value.device_identification_active_scan
  device_access_list                         = each.value.device_access_list
  device_netscan                             = each.value.device_netscan
  lldp_reception                             = each.value.lldp_reception
  lldp_transmission                          = each.value.lldp_transmission
  lldp_network_policy                        = each.value.lldp_network_policy
  fortiheartbeat                             = each.value.fortiheartbeat
  broadcast_forticlient_discovery            = each.value.broadcast_forticlient_discovery
  endpoint_compliance                        = each.value.endpoint_compliance
  estimated_upstream_bandwidth               = each.value.estimated_upstream_bandwidth
  estimated_downstream_bandwidth             = each.value.estimated_downstream_bandwidth
  measured_upstream_bandwidth                = each.value.measured_upstream_bandwidth
  measured_downstream_bandwidth              = each.value.measured_downstream_bandwidth
  bandwidth_measure_time                     = each.value.bandwidth_measure_time
  monitor_bandwidth                          = each.value.monitor_bandwidth
  vrrp_virtual_mac                           = each.value.vrrp_virtual_mac
  role                                       = each.value.role
  snmp_index                                 = each.value.snmp_index
  secondary_ip                               = each.value.secondary_ip
  preserve_session_route                     = each.value.preserve_session_route
  auto_auth_extension_device                 = each.value.auto_auth_extension_device
  ap_discover                                = each.value.ap_discover
  fortilink_stacking                         = each.value.fortilink_stacking
  fortilink_neighbor_detect                  = each.value.fortilink_neighbor_detect
  ip_managed_by_fortiipam                    = each.value.ip_managed_by_fortiipam
  managed_subnetwork_size                    = each.value.managed_subnetwork_size
  fortilink_split_interface                  = each.value.fortilink_split_interface
  internal                                   = each.value.internal
  fortilink_backup_link                      = each.value.fortilink_backup_link
  switch_controller_access_vlan              = each.value.switch_controller_access_vlan
  switch_controller_traffic_policy           = each.value.switch_controller_traffic_policy
  switch_controller_rspan_mode               = each.value.switch_controller_rspan_mode
  switch_controller_netflow_collect          = each.value.switch_controller_netflow_collect
  switch_controller_mgmt_vlan                = each.value.switch_controller_mgmt_vlan
  switch_controller_igmp_snooping            = each.value.switch_controller_igmp_snooping
  switch_controller_igmp_snooping_proxy      = each.value.switch_controller_igmp_snooping_proxy
  switch_controller_igmp_snooping_fast_leave = each.value.switch_controller_igmp_snooping_fast_leave
  switch_controller_dhcp_snooping            = each.value.switch_controller_dhcp_snooping
  switch_controller_dhcp_snooping_verify_mac = each.value.switch_controller_dhcp_snooping_verify_mac
  switch_controller_dhcp_snooping_option82   = each.value.switch_controller_dhcp_snooping_option82
  switch_controller_arp_inspection           = each.value.switch_controller_arp_inspection
  switch_controller_learning_limit           = each.value.switch_controller_learning_limit
  switch_controller_nac                      = each.value.switch_controller_nac
  switch_controller_dynamic                  = each.value.switch_controller_dynamic
  switch_controller_feature                  = each.value.switch_controller_feature
  switch_controller_iot_scanning             = each.value.switch_controller_iot_scanning
  switch_controller_offload                  = each.value.switch_controller_offload
  switch_controller_offload_ip               = each.value.switch_controller_offload_ip
  switch_controller_offload_gw               = each.value.switch_controller_offload_gw
  swc_first_create                           = each.value.swc_first_create
  color                                      = each.value.color
  eap_supplicant                             = each.value.eap_supplicant
  eap_method                                 = each.value.eap_method
  eap_identity                               = each.value.eap_identity
  eap_password                               = each.value.eap_password
  eap_ca_cert                                = each.value.eap_ca_cert
  eap_user_cert                              = each.value.eap_user_cert
  default_purdue_level                       = each.value.default_purdue_level
  forward_error_correction                   = each.value.forward_error_correction
  autogenerated                              = each.value.autogenerated
  dynamic_sort_subtable                      = each.value.dynamic_sort_subtable
  get_all_tables                             = each.value.get_all_tables


  dynamic "client_options" {
    for_each = [for option in each.value.client_options : option]
    content {
      id    = client_options.value.id
      code  = lient_options.value.code
      type  = client_options.value.type
      value = client_options.value.value
      ip    = client_options.value.ip
    }
  }

  dynamic "fail_alert_interfaces" {
    for_each = [for interface in each.value.fail_alert_interfaces : interface]
    content {
      name = fail_alert_interfaces.value
    }
  }

  dynamic "member" {
    for_each = [for member in each.value.member : member]
    content {
      interface_name = member.value
    }
  }

  dynamic "managed_device" {
    for_each = [for device in each.value.managed_device : device]
    content {
      name = managed_device.value
    }
  }

  dynamic "security_groups" {
    for_each = [for group in each.value.security_groups : group]
    content {
      name = security_groups.value
    }
  }

  dynamic "vrrp" {
    for_each = [for vrrp in each.value.vrrp : vrrp]
    content {
      vrid                 = vrrp.value.vrid
      version              = vrrp.value.version
      vrgrp                = vrrp.value.vrgrp
      vrip                 = vrrp.value.vrip
      priority             = vrrp.value.priority
      adv_interval         = vrrp.value.adv_interval
      start_time           = vrrp.value.start_time
      preempt              = vrrp.value.preempt
      accept_mode          = vrrp.value.accept_mode
      vrdst                = vrrp.value.vrdst
      vrdst_priority       = vrrp.value.vrdst_priority
      ignore_default_route = vrrp.value.ignore_default_route
      status               = vrrp.value.status
      dynamic "proxy_arp" {
        for_each = [for proxy_arp in vrrp.value.proxy_arps : proxy_arp]
        content {
          id = proxy_arp.value.id
          ip = proxy_arp.value.ip
        }
      }
    }
  }

  dynamic "phy_setting" {
    for_each = each.value.phy_setting != null ? [each.value.phy_setting] : []
    content {
      signal_ok_threshold       = phy_setting.value.signal_ok_threshold
      signal_ok_threshold_value = phy_setting.value.signal_ok_threshold_value
    }
  }

  dynamic "secondaryip" {
    for_each = [for secip in each.value.secondaryip : secip]
    content {
      ip               = secondaryip.value.ip
      id               = secondaryip.value.id
      secip_relay_ip   = secondaryip.value.secip_relay_ip
      allowaccess      = secondaryip.value.allowaccess
      gwdetect         = secondaryip.value.gwdetect
      ping_serv_status = secondaryip.value.ping_serv_status
      detectserver     = secondaryip.value.detectserver
      detectprotocol   = secondaryip.value.detectprotocol
      ha_priority      = secondaryip.value.ha_priority
    }
  }

  dynamic "dhcp_snooping_server_list" {
    for_each = [for snoop in each.value.dhcp_snooping_server_list : snoop]
    content {
      name      = snoop.value.name
      server_ip = snoop.value.server_ip
    }
  }

  dynamic "tagging" {
    for_each = [for tag in each.value.tagging : tag]
    content {
      name     = tagging.value.name
      category = tagging.value.category
      dynamic "tags" {
        for_each = [for tag in tagging.value.tags : tag]
        content {
          name = tags.value
        }
      }
    }
  }

  dynamic "ipv6" {
    for_each = each.value.ipv6 != null ? [each.value.ipv6] : []
    content {
      ip6_mode                     = ipv6.value.ip6_mode
      nd_mode                      = ipv6.value.nd_mode
      nd_cert                      = ipv6.value.nd_cert
      nd_security_level            = ipv6.value.nd_security_level
      nd_timestamp_delta           = ipv6.value.nd_timestamp_delta
      nd_timestamp_fuzz            = ipv6.value.nd_timestamp_fuzz
      nd_cga_modifier              = ipv6.value.nd_cga_modifier
      ip6_dns_server_override      = ipv6.value.ip6_dns_server_override
      ip6_address                  = ipv6.value.ip6_address
      ip6_allowaccess              = ipv6.value.ip6_allowaccess
      ip6_send_adv                 = ipv6.value.ip6_send_adv
      icmp6_send_redirect          = ipv6.value.icmp6_send_redirect
      ip6_manage_flag              = ipv6.value.ip6_manage_flag
      ip6_other_flag               = ipv6.value.ip6_other_flag
      ip6_max_interval             = ipv6.value.ip6_max_interval
      ip6_min_interval             = ipv6.value.ip6_min_interval
      ip6_link_mtu                 = ipv6.value.ip6_link_mtu
      ra_send_mtu                  = ipv6.value.ra_send_mtu
      ip6_reachable_time           = ipv6.value.ip6_reachable_time
      ip6_retrans_time             = ipv6.value.ip6_retrans_time
      ip6_default_life             = ipv6.value.ip6_default_life
      ip6_hop_limit                = ipv6.value.ip6_hop_limit
      ip6_adv_rio                  = ipv6.value.ip6_adv_rio
      ip6_route_pref               = ipv6.value.ip6_route_pref
      autoconf                     = ipv6.value.autoconf
      unique_autoconf_addr         = ipv6.value.unique_autoconf_addr
      interface_identifier         = ipv6.value.interface_identifier
      ip6_prefix_mode              = ipv6.value.ip6_prefix_mode
      ip6_upstream_interface       = ipv6.value.ip6_upstream_interface
      ip6_delegated_prefix_iaid    = ipv6.value.ip6_delegated_prefix_iaid
      ip6_subnet                   = ipv6.value.ip6_subnet
      dhcp6_relay_service          = ipv6.value.dhcp6_relay_service
      dhcp6_relay_type             = ipv6.value.dhcp6_relay_type
      dhcp6_relay_source_interface = ipv6.value.dhcp6_relay_source_interface
      dhcp6_relay_ip               = ipv6.value.dhcp6_relay_ip
      dhcp6_relay_source_ip        = ipv6.value.dhcp6_relay_source_ip
      dhcp6_relay_interface_id     = ipv6.value.dhcp6_relay_interface_id
      dhcp6_client_options         = ipv6.value.dhcp6_client_options
      dhcp6_prefix_delegation      = ipv6.value.dhcp6_prefix_delegation
      dhcp6_information_request    = ipv6.value.dhcp6_information_request
      dhcp6_prefix_hint            = ipv6.value.dhcp6_prefix_hint
      dhcp6_prefix_hint_plt        = ipv6.value.dhcp6_prefix_hint_plt
      dhcp6_prefix_hint_vlt        = ipv6.value.dhcp6_prefix_hint_vlt
      vrrp_virtual_mac6            = ipv6.value.vrrp_virtual_mac6
      vrip6_link_local             = ipv6.value.vrip6_link_local

      dynamic "client_options" {
        for_each = [for option in ipv6.value.client_options : option]
        content {
          id    = client_options.value.id
          code  = lient_options.value.code
          type  = client_options.value.type
          value = client_options.value.value
          ip6   = client_options.value.ip6
        }
      }

      dynamic "ip6_extra_addr" {
        for_each = [for addr in ipv6.value.ip6_extra_addr : addr]
        content {
          prefix = ip6_extra_addr.value
        }
      }

      dynamic "ip6_route_list" {
        for_each = [for route in ipv6.value.ip6_route_list : route]
        content {
          route           = ip6_route_list.value.route
          route_pref      = ip6_route_list.value.route_pref
          route_life_time = ip6_route_list.value.route_life_time
        }
      }

      dynamic "ip6_prefix_list" {
        for_each = [for prefix_list in ipv6.value.ip6_prefix_list : prefix_list]
        content {
          prefix              = ip6_prefix_list.value.prefix
          autonomous_flag     = ip6_prefix_list.value.autonomous_flag
          onlink_flag         = ip6_prefix_list.value.onlink_flag
          valid_life_time     = ip6_prefix_list.value.valid_life_time
          preferred_life_time = ip6_prefix_list.value.preferred_life_time
          rdnss               = ip6_prefix_list.value.rdnss
          dynamic "dnssl" {
            for_each = [for suffix in ip6_prefix_list.value.dnssl : suffix]
            content {
              domain = dnssl.value
            }
          }
        }
      }

      dynamic "ip6_rdnss_list" {
        for_each = [for rdns in ipv6.value.ip6_rdnss_list : rdns.rdnss]
        content {
          rdnss           = ip6_rdnss_list.value.rdnss
          rdnss_life_time = ip6_rdnss_list.value.rdnss_life_time
        }
      }

      dynamic "ip6_dnssl_list" {
        for_each = [for dnssl in ipv6.value.ip6_dnssl_list : dnssl]
        content {
          domain          = ip6_dnssl_list.value.domain
          dnssl_life_time = ip6_dnssl_list.value.dnssl_life_time
        }
      }

      dynamic "ip6_delegated_prefix_list" {
        for_each = [for prefix in ipv6.value.ip6_delegated_prefix_list : prefix]
        content {
          prefix_id             = ip6_delegated_prefix_list.value.id
          upstream_interface    = ip6_delegated_prefix_list.value.upstream_interface
          delegated_prefix_iaid = ip6_delegated_prefix_list.value.delegated_prefix_iaid
          autonomous_flag       = ip6_delegated_prefix_list.value.autonomous_flag
          onlink_flag           = ip6_delegated_prefix_list.value.onlink_flag
          subnet                = ip6_delegated_prefix_list.value.subnet
          rdnss                 = ip6_delegated_prefix_list.value.rdnss
          rdnss_service         = ip6_delegated_prefix_list.value.rdnss_service
        }
      }

      dynamic "dhcp6_iapd_list" {
        for_each = [for iapd in ipv6.value.dhcp6_iapd_list : iapd]
        content {
          iaid            = dhcp6_iapd_list.value.iaid
          prefix_hint     = dhcp6_iapd_list.value.prefix_hint
          prefix_hint_plt = dhcp6_iapd_list.value.prefix_hint_plt
          prefix_hint_vlt = dhcp6_iapd_list.value.prefix_hint_vlt
        }
      }

      dynamic "vrrp6" {
        for_each = [for vrrp in ipv6.value.vrrp6 : vrrp]
        content {
          vrid                 = vrrp6.value.vrid
          vrgrp                = vrrp6.value.vrgrp
          vrip6                = vrrp6.value.vrip6
          priority             = vrrp6.value.priority
          adv_interval         = vrrp6.value.adv_interval
          start_time           = vrrp6.value.start_time
          preempt              = vrrp6.value.preempt
          accept_mode          = vrrp6.value.accept_mode
          vrdst6               = vrrp6.value.vrdst6
          vrdst_priority       = vrrp6.value.vrdst_priority
          ignore_default_route = vrrp6.value.ignore_default_route
          status               = vrrp6.value.status
        }
      }
    } # /dynamic
  }   # /ipv6
}

resource "fortios_system_zone" "zones" {
  for_each              = { for zone in var.zones : zone.name => zone }
  depends_on            = [fortios_system_interface.interfaces]
  uuid                  = each.value.uuid
  fabric_object         = each.value.fabric_object
  fabric_force_sync     = each.value.fabric_force_sync
  fabric_object_source  = each.value.fabric_object_source
  name                  = each.value.name
  description           = each.value.description
  intrazone             = each.value.intrazone
  dynamic_sort_subtable = each.value.dynamic_sort_subtable
  get_all_tables        = each.value.get_all_tables
  vdomparam             = each.value.vdomparam
  update_if_exist       = each.value.update_if_exist

  dynamic "tagging" {
    for_each = [for tagging in each.value.tagging : tagging]
    content {
      name     = tagging.value.name
      category = tagging.value.category
      dynamic "tags" {
        for_each = [for tag in tagging.value.tags : tag]
        content {
          name = tags.value
        }
      }
    }
  }
  dynamic "interface" {
    for_each = [for interface in each.value.interface : interface]
    content {
      interface_name = interface.value
    }
  }
}
