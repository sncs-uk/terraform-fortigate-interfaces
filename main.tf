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

locals {
  interface_yaml = yamldecode(file("${var.config_path}/interfaces.yaml"))
}

resource "fortios_system_interface" "interfaces" {
  for_each   = { for name, interface in try(local.interface_yaml[var.interface_key], []) : name => interface }
  depends_on = [module.hardware_switch]
  lifecycle {
    ignore_changes = [cli_conn_status, ipv6[0].cli_conn6_status]
  }

  name = each.key
  vdom = each.value.vdom

  vrf                                        = try(each.value.vrf, null)
  cli_conn_status                            = try(each.value.cli_conn_status, null)
  fortilink                                  = try(each.value.fortilink, null)
  switch_controller_source_ip                = try(each.value.switch_controller_source_ip, null)
  mode                                       = try(each.value.mode, null)
  distance                                   = try(each.value.distance, null)
  priority                                   = try(each.value.priority, null)
  dhcp_relay_interface_select_method         = try(each.value.dhcp_relay_interface_select_method, null)
  dhcp_relay_interface                       = try(each.value.dhcp_relay_interface, null)
  dhcp_relay_vrf_select                      = try(each.value.dhcp_relay_vrf_select, null)
  dhcp_broadcast_flag                        = try(each.value.dhcp_broadcast_flag, null)
  dhcp_relay_service                         = try(each.value.dhcp_relay_service, null)
  dhcp_relay_ip                              = try(each.value.dhcp_relay_ip, null)
  dhcp_relay_source_ip                       = try(each.value.dhcp_relay_source_ip, null)
  dhcp_relay_circuit_id                      = try(each.value.dhcp_relay_circuit_id, null)
  dhcp_relay_link_selection                  = try(each.value.dhcp_relay_link_selection, null)
  dhcp_relay_request_all_server              = try(each.value.dhcp_relay_request_all_server, null)
  dhcp_relay_allow_no_end_option             = try(each.value.dhcp_relay_allow_no_end_option, null)
  dhcp_relay_type                            = try(each.value.dhcp_relay_type, null)
  dhcp_smart_relay                           = try(each.value.dhcp_smart_relay, null)
  dhcp_relay_agent_option                    = try(each.value.dhcp_relay_agent_option, null)
  dhcp_classless_route_addition              = try(each.value.dhcp_classless_route_addition, null)
  management_ip                              = try(each.value.management_ip, null)
  ip                                         = try(each.value.ip, null)
  allowaccess                                = join(" ", try(each.value.allowaccess, try(each.value.role, null) == "wan" ? [] : ["ping"]))
  gwdetect                                   = try(each.value.gwdetect, null)
  ping_serv_status                           = try(each.value.ping_serv_status, null)
  detectserver                               = try(each.value.detectserver, null)
  detectprotocol                             = try(each.value.detectprotocol, null)
  ha_priority                                = try(each.value.ha_priority, null)
  fail_detect                                = try(each.value.fail_detect, null)
  fail_detect_option                         = try(each.value.fail_detect_option, null)
  fail_alert_method                          = try(each.value.fail_alert_method, null)
  fail_action_on_extender                    = try(each.value.fail_action_on_extender, null)
  dhcp_client_identifier                     = try(each.value.dhcp_client_identifier, null)
  dhcp_renew_time                            = try(each.value.dhcp_renew_time, null)
  ipunnumbered                               = try(each.value.ipunnumbered, null)
  username                                   = try(each.value.username, null)
  pppoe_egress_cos                           = try(each.value.pppoe_egress_cos, null)
  pppoe_unnumbered_negotiate                 = try(each.value.pppoe_unnumbered_negotiate, null)
  password                                   = try(each.value.password, null)
  idle_timeout                               = try(each.value.idle_timeout, null)
  detected_peer_mtu                          = try(each.value.detected_peer_mtu, null)
  disc_retry_timeout                         = try(each.value.disc_retry_timeout, null)
  padt_retry_timeout                         = try(each.value.padt_retry_timeout, null)
  service_name                               = try(each.value.service_name, null)
  ac_name                                    = try(each.value.ac_name, null)
  lcp_echo_interval                          = try(each.value.lcp_echo_interval, null)
  lcp_max_echo_fails                         = try(each.value.lcp_max_echo_fails, null)
  defaultgw                                  = try(each.value.defaultgw, null)
  dns_server_override                        = try(each.value.dns_server_override, null)
  dns_server_protocol                        = try(each.value.dns_server_protocol, null)
  auth_type                                  = try(each.value.auth_type, null)
  pptp_client                                = try(each.value.pptp_client, null)
  pptp_user                                  = try(each.value.pptp_user, null)
  pptp_password                              = try(each.value.pptp_password, null)
  pptp_server_ip                             = try(each.value.pptp_server_ip, null)
  pptp_auth_type                             = try(each.value.pptp_auth_type, null)
  pptp_timeout                               = try(each.value.pptp_timeout, null)
  arpforward                                 = try(each.value.arpforward, null)
  ndiscforward                               = try(each.value.ndiscforward, null)
  broadcast_forward                          = try(each.value.broadcast_forward, null)
  bfd                                        = try(each.value.bfd, null)
  bfd_desired_min_tx                         = try(each.value.bfd_desired_min_tx, null)
  bfd_detect_mult                            = try(each.value.bfd_detect_mult, null)
  bfd_required_min_rx                        = try(each.value.bfd_required_min_rx, null)
  l2forward                                  = try(each.value.l2forward, null)
  icmp_send_redirect                         = try(each.value.icmp_send_redirect, null)
  icmp_accept_redirect                       = try(each.value.icmp_accept_redirect, null)
  reachable_time                             = try(each.value.reachable_time, null)
  vlanforward                                = try(each.value.vlanforward, null)
  stpforward                                 = try(each.value.stpforward, null)
  stpforward_mode                            = try(each.value.stpforward_mode, null)
  ips_sniffer_mode                           = try(each.value.ips_sniffer_mode, null)
  ident_accept                               = try(each.value.ident_accept, null)
  ipmac                                      = try(each.value.ipmac, null)
  subst                                      = try(each.value.subst, null)
  macaddr                                    = try(each.value.macaddr, null)
  virtual_mac                                = try(each.value.virtual_mac, null)
  substitute_dst_mac                         = try(each.value.substitute_dst_mac, null)
  speed                                      = try(each.value.speed, null)
  status                                     = try(each.value.status, null)
  netbios_forward                            = try(each.value.netbios_forward, null)
  wins_ip                                    = try(each.value.wins_ip, null)
  type                                       = each.value.type
  dedicated_to                               = try(each.value.dedicated_to, null)
  trust_ip_1                                 = try(each.value.trust_ip_1, null)
  trust_ip_2                                 = try(each.value.trust_ip_2, null)
  trust_ip_3                                 = try(each.value.trust_ip_3, null)
  trust_ip6_1                                = try(each.value.trust_ip6_1, null)
  trust_ip6_2                                = try(each.value.trust_ip6_2, null)
  trust_ip6_3                                = try(each.value.trust_ip6_3, null)
  mtu_override                               = try(each.value.mtu_override, null)
  mtu                                        = try(each.value.mtu, null)
  ring_rx                                    = try(each.value.ring_rx, null)
  ring_tx                                    = try(each.value.ring_tx, null)
  wccp                                       = try(each.value.wccp, null)
  netflow_sampler                            = try(each.value.netflow_sampler, null)
  netflow_sample_rate                        = try(each.value.netflow_sample_rate, null)
  netflow_sampler_id                         = try(each.value.netflow_sampler_id, null)
  sflow_sampler                              = try(each.value.sflow_sampler, null)
  drop_overlapped_fragment                   = try(each.value.drop_overlapped_fragment, null)
  drop_fragment                              = try(each.value.drop_fragment, null)
  scan_botnet_connections                    = try(each.value.scan_botnet_connections, null)
  src_check                                  = try(each.value.src_check, null)
  sample_rate                                = try(each.value.sample_rate, null)
  polling_interval                           = try(each.value.polling_interval, null)
  sample_direction                           = try(each.value.sample_direction, null)
  explicit_web_proxy                         = try(each.value.explicit_web_proxy, null)
  explicit_ftp_proxy                         = try(each.value.explicit_ftp_proxy, null)
  proxy_captive_portal                       = try(each.value.proxy_captive_portal, null)
  tcp_mss                                    = try(each.value.tcp_mss, null)
  mediatype                                  = try(each.value.mediatype, null)
  inbandwidth                                = try(each.value.inbandwidth, null)
  outbandwidth                               = try(each.value.outbandwidth, null)
  egress_shaping_profile                     = try(each.value.egress_shaping_profile, null)
  ingress_shaping_profile                    = try(each.value.ingress_shaping_profile, null)
  disconnect_threshold                       = try(each.value.disconnect_threshold, null)
  spillover_threshold                        = try(each.value.spillover_threshold, null)
  ingress_spillover_threshold                = try(each.value.ingress_spillover_threshold, null)
  weight                                     = try(each.value.weight, null)
  interface                                  = try(each.value.interface, null)
  external                                   = try(each.value.external, null)
  vlan_protocol                              = try(each.value.vlan_protocol, null)
  vlanid                                     = try(each.value.vlanid, null)
  trunk                                      = try(each.value.trunk, null)
  forward_domain                             = try(each.value.forward_domain, null)
  remote_ip                                  = try(each.value.remote_ip, null)
  lacp_mode                                  = try(each.value.lacp_mode, null)
  lacp_ha_secondary                          = try(each.value.lacp_ha_secondary, null)
  lacp_ha_slave                              = try(each.value.lacp_ha_slave, null)
  system_id_type                             = try(each.value.system_id_type, null)
  system_id                                  = try(each.value.system_id, null)
  lacp_speed                                 = try(each.value.lacp_speed, null)
  min_links                                  = try(each.value.min_links, null)
  min_links_down                             = try(each.value.min_links_down, null)
  algorithm                                  = try(each.value.algorithm, null)
  link_up_delay                              = try(each.value.link_up_delay, null)
  aggregate_type                             = try(each.value.aggregate_type, null)
  priority_override                          = try(each.value.priority_override, null)
  aggregate                                  = try(each.value.aggregate, null)
  redundant_interface                        = try(each.value.redundant_interface, null)
  devindex                                   = try(each.value.devindex, null)
  vindex                                     = try(each.value.vindex, null)
  switch                                     = try(each.value.switch, null)
  description                                = try(each.value.description, null)
  alias                                      = try(each.value.alias, null)
  security_mode                              = try(each.value.security_mode, null)
  captive_portal                             = try(each.value.captive_portal, null)
  security_mac_auth_bypass                   = try(each.value.security_mac_auth_bypass, null)
  security_ip_auth_bypass                    = try(each.value.security_ip_auth_bypass, null)
  security_external_web                      = try(each.value.security_external_web, null)
  security_external_logout                   = try(each.value.security_external_logout, null)
  replacemsg_override_group                  = try(each.value.replacemsg_override_group, null)
  security_redirect_url                      = try(each.value.security_redirect_url, null)
  auth_cert                                  = try(each.value.auth_cert, null)
  auth_portal_addr                           = try(each.value.auth_portal_addr, null)
  security_exempt_list                       = try(each.value.security_exempt_list, null)
  ike_saml_server                            = try(each.value.ike_saml_server, null)
  stp                                        = try(each.value.stp, null)
  stp_ha_secondary                           = try(each.value.stp_ha_secondary, null)
  device_identification                      = try(each.value.device_identification, null)
  exclude_signatures                         = try(each.value.exclude_signatures, null)
  device_user_identification                 = try(each.value.device_user_identification, null)
  device_identification_active_scan          = try(each.value.device_identification_active_scan, null)
  device_access_list                         = try(each.value.device_access_list, null)
  device_netscan                             = try(each.value.device_netscan, null)
  lldp_reception                             = try(each.value.lldp_reception, null)
  lldp_transmission                          = try(each.value.lldp_transmission, null)
  lldp_network_policy                        = try(each.value.lldp_network_policy, null)
  fortiheartbeat                             = try(each.value.fortiheartbeat, null)
  broadcast_forticlient_discovery            = try(each.value.broadcast_forticlient_discovery, null)
  endpoint_compliance                        = try(each.value.endpoint_compliance, null)
  estimated_upstream_bandwidth               = try(each.value.estimated_upstream_bandwidth, null)
  estimated_downstream_bandwidth             = try(each.value.estimated_downstream_bandwidth, null)
  measured_upstream_bandwidth                = try(each.value.measured_upstream_bandwidth, null)
  measured_downstream_bandwidth              = try(each.value.measured_downstream_bandwidth, null)
  bandwidth_measure_time                     = try(each.value.bandwidth_measure_time, null)
  monitor_bandwidth                          = try(each.value.monitor_bandwidth, null)
  vrrp_virtual_mac                           = try(each.value.vrrp_virtual_mac, null)
  role                                       = try(each.value.role, null)
  snmp_index                                 = try(each.value.snmp_index, null)
  secondary_ip                               = length(try(each.value.secondaryip, [])) > 0 ? "enable" : "disable"
  preserve_session_route                     = try(each.value.preserve_session_route, null)
  auto_auth_extension_device                 = try(each.value.auto_auth_extension_device, null)
  ap_discover                                = try(each.value.ap_discover, null)
  fortilink_stacking                         = try(each.value.fortilink_stacking, null)
  fortilink_neighbor_detect                  = try(each.value.fortilink_neighbor_detect, null)
  ip_managed_by_fortiipam                    = try(each.value.ip_managed_by_fortiipam, null)
  managed_subnetwork_size                    = try(each.value.managed_subnetwork_size, null)
  fortilink_split_interface                  = try(each.value.fortilink_split_interface, null)
  internal                                   = try(each.value.internal, null)
  fortilink_backup_link                      = try(each.value.fortilink_backup_link, null)
  switch_controller_access_vlan              = try(each.value.switch_controller_access_vlan, null)
  switch_controller_traffic_policy           = try(each.value.switch_controller_traffic_policy, null)
  switch_controller_rspan_mode               = try(each.value.switch_controller_rspan_mode, null)
  switch_controller_netflow_collect          = try(each.value.switch_controller_netflow_collect, null)
  switch_controller_mgmt_vlan                = try(each.value.switch_controller_mgmt_vlan, null)
  switch_controller_igmp_snooping            = try(each.value.switch_controller_igmp_snooping, null)
  switch_controller_igmp_snooping_proxy      = try(each.value.switch_controller_igmp_snooping_proxy, null)
  switch_controller_igmp_snooping_fast_leave = try(each.value.switch_controller_igmp_snooping_fast_leave, null)
  switch_controller_dhcp_snooping            = try(each.value.switch_controller_dhcp_snooping, null)
  switch_controller_dhcp_snooping_verify_mac = try(each.value.switch_controller_dhcp_snooping_verify_mac, null)
  switch_controller_dhcp_snooping_option82   = try(each.value.switch_controller_dhcp_snooping_option82, null)
  switch_controller_arp_inspection           = try(each.value.switch_controller_arp_inspection, null)
  switch_controller_learning_limit           = try(each.value.switch_controller_learning_limit, null)
  switch_controller_nac                      = try(each.value.switch_controller_nac, null)
  switch_controller_dynamic                  = try(each.value.switch_controller_dynamic, null)
  switch_controller_feature                  = try(each.value.switch_controller_feature, null)
  switch_controller_iot_scanning             = try(each.value.switch_controller_iot_scanning, null)
  switch_controller_offload                  = try(each.value.switch_controller_offload, null)
  switch_controller_offload_ip               = try(each.value.switch_controller_offload_ip, null)
  switch_controller_offload_gw               = try(each.value.switch_controller_offload_gw, null)
  swc_vlan                                   = try(each.value.swc_vlan, null)
  swc_first_create                           = try(each.value.swc_first_create, null)
  color                                      = try(each.value.color, null)
  eap_supplicant                             = try(each.value.eap_supplicant, null)
  eap_method                                 = try(each.value.eap_method, null)
  eap_identity                               = try(each.value.eap_identity, null)
  eap_password                               = try(each.value.eap_password, null)
  eap_ca_cert                                = try(each.value.eap_ca_cert, null)
  eap_user_cert                              = try(each.value.eap_user_cert, null)
  default_purdue_level                       = try(each.value.default_purdue_level, null)
  forward_error_correction                   = try(each.value.forward_error_correction, null)
  autogenerated                              = try(each.value.autogenerated, null)
  dynamic_sort_subtable                      = try(each.value.dynamic_sort_subtable, null)
  get_all_tables                             = try(each.value.get_all_tables, null)


  dynamic "client_options" {
    for_each = { for option in try(each.value.client_options, []) : option.code => option }
    content {
      id    = try(client_options.value.id, null)
      code  = try(lient_options.value.code, null)
      type  = try(client_options.value.type, null)
      value = try(client_options.value.value, null)
      ip    = try(client_options.value.ip, null)
    }
  }

  dynamic "fail_alert_interfaces" {
    for_each = { for interface in try(each.value.fail_alert_interfaces, []) : interface => interface }
    content {
      name = fail_alert_interfaces.value
    }
  }

  dynamic "member" {
    for_each = { for member in try(each.value.members, []) : member => member }
    content {
      interface_name = member.value
    }
  }

  dynamic "managed_device" {
    for_each = { for device in try(each.value.managed_devices, []) : device => device }
    content {
      name = managed_device.value
    }
  }

  dynamic "security_groups" {
    for_each = { for group in try(each.value.security_groups, []) : group => group }
    content {
      name = security_groups.value
    }
  }

  dynamic "vrrp" {
    for_each = { for vrrp in try(each.value.vrrp, []) : vrrp.vrid => vrrp }
    content {
      vrid                 = try(vrrp.value.vrid, null)
      version              = try(vrrp.value.version, null)
      vrgrp                = try(vrrp.value.vrgrp, null)
      vrip                 = try(vrrp.value.vrip, null)
      priority             = try(vrrp.value.priority, null)
      adv_interval         = try(vrrp.value.adv_interval, null)
      start_time           = try(vrrp.value.start_time, null)
      preempt              = try(vrrp.value.preempt, null)
      accept_mode          = try(vrrp.value.accept_mode, null)
      vrdst                = try(vrrp.value.vrdst, null)
      vrdst_priority       = try(vrrp.value.vrdst_priority, null)
      ignore_default_route = try(vrrp.value.ignore_default_route, null)
      status               = try(vrrp.value.status, null)
      dynamic "proxy_arp" {
        for_each = { for proxy_arp in try(vrrp.value.proxy_arps, []) : proxy_arp => proxy_arp }
        content {
          ip = proxy_arp.value
        }
      }
    }
  }

  dynamic "phy_setting" {
    for_each = { for setting in try(each.value.phy_settings, []) : setting => setting }
    content {
      signal_ok_threshold_value = phy_setting.value
    }
  }

  dynamic "secondaryip" {
    for_each = { for secip in try(each.value.secondaryip, []) : secip.ip => secip }
    content {
      ip               = secondaryip.value.ip
      id               = try(secondaryip.value.id, null)
      secip_relay_ip   = try(secondaryip.value.secip_relay_ip, null)
      allowaccess      = join(" ", try(secondaryip.value.allowaccess, try(each.value.role, null) == "wan" ? [] : ["ping"]))
      gwdetect         = try(secondaryip.value.gwdetect, null)
      ping_serv_status = try(secondaryip.value.ping_serv_status, null)
      detectserver     = try(secondaryip.value.detectserver, null)
      detectprotocol   = try(secondaryip.value.detectprotocol, null)
      ha_priority      = try(secondaryip.value.ha_priority, null)
    }
  }

  dynamic "dhcp_snooping_server_list" {
    for_each = { for snoop in try(each.value.dhcp_snooping_server_list, []) : snoop.name => snoop }
    content {
      name      = try(snoop.value.name, null)
      server_ip = try(snoop.value.server_ip, null)
    }
  }

  dynamic "tagging" {
    for_each = { for tag in try(each.value.tagging, []) : tag.name => tag }
    content {
      name     = tagging.value.name
      category = try(tagging.value.category, null)
      dynamic "tags" {
        for_each = { for tag in try(tagging.value.tags, []) : tag => tag }
        content {
          name = tags.value
        }
      }
    }
  }

  ipv6 {
    ip6_mode                     = try(each.value.ipv6.ip6_mode, null)
    nd_mode                      = try(each.value.ipv6.nd_mode, null)
    nd_cert                      = try(each.value.ipv6.nd_cert, null)
    nd_security_level            = try(each.value.ipv6.nd_security_level, null)
    nd_timestamp_delta           = try(each.value.ipv6.nd_timestamp_delta, null)
    nd_timestamp_fuzz            = try(each.value.ipv6.nd_timestamp_fuzz, null)
    nd_cga_modifier              = try(each.value.ipv6.nd_cga_modifier, null)
    ip6_dns_server_override      = try(each.value.ipv6.ip6_dns_server_override, null)
    ip6_address                  = try(each.value.ipv6.ip6_address, null)
    ip6_allowaccess              = join(" ", try(each.value.ipv6.ip6_allowaccess, try(each.value.role, null) == "wan" ? [] : ["ping"]))
    ip6_send_adv                 = try(each.value.ipv6.ip6_send_adv, null)
    icmp6_send_redirect          = try(each.value.ipv6.icmp6_send_redirect, null)
    ip6_manage_flag              = try(each.value.ipv6.ip6_manage_flag, null)
    ip6_other_flag               = try(each.value.ipv6.ip6_other_flag, null)
    ip6_max_interval             = try(each.value.ipv6.ip6_max_interval, null)
    ip6_min_interval             = try(each.value.ipv6.ip6_min_interval, null)
    ip6_link_mtu                 = try(each.value.ipv6.ip6_link_mtu, null)
    ra_send_mtu                  = try(each.value.ipv6.ra_send_mtu, null)
    ip6_reachable_time           = try(each.value.ipv6.ip6_reachable_time, null)
    ip6_retrans_time             = try(each.value.ipv6.ip6_retrans_time, null)
    ip6_default_life             = try(each.value.ipv6.ip6_default_life, null)
    ip6_hop_limit                = try(each.value.ipv6.ip6_hop_limit, null)
    ip6_adv_rio                  = try(each.value.ipv6.ip6_adv_rio, null)
    ip6_route_pref               = try(each.value.ipv6.ip6_route_pref, null)
    autoconf                     = try(each.value.ipv6.autoconf, null)
    unique_autoconf_addr         = try(each.value.ipv6.unique_autoconf_addr, null)
    interface_identifier         = try(each.value.ipv6.interface_identifier, null)
    ip6_prefix_mode              = try(each.value.ipv6.ip6_prefix_mode, null)
    ip6_upstream_interface       = try(each.value.ipv6.ip6_upstream_interface, null)
    ip6_delegated_prefix_iaid    = try(each.value.ipv6.ip6_delegated_prefix_iaid, null)
    ip6_subnet                   = try(each.value.ipv6.ip6_subnet, null)
    dhcp6_relay_service          = try(each.value.ipv6.dhcp6_relay_service, null)
    dhcp6_relay_type             = try(each.value.ipv6.dhcp6_relay_type, null)
    dhcp6_relay_source_interface = try(each.value.ipv6.dhcp6_relay_source_interface, null)
    dhcp6_relay_ip               = try(each.value.ipv6.dhcp6_relay_ip, null)
    dhcp6_relay_source_ip        = try(each.value.ipv6.dhcp6_relay_source_ip, null)
    dhcp6_relay_interface_id     = try(each.value.ipv6.dhcp6_relay_interface_id, null)
    dhcp6_client_options         = try(each.value.ipv6.dhcp6_client_options, null)
    dhcp6_prefix_delegation      = try(each.value.dhcp6_prefix_delegation, false) ? "enable" : "disable"
    dhcp6_information_request    = try(each.value.ipv6.dhcp6_information_request, null)
    dhcp6_prefix_hint            = try(each.value.ipv6.dhcp6_prefix_hint, null)
    dhcp6_prefix_hint_plt        = try(each.value.ipv6.dhcp6_prefix_hint_plt, null)
    dhcp6_prefix_hint_vlt        = try(each.value.ipv6.dhcp6_prefix_hint_vlt, null)
    cli_conn6_status             = try(each.value.ipv6.cli_conn6_status, null)
    vrrp_virtual_mac6            = try(each.value.ipv6.vrrp_virtual_mac6, null)
    vrip6_link_local             = try(each.value.ipv6.vrip6_link_local, null)

    dynamic "client_options" {
      for_each = { for option in try(each.value.ipv6.client_options, []) : option.code => option }
      content {
        id    = try(client_options.value.id, null)
        code  = try(lient_options.value.code, null)
        type  = try(client_options.value.type, null)
        value = try(client_options.value.value, null)
        ip6   = try(client_options.value.ip6, null)
      }
    }

    dynamic "ip6_extra_addr" {
      for_each = { for addr in try(each.value.ipv6.ip6_extra_addr, []) : addr => addr }
      content {
        prefix = ip6_extra_addr.value
      }
    }

    dynamic "ip6_route_list" {
      for_each = { for route in try(each.value.ipv6.ip6_route_list, []) : route.route => route }
      content {
        route           = ip6_route_list.value.route
        route_pref      = try(ip6_route_list.value.route_pref, null)
        route_life_time = try(ip6_route_list.value.route_life_time, null)
      }
    }

    dynamic "ip6_prefix_list" {
      for_each = { for list in try(each.value.ipv6.ip6_prefix_list, []) : list.prefix => list }
      content {
        prefix              = try(ip6_prefix_list.value.prefix, null)
        autonomous_flag     = try(ip6_prefix_list.value.autonomous_flag, null)
        onlink_flag         = try(ip6_prefix_list.value.onlink_flag, null)
        valid_life_time     = try(ip6_prefix_list.value.valid_life_time, null)
        preferred_life_time = try(ip6_prefix_list.value.preferred_life_time, null)
        rdnss               = try(ip6_prefix_list.value.rdnss, null)
        dynamic "dnssl" {
          for_each = { for suffix in try(ip6_prefix_list.dnssl, []) : suffix => suffix }
          content {
            domain = dnssl.value
          }
        }
      }
    }

    dynamic "ip6_rdnss_list" {
      for_each = { for rdns in try(each.value.ipv6.ip6_rdnss_list, []) : rdns.rdnss => rdns }
      content {
        rdnss           = ip6_rdnss_list.value.rdnss
        rdnss_life_time = try(ip6_rdnss_list.value.rdnss_life_time, null)
      }
    }

    dynamic "ip6_dnssl_list" {
      for_each = { for dnssl in try(each.value.ipv6.ip6_dnssl_list, []) : dnssl.domain => dnssl }
      content {
        domain          = ip6_dnssl_list.value.domain
        dnssl_life_time = try(ip6_dnssl_list.value.dnssl_life_time, null)
      }
    }

    dynamic "ip6_delegated_prefix_list" {
      for_each = { for prefix in try(each.value.ip6_delegated_prefix_list, []) : prefix.id => prefix }
      content {
        prefix_id             = ip6_delegated_prefix_list.value.id
        upstream_interface    = ip6_delegated_prefix_list.value.upstream_interface
        delegated_prefix_iaid = ip6_delegated_prefix_list.value.delegated_prefix_iaid
        autonomous_flag       = try(ip6_delegated_prefix_list.value.autonomous_flag, null)
        onlink_flag           = try(ip6_delegated_prefix_list.value.onlink_flag, null)
        subnet                = ip6_delegated_prefix_list.value.subnet
        rdnss                 = ip6_delegated_prefix_list.value.rdnss
        rdnss_service         = try(ip6_delegated_prefix_list.value.rdnss_service, null)
      }
    }

    dynamic "dhcp6_iapd_list" {
      for_each = { for iapd in try(each.value.dhcp6_iapd_list, []) : iapd.iaid => iapd }
      content {
        iaid            = dhcp6_iapd_list.value.iaid
        prefix_hint     = dhcp6_iapd_list.value.prefix_hint
        prefix_hint_plt = try(dhcp6_iapd_list.value.prefix_hint_plt, null)
        prefix_hint_vlt = try(dhcp6_iapd_list.value.prefix_hint_vlt, null)
      }
    }

    dynamic "vrrp6" {
      for_each = { for vrrp in try(each.value.ipv6.vrrp6, []) : vrrp.vrid => vrrp }
      content {
        vrid                 = vrrp6.value.vrid
        vrgrp                = try(vrrp6.value.vrgrp, null)
        vrip6                = try(vrrp6.value.vrip6, null)
        priority             = try(vrrp6.value.priority, null)
        adv_interval         = try(vrrp6.value.adv_interval, null)
        start_time           = try(vrrp6.value.start_time, null)
        preempt              = try(vrrp6.value.preempt, null)
        accept_mode          = try(vrrp6.value.accept_mode, null)
        vrdst6               = try(vrrp6.value.vrdst6, null)
        vrdst_priority       = try(vrrp6.value.vrdst_priority, null)
        ignore_default_route = try(vrrp6.value.ignore_default_route, null)
        status               = try(vrrp6.value.status, null)
      }
    }
  } # /ipv6

}

resource "fortios_system_zone" "zones" {
  for_each   = { for name, zone in try(local.interface_yaml.zones, []) : name => zone }
  depends_on = [fortios_system_interface.interfaces, module.hardware_switch]
  name       = each.key
  intrazone  = try(each.value.intrazone, null)
  vdomparam  = each.value.vdom
  dynamic "interface" {
    for_each = { for interface in each.value.interfaces : interface => interface }
    content {
      interface_name = interface.value
    }
  }
}

module "hardware_switch" {
  for_each     = { for name, switch in try(local.interface_yaml.switches, []) : name => switch }
  source       = "github.com/sncs-uk/terraform-fortigate-hardware-switch?ref=v1.0.0"
  name         = each.key
  ports        = try(each.value.ports, null)
  vdom         = try(each.value.vdom, null)
  role         = try(each.value.role, null)
  ipv4         = try(each.value.ipv4, null)
  ipv6         = try(each.value.ipv6, null)
  allowaccess  = join(" ", try(each.value.allowaccess, []))
  allowaccess6 = join(" ", try(each.value.allowaccess, []))
}
