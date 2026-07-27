variable "interfaces" {
  description = "Interfaces to create"
  default = []

  type = list(object({
    name                        = optional(string)
    vdom                        = string
    vrf                         = optional(number)
    cli_conn_status             = optional(string)
    fortilink                   = optional(string)
    switch_controller_source_ip = optional(string)
    mode                        = optional(string)
    client_options = optional(list(object({
      id    = optional(number)
      code  = number
      type  = optional(string)
      value = optional(string)
      ip    = optional(string)
    })), [])
    distance                           = optional(number)
    priority                           = optional(number)
    dhcp_relay_interface_select_method = optional(string)
    dhcp_relay_interface               = optional(string)
    dhcp_relay_vrf_select              = optional(number)
    dhcp_broadcast_flag                = optional(string)
    dhcp_relay_service                 = optional(string)
    dhcp_relay_ip                      = optional(string)
    dhcp_relay_source_ip               = optional(string)
    dhcp_relay_circuit_id              = optional(string)
    dhcp_relay_link_selection          = optional(string)
    dhcp_relay_request_all_server      = optional(string)
    dhcp_relay_allow_no_end_option     = optional(string)
    dhcp_relay_type                    = optional(string)
    dhcp_smart_relay                   = optional(string)
    dhcp_relay_agent_option            = optional(string)
    dhcp_classless_route_addition      = optional(string)
    management_ip                      = optional(string)
    ip                                 = optional(string)
    allowaccess                        = optional(string)
    gwdetect                           = optional(string)
    ping_serv_status                   = optional(string)
    detectserver                       = optional(string)
    detectprotocol                     = optional(string)
    ha_priority                        = optional(string)
    fail_detect                        = optional(string)
    fail_detect_option                 = optional(string)
    fail_alert_method                  = optional(string)
    fail_action_on_extender            = optional(string)
    fail_alert_interfaces              = optional(list(string), [])
    dhcp_client_identifier             = optional(string)
    dhcp_renew_time                    = optional(string)
    dhcp_egress_cos                    = optional(string)
    arp_egress_cos                     = optional(string)
    ipunnumbered                       = optional(string)
    username                           = optional(string)
    pppoe_egress_cos                   = optional(string)
    pppoe_unnumbered_negotiate         = optional(string)
    password                           = optional(string)
    idle_timeout                       = optional(string)
    multilink                          = optional(string)
    mrru                               = optional(number)
    detected_peer_mtu                  = optional(number)
    disc_retry_timeout                 = optional(number)
    padt_retry_timeout                 = optional(number)
    service_name                       = optional(string)
    ac_name                            = optional(string)
    lcp_echo_interval                  = optional(number)
    lcp_max_echo_fails                 = optional(string)
    defaultgw                          = optional(string)
    dns_server_override                = optional(string)
    dns_server_protocol                = optional(string)
    auth_type                          = optional(string)
    pptp_client                        = optional(string)
    pptp_user                          = optional(string)
    pptp_password                      = optional(string)
    pptp_server_ip                     = optional(string)
    pptp_auth_type                     = optional(string)
    pptp_timeout                       = optional(number)
    arpforward                         = optional(string)
    ndiscforward                       = optional(string)
    broadcast_forward                  = optional(string)
    bfd                                = optional(string)
    bfd_desired_min_tx                 = optional(number)
    bfd_detect_mult                    = optional(number)
    bfd_required_min_rx                = optional(number)
    l2forward                          = optional(string)
    icmp_send_redirect                 = optional(string)
    icmp_accept_redirect               = optional(string)
    reachable_time                     = optional(number)
    vlanforward                        = optional(string)
    stpforward                         = optional(string)
    stpforward_mode                    = optional(string)
    ips_sniffer_mode                   = optional(string)
    ident_accept                       = optional(string)
    ipmac                              = optional(string)
    subst                              = optional(string)
    macaddr                            = optional(string)
    virtual_mac                        = optional(string)
    substitute_dst_mac                 = optional(string)
    speed                              = optional(string)
    status                             = optional(string)
    netbios_forward                    = optional(string)
    wins_ip                            = optional(string)
    type                               = optional(string)
    dedicated_to                       = optional(string)
    trust_ip_1                         = optional(string)
    trust_ip_2                         = optional(string)
    trust_ip_3                         = optional(string)
    trust_ip6_1                        = optional(string)
    trust_ip6_2                        = optional(string)
    trust_ip6_3                        = optional(string)
    mtu_override                       = optional(string)
    mtu                                = optional(number)
    ring_rx                            = optional(number)
    ring_tx                            = optional(number)
    wccp                               = optional(string)
    netflow_sampler                    = optional(string)
    netflow_sample_rate                = optional(number)
    netflow_sampler_id                 = optional(string)
    sflow_sampler                      = optional(string)
    drop_overlapped_fragment           = optional(string)
    drop_fragment                      = optional(string)
    scan_botnet_connections            = optional(string)
    src_check                          = optional(string)
    sample_rate                        = optional(number)
    polling_interval                   = optional(number)
    sample_direction                   = optional(string)
    explicit_web_proxy                 = optional(string)
    explicit_ftp_proxy                 = optional(string)
    proxy_captive_portal               = optional(string)
    tcp_mss                            = optional(number)
    mediatype                          = optional(string)
    inbandwidth                        = optional(number)
    outbandwidth                       = optional(number)
    egress_shaping_profile             = optional(string)
    ingress_shaping_profile            = optional(string)
    inbandwidth_source                 = optional(string)
    outbandwidth_source                = optional(string)
    disconnect_threshold               = optional(string)
    spillover_threshold                = optional(number)
    ingress_spillover_threshold        = optional(string)
    weight                             = optional(number)
    interface                          = optional(string)
    external                           = optional(string)
    vlan_protocol                      = optional(string)
    vlanid                             = optional(number)
    trunk                              = optional(string)
    forward_domain                     = optional(string)
    remote_ip                          = optional(string)
    member                             = optional(list(string), [])
    lacp_mode                          = optional(string)
    lacp_ha_secondary                  = optional(string)
    lacp_ha_slave                      = optional(string)
    system_id_type                     = optional(string)
    system_id                          = optional(string)
    lacp_speed                         = optional(string)
    min_links                          = optional(number)
    min_links_down                     = optional(number)
    algorithm                          = optional(string)
    link_up_delay                      = optional(string)
    aggregate_type                     = optional(string)
    priority_override                  = optional(string)
    aggregate                          = optional(string)
    redundant_interface                = optional(string)
    managed_device                     = optional(list(string), [])
    devindex                           = optional(string)
    vindex                             = optional(number)
    switch                             = optional(string)
    description                        = optional(string)
    alias                              = optional(string)
    security_mode                      = optional(string)
    captive_portal                     = optional(string)
    security_mac_auth_bypass           = optional(string)
    security_ip_auth_bypass            = optional(string)
    security_8021x_mode                = optional(string)
    security_8021x_master              = optional(string)
    security_8021x_dynamic_vlan_id     = optional(string)
    security_8021x_member_mode         = optional(string)
    security_external_web              = optional(string)
    security_external_logout           = optional(string)
    replacemsg_override_group          = optional(string)
    security_redirect_url              = optional(string)
    auth_cert                          = optional(string)
    auth_portal_addr                   = optional(string)
    security_exempt_list               = optional(string)
    security_groups                    = optional(list(string), [])
    ike_saml_server                    = optional(string)
    stp                                = optional(string)
    stp_ha_secondary                   = optional(string)
    stp_edge                           = optional(string)
    device_identification              = optional(string)
    exclude_signatures                 = optional(string)
    device_user_identification         = optional(string)
    device_identification_active_scan  = optional(string)
    device_access_list                 = optional(string)
    device_netscan                     = optional(string)
    lldp_reception                     = optional(string)
    lldp_transmission                  = optional(string)
    lldp_network_policy                = optional(string)
    fortiheartbeat                     = optional(string)
    broadcast_forticlient_discovery    = optional(string)
    endpoint_compliance                = optional(string)
    estimated_upstream_bandwidth       = optional(string)
    estimated_downstream_bandwidth     = optional(string)
    measured_upstream_bandwidth        = optional(number)
    measured_downstream_bandwidth      = optional(number)
    bandwidth_measure_time             = optional(string)
    monitor_bandwidth                  = optional(string)
    vrrp_virtual_mac                   = optional(string)
    vrrp = optional(list(object({
      vrid                 = optional(number)
      version              = optional(string)
      vrgrp                = optional(number)
      vrip                 = string
      priority             = optional(number)
      adv_interval         = optional(number)
      start_time           = optional(number)
      preempt              = optional(string)
      accept_mode          = optional(string)
      vrdst                = optional(string)
      vrdst_priority       = optional(number)
      ignore_default_route = optional(string)
      status               = optional(string)
      proxy_arp = optional(list(object({
        id = optional(number)
        ip = optional(string)
      })))
    })), [])
    phy_setting = optional(object({
      signal_ok_threshold       = optional(number)
      signal_ok_threshold_value = optional(number)
    }))
    role         = optional(string)
    snmp_index   = optional(string)
    secondary_ip = optional(string)
    secondaryip = optional(list(object({
      id               = optional(number)
      ip               = string
      secip_relay_ip   = optional(string)
      allowaccess      = optional(string)
      gwdetect         = optional(string)
      ping_serv_status = optional(string)
      detectserver     = optional(string)
      detectprotocol   = optional(string)
      ha_priority      = optional(string)
    })), [])
    preserve_session_route                     = optional(string)
    auto_auth_extension_device                 = optional(string)
    ap_discover                                = optional(string)
    telemetry_discover                         = optional(string)
    fortilink_stacking                         = optional(string)
    fortilink_neighbor_detect                  = optional(string)
    ip_managed_by_fortiipam                    = optional(string)
    managed_subnetwork_size                    = optional(string)
    ipam_conflicts                             = optional(string)
    fortilink_split_interface                  = optional(string)
    internal                                   = optional(string)
    fortilink_backup_link                      = optional(string)
    switch_controller_access_vlan              = optional(string)
    switch_controller_traffic_policy           = optional(string)
    switch_controller_rspan_mode               = optional(string)
    switch_controller_netflow_collect          = optional(string)
    switch_controller_mgmt_vlan                = optional(string)
    switch_controller_igmp_snooping            = optional(string)
    switch_controller_igmp_snooping_proxy      = optional(string)
    switch_controller_igmp_snooping_fast_leave = optional(string)
    switch_controller_dhcp_snooping            = optional(string)
    switch_controller_dhcp_snooping_verify_mac = optional(string)
    switch_controller_dhcp_snooping_option82   = optional(string)
    dhcp_snooping_server_list = optional(list(object({
      name      = string
      server_ip = string
    })), [])
    switch_controller_arp_inspection     = optional(string)
    switch_controller_learning_limit     = optional(number)
    switch_controller_nac                = optional(string)
    switch_controller_dynamic            = optional(string)
    switch_controller_feature            = optional(string)
    switch_controller_iot_scanning       = optional(string)
    switch_controller_offload            = optional(string)
    switch_controller_offload_ip         = optional(string)
    switch_controller_offload_gw         = optional(string)
    switch_controller_fortilink_settings = optional(string)
    swc_first_create                     = optional(string)
    color                                = optional(string)
    tagging = optional(list(object({
      name     = optional(string)
      category = optional(string)
      tags     = list(string)
    })), [])
    eap_supplicant      = optional(string)
    eap_method          = optional(string)
    eap_identity        = optional(string)
    eap_password        = optional(string)
    eap_ca_cert         = optional(string)
    eap_user_cert       = optional(string)
    np_qos_profile      = optional(string)
    port_mirroring      = optional(string)
    mirroring_direction = optional(string)
    mirroring_port      = optional(string)
    mirroring_filter = optional(list(object({
      filter_srcip    = optional(string)
      filter_dstip    = optional(string)
      filter_sport    = optional(string)
      filter_dport    = optional(string)
      filter_protocol = optional(string)
    })), [])
    default_purdue_level     = optional(string)
    forward_error_correction = optional(string)
    ipv6 = optional(object({
      ip6_mode = string
      client_options = optional(list(object({
        id    = optional(number)
        code  = number
        type  = optional(string)
        value = optional(string)
        ip6   = optional(string)
      })), [])
      nd_mode                 = optional(string)
      nd_cert                 = optional(string)
      nd_security_level       = optional(number)
      nd_timestamp_delta      = optional(number)
      nd_timestamp_fuzz       = optional(number)
      nd_cga_modifier         = optional(string)
      ip6_dns_server_override = optional(string)
      ip6_address             = optional(string)
      ip6_mgmt_address        = optional(string)
      ip6_extra_addr          = optional(list(string), [])
      ip6_link_local          = optional(string)
      ip6_allowaccess         = optional(string)
      ip6_send_adv            = optional(string)
      icmp6_send_redirect     = optional(string)
      ip6_manage_flag         = optional(string)
      ip6_other_flag          = optional(string)
      ip6_max_interval        = optional(number)
      ip6_min_interval        = optional(number)
      ip6_link_mtu            = optional(number)
      ra_send_mtu             = optional(number)
      ip6_reachable_time      = optional(number)
      ip6_retrans_time        = optional(number)
      ip6_default_life        = optional(number)
      ip6_hop_limit           = optional(number)
      ip6_adv_rio             = optional(string)
      ip6_route_pref          = optional(string)
      ip6_route_list = optional(list(object({
        route           = string
        route_pref      = optional(string)
        route_life_time = optional(number)
      })), [])
      autoconf                  = optional(string)
      unique_autoconf_addr      = optional(string)
      interface_identifier      = optional(string)
      ip6_prefix_mode           = optional(string)
      ip6_upstream_interface    = optional(string)
      ip6_delegated_prefix_iaid = optional(string)
      ip6_subnet                = optional(string)
      ip6_prefix_list = optional(list(object({
        prefix              = string
        autonomous_flag     = optional(string)
        onlink_flag         = optional(string)
        valid_life_time     = optional(number)
        preferred_life_time = optional(number)
        rdnss               = optional(string)
        dnssl               = optional(list(string))
      })), [])
      ip6_rdnss_list = optional(list(object({
        rdnss           = string
        rdnss_life_time = optional(number)
      })), [])
      ip6_dnssl_list = optional(list(object({
        domain          = string
        dnssl_life_time = optional(number)
      })), [])
      ip6_delegated_prefix_list = optional(list(object({
        prefix_id             = optional(number)
        upstream_interface    = optional(string)
        delegated_prefix_iaid = optional(string)
        autonomous_flag       = optional(string)
        onlink_flag           = optional(string)
        subnet                = optional(string)
        rdnss_service         = optional(string)
        rdnss                 = optional(string)
        dnssl_service         = optional(string)
      })), [])
      dhcp6_egress_cos             = optional(string)
      dhcp6_relay_service          = optional(string)
      dhcp6_relay_type             = optional(string)
      dhcp6_relay_source_interface = optional(string)
      dhcp6_relay_ip               = optional(string)
      dhcp6_relay_source_ip        = optional(string)
      dhcp6_relay_interface_id     = optional(string)
      dhcp6_client_options         = optional(string)
      dhcp6_prefix_delegation      = optional(string)
      dhcp6_information_request    = optional(string)
      dhcp6_iapd_list = optional(list(object({
        iaid            = optional(string)
        prefix_hint     = optional(string)
        prefix_hint_plt = optional(string)
        prefix_hint_vlt = optional(string)
      })), [])
      dhcp6_prefix_hint     = optional(string)
      dhcp6_prefix_hint_plt = optional(number)
      dhcp6_prefix_hint_vlt = optional(number)
      vrrp_virtual_mac6     = optional(string)
      vrip6_link_local      = optional(string)
      vrrp6 = optional(list(object({
        vrid                 = optional(number)
        vrgrp                = optional(number)
        vrip6                = string
        priority             = optional(number)
        adv_interval         = optional(number)
        start_time           = optional(number)
        preempt              = optional(string)
        accept_mode          = optional(string)
        vrdst6               = optional(string)
        vrdst_priority       = optional(number)
        ignore_default_route = optional(string)
        status               = optional(string)
      })), [])
    }))
    autogenerated         = optional(string)
    dynamic_sort_subtable = optional(string, "natural")
    get_all_tables        = optional(string)
    vdomparam             = optional(string)
    update_if_exist       = optional(string)
  }))

  validation {
    condition = alltrue([for o in var.interfaces : o.fortilink == null || contains(["enable", "disable"], o.fortilink)])
    error_message = "Parameter `fortilink` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_source_ip == null || contains(["outbound", "fixed"], o.switch_controller_source_ip)])
    error_message = "Parameter `switch_controller_source_ip` must be one of `outbound`, or `fixed`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.mode == null || contains(["static", "dhcp", "pppoe"], o.mode)])
    error_message = "Parameter `mode` must be one of `static`, `dhcp`, or `pppoe`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.distance == null || o.distance >= 0])
    error_message = "Parameter `distance` must be zero or greater"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.priority == null || o.priority >= 0])
    error_message = "Parameter `priority` must be zero or greater"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_relay_interface_select_method == null || contains(["auto", "sdwan", "speficy"], o.dhcp_relay_interface_select_method)])
    error_message = "Parameter `dhcp_relay_interface_select_method` must be one of `auto`, `sdwan`, or `speficy`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_relay_service == null || contains(["enable", "disable"], o.dhcp_relay_service)])
    error_message = "Parameter `dhcp_relay_service` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_relay_request_all_server == null || contains(["enable", "disable"], o.dhcp_relay_request_all_server)])
    error_message = "Parameter `dhcp_relay_request_all_server` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_relay_allow_no_end_option == null || contains(["enable", "disable"], o.dhcp_relay_allow_no_end_option)])
    error_message = "Parameter `dhcp_relay_allow_no_end_option` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_relay_type == null || contains(["regular", "ipsec"], o.dhcp_relay_type)])
    error_message = "Parameter `dhcp_relay_type` must be one of `regular`, or `ipsec`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_smart_relay == null || contains(["enable", "disable"], o.dhcp_smart_relay)])
    error_message = "Parameter `dhcp_smart_relay` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_relay_agent_option == null || contains(["enable", "disable"], o.dhcp_relay_agent_option)])
    error_message = "Parameter `dhcp_relay_agent_option` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_classless_route_addition == null || contains(["enable", "disable"], o.dhcp_classless_route_addition)])
    error_message = "Parameter `dhcp_classless_route_addition` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.gwdetect == null || contains(["enable", "disable"], o.gwdetect)])
    error_message = "Parameter `gwdetect` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.detectprotocol == null || contains(["ping", "tcp-echo", "udp-echo"], o.detectprotocol)])
    error_message = "Parameter `detectprotocol` must be one of `ping`, `tcp-echo`, or `udp-echo`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fail_detect == null || contains(["enable", "disable"], o.fail_detect)])
    error_message = "Parameter `fail_detect` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fail_detect_option == null || contains(["detectserver", "link-down"], o.fail_detect_option)])
    error_message = "Parameter `fail_detect_option` must be one of `detectserver`, or `link-down`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fail_alert_method == null || contains(["link-failed-signal", "link-down"], o.fail_alert_method)])
    error_message = "Parameter `fail_alert_method` must be one of `link-failed-signal`, or `link-down`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fail_action_on_extender == null || contains(["soft-restart", "hard-restart", "reboot"], o.fail_action_on_extender)])
    error_message = "Parameter `fail_action_on_extender` must be one of `soft-restart`, `hard-restart`, or `reboot`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dhcp_egress_cos == null || contains(["cos0", "cos1", "cos2", "cos3", "cos4", "cos5", "cos6", "cos7"], o.dhcp_egress_cos)])
    error_message = "Parameter `dhcp_egress_cos` must be one of `cos0`, `cos1`, `cos2`, `cos3`, `cos4`, `cos5`, `cos6`, or `cos7`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.arp_egress_cos == null || contains(["cos0", "cos1", "cos2", "cos3", "cos4", "cos5", "cos6", "cos7"], o.arp_egress_cos)])
    error_message = "Parameter `arp_egress_cos` must be one of `cos0`, `cos1`, `cos2`, `cos3`, `cos4`, `cos5`, `cos6`, or `cos7`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.pppoe_egress_cos == null || contains(["cos0", "cos1", "cos2", "cos3", "cos4", "cos5", "cos6", "cos7"], o.pppoe_egress_cos)])
    error_message = "Parameter `pppoe_egress_cos` must be one of `cos0`, `cos1`, `cos2`, `cos3`, `cos4`, `cos5`, `cos6`, or `cos7`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.pppoe_unnumbered_negotiate == null || contains(["enable", "disable"], o.pppoe_unnumbered_negotiate)])
    error_message = "Parameter `pppoe_unnumbered_negotiate` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.multilink == null || contains(["enable", "disable"], o.multilink)])
    error_message = "Parameter `multilink` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.mrru == null || (o.mrru > 295 && o.mrru < 65536)])
    error_message = "Parameter `mrru` must be in the range 296-65535"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.detected_peer_mtu == null || (o.detected_peer_mtu > -1 && o.detected_peer_mtu < 4294967296)])
    error_message = "Parameter `detected_peer_mtu` must be in the range 0-4294967295"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.disc_retry_timeout == null || o.disc_retry_timeout > -1])
    error_message = "Parameter `disc_retry_timeout` must be zero or greater"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.padt_retry_timeout == null || o.padt_retry_timeout > 0])
    error_message = "Parameter `padt_retry_timeout` must be greater than zero"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lcp_echo_interval == null || o.lcp_echo_interval > 0])
    error_message = "Parameter `lcp_echo_interval` must be greater than zero"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lcp_max_echo_fails == null || o.lcp_max_echo_fails > 0])
    error_message = "Parameter `lcp_max_echo_fails` must be greater than zero"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.defaultgw == null || contains(["enable", "disable"], o.defaultgw)])
    error_message = "Parameter `defaultgw` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dns_server_override == null || contains(["enable", "disable"], o.dns_server_override)])
    error_message = "Parameter `dns_server_override` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dns_server_protocol == null || contains(["cleartext", "dot", "doh"], o.dns_server_protocol)])
    error_message = "Parameter `dns_server_protocol` must be one of `cleartext`, `dot`, or `doh`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.auth_type == null || contains(["auto", "pap", "chap", "mschapv1", "mschapv2"], o.auth_type)])
    error_message = "Parameter `auth_type` must be one of `auto`, `pap`, `chap`, `mschapv1`, or `mschapv2`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.pptp_client == null || contains(["enable", "disable"], o.pptp_client)])
    error_message = "Parameter `pptp_client` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.pptp_auth_type == null || contains(["auto", "pap", "chap", "mschapv1", "mschapv2"], o.pptp_auth_type)])
    error_message = "Parameter `pptp_auth_type` must be one of `auto`, `pap`, `chap`, `mschapv1`, or `mschapv2`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.pptp_timeout == null || o.pptp_timeout > 0])
    error_message = "Parameter `pptp_timeout` must be greater than zero"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.arpforward == null || contains(["enable", "disable"], o.arpforward)])
    error_message = "Parameter `arpforward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ndiscforward == null || contains(["enable", "disable"], o.ndiscforward)])
    error_message = "Parameter `ndiscforward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.broadcast_forward == null || contains(["enable", "disable"], o.broadcast_forward)])
    error_message = "Parameter `broadcast_forward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.bfd == null || contains(["enable", "disable"], o.bfd)])
    error_message = "Parameter `bfd` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.bfd_desired_min_tx == null || o.bfd_desired_min_tx > 0])
    error_message = "Parameter `bfd_desired_min_tx` must be greater than zero"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.bfd_required_min_rx == null || o.bfd_required_min_rx > 0])
    error_message = "Parameter `bfd_required_min_rx` must be greater than zero"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.l2forward == null || contains(["enable", "disable"], o.l2forward)])
    error_message = "Parameter `l2forward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.icmp_send_redirect == null || contains(["enable", "disable"], o.icmp_send_redirect)])
    error_message = "Parameter `icmp_send_redirect` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.icmp_accept_redirect == null || contains(["enable", "disable"], o.icmp_accept_redirect)])
    error_message = "Parameter `icmp_accept_redirect` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.reachable_time == null || (o.reachable_time >= 30000 && o.reachable_time <= 3600000)])
    error_message = "Parameter `reachable_time` must be in the range 30000-3600000"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.vlanforward == null || contains(["enable", "disable"], o.vlanforward)])
    error_message = "Parameter `vlanforward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.stpforward == null || contains(["enable", "disable"], o.stpforward)])
    error_message = "Parameter `stpforward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.stpforward_mode == null || contains(["rpl-all-ext-id", "rpl-bridge-ext-id", "rpl-nothing"], o.stpforward_mode)])
    error_message = "Parameter `stpforward_mode` must be one of `rpl-all-ext-id`, `rpl-bridge-ext-id`, or `rpl-nothing`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ips_sniffer_mode == null || contains(["enable", "disable"], o.ips_sniffer_mode)])
    error_message = "Parameter `ips_sniffer_mode` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ident_accept == null || contains(["enable", "disable"], o.ident_accept)])
    error_message = "Parameter `ident_accept` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ipmac == null || contains(["enable", "disable"], o.ipmac)])
    error_message = "Parameter `ipmac` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.subst == null || contains(["enable", "disable"], o.subst)])
    error_message = "Parameter `subst` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.status == null || contains(["up", "down"], o.status)])
    error_message = "Parameter `status` must be one of `up`, or `down`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.netbios_forward == null || contains(["enable", "disable"], o.netbios_forward)])
    error_message = "Parameter `netbios_forward` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.dedicated_to == null || contains(["none", "management"], o.dedicated_to)])
    error_message = "Parameter `dedicated_to` must be one of `none`, or `management`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.mtu_override == null || contains(["enable", "disable"], o.mtu_override)])
    error_message = "Parameter `mtu_override` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.wccp == null || contains(["enable", "disable"], o.wccp)])
    error_message = "Parameter `wccp` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.netflow_sampler == null || contains(["disable", "tx", "rx", "both"], o.netflow_sampler)])
    error_message = "Parameter `netflow_sampler` must be one of `disable`, `tx`, `rx`, or `both`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.netflow_sample_rate == null || (o.netflow_sample_rate >= 1 && o.netflow_sample_rate <= 65535)])
    error_message = "Parameter `netflow_sample_rate` must be in the range 1-65535"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.sflow_sampler == null || contains(["enable", "disable"], o.sflow_sampler)])
    error_message = "Parameter `sflow_sampler` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.drop_overlapped_fragment == null || contains(["enable", "disable"], o.drop_overlapped_fragment)])
    error_message = "Parameter `drop_overlapped_fragment` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.drop_fragment == null || contains(["enable", "disable"], o.drop_fragment)])
    error_message = "Parameter `drop_fragment` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.scan_botnet_connections == null || contains(["disable", "block", "monitor"], o.scan_botnet_connections)])
    error_message = "Parameter `scan_botnet_connections` must be one of `disable`, `block`, or `monitor`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.src_check == null || contains(["enable", "disable"], o.src_check)])
    error_message = "Parameter `src_check` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.sample_rate == null || (o.sample_rate >= 10 && o.sample_rate <= 99999)])
    error_message = "Parameter `sample_rate` must be in the range 10-99999"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.polling_interval == null || (o.polling_interval >= 1 && o.polling_interval <= 255)])
    error_message = "Parameter `polling_interval` must be in the range 1-255"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.sample_direction == null || contains(["tx", "rx", "both"], o.sample_direction)])
    error_message = "Parameter `sample_direction` must be one of `tx`, `rx`, or `both`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.explicit_web_proxy == null || contains(["enable", "disable"], o.explicit_web_proxy)])
    error_message = "Parameter `explicit_web_proxy` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.explicit_ftp_proxy == null || contains(["enable", "disable"], o.explicit_ftp_proxy)])
    error_message = "Parameter `explicit_ftp_proxy` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.proxy_captive_portal == null || contains(["enable", "disable"], o.proxy_captive_portal)])
    error_message = "Parameter `proxy_captive_portal` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.inbandwidth_source == null || contains(["default", "measured"], o.inbandwidth_source)])
    error_message = "Parameter `inbandwidth_source` must be one of `default`, or `measured`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.spillover_threshold == null || (o.spillover_threshold >= 0 && o.spillover_threshold <= 16776000)])
    error_message = "Parameter `spillover_threshold` must be in the range 0-16776000"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ingress_spillover_threshold == null || (o.ingress_spillover_threshold >= 0 && o.ingress_spillover_threshold <= 16776000)])
    error_message = "Parameter `ingress_spillover_threshold` must be in the range 0-16776000"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.external == null || contains(["enable", "disable"], o.external)])
    error_message = "Parameter `external` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.vlan_protocol == null || contains(["8021q", "8021ad"], o.vlan_protocol)])
    error_message = "Parameter `vlan_protocol` must be one of `8021q`, or `8021ad`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.vlanid == null || (o.vlanid >= 1 && o.vlanid <= 4094)])
    error_message = "Parameter `vlanid` must be in the range 1-4094"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.trunk == null || contains(["enable", "disable"], o.trunk)])
    error_message = "Parameter `trunk` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lacp_mode == null || contains(["static", "passive", "active"], o.lacp_mode)])
    error_message = "Parameter `lacp_mode` must be one of `static`, `passive`, or `active`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lacp_ha_secondary == null || contains(["enable", "disable"], o.lacp_ha_secondary)])
    error_message = "Parameter `lacp_ha_secondary` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lacp_ha_slave == null || contains(["enable", "disable"], o.lacp_ha_slave)])
    error_message = "Parameter `lacp_ha_slave` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.system_id_type == null || contains(["auto", "user"], o.system_id_type)])
    error_message = "Parameter `system_id_type` must be one of `auto`, or `user`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lacp_speed == null || contains(["slow", "fast"], o.lacp_speed)])
    error_message = "Parameter `lacp_speed` must be one of `slow`, or `fast`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.min_links_down == null || contains(["operational", "administrative"], o.min_links_down)])
    error_message = "Parameter `min_links_down` must be one of `operational`, or `administrative`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.aggregate_type == null || contains(["physical", "vxlan"], o.aggregate_type)])
    error_message = "Parameter `aggregate_type` must be one of `physical`, or `vxlan`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.priority_override == null || contains(["enable", "disable"], o.priority_override)])
    error_message = "Parameter `priority_override` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.security_mode == null || contains(["none", "captive-portal", "802.1X"], o.security_mode)])
    error_message = "Parameter `security_mode` must be one of `none`, `captive-portal`, or `802.1X`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.security_mac_auth_bypass == null || contains(["mac-auth-only", "enable", "disable"], o.security_mac_auth_bypass)])
    error_message = "Parameter `security_mac_auth_bypass` must be one of `mac-auth-only`, `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.security_ip_auth_bypass == null || contains(["enable", "disable"], o.security_ip_auth_bypass)])
    error_message = "Parameter `security_ip_auth_bypass` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.security_8021x_mode == null || contains(["default", "dynamic-vlan", "fallback", "slave"], o.security_8021x_mode)])
    error_message = "Parameter `security_8021x_mode` must be one of `default`, `dynamic-vlan`, `fallback`, or `slave`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.security_8021x_member_mode == null || contains(["switch", "disable"], o.security_8021x_member_mode)])
    error_message = "Parameter `security_8021x_member_mode` must be one of `switch`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.stp == null || contains(["enable", "disable"], o.stp)])
    error_message = "Parameter `stp` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.stp_ha_secondary == null || contains(["disable", "enable", "priority_adjust"], o.stp_ha_secondary)])
    error_message = "Parameter `stp_ha_secondary` must be one of `disable`, `enable`, or `priority_adjust`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.stp_edge == null || contains(["enable", "disable"], o.stp_edge)])
    error_message = "Parameter `stp_edge` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.device_identification == null || contains(["enable", "disable"], o.device_identification)])
    error_message = "Parameter `device_identification` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.exclude_signatures == null || contains(["iot", "ot"], o.exclude_signatures)])
    error_message = "Parameter `exclude_signatures` must be one of `iot`, or `ot`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.device_user_identification == null || contains(["enable", "disable"], o.device_user_identification)])
    error_message = "Parameter `device_user_identification` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.device_identification_active_scan == null || contains(["enable", "disable"], o.device_identification_active_scan)])
    error_message = "Parameter `device_identification_active_scan` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.device_netscan == null || contains(["enable", "disable"], o.device_netscan)])
    error_message = "Parameter `device_netscan` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lldp_reception == null || contains(["enable", "disable", "vdom"], o.lldp_reception)])
    error_message = "Parameter `lldp_reception` must be one of `enable`, `disable`, or `vdom`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.lldp_transmission == null || contains(["enable", "disable", "vdom"], o.lldp_transmission)])
    error_message = "Parameter `lldp_transmission` must be one of `enable`, `disable`, or `vdom`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fortiheartbeat == null || contains(["enable", "disable"], o.fortiheartbeat)])
    error_message = "Parameter `fortiheartbeat` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.broadcast_forticlient_discovery == null || contains(["enable", "disable"], o.broadcast_forticlient_discovery)])
    error_message = "Parameter `broadcast_forticlient_discovery` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.endpoint_compliance == null || contains(["enable", "disable"], o.endpoint_compliance)])
    error_message = "Parameter `endpoint_compliance` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.monitor_bandwidth == null || contains(["enable", "disable"], o.monitor_bandwidth)])
    error_message = "Parameter `monitor_bandwidth` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.vrrp_virtual_mac == null || contains(["enable", "disable"], o.vrrp_virtual_mac)])
    error_message = "Parameter `vrrp_virtual_mac` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.role == null || contains(["lan", "wan", "dmz", "undefined"], o.role)])
    error_message = "Parameter `role` must be one of `lan`, `wan`, `dmz`, or `undefined`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.secondary_ip == null || contains(["enable", "disable"], o.secondary_ip)])
    error_message = "Parameter `secondary_ip` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.preserve_session_route == null || contains(["enable", "disable"], o.preserve_session_route)])
    error_message = "Parameter `preserve_session_route` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.auto_auth_extension_device == null || contains(["enable", "disable"], o.auto_auth_extension_device)])
    error_message = "Parameter `auto_auth_extension_device` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ap_discover == null || contains(["enable", "disable"], o.ap_discover)])
    error_message = "Parameter `ap_discover` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.telemetry_discover == null || contains(["enable", "disable"], o.telemetry_discover)])
    error_message = "Parameter `telemetry_discover` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fortilink_stacking == null || contains(["enable", "disable"], o.fortilink_stacking)])
    error_message = "Parameter `fortilink_stacking` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fortilink_neighbor_detect == null || contains(["lldp", "fortilink"], o.fortilink_neighbor_detect)])
    error_message = "Parameter `fortilink_neighbor_detect` must be one of `lldp`, or `fortilink`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.ipam_conflicts == null || contains(["enable", "disable"], o.ipam_conflicts)])
    error_message = "Parameter `ipam_conflicts` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.fortilink_split_interface == null || contains(["enable", "disable"], o.fortilink_split_interface)])
    error_message = "Parameter `fortilink_split_interface` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_access_vlan == null || contains(["enable", "disable"], o.switch_controller_access_vlan)])
    error_message = "Parameter `switch_controller_access_vlan` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_netflow_collect == null || contains(["enable", "disable"], o.switch_controller_netflow_collect)])
    error_message = "Parameter `switch_controller_netflow_collect` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_igmp_snooping == null || contains(["enable", "disable"], o.switch_controller_igmp_snooping)])
    error_message = "Parameter `switch_controller_igmp_snooping` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_igmp_snooping_proxy == null || contains(["enable", "disable"], o.switch_controller_igmp_snooping_proxy)])
    error_message = "Parameter `switch_controller_igmp_snooping_proxy` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_dhcp_snooping == null || contains(["enable", "disable"], o.switch_controller_dhcp_snooping)])
    error_message = "Parameter `switch_controller_dhcp_snooping` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_dhcp_snooping_verify_mac == null || contains(["enable", "disable"], o.switch_controller_dhcp_snooping_verify_mac)])
    error_message = "Parameter `switch_controller_dhcp_snooping_verify_mac` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_dhcp_snooping_option82 == null || contains(["enable", "disable"], o.switch_controller_dhcp_snooping_option82)])
    error_message = "Parameter `switch_controller_dhcp_snooping_option82` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_learning_limit == null || (o.switch_controller_learning_limit >= 1 && o.switch_controller_learning_limit <= 128)])
    error_message = "Parameter `switch_controller_learning_limit` must be in the range 1-128"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_dhcp_snooping_option82 == null || contains(["enable", "disable"], o.switch_controller_dhcp_snooping_option82)])
    error_message = "Parameter `switch_controller_dhcp_snooping_option82` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_iot_scanning == null || contains(["enable", "disable"], o.switch_controller_iot_scanning)])
    error_message = "Parameter `switch_controller_iot_scanning` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_offload == null || contains(["enable", "disable"], o.switch_controller_offload)])
    error_message = "Parameter `switch_controller_offload` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.switch_controller_offload_gw == null || contains(["enable", "disable"], o.switch_controller_offload_gw)])
    error_message = "Parameter `switch_controller_offload_gw` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.eap_supplicant == null || contains(["enable", "disable"], o.eap_supplicant)])
    error_message = "Parameter `eap_supplicant` must be one of `enable`, or `disable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.eap_method == null || contains(["tls", "peap"], o.eap_method)])
    error_message = "Parameter `eap_method` must be one of `tls`, or `peap`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.port_mirroring == null || contains(["disable", "enable"], o.port_mirroring)])
    error_message = "Parameter `port_mirroring` must be one of `disable`, or `enable`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.mirroring_direction == null || contains(["rx"], o.mirroring_direction)])
    error_message = "Parameter `mirroring_direction` must be one of `rx`"
  }
  validation {
    condition = alltrue([for o in var.interfaces : o.default_purdue_level == null || contains(["1", "1.5", "2", "2.5", "3", "3.5", "4", "5", "5.5"], o.default_purdue_level)])
    error_message = "Parameter `default_purdue_level` must be one of `1`, `1.5`, `2`, `2.5`, `3`, `3.5`, `4`, `5`, or `5.5`"
  }

  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.client_options : p.type == null || contains(["hex", "string", "ip", "fqdn"], p.type)]]))
    error_message = "Parameter `client_options.type` must be one of `hex`, `string`, `ip`, or `fqdn`"
  }

  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.vrid == null || (p.vrid >= 1 && p.vrid <= 255)]]))
    error_message = "Parameter `vrrp.vrid` must be in the range 1-255"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.version == null || contains(["2", "3"], p.version)]]))
    error_message = "Parameter `vrrp.version` must be one of `2`, or `3`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.vrgrp == null || (p.vrgrp >= 1 && p.vrgrp <= 65535)]]))
    error_message = "Parameter `vrrp.vrgrp` must be in the range 1-65535"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.priority == null || (p.priority >= 1 && p.priority <= 255)]]))
    error_message = "Parameter `vrrp.priority` must be in the range 1-255"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.start_time == null || (p.start_time >= 1 && p.start_time <= 255)]]))
    error_message = "Parameter `vrrp.start_time` must be in the range 1-255"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.preempt == null || contains(["enable", "disable"], p.preempt)]]))
    error_message = "Parameter `vrrp.preempt` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.accept_mode == null || contains(["enable", "disable"], p.accept_mode)]]))
    error_message = "Parameter `vrrp.accept_mode` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.vrdst_priority == null || (p.vrdst_priority >= 0 && p.vrdst_priority <= 254)]]))
    error_message = "Parameter `vrrp.vrdst_priority` must be in the range 0-254"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.ignore_default_route == null || contains(["enable", "disable"], p.ignore_default_route)]]))
    error_message = "Parameter `vrrp.ignore_default_route` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.vrrp : p.status == null || contains(["enable", "disable"], p.status)]]))
    error_message = "Parameter `vrrp.status` must be one of `enable`, or `disable`"
  }

  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.phy_setting == null || (o.phy_setting.signal_ok_threshold == null || (o.phy_setting.signal_ok_threshold >= 0 && o.phy_setting.signal_ok_threshold <= 12)))]))
    error_message = "Parameter `phy_setting.signal_ok_threshold` must be in the range 0-12"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.phy_setting == null || (o.phy_setting.signal_ok_threshold_value == null || (o.phy_setting.signal_ok_threshold_value >= 0 && o.phy_setting.signal_ok_threshold_value <= 12)))]))
    error_message = "Parameter `phy_setting.signal_ok_threshold_value` must be in the range 0-12"
  }

  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.secondaryip : p.gwdetect == null || contains(["enable", "disable"], p.gwdetect)]]))
    error_message = "Parameter `secondaryip.gwdetect` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : [for p in o.secondaryip : p.detectprotocol == null || contains(["ping", "tcp-echo", "udp-echo"], p.detectprotocol)]]))
    error_message = "Parameter `secondaryip.detectprotocol` must be one of `ping`, `tcp-echo`, or `udp-echo`"
  }

  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_mode == null || contains(["static", "dhcp", "pppoe", "delegated"], o.ipv6.ip6_mode)))]))
    error_message = "Parameter `ipv6.ip6_mode` must be one of `static`, `dhcp`, `pppoe`, or `delegated`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.nd_mode == null || contains(["basic", "SEND-compatible"], o.ipv6.nd_mode)))]))
    error_message = "Parameter `ipv6.nd_mode` must be one of `basic`, or `SEND-compatible`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.nd_security_level == null || (o.ipv6.nd_security_level >= 0 && o.ipv6.nd_security_level <= 7)))]))
    error_message = "Parameter `ipv6.nd_security_level` must be in the range 0-7"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.nd_timestamp_delta == null || (o.ipv6.nd_timestamp_delta >= 0 && o.ipv6.nd_timestamp_delta <= 3600)))]))
    error_message = "Parameter `ipv6.nd_timestamp_delta` must be in the range 0-3600"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.nd_timestamp_fuzz == null || (o.ipv6.nd_timestamp_fuzz >= 1 && o.ipv6.nd_timestamp_fuzz <= 60)))]))
    error_message = "Parameter `ipv6.nd_timestamp_fuzz` must be in the range 1-60"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_dns_server_override == null || contains(["enable", "disable"], o.ipv6.ip6_dns_server_override)))]))
    error_message = "Parameter `ipv6.ip6_dns_server_override` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_send_adv == null || contains(["enable", "disable"], o.ipv6.ip6_send_adv)))]))
    error_message = "Parameter `ipv6.ip6_send_adv` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.icmp6_send_redirect == null || contains(["enable", "disable"], o.ipv6.icmp6_send_redirect)))]))
    error_message = "Parameter `ipv6.icmp6_send_redirect` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_manage_flag == null || contains(["enable", "disable"], o.ipv6.ip6_manage_flag)))]))
    error_message = "Parameter `ipv6.ip6_manage_flag` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_other_flag == null || contains(["enable", "disable"], o.ipv6.ip6_other_flag)))]))
    error_message = "Parameter `ipv6.ip6_other_flag` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_max_interval == null || (o.ipv6.ip6_max_interval >= 4 && o.ipv6.ip6_max_interval <= 1800)))]))
    error_message = "Parameter `ipv6.ip6_max_interval` must be in the range 4-1800"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_min_interval == null || (o.ipv6.ip6_min_interval >= 4 && o.ipv6.ip6_min_interval <= 1800)))]))
    error_message = "Parameter `ipv6.ip6_min_interval` must be in the range 4-1800"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ra_send_mtu == null || contains(["enable", "disable"], o.ipv6.ra_send_mtu)))]))
    error_message = "Parameter `ipv6.ra_send_mtu` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_adv_rio == null || contains(["enable", "disable"], o.ipv6.ip6_adv_rio)))]))
    error_message = "Parameter `ipv6.ip6_adv_rio` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_route_pref == null || contains(["medium", "high", "low"], o.ipv6.ip6_route_pref)))]))
    error_message = "Parameter `ipv6.ip6_route_pref` must be one of `medium`, `high`, or `low`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.autoconf == null || contains(["enable", "disable"], o.ipv6.autoconf)))]))
    error_message = "Parameter `ipv6.autoconf` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.unique_autoconf_addr == null || contains(["enable", "disable"], o.ipv6.unique_autoconf_addr)))]))
    error_message = "Parameter `ipv6.unique_autoconf_addr` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.ip6_prefix_mode == null || contains(["dhcp6", "ra"], o.ipv6.ip6_prefix_mode)))]))
    error_message = "Parameter `ipv6.ip6_prefix_mode` must be one of `dhcp6`, or `ra`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_egress_cos == null || contains(["cos0", "cos1", "cos2", "cos3", "cos4", "cos5", "cos6", "cos7"], o.ipv6.dhcp6_egress_cos)))]))
    error_message = "Parameter `ipv6.dhcp6_egress_cos` must be one of `cos0`, `cos1`, `cos2`, `cos3`, `cos4`, `cos5`, `cos6`, or `cos7`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_relay_service == null || contains(["enable", "disable"], o.ipv6.dhcp6_relay_service)))]))
    error_message = "Parameter `ipv6.dhcp6_relay_service` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_relay_type == null || contains(["regular"], o.ipv6.dhcp6_relay_type)))]))
    error_message = "Parameter `ipv6.dhcp6_relay_type` must be one of `regular`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_relay_source_interface == null || contains(["enable", "disable"], o.ipv6.dhcp6_relay_source_interface)))]))
    error_message = "Parameter `ipv6.dhcp6_relay_source_interface` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_client_options == null || contains(["rapid", "iapd", "iana"], o.ipv6.dhcp6_client_options)))]))
    error_message = "Parameter `ipv6.dhcp6_client_options` must be one of `rapid`, `iapd`, or `iana`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_prefix_delegation == null || contains(["enable", "disable"], o.ipv6.dhcp6_prefix_delegation)))]))
    error_message = "Parameter `ipv6.dhcp6_prefix_delegation` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.dhcp6_information_request == null || contains(["enable", "disable"], o.ipv6.dhcp6_information_request)))]))
    error_message = "Parameter `ipv6.dhcp6_information_request` must be one of `enable`, or `disable`"
  }
  validation {
    condition     = alltrue(flatten([for o in var.interfaces : (o.ipv6 == null || (o.ipv6.vrrp_virtual_mac6 == null || contains(["enable", "disable"], o.ipv6.vrrp_virtual_mac6)))]))
    error_message = "Parameter `ipv6.vrrp_virtual_mac6` must be one of `enable`, or `disable`"
  }
}
variable "zones" {
  default = []
  description = "Zones to create"

  type = list(object({
    uuid                 = optional(string)
    fabric_object        = optional(string)
    fabric_force_sync    = optional(string)
    fabric_object_source = optional(string)
    name                 = optional(string)
    tagging = optional(list(object({
      name     = optional(string)
      category = optional(string)
      tags     = optional(list(string), [])
    })), [])
    description           = optional(string)
    intrazone             = optional(string)
    interface             = optional(list(string), [])
    dynamic_sort_subtable = optional(string, "natural")
    get_all_tables        = optional(string)
    vdomparam             = optional(string)
    update_if_exist       = optional(string)
  }))
}
