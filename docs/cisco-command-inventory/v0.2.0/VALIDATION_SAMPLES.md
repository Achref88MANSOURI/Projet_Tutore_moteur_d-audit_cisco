# Vérification stratifiée — sélections fixes 0.2.0

Les attentes sont écrites séparément des règles de classification dans SAMPLE_EXPECTATIONS.json. Ce contrôle utilise un validateur distinct et des preuves Cisco sélectionnées ; il ne constitue ni une relecture par un autre humain ni une validation exhaustive des milliers d'entrées.

L'échantillon couvre les quatre statuts, les frontières entre exploitation et configuration, les variantes conditionnelles, les familles de plateformes disposant de preuves et les principales technologies. L'absence de fixture 8000V et de startup-config est une lacune, pas une strate faussement validée.

## exec-wrapper — administration / operational boundary

Attendu : `excluded`. Résultat : PASS. The do definition explicitly executes EXEC commands from configuration modes.

- `cmd-31d819eb45521a0262cd` : `do command` ; modes : All configuration modes.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/Cisco_IOS_Configuration_Fundamentals_Command_Reference/D_through_E.html#wp1463793793).

## switch-only-1712 — switch-only / IOS-XE 17.12 document

Attendu : `excluded`. Résultat : PASS. App Hosting enable is explicitly supported only on Catalyst 9410 in this reference edition.

- `cmd-b199c6e9c8bfee02812a` : `enable` ; modes : Interface configuration (config-if).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/command/1718/b_1718_programmability_cr/m_17_18_prog_cr.html#wp9098318220).

## switch-only-1718 — switch-only / IOS-XE 17.18 document

Attendu : `excluded`. Résultat : PASS. Keep edition scope separate even when wording is identical.

- `cmd-705bd633b2ab93bc81b1` : `enable` ; modes : Interface configuration (config-if).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/command/1712/b_1712_programmability_cr/programmability.html#wp9098318220).

## issu-not-exec — HA / false operational-prefix exclusion

Attendu : `uncertain`. Résultat : PASS. The reference puts configure issu set rollback timer in global configuration; the configure prefix does not establish an exclusion.

- `cmd-61d3168bf3d9389d7746` : `configure issu set rollback timer seconds` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ha/command/ha-cr-book/ha-active-through-issu-set-rollback-timer.html#wp1199183778).

## webex-spa — ASR 1000 / hardware condition

Attendu : `documented_config`. Résultat : PASS. The command introduction identifies ASR 1000 and Cisco WebEx Node SPA; no saved configuration is shown.

- `cmd-8781d737b4e2256483e2` : `service-engine wma-passcode name-string key-string` ; modes : Interface configuration (config-if).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/interface/command/ir-cr-book/ir-s1.html#wp1946421764).

## aes-image — ISR 800 / image condition

Attendu : `documented_config`. Résultat : PASS. The IOS reference names Cisco 836 and limits AES availability to IP plus images.

- `cmd-9722d28c8c44406de83e` : `password encryption aes` ; modes : Global configuration.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/m1/sec-m1-cr-book/pac_key_through_port_misuse.html#wp3357103729).

## protected-not-whole — administration / option-level evidence

Attendu : `uncertain`. Résultat : PASS. An ASR 1000 assertion for protected cannot qualify every logging persistent option.

- `cmd-fb7587b609d245731e8e` : `logging persistent [batch batch-size] {filesize logging-file-size} [immediate] {notify} [protected] {size filesystem-size} [threshold threshold-capacity [alert]] [url {disk0:/directory | disk1:/directory}]` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/esm/command/esm-cr-book/book_cjab_m_escalate-a-cisco-jabber-group_chapter_00.html#wp8708534740).

## strict-not-whole — security / release-scoped keyword

Attendu : `uncertain`. Résultat : PASS. IOS-XE 3.10 evidence is scoped to strict, not every printed variant.

- `cmd-13286f151f9582618a5a` : `service password-recovery` ; modes : Global configuration.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s1.html#wp1482810024).

## bgp-generic — routing / BGP

Attendu : `uncertain`. Résultat : PASS. A generic IOS reference and Command History alone do not prove targeted router support or serialization.

- `cmd-8501895e8eb3eeb086cc` : `router bgp autonomous-system-number` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/command/irg-cr-book/bgp-n1.html#wp2779013235).

## ospf-generic — routing / OSPF

Attendu : `uncertain`. Résultat : PASS. No device-specific form/serialization proof for the whole generic syntax.

- `cmd-831f211850374da74d1f` : `router ospf process-id [vrf vrf-name]` ; modes : Global configuration.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book/m_ospf-i1.html#wp1848823089).

## qos-class — QoS / class-map

Attendu : `uncertain`. Résultat : PASS. Class-map names and modes must not be treated as universal feature support.

- `cmd-f47bf5c3c0e08c2a689f` : `class-map [type {stack | access-control | port-filter | queue-threshold | logging log-class}] [match-all | match-any] class-map-name` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mpls/command/mp-cr-book/mp-a1.html#wp3774569566).

## qos-policy — QoS / policy-map

Attendu : `uncertain`. Résultat : PASS. Different policy-map contexts cannot be merged by keyword alone.

- `cmd-edc4b9e80fe347916fdc` : `policy-map [type {stack | access-control | port-filter | queue-threshold | logging log-policy}] policy-map-name` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/isg/command/isg-cr-book/isg_m1.html#wp8554474930).

## mpls — MPLS

Attendu : `uncertain`. Résultat : PASS. A reference syntax is not an identified-router configuration fixture.

- `cmd-0da8d8f67be49aa073e4` : `mpls ldp router-id [vrf vrf-name] interface [force]` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mpls/command/mp-cr-book/mp-m2.html#wp4236174500).

## nat — VPN/security / NAT

Attendu : `uncertain`. Résultat : PASS. Do not infer all option combinations from a basic NAT example.

- `cmd-f037b3c4ad46c2aac2c3` : `ip nat inside source {list {access-list-number | access-list-name} | route-map name} {interface type number | pool name [redundancy rg-id mapping-id mapping-id]} [no-payload] [overload] [c] [vrf name [match-in-vrf]] [oer] [portmap name]` ; modes : Global configuration (config).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr/command/ipaddr-cr-book/ipaddr-i3.html#wp1284532593).

## banner — opaque multiline banner

Attendu : `uncertain`. Résultat : PASS. Delimiter and payload semantics require block evidence; payload text is not independent CLI.

- `cmd-9db2e86a9605886ec626` : `banner motd d message d` ; modes : Global configuration.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/Cisco_IOS_Configuration_Fundamentals_Command_Reference/A_through_B.html#wp8038671030).

## pki — opaque certificate chain

Attendu : `uncertain`. Résultat : PASS. The grammar entry does not establish certificate-payload round-trip serialization.

- `cmd-1755280b24d851ae54f2` : `crypto pki certificate chain name` ; modes : Global configuration.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-a1-cr-book_chapter_0111.html#wp2454642604).

## flow-modes — NetFlow / multiple modes

Attendu : `uncertain`. Résultat : PASS. Global and QoS policy-map-class modes remain separate context possibilities.

- `cmd-3a53f864f9bab1b1f15d` : `flow monitor monitor-name` ; modes : Global configuration (config), QoS policy-map-class configuration (config-pmap-c).
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/command/fnf-cr-book/fnf-c1.html#wp3945532463).

## isr800-saved — ISR 800 / running-config

Attendu : `confirmed_config`. Résultat : PASS. Exact line in the Cisco 881W default running-config example.

- `form-bb3c078389c12ef58d2d` : `ip route 0.0.0.0 0.0.0.0 10.1.1.1` ; modes : global.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/routers/access/800/software/configuration/guide/SCG800Guide/SCG800_Guide_BookMap_chapter_010.html).
  Preuve `proof-ffab06fa0463ece071ff` : contexte global ; extrait `ip route 0.0.0.0 0.0.0.0 10.1.1.1` ; type `running_config_output`.

## isr1k-saved — ISR 1000 / cellular interface

Attendu : `confirmed_config`. Résultat : PASS. Exact line in a running-config whose license UDI identifies C1111.

- `form-313750d6a99ab24214a5` : `ip address negotiated` ; modes : interface.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/routers/access/isr1100/software/configuration/guide/isr1100-sw-config/basic_router_config.html).
  Preuve `proof-v01-783070d3b185dadf` : contexte ['interface Cellular0/2/0'] ; extrait `ip address negotiated` ; type `running_config_output`.

## isr4k-saved — ISR 4000 / running-config

Attendu : `confirmed_config`. Résultat : PASS. Exact example line, without interpreting version 15.3 as the IOS-XE release.

- `form-6bcaf02bc27d6bf97831` : `ipv6 multicast rpf use-bgp` ; modes : global.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/routers/access/isr4400/software/configuration/xe-17/isr4400-sw-config-xe-17/basic_router_configuration.html).
  Preuve `proof-0eb1cdfc2a057d041df7` : contexte global ; extrait `ipv6 multicast rpf use-bgp` ; type `running_config_output`.

## c8500-saved — Catalyst 8500 / VRF context

Attendu : `confirmed_config`. Résultat : PASS. Exact line in show running-config vrf; context is Mgmt-intf, not BGP.

- `form-ee059ef89a20cffe8b07` : `address-family ipv4` ; modes : vrf-definition.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/routers/cloud_edge/c8500/software-configuration-guide/c8500-software-config-guide/management-ethernet-interface/using-the-management-ethernet-interface.html).
  Preuve `proof-87024dbcdf09f8c04e36` : contexte ['vrf definition Mgmt-intf'] ; extrait `address-family ipv4` ; type `running_config_output`.

## snmp-cli — SNMP / router integrated switching

Attendu : `documented_config`. Résultat : PASS. A router guide supplies a CLI example; no running-config confirmation is claimed.

- `form-00e53937026c454d34f8` : `snmp-server community public RW` ; modes : global.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/routers/access/800/software/configuration/guide/SCG800Guide/SCG800_Guide_BookMap_chapter_0110.html).
  Preuve `proof-4f48f82e28e4de131041` : contexte global ; extrait `snmp-server community public RW` ; type `cli_configuration_example`.

## telemetry-cli — telemetry / CLI versus persistence

Attendu : `documented_config`. Résultat : PASS. Platform feature information and configured-subscription discussion do not turn the CLI example into an observed saved line.

- `form-a7d6d8379c50367741fe` : `telemetry ietf subscription 101` ; modes : global.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1715/b_1715_programmability_cg/model-driven-telemetry.html).
  Preuve `proof-41206d6a32b12949dfd3` : contexte global ; extrait `telemetry ietf subscription 101` ; type `cli_configuration_example`.

## pim-no-platform — IPv4 multicast / missing target platform

Attendu : `uncertain`. Résultat : PASS. A generic native example and a product breadcrumb are insufficient for targeted-router qualification.

- `form-67268afefe0aea3e6045` : `ip pim sparse-mode` ; modes : interface.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipmulti_pim/configuration/xe-16-6/imc-pim-xe-16-6-book/imc-basic-cfg.html).
  Preuve `proof-c8bcc86c5f93e1c3e386` : contexte ['interface GigabitEthernet0/0/0'] ; extrait `ip pim sparse-mode` ; type `native_example_unidentified_target_platform`.

## flow-no-platform — NetFlow / exporter context

Attendu : `uncertain`. Résultat : PASS. Keep the native exporter example while the targeted platform is unresolved.

- `form-774b5701500204dce8ad` : `destination 172.16.10.2` ; modes : flow-exporter.
  Source : [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/configuration/xe-16-12/fnf-xe-17-book/fnf-fnetflow.html).
  Preuve `proof-cfbd37b7473f20dbf578` : contexte ['flow exporter EXPORTER-1'] ; extrait `destination 172.16.10.2` ; type `native_example_unidentified_target_platform`.
