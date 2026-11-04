# CIS Implementation Roadmap

## Overview

This roadmap classifies the 90 CIS controls by implementation priority based on:
1. **Criticity** (CIS Level 1 > Level 2)
2. **Data Availability** (V1 paths present in current normalizer)
3. **Difficulty** (simple field check vs complex resolver)
4. **Operational Evidence** (requires `show` commands)
5. **Applicability** (conditional vs always applicable)

## Phase 1: Quick Wins (V1 paths exist, simple evaluators)

| Control | Title | Family | Level | V1 Path Status | Effort |
|---------|-------|--------|-------|----------------|--------|
| 1.1.3 | aaa authentication enable | F01 | L1 | /system/aaa/authentication_enable | Low |
| 1.2.1 | privilege 1 for local users | F01 | L1 | /system/aaa/local_users/*/privilege_level | Low |
| 1.2.3 | no exec for line aux 0 | F01 | L1 | /system/management/lines/*/exec_disabled | Low |
| 1.2.4 | access-list for line vty | F01 | L1 | /system/management/lines/*/access_list | Low |
| 1.2.5 | access-class for line vty | F01 | L1 | /system/management/lines/*/access_list | Low |
| 1.2.7 | exec-timeout for line tty | F01 | L1 | /system/management/lines/*/idle_timeout_seconds | Low |
| 1.2.8 | exec-timeout for line tty | F01 | L1 | /system/management/lines/*/idle_timeout_seconds | Low |
| 1.2.9 | exec-timeout for line vty (dup) | F01 | L1 | /system/management/lines/*/idle_timeout_seconds | Low |
| 1.2.10 | exec-timeout for line vty (dup) | F01 | L1 | /system/management/lines/*/idle_timeout_seconds | Low |
| 1.2.11 | transport input none for line aux 0 | F01 | L1 | /system/management/lines/*/allowed_transports | Low |
| 1.3.1 | banner exec text | F03 | L1 | /system/identity/banners/* | Low |
| 1.3.2 | banner login text | F03 | L1 | /system/identity/banners/* | Low |
| 1.3.3 | banner motd text | F03 | L1 | /system/identity/banners/* | Low |
| 1.5.2 | No 'private' SNMP community | F05 | L1 | /system/snmp/communities/*/identifier_redacted | Low |
| 1.5.3 | No 'public' SNMP community | F05 | L1 | /system/snmp/communities/*/identifier_redacted | Low |
| 1.5.7 | snmp-server host | F05 | L1 | /system/snmp/hosts/* | Low |
| 1.5.8 | snmp-server enable traps | F05 | L1 | /system/snmp/trap_config | Low |
| 2.1.1.1.1 | hostname | F02 | L1 | /system/identity/hostname | Low |
| 2.1.1.1.2 | ip domain-name | F02 | L1 | /system/identity/domain_name | Low |
| 2.1.1.1.4 | ip ssh timeout | F02 | L1 | /system/management/ssh/timeout_seconds | Low |
| 2.1.1.1.5 | ip ssh authentication-retries | F02 | L1 | /system/management/ssh/authentication_retries | Low |
| 2.1.2 | no cdp run | F07 | L1 | /system/ip_services/cdp_enabled | Low |
| 2.1.4 | no service dhcp | F07 | L1 | /system/ip_services/dhcp_service_enabled | Low |
| 2.1.5 | no ip identd | F07 | L1 | /system/ip_services/ident_enabled | Low |
| 2.1.7 | service tcp-keepalives-out | F07 | L1 | /system/ip_services/tcp_keepalives_out | Low |
| 2.1.8 | no service pad | F07 | L1 | /system/ip_services/pad_enabled | Low |
| 2.2.1 | logging on | F08 | L1 | /system/logging/enabled | Low |
| 2.2.2 | logging buffered size | F08 | L1 | /system/logging/buffered_size | Low |
| 2.2.3 | logging console critical | F08 | L1 | /system/logging/console_severity | Low |
| 2.2.5 | logging trap informational | F08 | L1 | /system/logging/trap_severity | Low |
| 2.2.6 | service timestamps | F08 | L1 | /system/logging/timestamps | Low |
| 2.2.7 | logging source-interface | F08 | L1 | /system/logging/source_interface | Low |
| 2.3.2 | ntp server with key | F09 | L2 | /system/ntp/servers/*/key_id | Low |

**Total: 42 controls** - Mostly simple field existence checks

## Phase 2: Normalizer Gaps (require parser/normalizer fixes)

| Control | Title | Family | Level | V1 Path | Gap |
|---------|-------|--------|-------|---------|-----|
| 1.4.1 | enable secret password | F04 | L1 | /system/aaa/enable_secrets | Normalizer doesn't parse `enable secret` |
| 1.4.2 | service password-encryption | F04 | L1 | /system/password_encryption_service | Normalizer doesn't parse |
| 1.5.1 | no snmp-server when unused | F05 | L1 | /system/snmp/enabled | Needs operational evidence |
| 1.5.9 | SNMPv3 group priv | F05 | L2 | /system/snmp/groups/*/security_level | security_level not parsed |
| 1.5.10 | SNMPv3 user AES 128 | F05 | L2 | /system/snmp/users/*/privacy_algorithm | Algorithm parsing incomplete |
| 2.1.1.1.3 | RSA modulus >= 2048 | F02 | L1 | /system/management/ssh/rsa_keys/*/modulus | Needs operational `show crypto key` |
| 2.2.3 | logging console critical | F08 | L1 | /system/logging/console_severity | Severity mapping needed |
| 2.3.1.1 | ntp authenticate | F09 | L2 | /system/ntp/authentication_enabled | ✓ Implemented |

**Total: 8 controls** - Require normalizer enhancements

## Phase 3: Complex Resolvers (need new resolver modules)

| Control | Title | Family | Level | Resolver Needed |
|---------|-------|--------|-------|-----------------|
| 1.2.4 | access-list for VTY | F01 | L1 | ACL-VTY binding resolver |
| 1.2.5 | access-class for VTY | F01 | L1 | ACL-VTY binding resolver |
| 1.5.5 | ACL for SNMP community | F05 | L1 | ACL reference resolver |
| 1.5.6 | Create ACL for SNMP | F05 | L1 | ACL existence validator |
| 2.1.3 | no ip bootp server | F07 | L1 | BOOTP/DHCP interaction resolver |
| 2.1.6 | tcp-keepalives-in | F07 | L1 | ✓ Implemented |
| 2.2.2 | logging buffered size | F08 | L1 | Buffered logging resolver |
| 2.2.5 | logging trap informational | F08 | L1 | Trap severity resolver |
| 2.2.6 | service timestamps | F08 | L1 | Timestamp config resolver |
| 2.2.7 | logging source-interface | F08 | L1 | Source interface resolver |
| 3.1.1 | no ip source-route | F11 | L1 | ✓ Implemented |
| 3.1.3 | tunnel inventory | F11 | L1 | VPN tunnel resolver |
| 3.1.2 | Proxy ARP operational | F11 | L1 | Manual (show command) |
| 3.2.1 | uRPF operational | F11 | L1 | Manual (show command) |
| 3.2.2 | uRPF operational | F11 | L1 | Manual (show command) |

**Total: 16 controls** - Need new resolver infrastructure

## Phase 4: Manual Controls (require human review)

| Control | Title | Family | Level | Reason |
|---------|-------|--------|-------|--------|
| 3.1.2 | Proxy ARP operational | F11 | L1 | Requires `show ip interface` operational check |
| 3.1.3 | Tunnel inventory approval | F11 | L1 | Business context required |
| 3.2.1 | uRPF strict mode operational | F11 | L1 | Requires `show ip interface` + `show ip cef` |
| 3.2.2 | uRPF loose mode operational | F11 | L1 | Requires `show ip interface` + `show ip cef` |

**Total: 4 controls** - Cannot be fully automated

## Phase 5: Conditional/Applicability Controls

| Control | Title | Family | Level | Condition |
|---------|-------|--------|-------|-----------|
| 1.5.1 | Disable SNMP when unused | F05 | L1 | "SNMP not needed" - requires network context |
| 2.1.3 | no ip bootp server | F07 | L1 | "BOOTP not needed" - requires network context |
| 2.1.4 | no service dhcp | F07 | L1 | "DHCP not needed" - requires network context |
| 2.1.5 | no ip identd | F07 | L1 | "Ident not needed" - requires network context |
| 2.1.7 | service tcp-keepalives-out | F07 | L1 | "TCP keepalives relevant" |
| 2.1.8 | no service pad | F07 | L1 | "PAD not needed" - requires network context |

**Total: 6 controls** - Need profile/exclusion mechanism

## Implementation Priority Matrix

| Priority | Phase | Controls | Est. Effort | Blockers |
|----------|-------|----------|-------------|----------|
| P0 | Phase 1 | 42 | 1-2 weeks | None |
| P1 | Phase 2 | 8 | 2-3 weeks | Normalizer changes |
| P2 | Phase 3 | 16 | 4-6 weeks | New resolvers |
| P3 | Phase 4 | 4 | Ongoing | Manual process |
| P4 | Phase 5 | 6 | 1-2 weeks | Profile mechanism |

## Total: 76 Automatable / 4 Manual / 10 Conditional

## Recommended Sprint Plan

### Sprint 1 (Week 1-2): Phase 1 Quick Wins
- Implement 42 simple field-check evaluators
- Add tests for each
- Target: 60%+ Level 1 coverage

### Sprint 2 (Week 3-4): Phase 2 Normalizer Fixes
- Add `enable secret` parsing
- Add `service password-encryption` parsing
- Fix SNMPv3 group `security_level` parsing
- Target: 75%+ Level 1 coverage

### Sprint 3 (Week 5-7): Phase 3 Resolvers
- ACL-VTY binding resolver
- ACL reference validator
- VPN tunnel inventory resolver
- Source interface resolvers
- Target: 90%+ Level 1, 50% Level 2

### Sprint 4 (Week 8): Phase 4-5
- Manual control documentation
- Conditional applicability framework
- Profile exclusion mechanism
- Target: 100% Level 1, 75% Level 2 automatable

## Success Metrics

| Metric | Current | Sprint 1 | Sprint 2 | Sprint 3 | Sprint 4 |
|--------|---------|----------|----------|----------|----------|
| Level 1 Automated | 15% | 60% | 75% | 90% | 100% |
| Level 2 Automated | 0% | 5% | 15% | 50% | 75% |
| Implemented Evaluators | 12 | 54 | 62 | 78 | 86 |
| Normalizer Gaps | 3 | 3 | 1 | 0 | 0 |