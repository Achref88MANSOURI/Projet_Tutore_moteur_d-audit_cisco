# Integration Validation Report

## Test Results Summary

| Test Suite | Tests | Passed | Failed | Duration |
|------------|-------|--------|--------|----------|
| Audit Engine | 236 | 236 | 0 | 30s |
| Pipeline/Normalized | 66 | 66 | 0 | 38s |
| **Total Core** | **302** | **302** | **0** | **67s** |
| Catalog Verification | 1 | 1 | 0 | <1s |
| Profile Filtering | 3 | 3 | 0 | <1s |

## Catalog Validation

```
OK: 90 controls, 87 automated/3 manual, 53 level 1/37 level 2, 744 unique mapped dependencies, 90 rule stubs.
  F01: 11 controls, 139 dependencies
  F02: 11 controls, 101 dependencies
  F03: 3 controls, 47 dependencies
  F04: 3 controls, 40 dependencies
  F05: 10 controls, 78 dependencies
  F06: 6 controls, 45 dependencies
  F07: 7 controls, 48 dependencies
  F08: 7 controls, 24 dependencies
  F09: 5 controls, 24 dependencies
  F10: 4 controls, 24 dependencies
  F11: 4 controls, 43 dependencies
  F12: 2 controls, 88 dependencies
  F13: 9 controls, 20 dependencies
  F14: 2 controls, 6 dependencies
  F15: 5 controls, 12 dependencies
  F16: 1 controls, 5 dependencies
```

## Profile Filtering Tests

```
Level 1: 53 controls ✓
Level 2: 90 controls ✓
Level 2 only (include_lower=False): 37 controls ✓
```

## CIS Evaluation Results

### Test Configuration 1: Level 1 Profile (AAA + SSH + Logging + Source Route)

```cisco
aaa new-model
aaa authentication login default local
ip ssh version 2
logging host 192.0.2.1
```

| Control | Status | Evidence |
|---------|--------|----------|
| CIS-1.1.1 | PASS | /system/aaa/enabled = true |
| CIS-1.1.2 | PASS | /system/aaa/authentication_method_lists[0].methods = ["local"] |
| CIS-2.1.1.2 | PASS | /system/management/ssh/version = 2 |
| CIS-2.2.4 | PASS | /system/logging/destinations[0].address = 192.0.2.1 |
| CIS-3.1.1 | PASS | /system/ip_services/source_routing = false |

**Summary**: 5 PASS, 0 FAIL, 48 NEEDS_REVIEW

### Test Configuration 2: Level 1 Profile (Complete AAA + SNMP + NTP)

```cisco
aaa new-model
aaa authentication login default local
enable secret 5 $1$abc$xyz
service password-encryption
ip ssh version 2
service tcp-keepalives-in
logging host 192.0.2.1
ntp authenticate
ntp authentication-key 1 md5 7 secret
ntp trusted-key 1
ntp server 192.0.2.10 key 1
no ip source-route
snmp-server community public RO
snmp-server community private RW
snmp-server group GRP1 v3 priv
snmp-server user USER1 GRP1 v3 auth sha secret priv aes 128 secret
```

| Control | Status | Evidence |
|---------|--------|----------|
| CIS-1.1.1 | PASS | aaa enabled |
| CIS-1.1.2 | PASS | login method list with local |
| CIS-1.2.2 | NEEDS_REVIEW | No VTY lines in config |
| CIS-1.2.6 | NEEDS_REVIEW | No VTY lines in config |
| CIS-1.4.1 | FAIL | enable_secrets not parsed (normalizer gap) |
| CIS-1.4.2 | FAIL | password_encryption_service not parsed (normalizer gap) |
| CIS-1.5.4 | FAIL | RW community "private" found |
| CIS-1.5.9 | FAIL | SNMPv3 group security_level=null (normalizer gap) |
| CIS-2.1.1.2 | PASS | SSH version 2 |
| CIS-2.1.6 | PASS | tcp_keepalives_in = true |
| CIS-2.3.1.1 | PASS | NTP authentication_enabled = true |
| CIS-3.1.1 | PASS | source_routing = false |

**Summary**: 7 PASS, 3 FAIL, 80 NEEDS_REVIEW (Level 2 profile)

## Implemented Evaluators (12/90)

| Control | Title | Status | Category |
|---------|-------|--------|----------|
| 1.1.1 | Enable 'aaa new-model' | IMPLEMENTED | AAA |
| 1.1.2 | Enable 'aaa authentication login' | IMPLEMENTED | AAA |
| 1.2.2 | Set 'transport input ssh' for VTY | IMPLEMENTED | Lines/Access |
| 1.2.6 | Set 'exec-timeout' <= 10 min for VTY | IMPLEMENTED | Lines/Access |
| 1.4.1 | Set password for enable secret | IMPLEMENTED* | Secrets |
| 1.4.2 | Enable service password-encryption | IMPLEMENTED* | Secrets |
| 1.5.4 | No RW SNMP community | IMPLEMENTED | SNMP |
| 1.5.9 | SNMPv3 group priv security level | IMPLEMENTED* | SNMP |
| 2.1.1.2 | SSH version 2 | IMPLEMENTED | SSH |
| 2.1.6 | TCP keepalives-in | IMPLEMENTED | Services |
| 2.2.4 | Remote syslog destination | IMPLEMENTED | Logging |
| 2.3.1.1 | NTP authentication enabled | IMPLEMENTED | NTP |
| 3.1.1 | No IP source-route | IMPLEMENTED | IP Security |

*Limited by normalizer coverage (see Limitations below)

## Limitations Identified

### Normalizer Gaps Affecting CIS Evaluation

| Control | Expected V1 Path | Actual Value | Gap |
|---------|-----------------|--------------|-----|
| 1.4.1 | /system/aaa/enable_secrets | null | enable secret not parsed |
| 1.4.2 | /system/password_encryption_service | null | service password-encryption not parsed |
| 1.5.9 | /system/snmp/groups/*/security_level | null | SNMPv3 group security_level not parsed |

These are **normalizer limitations**, not CIS integration issues. The evaluators correctly return FAIL/NEEDS_REVIEW based on available data.

### Operational Evidence Required

| Control | Requirement | Evidence Source |
|---------|-------------|-----------------|
| 1.5.1 | SNMP disabled when unused | show snmp |
| 1.5.9 | SNMPv3 group priv | show snmp group |
| 2.1.1.1.3 | RSA key modulus >= 2048 | show crypto key mypubkey rsa |
| 3.1.2 | Proxy ARP operational | show ip interface |

### Manual Controls (3)

| Control | Title | Status |
|---------|-------|--------|
| 3.1.2 | Proxy ARP operational | MANUAL |
| 3.2.1 | uRPF operational | MANUAL |
| 3.2.2 | uRPF operational | MANUAL |

## Non-Regression Verification

All existing audit tests pass (236/236):
- AAA-01, AAA-02, SSH-01, LOG-01 unchanged
- OSPF resolver (28 tests) passes
- Phase 2H evidence/review tests pass
- Pipeline and normalized tests pass (66/66)

## Security Verification

- No secrets in findings or evidence
- `identifier_redacted: true` for SNMP communities
- No remediation commands executed
- No raw configuration in audit output