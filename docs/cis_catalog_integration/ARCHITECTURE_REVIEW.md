# Architecture Review: CIS Cisco IOS 15 Catalog Integration

## Overview

This document describes the integration of the CIS Cisco IOS 15 Benchmark v4.1.1 catalog into the existing audit engine.

## Current Architecture

### Existing Components

1. **Normalization Pipeline**
   - Cisco IOS/IOS-XE configuration → TTP parsing → RouterContractV1
   - Secrets protection, context validation, handlers, resolution
   - Output: `RouterContractV1` canonical JSON

2. **Audit Engine** (`audit/engine.py`)
   - Function: `audit_normalized(normalized_document, ...)`
   - Four operational rules: AAA-01, AAA-02, SSH-01, LOG-01
   - Models: `Finding`, `AuditReport`, `Evidence`, `Reference`
   - Status enum: `PASS`, `FAIL`, `NEEDS_REVIEW`, `NOT_APPLICABLE`

3. **Rules** (`audit/rules/`)
   - `management.py`: AAA-01, SSH-01
   - `logging.py`: LOG-01
   - `aaa_central.py`: AAA-02

4. **Reference Mappings** (`audit/mappings/verified_references.json`)
   - Maps internal rule IDs to CIS control IDs
   - Provenance and verification status tracking

### New Components Added

1. **CIS Catalog** (`audit/catalog/`)
   - `cis_ios15_v4_1_1.json`: 90 controls with full metadata
   - `cis_ios15_v4_1_1_dependency_bridge.json`: 744 F01-F16 dependencies
   - `cis_ios15_rule_manifest.json`: 90 evaluator stubs
   - `loader.py`: `CISIOS15Catalog` class for programmatic access
   - `cis_ios15_v4_1_1.schema.json`: JSON Schema validation

2. **CIS Evaluation Layer** (`audit/cis.py`)
   - `audit_cis_normalized()`: New entry point for CIS profile evaluation
   - `CISEvaluatorRegistry`: Registry pattern for control evaluators
   - 12 implemented evaluators covering AAA, SNMP, SSH, NTP, Logging, IP Security
   - Reuses existing `audit_normalized()` models and status enum

3. **Tools** (`tools/`)
   - `verify_cis_ios15_catalog.py`: Validates 90 controls, 744 dependencies
   - `explore_cis_ios15_catalog.py`: CLI for control/family exploration

## Integration Points

### Minimal Changes to Existing Code

- `audit/__init__.py`: Added `audit_cis_normalized` and `CISEvaluatorRegistry` exports
- `audit/cis.py`: New module, no modifications to existing engine/rules
- `audit/catalog/loader.py`: Fixed `controls_for_profile(include_lower=False)` bug
- No changes to `audit_normalized()`, `RouterContractV1`, or existing rules

### Data Flow

```
RouterContractV1 (normalized)
        |
        v
audit_cis_normalized(profile_level=1/2)
        |
        v
CISIOS15Catalog.load() -> 90 controls (filtered by profile)
        |
        v
For each control: Registry.get(control_id) -> evaluator
        |
        v
Evaluator(raw_document, control_metadata) -> (status, evidence, detail)
        |
        v
Finding(check_id="CIS-1.1.1", status, evidence, reason)
        |
        v
AuditReport(findings=[...], counts={PASS:5, FAIL:3, NEEDS_REVIEW:45})
```

## Decisions and Compromises

### 1. Evaluator Registry Pattern
**Decision**: Use a registry (`CISEvaluatorRegistry`) instead of dynamic imports.
**Rationale**: Explicit registration makes it clear which controls are implemented; avoids import-time side effects; easy to test and extend.

### 2. Reuse of Existing Models
**Decision**: `audit_cis_normalized()` returns `AuditReport` using existing `Finding`, `Evidence`, `AuditStatus`.
**Rationale**: Consistent API; existing consumers (CLI, Web, tests) work unchanged; single source of truth for status enum.

### 3. Profile Selection
**Decision**: `profile_level=1` (53 controls) or `profile_level=2` (90 controls), with `include_lower` flag.
**Rationale**: Matches CIS benchmark semantics (Level 2 extends Level 1). Fixed bug in `controls_for_profile(include_lower=False)`.

### 4. Missing Evaluators → NEEDS_REVIEW
**Decision**: Controls without registered evaluators return `NEEDS_REVIEW` with explanatory reason.
**Rationale**: Honest about coverage; doesn't fake compliance; catalog `catalogue_integration_status` field documents status.

### 4. No New Parser in Audit Layer
**Decision**: Evaluators consume `RouterContractV1` only; no TTP/regex in `audit/`.
**Rationale**: Maintains separation of concerns; normalization pipeline is single source of truth for CLI parsing.

## Limitations

1. **Parser Coverage**: Some controls fail due to parser/normalizer gaps (e.g., SNMPv3 `security_level`, `enable_secret`, `password_encryption_service`). These are normalization issues, not CIS integration issues.

2. **Operational Evidence**: Controls requiring `show` command output (e.g., 2.1.1.1.3 RSA key size, 1.5.9 SNMP group verification) cannot be fully evaluated from `running-config` alone. The framework accepts optional `evidence` dict for future operational data.

3. **Manual Controls**: 3 controls (3.1.2, 3.2.1, 3.2.2) are `Manual` in benchmark. Current framework returns `NEEDS_REVIEW` — human review still required.

4. **Applicability Conditions**: Some controls have conditional applicability (e.g., 1.5.1 "SNMP unused"). Not yet encoded in evaluators.

## Extensibility

Adding a new evaluator:
```python
def _eval_X_Y_Z(raw: dict, control: dict) -> tuple[AuditStatus, list[str], str]:
    # inspect raw RouterContractV1 dict
    return AuditStatus.PASS, ["path", "to", "field"], "detail"

registry.register("X.Y.Z", _eval_X_Y_Z)
```

No other changes needed. The registry auto-discovers at runtime.

## Testing

- All 236 existing audit tests pass
- All 66 pipeline/normalized tests pass
- 302 total core tests pass
- Catalog verification: 90 controls, 744 dependencies validated
- Profile filtering: Level 1=53, Level 2=90, Level 2 only=37 ✓