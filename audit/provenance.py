"""Presentation-only evidence enrichment inside the producing worker.

This module never parses CLI, chooses a failing collection member, or changes
an AuditReport. A serialized SourceMap is not a trusted input to this layer.
"""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

from normalizer.provenance import Quality, Role, State
from parser.safe_view import SourceLine

MAX_PROVENANCE_BYTES = 8 * 1024 * 1024
MAX_COMMANDS = 64
MAX_RELATED = 64


class PublicModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class CommandOrigin(PublicModel):
    source_line: int = Field(ge=1)
    context_lines: tuple[int, ...] = ()
    role: Role


class ContextOrigin(PublicModel):
    json_pointer: str
    quality: Quality
    use: Literal['CONTEXT_ONLY'] = 'CONTEXT_ONLY'
    commands: tuple[CommandOrigin, ...] = Field(default=(), max_length=MAX_COMMANDS)
    limitations: tuple[str, ...] = ()


class EvidenceOrigin(PublicModel):
    evidence_index: int = Field(ge=0)
    json_pointer: str
    quality: Quality
    claim: Literal['VALUE_ORIGIN', 'CONTEXT_ONLY', 'INCOMPLETE_ORIGIN', 'NO_SOURCE']
    failure_responsibility: Literal['NOT_INFERRED'] = 'NOT_INFERRED'
    commands: tuple[CommandOrigin, ...] = Field(default=(), max_length=MAX_COMMANDS)
    related: tuple[ContextOrigin, ...] = Field(default=(), max_length=MAX_RELATED)
    limitations: tuple[str, ...] = ()


class FindingOrigin(PublicModel):
    check_id: str
    quality: Quality
    evidence: tuple[EvidenceOrigin, ...] = ()
    limitations: tuple[str, ...] = ()


class PublicProvenance(PublicModel):
    version: Literal['0.1.0'] = '0.1.0'
    document_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{32}$')
    state: Literal['AVAILABLE', 'DEGRADED']
    coverage: Literal['pilot-only; no exhaustive absence proof'] = 'pilot-only; no exhaustive absence proof'
    source_lines: tuple[SourceLine, ...] = Field(default=(), max_length=20000)
    findings: tuple[FindingOrigin, ...]
    limitations: tuple[str, ...] = ('VALUE_ORIGIN_IS_NOT_FAILURE_RESPONSIBILITY', 'PILOT_ONLY', 'NO_EXHAUSTIVE_ABSENCE_PROOF')


def unavailable(report, code):
    """No source text, IDs or links survive an untrusted/failed association."""
    return PublicProvenance(state='DEGRADED', findings=tuple(
        FindingOrigin(check_id=f.check_id, quality=Quality.UNAVAILABLE,
                      evidence=tuple(EvidenceOrigin(evidence_index=i, json_pointer=e.json_pointer,
                                                    quality=Quality.UNAVAILABLE, claim='NO_SOURCE',
                                                    limitations=(code,)) for i, e in enumerate(f.evidence)),
                      limitations=(code,)) for f in report.findings),
        limitations=('VALUE_ORIGIN_IS_NOT_FAILURE_RESPONSIBILITY', 'PILOT_ONLY', 'NO_EXHAUSTIVE_ABSENCE_PROOF', code))


def _summary(qualities):
    qualities = set(qualities)
    if not qualities or qualities == {Quality.UNAVAILABLE}:
        return Quality.UNAVAILABLE
    if qualities == {Quality.EXACT}:
        return Quality.EXACT
    if qualities == {Quality.CONTEXTUAL}:
        return Quality.CONTEXTUAL
    return Quality.PARTIAL


def enrich_findings(result, report, *, document_id, max_bytes=MAX_PROVENANCE_BYTES):
    """Verify once, then project a bounded public DTO from live sealed objects.

    Business findings/evidence are read-only. No audit status is consulted to
    label a source command faulty: exactness describes a value's origin only.
    """
    sidecar = result.source_map
    if sidecar is None:
        return unavailable(report, 'PROVENANCE_UNAVAILABLE')
    try:
        sidecar.validate_links(result.normalized, document_id=document_id)
    except Exception:
        return unavailable(report, 'PROVENANCE_INTEGRITY_FAILED')

    try:
        entries = {e.json_pointer: e for e in sidecar.entries if e.json_pointer is not None}
        captures = {c.capture_id: c for c in sidecar.captures}
        contributions = {c.contribution_id: c for c in sidecar.contributions}

        def origins(entry):
            commands, notes = [], []
            if entry.quality == Quality.UNAVAILABLE:
                return (), ('NO_DEMONSTRATED_SOURCE',), Quality.UNAVAILABLE
            for cid in entry.contribution_ids:
                contribution = contributions[cid]
                capture = captures[contribution.capture_id]
                if (contribution.state != State.ACTIVE or contribution.quality != Quality.EXACT
                        or sidecar.source.lines[capture.source_line - 1].masked):
                    notes.append('REDACTED_OR_INCOMPLETE_SOURCE')
                    continue
                command = CommandOrigin(source_line=capture.source_line, context_lines=capture.context_lines,
                                        role=contribution.role)
                if command not in commands:
                    commands.append(command)
            commands.sort(key=lambda c: (c.source_line, c.role.value))
            quality = entry.quality
            if len(commands) > MAX_COMMANDS:
                commands = commands[:MAX_COMMANDS]
                quality = Quality.PARTIAL
                notes.append('COMMAND_LIMIT')
            for ref in entry.references:
                notes.append('UNRESOLVED_REFERENCE' if ref.status == 'UNRESOLVED' else 'DECLARATION_REFERENCE_NOT_EFFECTIVE_CHAIN')
            return tuple(commands), tuple(dict.fromkeys(notes)), quality

        findings = []
        for finding in report.findings:
            evidence = []
            for index, item in enumerate(finding.evidence):
                entry = entries.get(item.json_pointer)
                if entry is None:
                    evidence.append(EvidenceOrigin(evidence_index=index, json_pointer=item.json_pointer,
                                                   quality=Quality.UNAVAILABLE, claim='NO_SOURCE',
                                                   limitations=('NO_DEMONSTRATED_SOURCE',)))
                    continue
                commands, notes, quality = origins(entry)
                related = []
                if entry.quality == Quality.CONTEXTUAL:
                    # A collection is not a list of faulty members. Children
                    # remain contextual navigation, with no collective highlight.
                    commands = ()
                    notes += ('COLLECTION_OR_OBJECT_CONTEXT_NOT_UNIQUE_CAUSE',)
                    pointers = sorted(set(entry.related_pointers))
                    if len(pointers) > MAX_RELATED:
                        notes += ('CONTEXT_LIMIT',)
                        quality = Quality.PARTIAL
                    for pointer in pointers[:MAX_RELATED]:
                        child = entries[pointer]
                        child_commands, child_notes, child_quality = origins(child)
                        related.append(ContextOrigin(json_pointer=pointer, quality=child_quality,
                                                     commands=child_commands, limitations=child_notes))
                claim = {Quality.EXACT: 'VALUE_ORIGIN', Quality.CONTEXTUAL: 'CONTEXT_ONLY',
                         Quality.PARTIAL: 'INCOMPLETE_ORIGIN', Quality.UNAVAILABLE: 'NO_SOURCE'}[quality]
                evidence.append(EvidenceOrigin(evidence_index=index, json_pointer=item.json_pointer, quality=quality,
                                               claim=claim, commands=commands, related=tuple(related), limitations=notes))
            findings.append(FindingOrigin(check_id=finding.check_id, quality=_summary(e.quality for e in evidence),
                                           evidence=tuple(evidence), limitations=() if evidence else ('NO_BUSINESS_EVIDENCE',)))
        public = PublicProvenance(state='AVAILABLE', document_id=sidecar.document_id,
                                  source_lines=sidecar.source.lines, findings=tuple(findings))
        if len(public.model_dump_json().encode('utf-8')) > max_bytes:
            return unavailable(report, 'PROVENANCE_OUTPUT_LIMIT')
        return public
    except Exception:
        # Do not serialize a partial graph or an exception containing a value.
        return unavailable(report, 'PROVENANCE_ENRICHMENT_FAILED')
