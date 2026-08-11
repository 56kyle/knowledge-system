"""Built-in and declarative profile validation for knowledge_system."""

from __future__ import annotations

import json
from collections.abc import Mapping
from collections.abc import Sequence
from hashlib import sha256

from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import CollectionNote
from knowledge_system.domain import Finding
from knowledge_system.domain import Severity


_FLAP_TYPES = frozenset({"fleeting", "literature", "atomic", "project"})
_RESEARCH_DEPTHS = ("named", "scanned", "studied", "applied")
_TERMINAL_LITERATURE_OUTCOMES = frozenset({"atomic", "project", "discarded", "duplicate"})
BUILTIN_PREDICATES = frozenset({"related", "supports", "contradicts", "derived_from", "up", "led_to"})
_BUILTIN_DEFINITIONS: dict[tuple[str, int], dict[str, object]] = {
    ("flap", 1): {
        "types": ["fleeting", "literature", "atomic", "project"],
        "deferral": "unresolved-with-review-trigger",
        "atomic_up_max": 1,
    },
    ("research", 1): {
        "depths": list(_RESEARCH_DEPTHS),
        "roles": ["note", "map", "frontier"],
        "studied_requires_provenance": True,
    },
    ("core@1", 1): {
        "predicates": sorted(BUILTIN_PREDICATES),
        "canonical_confidence": "asserted",
    },
}
BUILTIN_LOCK_DIGESTS: dict[tuple[str, int], str] = {
    key: sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    for key, value in _BUILTIN_DEFINITIONS.items()
}


def validate_profiles(note: CollectionNote, manifest: CollectionManifest | None) -> tuple[Finding, ...]:
    """Validate built-in profiles selected by a registered note."""
    envelope = note.envelope
    if envelope is None:
        return ()
    findings: list[Finding] = []
    enabled: Mapping[str, int] = manifest.profiles.enabled if manifest else {}
    for profile in envelope.profiles:
        name, _, version_text = profile.partition("@")
        if name not in enabled:
            findings.append(_finding(note, "profile.not-enabled", f"profile {profile} is not enabled"))
        elif enabled[name] != int(version_text):
            findings.append(_finding(note, "profile.version-mismatch", f"profile {profile} is not selected"))
    if "flap@1" in envelope.profiles:
        findings.extend(_validate_flap(note, manifest))
    if "research@1" in envelope.profiles:
        findings.extend(_validate_research(note, manifest))
    return tuple(findings)


def _validate_flap(  # noqa: C901
    note: CollectionNote,
    manifest: CollectionManifest | None,
) -> list[Finding]:
    envelope = note.envelope
    if envelope is None:
        return []
    findings: list[Finding] = []
    if envelope.flap_type not in _FLAP_TYPES:
        return [_finding(note, "flap.type-required", "flap@1 requires flap_type")]
    if envelope.flap_type == "fleeting":
        if not envelope.captures:
            findings.append(_finding(note, "flap.capture-required", "Fleeting notes require a capture"))
        if envelope.processing_state == "deferred" and not envelope.review_due:
            findings.append(
                _finding(note, "flap.review-trigger-required", "Deferred Fleeting notes require review_due")
            )
    elif envelope.flap_type == "literature":
        if envelope.processing_state not in {"unfiled", "processed"}:
            findings.append(
                _finding(note, "flap.literature-state-invalid", "Literature state must be unfiled or processed")
            )
        if not envelope.source_version:
            findings.append(_finding(note, "flap.source-version-required", "Literature notes require source_version"))
        for index, item in enumerate(envelope.literature_items):
            checked = item.checked
            outcome = item.outcome
            if checked and outcome not in _TERMINAL_LITERATURE_OUTCOMES:
                findings.append(
                    _finding(
                        note,
                        "flap.nonterminal-item-completed",
                        f"Literature item {index} is checked without a terminal outcome",
                    )
                )
        if envelope.processing_state == "processed" and any(not item.checked for item in envelope.literature_items):
            findings.append(
                _finding(note, "flap.unresolved-literature-item", "Processed Literature has unresolved items")
            )
    elif envelope.flap_type == "atomic":
        if not note.title or not note.body.strip():
            findings.append(_finding(note, "flap.claim-required", "Atomic notes require a title and claim body"))
        if not envelope.sources and not envelope.captures:
            findings.append(
                _finding(
                    note,
                    "flap.provenance-uncertain",
                    "Atomic provenance is not explicit",
                    Severity.WARNING,
                )
            )
    elif envelope.flap_type == "project":
        settings: Mapping[str, object] = manifest.profiles.settings.get("flap", {}) if manifest else {}
        allowed = set(_strings(settings.get("allowed_project_states", ("planning", "writing", "done"))))
        terminal = set(_strings(settings.get("terminal_project_states", ("done",))))
        if not envelope.outcome or not envelope.project_state:
            findings.append(
                _finding(note, "flap.project-contract-required", "Project notes require outcome and project_state")
            )
        if not envelope.tasks:
            findings.append(_finding(note, "flap.project-task-required", "Project notes require actionable tasks"))
        if envelope.project_state is not None and envelope.project_state not in allowed:
            findings.append(_finding(note, "flap.project-state-invalid", "Project state is not allowed"))
        if envelope.project_state in terminal and any(not task.checked for task in envelope.tasks):
            findings.append(_finding(note, "flap.terminal-project-open-task", "Terminal Project has unchecked tasks"))
        if (
            envelope.project_state not in terminal
            and envelope.tasks
            and not any(not task.checked and task.action for task in envelope.tasks)
        ):
            findings.append(
                _finding(note, "flap.project-action-required", "Nonterminal Project requires an open actionable task")
            )
    return findings


def _validate_research(note: CollectionNote, manifest: CollectionManifest | None) -> list[Finding]:
    envelope = note.envelope
    if envelope is None:
        return []
    settings: Mapping[str, object] = manifest.profiles.settings.get("research", {}) if manifest else {}
    allowed_kinds = set(_strings(settings.get("kinds", ("tool", "concept", "paradigm", "person-org", "reference"))))
    findings: list[Finding] = []
    if envelope.research_role in {"map", "frontier"}:
        return findings
    if envelope.research_kind not in allowed_kinds:
        findings.append(_finding(note, "research.kind-invalid", "research_kind is absent or not allowed"))
    if envelope.research_depth not in _RESEARCH_DEPTHS:
        findings.append(_finding(note, "research.depth-required", "research_depth is required"))
    if envelope.research_depth in {"studied", "applied"} and not envelope.sources and not envelope.captures:
        findings.append(
            _finding(
                note,
                "research.evidence-required",
                "Studied or applied research requires provenance",
            )
        )
    governed_led_to = {relation.target for relation in envelope.relations if relation.predicate == "led_to"}
    if any(target not in governed_led_to for target in envelope.led_to):
        findings.append(_finding(note, "research.led-to-ungoverned", "each led_to target requires a led_to relation"))
    return findings


def _strings(value: object) -> Sequence[str]:
    """Return a validated string sequence or an empty sequence."""
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _finding(
    note: CollectionNote,
    code: str,
    message: str,
    severity: Severity = Severity.ERROR,
) -> Finding:
    """Create a profile finding scoped to one note."""
    return Finding(severity=severity, code=code, message=message, path=note.path, line=1)
