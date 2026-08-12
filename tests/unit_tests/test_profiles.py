from hashlib import sha256

import pytest

from knowledge_system.domain import CollectionIdentity
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import CollectionNote
from knowledge_system.domain import NoteEnvelope
from knowledge_system.domain import ProfileSelection
from knowledge_system.profiles import validate_profiles


def _note(**metadata: object) -> CollectionNote:
    envelope = NoteEnvelope.model_validate({"id": "note", "created_by": "human", **metadata})
    return CollectionNote(
        path="note.md",
        title="A claim",
        envelope=envelope,
        body="# A claim\n\nClaim body.\n",
        content_sha256=sha256(b"note").hexdigest(),
    )


def _manifest(**settings: dict[str, object]) -> CollectionManifest:
    return CollectionManifest(
        collection=CollectionIdentity(id="notes", title="Notes", trust_domain="work"),
        profiles=ProfileSelection(enabled={"flap": 1, "research": 1}, settings=settings),
    )


@pytest.mark.parametrize(
    ("metadata", "code"),
    [
        ({"profiles": ["flap@1"]}, "flap.type-required"),
        ({"profiles": ["flap@1"], "flap_type": "fleeting"}, "flap.capture-required"),
        (
            {
                "profiles": ["flap@1"],
                "flap_type": "fleeting",
                "captures": ["capture:one"],
                "processing_state": "deferred",
            },
            "flap.review-trigger-required",
        ),
        ({"profiles": ["flap@1"], "flap_type": "literature"}, "flap.source-version-required"),
        (
            {
                "profiles": ["flap@1"],
                "flap_type": "literature",
                "source_version": "source-version:one",
                "processing_state": "processed",
                "literature_items": [{"text": "Unresolved", "checked": False}],
            },
            "flap.unresolved-literature-item",
        ),
        (
            {"profiles": ["flap@1"], "flap_type": "atomic"},
            "flap.provenance-uncertain",
        ),
        (
            {
                "profiles": ["flap@1"],
                "flap_type": "project",
                "outcome": "Ship it",
                "project_state": "done",
                "tasks": [{"text": "Open", "checked": False}],
            },
            "flap.terminal-project-open-task",
        ),
        ({"profiles": ["research@1"], "research_depth": "named"}, "research.kind-invalid"),
        (
            {"profiles": ["research@1"], "research_kind": "concept", "research_depth": "studied"},
            "research.evidence-required",
        ),
    ],
)
def test_validate_profiles_reports_profile_contract(metadata: dict[str, object], code: str) -> None:
    findings = validate_profiles(_note(**metadata), _manifest(flap={"terminal_project_states": ["done"]}))
    assert code in {finding.code for finding in findings}


def test_validate_profiles_allows_research_map_without_note_kind_or_depth() -> None:
    findings = validate_profiles(
        _note(profiles=["research@1"], research_role="map"),
        _manifest(),
    )
    assert findings == ()


def test_validate_profiles_requires_actionable_open_project_task() -> None:
    findings = validate_profiles(
        _note(
            profiles=["flap@1"],
            flap_type="project",
            outcome="Ship",
            project_state="writing",
            tasks=[{"text": "Vague task", "checked": False}],
        ),
        _manifest(),
    )
    assert "flap.project-action-required" in {finding.code for finding in findings}


def test_validate_profiles_requires_led_to_relation_governance() -> None:
    findings = validate_profiles(
        _note(
            profiles=["research@1"],
            research_kind="concept",
            research_depth="named",
            led_to=["note:notes/next"],
        ),
        _manifest(),
    )
    assert "research.led-to-ungoverned" in {finding.code for finding in findings}
