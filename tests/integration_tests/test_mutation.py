# pyright: reportPrivateUsage=false, reportUnusedCallResult=false, reportUnusedFunction=false

from dataclasses import FrozenInstanceError
from datetime import date
from pathlib import Path

import pytest

from knowledge_system import validate_collection
from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import CatalogEntry
from knowledge_system.domain import MutationIntent
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import Origin
from knowledge_system.domain import RegistrationRequest
from knowledge_system.domain import RetirementPayload
from knowledge_system.domain import ValidateRequest
from knowledge_system.exceptions import MutationConflictError
from knowledge_system.exceptions import MutationPlanningError
from knowledge_system.mutation import _collection_path
from knowledge_system.mutation import _slug
from knowledge_system.mutation import apply_mutation
from knowledge_system.mutation import plan_mutation
from knowledge_system.mutation import plan_registration
from tests.helpers import write_manifest
from tests.helpers import write_note


@pytest.fixture(autouse=True)
def _managed_collection(tmp_path: Path) -> None:
    write_manifest(tmp_path, enabled_profiles={"research": 1})


def _context(plan: MutationPlan) -> ApplyContext:
    return ApplyContext(principal=authenticate_local_filesystem(), expected_operation_id=plan.operation_id)


def _request(
    root: Path,
    intent: MutationIntent,
    *,
    path: str | None = None,
    destination: str | None = None,
    field: str | None = None,
    value: object | None = None,
    expected_git_revision: str | None = None,
) -> MutationRequest:
    return MutationRequest.model_validate(
        {
            "intent": intent,
            "collection": str(root),
            "actor": "agent-author",
            "task": "task-1",
            "path": path,
            "destination": destination,
            "field": field,
            "value": value,
            "expected_git_revision": expected_git_revision,
        }
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [("A Readable Title", "a-readable-title"), ("Café & Tea", "caf-tea"), ("Already--Spaced", "already-spaced")],
)
def test__slug(value: str, expected: str) -> None:
    assert _slug(value) == expected


@pytest.mark.parametrize("value", ["../outside.md", "/absolute.md", "C:/absolute.md", "nested//note.md"])
def test__collection_path_rejects_nonrelative_or_unnormalized_path(tmp_path: Path, value: str) -> None:
    with pytest.raises(MutationPlanningError):
        _collection_path(tmp_path, value, must_exist=False)


def test_plan_registration_preserves_body_and_local_yaml_formatting(tmp_path: Path) -> None:
    note = tmp_path / "note.md"
    note.write_bytes(b'---\r\n# retained\r\ntitle: "Yes"\r\n---\r\n# Claim Title\r\n\r\nBody.\r\n')

    plan = plan_registration(
        RegistrationRequest(
            note="note.md",
            collection=str(tmp_path),
            actor="agent-author",
            task="capture",
            origin=Origin.AGENT,
        )
    )
    result = apply_mutation(plan, _context(plan))

    rendered = note.read_bytes()
    assert result.written_paths == (str(note),)
    assert b'# retained\r\ntitle: "Yes"' in rendered
    assert rendered.endswith(b"# Claim Title\r\n\r\nBody.\r\n")
    assert b"created_by: agent-author\r\norigin: agent" in rendered


@pytest.mark.parametrize("origin", list(Origin))
def test_plan_registration_records_explicit_origin(tmp_path: Path, origin: Origin) -> None:
    note = tmp_path / f"{origin.value}.md"
    write_note(note, body=f"# {origin.value}\n")
    plan = plan_registration(
        RegistrationRequest(
            note=note.name,
            collection=str(tmp_path),
            actor="author",
            task="capture",
            origin=origin,
        )
    )
    apply_mutation(plan, _context(plan))
    assert f"origin: {origin.value}" in note.read_text(encoding="utf-8")


def test_plan_registration_uses_suffix_and_respects_retired_ids(tmp_path: Path) -> None:
    write_note(tmp_path / "existing.md", identity="claim")
    (tmp_path / "retired-ids.yaml").write_text(
        "version: 1\nrecords:\n  - id: claim-2\n    disposition: old\n    retired_on: 2026-08-11\n",
        encoding="utf-8",
    )
    write_note(tmp_path / "new.md", body="# Claim\n")

    plan = plan_registration(
        RegistrationRequest(
            note="new.md",
            collection=str(tmp_path),
            actor="agent",
            task="capture",
            origin=Origin.AGENT,
        )
    )

    assert plan.reservations[0].identifier == "claim-3"


def test_plan_registration_rejects_explicit_collision(tmp_path: Path) -> None:
    write_note(tmp_path / "existing.md", identity="claimed")
    write_note(tmp_path / "new.md")
    with pytest.raises(MutationPlanningError):
        plan_registration(
            RegistrationRequest(
                note="new.md",
                collection=str(tmp_path),
                actor="agent",
                task="capture",
                origin=Origin.AGENT,
                requested_id="claimed",
            )
        )


def test_apply_context_is_frozen() -> None:
    context = ApplyContext(principal=authenticate_local_filesystem(), expected_operation_id="operation")
    with pytest.raises(FrozenInstanceError):
        context.expected_operation_id = "changed"  # pyright: ignore[reportAttributeAccessIssue]


def test_apply_local_os_principal_is_separate_from_asserted_actor(tmp_path: Path) -> None:
    plan = plan_mutation(_request(tmp_path, MutationIntent.CREATE, path="new.md", value="# New\n"))
    assert _context(plan).principal.principal != plan.actor
    apply_mutation(plan, _context(plan))
    assert (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_stale_content_without_writes(tmp_path: Path) -> None:
    note = tmp_path / "note.md"
    write_note(note, identity="note", extra="tags: [old]\n")
    plan = plan_mutation(_request(tmp_path, MutationIntent.SET_FIELD, path="note.md", field="tags", value=("new",)))
    changed = note.read_bytes() + b"Human change.\n"
    note.write_bytes(changed)
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert note.read_bytes() == changed


def test_apply_mutation_rejects_operation_identity_mismatch_without_writes(tmp_path: Path) -> None:
    plan = plan_mutation(_request(tmp_path, MutationIntent.CREATE, path="new.md", value="# New\n"))
    context = ApplyContext(principal=authenticate_local_filesystem(), expected_operation_id="wrong")
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, context)
    assert not (tmp_path / "new.md").exists()


@pytest.mark.parametrize("decision_file", ["collection.yaml", "profiles.lock.yaml"])
def test_apply_mutation_rejects_changed_decision_input(tmp_path: Path, decision_file: str) -> None:
    plan = plan_mutation(_request(tmp_path, MutationIntent.CREATE, path="new.md", value="# New\n"))
    path = tmp_path / decision_file
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises((MutationConflictError, MutationPlanningError)):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_stale_git_revision_without_writes(tmp_path: Path) -> None:
    plan = plan_mutation(
        _request(
            tmp_path,
            MutationIntent.CREATE,
            path="new.md",
            value="# New\n",
            expected_git_revision="not-current",
        )
    )
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()


def test_plan_mutation_creates_utf8_markdown(tmp_path: Path) -> None:
    plan = plan_mutation(_request(tmp_path, MutationIntent.CREATE, path="new.md", value="# Café\n"))
    apply_mutation(plan, _context(plan))
    assert (tmp_path / "new.md").read_bytes() == "# Café\n".encode()


@pytest.mark.parametrize(
    ("intent", "field", "value", "expected"),
    [
        (MutationIntent.SET_FIELD, "tags", ("new",), "tags:\n- new"),
        (MutationIntent.REPLACE_SUBTREE, "aliases", ("Alias",), "aliases:\n- Alias"),
    ],
)
def test_plan_mutation_applies_bounded_frontmatter_update(
    tmp_path: Path,
    intent: MutationIntent,
    field: str,
    value: tuple[str, ...],
    expected: str,
) -> None:
    note = tmp_path / "note.md"
    write_note(note, identity="note", body="# Body\n")
    plan = plan_mutation(_request(tmp_path, intent, path="note.md", field=field, value=value))
    apply_mutation(plan, _context(plan))
    assert expected in note.read_text(encoding="utf-8")


def test_plan_mutation_rejects_reserved_frontmatter_field(tmp_path: Path) -> None:
    write_note(tmp_path / "note.md", identity="note")
    with pytest.raises(MutationPlanningError):
        plan_mutation(_request(tmp_path, MutationIntent.SET_FIELD, path="note.md", field="id", value=("new",)))


def test_plan_mutation_removes_bounded_frontmatter_field(tmp_path: Path) -> None:
    note = tmp_path / "note.md"
    write_note(note, identity="note", extra="tags: [temporary]\n")
    plan = plan_mutation(_request(tmp_path, MutationIntent.REMOVE_FIELD, path="note.md", field="tags"))
    apply_mutation(plan, _context(plan))
    assert "tags:" not in note.read_text(encoding="utf-8")


def test_plan_mutation_moves_registered_note_without_changing_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source.md"
    write_note(source, identity="stable")
    before = source.read_bytes()
    plan = plan_mutation(_request(tmp_path, MutationIntent.MOVE, path="source.md", destination="nested/destination.md"))
    apply_mutation(plan, _context(plan))
    assert not source.exists()
    assert (tmp_path / "nested" / "destination.md").read_bytes() == before


def test_plan_mutation_retires_note_and_appends_ledger(tmp_path: Path) -> None:
    note = tmp_path / "old.md"
    write_note(note, identity="old-note")
    plan = plan_mutation(
        _request(
            tmp_path,
            MutationIntent.RETIRE_IDENTITY,
            path="old.md",
            value=RetirementPayload(
                disposition="superseded",
                retired_on=date(2026, 8, 11),
                successor="note:local-notes/new-note",
            ),
        )
    )
    apply_mutation(plan, _context(plan))
    assert "record_status: retired" in note.read_text(encoding="utf-8")
    assert "old-note" in (tmp_path / "retired-ids.yaml").read_text(encoding="utf-8")
    assert "successor: note:local-notes/new-note" in note.read_text(encoding="utf-8")
    assert not validate_collection(ValidateRequest(collection=str(tmp_path))).has_blocking_findings


def test_retirement_tombstone_mismatch_is_invalid_and_identity_cannot_be_reused(tmp_path: Path) -> None:
    note = tmp_path / "old.md"
    write_note(note, identity="old-note")
    plan = plan_mutation(
        _request(
            tmp_path,
            MutationIntent.RETIRE_IDENTITY,
            path="old.md",
            value=RetirementPayload(disposition="obsolete", retired_on=date(2026, 8, 11)),
        )
    )
    apply_mutation(plan, _context(plan))
    write_note(tmp_path / "replacement.md", body="# Replacement\n")
    with pytest.raises(MutationPlanningError):
        plan_registration(
            RegistrationRequest(
                note="replacement.md",
                collection=str(tmp_path),
                actor="author",
                task="capture",
                origin=Origin.HUMAN,
                requested_id="old-note",
            )
        )
    note.write_text(
        note.read_text(encoding="utf-8").replace("disposition: obsolete", "disposition: mismatched"),
        encoding="utf-8",
    )
    assert "identity.retired-reused" in {
        finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings
    }


@pytest.mark.parametrize(
    ("original", "replacement"),
    [("2026-08-11", "2026-08-12"), ("note:local-notes/new-note", "note:local-notes/other-note")],
)
def test_retirement_tombstone_must_match_date_and_canonical_successor(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    note = tmp_path / "old.md"
    write_note(note, identity="old-note")
    plan = plan_mutation(
        _request(
            tmp_path,
            MutationIntent.RETIRE_IDENTITY,
            path="old.md",
            value=RetirementPayload(
                disposition="superseded",
                retired_on=date(2026, 8, 11),
                successor="note:local-notes/new-note",
            ),
        )
    )
    apply_mutation(plan, _context(plan))
    note.write_text(note.read_text(encoding="utf-8").replace(original, replacement), encoding="utf-8")
    assert "identity.retired-reused" in {
        finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings
    }


def test_plan_mutation_reserves_collection_identity(tmp_path: Path) -> None:
    entry = CatalogEntry(
        collection_id="research",
        manifest="repo://repos/research/collection.yaml",
        trust_domains=frozenset({"work"}),
    )
    plan = plan_mutation(_request(tmp_path, MutationIntent.RESERVE_COLLECTION, path="catalog.yaml", value=entry))
    apply_mutation(plan, _context(plan))
    assert "collection_id: research" in (tmp_path / "catalog.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("intent", "path", "value"),
    [
        (MutationIntent.CREATE, "malformed.md", "---\nid: never-closed\n"),
        (MutationIntent.CREATE, "invalid.md", b"not a string"),
    ],
)
def test_plan_mutation_rejects_malformed_or_invalid_create_payload(
    tmp_path: Path,
    intent: MutationIntent,
    path: str,
    value: object,
) -> None:
    with pytest.raises((MutationPlanningError, ValueError)):
        plan_mutation(_request(tmp_path, intent, path=path, value=value))


def test_plan_registration_rejects_malformed_frontmatter(tmp_path: Path) -> None:
    (tmp_path / "broken.md").write_text("---\ntitle: Never closed\n", encoding="utf-8")
    with pytest.raises(MutationPlanningError):
        plan_registration(
            RegistrationRequest(
                note="broken.md",
                collection=str(tmp_path),
                actor="agent",
                task="capture",
                origin=Origin.AGENT,
            )
        )


def test_plan_mutation_rejects_retiring_inactive_note(tmp_path: Path) -> None:
    write_note(tmp_path / "old.md", identity="old", extra="record_status: retired\n")
    with pytest.raises(MutationPlanningError):
        plan_mutation(
            _request(
                tmp_path,
                MutationIntent.RETIRE_IDENTITY,
                path="old.md",
                value=RetirementPayload(disposition="already done", retired_on=date(2026, 8, 11)),
            )
        )
