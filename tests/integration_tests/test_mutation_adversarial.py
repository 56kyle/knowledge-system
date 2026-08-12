# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

from base64 import b64encode
from hashlib import sha256
from pathlib import Path

import pytest

from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import FilePrecondition
from knowledge_system.domain import IdentityReservation
from knowledge_system.domain import MutationIntent
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import Origin
from knowledge_system.domain import RegistrationRequest
from knowledge_system.exceptions import MutationConflictError
from knowledge_system.exceptions import MutationPlanningError
from knowledge_system.mutation import _canonical_plan_digest
from knowledge_system.mutation import _recheck_parent_identities
from knowledge_system.mutation import _retained_parent_identities
from knowledge_system.mutation import _retained_target_path
from knowledge_system.mutation import apply_mutation
from knowledge_system.mutation import plan_mutation
from knowledge_system.mutation import plan_registration
from knowledge_system.profiles import BUILTIN_LOCK_DIGESTS
from tests.helpers import write_manifest
from tests.helpers import write_note


def _create_plan(root: Path) -> MutationPlan:
    write_manifest(root)
    request = MutationRequest(
        intent=MutationIntent.CREATE,
        collection=str(root),
        actor="agent-author",
        task="task-1",
        path="new.md",
        value="# New\n",
    )
    return plan_mutation(request)


def _context(plan: MutationPlan) -> ApplyContext:
    return ApplyContext(principal=authenticate_local_filesystem(), expected_operation_id=plan.operation_id)


def _resign(plan: MutationPlan) -> MutationPlan:
    provisional = plan.model_copy(update={"operation_id": "0" * 64, "plan_sha256": "0" * 64})
    digest = _canonical_plan_digest(provisional)
    return provisional.model_copy(update={"operation_id": digest, "plan_sha256": digest})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor", "another-author"),
        ("task", "another-task"),
        ("intent_payload_json", '{"path":"other.md"}'),
    ],
)
def test_apply_mutation_rejects_checksum_bound_field_tampering(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    plan = _create_plan(tmp_path)
    hostile = plan.model_copy(update={field: value})

    with pytest.raises((MutationConflictError, MutationPlanningError)):
        apply_mutation(hostile, _context(hostile))

    assert not (tmp_path / "new.md").exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("collection_snapshot_sha256", "0" * 64),
        ("configuration_sha256", "0" * 64),
        ("collection_id", "another-collection"),
    ],
)
def test_apply_mutation_rejects_resigned_snapshot_binding_tampering(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    plan = _create_plan(tmp_path)
    hostile = _resign(plan.model_copy(update={field: value}))
    with pytest.raises((MutationConflictError, MutationPlanningError)):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_operation_digest_tampering(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    hostile = plan.model_copy(update={"operation_id": "0" * 64})
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_collection_root_tampering(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    other = tmp_path.parent / f"{tmp_path.name}-other"
    other.mkdir()
    write_manifest(other)
    hostile = plan.model_copy(update={"collection": str(other)})
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (other / "new.md").exists()


def test_apply_mutation_rejects_collection_root_replaced_by_symlink(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    original = tmp_path.parent / f"{tmp_path.name}-original"
    tmp_path.rename(original)
    try:
        tmp_path.symlink_to(original, target_is_directory=True)
    except OSError:
        original.rename(tmp_path)
        pytest.skip("directory symlink creation is unavailable")
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (original / "new.md").exists()


def test__recheck_parent_identities_rejects_replaced_parent(tmp_path: Path) -> None:
    parent = tmp_path / "nested"
    parent.mkdir()
    target = parent / "new.md"
    retained = _retained_parent_identities(tmp_path, target)
    parent.rename(tmp_path / "original-parent")
    parent.mkdir()
    with pytest.raises(MutationConflictError):
        _recheck_parent_identities(
            tmp_path,
            {"nested/new.md": b"# New\n"},
            {"nested/new.md": retained},
        )


@pytest.mark.parametrize("phase", ["backup", "operation"])
def test__retained_target_path_rejects_replaced_parent_for_every_apply_phase(tmp_path: Path, phase: str) -> None:
    parent = tmp_path / "nested"
    parent.mkdir()
    relative = "nested/new.md"
    retained = {relative: _retained_parent_identities(tmp_path, tmp_path / relative)}
    parent.rename(tmp_path / f"original-{phase}")
    parent.mkdir()
    with pytest.raises(MutationConflictError):
        _retained_target_path(tmp_path, relative, retained)


@pytest.mark.parametrize(
    "hostile_path",
    [
        "../outside.md",
        "/absolute.md",
        "C:/absolute.md",
        "C:drive-relative.md",
        "nested/C:/absolute.md",
        "nested/C:drive-relative.md",
    ],
)
def test_apply_mutation_rejects_resigned_hostile_target_path(tmp_path: Path, hostile_path: str) -> None:
    plan = _create_plan(tmp_path)
    file = plan.files[0].model_copy(update={"path": hostile_path})
    condition = plan.preconditions[0].model_copy(update={"path": hostile_path})
    hostile = _resign(plan.model_copy(update={"files": (file,), "preconditions": (condition,)}))

    with pytest.raises(MutationPlanningError):
        apply_mutation(hostile, _context(hostile))

    assert not (tmp_path.parent / "outside.md").exists()


def test_apply_mutation_rejects_resigned_symlink_escape(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    file = plan.files[0].model_copy(update={"path": "linked/new.md"})
    condition = plan.preconditions[0].model_copy(update={"path": "linked/new.md"})
    hostile = _resign(plan.model_copy(update={"files": (file,), "preconditions": (condition,)}))

    with pytest.raises(MutationPlanningError):
        apply_mutation(hostile, _context(hostile))

    assert not (outside / "new.md").exists()


def test_apply_mutation_rejects_duplicate_planned_paths(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    hostile = _resign(
        plan.model_copy(update={"files": (plan.files[0], plan.files[0]), "preconditions": plan.preconditions})
    )
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_missing_or_extra_precondition(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    extra = FilePrecondition(path="other.md", exists=False)
    hostile = _resign(plan.model_copy(update={"preconditions": (*plan.preconditions, extra)}))
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_duplicate_precondition_paths(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    hostile = _resign(plan.model_copy(update={"preconditions": (plan.preconditions[0], plan.preconditions[0])}))
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


@pytest.mark.parametrize(
    ("content_base64", "after_sha256"),
    [("not base64!", "0" * 64), (b64encode(b"changed").decode(), "0" * 64)],
)
def test_apply_mutation_rejects_malformed_or_hash_mismatched_payload(
    tmp_path: Path,
    content_base64: str,
    after_sha256: str,
) -> None:
    plan = _create_plan(tmp_path)
    file = plan.files[0].model_copy(update={"content_base64": content_base64, "after_sha256": after_sha256})
    hostile = _resign(plan.model_copy(update={"files": (file,)}))
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_validly_hashed_malformed_markdown(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    malformed = b"---\nid: no-close\n"
    file = plan.files[0].model_copy(
        update={"content_base64": b64encode(malformed).decode(), "after_sha256": sha256(malformed).hexdigest()}
    )
    hostile = _resign(plan.model_copy(update={"files": (file,)}))
    with pytest.raises(MutationPlanningError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_internally_inconsistent_before_state(tmp_path: Path) -> None:
    plan = _create_plan(tmp_path)
    condition = plan.preconditions[0].model_copy(update={"exists": True, "sha256": "0" * 64})
    hostile = _resign(plan.model_copy(update={"preconditions": (condition,)}))
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_invalid_reservation_binding(tmp_path: Path) -> None:
    note = tmp_path / "capture.md"
    write_manifest(tmp_path)
    write_note(note, body="# Capture\n")
    plan = plan_registration(
        RegistrationRequest(
            note="capture.md",
            collection=str(tmp_path),
            actor="agent",
            task="task",
            origin=Origin.AGENT,
        )
    )
    invalid = IdentityReservation(namespace="note", collection_id="other", identifier="capture")
    hostile = _resign(plan.model_copy(update={"reservations": (invalid,)}))
    with pytest.raises(MutationConflictError):
        apply_mutation(hostile, _context(hostile))
    assert b"id:" not in note.read_bytes()


@pytest.mark.parametrize("change", ["new-note", "retired-ledger"])
def test_apply_mutation_rejects_identity_snapshot_change(tmp_path: Path, change: str) -> None:
    plan = _create_plan(tmp_path)
    if change == "new-note":
        write_note(tmp_path / "other.md", identity="other")
    else:
        (tmp_path / "retired-ids.yaml").write_text("version: 1\nids: [other]\n", encoding="utf-8")
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()


@pytest.mark.parametrize("reference", ["catalog", "trust_policy"])
def test_apply_mutation_rejects_referenced_decision_file_change(tmp_path: Path, reference: str) -> None:
    relative = "catalog.yaml" if reference == "catalog" else "trust-policy.yaml"
    write_manifest(tmp_path)
    manifest = tmp_path / "collection.yaml"
    binding = f"references:\n  {reference}: {relative}\n"
    if reference == "trust_policy":
        binding += "  trust_policy_id: local-trust\n"
    manifest.write_text(manifest.read_text(encoding="utf-8") + binding, encoding="utf-8")
    decision = tmp_path / relative
    content = "version: 1\ncollections: []\n" if reference == "catalog" else "version: 1\nid: local-trust\nrules: []\n"
    decision.write_text(content, encoding="utf-8")
    plan = plan_mutation(
        MutationRequest(
            intent=MutationIntent.CREATE,
            collection=str(tmp_path),
            actor="author",
            task="task",
            path="new.md",
            value="# New\n",
        )
    )
    decision.write_text(content + "\n", encoding="utf-8")
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()


def test_apply_mutation_rejects_locked_vocabulary_definition_change(tmp_path: Path) -> None:
    definition = (
        b"version: 1\nid: custom\nfield_prefix: custom_\nfields: []\n"
        b"predicates:\n  - name: future_link\n    prospective_allowed: true\n"
    )
    (tmp_path / "custom.yaml").write_bytes(definition)
    write_manifest(tmp_path, enabled_profiles={"custom": 1})
    (tmp_path / "profiles.lock.yaml").write_text(
        f"""version: 1
profiles:
  - identifier: custom
    version: 1
    sha256: "{sha256(definition).hexdigest()}"
    path: custom.yaml
relation_vocabularies:
  - identifier: core@1
    version: 1
    sha256: "{BUILTIN_LOCK_DIGESTS[("core@1", 1)]}"
""",
        encoding="utf-8",
    )
    plan = plan_mutation(
        MutationRequest(
            intent=MutationIntent.CREATE,
            collection=str(tmp_path),
            actor="author",
            task="task",
            path="new.md",
            value="# New\n",
        )
    )
    (tmp_path / "custom.yaml").write_bytes(definition + b"\n")
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()
