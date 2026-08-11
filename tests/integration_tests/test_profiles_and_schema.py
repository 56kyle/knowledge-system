# pyright: reportUnusedCallResult=false

from datetime import datetime
from datetime import timezone
from hashlib import sha256
from pathlib import Path

from knowledge_system import ValidateRequest
from knowledge_system import validate_collection
from knowledge_system.domain import ChunkRecord
from knowledge_system.domain import IngestionRecord
from knowledge_system.domain import ProjectionRecipe
from knowledge_system.domain import ReviewStatus
from knowledge_system.domain import RevisionAttestation
from knowledge_system.profiles import BUILTIN_LOCK_DIGESTS
from knowledge_system.schema import export_schemas
from knowledge_system.schema import rendered_schemas
from tests.helpers import write_manifest
from tests.helpers import write_note


def test_validate_collection_accepts_matching_builtin_profile_locks(tmp_path: Path) -> None:
    write_manifest(tmp_path, enabled_profiles={"research": 1})
    write_note(
        tmp_path / "note.md",
        identity="research-note",
        extra=(
            "profiles: [research@1]\nresearch_kind: concept\nresearch_depth: studied\n"
            "sources: [source-version:book-v1]\n"
        ),
    )

    report = validate_collection(ValidateRequest(collection=str(tmp_path)))

    assert not report.has_blocking_findings


def test_validate_collection_reports_builtin_profile_digest_mismatch(tmp_path: Path) -> None:
    write_manifest(tmp_path, enabled_profiles={"research": 1})
    lock = tmp_path / "profiles.lock.yaml"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(BUILTIN_LOCK_DIGESTS[("research", 1)], "0" * 64),
        encoding="utf-8",
    )

    report = validate_collection(ValidateRequest(collection=str(tmp_path)))

    assert "semantic.bundle-invalid" in {finding.code for finding in report.findings}


def test_validate_collection_enforces_declarative_profile_fields_and_invariants(tmp_path: Path) -> None:
    definition = (
        "version: 1\n"
        "id: custom\n"
        "field_prefix: custom_\n"
        "fields:\n"
        "  - name: custom_claim_type\n"
        "    type: string\n"
        "    required: true\n"
        "    enum: [fact, hypothesis]\n"
        "  - name: custom_confidence\n"
        "    type: integer\n"
        "invariants:\n"
        "  - kind: requires\n"
        "    fields: [custom_confidence, custom_claim_type]\n"
    ).encode()
    (tmp_path / "custom-profile.yaml").write_bytes(definition)
    write_manifest(tmp_path, enabled_profiles={"custom": 1})
    core_digest = BUILTIN_LOCK_DIGESTS[("core@1", 1)]
    (tmp_path / "profiles.lock.yaml").write_text(
        f"""version: 1
profiles:
  - identifier: custom
    version: 1
    sha256: "{sha256(definition).hexdigest()}"
    path: custom-profile.yaml
relation_vocabularies:
  - identifier: core@1
    version: 1
    sha256: "{core_digest}"
""",
        encoding="utf-8",
    )
    write_note(
        tmp_path / "note.md",
        identity="custom-note",
        extra="profiles: [custom@1]\ncustom_claim_type: unsupported\ncustom_confidence: 1\n",
    )

    report = validate_collection(ValidateRequest(collection=str(tmp_path)))

    assert "profile.field-invalid" in {finding.code for finding in report.findings}


def test_rendered_schemas_is_deterministic_and_matches_export(tmp_path: Path) -> None:
    rendered = rendered_schemas()
    updated = export_schemas(tmp_path)

    assert updated == tuple(sorted(rendered))
    assert export_schemas(tmp_path, check=True) == ()
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == rendered


def test_export_schemas_reports_extra_stale_schema(tmp_path: Path) -> None:
    _ = export_schemas(tmp_path)
    (tmp_path / "stale.schema.json").write_text("{}\n", encoding="utf-8")
    assert "stale.schema.json" in export_schemas(tmp_path, check=True)


def test_provenance_registry_schema_is_exported_and_drift_checked(tmp_path: Path) -> None:
    rendered = rendered_schemas()
    expected = rendered["provenance-registry.schema.json"]
    _ = export_schemas(tmp_path)
    schema = tmp_path / "provenance-registry.schema.json"
    assert schema.read_bytes() == expected
    schema.write_bytes(b"{}\n")
    assert "provenance-registry.schema.json" in export_schemas(tmp_path, check=True)


def test_projection_records_retain_canonical_revision_trust_and_location() -> None:
    ingestion = IngestionRecord(
        projection="work-search",
        canonical_reference="note:research/claim",
        revision="git:abc123",
        content_sha256="0" * 64,
        trust_domains=frozenset({"work"}),
        ingested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        attestation=RevisionAttestation(
            canonical_revision="git:abc123",
            content_sha256="0" * 64,
            review_status=ReviewStatus.REVIEWED,
            review_basis="sha256:" + "0" * 64,
            attested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ),
    )
    chunk = ChunkRecord(
        id="chunk-1",
        ingestion=ingestion,
        heading="Claim",
        block="claim-1",
        text="Canonical text",
        ordinal=0,
    )

    assert chunk.ingestion.canonical_reference == "note:research/claim"
    assert chunk.block == "claim-1"


def test_projection_recipe_keeps_admission_and_enclave_explicit() -> None:
    recipe = ProjectionRecipe(
        id="reviewed-work",
        collections=("research",),
        admitted_review_statuses=(ReviewStatus.REVIEWED,),
        trust_domains=frozenset({"work"}),
        chunker="heading-v1",
    )
    assert recipe.admitted_review_statuses == (ReviewStatus.REVIEWED,)
    assert recipe.trust_domains == frozenset({"work"})


def test_validation_rejects_custom_field_and_predicate_ownership_conflicts(tmp_path: Path) -> None:
    first = (
        "version: 1\nid: first\nfield_prefix: shared_\n"
        "fields:\n  - name: shared_value\n    type: string\n"
        "predicates:\n  - name: custom_related\n"
    ).encode()
    second = first.replace(b"id: first", b"id: second")
    (tmp_path / "first.yaml").write_bytes(first)
    (tmp_path / "second.yaml").write_bytes(second)
    write_manifest(tmp_path, enabled_profiles={"first": 1, "second": 1})
    core_digest = BUILTIN_LOCK_DIGESTS[("core@1", 1)]
    (tmp_path / "profiles.lock.yaml").write_text(
        f"""version: 1
profiles:
  - identifier: first
    version: 1
    sha256: "{sha256(first).hexdigest()}"
    path: first.yaml
  - identifier: second
    version: 1
    sha256: "{sha256(second).hexdigest()}"
    path: second.yaml
relation_vocabularies:
  - identifier: core@1
    version: 1
    sha256: "{core_digest}"
""",
        encoding="utf-8",
    )
    write_note(
        tmp_path / "note.md",
        identity="note",
        extra="profiles: [first@1, second@1]\nshared_value: present\n",
    )

    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert codes == {"semantic.bundle-invalid"}
