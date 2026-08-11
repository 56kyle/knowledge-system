from pathlib import Path

import pytest

from knowledge_system import ValidateRequest
from knowledge_system import validate_collection
from tests.helpers import write_manifest
from tests.helpers import write_note


def _configure_registry(
    root: Path,
    content: str,
    *,
    field: str = "source_version_registry",
    enabled_profiles: dict[str, int] | None = None,
) -> None:
    write_manifest(root, enabled_profiles=enabled_profiles)
    manifest = root / "collection.yaml"
    _ = manifest.write_text(
        manifest.read_text(encoding="utf-8") + f"references:\n  {field}: registries/sources.yaml\n",
        encoding="utf-8",
    )
    path = root / "registries" / "sources.yaml"
    path.parent.mkdir()
    _ = path.write_text(content, encoding="utf-8")


def _write_literature(root: Path, *, extra: str = "") -> None:
    write_note(
        root / "literature.md",
        identity="literature",
        extra=(
            "profiles: [flap@1]\n"
            "flap_type: literature\n"
            "processing_state: unfiled\n"
            "source_version: source-version:book-v1\n"
            f"{extra}"
        ),
    )


@pytest.mark.parametrize(
    ("status", "attributes", "code"),
    [
        ("missing", "", "registry.missing"),
        ("unavailable", "", "registry.unavailable"),
        ("unverifiable", "", "registry.unverifiable"),
        (
            "integrity_mismatch",
            f'    expected_sha256: "{"0" * 64}"\n    observed_sha256: "{"1" * 64}"\n',
            "registry.integrity-mismatch",
        ),
    ],
)
def test_validation_reports_each_provenance_registry_state(
    tmp_path: Path,
    status: str,
    attributes: str,
    code: str,
) -> None:
    _configure_registry(
        tmp_path,
        f"version: 1\nentries:\n  - reference: source-version:book-v1\n    status: {status}\n{attributes}",
    )
    report = validate_collection(ValidateRequest(collection=str(tmp_path)))
    assert code in {finding.code for finding in report.findings}


def test_validation_reports_integrity_drift_from_registry(tmp_path: Path) -> None:
    _configure_registry(
        tmp_path,
        "".join(
            (
                "version: 1\nentries:\n",
                "  - reference: source-version:book-v1\n",
                "    status: integrity_mismatch\n",
                f'    expected_sha256: "{"0" * 64}"\n',
                f'    observed_sha256: "{"1" * 64}"\n',
            )
        ),
    )
    findings = validate_collection(ValidateRequest(collection=str(tmp_path))).findings
    assert any(finding.code == "registry.integrity-mismatch" for finding in findings)


def test_reviewed_supported_claim_cannot_rely_only_on_unverifiable_evidence(tmp_path: Path) -> None:
    _configure_registry(
        tmp_path,
        "version: 1\nentries:\n  - reference: source-version:book-v1\n    status: unverifiable\n",
    )
    write_note(
        tmp_path / "claim.md",
        identity="claim",
        extra=(
            "epistemic_status: supported\n"
            "sources: [source-version:book-v1]\n"
            "review:\n"
            "  status: reviewed\n"
            "  reviewed_by: owner\n"
            "  reviewed_at: 2026-08-11T00:00:00Z\n"
            f"  basis: sha256:{'0' * 64}\n"
        ),
    )
    report = validate_collection(ValidateRequest(collection=str(tmp_path)))
    assert "provenance.review-support-unverifiable" in {finding.code for finding in report.findings}


def test_validation_rejects_registry_path_escape(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    manifest = tmp_path / "collection.yaml"
    _ = manifest.write_text(
        manifest.read_text(encoding="utf-8") + "references:\n  source_registry: ../outside.yaml\n",
        encoding="utf-8",
    )
    report = validate_collection(ValidateRequest(collection=str(tmp_path)))
    assert "registry.path-invalid" in {finding.code for finding in report.findings}


@pytest.mark.parametrize(
    ("field", "reference"),
    [
        ("source_registry", "source:book"),
        ("source_version_registry", "source-version:book-v1"),
        ("capture_registry", "capture:quote-1"),
        ("asset_registry", "asset:diagram"),
    ],
)
def test_registry_accepts_only_its_canonical_reference_scheme(tmp_path: Path, field: str, reference: str) -> None:
    _configure_registry(
        tmp_path,
        f"version: 1\nentries:\n  - reference: {reference}\n    status: verified\n",
        field=field,
    )
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.scheme-invalid" not in codes


@pytest.mark.parametrize(
    "field",
    ["source_registry", "source_version_registry", "capture_registry", "asset_registry"],
)
def test_registry_rejects_reference_from_a_different_scheme(tmp_path: Path, field: str) -> None:
    _configure_registry(
        tmp_path,
        "version: 1\nentries:\n  - reference: note:local-notes/claim\n    status: verified\n",
        field=field,
    )
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.scheme-invalid" in codes


def test_reference_repeated_across_registry_roles_is_ambiguous(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    manifest = tmp_path / "collection.yaml"
    _ = manifest.write_text(
        manifest.read_text(encoding="utf-8")
        + "references:\n"
        + "  source_registry: registries/shared.yaml\n"
        + "  source_version_registry: registries/shared.yaml\n",
        encoding="utf-8",
    )
    registry = tmp_path / "registries" / "shared.yaml"
    registry.parent.mkdir()
    _ = registry.write_text(
        "version: 1\nentries:\n  - reference: source:book\n    status: verified\n",
        encoding="utf-8",
    )
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.reference-ambiguous" in codes


def test_configured_registry_accounts_for_every_matching_evidence_reference(tmp_path: Path) -> None:
    _configure_registry(tmp_path, "version: 1\nentries: []\n")
    write_note(
        tmp_path / "claim.md",
        identity="claim",
        extra="sources: [source-version:unaccounted]\n",
    )
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.evidence-missing" in codes


@pytest.mark.parametrize("status", ["verified", "unverifiable", "missing", "unavailable"])
def test_registered_state_accounts_for_referenced_evidence(tmp_path: Path, status: str) -> None:
    _configure_registry(
        tmp_path,
        f"version: 1\nentries:\n  - reference: source-version:book-v1\n    status: {status}\n",
    )
    write_note(tmp_path / "claim.md", identity="claim", extra="sources: [source-version:book-v1]\n")
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.evidence-missing" not in codes


def test_literature_primary_source_version_requires_registry_accounting(tmp_path: Path) -> None:
    _configure_registry(tmp_path, "version: 1\nentries: []\n", enabled_profiles={"flap": 1})
    _write_literature(tmp_path)
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.evidence-missing" in codes


def test_literature_primary_source_version_can_be_verified_by_registry(tmp_path: Path) -> None:
    _configure_registry(
        tmp_path,
        "version: 1\nentries:\n  - reference: source-version:book-v1\n    status: verified\n",
        enabled_profiles={"flap": 1},
    )
    _write_literature(tmp_path)
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "registry.evidence-missing" not in codes


def test_reviewed_supported_literature_rejects_unverifiable_primary_source_version(tmp_path: Path) -> None:
    _configure_registry(
        tmp_path,
        "version: 1\nentries:\n  - reference: source-version:book-v1\n    status: unverifiable\n",
        enabled_profiles={"flap": 1},
    )
    _write_literature(
        tmp_path,
        extra=(
            "epistemic_status: supported\n"
            "review:\n"
            "  status: reviewed\n"
            "  reviewed_by: owner\n"
            "  reviewed_at: 2026-08-11T00:00:00Z\n"
            f"  basis: sha256:{'0' * 64}\n"
        ),
    )
    codes = {finding.code for finding in validate_collection(ValidateRequest(collection=str(tmp_path))).findings}
    assert "provenance.review-support-unverifiable" in codes


def test_literature_source_version_duplicated_in_sources_is_counted_once(tmp_path: Path) -> None:
    _configure_registry(tmp_path, "version: 1\nentries: []\n", enabled_profiles={"flap": 1})
    _write_literature(tmp_path, extra="sources: [source-version:book-v1]\n")
    findings = validate_collection(ValidateRequest(collection=str(tmp_path))).findings
    assert sum(finding.code == "registry.evidence-missing" for finding in findings) == 1
