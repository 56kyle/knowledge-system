# pyright: reportUnknownMemberType=false, reportUnusedCallResult=false

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import TypeAlias
from typing import cast

import pytest
from pydantic import ValidationError

from knowledge_system import ControlInspectRequest
from knowledge_system import ControlValidateRequest
from knowledge_system import inspect_control
from knowledge_system import validate_control
from knowledge_system.domain import TaskScopedGrant
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.profiles import BUILTIN_LOCK_DIGESTS


ControlDocuments: TypeAlias = dict[str, dict[str, object]]

_ACTIONS = [
    "administer",
    "read",
    "link",
    "retrieve",
    "synthesize",
    "declassify",
    "update_local_evidence",
    "register",
    "create",
    "set_field",
    "remove_field",
    "replace_subtree",
    "move",
    "reserve_collection",
    "retire_identity",
]
_REVISION_PATTERN = re.compile(r"^(?:[0-9a-f]{40}(?:\+dirty)?|distribution:[^\s]+)$")


@pytest.fixture
def control_documents() -> ControlDocuments:
    return {
        "control.yaml": {
            "version": 1,
            "control_id": "test-control",
            "owner": "human:kyle",
            "catalog": "catalog/collections.yaml",
            "trust_domains": "trust/domains.yaml",
            "trust_policy": "trust/policy.yaml",
            "grants": "trust/grants.yaml",
            "semantic_releases": "semantics/releases.yaml",
            "projection_recipes": "projections/recipes.yaml",
        },
        "catalog/collections.yaml": {"version": 1, "collections": []},
        "trust/domains.yaml": {
            "version": 1,
            "domains": [{"id": "public"}, {"id": "work"}],
            "enclaves": [
                {"id": "public", "domains": ["public"]},
                {"id": "work", "domains": ["work"]},
            ],
        },
        "trust/policy.yaml": {"version": 1, "id": "default-deny", "rules": []},
        "trust/grants.yaml": {
            "version": 1,
            "grants": [
                {
                    "principal": "human:kyle",
                    "task": "*",
                    "actions": _ACTIONS,
                    "domains": ["public", "work"],
                    "collections": [],
                }
            ],
        },
        "semantics/releases.yaml": {
            "version": 1,
            "profiles": [
                {"identifier": "flap", "version": 1, "sha256": BUILTIN_LOCK_DIGESTS[("flap", 1)]},
                {
                    "identifier": "research",
                    "version": 1,
                    "sha256": BUILTIN_LOCK_DIGESTS[("research", 1)],
                },
            ],
            "relation_vocabularies": [
                {"identifier": "core@1", "version": 1, "sha256": BUILTIN_LOCK_DIGESTS[("core@1", 1)]}
            ],
        },
        "projections/recipes.yaml": {"version": 1, "recipes": []},
    }


@pytest.fixture
def write_control() -> Callable[[Path, ControlDocuments], Path]:
    def write(root: Path, documents: ControlDocuments) -> Path:
        for relative, document in documents.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        return root

    return write


@pytest.fixture
def control_root(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> Path:
    return write_control(tmp_path / "control", control_documents)


def _finding_codes(root: Path) -> set[str]:
    return {finding.code for finding in validate_control(ControlValidateRequest(root=str(root))).findings}


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "knowledge_system", *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_validate_control_with_valid_empty_authority(control_root: Path) -> None:
    report = validate_control(ControlValidateRequest(root=str(control_root)))
    assert report.has_blocking_findings is False


def test_inspect_control_reports_loaded_authority(control_root: Path) -> None:
    report = inspect_control(ControlInspectRequest(root=str(control_root)))
    assert (report.manifest is not None, report.catalog is not None, report.bundle_sha256 is not None) == (
        True,
        True,
        True,
    )


@pytest.mark.parametrize(
    ("relative", "field", "value"),
    [
        ("control.yaml", "unexpected", True),
        ("control.yaml", "version", 2),
        ("trust/domains.yaml", "unexpected", True),
        ("trust/domains.yaml", "version", 2),
    ],
)
def test_validate_control_with_closed_or_unsupported_document(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    relative: str,
    field: str,
    value: object,
) -> None:
    documents = deepcopy(control_documents)
    documents[relative][field] = value
    root = write_control(tmp_path / "control", documents)
    assert any(code.endswith("invalid") for code in _finding_codes(root))


def test_validate_control_with_missing_reference(control_root: Path) -> None:
    (control_root / "catalog" / "collections.yaml").unlink()
    assert "control.catalog-invalid" in _finding_codes(control_root)


@pytest.mark.parametrize("locator", ["C:/outside.yaml", "../outside.yaml", "catalog/../../outside.yaml"])
def test_validate_control_with_escaping_locator(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    locator: str,
) -> None:
    documents = deepcopy(control_documents)
    documents["control.yaml"]["catalog"] = locator
    root = write_control(tmp_path / "control", documents)
    assert "control.catalog-invalid" in _finding_codes(root)


def test_validate_control_with_symlink_escape(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    root = write_control(tmp_path / "control", control_documents)
    outside = tmp_path / "outside.yaml"
    outside.write_text('{"version": 1, "collections": []}', encoding="utf-8")
    locator = root / "catalog-link.yaml"
    try:
        locator.symlink_to(outside)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    documents = deepcopy(control_documents)
    documents["control.yaml"]["catalog"] = locator.name
    (root / "control.yaml").write_text(json.dumps(documents["control.yaml"]), encoding="utf-8")
    assert "control.catalog-invalid" in _finding_codes(root)


def test_validate_control_with_manifest_symlink_escape(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    root = write_control(tmp_path / "control", control_documents)
    manifest = root / "control.yaml"
    outside = tmp_path / "outside.yaml"
    manifest.replace(outside)
    try:
        manifest.symlink_to(outside)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    assert "control.manifest-invalid" in _finding_codes(root)


def test_validate_control_with_contained_manifest_symlink(
    control_root: Path,
) -> None:
    manifest = control_root / "control.yaml"
    contained = control_root / "authority" / "manifest.yaml"
    contained.parent.mkdir()
    manifest.replace(contained)
    try:
        manifest.symlink_to(contained)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    assert validate_control(ControlValidateRequest(root=str(control_root))).has_blocking_findings is False


def test_validate_control_with_contained_symlink(
    control_root: Path,
    control_documents: ControlDocuments,
) -> None:
    locator = control_root / "catalog-link.yaml"
    try:
        locator.symlink_to(control_root / "catalog" / "collections.yaml")
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    manifest = deepcopy(control_documents["control.yaml"])
    manifest["catalog"] = locator.name
    (control_root / "control.yaml").write_text(json.dumps(manifest), encoding="utf-8")
    assert validate_control(ControlValidateRequest(root=str(control_root))).has_blocking_findings is False


@pytest.mark.parametrize(
    ("relative", "collection", "duplicate", "expected_code"),
    [
        ("trust/domains.yaml", "domains", {"id": "public"}, "trust.domain-duplicate"),
        ("trust/domains.yaml", "enclaves", {"id": "public", "domains": ["work"]}, "trust.enclave-duplicate"),
        (
            "trust/domains.yaml",
            "enclaves",
            {"id": "work-copy", "domains": ["work"]},
            "trust.enclave-domain-set-duplicate",
        ),
        (
            "semantics/releases.yaml",
            "profiles",
            {"identifier": "flap", "version": 1, "sha256": BUILTIN_LOCK_DIGESTS[("flap", 1)]},
            "semantic.release-duplicate",
        ),
    ],
)
def test_validate_control_with_duplicate_registry_entry(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    relative: str,
    collection: str,
    duplicate: dict[str, object],
    expected_code: str,
) -> None:
    documents = deepcopy(control_documents)
    values = documents[relative][collection]
    assert isinstance(values, list)
    values.append(duplicate)
    root = write_control(tmp_path / "control", documents)
    assert expected_code in _finding_codes(root)


def test_validate_control_with_duplicate_collection_id(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    documents["catalog/collections.yaml"]["collections"] = [
        {"collection_id": "same", "manifest": "one.yaml", "trust_domains": ["work"]},
        {"collection_id": "same", "manifest": "two.yaml", "trust_domains": ["work"]},
    ]
    root = write_control(tmp_path / "control", documents)
    assert "control.catalog-invalid" in _finding_codes(root)


def test_validate_control_with_duplicate_grant(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    grants = documents["trust/grants.yaml"]["grants"]
    assert isinstance(grants, list)
    grants = cast("list[object]", grants)
    grants.append(deepcopy(grants[0]))
    root = write_control(tmp_path / "control", documents)
    assert "grant.duplicate" in _finding_codes(root)


@pytest.mark.parametrize(
    ("relative", "change", "expected_code"),
    [
        (
            "trust/domains.yaml",
            ("enclaves", [{"id": "public", "domains": ["unknown"]}]),
            "trust.enclave-domain-unknown",
        ),
        (
            "catalog/collections.yaml",
            (
                "collections",
                [{"collection_id": "notes", "manifest": "notes.yaml", "trust_domains": ["unknown"]}],
            ),
            "catalog.trust-domain-unknown",
        ),
    ],
)
def test_validate_control_with_unknown_domain_reference(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    relative: str,
    change: tuple[str, object],
    expected_code: str,
) -> None:
    documents = deepcopy(control_documents)
    documents[relative][change[0]] = change[1]
    root = write_control(tmp_path / "control", documents)
    assert expected_code in _finding_codes(root)


def test_validate_control_with_missing_singleton_enclave(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    documents["trust/domains.yaml"]["enclaves"] = [{"id": "public", "domains": ["public"]}]
    root = write_control(tmp_path / "control", documents)
    assert "trust.singleton-enclave-missing" in _finding_codes(root)


def test_validate_control_with_owner_not_covering_exact_authority(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    grants = documents["trust/grants.yaml"]["grants"]
    assert isinstance(grants, list)
    assert isinstance(grants[0], dict)
    grants[0]["domains"] = ["work"]
    root = write_control(tmp_path / "control", documents)
    assert "grant.owner-domains-incomplete" in _finding_codes(root)


def test_validate_control_with_non_snake_case_action(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    grants = documents["trust/grants.yaml"]["grants"]
    assert isinstance(grants, list)
    assert isinstance(grants[0], dict)
    grants[0]["actions"] = [*_ACTIONS, "update-local-evidence"]
    root = write_control(tmp_path / "control", documents)
    assert "control.grants-invalid" in _finding_codes(root)


@pytest.mark.parametrize(
    ("task", "collections", "expires_at"),
    [
        ("*", ["notes"], "2099-01-01T00:00:00Z"),
        ("curate", [], "2099-01-01T00:00:00Z"),
        ("curate", ["notes"], None),
        ("curate", ["notes"], "2099-01-01T00:00:00"),
    ],
)
def test_validate_control_with_invalid_task_grant_shape(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    task: str,
    collections: list[object],
    expires_at: str | None,
) -> None:
    documents = deepcopy(control_documents)
    documents["catalog/collections.yaml"]["collections"] = [
        {"collection_id": "notes", "manifest": "notes.yaml", "trust_domains": ["work"]}
    ]
    grant: dict[str, object] = {
        "principal": "agent:curator",
        "task": task,
        "actions": ["read"],
        "domains": ["work"],
        "collections": collections,
        "expires_at": expires_at,
    }
    grants = documents["trust/grants.yaml"]["grants"]
    assert isinstance(grants, list)
    grants.append(grant)
    root = write_control(tmp_path / "control", documents)
    assert validate_control(ControlValidateRequest(root=str(root))).has_blocking_findings is True


@pytest.mark.parametrize("task", ["", " ", " curate", "curate ", "*"])
def test_task_scoped_grant_rejects_unbounded_task_identifier(task: str) -> None:
    with pytest.raises(ValidationError):
        TaskScopedGrant(
            principal="agent:curator",
            task=task,
            actions=frozenset({"read"}),
            domains=frozenset({"work"}),
            collections=frozenset({"notes"}),
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )


def test_task_scoped_grant_accepts_bounded_task_identifier() -> None:
    grant = TaskScopedGrant(
        principal="agent:curator",
        task="curate-notes",
        actions=frozenset({"read"}),
        domains=frozenset({"work"}),
        collections=frozenset({"notes"}),
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    assert grant.task == "curate-notes"


def test_validate_control_with_expired_task_grant(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    documents["catalog/collections.yaml"]["collections"] = [
        {"collection_id": "notes", "manifest": "notes.yaml", "trust_domains": ["work"]}
    ]
    grants = documents["trust/grants.yaml"]["grants"]
    assert isinstance(grants, list)
    grants.append(
        {
            "principal": "agent:curator",
            "task": "curate",
            "actions": ["read"],
            "domains": ["work"],
            "collections": ["notes"],
            "expires_at": "2000-01-01T00:00:00Z",
        }
    )
    root = write_control(tmp_path / "control", documents)
    assert "grant.expired" in _finding_codes(root)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [("domains", ["unknown"], "grant.domain-unknown"), ("collections", ["unknown"], "grant.collection-unknown")],
)
def test_validate_control_with_unknown_grant_reference(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    field: str,
    value: list[object],
    code: str,
) -> None:
    documents = deepcopy(control_documents)
    grants = documents["trust/grants.yaml"]["grants"]
    assert isinstance(grants, list)
    grants.append(
        {
            "principal": "agent:curator",
            "task": "curate",
            "actions": ["read"],
            "domains": ["work"],
            "collections": ["notes"],
            "expires_at": "2099-01-01T00:00:00Z",
            field: value,
        }
    )
    root = write_control(tmp_path / "control", documents)
    assert code in _finding_codes(root)


def test_validate_control_with_builtin_digest_mismatch(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    profiles = documents["semantics/releases.yaml"]["profiles"]
    assert isinstance(profiles, list)
    assert isinstance(profiles[0], dict)
    profiles[0]["sha256"] = "0" * 64
    root = write_control(tmp_path / "control", documents)
    assert "semantic.builtin-digest-mismatch" in _finding_codes(root)


def test_validate_control_with_builtin_in_wrong_category(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    profiles = documents["semantics/releases.yaml"]["profiles"]
    vocabularies = documents["semantics/releases.yaml"]["relation_vocabularies"]
    assert isinstance(profiles, list)
    assert isinstance(vocabularies, list)
    profiles = cast("list[object]", profiles)
    vocabularies = cast("list[object]", vocabularies)
    profiles.append(vocabularies.pop())
    root = write_control(tmp_path / "control", documents)
    assert "semantic.builtin-category-invalid" in _finding_codes(root)


def test_validate_control_with_builtin_owned_twice_across_categories(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
) -> None:
    documents = deepcopy(control_documents)
    profiles = documents["semantics/releases.yaml"]["profiles"]
    vocabularies = documents["semantics/releases.yaml"]["relation_vocabularies"]
    assert isinstance(profiles, list)
    assert isinstance(vocabularies, list)
    profiles = cast("list[object]", profiles)
    vocabularies = cast("list[object]", vocabularies)
    profiles.append(deepcopy(vocabularies[0]))
    root = write_control(tmp_path / "control", documents)
    assert "semantic.release-duplicate" in _finding_codes(root)


@pytest.mark.parametrize(
    ("rule", "code"),
    [
        (
            {"source_domains": ["unknown"], "destination_domains": ["work"], "predicates": ["related"]},
            "trust.policy-domain-unknown",
        ),
        (
            {"source_domains": ["public"], "destination_domains": ["work"], "predicates": ["invented"]},
            "trust.policy-predicate-ungoverned",
        ),
    ],
)
def test_validate_control_with_invalid_cross_domain_rule(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    rule: dict[str, object],
    code: str,
) -> None:
    documents = deepcopy(control_documents)
    documents["trust/policy.yaml"]["rules"] = [rule]
    root = write_control(tmp_path / "control", documents)
    assert code in _finding_codes(root)


def test_inspect_control_with_empty_rules_preserves_default_deny(control_root: Path) -> None:
    policy = inspect_control(ControlInspectRequest(root=str(control_root))).trust_policy
    assert policy is not None
    assert policy.rules == ()


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("collections", ["unknown"], "projection.collection-unknown"),
        ("trust_domains", ["unknown"], "projection.domain-unknown"),
    ],
)
def test_validate_control_with_unknown_projection_reference(
    tmp_path: Path,
    control_documents: ControlDocuments,
    write_control: Callable[[Path, ControlDocuments], Path],
    field: str,
    value: list[object],
    code: str,
) -> None:
    documents = deepcopy(control_documents)
    recipe: dict[str, object] = {
        "version": 1,
        "id": "search",
        "collections": [],
        "admitted_review_statuses": ["reviewed"],
        "trust_domains": ["work"],
        "chunker": "heading",
        field: value,
    }
    documents["projections/recipes.yaml"]["recipes"] = [recipe]
    root = write_control(tmp_path / "control", documents)
    assert code in _finding_codes(root)


def test_inspect_control_reports_deterministic_identities(control_root: Path) -> None:
    first = inspect_control(ControlInspectRequest(root=str(control_root)))
    second = inspect_control(ControlInspectRequest(root=str(control_root)))
    assert (first.bundle_sha256, first.exported_schema_sha256, first.knowledge_system_version) == (
        second.bundle_sha256,
        second.exported_schema_sha256,
        second.knowledge_system_version,
    )


def test_inspect_control_reports_deterministic_source_revision(control_root: Path) -> None:
    first = inspect_control(ControlInspectRequest(root=str(control_root)))
    second = inspect_control(ControlInspectRequest(root=str(control_root)))
    assert first.knowledge_system_revision == second.knowledge_system_revision
    assert _REVISION_PATTERN.fullmatch(first.knowledge_system_revision) is not None


@pytest.mark.skipif(os.name == "nt", reason="Windows chmod does not reliably deny the current owner read access")
def test_inspect_control_with_environmental_read_failure_is_operational(control_root: Path) -> None:
    catalog = control_root / "catalog" / "collections.yaml"
    catalog.chmod(0)
    try:
        with pytest.raises(ConfigurationError):
            inspect_control(ControlInspectRequest(root=str(control_root)))
    finally:
        catalog.chmod(0o600)


@pytest.mark.skipif(os.name == "nt", reason="Windows chmod does not reliably deny the current owner read access")
def test_control_cli_with_environmental_read_failure_returns_two(control_root: Path) -> None:
    catalog = control_root / "catalog" / "collections.yaml"
    catalog.chmod(0)
    try:
        result = _run("control", "inspect", str(control_root))
    finally:
        catalog.chmod(0o600)
    assert result.returncode == 2


def test_inspect_and_validate_control_are_byte_and_mtime_preserving(control_root: Path) -> None:
    before = {
        path.relative_to(control_root): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in control_root.rglob("*")
        if path.is_file()
    }
    inspect_control(ControlInspectRequest(root=str(control_root)))
    validate_control(ControlValidateRequest(root=str(control_root)))
    after = {
        path.relative_to(control_root): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in control_root.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_control_cli_inspect_json_is_deterministic(control_root: Path) -> None:
    first = _run("control", "inspect", str(control_root), "--format", "json")
    second = _run("control", "inspect", str(control_root), "--format", "json")
    assert first.returncode == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["schema_version"] == 1


def test_control_cli_validate_text_reports_package_and_schema(control_root: Path) -> None:
    result = _run("control", "validate", str(control_root))
    assert result.returncode == 0
    assert "knowledge_system_version:" in result.stdout
    assert "knowledge_system_revision:" in result.stdout
    assert "exported_schema_sha256:" in result.stdout


def test_control_cli_validate_returns_one_for_blocking_findings(control_root: Path) -> None:
    (control_root / "catalog" / "collections.yaml").unlink()
    assert _run("control", "validate", str(control_root)).returncode == 1


def test_control_cli_returns_two_for_invocation_error() -> None:
    assert _run("control", "validate", "does-not-exist").returncode == 2


def test_control_request_models_are_frozen() -> None:
    request = ControlInspectRequest(root=".")
    with pytest.raises(ValidationError):
        request.root = "elsewhere"


def test_control_schema_export_check_is_clean() -> None:
    schemas = Path(__file__).parents[2] / "schemas"
    result = _run("schema", "export", "--destination", str(schemas), "--check")
    assert result.returncode == 0
