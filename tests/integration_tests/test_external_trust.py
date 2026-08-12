# pyright: reportUnusedCallResult=false

from pathlib import Path

from knowledge_system import ValidateRequest
from knowledge_system import validate_collection
from tests.helpers import write_manifest
from tests.helpers import write_note


def _write_catalog(root: Path) -> Path:
    path = root / "catalog.yaml"
    path.write_text(
        """version: 1
collections:
  - collection_id: source
    manifest: source/collection.yaml
    trust_domains: [work]
  - collection_id: destination
    manifest: destination/collection.yaml
    trust_domains: [public]
""",
        encoding="utf-8",
    )
    return path


def _write_policy(source: Path, *, predicate: str) -> None:
    (source / "trust-policy.yaml").write_text(
        f"""version: 1
id: local-trust
rules:
  - source_domains: [work]
    destination_domains: [public]
    predicates: [{predicate}]
""",
        encoding="utf-8",
    )


def _write_cross_domain_collections(root: Path, *, target: str = "claim") -> tuple[Path, Path]:
    source = root / "source"
    destination = root / "destination"
    source.mkdir()
    destination.mkdir()
    write_manifest(
        source,
        collection_id="source",
        trust_domain="work",
        trust_policy="trust-policy.yaml",
        trust_policy_id="local-trust",
    )
    write_manifest(destination, collection_id="destination", trust_domain="public")
    write_note(destination / "claim.md", identity="claim")
    write_note(
        source / "note.md",
        identity="note",
        extra=f"relations:\n  - predicate: supports\n    target: note:destination/{target}\n",
    )
    return source, _write_catalog(root)


def test_validate_collection_allows_explicit_cross_domain_relation(tmp_path: Path) -> None:
    source, catalog = _write_cross_domain_collections(tmp_path)
    _write_policy(source, predicate="supports")

    report = validate_collection(ValidateRequest(collection=str(source), catalog=str(catalog)))

    assert not report.has_blocking_findings


def test_validate_collection_denies_before_disclosing_missing_foreign_target(tmp_path: Path) -> None:
    source, catalog = _write_cross_domain_collections(tmp_path, target="secret-missing")
    _write_policy(source, predicate="related")

    report = validate_collection(ValidateRequest(collection=str(source), catalog=str(catalog)))

    codes = {finding.code for finding in report.findings}
    assert "relation.cross-domain-denied" in codes
    assert "relation.external-target-missing" not in codes


def test_validate_collection_reports_allowed_but_missing_external_target(tmp_path: Path) -> None:
    source, catalog = _write_cross_domain_collections(tmp_path, target="missing")
    _write_policy(source, predicate="supports")
    report = validate_collection(ValidateRequest(collection=str(source), catalog=str(catalog)))
    assert "relation.external-target-unavailable" in {finding.code for finding in report.findings}
