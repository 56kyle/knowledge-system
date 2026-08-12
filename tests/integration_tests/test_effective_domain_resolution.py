from pathlib import Path

import pytest

from knowledge_system.domain import CatalogEntry
from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import CrossDomainRule
from knowledge_system.domain import ResolutionContext
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.exceptions import ReferenceResolutionError
from knowledge_system.resolution import parse_reference
from knowledge_system.resolution import resolve_reference_effective_domains
from tests.helpers import write_manifest
from tests.helpers import write_note


def _collection(root: Path, name: str, domain: str) -> Path:
    path = root / name
    path.mkdir()
    write_manifest(path, collection_id=name, trust_domain=domain)
    return path


def _context(root: Path, domains: dict[str, str]) -> ResolutionContext:
    return ResolutionContext(
        catalog=CollectionCatalog(
            collections=tuple(
                CatalogEntry(
                    collection_id=name,
                    manifest=f"{name}/collection.yaml",
                    trust_domains=frozenset({domain}),
                )
                for name, domain in domains.items()
            )
        ),
        catalog_root=str(root),
        allowed_collections=tuple(domains),
    )


def test_resolve_reference_denies_after_transitive_domain_expansion(tmp_path: Path) -> None:
    work = _collection(tmp_path, "work", "work")
    private = _collection(tmp_path, "private", "private")
    write_note(
        work / "claim.md",
        identity="claim",
        extra="relations:\n  - predicate: related\n    target: note:private/evidence\n",
    )
    write_note(private / "evidence.md", identity="evidence")
    policy = TrustPolicy(
        id="policy",
        rules=(
            CrossDomainRule(
                source_domains=frozenset({"work"}),
                destination_domains=frozenset({"private"}),
                predicates=frozenset({"related"}),
            ),
        ),
    )
    with pytest.raises(AuthorizationError):
        _ = resolve_reference_effective_domains(
            parse_reference("note:work/claim"),
            _context(tmp_path, {"work": "work", "private": "private"}),
            policy,
            source_domains=frozenset({"work"}),
            predicate="supports",
        )


def test_resolve_reference_handles_cycles_and_invalidates_revision_attestation(tmp_path: Path) -> None:
    first = _collection(tmp_path, "first", "work")
    second = _collection(tmp_path, "second", "work")
    write_note(
        first / "one.md",
        identity="one",
        extra="relations:\n  - predicate: related\n    target: note:second/two\n",
    )
    write_note(
        second / "two.md",
        identity="two",
        extra="relations:\n  - predicate: related\n    target: note:first/one\n",
    )
    context = _context(tmp_path, {"first": "work", "second": "work"})
    policy = TrustPolicy(id="same-domain")
    initial = resolve_reference_effective_domains(
        parse_reference("note:first/one"),
        context,
        policy,
        source_domains=frozenset({"work"}),
        predicate="supports",
    )
    assert initial.effective_domains == frozenset({"work"})
    assert initial.revision_attestation_sha256 is not None
    _ = (second / "two.md").write_text(
        (second / "two.md").read_text(encoding="utf-8") + "Changed.\n",
        encoding="utf-8",
    )
    changed = resolve_reference_effective_domains(
        parse_reference("note:first/one"),
        context,
        policy,
        source_domains=frozenset({"work"}),
        predicate="supports",
    )
    assert changed.revision_attestation_sha256 != initial.revision_attestation_sha256


def test_denied_present_and_absent_targets_are_opaque(tmp_path: Path) -> None:
    secret = _collection(tmp_path, "secret", "private")
    write_note(secret / "present.md", identity="present")
    context = _context(tmp_path, {"secret": "private"})
    policy = TrustPolicy(id="deny")
    messages: list[str] = []
    for identity in ("present", "absent"):
        with pytest.raises((AuthorizationError, ReferenceResolutionError)) as captured:
            _ = resolve_reference_effective_domains(
                parse_reference(f"note:secret/{identity}"),
                context,
                policy,
                source_domains=frozenset({"public"}),
                predicate="supports",
            )
        _ = messages.append(str(captured.value))
    assert messages[0] == messages[1]


def _public_to_work_policy() -> TrustPolicy:
    return TrustPolicy(
        id="public-work",
        rules=(
            CrossDomainRule(
                source_domains=frozenset({"public"}),
                destination_domains=frozenset({"work"}),
                predicates=frozenset({"supports"}),
            ),
        ),
    )


def test_prospective_relation_is_omitted_from_recursive_effective_domains(tmp_path: Path) -> None:
    work = _collection(tmp_path, "work", "work")
    private = _collection(tmp_path, "private", "private")
    write_note(
        work / "claim.md",
        identity="claim",
        extra=("relations:\n  - predicate: related\n    target: note:private/evidence\n    resolution: prospective\n"),
    )
    write_note(private / "evidence.md", identity="evidence")
    result = resolve_reference_effective_domains(
        parse_reference("note:work/claim"),
        _context(tmp_path, {"work": "work", "private": "private"}),
        _public_to_work_policy(),
        source_domains=frozenset({"public"}),
        predicate="supports",
    )
    assert result.effective_domains == frozenset({"work"})


def test_required_relation_enforces_transitive_destination_domains(tmp_path: Path) -> None:
    work = _collection(tmp_path, "work", "work")
    private = _collection(tmp_path, "private", "private")
    write_note(
        work / "claim.md",
        identity="claim",
        extra="relations:\n  - predicate: related\n    target: note:private/evidence\n    resolution: required\n",
    )
    write_note(private / "evidence.md", identity="evidence")
    with pytest.raises(AuthorizationError):
        _ = resolve_reference_effective_domains(
            parse_reference("note:work/claim"),
            _context(tmp_path, {"work": "work", "private": "private"}),
            _public_to_work_policy(),
            source_domains=frozenset({"public"}),
            predicate="supports",
        )
